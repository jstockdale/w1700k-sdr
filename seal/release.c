// SPDX-License-Identifier: MIT
/* w1700k-release: is this a release, or a new list of keys, sealed by a key this unit trusts?
 *
 *   w1700k-release verify [--keys FILE] [--state DIR] [--floor N] ENVELOPE
 *   w1700k-release rotate [--keys FILE] [--first] --out FILE ENVELOPE
 *   w1700k-release list [--keys FILE]
 *   w1700k-release mark --environment FILE
 *   w1700k-release allows [--state DIR] SHA256
 *   w1700k-release number [--state DIR]
 *
 * Both are WMS2 control envelopes: `wms2.c`, the envelope Whitehat Hardware's
 * devices take their commands in. The signature is Ed25519 over the topic, the
 * header and the body, so what is sealed for another topic or another product,
 * or changed in one bit, is not this.
 *
 * The keys a unit trusts are a list (FILE): its epoch and generation, and up to
 * eight keys, each with a scope that says what the key may seal.
 *
 *   w1700k-sdr keys 2.3
 *   <64 hex digits>  root  <name>
 *   <64 hex digits>  keys  <name>
 *   <64 hex digits>  release  <name>
 *
 *   release     a release: an update archive's manifest, under the release topic
 *   timestamp   nothing a unit takes: what a host is told is current
 *   keys        the next list of the epoch, which leaves every root and keys line as it is
 *   root        that, and the first list of the next epoch, which may change any line
 *
 * Lists are in order by epoch and then by generation. A keys key cannot leave
 * its epoch, so however far it runs the generation up, a root key's next epoch
 * comes after it.
 *
 * The list is read in one form only, byte for byte; `parse_list` says which.
 *
 * `verify` checks a release against the list's release keys and against the
 * floor, the newest release this unit has settled on: an older one is refused,
 * and that is all the protection against being walked backwards that a unit
 * without a clock can have. What passes is left in DIR as `manifest` and
 * `number`, where `allows` and `number` read it. DIR is in RAM, so a
 * verification lasts until the reboot that applies it.
 *
 * `rotate` checks a new list against the list held. It is sealed by a root or
 * keys key of the held list, and is one of two things: a later generation of
 * the epoch held, with the root and keys lines as they are held; or generation
 * 1 of the next epoch, sealed by a root key. What passes is written to --out,
 * for the caller to put in the held list's place. The list held, again, changes
 * nothing and is no error; another list of its epoch and generation, sealed by
 * a key of it, is refused loudly: two lists were sealed as one. `--first` is
 * for a unit that holds no list: the list must be sealed by a root key it names
 * itself, and whoever gives it to the unit answers for whose keys those are.
 *
 * `list` prints the held list's generation and keys, with the fingerprint a
 * person compares; it exits 1 for no list and 2 for one that does not read.
 * `allows` says whether the verified manifest lists an image with that digest.
 *
 * `mark` says whether this unit is marked as keyed: whether the stock boot
 * loader's environment (FILE: the `uenv` partition) holds `w1700k_keyed=1`. It
 * exits 0 when it does, 1 when the environment reads and does not, and 2 when
 * the environment does not read, which is not the same as no mark.
 *
 * It only reads its inputs and writes DIR and --out. It runs on the unit, and
 * on a host for the tests.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "monocypher.h"
#include "optional/monocypher-ed25519.h"
#include "release.h"
#include "wms2.h"

#define KEYS_FILE "/durable/keys"
#define STATE_DIR "/run/w1700k-release"

enum scope { SCOPE_ROOT, SCOPE_KEYS, SCOPE_RELEASE, SCOPE_TIMESTAMP, SCOPES };
static const char *const scope_names[SCOPES] = { "root", "keys", "release", "timestamp" };

/* The keys that say who is trusted: what only a root key may change. */
static bool authority(enum scope scope)
{
	return scope == SCOPE_ROOT || scope == SCOPE_KEYS;
}

struct key {
	uint8_t public[32];
	enum scope scope;
	char name[KEY_NAME_MOST + 1];
};

struct list {
	uint64_t epoch, generation;
	int count;
	struct key keys[KEYS_MOST];
	uint8_t text[LIST_MOST];	/* as it was read, for telling one list from another */
	size_t size;
};

enum held { HELD_GOOD, HELD_NONE, HELD_DAMAGED };

static uint8_t envelope[RELEASE_ENVELOPE_MOST + 1];
static uint8_t scratch[2 + WMS2_MAX_TOPIC + RELEASE_ENVELOPE_MOST];

static int hex_value(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

/* The eight points of small order, as libsodium lists them (the top bit, the sign
 * of x, set aside). A signature under such a key verifies for any message, so a
 * list that names one would let anyone seal; no honest key is one of them. */
static bool small_order(const uint8_t key[32])
{
	static const uint8_t points[][32] = {
		{ 0x00 },
		{ 0x01 },
		{ 0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
		  0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05 },
		{ 0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
		  0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a },
		{ 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
		{ 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
		{ 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
	};
	uint8_t plain[32];

	memcpy(plain, key, 32);
	plain[31] &= 0x7f;
	for (size_t i = 0; i < sizeof points / sizeof points[0]; i++)
		if (memcmp(plain, points[i], 32) == 0)
			return true;
	return false;
}

/* Is this the one encoding of a point's y and sign? Monocypher takes others as
 * well: a y of p or more, which it reduces, and a set sign on a point whose x is
 * zero. RFC 8032 refuses them, and so does the host's verifier, so they are
 * refused here before Monocypher sees them, in a key and in the first half of a
 * signature alike. */
static bool one_encoding(const uint8_t point[32])
{
	static const uint8_t zero_x[2][32] = {
		{ 0x01 },
		{ 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
	};
	bool below_p = (point[31] & 0x7f) != 0x7f || point[0] < 0xed;

	for (int i = 1; i < 31 && !below_p; i++)
		below_p = point[i] != 0xff;
	if (!below_p)
		return false;
	if (point[31] & 0x80)
		for (int i = 0; i < 2; i++)
			if (memcmp(point, zero_x[i], 31) == 0 && (point[31] & 0x7f) == zero_x[i][31])
				return false;
	return true;
}

/* A list in its one form, or why it is not one. Every byte is printable or a line
 * feed; it ends in one line feed; the first line is the product, `keys`, the epoch,
 * a dot and the generation, each a number from 1 written the one way a number is;
 * each line after it is a key, two spaces, a scope, two spaces, a name. One to eight keys, no key and no
 * name twice, no key of small order, and a root key among them: a list without
 * one could never have its root or keys lines changed again. */
static const char *parse_list(const uint8_t *text, size_t size, struct list *list)
{
	static const char head[] = RELEASE_PRODUCT " keys ";
	size_t at = 0, end;
	bool root = false;

	memset(list, 0, sizeof *list);
	if (size == 0 || size > LIST_MOST)
		return "it is not the size of a list";
	for (size_t i = 0; i < size; i++)
		if (text[i] != '\n' && (text[i] < 0x20 || text[i] > 0x7e))
			return "it holds a byte that is neither printable nor a line feed";
	if (text[size - 1] != '\n')
		return "it does not end in a line feed";
	memcpy(list->text, text, size);
	list->size = size;

	end = (size_t)((const uint8_t *)memchr(text, '\n', size) - text);
	if (end <= sizeof head - 1 || memcmp(text, head, sizeof head - 1) != 0)
		return "its first line is not `" RELEASE_PRODUCT " keys E.G'";
	at = sizeof head - 1;
	for (int part = 0; part < 2; part++) {
		uint64_t *number = part ? &list->generation : &list->epoch;
		size_t digits = 0;

		if (at == end || text[at] < '1' || text[at] > '9')
			return "its epoch and generation are not E.G, each a number from 1 written plainly";
		for (; at < end && text[at] >= '0' && text[at] <= '9' && digits < 11; at++, digits++)
			*number = *number * 10 + (uint64_t)(text[at] - '0');
		if (part ? at != end : at == end || text[at++] != '.')
			return "its epoch and generation are not E.G, each a number from 1 written plainly";
	}
	if (list->epoch > EPOCH_MOST || list->generation > GENERATION_MOST)
		return "its epoch or its generation is beyond what a list may reach";
	at = end + 1;

	while (at < size) {
		struct key *key = &list->keys[list->count];
		size_t length;
		int scope;

		end = (size_t)((const uint8_t *)memchr(text + at, '\n', size - at) - text);
		if (list->count == KEYS_MOST)
			return "it holds more than eight keys";
		if (end - at < 64 + 2)
			return "a line of it is not a key, a scope and a name";
		for (int i = 0; i < 32; i++) {
			int high = hex_value(text[at + 2 * i]), low = hex_value(text[at + 2 * i + 1]);

			if (high < 0 || low < 0)
				return "a line of it does not start with a key of 64 hex digits";
			key->public[i] = (uint8_t)(high << 4 | low);
		}
		at += 64;
		if (text[at] != ' ' || text[at + 1] != ' ')
			return "a key of it is not followed by two spaces";
		at += 2;
		for (scope = 0; scope < SCOPES; scope++) {
			length = strlen(scope_names[scope]);
			if (end - at >= length + 2 && memcmp(text + at, scope_names[scope], length) == 0 &&
			    text[at + length] == ' ' && text[at + length + 1] == ' ')
				break;
		}
		if (scope == SCOPES)
			return "a key of it has no scope of root, keys or release, followed by two spaces";
		key->scope = (enum scope)scope;
		at += strlen(scope_names[scope]) + 2;
		length = end - at;
		if (length < 1 || length > KEY_NAME_MOST)
			return "a key of it has no name of 1 to 48 characters";
		for (size_t i = 0; i < length; i++) {
			uint8_t c = text[at + i];

			if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-'))
				return "a name in it is not lowercase letters, digits and hyphens";
		}
		memcpy(key->name, text + at, length);
		if (small_order(key->public))
			return "a key of it is a point of small order, which anyone can sign for";
		if (!one_encoding(key->public))
			return "a key of it is not in the one form a key is written in";
		for (int i = 0; i < list->count; i++) {
			if (memcmp(list->keys[i].public, key->public, 32) == 0)
				return "it names the same key twice";
			if (strcmp(list->keys[i].name, key->name) == 0)
				return "it gives two keys the same name";
		}
		root = root || key->scope == SCOPE_ROOT;
		list->count++;
		at = end + 1;
	}
	if (list->count == 0)
		return "it holds no key";
	if (!root)
		return "it holds no root key";
	return NULL;
}

/* The list in the file at `path`. HELD_NONE is no file at all. */
static enum held read_list(const char *path, struct list *list, const char **why)
{
	static uint8_t text[LIST_MOST + 1];
	size_t size;
	FILE *file = fopen(path, "rb");

	*why = "it cannot be read";
	if (!file)
		return errno == ENOENT ? HELD_NONE : HELD_DAMAGED;
	size = fread(text, 1, sizeof text, file);
	if (ferror(file)) {
		fclose(file);
		return HELD_DAMAGED;
	}
	fclose(file);
	*why = parse_list(text, size, list);
	return *why ? HELD_DAMAGED : HELD_GOOD;
}

/* The list a unit holds, or the exit status and the word for having none that reads. */
static int held_list(const char *path, struct list *list)
{
	const char *why;

	switch (read_list(path, list, &why)) {
	case HELD_GOOD:
		return 0;
	case HELD_NONE:
		fprintf(stderr, "w1700k-release: this unit holds no key list (%s)\n", path);
		return 2;
	default:
		fprintf(stderr, "w1700k-release: %s is not a key list: %s\n", path, why);
		return 2;
	}
}

static void fingerprint(const uint8_t key[32], char out[17])
{
	uint8_t hash[8];

	crypto_blake2b(hash, sizeof hash, key, 32);
	for (int i = 0; i < 8; i++)
		sprintf(out + 2 * i, "%02x", hash[i]);
}

/* Whole, or not there: `path` is written beside itself and moved into place. */
static int write_file(const char *path, const void *data, size_t size)
{
	char part[512];
	FILE *file;

	if (snprintf(part, sizeof part, "%s.part", path) >= (int)sizeof part)
		return -1;
	file = fopen(part, "wb");
	if (!file)
		return -1;
	if (fwrite(data, 1, size, file) != size || fflush(file) != 0 || fsync(fileno(file)) != 0) {
		fclose(file);
		remove(part);
		return -1;
	}
	if (fclose(file) != 0 || rename(part, path) != 0) {
		remove(part);
		return -1;
	}
	return 0;
}

static int write_whole(const char *dir, const char *name, const void *data, size_t size)
{
	char path[512];

	if (snprintf(path, sizeof path, "%s/%s", dir, name) >= (int)sizeof path)
		return -1;
	return write_file(path, data, size);
}

static long read_whole(const char *dir, const char *name, char *out, size_t most)
{
	char path[512];
	FILE *file;
	size_t size;

	if (snprintf(path, sizeof path, "%s/%s", dir, name) >= (int)sizeof path)
		return -1;
	file = fopen(path, "r");
	if (!file)
		return -1;
	size = fread(out, 1, most - 1, file);
	fclose(file);
	out[size] = '\0';
	return (long)size;
}

/* The envelope in the file at `path`, into `envelope`: its length, -1 when it
 * cannot be read, -2 when it is too long to be one. Either is said here. */
static long read_envelope(const char *path, const char *what)
{
	size_t length;
	FILE *file = fopen(path, "rb");

	if (!file) {
		fprintf(stderr, "w1700k-release: cannot read %s\n", path);
		return -1;
	}
	length = fread(envelope, 1, sizeof envelope, file);
	fclose(file);
	if (length > RELEASE_ENVELOPE_MOST) {
		fprintf(stderr, "w1700k-release: %s is too long to be %s\n", path, what);
		return -2;
	}
	return (long)length;
}

/* What a signature over the envelope covers: the topic, the header and the body. */
static size_t signed_bytes(const char *topic, size_t length)
{
	size_t size = strlen(topic), covered = length - WMS2_SIG_LEN;

	scratch[0] = (uint8_t)size;
	scratch[1] = (uint8_t)(size >> 8);
	memcpy(scratch + 2, topic, size);
	memcpy(scratch + 2 + size, envelope, covered);
	return 2 + size + covered;
}

/* A control envelope with nothing in it that the verifier would pass over: no
 * flag, nothing in the reserved bytes, and the product alone in the device field. */
static bool plain_header(void)
{
	static const uint8_t device[WMS2_DEVID_LEN] = RELEASE_PRODUCT;

	return envelope[4] == WMS2_KIND_CTRL && envelope[5] == 0 &&
	       memcmp(envelope + 6, device, WMS2_DEVID_LEN) == 0 &&
	       envelope[38] == 0 && envelope[39] == 0;
}

static int verify(const char *keys_path, const char *state, uint64_t floor, const char *path)
{
	static struct list list;
	const struct key *sealer = NULL, *first = NULL;
	size_t body_length, message;
	const uint8_t *body;
	wms2_replay replay = { floor };
	/* Strict, and no window of time: the unit has no clock to hold a release against. */
	wms2_policy policy = { true, 0, 0, 0 };
	wms2_hdr header;
	wms2_rc rc;
	char number[32], mark[17];
	long length;
	int status = held_list(keys_path, &list);

	if (status)
		return status;
	for (int i = 0; i < list.count; i++)
		if (list.keys[i].scope == SCOPE_RELEASE && !first)
			first = &list.keys[i];
	if (!first) {
		fprintf(stderr, "w1700k-release: this unit's key list (%llu.%llu) holds no release key: "
			"it takes no release until a new list gives it one\n", (unsigned long long)list.epoch,
			(unsigned long long)list.generation);
		return 1;
	}
	length = read_envelope(path, "a release");
	if (length < 0)
		return length == -1 ? 2 : 1;
	if (length >= WMS2_HDR_LEN + WMS2_SIG_LEN && !one_encoding(envelope + length - WMS2_SIG_LEN)) {
		fprintf(stderr, "w1700k-release: not a release sealed by a release key this unit holds "
			"(its signature is not in the one form a signature is written in)\n");
		return 1;
	}
	/* Whichever release key sealed it is the one the envelope is then held to in
	 * full; with none, the first is, and the envelope's own verifier says why not. */
	if (length >= WMS2_HDR_LEN + WMS2_SIG_LEN) {
		message = signed_bytes(RELEASE_TOPIC, (size_t)length);
		for (int i = 0; i < list.count && !sealer; i++)
			if (list.keys[i].scope == SCOPE_RELEASE &&
			    crypto_ed25519_check(envelope + length - WMS2_SIG_LEN, list.keys[i].public,
						 scratch, message) == 0)
				sealer = &list.keys[i];
	}
	if (!sealer)
		sealer = first;
	rc = wms2_verify(envelope, (size_t)length, RELEASE_TOPIC, NULL, sealer->public, scratch, sizeof scratch,
			 0, &replay, &policy, &header, &body, &body_length);
	if (rc != WMS2_OK && rc != WMS2_OK_DUP) {
		if (rc == WMS2_E_REPLAY)
			fprintf(stderr, "w1700k-release: release %llu is older than release %llu, which this "
				"unit has settled on\n", (unsigned long long)header.ctr, (unsigned long long)floor);
		else
			fprintf(stderr, "w1700k-release: not a release sealed by a release key this unit holds (%s)\n",
				wms2_rc_str(rc));
		return 1;
	}
	if (header.kind != WMS2_KIND_CTRL || strcmp(header.dev_id, RELEASE_PRODUCT) != 0) {
		fprintf(stderr, "w1700k-release: sealed for %s, not for %s\n", header.dev_id, RELEASE_PRODUCT);
		return 1;
	}
	if (!plain_header()) {
		fprintf(stderr, "w1700k-release: not a plain control envelope: a flag or a reserved byte is set\n");
		return 1;
	}
	if (header.ctr == 0 || header.ctr > RELEASE_NUMBER_MOST || body_length == 0 ||
	    memchr(body, '\0', body_length)) {
		fprintf(stderr, "w1700k-release: a release has a number from 1 to %llu and a manifest of text\n",
			(unsigned long long)RELEASE_NUMBER_MOST);
		return 1;
	}
	if (mkdir(state, 0755) != 0 && errno != EEXIST) {
		fprintf(stderr, "w1700k-release: cannot make %s\n", state);
		return 2;
	}
	snprintf(number, sizeof number, "%llu\n", (unsigned long long)header.ctr);
	if (write_whole(state, "manifest", body, body_length) != 0 ||
	    write_whole(state, "number", number, strlen(number)) != 0) {
		fprintf(stderr, "w1700k-release: cannot write to %s\n", state);
		return 2;
	}
	fingerprint(sealer->public, mark);
	printf("release=%llu key=%s name=%s\n", (unsigned long long)header.ctr, mark, sealer->name);
	return 0;
}

/* Does `next` have the root and keys lines of `held`, each as it is there, and no other? */
static bool same_authorities(const struct list *held, const struct list *next)
{
	int in_held = 0, in_next = 0;

	for (int i = 0; i < held->count; i++)
		in_held += authority(held->keys[i].scope);
	for (int i = 0; i < next->count; i++) {
		const struct key *key = &next->keys[i];
		bool found = false;

		if (!authority(key->scope))
			continue;
		in_next++;
		for (int j = 0; j < held->count && !found; j++)
			found = held->keys[j].scope == key->scope &&
				memcmp(held->keys[j].public, key->public, 32) == 0 &&
				strcmp(held->keys[j].name, key->name) == 0;
		if (!found)
			return false;
	}
	return in_held == in_next;
}

static int rotate(const char *keys_path, bool first, const char *out, const char *path)
{
	static struct list held, next;
	const struct key *signer = NULL;
	const struct list *judges = first ? &next : &held;
	size_t body_length, message;
	const uint8_t *body;
	const char *why;
	/* Lists are put in order here, by epoch and generation: the envelope's own
	 * counter is the generation alone, which starts again with each epoch. */
	wms2_replay replay = { 0 };
	wms2_policy policy = { true, 0, 0, 0 };
	wms2_hdr header;
	wms2_rc rc;
	uint64_t counter;
	char mark[17];
	long length;

	if (!first) {
		int status = held_list(keys_path, &held);

		if (status)
			return status;
	}
	length = read_envelope(path, "a list of keys");
	if (length < 0)
		return length == -1 ? 2 : 1;
	if (length < WMS2_HDR_LEN + WMS2_SIG_LEN + 1 || memcmp(envelope, "WMS2", 4) != 0 || !plain_header()) {
		fprintf(stderr, "w1700k-release: %s is not a list of keys sealed for %s\n", path, RELEASE_PRODUCT);
		return 1;
	}
	why = parse_list(envelope + WMS2_HDR_LEN, (size_t)length - WMS2_HDR_LEN - WMS2_SIG_LEN, &next);
	if (why) {
		fprintf(stderr, "w1700k-release: what %s seals is not a key list: %s\n", path, why);
		return 1;
	}
	counter = 0;
	for (int i = 7; i >= 0; i--)
		counter = counter << 8 | envelope[22 + i];
	if (counter != next.generation) {
		fprintf(stderr, "w1700k-release: not a list this unit takes: the envelope's counter is %llu and "
			"the list says generation %llu\n", (unsigned long long)counter,
			(unsigned long long)next.generation);
		return 1;
	}
	/* The list held, whoever hands it over and however it is sealed, changes nothing. */
	if (!first && next.size == held.size && memcmp(next.text, held.text, held.size) == 0) {
		printf("generation=%llu.%llu unchanged\n", (unsigned long long)held.epoch,
		       (unsigned long long)held.generation);
		return 0;
	}
	/* Sealed by a key that may seal a list: of the list held, or, for a first list,
	 * a root key the list names itself. Only of what is so sealed is anything more said. */
	message = signed_bytes(ROTATE_TOPIC, (size_t)length);
	for (int i = 0; one_encoding(envelope + length - WMS2_SIG_LEN) && i < judges->count && !signer; i++) {
		const struct key *key = &judges->keys[i];

		if ((first ? key->scope == SCOPE_ROOT : authority(key->scope)) &&
		    crypto_ed25519_check(envelope + length - WMS2_SIG_LEN, key->public, scratch, message) == 0)
			signer = key;
	}
	if (!signer) {
		fprintf(stderr, first ? "w1700k-release: a first list is sealed by a root key it names itself; "
					"this one is not\n"
				      : "w1700k-release: not sealed by a root or keys key of the list this unit "
					"holds (%llu.%llu)\n", (unsigned long long)held.epoch,
			(unsigned long long)held.generation);
		return 1;
	}
	rc = wms2_verify(envelope, (size_t)length, ROTATE_TOPIC, NULL, signer->public, scratch, sizeof scratch,
			 0, &replay, &policy, &header, &body, &body_length);
	if (rc != WMS2_OK || header.ctr != next.generation) {
		fprintf(stderr, "w1700k-release: not a list this unit takes (%s)\n", wms2_rc_str(rc));
		return 1;
	}
	if (!first && next.epoch == held.epoch && next.generation == held.generation) {
		fprintf(stderr, "w1700k-release: this is ANOTHER list %llu.%llu than the one this unit holds, and "
			"%s sealed it: two lists were sealed as one. Nothing is changed\n",
			(unsigned long long)held.epoch, (unsigned long long)held.generation, signer->name);
		return 1;
	}
	if (!first && (next.epoch < held.epoch || (next.epoch == held.epoch && next.generation < held.generation))) {
		fprintf(stderr, "w1700k-release: list %llu.%llu is older than %llu.%llu, which this unit holds\n",
			(unsigned long long)next.epoch, (unsigned long long)next.generation,
			(unsigned long long)held.epoch, (unsigned long long)held.generation);
		return 1;
	}
	if (!first && next.epoch == held.epoch && !same_authorities(&held, &next)) {
		fprintf(stderr, "w1700k-release: this list changes a root or keys line and stays in epoch %llu: "
			"only the first list of the next epoch, sealed by a root key, may change one\n",
			(unsigned long long)held.epoch);
		return 1;
	}
	if (!first && next.epoch != held.epoch) {
		if (signer->scope != SCOPE_ROOT) {
			fprintf(stderr, "w1700k-release: %s is a keys key, and this list is of another epoch: "
				"only a root key of the list held starts one\n", signer->name);
			return 1;
		}
		if (next.epoch != held.epoch + 1 || next.generation != 1) {
			fprintf(stderr, "w1700k-release: after epoch %llu comes list %llu.1 and no other; this is "
				"%llu.%llu\n", (unsigned long long)held.epoch, (unsigned long long)held.epoch + 1,
				(unsigned long long)next.epoch, (unsigned long long)next.generation);
			return 1;
		}
	}
	if (write_file(out, next.text, next.size) != 0) {
		fprintf(stderr, "w1700k-release: cannot write %s\n", out);
		return 2;
	}
	fingerprint(signer->public, mark);
	printf("generation=%llu.%llu sealed_by=%s scope=%s key=%s\n", (unsigned long long)next.epoch,
	       (unsigned long long)next.generation, signer->name, scope_names[signer->scope], mark);
	return 0;
}

static int show(const char *keys_path)
{
	static struct list list;
	const char *why;
	char mark[17];

	switch (read_list(keys_path, &list, &why)) {
	case HELD_NONE:
		return 1;
	case HELD_DAMAGED:
		fprintf(stderr, "w1700k-release: %s is not a key list: %s\n", keys_path, why);
		return 2;
	default:
		break;
	}
	printf("generation=%llu.%llu\n", (unsigned long long)list.epoch, (unsigned long long)list.generation);
	for (int i = 0; i < list.count; i++) {
		fingerprint(list.keys[i].public, mark);
		printf("%s %s %s ", scope_names[list.keys[i].scope], list.keys[i].name, mark);
		for (int j = 0; j < 32; j++)
			printf("%02x", list.keys[i].public[j]);
		putchar('\n');
	}
	return 0;
}

static uint32_t crc32(const uint8_t *data, size_t size)
{
	uint32_t crc = 0xffffffff;

	for (size_t i = 0; i < size; i++) {
		crc ^= data[i];
		for (int bit = 0; bit < 8; bit++)
			crc = crc >> 1 ^ (crc & 1 ? 0xedb88320 : 0);
	}
	return ~crc;
}

/* The stock boot loader's environment is a CRC-32 and then `name=value` strings,
 * each ended by a NUL, the last by two. */
static int marked(const char *path)
{
	static uint8_t environment[STOCK_ENVIRONMENT];
	size_t at = 4, size;
	FILE *file = path ? fopen(path, "rb") : NULL;

	if (!file) {
		fprintf(stderr, "w1700k-release: cannot read the stock environment\n");
		return 2;
	}
	size = fread(environment, 1, sizeof environment, file);
	fclose(file);
	if (size != sizeof environment || environment[sizeof environment - 1] != 0 ||
	    crc32(environment + 4, sizeof environment - 4) !=
	    ((uint32_t)environment[0] | (uint32_t)environment[1] << 8 |
	     (uint32_t)environment[2] << 16 | (uint32_t)environment[3] << 24)) {
		fprintf(stderr, "w1700k-release: %s does not read as the stock environment\n", path);
		return 2;
	}
	while (at < sizeof environment && environment[at]) {
		if (strcmp((const char *)environment + at, KEYED_MARK) == 0)
			return 0;
		at += strlen((const char *)environment + at) + 1;
	}
	return 1;
}

static int allows(const char *state, const char *digest)
{
	static char manifest[RELEASE_ENVELOPE_MOST + 1];
	char listed[80];

	if (strlen(digest) != 64 || strspn(digest, "0123456789abcdef") != 64) {
		fprintf(stderr, "w1700k-release: %s is not a SHA-256 digest\n", digest);
		return 2;
	}
	if (read_whole(state, "manifest", manifest, sizeof manifest) < 0)
		return 1;
	/* As the digest of an image and nothing else: a manifest has other text in it. */
	snprintf(listed, sizeof listed, "\"sha256\": \"%s\"", digest);
	return strstr(manifest, listed) ? 0 : 1;
}

int main(int argc, char **argv)
{
	const char *keys = KEYS_FILE, *state = STATE_DIR, *verb = argc > 1 ? argv[1] : "";
	const char *operand = NULL, *out = NULL, *environment = NULL;
	unsigned long long floor = 0;
	bool first = false;
	char text[32], *end;

	for (int i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "--keys") && i + 1 < argc) {
			keys = argv[++i];
		} else if (!strcmp(argv[i], "--state") && i + 1 < argc) {
			state = argv[++i];
		} else if (!strcmp(argv[i], "--out") && i + 1 < argc) {
			out = argv[++i];
		} else if (!strcmp(argv[i], "--environment") && i + 1 < argc) {
			environment = argv[++i];
		} else if (!strcmp(argv[i], "--first")) {
			first = true;
		} else if (!strcmp(argv[i], "--floor") && i + 1 < argc) {
			errno = 0;
			floor = strtoull(argv[++i], &end, 10);
			if (errno || *end || end == argv[i])
				goto usage;
		} else if (argv[i][0] != '-' && !operand) {
			operand = argv[i];
		} else {
			goto usage;
		}
	}
	if (!strcmp(verb, "verify") && operand && !out && !first)
		return verify(keys, state, floor, operand);
	if (!strcmp(verb, "rotate") && operand && out)
		return rotate(keys, first, out, operand);
	if (!strcmp(verb, "list") && !operand)
		return show(keys);
	if (!strcmp(verb, "mark") && !operand && environment)
		return marked(environment);
	if (!strcmp(verb, "allows") && operand)
		return allows(state, operand);
	if (!strcmp(verb, "number") && !operand) {
		if (read_whole(state, "number", text, sizeof text) <= 0)
			return 1;
		fputs(text, stdout);
		return 0;
	}
usage:
	fprintf(stderr, "usage: w1700k-release verify [--keys FILE] [--state DIR] [--floor N] ENVELOPE\n"
			"       w1700k-release rotate [--keys FILE] [--first] --out FILE ENVELOPE\n"
			"       w1700k-release list [--keys FILE]\n"
			"       w1700k-release mark --environment FILE\n"
			"       w1700k-release allows [--state DIR] SHA256\n"
			"       w1700k-release number [--state DIR]\n");
	return 2;
}
