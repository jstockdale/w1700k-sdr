// SPDX-License-Identifier: MIT
/* w1700k-release: is this the manifest of a release, sealed by a key this unit pins?
 *
 *   w1700k-release verify [--keys FILE] [--state DIR] [--floor N] ENVELOPE
 *   w1700k-release allows [--state DIR] SHA256
 *   w1700k-release number [--state DIR]
 *   w1700k-release pinned [--keys FILE]
 *
 * A release is an update archive's manifest (the SHA-256 of every image in it)
 * in a WMS2 control envelope: `wms2.c`, the envelope Whitehat Hardware's devices
 * take their commands in. Its signature is Ed25519 over the topic, the header and
 * the manifest, so a manifest sealed for another product, or changed in one bit,
 * is not this one. The header's counter is the release number.
 *
 * `verify` checks ENVELOPE against the pinned keys (one 64-digit hex public key
 * to a line of FILE; any of them may have sealed it, so that one can be kept
 * offline as the spare) and against the floor, the newest release this unit has
 * settled on: an older one is refused, and that is all the protection against
 * being walked backwards that a unit without a clock can have. What passes is
 * left in DIR as `manifest` and `number`, where `allows` and `number` read it.
 * DIR is in RAM, so a verification lasts until the reboot that applies it.
 *
 * `allows` says whether the verified manifest lists an image with that digest.
 * `pinned` says how many keys the unit pins; none means it takes any update.
 *
 * It only reads its inputs and writes DIR. It runs on the unit, and on a host
 * for the tests.
 */
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "monocypher.h"
#include "optional/monocypher-ed25519.h"
#include "release.h"
#include "wms2.h"

#define KEYS_FILE "/etc/w1700k/release-keys"
#define STATE_DIR "/run/w1700k-release"
#define KEYS_MOST 8

static uint8_t envelope[RELEASE_ENVELOPE_MOST + 1];
static uint8_t scratch[2 + WMS2_MAX_TOPIC + RELEASE_ENVELOPE_MOST];

static int hex_value(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	return -1;
}

/* The keys of FILE; -1 when it cannot be read as a key file. A missing file is no keys. */
static int read_keys(const char *path, uint8_t keys[KEYS_MOST][32])
{
	char line[256];
	int count = 0;
	FILE *file = fopen(path, "r");

	if (!file)
		return errno == ENOENT ? 0 : -1;
	while (fgets(line, sizeof line, file)) {
		char *text = line + strspn(line, " \t");
		size_t digits = strspn(text, "0123456789abcdef");

		if (*text == '#' || *text == '\n' || *text == '\0')
			continue;
		/* A key, then nothing or a note for whoever reads the file. */
		if (digits != 64 || !strchr(" \t\n", text[64]) || count == KEYS_MOST) {
			fclose(file);
			return -1;
		}
		for (int i = 0; i < 32; i++)
			keys[count][i] = (uint8_t)(hex_value(text[2 * i]) << 4 | hex_value(text[2 * i + 1]));
		count++;
	}
	fclose(file);
	return count;
}

static void fingerprint(const uint8_t key[32], char out[17])
{
	uint8_t hash[8];

	crypto_blake2b(hash, sizeof hash, key, 32);
	for (int i = 0; i < 8; i++)
		sprintf(out + 2 * i, "%02x", hash[i]);
}

static int write_whole(const char *dir, const char *name, const void *data, size_t size)
{
	char part[512], path[512];
	FILE *file;

	if (snprintf(path, sizeof path, "%s/%s", dir, name) >= (int)sizeof path ||
	    snprintf(part, sizeof part, "%s.part", path) >= (int)sizeof part)
		return -1;
	file = fopen(part, "w");
	if (!file)
		return -1;
	if (fwrite(data, 1, size, file) != size || fclose(file) != 0)
		return -1;
	return rename(part, path);
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

static int verify(const char *keys_path, const char *state, uint64_t floor, const char *path)
{
	uint8_t keys[KEYS_MOST][32];
	int count = read_keys(keys_path, keys), chosen = 0;
	size_t length, body_length, message;
	const uint8_t *body;
	wms2_replay replay = { floor };
	/* Strict, and no window of time: the unit has no clock to hold a release against. */
	wms2_policy policy = { true, 0, 0, 0 };
	wms2_hdr header;
	wms2_rc rc;
	char number[32], mark[17];
	FILE *file;

	if (count < 0) {
		fprintf(stderr, "w1700k-release: %s is not a list of release keys\n", keys_path);
		return 2;
	}
	if (count == 0) {
		fprintf(stderr, "w1700k-release: this unit pins no release key (%s)\n", keys_path);
		return 2;
	}
	file = fopen(path, "rb");
	if (!file) {
		fprintf(stderr, "w1700k-release: cannot read %s\n", path);
		return 2;
	}
	length = fread(envelope, 1, sizeof envelope, file);
	fclose(file);
	if (length > RELEASE_ENVELOPE_MOST) {
		fprintf(stderr, "w1700k-release: %s is too long to be a release\n", path);
		return 1;
	}
	/* Whichever pinned key sealed it is the one the envelope is then held to in
	 * full; with none, the first is, and the envelope's own verifier says why not. */
	if (length >= WMS2_HDR_LEN + WMS2_SIG_LEN) {
		body_length = length - WMS2_HDR_LEN - WMS2_SIG_LEN;
		message = 0;
		scratch[message++] = (uint8_t)strlen(RELEASE_TOPIC);
		scratch[message++] = 0;
		memcpy(scratch + message, RELEASE_TOPIC, strlen(RELEASE_TOPIC));
		message += strlen(RELEASE_TOPIC);
		memcpy(scratch + message, envelope, WMS2_HDR_LEN + body_length);
		message += WMS2_HDR_LEN + body_length;
		for (int i = 0; i < count; i++)
			if (crypto_ed25519_check(envelope + length - WMS2_SIG_LEN, keys[i], scratch, message) == 0) {
				chosen = i;
				break;
			}
	}
	rc = wms2_verify(envelope, length, RELEASE_TOPIC, NULL, keys[chosen], scratch, sizeof scratch,
			 0, &replay, &policy, &header, &body, &body_length);
	if (rc != WMS2_OK && rc != WMS2_OK_DUP) {
		if (rc == WMS2_E_REPLAY)
			fprintf(stderr, "w1700k-release: release %llu is older than release %llu, which this "
				"unit has settled on\n", (unsigned long long)header.ctr, (unsigned long long)floor);
		else
			fprintf(stderr, "w1700k-release: not a release sealed by a key this unit pins (%s)\n",
				wms2_rc_str(rc));
		return 1;
	}
	if (header.kind != WMS2_KIND_CTRL || strcmp(header.dev_id, RELEASE_PRODUCT) != 0) {
		fprintf(stderr, "w1700k-release: sealed for %s, not for %s\n", header.dev_id, RELEASE_PRODUCT);
		return 1;
	}
	if (header.ctr == 0 || body_length == 0 || memchr(body, '\0', body_length)) {
		fprintf(stderr, "w1700k-release: a release has a number and a manifest of text\n");
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
	fingerprint(keys[chosen], mark);
	printf("release=%llu key=%s\n", (unsigned long long)header.ctr, mark);
	return 0;
}

static int allows(const char *state, const char *digest)
{
	static char manifest[RELEASE_ENVELOPE_MOST + 1];
	char quoted[67];

	if (strlen(digest) != 64 || strspn(digest, "0123456789abcdef") != 64) {
		fprintf(stderr, "w1700k-release: %s is not a SHA-256 digest\n", digest);
		return 2;
	}
	if (read_whole(state, "manifest", manifest, sizeof manifest) < 0)
		return 1;
	snprintf(quoted, sizeof quoted, "\"%s\"", digest);
	return strstr(manifest, quoted) ? 0 : 1;
}

int main(int argc, char **argv)
{
	const char *keys = KEYS_FILE, *state = STATE_DIR, *verb = argc > 1 ? argv[1] : "";
	const char *operand = NULL;
	unsigned long long floor = 0;
	char text[32], *end;

	for (int i = 2; i < argc; i++) {
		if (!strcmp(argv[i], "--keys") && i + 1 < argc) {
			keys = argv[++i];
		} else if (!strcmp(argv[i], "--state") && i + 1 < argc) {
			state = argv[++i];
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
	if (!strcmp(verb, "verify") && operand)
		return verify(keys, state, floor, operand);
	if (!strcmp(verb, "allows") && operand)
		return allows(state, operand);
	if (!strcmp(verb, "number") && !operand) {
		if (read_whole(state, "number", text, sizeof text) <= 0)
			return 1;
		fputs(text, stdout);
		return 0;
	}
	if (!strcmp(verb, "pinned") && !operand) {
		uint8_t found[KEYS_MOST][32];
		int count = read_keys(keys, found);

		if (count < 0) {
			fprintf(stderr, "w1700k-release: %s is not a list of release keys\n", keys);
			return 2;
		}
		printf("%d\n", count);
		return count ? 0 : 1;
	}
usage:
	fprintf(stderr, "usage: w1700k-release verify [--keys FILE] [--state DIR] [--floor N] ENVELOPE\n"
			"       w1700k-release allows [--state DIR] SHA256\n"
			"       w1700k-release number [--state DIR]\n"
			"       w1700k-release pinned [--keys FILE]\n");
	return 2;
}
