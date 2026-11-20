// SPDX-License-Identifier: MIT
/*
 * wifi-beacons: Wi-Fi beacons out of the receiver's samples.
 *
 *   wifi-beacons FILE --rate 40|20 [--private] [--all]
 *
 * FILE holds int16 I, Q pairs, as sdr-recv --out writes them, taken with the LO on a Wi-Fi
 * channel's centre at 40 Msps (or 20). Every frame found whose 32-bit frame check sequence holds
 * is counted; for beacons and probe responses a line says when it came, how it was sent, the
 * network's name (SSID), its BSSID and the channel it says it is on. --all lists the other
 * frames too (type and length only). --private prints a hash of each name and address in
 * place of the thing itself, for output that will be shown to somebody else.
 *
 * Two receivers, both written from the standard (IEEE 802.11-2020):
 *
 *   DSSS, 1 and 2 Mbit/s (clause 15, long preamble): what 2.4 GHz networks that still serve
 *   the oldest clients beacon with. Barker-11 despreading, differential BPSK/QPSK, the
 *   self-synchronising descrambler, the PLCP header with its own check.
 *
 *   OFDM, 6, 12 and 24 Mbit/s (clause 17): what 5 and 6 GHz networks beacon with, and 2.4 GHz
 *   ones that dropped the old rates. Short-training detection, carrier offset from both
 *   trainings, a channel estimate from the long one, pilot phase tracking, the half-rate
 *   K = 7 code decoded with soft decisions. The punctured rates (9, 18, 36, 48, 54) are
 *   stepped over: beacons go out at a network's lowest basic rate, nearly always 6.
 *
 * Nothing here transmits or asks anything of anybody: it reads what was received.
 * It is not fast: about ten times slower than the samples arrive, on one core of a laptop.
 */
#include <complex.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef float complex cf;

static int private_names, show_all;
static double sample_rate;

/* ---- shared: checksums, the frame parser --------------------------------------------------- */

static uint32_t crc32_ieee(const uint8_t *p, size_t n)
{
	uint32_t c = 0xffffffffu;

	for (size_t i = 0; i < n; i++) {
		c ^= p[i];
		for (int k = 0; k < 8; k++)
			c = c >> 1 ^ (0xedb88320u & -(c & 1u));
	}
	return ~c;
}

static uint64_t fnv(const uint8_t *p, size_t n)
{
	uint64_t h = 0xcbf29ce484222325ull;

	for (size_t i = 0; i < n; i++)
		h = (h ^ p[i]) * 0x100000001b3ull;
	return h;
}

static unsigned long frames_ok, frames_bad, beacons;

/* A PSDU of `n` bytes that some receiver produced: checked, and reported if it holds. */
static int report(const char *phy, double mbps, double seconds, double snr_db, const uint8_t *m, size_t n)
{
	static const char *const kinds[16] = { "assoc-req", "assoc-resp", "reassoc-req", "reassoc-resp", "probe-req", "probe-resp",
					       "timing", "?", "beacon", "atim", "disassoc", "auth", "deauth", "action", "action-noack", "?" };
	unsigned type, sub;

	if (n < 14 || crc32_ieee(m, n - 4) != ((uint32_t)m[n - 4] | (uint32_t)m[n - 3] << 8 | (uint32_t)m[n - 2] << 16 | (uint32_t)m[n - 1] << 24)) {
		frames_bad++;
		return 0;
	}
	frames_ok++;
	type = m[0] >> 2 & 3; sub = m[0] >> 4;
	if (type != 0 || (sub != 8 && sub != 5)) {
		if (show_all)
			printf("%.6f %s %.4g Mbit/s %zu bytes type %u subtype %u\n", seconds, phy, mbps, n, type, sub);
		return 1;
	}
	if (n < 24 + 12 + 4)
		return 1;
	beacons += sub == 8;
	{
		const uint8_t *bssid = m + 16, *ie = m + 36, *end = m + n - 4, *ssid = NULL;
		unsigned ssid_len = 0, channel = 0;

		while (ie + 2 <= end && ie + 2 + ie[1] <= end) {
			if (ie[0] == 0 && !ssid) { ssid = ie + 2; ssid_len = ie[1]; }
			if (ie[0] == 3 && ie[1] == 1) channel = ie[2];
			if (ie[0] == 61 && ie[1] >= 1 && !channel) channel = ie[2];		/* HT operation: primary channel */
			ie += 2 + ie[1];
		}
		printf("%.6f %s %.4g Mbit/s %4zu bytes %-10s snr %4.1f dB channel %3u ", seconds, phy, mbps, n, kinds[sub], snr_db, channel);
		if (private_names) {
			printf("bssid #%08x ssid #%08x (%u bytes)\n", (unsigned)fnv(bssid, 6), (unsigned)fnv(ssid, ssid_len), ssid_len);
		} else {
			printf("bssid %02x:%02x:%02x:%02x:%02x:%02x ssid \"", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
			for (unsigned i = 0; i < ssid_len; i++)
				putchar(ssid[i] >= 32 && ssid[i] < 127 && ssid[i] != '"' ? ssid[i] : '.');
			printf("\"\n");
		}
	}
	return 1;
}

/* ---- DSSS (clause 15): Barker-11 at 11 Mchip/s, a symbol a microsecond ---------------------- */

static const int barker[11] = { 1, -1, 1, 1, -1, 1, 1, 1, -1, -1, -1 };

struct dsss {
	int sps;			/* samples a symbol */
	int *tmpl;			/* the Barker word, a chip at a time, at the sample rate */
	cf *corr;			/* the input despread, every sample */
	float *power;
	size_t n;
	unsigned long preambles, headers;
};

static void dsss_correlate(struct dsss *d, const cf *x, size_t n)
{
	int sps = d->sps;
	cf *pre = malloc((n + 1) * sizeof(cf));

	/* The template is +-1 over runs of samples: prefix sums make each chip two reads. */
	pre[0] = 0;
	for (size_t i = 0; i < n; i++)
		pre[i + 1] = pre[i] + x[i];
	d->corr = calloc(n, sizeof(cf)); d->power = calloc(n, sizeof(float)); d->n = n;
	for (size_t i = 0; i + sps <= n; i++) {
		cf acc = 0;

		for (int k = 0; k < 11; k++) {
			size_t a = i + (size_t)(k * sps / 11), b = i + (size_t)((k + 1) * sps / 11);

			acc += (float)barker[k] * (pre[b] - pre[a]);
		}
		d->corr[i] = acc;
		d->power[i] = crealf(acc) * crealf(acc) + cimagf(acc) * cimagf(acc);
	}
	free(pre);
}

/* One frame, tried from sample `at` (a correlation peak, on symbol timing). Returns the sample
 * after what it consumed, or 0 if nothing was there. */
static size_t dsss_frame(struct dsss *d, size_t at, double noise)
{
	static uint8_t psdu[4096];
	int sps = d->sps;
	uint32_t raw = 0, hist = 0;		/* raw differential bits; descrambled bits */
	uint64_t h64 = 0;
	unsigned state = 0, need = 0, got = 0, rate = 1, length = 0, sym = 0, nbytes = 0;
	cf prev = d->corr[at], rot = 1;
	double early = 0, late = 0, signal = 0;
	size_t pos = at;
	cf sq = 0;

	for (;; sym++) {
		cf cur, diff;
		unsigned bits, nb;

		pos += (size_t)sps;
		if (pos + (size_t)sps + 2 >= d->n)
			return 0;
		/* follow the sender's clock: lean towards whichever neighbour is stronger */
		early += d->power[pos - 1]; late += d->power[pos + 1];
		if ((sym & 15) == 15) {
			if (early > late * 1.3 && early > d->power[pos]) pos--;
			else if (late > early * 1.3 && late > d->power[pos]) pos++;
			early = late = 0;
		}
		cur = d->corr[pos];
		diff = cur * conjf(prev);
		prev = cur;
		if (state == 0)				/* the preamble is BPSK: its square gives the carrier offset */
			sq += diff * diff;
		diff *= rot;
		signal += d->power[pos];
		if (rate == 1 || state < 2) {
			bits = crealf(diff) < 0; nb = 1;
		} else {				/* 2 Mbit/s: DQPSK, phase change 0, 90, 180, 270 degrees = 00, 01, 11, 10, first bit first */
			float re = crealf(diff), im = cimagf(diff);

			if (fabsf(re) >= fabsf(im)) bits = re >= 0 ? 0 : 3;
			else bits = im >= 0 ? 2 : 1;	/* first bit sent is the low one here: 01 -> low 0, high 1 */
			nb = 2;
		}
		for (unsigned k = 0; k < nb; k++) {
			unsigned r = bits >> k & 1, o;

			o = r ^ (raw >> 3 & 1) ^ (raw >> 6 & 1);	/* self-synchronising descrambler, 1 + z^-4 + z^-7 */
			raw = raw << 1 | r;
			hist = hist << 1 | o;
			if (state == 0) {			/* scrambled ones, then the start-of-frame word 0xf3a0, low bit first */
				if (hist == 0xffff05cfu) {	/* sixteen ones, then the word */
					state = 1; need = 48; got = 0; d->preambles++;
					rot = cexpf(-I * cargf(sq) / 2);
					continue;
				}
				if (sym > 400)
					return 0;
			} else if (state == 1) {		/* SIGNAL, SERVICE, LENGTH, CRC: 48 bits */
				if (got == 0) h64 = 0;
				h64 |= (uint64_t)o << got;
				if (++got == need) {
					unsigned signal_f = h64 & 0xff, crc = 0xffff, sent = 0;

					length = (unsigned)(h64 >> 16 & 0xffff);
					for (unsigned b = 0; b < 32; b++) {
						unsigned fb = (crc >> 15 & 1) ^ (unsigned)(h64 >> b & 1);

						crc = crc << 1 & 0xffff;
						if (fb) crc ^= 0x1021;
					}
					for (unsigned b = 0; b < 16; b++)		/* sent high bit first */
						sent = sent << 1 | (unsigned)(h64 >> (32 + b) & 1);
					if (((~crc) & 0xffff) != sent)
						return pos;
					d->headers++;
					if (signal_f == 0x0a) rate = 1;
					else if (signal_f == 0x14) rate = 2;
					else return pos + (size_t)length * (size_t)sps;	/* 5.5 and 11 Mbit/s (CCK): not received here */
					nbytes = length * rate / 8;
					if (nbytes < 14 || nbytes > sizeof(psdu))
						return pos;
					state = 2; got = 0; memset(psdu, 0, nbytes);
					signal = 0;
				}
			} else {
				psdu[got >> 3] |= (uint8_t)(o << (got & 7));
				if (++got == nbytes * 8) {
					double snr = 10 * log10(signal / (double)(length ? length : 1) / (noise > 0 ? noise : 1));

					report("dsss", rate, (double)at / sample_rate, snr, psdu, nbytes);
					return pos + (size_t)sps;
				}
			}
		}
	}
}

static void dsss_run(const cf *x, size_t n)
{
	struct dsss d = { .sps = (int)(sample_rate / 1e6 + 0.5) };
	int sps = d.sps;
	size_t block = (size_t)sps * 32;
	double floor = 0;

	if (fabs(sample_rate / 1e6 - sps) > 1e-6) {
		fprintf(stderr, "dsss: the sample rate must be a whole number of Msps\n");
		return;
	}
	dsss_correlate(&d, x, n);
	{	/* the noise level of the despread signal: a low percentile of block means */
		size_t nb = n / block, k = 0;
		float *means = malloc(nb * sizeof(float));

		for (size_t b = 0; b < nb; b++) {
			double s = 0;

			for (size_t i = 0; i < block; i++) s += d.power[b * block + i];
			means[k++] = (float)(s / block);
		}
		for (size_t i = 1; i < k; i++) {		/* insertion sort of a few thousand */
			float v = means[i]; size_t j = i;

			while (j && means[j - 1] > v) { means[j] = means[j - 1]; j--; }
			means[j] = v;
		}
		floor = means[k / 10];
		free(means);
	}
	for (size_t at = 0; at + block * 4 < n;) {
		/* fold 32 symbols of despread power by position in the symbol: a DSSS signal piles up at one */
		static double fold[64];
		double total = 0, best = 0;
		int phase = 0;
		size_t next;

		for (int p = 0; p < sps; p++) fold[p] = 0;
		for (size_t i = 0; i < block; i++) fold[i % (size_t)sps] += d.power[at + i];
		for (int p = 0; p < sps; p++) { total += fold[p]; if (fold[p] > best) { best = fold[p]; phase = p; } }
		if (best < 6 * total / sps || best / 32 < 8 * floor) {
			at += block;
			continue;
		}
		next = dsss_frame(&d, at + (size_t)phase, floor);
		at = next > at + block ? next : at + block;
	}
	fprintf(stderr, "dsss: %lu preambles, %lu headers whose check held\n", d.preambles, d.headers);
	free(d.corr); free(d.power);
}

/* ---- OFDM (clause 17): 20 MHz, 64 carriers, a symbol every 4 microseconds --------------------
 * Rates with the half-rate code and no puncturing: 6 (BPSK), 12 (QPSK) and 24 Mbit/s (16-QAM).
 * Beacons go out at a network's lowest basic rate, which is nearly always 6. */

#define PI 3.14159265358979323846

static const int8_t ltf_seq[53] = { 1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 0,
				    1, -1, -1, 1, 1, -1, 1, -1, 1, -1, -1, -1, -1, -1, 1, 1, -1, -1, 1, -1, 1, -1, 1, 1, 1, 1 };

static void fft64(cf *v, int inverse)
{
	for (unsigned i = 1, j = 0; i < 64; i++) {
		unsigned bit = 32;

		for (; j & bit; bit >>= 1) j ^= bit;
		j ^= bit;
		if (i < j) { cf t = v[i]; v[i] = v[j]; v[j] = t; }
	}
	for (unsigned len = 2; len <= 64; len <<= 1) {
		cf wl = cexpf((inverse ? 2 : -2) * (float)PI * I / (float)len);

		for (unsigned i = 0; i < 64; i += len) {
			cf w = 1;

			for (unsigned k = 0; k < len / 2; k++, w *= wl) {
				cf a = v[i + k], b = v[i + k + len / 2] * w;

				v[i + k] = a + b; v[i + k + len / 2] = a - b;
			}
		}
	}
}

static int8_t pilot_polarity[127];
static int data_carrier[48];			/* subcarrier numbers -26..26 without the pilots and 0 */
static cf ltf_time[64];

static void ofdm_tables(void)
{
	unsigned state = 0x7f, n = 0;
	cf v[64];

	for (int i = 0; i < 127; i++) {		/* the scrambler from all ones: 0 -> +1, 1 -> -1 */
		unsigned fb = (state >> 3 ^ state >> 6) & 1;

		state = (state << 1 | fb) & 0x7f;
		pilot_polarity[i] = fb ? -1 : 1;
	}
	for (int k = -26; k <= 26; k++)
		if (k != 0 && k != -21 && k != -7 && k != 7 && k != 21)
			data_carrier[n++] = k;
	memset(v, 0, sizeof(v));
	for (int k = -26; k <= 26; k++)
		v[(k + 64) & 63] = ltf_seq[k + 26];
	fft64(v, 1);
	for (int i = 0; i < 64; i++) ltf_time[i] = v[i] / 64;
}

/* The half-rate K = 7 code (133, 171 octal), decoded from soft values (positive: a one). `n` data
 * bits out of 2n soft values; the encoder starts at zero. */
static void viterbi(const float *soft, uint8_t *bits, size_t n)
{
	static float metric[64], next[64];
	uint64_t *choice = malloc(n * sizeof(uint64_t));
	static int8_t out_a[128], out_b[128];
	static int ready;
	unsigned state;

	if (!ready) {
		for (unsigned r = 0; r < 128; r++) {
			out_a[r] = (int8_t)(__builtin_parity(r & 0x5b) ? 1 : -1);
			out_b[r] = (int8_t)(__builtin_parity(r & 0x79) ? 1 : -1);
		}
		ready = 1;
	}
	for (unsigned s = 0; s < 64; s++) metric[s] = s ? -1e30f : 0;
	for (size_t t = 0; t < n; t++) {
		float a = soft[2 * t], b = soft[2 * t + 1];
		uint64_t ch = 0;

		for (unsigned ns = 0; ns < 64; ns++) {
			unsigned in = ns >> 5, p0 = (ns & 31) << 1, p1 = p0 | 1;
			unsigned r0 = in << 6 | p0, r1 = in << 6 | p1;
			float m0 = metric[p0] + out_a[r0] * a + out_b[r0] * b;
			float m1 = metric[p1] + out_a[r1] * a + out_b[r1] * b;

			if (m1 > m0) { next[ns] = m1; ch |= 1ull << ns; } else next[ns] = m0;
		}
		memcpy(metric, next, sizeof(metric));
		choice[t] = ch;
	}
	state = 0;
	{	/* the tail brings the encoder back to zero; if it did not, start from the best survivor */
		float best = metric[0];

		for (unsigned s = 1; s < 64; s++)
			if (metric[s] > best + 1e-3f * fabsf(best)) { best = metric[s]; state = s; }
	}
	for (size_t t = n; t-- > 0;) {
		bits[t] = (uint8_t)(state >> 5);
		state = (state & 31) << 1 | (unsigned)(choice[t] >> state & 1);
	}
	free(choice);
}

/* Where coded bit k of a symbol is sent (17.3.5.7). */
static unsigned interleave(unsigned k, unsigned ncbps, unsigned nbpsc)
{
	unsigned s = nbpsc / 2 ? nbpsc / 2 : 1;
	unsigned i = (ncbps / 16) * (k % 16) + k / 16;

	return s * (i / s) + (i + ncbps - 16 * i / ncbps) % s;
}

struct ofdm_rx {
	const cf *x;			/* 20 Msps */
	size_t n;
	double cfo;			/* radians a sample */
	size_t origin;
	cf h[64];
};

static inline cf ofdm_at(const struct ofdm_rx *r, size_t i)
{
	double ph = -r->cfo * (double)((long long)i - (long long)r->origin);

	return r->x[i] * (cf)(cos(ph) + I * sin(ph));
}

/* One symbol whose 64-sample body starts at `at`: its 48 data values as soft bits. */
static void ofdm_symbol(const struct ofdm_rx *r, size_t at, int polarity, unsigned nbpsc, float *soft, unsigned ncbps)
{
	static const int pilots[4] = { -21, -7, 7, 21 };
	static const int pilot_sign[4] = { 1, 1, 1, -1 };
	cf v[64], cpe = 0, rot;

	for (int i = 0; i < 64; i++) v[i] = ofdm_at(r, at + (size_t)i);
	fft64(v, 0);
	for (int p = 0; p < 4; p++) {
		unsigned bin = (unsigned)(pilots[p] + 64) & 63;

		cpe += v[bin] * conjf(r->h[bin]) * (float)(pilot_sign[p] * polarity);
	}
	rot = cabsf(cpe) > 0 ? conjf(cpe) / cabsf(cpe) : 1;
	for (unsigned d = 0; d < 48; d++) {
		unsigned bin = (unsigned)(data_carrier[d] + 64) & 63;
		cf z = v[bin] * conjf(r->h[bin]) * rot;		/* weighted by the carrier's strength */
		float g = crealf(r->h[bin] * conjf(r->h[bin])), re = crealf(z), im = cimagf(z);
		float bit[4];

		if (nbpsc == 1) {
			bit[0] = re;
		} else if (nbpsc == 2) {
			bit[0] = re; bit[1] = im;
		} else {			/* 16-QAM: points at +-1, +-3 times 1/sqrt(10) */
			float u = 3.16227766f;

			bit[0] = re * u; bit[1] = 2 * g - fabsf(re * u); bit[2] = im * u; bit[3] = 2 * g - fabsf(im * u);
		}
		for (unsigned b = 0; b < nbpsc; b++) {
			unsigned sent = d * nbpsc + b;			/* position on the air */

			/* find the coded bit that was sent there */
			soft[sent] = bit[b];
		}
	}
	{	/* undo the interleaver: coded bit k was sent at interleave(k) */
		static float tmp[192];

		memcpy(tmp, soft, ncbps * sizeof(float));
		for (unsigned k = 0; k < ncbps; k++)
			soft[k] = tmp[interleave(k, ncbps, nbpsc)];
	}
}

static unsigned long ofdm_detections, ofdm_signals;

/* A frame whose short training starts near `start`. Returns the sample after it, or 0. */
static size_t ofdm_frame(struct ofdm_rx *r, size_t start, cf coarse, double noise)
{
	static uint8_t bits[8 * 4200], psdu[4200];
	static float soft[192 * 1400];
	const int back = 3;			/* take each symbol this many samples early, inside its guard interval */
	size_t best = 0, sig, nsym;
	double bestv = 0, power = 0;
	float s48[48];
	uint8_t sb[24];
	unsigned rate, length, parity = 0, nbpsc, ncbps, ndbps;
	double mbps;
	cf fine = 0, v1[64], v2[64];

	if (start + 2000 >= r->n)
		return 0;
	r->origin = start;
	r->cfo = -carg(coarse) / 16.0;
	/* the two long training symbols: the pair of places 64 apart that best match the known one */
	for (size_t i = start; i < start + 420 && i + 200 < r->n; i++) {
		cf a = 0, b = 0;
		double v;

		for (int k = 0; k < 64; k++) {
			a += ofdm_at(r, i + (size_t)k) * conjf(ltf_time[k]);
			b += ofdm_at(r, i + 64 + (size_t)k) * conjf(ltf_time[k]);
		}
		v = cabsf(a) + cabsf(b);
		if (v > bestv) { bestv = v; best = i; }
	}
	for (int k = 0; k < 64; k++)
		fine += ofdm_at(r, best + (size_t)k) * conjf(ofdm_at(r, best + 64 + (size_t)k));
	r->cfo += -carg(fine) / 64.0;
	for (int k = 0; k < 64; k++) {
		v1[k] = ofdm_at(r, best - back + (size_t)k);
		v2[k] = ofdm_at(r, best - back + 64 + (size_t)k);
		power += creal(v1[k] * conjf(v1[k]));
	}
	fft64(v1, 0); fft64(v2, 0);
	memset(r->h, 0, sizeof(r->h));
	for (int k = -26; k <= 26; k++)
		if (k) {
			unsigned bin = (unsigned)(k + 64) & 63;

			r->h[bin] = (v1[bin] + v2[bin]) * 0.5f * (float)ltf_seq[k + 26];
		}
	/* SIGNAL: one BPSK symbol, 24 bits */
	sig = best + 128 + 16 - back;
	ofdm_symbol(r, sig, pilot_polarity[0], 1, s48, 48);
	viterbi(s48, sb, 24);
	rate = sb[0] | sb[1] << 1 | sb[2] << 2 | sb[3] << 3;
	length = 0;
	for (unsigned b = 0; b < 12; b++) length |= (unsigned)sb[5 + b] << b;
	for (unsigned b = 0; b < 18; b++) parity ^= sb[b];
	if (parity || sb[4] || sb[18] | sb[19] | sb[20] | sb[21] | sb[22] | sb[23] || length < 14 || length > 4095)
		return 0;
	ofdm_signals++;
	switch (rate) {				/* R1..R4 as sent, R1 in bit 0 */
	case 0xb: mbps = 6; nbpsc = 1; break;
	case 0xa: mbps = 12; nbpsc = 2; break;
	case 0x9: mbps = 24; nbpsc = 4; break;
	default: {				/* the punctured rates: not received here; step over the frame */
		static const struct { unsigned code, dbps; } other[] = { { 0xf, 36 }, { 0xe, 72 }, { 0xd, 144 }, { 0x8, 192 }, { 0xc, 216 } };

		for (unsigned i = 0; i < 5; i++)
			if (other[i].code == rate)
				return sig + 80 * (1 + (16 + 8 * (size_t)length + 6 + other[i].dbps - 1) / other[i].dbps);
		return 0;
	}
	}
	ncbps = 48 * nbpsc; ndbps = ncbps / 2;
	nsym = (16 + 8 * (size_t)length + 6 + ndbps - 1) / ndbps;
	if (nsym > 1400 || sig + 80 * (nsym + 1) + 64 >= r->n)
		return 0;
	for (size_t s = 0; s < nsym; s++)
		ofdm_symbol(r, sig + 80 * (s + 1), pilot_polarity[(s + 1) % 127], nbpsc, soft + s * ncbps, ncbps);
	viterbi(soft, bits, nsym * ndbps);
	{	/* the scrambler's sequence shows in the first seven bits, which were zeros */
		uint8_t seq[7];

		memcpy(seq, bits, 7);
		for (size_t k = 7; k < 16 + 8 * (size_t)length; k++) {
			uint8_t sq = seq[(k - 4) % 7] ^ seq[k % 7];	/* seq[k-7] is in slot k % 7 */

			seq[k % 7] = sq;
			bits[k] ^= sq;
		}
	}
	memset(psdu, 0, length);
	for (size_t k = 0; k < 8 * (size_t)length; k++)
		psdu[k >> 3] |= (uint8_t)(bits[16 + k] << (k & 7));
	report("ofdm", mbps, (double)start / 20e6, 10 * log10(power / 64 / (noise > 0 ? noise : 1)), psdu, length);
	return sig + 80 * (nsym + 1);
}

static void ofdm_run(const cf *x, size_t n)
{
	struct ofdm_rx r = { 0 };
	cf *y;
	size_t m;
	double noise;

	ofdm_tables();
	if (fabs(sample_rate - 40e6) < 1) {		/* to 20 Msps: a low-pass at 9.5 MHz, every other sample */
		enum { TAPS = 47 };
		float h[TAPS], sum = 0;

		for (int k = 0; k < TAPS; k++) {
			double t = k - (TAPS - 1) / 2.0, c = 2 * 9.5 / 40.0;

			h[k] = (float)((t == 0 ? c : sin(PI * c * t) / (PI * t)) * (0.54 - 0.46 * cos(2 * PI * k / (TAPS - 1))));
			sum += h[k];
		}
		for (int k = 0; k < TAPS; k++) h[k] /= sum;
		m = (n - TAPS) / 2;
		y = malloc(m * sizeof(cf));
		for (size_t i = 0; i < m; i++) {
			cf acc = 0;

			for (int k = 0; k < TAPS; k++) acc += x[2 * i + (size_t)k] * h[k];
			y[i] = acc;
		}
	} else if (fabs(sample_rate - 20e6) < 1) {
		m = n; y = malloc(m * sizeof(cf)); memcpy(y, x, m * sizeof(cf));
	} else {
		fprintf(stderr, "ofdm: 20 or 40 Msps\n");
		return;
	}
	r.x = y; r.n = m;
	{	/* the noise level: a low percentile of block powers */
		size_t nb = m / 400, k = 0;
		float *means = malloc(nb * sizeof(float));

		for (size_t b = 0; b < nb; b++) {
			double s = 0;

			for (size_t i = 0; i < 400; i++) s += creal(y[b * 400 + i] * conjf(y[b * 400 + i]));
			means[k++] = (float)(s / 400);
		}
		for (size_t i = 1; i < k; i++) { float v = means[i]; size_t j = i; while (j && means[j - 1] > v) { means[j] = means[j - 1]; j--; } means[j] = v; }
		noise = means[k / 10];
		free(means);
	}
	{	/* the short training repeats every 16 samples: correlate the signal with itself 16 later */
		cf a = 0;
		double p = 0;
		unsigned run = 0;
		const size_t W = 48;

		for (size_t i = 0; i + W + 16 + 1 < m; i++) {
			if (i == 0)
				for (size_t k = 0; k < W; k++) { a += y[k] * conjf(y[k + 16]); p += creal(y[k + 16] * conjf(y[k + 16])); }
			if (cabsf(a) > 0.75 * p && p / W > 6 * noise) {
				if (++run == 40) {
					size_t next = ofdm_frame(&r, i > 60 ? i - 60 : 0, a, noise);

					ofdm_detections++;
					run = 0;
					if (next > i + 1 && next + W + 20 < m) {	/* jump past the frame: start the sums afresh there */
						i = next;
						a = 0; p = 0;
						for (size_t k = 0; k < W; k++) { a += y[i + k] * conjf(y[i + k + 16]); p += creal(y[i + k + 16] * conjf(y[i + k + 16])); }
						continue;
					}
				}
			} else {
				run = 0;
			}
			a += y[i + W] * conjf(y[i + W + 16]) - y[i] * conjf(y[i + 16]);
			p += creal(y[i + W + 16] * conjf(y[i + W + 16])) - creal(y[i + 16] * conjf(y[i + 16]));
		}
	}
	fprintf(stderr, "ofdm: %lu short trainings found, %lu SIGNAL fields that held\n", ofdm_detections, ofdm_signals);
	free(y);
}

int main(int argc, char **argv)
{
	const char *path = NULL;
	FILE *f;
	long bytes;
	int16_t *raw;
	cf *x;
	size_t n;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--rate") && i + 1 < argc) sample_rate = atof(argv[++i]) * 1e6;
		else if (!strcmp(argv[i], "--private")) private_names = 1;
		else if (!strcmp(argv[i], "--all")) show_all = 1;
		else path = argv[i];
	}
	if (!path || sample_rate <= 0) {
		fprintf(stderr, "usage: wifi-beacons FILE --rate 40|20 [--private] [--all]\n");
		return 2;
	}
	f = fopen(path, "rb");
	if (!f) { perror(path); return 1; }
	fseek(f, 0, SEEK_END); bytes = ftell(f); fseek(f, 0, SEEK_SET);
	n = (size_t)bytes / 4;
	raw = malloc(n * 4); x = malloc(n * sizeof(cf));
	if (fread(raw, 4, n, f) != n) { perror("read"); return 1; }
	fclose(f);
	for (size_t i = 0; i < n; i++)
		x[i] = raw[2 * i] + I * raw[2 * i + 1];
	free(raw);
	dsss_run(x, n);
	ofdm_run(x, n);
	fprintf(stderr, "%.3f s of samples: %lu frames whose check held (%lu beacons), %lu that did not\n", n / sample_rate, frames_ok, beacons, frames_bad);
	return 0;
}
