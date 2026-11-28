// SPDX-License-Identifier: MIT
#include "iqfix.h"

#include <algorithm>
#include <cmath>

#if defined(__SSE2__)
#include <emmintrin.h>
#endif

void IqSums::add(const int16_t *iq, unsigned count)
{
    // exact: |I|, |Q| <= 2^15, so a slice's squares stay far inside 64 bits (and inside a double's 53)
    int64_t a = 0, b = 0, aa = 0, bb = 0, ab = 0;
    unsigned k = 0;
#if defined(__SSE2__)
    // four pairs at a time: each product alone in its 32-bit lane (the other half of the pair zeroed), at most 2^30;
    // the products summed as doubles, the plain sums in 32 bits (2^15 x 2^15 at most per lane before they are added up)
    const __m128i mi = _mm_set1_epi32(0x0000ffff), mq = _mm_set1_epi32(int(0xffff0000u));
    const __m128i one_i = _mm_set1_epi32(1), one_q = _mm_set1_epi32(0x00010000);
    __m128i li4 = _mm_setzero_si128(), lq4 = _mm_setzero_si128();
    __m128d s2[6] = {_mm_setzero_pd(), _mm_setzero_pd(), _mm_setzero_pd(), _mm_setzero_pd(), _mm_setzero_pd(), _mm_setzero_pd()};
    const unsigned whole = count & ~3u, chunk = 4u * 32768u;  // lane sums of I or Q stay inside 32 bits over a chunk
    for (unsigned at = 0; at < whole; at += chunk) {
        const unsigned end = at + chunk < whole ? at + chunk : whole;
        for (k = at; k < end; k += 4) {
            const __m128i x = _mm_loadu_si128(reinterpret_cast<const __m128i *>(iq + 2 * k));
            const __m128i xi = _mm_and_si128(x, mi), xq = _mm_and_si128(x, mq);
            const __m128i xs = _mm_shufflehi_epi16(_mm_shufflelo_epi16(x, _MM_SHUFFLE(2, 3, 0, 1)), _MM_SHUFFLE(2, 3, 0, 1));
            li4 = _mm_add_epi32(li4, _mm_madd_epi16(x, one_i));
            lq4 = _mm_add_epi32(lq4, _mm_madd_epi16(x, one_q));
            const __m128i p[3] = {_mm_madd_epi16(xi, xi), _mm_madd_epi16(xq, xq), _mm_madd_epi16(xi, xs)};
            for (int j = 0; j < 3; ++j) {
                s2[2 * j] = _mm_add_pd(s2[2 * j], _mm_cvtepi32_pd(p[j]));
                s2[2 * j + 1] = _mm_add_pd(s2[2 * j + 1], _mm_cvtepi32_pd(_mm_shuffle_epi32(p[j], _MM_SHUFFLE(1, 0, 3, 2))));
            }
        }
        alignas(16) int32_t li[4], lq[4];
        _mm_store_si128(reinterpret_cast<__m128i *>(li), li4);
        _mm_store_si128(reinterpret_cast<__m128i *>(lq), lq4);
        for (int j = 0; j < 4; ++j) {
            a += li[j];
            b += lq[j];
        }
        li4 = lq4 = _mm_setzero_si128();
    }
    alignas(16) double d[12];
    for (int j = 0; j < 6; ++j) _mm_store_pd(d + 2 * j, s2[j]);
    aa += int64_t(d[0] + d[1] + d[2] + d[3]);
    bb += int64_t(d[4] + d[5] + d[6] + d[7]);
    ab += int64_t(d[8] + d[9] + d[10] + d[11]);
    k = whole;
#endif
    for (; k < count; ++k) {
        const int32_t i = iq[2 * k], q = iq[2 * k + 1];
        a += i;
        b += q;
        aa += i * i;
        bb += q * q;
        ab += i * q;
    }
    n += count;
    si += a;
    sq += b;
    sii += aa;
    sqq += bb;
    siq += ab;
}

void IqSums::add(const IqSums &o)
{
    n += o.n;
    si += o.si;
    sq += o.sq;
    sii += o.sii;
    sqq += o.sqq;
    siq += o.siq;
    for (unsigned k = 0; k < kBins; ++k) spec[k] += o.spec[k];
    frames += o.frames;
}

void IqSums::add_spectrum(const float *power)
{
    for (unsigned k = 0; k < kBins; ++k) spec[k] += power[k];
    ++frames;
}

bool IqSums::signal() const
{
    float v[kBins];
    unsigned m = 0;
    for (unsigned k = 3; k <= kBins - 3; ++k) v[m++] = spec[k];  // DC (bin 0) and two bins either side left out
    float peak = 0;
    for (unsigned k = 0; k < m; ++k) peak = std::max(peak, v[k]);
    std::nth_element(v, v + m / 2, v + m);
    return frames && peak >= kSignalRatio * v[m / 2];
}

uint64_t iq_apply(const IqParams &p, int16_t *iq, unsigned count)
{
    // I' = I - dc_i; Q' = gain Q + gain cross I - gain (dc_q + cross dc_i)
    const float gc = p.gain * p.cross, off_i = -p.dc_i, off_q = -p.gain * (p.dc_q + p.cross * p.dc_i);
    uint64_t clipped = 0;
    unsigned k = 0;
#if defined(__SSE2__)
    const __m128 m1 = _mm_setr_ps(1.0f, p.gain, 1.0f, p.gain), m2 = _mm_setr_ps(0.0f, gc, 0.0f, gc);
    const __m128 c = _mm_setr_ps(off_i, off_q, off_i, off_q);
    const __m128i top = _mm_set1_epi16(32767), bottom = _mm_set1_epi16(-32768);
    for (; k + 4 <= count; k += 4) {  // four pairs: eight int16
        const __m128i x = _mm_loadu_si128(reinterpret_cast<const __m128i *>(iq + 2 * k));
        const __m128 v0 = _mm_cvtepi32_ps(_mm_srai_epi32(_mm_unpacklo_epi16(x, x), 16));  // I0 Q0 I1 Q1
        const __m128 v1 = _mm_cvtepi32_ps(_mm_srai_epi32(_mm_unpackhi_epi16(x, x), 16));  // I2 Q2 I3 Q3
        const __m128 i0 = _mm_shuffle_ps(v0, v0, _MM_SHUFFLE(2, 2, 0, 0)), i1 = _mm_shuffle_ps(v1, v1, _MM_SHUFFLE(2, 2, 0, 0));
        const __m128 y0 = _mm_add_ps(_mm_add_ps(_mm_mul_ps(v0, m1), _mm_mul_ps(i0, m2)), c);
        const __m128 y1 = _mm_add_ps(_mm_add_ps(_mm_mul_ps(v1, m1), _mm_mul_ps(i1, m2)), c);
        const __m128i y = _mm_packs_epi32(_mm_cvtps_epi32(y0), _mm_cvtps_epi32(y1));  // saturating
        // a component at the int16 range's end was clipped there (the radio's own reach 8192 at most)
        const int over = _mm_movemask_epi8(_mm_or_si128(_mm_cmpeq_epi16(y, top), _mm_cmpeq_epi16(y, bottom)));
        if (over) clipped += unsigned(__builtin_popcount(unsigned(over))) / 2;
        _mm_storeu_si128(reinterpret_cast<__m128i *>(iq + 2 * k), y);
    }
#endif
    for (; k < count; ++k) {
        const float i = iq[2 * k], q = iq[2 * k + 1];
        const float y[2] = {i + off_i, (q * p.gain + i * gc) + off_q};
        for (unsigned j = 0; j < 2; ++j) {
            float v = std::nearbyint(y[j]);
            if (v >= 32767.0f || v <= -32768.0f) {  // as the SSE2 form counts it
                ++clipped;
                v = v > 0 ? 32767.0f : -32768.0f;
            }
            iq[2 * k + j] = int16_t(v);
        }
    }
    return clipped;
}

bool IqEstimator::estimate(const IqSums &s, IqParams *out)
{
    if (s.n < 2) return false;
    const double n = double(s.n), mi = s.si / n, mq = s.sq / n;
    const double pii = s.sii / n - mi * mi, pqq = s.sqq / n - mq * mq, piq = s.siq / n - mi * mq;
    if (!(pii > 1e-3) || !(pqq > 1e-3)) return false;  // nothing but a constant
    const double cross = -piq / pii, rest = pqq - piq * piq / pii;
    if (!(rest > 0)) return false;
    const double gain = std::sqrt(pii / rest);
    if (!(gain >= kGainMin && gain <= kGainMax) || std::fabs(cross) > kCrossMax) return false;
    out->dc_i = float(mi);
    out->dc_q = float(mq);
    out->gain = float(gain);
    out->cross = float(cross);
    return true;
}

void IqEstimator::reset()
{
    std::lock_guard<std::mutex> lock(mutex_);
    acc_ = IqSums();
    params_ = IqParams();
    estimates_ = imbalance_estimates_ = 0;
}

IqParams IqEstimator::params() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return params_;
}

uint64_t IqEstimator::estimates() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return estimates_;
}

uint64_t IqEstimator::imbalance_estimates() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return imbalance_estimates_;
}

void IqEstimator::add(const IqSums &s)
{
    std::lock_guard<std::mutex> lock(mutex_);
    acc_.add(s);
    if (acc_.n < kSamples) return;
    IqParams e;
    if (estimate(acc_, &e)) {
        float w = estimates_ ? float(kWeight) : 1.0f;
        params_.dc_i += w * (e.dc_i - params_.dc_i);
        params_.dc_q += w * (e.dc_q - params_.dc_q);
        ++estimates_;
        if (!acc_.frames || acc_.signal()) {   // the imbalance only from a signal (IqSums::signal)
            w = imbalance_estimates_ ? float(kWeight) : 1.0f;
            params_.gain += w * (e.gain - params_.gain);
            params_.cross += w * (e.cross - params_.cross);
            ++imbalance_estimates_;
        }
    }
    acc_ = IqSums();
}
