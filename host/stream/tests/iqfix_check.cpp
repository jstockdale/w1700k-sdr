// SPDX-License-Identifier: MIT
// The DC and I/Q correction (src/iqfix.cpp) against the rule written out plainly: the sums of a slice exactly (the
// SSE2 form keeps its products apart and adds them as doubles), the correction to within one count of the arithmetic
// done in double (float rounding), the saturation count, and the estimate of a known imbalance. Prints the
// differences; exit 1 on any.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

#include "../src/iqfix.h"

int main()
{
    std::mt19937 rng(1);
    std::uniform_int_distribution<int> any(-32768, 32767), radio(-8192, 8191);
    unsigned differ = 0, cases = 0;

    // sums: odd lengths (the plain tail), the int16 range's ends, the radio's range
    for (int t = 0; t < 300; ++t, ++cases) {
        const unsigned n = 1 + rng() % 5000;
        std::vector<int16_t> v(2 * n);
        for (auto &x : v) x = int16_t(t % 3 == 0 ? (rng() & 1 ? 32767 : -32768) : t % 3 == 1 ? any(rng) : radio(rng));
        IqSums s;
        s.add(v.data(), n);
        int64_t a = 0, b = 0, aa = 0, bb = 0, ab = 0;
        for (unsigned k = 0; k < n; ++k) {
            const int64_t i = v[2 * k], q = v[2 * k + 1];
            a += i, b += q, aa += i * i, bb += q * q, ab += i * q;
        }
        if (a != s.si || b != s.sq || aa != s.sii || bb != s.sqq || ab != s.siq || int64_t(n) != s.n) {
            if (++differ < 5) std::printf("sums differ: case %d, %u pairs\n", t, n);
        }
    }

    // the correction against double arithmetic; saturation counted where a component reaches the int16 range's end
    for (int t = 0; t < 300; ++t, ++cases) {
        const unsigned n = 1 + rng() % 3000;
        IqParams p;
        p.dc_i = float(radio(rng)) / 16; p.dc_q = float(radio(rng)) / 16;
        p.gain = 1 + float(int(rng() % 2001) - 1000) / 10000; p.cross = float(int(rng() % 2001) - 1000) / 20000;
        std::vector<int16_t> v(2 * n);
        for (auto &x : v) x = int16_t(t % 5 == 0 ? any(rng) : radio(rng));
        std::vector<int16_t> w = v;
        const uint64_t clipped = iq_apply(p, w.data(), n);
        uint64_t want_clipped = 0;
        unsigned off = 0;
        for (unsigned k = 0; k < n; ++k) {
            const double i = v[2 * k] - double(p.dc_i), q = v[2 * k + 1] - double(p.dc_q);
            const double y[2] = {i, double(p.gain) * (q + double(p.cross) * i)};
            for (int j = 0; j < 2; ++j) {
                double r = std::nearbyint(y[j]);
                if (r >= 32767 || r <= -32768) {
                    ++want_clipped;
                    r = r > 0 ? 32767 : -32768;
                }
                if (std::fabs(r - w[2 * k + j]) > 1) ++off;
            }
        }
        // a value within one count of the range's end may be counted on one side and not the other
        if (off || (clipped > want_clipped + n / 50 + 2) || (want_clipped > clipped + n / 50 + 2)) {
            if (++differ < 5) std::printf("correction differs: case %d, %u off by more than a count, clipped %llu want %llu\n", t,
                                          off, (unsigned long long)clipped, (unsigned long long)want_clipped);
        }
    }

    // the estimate of a known imbalance (a tone and some noise)
    {
        ++cases;
        const unsigned n = 1u << 20;
        std::normal_distribution<double> noise(0, 40);
        std::vector<int16_t> v(2 * n);
        const double g = 1.05, phi = 3.0 * M_PI / 180;
        for (unsigned k = 0; k < n; ++k) {
            const double th = 2 * M_PI * 0.0917 * k, re = 3000 * std::cos(th) + noise(rng), im = 3000 * std::sin(th) + noise(rng);
            v[2 * k] = int16_t(std::lrint(re + 150));
            v[2 * k + 1] = int16_t(std::lrint(g * (im * std::cos(phi) - re * std::sin(phi)) - 80));
        }
        IqSums s;
        s.add(v.data(), n);
        IqParams e;
        const bool ok = IqEstimator::estimate(s, &e);
        if (!ok || std::fabs(e.dc_i - 150) > 0.5 || std::fabs(e.dc_q + 80) > 0.5 || std::fabs(e.gain - 1 / (g * std::cos(phi))) > 1e-3 ||
            std::fabs(e.cross - g * std::sin(phi)) > 1e-3) {
            ++differ;
            std::printf("estimate: %d dc %.2f %.2f gain %.5f cross %.5f\n", ok, e.dc_i, e.dc_q, e.gain, e.cross);
        }
    }
    // the signal test: a flat spectrum (noise) is not a signal, a line 10 dB over the median is, DC does not count
    {
        cases += 3;
        IqSums flat, line, dc;
        std::vector<float> p(IqSums::kBins);
        std::exponential_distribution<float> chi2(1.0f);   // one bin of complex noise
        for (int f = 0; f < 32; ++f) {
            for (auto &v : p) v = chi2(rng);
            flat.add_spectrum(p.data());
            p[100] += 15.0f; line.add_spectrum(p.data());
            p[100] -= 15.0f; p[0] += 1000.0f; p[1] += 500.0f; dc.add_spectrum(p.data());
        }
        if (flat.signal() || !line.signal() || dc.signal()) {
            ++differ;
            std::printf("signal test: flat %d line %d dc %d\n", flat.signal(), line.signal(), dc.signal());
        }
    }
    std::printf("iqfix: %u cases, %u differ\n", cases, differ);
    return differ ? 1 : 0;
}
