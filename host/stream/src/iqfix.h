// SPDX-License-Identifier: MIT
// The receiver's own DC offset and I/Q imbalance, taken out of the samples ("iq_correct").
//
// The radio's I and Q branches differ a little in gain and are not quite 90 degrees apart, which
// puts a mirror image of every signal at minus its frequency (-36 to -47 dBc on one W1700K's three
// radios), and each branch has an offset (up to about -230 counts, -31 dBFS). Its RX IQ
// compensation filters sit after the capture tap (docs/architecture.md), so the stream carries
// both as the radio made them.
//
// The correction is blind: it goes by the stream's own statistics, which for anything a receiver
// takes in (noise, a tone, a modulated signal off the LO) have I and Q of equal power, uncorrelated,
// and without a mean. Over 2^20 samples (a quarter of the slots measured) it estimates the means
// m_I, m_Q, the powers P_I, P_Q and the covariance C of I and Q, and from them
//     I' = I - m_I
//     Q' = g ((Q - m_Q) + c (I - m_I)),   c = -C / P_I,   g = sqrt(P_I / (P_Q - C^2 / P_I))
// (Q made orthogonal to I and of I's power: a Gram-Schmidt step). g and c are taken only from an
// estimate in which a signal stands out of the noise (IqSums::signal); the means from every one.
// Each estimate counts a quarter towards the parameters in use (the first counts whole), so they
// settle within a few estimates:
// about 0.1 s at 160 Msps, 0.4 s at 40, and follow a change of gain or LO as quickly. A run starts
// from no correction. The correction is one gain and one cross term for the whole band (the
// imbalance that varies with frequency is left: host/stream/README.md has what is left, measured).
// It also takes out a signal exactly at the LO, as any DC correction does.
#pragma once

#include <cstdint>
#include <mutex>

struct IqParams {
    float dc_i = 0, dc_q = 0;  // counts taken off I and Q
    float gain = 1, cross = 0;  // Q' = gain * ((Q - dc_q) + cross * (I - dc_i))
};

struct IqSums {
    static constexpr unsigned kBins = 512;  // the spectrum that says whether a signal is there
    int64_t n = 0, si = 0, sq = 0, sii = 0, sqq = 0, siq = 0;
    float spec[kBins] = {};                 // power by bin (FFT order), summed over `frames` transforms
    uint32_t frames = 0;
    // `count` int16 I, Q pairs
    void add(const int16_t *iq, unsigned count);
    // one kBins-point power spectrum of the stream (the caller's transform)
    void add_spectrum(const float *power);
    void add(const IqSums &o);
    // Something stands out of the noise: the strongest bin (DC and its neighbours left out) at least
    // kSignalRatio times the median bin. Without it the statistics are the receiver's own noise, whose
    // I and Q at the lowest gains come mostly from the two baseband chains separately and so do not
    // carry the RF path's imbalance (measured: a noise-only estimate left a weak signal's image 4 to
    // 5 dB worse than none on the 6 GHz radio).
    static constexpr float kSignalRatio = 10;  // 10 dB
    bool signal() const;
};

// `count` int16 I, Q pairs corrected in place by `p`; returns how many components saturated.
uint64_t iq_apply(const IqParams &p, int16_t *iq, unsigned count);

// One channel's estimate, shared by the workers.
class IqEstimator {
public:
    static constexpr int64_t kSamples = int64_t(1) << 20;  // measured samples per estimate
    static constexpr double kWeight = 0.25;                 // of each estimate after the first
    // An estimate outside these is not the receiver's imbalance (an improper signal, or nothing
    // but zeros): it is left out.
    static constexpr double kGainMin = 0.7, kGainMax = 1.4, kCrossMax = 0.3;

    void reset();
    IqParams params() const;
    // Sums folded in; every kSamples an estimate: the offsets always, the gain and cross term only
    // when a signal stands out of the noise (IqSums::signal); without spectra (frames 0), always.
    void add(const IqSums &s);
    uint64_t estimates() const;  // folded in since the last reset (offsets alone counted too)
    uint64_t imbalance_estimates() const;  // ... of which with the gain and cross term
    // An estimate from sums alone (static: tests and the folding above); false if left out.
    static bool estimate(const IqSums &s, IqParams *out);

private:
    mutable std::mutex mutex_;
    IqSums acc_;
    IqParams params_;
    uint64_t estimates_ = 0, imbalance_estimates_ = 0;
};
