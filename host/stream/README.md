# w1700k-stream

The host's one receiver of the W1700K's UDP export. It puts the stream in order, unpacks it and
serves it, as complex int16 IQ, to every consumer on the host through shared memory:
`w1700k-spectrum`, `sdr-recv`, the SoapySDR module ([`../soapy`](../soapy/README.md)), or any program that
maps the ring. It takes the receiver's own DC offset and I/Q imbalance out of the samples
([below](#the-receivers-dc-and-iq-imbalance-iq_correct)), and on request it also corrects the
stream for the radio's decimation roll-off ("flatten"), in the samples themselves, so that every
consumer gets the corrected stream.

## Build and run

Needs a C++17 compiler and FFTW3 in single precision (Debian/Ubuntu:
`apt install g++ make libfftw3-dev`).

```sh
make                                   # build/w1700k-stream
make CXXFLAGS="-O3 -march=native"      # tuned for this CPU
build/w1700k-stream                    # until Ctrl-C; consumers attach any time
```

| option | default | |
|---|---|---|
| `--bind IP` | `10.77.0.10` | the stream's destination address on this host (the 10G link) |
| `--port N` | `7700` | its UDP port |
| `--unit IP` | any sender | take the stream from this sender alone, the unit's address on the link (`10.77.0.1`) |
| `--rx-threads N` | 8 | UDP sockets and receive threads (`SO_REUSEPORT`; the unit spreads its source ports) |
| `--workers N` | 6 | threads that unpack and correct |
| `--ring-mib N` | 512 | the shared ring, a power of two (512 MiB holds 0.42 s at 320 Msps) |
| `--name NAME` | `/w1700k-stream` | the shared-memory object (`/dev/shm/w1700k-stream`) |
| `--report S` | 0 | a JSON status line on stdout every S seconds |
| `--share-irq-cpu` | | run also on the CPU that takes the interface's packets (see below) |
| `--deep-idle` | | let the host idle as deeply as it likes while a stream arrives (see below) |
| `--own-priority` | | run at the priority it was started with (see below) |
| `--iq-correct on\|off` | `on` | take the receiver's DC offset and I/Q imbalance out of the samples (below); consumers can change it at any time (`iq_correct`) |
| `--measure-plans` | | serve nothing: measure the correction's FFT plans and keep them (see "The correction") |

The object is the user's who runs the service, and its consumers run as that user: it is made
readable and writable by its owner alone, and a consumer opens only an object that is its own
user's, that nobody else may write, and whose layout lies inside it. On a host with other users
that keeps one of them from making an object under the name first and being read as the radio.
The service says so when the name is held by somebody else; `--name` gives it and its consumers
another.

Where one CPU takes every packet of the interface that holds the bind address (an interface
with a single receive queue, such as a USB adapter: the CPU its interrupt is delivered to), the
service keeps its threads off that CPU, looks again every two seconds, and names the CPU in the
shared header (`receive_cpu`) for its consumers; `w1700k-spectrum` follows it. That CPU has
nothing to spare at 320 Msps, and what the adapter cannot hand over in time it drops
([`tools/r8152-rtl8159`](../../tools/r8152-rtl8159/README.md) has the measurements).

While datagrams arrive, and for two seconds after the last, the service asks the kernel to keep
the CPUs out of their deep idle states (a CPU latency request of 100 us, held through
`/dev/cpu_dma_latency`). A stream at 40 or 80 Msps arrives in clumps, and a host that goes to
sleep between them can be too slow to wake for a USB adapter, which holds under a millisecond
of stream: 0.3 to 0.9 % of the 16-bit format's slices at 40 Msps on one such host, next to none
with the request ([the measurements](../../tools/r8152-rtl8159/README.md)). That file is root's
until `init/host/link` gives it to the user; where the service may not open it, it says so once
and carries on. Between streams the host idles as it likes.

The service raises itself to nice -10 at the start, where the user's limit allows it
(`init/host/link keep` sets that limit; it holds from the next login). The limit is the hard
one alone (`USER hard nice -10`), and the service takes its own soft limit up to it first: the
kernel judges a nice level by the soft limit, so no other program of the user runs any higher
for it. Given both limits, as `keep` once wrote them, every program that asks is let, and a
desktop application built on Chromium asks -8 for its main threads: on the measuring host it
ran at -8 with everything it started, tests and benchmarks among them, beside the service at
-10. A host set up by that earlier `keep` needs `keep` once more and a new login. With every CPU of a host
busy, the receive threads at the ordinary priority were starved: 2.1 % of a 320 Msps stream
lost in a minute, 61,000 datagrams of it dropped at the sockets. At -10, 0.008 and 0.08 % in two
such minutes, and with the kernel's own packet thread raised too (`link` does that), between
none and 0.04 % in six (2, 0, 314, 180, 3931 and 2 slices of 9.4 million), what was lost going
in one or two stalls of a fraction of a second. It is not immunity: a seventh run, two minutes
long, lost 0.3 % in one stall of a second and a half, whose cause was not found. Where the
service may not raise itself, it says so once and runs as it was started.

The host needs the destination address on the 10G link, an MTU of at least 8236
(`sudo init/host/link keep IFACE 10.77.0.10/24 9216` gives the interface both and keeps them
there; an interface with a smaller MTU drops the stream without a word), and room for
48 MiB socket buffers (`sysctl -w net.core.rmem_max=67108864`, or the kernel caps them silently
and drops datagrams under load: counted as `socket_drops`). One service owns the port: a second
receiver of the same port would take half the datagrams, so consumers read the ring instead. A
second service under the same name refuses to start; at exit the object is unlinked.

## The stream

A stream reduced to fewer bits (`w1700k` packings `16`, `14`, `8`, `7`) comes under the magic
`0x32524453` "SDR2" instead: the same header, with `seq` in 48 bits, the format (bits per I/Q
pair) in the next 8 and the slice's scale code in the top 8; the slice is 4096, 3584, 2048 or
1792 bytes (`include/hw/mt7996/iq_reduce.h`), and several whole slices may share a datagram,
each behind its own header. The service scales them back to 14-bit samples, so consumers see no
difference but the quantisation noise (`reduced` counts them). A slice may also come in pieces
(`export.piece`): datagrams with a rising `offset`, assembled here; a slice with a piece missing
counts as lost, and `pieces` counts those.

In a split stream (`w1700k` packing `split`, 320 Msps on 5 Gbit/s) the radio reduces most of
the chunks itself: those come under "SDR1" as completions of 3588 bytes whose last word is
`0x524431xx`, the low byte the shift their samples were cut under
(`include/hw/mt7996/iq_format.h`); the chunks between come reduced by the unit under "SDR2".
Both are scaled back to 14-bit samples and counted in `reduced`. The radio is told its shift
from the levels the unit sees in the chunks between, so a level that more than doubles within
a millisecond can wrap in the radio's chunks until the shift follows: `suspect` counts radio
chunks next to a unit-reduced slice whose peak was beyond their shift's range. They are
published all the same.

The export sends one UDP datagram per completion of the unit's DMA ring: a 16-byte header
(`u32` magic `0x31524453` "SDR1", `u16` offset, `u16` slice_bytes, `u64` seq) and one slice, 8192
bytes raw (2048 samples, I in bits [29:16], Q in [13:0]) or 7168 bytes packed (of each 8 samples,
the 8th rides in the other 7's spare bits [31:30] and [15:14]); completions shorter than 4096
bytes are firmware events that share the ring.

Completions are filed by `seq` into a reorder ring (256 MiB, 0.2 s at 320 Msps). A run, one stream, begins with the
first datagram after a second of silence, after a jump in `seq`, or after a consumer asks for one
(`restart_requests`, which the spectrum server does when the receiver starts or stops). Slots are
published in order: one whose completion has arrived, a firmware event, or a loss: a slot that is
still missing 250 ms after 1024 newer completions arrived (a receive thread kept off its CPU on a
busy host delivers late, not never, and the two paths of a split stream run tens of milliseconds
apart at moments), or at once when half the reorder ring is newer (`--receive-mib`, default
1 GiB: 0.42 s at 320 Msps). After 5 ms with nothing new, what has arrived is
published; a loss at the very end of a stream stays unpublished until more arrives. Of the
losses, `overruns` counts those that did arrive but were overwritten in the reorder ring before
the service published them: the service fell behind (CPU contention), not the export.

Every completion is checked on the way in, for the export's integrity: words of raw slices with
spare bits set (`spare_words`), and slices or 8-sample lines (28 bytes packed, 32 raw) equal to
the same slice or line one lap of the unit's capture ring (128 completions) earlier
(`stale_slices`, `stale_lines`), which a reader that overtook the capture, or a packer reading a
stale cache line, would send. Flat lines (all eight samples equal, which the radio does output)
are not compared.

## The shared memory

[`include/w1700k_stream.h`](include/w1700k_stream.h) is the interface, for C and C++: the
layout, the tag rules and helpers to map the object and read the position. In short:

- A 4 KiB header: the layout, the published position (`run`, `newest`: every slot of the run below
  `newest` is final), counters, a heartbeat (CLOCK_MONOTONIC, every 100 ms), and control words
  that consumers write.
- One 64-bit tag per slot: `(run << 40) | (index + 1)`, `index` counting the run's completions from
  0, plus a kind: `TAG_EVENT` (no samples, no sample time: the slices either side are contiguous),
  `TAG_LOST` (no samples; the sample time is lost), `TAG_FLAT` (corrected samples).
- Per slot one slice: 2048 complex samples, int16 I then int16 Q, on the scale of the radio's
  14-bit samples (full scale 8192). With neither correction (`iq_correct` 0, no flatten) the samples are
  the radio's, bit for bit; the DC and I/Q correction leaves them on the same scale; the int16
  range above them is the correction's headroom (a sample beyond it saturates, counted).

A reader reads a slot's tag (acquire), its samples, then the tag again: a changed tag means the
slot was overwritten meanwhile.

### Two channels

A stream is of one channel or of two: two receive chains of one band (chains 0 and 1), sampled at
the same instants, each at the band's sample rate (`w1700k start --channels 2`). The layout is
version 2 for it:

- A run is of one or of two for its whole length. `run_channels` is published with `run` and
  `newest`; read all three with `w1700k_stream_layout()`.
- A slot of a two-channel run holds 1024 sample times, laid out by channel: channel 0's 1024
  samples, then channel 1's (`w1700k_stream_channel()`). Sample k of each is the same instant.
  One tag covers the slot, so an event or a loss is the same for both channels. A one-channel
  run is laid out as it always was.
- Whoever starts a stream says how many channels it has before it starts, in the control word
  `radio_channels` (the controller does: `export.service`). A change of that word makes the next
  completion a new run's first, so no run is of both. `radio_sample_rate` is a channel's rate.
- The correction is applied to each channel as a stream of its own, and the DC and I/Q correction
  by each channel's own estimate.

A reader of the old layout refuses the object (`EPROTO`): read as one channel, a two-channel slot
would be two signals end to end.

## The correction ("flatten")

Every sample rate's decimation attenuates the band's edges, signal and noise alike: about -2 dB
at 62 % of Nyquist, -13 dB at 87 %, -22 dB at 99 % (research ledger D293). The correction is a
129-tap linear-phase FIR (Kaiser window) whose response is the inverse of that roll-off as
measured on unit A, per rate, capped at +24 dB; it is applied zero-phase (every corrected sample
keeps its index) by overlap-save FFTs, across slice boundaries, with events skipped and losses as
zeros. Its response is within 0.15 dB of the inverse up to 0.95 x Nyquist.

It applies when a consumer asks for it (`flatten` = 1) and the radio's state, which the consumer
also writes (`radio_sample_rate`, `radio_capture_rate`, `radio_filter_hz`), says the analog filter
is as wide as the sample rate and the stream is not 640/2 (which is flat already); the service
reports what applies in `flatten_active` and `flatten_rate`. The spectrum server writes these
from the receiver's controller and the page's Flatten toggle.

The service is ready at once: the correction's two 2048-point transforms start on the plans FFTW
estimates, and move to the ones it measures when those are there. The measured plans are found by
a process of their own (`w1700k-stream --measure-plans`, which a service that lacks them starts
by itself, at the ordinary priority; one at a time, and it goes on if the service ends) and kept
in `$XDG_CACHE_HOME/w1700k/stream-fftwf-wisdom` (default `~/.cache`), where the next service
finds them. Where FFTW has a cycle counter to time with that takes milliseconds. Where it has
none (FFTW 3.3.10 as Ubuntu builds it for arm64) it took 54 s on an 8-core arm64 host, and until
it was done apart the service took that long to start. It is worth having there: 3.4 us a
transform with the measured plans against 5.4 with the estimate. The service says on its error
output which plans it runs on when they are the estimate, and when it moves.

Measured on unit A, band 1 at 320 Msps, from the receiver's noise floor (relative to 15..45 % of
Nyquist): without the correction -1.7 / -6.4 / -14.2 / -19.8 / -22.8 dB at 62.5 / 75 / 87.5 / 94 /
97 % of Nyquist; with it +0.9 / +0.5 / +0.1 / -0.4 / -1.1 dB. The service used 0.8 CPU cores
without it and 1.8 with it, with no loss.

## The receiver's DC and I/Q imbalance (`iq_correct`)

The radio's I and Q branches differ a little in gain and are not quite 90 degrees apart, which
puts a mirror image of every signal at minus its frequency, and each branch carries an offset.
Measured on one W1700K (2026-11-27, a tone swept over +-68 MHz at 160 Msps): the image -36 to -47
dBc on its three radios, and offsets of up to about -230 counts (-31 dBFS) on I and -100 on Q,
which change with the gain. The radio's own RX IQ compensation filters sit after the capture tap
([`docs/architecture.md`](../../docs/architecture.md)), so the stream carries both as the
receiver made them.

The service takes them out ([`src/iqfix.h`](src/iqfix.h)), each channel by its own estimate, in
every format it decodes (raw, packed, reduced, split; one channel or two), with the roll-off
correction or without it (it is applied after it, to the int16 samples). The estimate is blind:
it goes by the stream's own statistics, in which whatever a receiver takes in (noise, a tone, a
modulated signal off the LO) has I and Q of equal power, uncorrelated and without a mean. Over
2^20 samples (a quarter of the slots measured) it takes the means, the two powers and the
covariance of I and Q, and makes Q orthogonal to I and of I's power (a Gram-Schmidt step). The
offsets are taken from every estimate; the gain and the cross term only from one in which a
signal stands out of the noise (the strongest bin of a 512-point spectrum, taken now and then,
at least 10 dB over the median bin): the receiver's own noise, at the lowest gains made mostly in
the two baseband chains apart, does not carry the RF path's imbalance. Each estimate counts a
quarter towards the parameters in use, so they settle in about 0.1 s at 160 Msps (0.4 s at 40)
and follow a change of gain or LO as quickly. A new run starts from no correction. The header
reports what applies (`iq_active`) and the parameters per channel (`iq_dc_i_milli`,
`iq_dc_q_milli`, `iq_gain_ppb`, `iq_cross_ppb`, `iq_estimates`, `iq_imbalance_estimates`).
`iq_correct` 0 (or `--iq-correct off`) gives the samples as the radio made them.

What it does and does not do, measured on that unit (a tone at a dozen offsets over +-68 MHz from
the LO at 160 Msps, the correction worked out from the unit's own samples by the service's
arithmetic; image in dBc, median / worst over the offsets):

| radio, gain | as captured | estimate from the tone itself | an estimate from noise alone (not used, below) | best single correction |
|---|---|---|---|---|
| 5 GHz, LNA 2 / filter 9 | -42.2 / -39.0 | -95 to -127 | -53.9 / -45.4 | -51.9 / -46.6 |
| 5 GHz, LNA 0 / filter 0 | -41.5 / -39.0 | -78 to -115 | -46.7 / -44.2 | -56.2 / -50.2 |
| 6 GHz, LNA 2 / filter 9 | -40.6 / -39.9 | -84 to -129 | -49.3 / -48.1 | -61.5 / -55.4 |
| 6 GHz, LNA 0 / filter 0 | -41.5 / -39.0 | -58 to -94 | -37.6 / -36.7 | -54.2 / -47.0 |
| 2.4 GHz, LNA 0 / filter 9 (3 offsets) | -39.0 / -36.4 | -41 to -56 | -40.9 / -38.0 | -52.6 / -50.1 |

(The tone's own estimate is what the service settles on while that tone dominates the band; a
tone at 0 dBFS that clips reads -75 dBc. The 2.4 GHz figures are few and noisy: outside Wi-Fi
got into the shielded box during the measurements and only quiet captures were kept.) DC: up to
about -230 counts on I and -100 on Q, which change with the gain (5 GHz radio: -233 / +47 at
LNA 2 / filter 9, -64 / -11 at LNA 0 / filter 0).

On the live stream through the service (a W1700K's 5 GHz radio at 160 Msps, a tone at -12 and at
-21 dBFS, the image read as the tone's coherent mirror in 13-ms captures): the image -41.7 dBc
without the correction and -80 to -90 dBc with it; the offsets 214 to 219 counts on I without it
and within 3 counts with it (they wander by about that much from one estimate to the next).

- **It follows the strongest signal.** One correction holds for the whole band, so it is exact
  only at the frequencies that dominate the statistics. With a strong signal in the band it
  converges on that signal's imbalance: the image of a tone near full scale fell from -40..-47
  dBc to below -75 dBc. The imbalance itself varies over the band (mostly a phase that grows
  linearly with frequency, as a delay of about 15 ps between the two branches would make, and a
  gain step near the filter's edge), so a signal far from the one the estimate followed keeps
  an image of -46 to -62 dBc. With nothing but noise in the band only the offsets are followed:
  an estimate of the imbalance from noise alone is the noise's, at the lowest gain the baseband's
  own, and was measured to leave a weak signal's image worse than none (6 GHz radio, LNA 0 /
  filter 0: -37.6 against -41.5 dBc; at LNA 2 / filter 9 -32.9 against -38.3), so it is not used.
- **It removes a signal exactly at the LO**, as any DC correction does (within about a hertz).
- **Cost**: about a quarter of a core at 160 Msps on an Intel N350, 1.5 to 1.7 ns a sample: on
  the live stream the service took 1.14 of a core with the correction against 0.87 without (five
  10-s periods each, by turns), and on a stream over loopback at the same rate 0.93 to 0.97
  against 0.68 to 0.74. No slice was lost in any of them, nor in a 30-s stream with it on. The
  forms measured are SSE2's (every x86-64); other hosts run plain ones, not measured.

## Tests

`python3 -m unittest discover -s tests -p test_stream.py` from the repository root (`make check`
runs it) builds the service and runs it against a fake export over loopback. It includes the DC
and I/Q correction end to end (`IqCorrection`: a known imbalance and offset taken out to below
-60 dBc and half a count, in every format and after the roll-off correction, each channel of two
by its own estimate; noise alone moving only the offsets; and with it off, from the start or
within a run, the samples bit for bit).

`make -C host/stream check` checks the DC and I/Q correction's sums, its arithmetic and its
estimate of a known imbalance against the rule written out plainly (`tests/iqfix_check.cpp`); the
test suite runs it too.
