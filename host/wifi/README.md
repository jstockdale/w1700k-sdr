# wifi-beacons: Wi-Fi networks read from the samples

`wifi-beacons` reads Wi-Fi beacons out of the receiver's samples and says which networks are on
a channel: each one's name (SSID), its BSSID, the channel it names and how it beacons. It only
reads what was received; nothing is transmitted and no network is asked anything.

```sh
make -C host/wifi                                   # or `make host`; a C11 compiler, nothing else
host/bin/w1700k band 0 --rate 40 --lo 2437M && host/bin/w1700k start     # channel 6
host/recv/build/sdr-recv --out /tmp/ch6 --seconds 0.5
host/wifi/build/wifi-beacons /tmp/ch6 --rate 40
```

```
0.068834 ofdm 6 Mbit/s  307 bytes beacon     snr 25.3 dB channel   6 bssid 02:00:00:00:0a:01 ssid "Test Net 2.4"
0.171201 dsss 1 Mbit/s  182 bytes beacon     snr 40.8 dB channel   6 bssid 02:00:00:00:0b:02 ssid "another"
```

A whole band at once, through the live receiver:

```sh
tools/wifi_scan.py --band 2.4        # or 5, or 6; --channels 1,6,11; --dwell 0.5
```

It starts a 40 Msps stream, retunes from channel to channel, listens a quarter of a second on
each, decodes, and lists the networks by channel, strongest first.

| | |
|---|---|
| `FILE` | int16 I, Q pairs, as `sdr-recv --out` writes them, with the LO on the channel's centre |
| `--rate 40` or `20` | the sample rate of the file, in Msps |
| `--all` | list every frame whose check held, not only beacons and probe responses (type and length only) |
| `--private` | a hash of each name and address in place of the thing itself |

## What it receives

- **DSSS at 1 and 2 Mbit/s** (IEEE 802.11-2020 clause 15, long preamble): what 2.4 GHz
  networks that still serve the oldest clients beacon with.
- **OFDM at 6, 12 and 24 Mbit/s** (clause 17): what 5 and 6 GHz networks beacon with, and
  2.4 GHz ones that dropped the old rates.
- A frame is reported only if its 32-bit frame check sequence holds, so a name printed is a
  name that was sent.
- **Not received:** the 5.5 and 11 Mbit/s DSSS rates and the OFDM rates with a punctured code
  (9, 18, 36, 48, 54) are stepped over; short-preamble DSSS, 802.11n and later formats are not
  looked for. Beacons go out at a network's lowest basic rate, so this misses few of them, and
  a network configured to beacon at 12 or 24 Mbit/s is still read.
- **One 20 MHz channel at a time.** A network is found on the channel its beacons are sent on
  (its primary channel), whatever width it then uses.

## How well

Checked on a W1700K against the host's own Wi-Fi card listing the same channels at the same time:

| Channel | The card lists | Decoded from 0.42 s | In both | Only decoded |
|---|---|---|---|---|
| 1 (2412 MHz) | 5 | 7 | 5 | 2 |
| 6 (2437 MHz) | 2 | 1 | 1 | 0 |
| 11 (2462 MHz) | 2 | 2 | 1 | 1 |
| 36 (5180 MHz) | 2 | 3 | 2 | 1 |

Every decoded beacon named the channel it was captured on. The channel 6 capture had a strong
narrow-band transmitter in it for most of its length. One network's beacons came 102.4 ms apart,
as they are sent.

It is not fast: decoding takes two to ten times as long as the samples did to arrive, on one
core of a laptop, most of it in looking for frames. It has not been made to run on the unit.

## Other people's networks

A beacon is broadcast for anyone to read, and reading it is what every Wi-Fi device does. The
samples it comes from are another matter: a capture of a channel holds everyone's traffic on
it. `tools/wifi_scan.py` keeps a channel's samples only for as long as the decoding takes.
Use `--private` for output that will be shown to somebody else.
