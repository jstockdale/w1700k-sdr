#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Which Wi-Fi networks are on the air, by the receiver alone: tune to each channel in turn, keep
a moment of samples, and read the beacons in them (host/wifi).

    tools/wifi_scan.py [--band 2.4|5|6] [--channels 1,6,11] [--dwell S] [--private] [--json]

Needs the unit reachable and w1700k-stream running on this host. A 40 Msps stream is started on
the band and retuned from channel to channel; each channel is listened to for S seconds (0.25
unless said: beacons come about every 0.1 s), its samples decoded, and at the end one line a
network says its name, its BSSID, the channel it names, how it beacons and how strong it was.
Nothing is transmitted and nothing is asked of any network: this only listens.

--private prints a hash of each name and address in place of the thing itself. The samples are
kept in a temporary file for the decoding and removed; they are other people's traffic.
The receiver is put back as it was found.
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'host'), str(ROOT / 'tests')]

from w1700k import config as host_config  # noqa: E402
from w1700k.controller import Controller  # noqa: E402
import stream_shm  # noqa: E402

DECODER = ROOT / 'host/wifi/build/wifi-beacons'
STREAM_NAME = '/w1700k-stream'
RATE = 40_000_000
# The receiver's band, and each channel's centre in MHz.
BANDS = {
    '2.4': (0, {n: 2407 + 5 * n for n in range(1, 14)}),
    '5': (1, {n: 5000 + 5 * n for n in (36, 40, 44, 48, 52, 56, 60, 64, *range(100, 145, 4), 149, 153, 157, 161, 165)}),
    '6': (2, {n: 5950 + 5 * n for n in range(5, 230, 16)}),          # the preferred scanning channels
}
LINE = re.compile(r'^(?P<t>\S+) (?P<phy>\w+) (?P<mbps>\S+) Mbit/s\s+(?P<bytes>\d+) bytes (?P<kind>\S+)\s+snr\s+(?P<snr>\S+) dB '
                  r'channel\s+(?P<channel>\d+) bssid (?P<bssid>\S+) ssid (?P<ssid>.*)$')


def listen(shm, seconds):
    """The newest `seconds` of the stream as bytes of int16 I, Q, or None if a slice of it was lost."""
    wanted = int(seconds * RATE / stream_shm.SLICE)
    _, newest = shm.position()
    first = newest - wanted
    ring, base = shm.get('ring_slices'), shm.get('samples_offset')
    if any(shm.tag(index) & stream_shm.TAG_KIND & ~stream_shm.TAG_FLAT for index in range(first, first + wanted)):
        return None
    size = stream_shm.SLICE * 4
    return b''.join(bytes(shm.map[base + (index & (ring - 1)) * size:base + (index & (ring - 1)) * size + size])
                    for index in range(first, first + wanted))


def decode(samples, private):
    with tempfile.NamedTemporaryFile(suffix='.cs16') as file:
        file.write(samples)
        file.flush()
        argv = [str(DECODER), file.name, '--rate', '40'] + (['--private'] if private else [])
        out = subprocess.run(argv, capture_output=True, text=True, timeout=300).stdout
    return [match.groupdict() for match in map(LINE.match, out.splitlines()) if match]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--band', choices=tuple(BANDS), default='2.4')
    parser.add_argument('--channels', help='channel numbers, comma-separated (default: every channel of the band)')
    parser.add_argument('--dwell', type=float, default=0.25, help='seconds listened to on each channel (default: %(default)s)')
    parser.add_argument('--private', action='store_true', help='hashes in place of names and addresses')
    parser.add_argument('--json', action='store_true', help='the networks as JSON')
    args = parser.parse_args()
    band, centres = BANDS[args.band]
    wanted = [int(c) for c in args.channels.split(',')] if args.channels else list(centres)
    unknown = [c for c in wanted if c not in centres]
    if unknown:
        parser.error(f'not channels of the {args.band} GHz band here: {unknown}')
    if not DECODER.exists():
        sys.exit('wifi_scan: host/wifi is not built (make host)')
    if not stream_shm.ready(STREAM_NAME):
        sys.exit('wifi_scan: w1700k-stream is not running on this host (host/stream/build/w1700k-stream)')
    shm = stream_shm.Shm(STREAM_NAME)
    ctl = Controller(host_config.load(), emit=lambda event: None)
    ctl.attach()
    found = ctl.state()
    was = (found['radio']['band'], found['radio']['sample_rate'], found['radio']['lo_hz'], found['radio']['capture_rate'],
           found['stream']['running'])
    if found['stream']['running']:
        ctl.stop()
    if not found['radio']['loaded']:
        ctl.load()
    networks, heard = {}, {}
    try:
        ctl.configure(band, RATE, centres[wanted[0]] * 10**6, None)
        ctl.start()
        for channel in wanted:
            ctl.tune(centres[channel] * 10**6)
            time.sleep(0.05 + args.dwell)
            samples = listen(shm, args.dwell)
            frames = decode(samples, args.private) if samples else []
            heard[channel] = len(frames)
            print(f'wifi_scan: channel {channel:3} ({centres[channel]} MHz): {len(frames)} beacons and probe responses', file=sys.stderr, flush=True)
            for frame in frames:
                said = int(frame['channel']) or channel
                if said != channel:             # a neighbouring channel's network, heard from here: its own channel will show it
                    continue
                entry = networks.setdefault(frame['bssid'], {'bssid': frame['bssid'], 'ssid': frame['ssid'], 'channel': said,
                                                             'sent': f"{frame['phy']} {frame['mbps']} Mbit/s", 'snr_db': -99.0, 'frames': 0})
                entry['frames'] += 1
                entry['snr_db'] = max(entry['snr_db'], float(frame['snr']))
    finally:
        try:
            ctl.stop()
            band_was, rate_was, lo_was, capture_was, running = was
            ctl.configure(band_was, rate_was, lo_was, capture_was if capture_was != rate_was else None)
            if running:
                ctl.start()
        except Exception as error:
            print(f'wifi_scan: the receiver could not be put back as it was: {error}', file=sys.stderr)
        ctl.close()
        shm.close()
    listed = sorted(networks.values(), key=lambda entry: (entry['channel'], -entry['snr_db']))
    if args.json:
        print(json.dumps({'band': args.band, 'channels': wanted, 'networks': listed}))
    else:
        for entry in listed:
            print(f"channel {entry['channel']:3}  {entry['snr_db']:5.1f} dB  {entry['sent']:16}  {entry['bssid']}  {entry['ssid']}")
        print(f'{len(listed)} networks on {sum(1 for c in heard if heard[c])} of {len(wanted)} channels', file=sys.stderr)
    return 0


if __name__ == '__main__':
    sys.exit(main())
