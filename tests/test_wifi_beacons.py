# SPDX-License-Identifier: MIT
"""host/wifi/wifi-beacons against frames made here: a small DSSS transmitter (IEEE 802.11-2020
clause 15, long preamble, 1 and 2 Mbit/s) and a small OFDM one (clause 17, the half-rate rates),
written from the standard in plain Python, with a carrier offset and noise put on what they send.
The decoder has also read real beacons off the air (host/wifi/README.md); these keep it reading
the ones a transmitter built to the standard sends."""
import cmath
import math
import os
import random
import struct
import subprocess
import tempfile
import unittest
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROGRAM = ROOT / 'host/wifi/build/wifi-beacons'


def beacon(ssid, bssid, channel, subtype=8, extra=b''):
    """A beacon (or, subtype 5, a probe response) with its frame check sequence."""
    body = bytes([subtype << 4, 0, 0, 0]) + b'\xff' * 6 + bssid + bssid + b'\x10\x00'
    body += bytes(8) + b'\x64\x00\x01\x04'
    body += bytes([0, len(ssid)]) + ssid + bytes([1, 4, 0x82, 0x84, 0x8b, 0x96]) + bytes([3, 1, channel]) + extra
    return body + struct.pack('<I', zlib.crc32(body))


def bits_of(data):
    return [byte >> k & 1 for byte in data for k in range(8)]


# --- DSSS ---

BARKER = (1, -1, 1, 1, -1, 1, 1, 1, -1, -1, -1)


def dsss(psdu, mbps=1, sps=40):
    """Samples of a long-preamble DSSS frame: 144 preamble bits and the 48-bit header at
    1 Mbit/s, then the PSDU at `mbps` (1: DBPSK, 2: DQPSK)."""
    length = len(psdu) * 8 // mbps                                   # microseconds
    header = bits_of(bytes([0x0a if mbps == 1 else 0x14, 0]) + struct.pack('<H', length))
    crc = 0xffff
    for bit in header:
        feedback = (crc >> 15 & 1) ^ bit
        crc = crc << 1 & 0xffff
        if feedback:
            crc ^= 0x1021
    crc = ~crc & 0xffff
    plain = [1] * 128 + bits_of(struct.pack('<H', 0xf3a0)) + header + [crc >> (15 - k) & 1 for k in range(16)] + bits_of(psdu)
    state, scrambled = [1, 0, 1, 1, 0, 1, 0], []                     # the last seven sent, newest first
    for bit in plain:
        sent = bit ^ state[3] ^ state[6]
        scrambled.append(sent)
        state = [sent] + state[:6]
    phase, symbols, at = 0.0, [], 0
    head = 144 + 48
    while at < len(scrambled):
        if at < head or mbps == 1:
            phase += math.pi * scrambled[at]
            at += 1
        else:
            phase += {(0, 0): 0, (0, 1): math.pi / 2, (1, 1): math.pi, (1, 0): 3 * math.pi / 2}[(scrambled[at], scrambled[at + 1])]
            at += 2
        symbols.append(cmath.exp(1j * phase))
    return [symbol * BARKER[j * 11 // sps] for symbol in symbols for j in range(sps)]


# --- OFDM ---

LTF = (1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 1, 1, -1, -1, 1, 1, -1, 1, -1, 1, 1, 1, 1, 0,
       1, -1, -1, 1, 1, -1, 1, -1, 1, -1, -1, -1, -1, -1, 1, 1, -1, -1, 1, -1, 1, -1, 1, 1, 1, 1)
STF_AT = {-24: 1, -20: -1, -16: 1, -12: -1, -8: -1, -4: 1, 4: -1, 8: -1, 12: 1, 16: 1, 20: 1, 24: 1}
RATES = {6: (0b1011, 1), 12: (0b1010, 2), 24: (0b1001, 4)}          # R1..R4 with R1 in bit 0, bits a carrier


def polarity():
    state, out = [1] * 7, []
    for _ in range(127):
        feedback = state[3] ^ state[6]
        state = [feedback] + state[:6]
        out.append(-1 if feedback else 1)
    return out


def symbol(carriers, n):
    """The time samples of one OFDM symbol body from {carrier number: value}, at n samples (64: 20 Msps)."""
    return [sum(value * cmath.exp(2j * math.pi * k * t / n) for k, value in carriers.items()) / math.sqrt(52) for t in range(n)]


def convolve(bits):
    out, reg = [], 0
    for bit in bits:
        reg = bit << 6 | reg >> 1
        out += [bin(reg & 0x5b).count('1') & 1, bin(reg & 0x79).count('1') & 1]
    return out


def interleaved(coded, bpsc):
    n, s = len(coded), max(bpsc // 2, 1)
    out = [0] * n
    for k, bit in enumerate(coded):
        i = (n // 16) * (k % 16) + k // 16
        out[s * (i // s) + (i + n - 16 * i // n) % s] = bit
    return out


def mapped(bits, bpsc):
    if bpsc == 1:
        return [2 * bits[0] - 1]
    if bpsc == 2:
        return [complex(2 * bits[0] - 1, 2 * bits[1] - 1) / math.sqrt(2)]
    level = {(0, 0): -3, (0, 1): -1, (1, 1): 1, (1, 0): 3}
    return [complex(level[(bits[0], bits[1])], level[(bits[2], bits[3])]) / math.sqrt(10)]


def ofdm(psdu, mbps=6, n=64, seed=0x5d):
    """Samples of a clause 17 frame at 20 Msps (n = 64) or 40 (n = 128)."""
    code, bpsc = RATES[mbps]
    data_carriers = [k for k in range(-26, 27) if k not in (0, -21, -7, 7, 21)]
    signs = polarity()

    def one(coded, index):
        carriers = {}
        spread = interleaved(coded, bpsc if index else 1)
        width = bpsc if index else 1
        for d, k in enumerate(data_carriers):
            carriers[k] = mapped(spread[d * width:(d + 1) * width], width)[0]
        for k, sign in zip((-21, -7, 7, 21), (1, 1, 1, -1)):
            carriers[k] = sign * signs[index % 127]
        body = symbol(carriers, n)
        return body[-n // 4:] + body

    short = symbol({k: math.sqrt(13 / 6) * v * (1 + 1j) for k, v in STF_AT.items()}, n)
    long = symbol({k: v for k, v in zip(range(-26, 27), LTF) if v}, n)
    out = (short * 3)[:n * 5 // 2] + long[-n // 2:] + long + long
    signal = [code >> k & 1 for k in range(4)] + [0] + [len(psdu) >> k & 1 for k in range(12)]
    signal += [sum(signal) & 1] + [0] * 6
    out += one(convolve(signal), 0)
    dbps = 24 * bpsc
    payload = [0] * 16 + bits_of(psdu) + [0] * 6
    payload += [0] * (-len(payload) % dbps)
    state = [seed >> k & 1 for k in range(7)]
    for k in range(len(payload)):
        feedback = state[3] ^ state[6]
        state = [feedback] + state[:6]
        payload[k] ^= feedback
    tail = 16 + 8 * len(psdu)
    payload[tail:tail + 6] = [0] * 6
    coded = convolve(payload)
    for index in range(len(payload) // dbps):
        out += one(coded[index * 2 * dbps:(index + 1) * 2 * dbps], index + 1)
    return out


def on_air(frames, rate, offset_hz=0.0, noise=0.05, seed=1):
    """Frames one after another with gaps, a carrier offset on all of it, and noise: int16 I, Q."""
    rng = random.Random(seed)
    gap = int(rate * 300e-6)
    samples = [0j] * gap
    for frame in frames:
        samples += frame + [0j] * gap
    out = bytearray()
    step = 2 * math.pi * offset_hz / rate
    for index, value in enumerate(samples):
        value = value * cmath.exp(1j * step * index) + complex(rng.gauss(0, noise), rng.gauss(0, noise))
        out += struct.pack('<hh', int(round(value.real * 2000)), int(round(value.imag * 2000)))
    return bytes(out)


@unittest.skipUnless(PROGRAM.exists(), 'host/wifi is not built (make host)')
class Beacons(unittest.TestCase):
    A = bytes.fromhex('020000000a01')
    B = bytes.fromhex('020000000b02')

    def decode(self, data, rate, *words):
        with tempfile.NamedTemporaryFile(suffix='.cs16') as file:
            file.write(data)
            file.flush()
            result = subprocess.run([str(PROGRAM), file.name, '--rate', str(rate), *words], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.splitlines(), result.stderr

    def test_a_dsss_beacon_at_one_megabit_with_its_carrier_off_and_noise(self):
        frame = dsss(beacon(b'Test Net 2.4', self.A, 6))
        for offset in (0.0, 45e3, -60e3):
            with self.subTest(offset=offset):
                lines, _ = self.decode(on_air([frame], 40e6, offset), 40)
                self.assertEqual(len(lines), 1, lines)
                self.assertIn('dsss 1 Mbit/s', lines[0])
                self.assertIn('beacon', lines[0])
                self.assertIn('channel   6', lines[0])
                self.assertIn('bssid 02:00:00:00:0a:01 ssid "Test Net 2.4"', lines[0])

    def test_dsss_at_two_megabits_and_at_twenty_msps(self):
        lines, _ = self.decode(on_air([dsss(beacon(b'two', self.B, 11), mbps=2)], 40e6, 20e3), 40)
        self.assertEqual(len(lines), 1, lines)
        self.assertIn('dsss 2 Mbit/s', lines[0])
        self.assertIn('ssid "two"', lines[0])
        lines, _ = self.decode(on_air([dsss(beacon(b'slow', self.B, 1), sps=20)], 20e6), 20)
        self.assertEqual([line.split(' ssid ')[1] for line in lines], ['"slow"'])

    def test_ofdm_beacons_at_each_rate_it_receives(self):
        for mbps in (6, 12, 24):
            with self.subTest(mbps=mbps):
                lines, _ = self.decode(on_air([ofdm(beacon(b'Five GHz', self.A, 36), mbps)], 20e6, -50e3, noise=0.02), 20)
                self.assertEqual(len(lines), 1, lines)
                self.assertIn(f'ofdm {mbps} Mbit/s', lines[0])
                self.assertIn('channel  36', lines[0])
                self.assertIn('ssid "Five GHz"', lines[0])

    def test_ofdm_at_forty_msps_as_the_receiver_gives_it(self):
        lines, _ = self.decode(on_air([ofdm(beacon(b'wide capture', self.B, 149), n=128)], 40e6, 70e3, noise=0.02), 40)
        self.assertEqual(len(lines), 1, lines)
        self.assertIn('ofdm 6 Mbit/s', lines[0])
        self.assertIn('bssid 02:00:00:00:0b:02 ssid "wide capture"', lines[0])

    def test_several_frames_and_only_what_checks_out_is_said(self):
        good = beacon(b'kept', self.A, 6)
        spoiled = bytearray(beacon(b'spoiled', self.B, 6))
        spoiled[40] ^= 0x10                                       # after the check sequence was worked out
        data = bytes([0x08, 0x01]) + bytes(30)                   # a data frame: type 2
        data += struct.pack('<I', zlib.crc32(data))
        probe = beacon(b'asked', self.B, 6, subtype=5)
        air = on_air([dsss(good), dsss(bytes(spoiled)), dsss(data), dsss(probe)], 40e6, 10e3)
        lines, summary = self.decode(air, 40)
        self.assertEqual([line.split(' ssid ')[1] for line in lines], ['"kept"', '"asked"'])
        self.assertIn('probe-resp', lines[1])
        self.assertIn('3 frames whose check held (1 beacons), 1 that did not', summary)
        everything, _ = self.decode(air, 40, '--all')
        self.assertEqual(len(everything), 3)
        self.assertIn('type 2 subtype 0', everything[1])

    def test_private_names_no_network_and_no_address(self):
        air = on_air([dsss(beacon(b'Somebody Elses', self.A, 1)), dsss(beacon(b'Somebody Elses', self.A, 1))], 40e6)
        lines, _ = self.decode(air, 40, '--private')
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertNotIn('Somebody', line)
            self.assertNotIn('0a:01', line)
            self.assertRegex(line, r'bssid #[0-9a-f]{8} ssid #[0-9a-f]{8} \(14 bytes\)')
        self.assertEqual(lines[0].split('bssid')[1], lines[1].split('bssid')[1], 'the same network hashes the same')

    def test_a_name_with_bytes_a_terminal_would_act_on_is_shown_harmlessly(self):
        lines, _ = self.decode(on_air([dsss(beacon(b'a\x1b[2J"b\n', self.A, 1))], 40e6), 40)
        self.assertIn('ssid "a.[2J.b."', lines[0])

    def test_noise_alone_and_bad_arguments(self):
        lines, summary = self.decode(on_air([], 40e6, noise=0.3)[:4 * 200000], 40)
        self.assertEqual(lines, [])
        self.assertIn('0 frames whose check held', summary)
        result = subprocess.run([str(PROGRAM)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('usage: wifi-beacons FILE --rate 40|20', result.stderr)

    def test_it_is_built_with_the_host_programs(self):
        self.assertIn('$(MAKE) -C host/wifi', (ROOT / 'Makefile').read_text())
        source = (ROOT / 'host/wifi/wifi-beacons.c').read_text()
        for word in ('socket', 'sendto', 'ioctl', 'popen', 'system('):
            self.assertNotIn(word, source, 'it reads a file and prints: nothing else')


if __name__ == '__main__':
    unittest.main()
