# SPDX-License-Identifier: MIT
"""The W1700K's low-power radio from the host: a Silicon Labs EFR32MG21 (Bluetooth LE, Zigbee and
Thread at 2.4 GHz) on the unit's second serial port, which the unit hands to the host over ssh
(`w1700k-efr32 link` there: platform/README.md, "The low-power radio").

    w1700k efr32 status          whether it runs, what start-up does with it, whether its port is there
    w1700k efr32 on [--keep]     let it run; with --keep, at every start-up too (and its port with it)
    w1700k efr32 off [--keep]    hold it in reset
    w1700k efr32 identify        ask the radio what firmware it runs
    w1700k efr32 scan [--seconds N] [--phy 1m|coded|both]
                                 listen for Bluetooth LE advertisers; the radio transmits nothing
    w1700k efr32 pty [--baud N] [--name PATH]
                                 its serial port as a terminal device on this host, until stopped

The radio is off unless its owner turns it on, and its port is there only at a boot where it is
kept on: `on --keep`, restart the unit, then `identify` or `pty`.

`identify` speaks the two commands of Silicon Labs' BGAPI that every Bluetooth co-processor image
answers and that make it do nothing else: `system_hello` and `system_get_version`. The factory
firmware is such an image (seen on a unit: stack 6.2.0 build 212). Other firmware (a Zigbee or
Thread co-processor) will not answer them.

`scan` is a passive scan: the radio listens on the advertising channels and reports what it
hears, and sends nothing (it asks no advertiser for more, as an active scan would). The radio's
own count of the packets it has transmitted is read before and after and given with the result.
That is all of Bluetooth this package does: nothing here advertises, connects or scans actively.

`pty` is the port itself, for whatever the host wants to run against it: a Bluetooth host stack,
a flasher, a terminal. What goes through it is the user's own doing: a host that tells the radio
to advertise, scan or connect makes the unit transmit at 2.4 GHz, up to 10 dBm.
"""
import struct
import time

from . import portlink

BAUD = 115200                     # the factory firmware's
BAUDS = (115200, 230400, 460800)  # what the port reaches
# BGAPI: a header of four bytes, then the payload. Byte 0: 0x20 a command or its response, 0xa0 an
# event, its low three bits the payload length's high bits; byte 1 the length's low byte; then
# the class and the command (sl_bt_api.h: system_hello 0x00010020, system_get_version 0x1b010020).
SYSTEM = 0x01
HELLO, GET_VERSION, BOOT = 0x00, 0x1b, 0x00
GET_COUNTERS = 0x0f
RESPONSE, EVENT = 0x20, 0xa0
# The scanner (sl_bt_api.h of stack 6.2.0, the factory firmware's: gecko_sdk v4.3.2).
SCANNER = 0x05
SCAN_SET_PARAMETERS, SCAN_START, SCAN_STOP = 0x06, 0x03, 0x05
LEGACY_REPORT, EXTENDED_REPORT = 0x00, 0x02              # events
PASSIVE = 0                                              # the scan mode; 1 would be active, which transmits
OBSERVATION = 2                                          # discover every advertiser, whatever its flags say
PHYS = {'1m': 1, 'coded': 4, 'both': 5}
SCAN_UNITS = 0x10                                        # interval and window, 0.625 ms each: 10 ms, so always listening
CONNECTABLE, SCANNABLE = 0x01, 0x02                      # event flags
ADDRESS_TYPES = {0: 'public', 1: 'random', 255: 'anonymous'}
NAME, SHORT_NAME = 0x09, 0x08                            # advertising data fields


class RadioError(portlink.LinkError):
    pass


def command(cls, cmd, payload=b''):
    return bytes([RESPONSE | len(payload) >> 8, len(payload) & 0xff, cls, cmd]) + payload


class Link(portlink.Link):
    """The radio's port (the unit's `w1700k-efr32 link` over ssh), and BGAPI's messages on it."""
    error = RadioError
    ended = 'the link to the radio ended'

    def message(self, timeout=1.0):
        """One BGAPI message: (kind, class, command, payload), or None when none came whole."""
        header = self.read(4, timeout)
        if len(header) < 4:
            self.pending = header + self.pending
            return None
        if header[0] & 0xf8 not in (RESPONSE, EVENT):
            raise RadioError(f'what the radio sent is not BGAPI (it begins {header.hex()}): other firmware, or '
                             'another speed')
        length = (header[0] & 7) << 8 | header[1]
        payload = self.read(length, timeout)
        if len(payload) < length:
            raise RadioError('the radio stopped in the middle of a message')
        return header[0] & 0xf8, header[2], header[3], payload

    def ask(self, cls, cmd, payload=b'', timeout=1.0):
        """A command's response payload; events that come first are passed over."""
        self.write(command(cls, cmd, payload))
        deadline = time.monotonic() + timeout
        while True:
            got = self.message(max(0.05, deadline - time.monotonic()))
            if got is None:
                raise RadioError('the radio did not answer (held in reset, other firmware, or another speed)')
            kind, rcls, rcmd, body = got
            if kind == RESPONSE and (rcls, rcmd) == (cls, cmd):
                return body


def _version(major, minor, patch, build, bootloader, digest, hardware=None):
    return {'stack': f'{major}.{minor}.{patch}', 'build': build, 'bootloader': f'{bootloader:#010x}',
            'hardware': None if hardware is None else f'{hardware:#06x}', 'hash': f'{digest:#010x}'}


def version_from_response(body):
    """system_get_version's response: its result, then the version (the bootloader word reads 0 in
    stacks that no longer fill it: the bootloader says its own version when it is started)."""
    if len(body) != 18:
        raise RadioError(f'a version response of {len(body)} bytes is not one this knows')
    result, major, minor, patch, build, bootloader, digest = struct.unpack('<HHHHHII', body)
    if result:
        raise RadioError(f'the radio refused: result {result:#06x}')
    return _version(major, minor, patch, build, bootloader, digest)


def version_from_boot(body):
    """The system_boot event the firmware sends when it starts: the version, with the hardware word."""
    if len(body) != 18:
        raise RadioError(f'a boot event of {len(body)} bytes is not one this knows')
    major, minor, patch, build, bootloader, hardware, digest = struct.unpack('<HHHHIHI', body)
    return _version(major, minor, patch, build, bootloader, digest, hardware)


def identify(link):
    """What Bluetooth co-processor firmware answers on the link: {'firmware': 'bgapi', stack, ...}."""
    hello = link.ask(SYSTEM, HELLO)
    if hello != b'\x00\x00':
        raise RadioError(f'system_hello answered {hello.hex()}')
    body = link.ask(SYSTEM, GET_VERSION)
    return dict(firmware='bgapi', **version_from_response(body))


def _ok(link, cls, cmd, payload=b'', what=''):
    """A command that answers a result first: its payload after the result, or RadioError."""
    body = link.ask(cls, cmd, payload)
    if len(body) < 2:
        raise RadioError(f'{what}: an answer of {len(body)} bytes')
    result = struct.unpack_from('<H', body)[0]
    if result:
        raise RadioError(f'{what}: the radio refused, result {result:#06x}')
    return body[2:]


def transmitted(link):
    """The radio's own count of the packets it has sent since it started (16 bits)."""
    body = _ok(link, SYSTEM, GET_COUNTERS, b'\x00', 'counters')
    if len(body) < 8:
        raise RadioError(f'a counters answer of {len(body) + 2} bytes is not one this knows')
    return struct.unpack_from('<H', body)[0]


def _name(data):
    """The device name in advertising data, where it carries one."""
    at = 0
    while at + 1 < len(data) and data[at]:
        if data[at + 1] in (NAME, SHORT_NAME):
            return data[at + 2:at + 1 + data[at]].decode('utf-8', errors='replace')
        at += data[at] + 1
    return None


def report(cmd, body):
    """One advertisement report event as (address, fields), or None for anything else."""
    data_at = {LEGACY_REPORT: 18, EXTENDED_REPORT: 26}.get(cmd)
    if data_at is None or len(body) <= data_at:
        return None
    flags, kind = body[0], body[7]
    rssi, channel = struct.unpack_from('<bB', body, 9)
    address = ':'.join(f'{byte:02x}' for byte in reversed(body[1:7])) if kind != 255 else 'anonymous'
    data = body[data_at + 1:data_at + 1 + body[data_at]]
    return address, {'address_type': ADDRESS_TYPES.get(kind, str(kind)), 'rssi': rssi, 'channel': channel,
                     'connectable': bool(flags & CONNECTABLE), 'scannable': bool(flags & SCANNABLE),
                     'extended': cmd == EXTENDED_REPORT, 'name': _name(data)}


def scan(link, seconds=10.0, phy='1m'):
    """Listen for advertisers for `seconds` and say who was heard, strongest first:
    {'seconds', 'phy', 'reports', 'transmitted', 'advertisers': [{'address', 'address_type',
    'rssi' (the strongest heard, dBm), 'reports', 'name', 'connectable', 'scannable', 'extended'}]}.

    A passive scan: the radio only listens. `transmitted` is how many packets it says it sent
    meanwhile, by its own counter, which is 0 for a scan that was passive. The scanner is stopped
    again however this ends."""
    if phy not in PHYS:
        raise ValueError(f'phy: one of {", ".join(PHYS)}')
    before = transmitted(link)
    _ok(link, SCANNER, SCAN_SET_PARAMETERS, struct.pack('<BHH', PASSIVE, SCAN_UNITS, SCAN_UNITS), 'scan parameters')
    heard, count, done = {}, 0, False
    try:                                                 # from before it starts: an interrupt then leaves no scan running
        _ok(link, SCANNER, SCAN_START, bytes([PHYS[phy], OBSERVATION]), 'starting the scan')
        began = time.monotonic()
        while True:
            left = began + seconds - time.monotonic()
            if left <= 0:
                break
            got = link.message(min(left, 0.25))
            if got is None or got[0] != EVENT or got[1] != SCANNER:
                continue
            one = report(got[2], got[3])
            if one is None:
                continue
            address, fields = one
            count += 1
            entry = heard.setdefault(address, dict(fields, reports=0))
            entry['reports'] += 1
            entry['rssi'] = max(entry['rssi'], fields['rssi'])
            entry['name'] = entry['name'] or fields['name']
            for key in ('connectable', 'scannable', 'extended'):
                entry[key] = entry[key] or fields[key]
        took = time.monotonic() - began
        done = True
    finally:
        try:
            _ok(link, SCANNER, SCAN_STOP, what='stopping the scan')
        except RadioError:
            if done:                                     # (else what went wrong first is what is said)
                raise
    sent = (transmitted(link) - before) & 0xffff
    order = ('address', 'address_type', 'rssi', 'reports', 'name', 'connectable', 'scannable', 'extended')
    advertisers = [{key: dict(entry, address=address)[key] for key in order}
                   for address, entry in sorted(heard.items(), key=lambda item: -item[1]['rssi'])]
    return {'seconds': round(took, 1), 'phy': phy, 'reports': count, 'transmitted': sent, 'advertisers': advertisers}


# --- on a unit ---

def tool(unit):
    return unit.tool('w1700k-efr32')


def status(unit):
    """{'efr32': 'on'|'off', 'start': 'on'|'off'|'unheld', 'port': 'on'|'off'} as the unit says it."""
    said = unit.check(f'{tool(unit)} status')
    return dict(line.split('=', 1) for line in said.split() if '=' in line)


def switch(unit, on, keep=False):
    said = unit.check(f'{tool(unit)} {"on" if on else "off"}{" --keep" if keep else ""}')
    return dict(line.split('=', 1) for line in said.split() if '=' in line)


def open_link(unit, baud=BAUD):
    if baud not in BAUDS:
        raise ValueError(f'baud: one of {", ".join(map(str, BAUDS))}')
    return Link(unit.popen_bytes(f'{tool(unit)} link --baud {baud}'))


def pty(unit, baud=BAUD, announce=print, name=None, rounds=None):
    """The radio's port as a pseudo-terminal on this host, until interrupted or the link ends
    (portlink.pty)."""
    portlink.pty(open_link(unit, baud), announce, name, rounds)
