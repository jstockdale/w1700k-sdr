#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package the Velo7 Max's kernel, device tree and a RAM root into the image its stock U-Boot starts.

    platform/velo7max/image.py [--login-key PUBLIC_KEY --unit-dir DIR]
                               [--management PORT ADDRESS/LEN] [--stream PORT ADDRESS/LEN]

Output: platform/build/images/velo7max-ram.itb, a FIT of the kernel (LZMA), the device tree and
an initramfs holding a busybox, the w1700k_sdr module and its clients. Nothing is installed on
the unit: stock U-Boot is given the image in RAM and starts it (platform/velo7max/README.md),
and the kernel has no node for the flash.

Without a login key the image lets nobody in but its serial console. With --login-key it also
runs an ssh server for that key alone, on the management port, under the unit's own identity
key: the one in --unit-dir (made there on first use, as init/provision keeps a W1700K's), whose
public half is written to DIR/known_hosts for the host to check. A unit directory is one unit's:
an image made with a key is that unit's image.

The FIT is written here, without mkimage: its hashes are CRC32 and SHA-1, which is what the
stock U-Boot's own images carry and what it was seen to check.
"""
import argparse
import gzip
import hashlib
import ipaddress
import lzma
from pathlib import Path
import stat
import struct
import sys
import zlib

UNIT = Path(__file__).resolve().parent
sys.path[:0] = [str(UNIT), str(UNIT.parent), str(UNIT.parents[1] / 'init')]
from buildlib import BUILDROOT_OUT, CROSS_COMPILE, IMAGES, LOGS, build_env, main_guard, require, run  # noqa: E402
import build as kernel  # noqa: E402

FIT = IMAGES / 'velo7max-ram.itb'
LOG = LOGS / 'velo7max.log'
TARGET = BUILDROOT_OUT / 'target'
CLIENTS = ('mt7996-probe', 'mt7996-download', 'mt7996-stream', 'mt7996-ctl')
# Where the host looks for them (host/w1700k/config.py UnitConfig).
BIN_DIR, MODULE_PATH = 'usr/sbin', 'lib/modules/w1700k_sdr.ko'
HOST_KEY = 'etc/dropbear/dropbear_ed25519_host_key'
# The stock image's own kernel address, and where the image is given to U-Boot: the kernel,
# unpacked, must end below the image it is unpacked from.
KERNEL_LOAD, FIT_LOAD = 0x48080000, 0x50000000
MANAGEMENT = ('lan0', '192.168.1.1/24')     # the socket marked LAN 1
STREAM = ('eth2', '10.77.0.1/24')           # the 10 GbE port stock calls its LAN one
STREAM_MTU = 9194                           # the most the kernel takes (patches/0001)


def newc(name, mode, data=b'', inode=1, rdev=(0, 0)):
    """One `newc` cpio record, owned by root, with a zero timestamp (as platform/images.py)."""
    encoded = name.encode() + b'\0'
    fields = (inode, mode, 0, 0, 1, 0, len(data), 0, 0, rdev[0], rdev[1], len(encoded), 0)
    record = b'070701' + b''.join(f'{value:08x}'.encode() for value in fields) + encoded
    record += bytes(-len(record) % 4) + data
    return record + bytes(-len(data) % 4)


def configuration(management, stream):
    return (f'MANAGEMENT_PORT={management[0]}\nMANAGEMENT_ADDRESS={management[1]}\n'
            f'STREAM_PORT={stream[0]}\nSTREAM_ADDRESS={stream[1]}\nSTREAM_MTU={STREAM_MTU}\n')


def root_entries(files, management=MANAGEMENT, stream=STREAM, login_key=None, host_key=None):
    """The RAM root as {name: (mode, bytes)}. `files` is {name in the root: bytes} for the
    programs and the module; with `login_key` (a public key line) and `host_key` (Dropbear's
    file) the root also lets that key in over ssh."""
    directory, program, plain, private = (stat.S_IFDIR | 0o755, stat.S_IFREG | 0o755,
                                          stat.S_IFREG | 0o644, stat.S_IFREG | 0o600)
    entries = {name: (directory, b'') for name in
               ('bin', 'dev', 'etc', 'lib', 'lib/modules', 'proc', 'run', 'sbin', 'sys', 'tmp',
                'usr', 'usr/bin', 'usr/sbin', 'var', 'var/run')}
    entries['root'] = (stat.S_IFDIR | 0o700, b'')
    entries['dev/console'] = (stat.S_IFCHR | 0o600, b'')
    entries['init'] = (program, (UNIT / 'ramroot/init').read_bytes())
    entries['etc/velo7max.conf'] = (plain, configuration(management, stream).encode())
    entries['etc/passwd'] = (plain, b'root:x:0:0:root:/root:/bin/sh\n')
    entries['etc/group'] = (plain, b'root:x:0:\n')
    entries['etc/shells'] = (plain, b'/bin/sh\n')
    for name, data in files.items():
        entries[name] = (plain if name == MODULE_PATH else program, data)
    require((login_key is None) == (host_key is None), 'a login key and the unit\'s identity key go together')
    if login_key is not None:
        entries['root/.ssh'] = (stat.S_IFDIR | 0o700, b'')
        entries['root/.ssh/authorized_keys'] = (private, login_key.strip() + b'\n')
        entries['etc/dropbear'] = (stat.S_IFDIR | 0o700, b'')
        entries[HOST_KEY] = (private, host_key)
    else:
        entries.pop('usr/sbin/dropbear', None)       # no key, no server
    return entries


def initramfs(entries):
    """The entries as a gzipped newc archive: sorted, root's, timestamps zero."""
    archive = bytearray()
    for inode, name in enumerate(sorted(entries), 1):
        mode, data = entries[name]
        archive += newc(name, mode, data, inode, (5, 1) if name == 'dev/console' else (0, 0))
    archive += newc('TRAILER!!!', stat.S_IFREG, inode=len(entries) + 1)
    archive += bytes(-len(archive) % 512)
    return gzip.compress(bytes(archive), compresslevel=9, mtime=0)


# --------------------------------------------------------------------------
# The FIT: a flattened device tree, written directly
# --------------------------------------------------------------------------

def _cells(*values):
    return struct.pack(f'>{len(values)}I', *values)


def _text(value):
    return value.encode() + b'\0'


def flatten(tree):
    """A version 17 flattened device tree of `tree`: (name, {property: bytes}, [children])."""
    strings, offsets = bytearray(), {}

    def name_offset(name):
        if name not in offsets:
            offsets[name] = len(strings)
            strings.extend(_text(name))
        return offsets[name]

    def node(item):
        name, properties, children = item
        out = _cells(1) + _text(name)
        out += bytes(-len(out) % 4)
        for key, value in properties.items():
            out += _cells(3, len(value), name_offset(key)) + value + bytes(-len(value) % 4)
        for child in children:
            out += node(child)
        return out + _cells(2)

    structure = node(tree) + _cells(9)
    strings.extend(bytes(-len(strings) % 4))    # a whole number of words in all
    reservations = bytes(16)
    off_reservations = 40
    off_structure = off_reservations + len(reservations)
    off_strings = off_structure + len(structure)
    total = off_strings + len(strings)
    header = _cells(0xd00dfeed, total, off_structure, off_strings, off_reservations, 17, 16, 0,
                    len(strings), len(structure))
    return header + reservations + structure + bytes(strings)


def hashes(data):
    return [('hash-1', {'algo': _text('crc32'), 'value': _cells(zlib.crc32(data))}, []),
            ('hash-2', {'algo': _text('sha1'), 'value': hashlib.sha1(data).digest()}, [])]


def fit(kernel_lzma, dtb, ramdisk, release):
    """The image stock U-Boot's bootm takes: kernel, device tree, initramfs, one configuration."""
    def image(name, description, data, kind, compression, **more):
        properties = {'description': _text(description), 'data': data, 'type': _text(kind),
                      'arch': _text('arm64'), 'compression': _text(compression)}
        properties.update(more)
        return (name, properties, hashes(data))
    images = ('images', {}, [
        image('kernel-1', f'Linux {release}', kernel_lzma, 'kernel', 'lzma', os=_text('linux'),
              load=_cells(KERNEL_LOAD), entry=_cells(KERNEL_LOAD)),
        image('fdt-1', 'LTC Velo7 Max, w1700k-sdr, started from RAM', dtb, 'flat_dt', 'none'),
        image('ramdisk-1', 'initramfs', ramdisk, 'ramdisk', 'none', os=_text('linux')),
    ])
    configurations = ('configurations', {'default': _text('config-1')}, [
        ('config-1', {'description': _text('Velo7 Max, w1700k-sdr'), 'kernel': _text('kernel-1'),
                      'fdt': _text('fdt-1'), 'ramdisk': _text('ramdisk-1')}, []),
    ])
    return flatten(('', {'description': _text('Velo7 Max: w1700k-sdr, started from RAM'),
                         '#address-cells': _cells(1)}, [images, configurations]))


# --------------------------------------------------------------------------

def port_and_address(values):
    port, address = values
    ipaddress.IPv4Interface(address)
    require('/' in address, f'{address}: an address with its prefix length, as 192.168.1.1/24')
    require(port.isalnum(), f'{port}: not a port name')
    return port, address


def unit_keys(unit_dir, login_key, address):
    """The login key's line and the unit's Dropbear identity key; writes DIR/known_hosts."""
    from initkit import provision
    line = provision.authorized_key(login_key)
    key = provision.host_key(unit_dir)
    public = provision.host_public_key(key).decode()
    known = Path(unit_dir) / provision.KNOWN_HOSTS
    known.write_text(f'{address.split("/")[0]} {public}\n')
    print(f'velo7max: the unit\'s ssh identity key is {provision.fingerprint(public)}; {known}')
    return line, key


def stripped(module):
    """The module without its debugging sections, which are most of it."""
    out = kernel.OUT / 'w1700k_sdr.stripped.ko'
    run([CROSS_COMPILE + 'strip', '--strip-debug', '-o', out, module], env=build_env(), log=LOG)
    return out.read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--login-key', help='a public key file: the one key ssh lets in, as root')
    parser.add_argument('--unit-dir', help="the unit's directory, where its ssh identity key is kept")
    parser.add_argument('--management', nargs=2, metavar=('PORT', 'ADDRESS/LEN'), default=MANAGEMENT)
    parser.add_argument('--stream', nargs=2, metavar=('PORT', 'ADDRESS/LEN'), default=STREAM)
    args = parser.parse_args()
    require(bool(args.login_key) == bool(args.unit_dir), '--login-key and --unit-dir go together')
    management, stream = port_and_address(args.management), port_and_address(args.stream)
    for path in (kernel.KERNEL_IMAGE, kernel.DTB, kernel.MODULE):
        require(path.is_file(), f'{path} is missing; run platform/velo7max/build.py first')
    busybox = TARGET / 'bin/busybox'
    require(busybox.is_file(), f'{busybox} is missing; run platform/rootfs/build.py toolchain first')

    files = {'bin/busybox': busybox.read_bytes(), 'usr/sbin/ethtool': (TARGET / 'usr/sbin/ethtool').read_bytes(),
             'usr/sbin/dropbear': (TARGET / 'usr/sbin/dropbear').read_bytes(),
             MODULE_PATH: stripped(kernel.MODULE)}
    files.update({f'{BIN_DIR}/{name}': (kernel.SDR_OUT / name).read_bytes() for name in CLIENTS})
    login_key = host_key = None
    if args.login_key:
        login_key, host_key = unit_keys(args.unit_dir, args.login_key, management[1])
    ramdisk = initramfs(root_entries(files, management, stream, login_key, host_key))

    image = kernel.KERNEL_IMAGE.read_bytes()
    require(image[56:60] == b'ARM\x64', 'the kernel is not an ARM64 Image')
    runtime = struct.unpack_from('<Q', image, 16)[0]
    require(KERNEL_LOAD + runtime <= FIT_LOAD, f'the running kernel ({runtime} bytes) reaches the image it came from')
    release = (kernel.LINUX_OUT / 'include/config/kernel.release').read_text().strip()
    blob = fit(lzma.compress(image, format=lzma.FORMAT_ALONE, preset=9), kernel.DTB.read_bytes(), ramdisk, release)
    IMAGES.mkdir(parents=True, exist_ok=True)
    FIT.write_bytes(blob)
    print(f'velo7max: {FIT} ({len(blob)} bytes, sha256 {hashlib.sha256(blob).hexdigest()}): at stock U-Boot\'s '
          f'prompt, into RAM at {FIT_LOAD:#x} and `bootm {FIT_LOAD:#x}`')
    return 0


if __name__ == '__main__':
    main_guard(main)
