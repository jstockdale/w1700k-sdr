# SPDX-License-Identifier: MIT
"""The unit's ssh host keys on the unit (platform/rootfs/overlay/usr/sbin/w1700k-hostkey), run as
the unit runs it: over a directory for the device tree's /chosen as the loader left it, one for
durable storage, and a stand-in for dropbearkey that reads and makes Ed25519 key files in
Dropbear's form."""
import base64
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOSTKEY = ROOT / 'platform/rootfs/overlay/usr/sbin/w1700k-hostkey'
DEFAULTS = ROOT / 'platform/rootfs/overlay/etc/default/dropbear'

# dropbearkey, as much of it as the script uses: `-y -f FILE` prints a key file's public half,
# `-t ed25519 -f FILE` makes one.
DROPBEARKEY = r'''#!/usr/bin/env python3
import base64, os, struct, sys
def wire(*fields):
    return b''.join(struct.pack('>I', len(f)) + f for f in fields)
args = sys.argv[1:]
path = args[args.index('-f') + 1]
if '-t' in args:
    assert args[args.index('-t') + 1] == 'ed25519'
    if os.path.exists(path):
        sys.exit('exists')
    with open(os.open(path, os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as stream:
        stream.write(wire(b'ssh-ed25519', os.urandom(64)))
data = open(path, 'rb').read()
try:
    n, = struct.unpack_from('>I', data, 0)
    kind = data[4:4 + n]
    m, = struct.unpack_from('>I', data, 4 + n)
    secret = data[8 + n:]
except struct.error:
    sys.exit('not a key')
if kind != b'ssh-ed25519' or m != 64 or len(secret) != 64:
    sys.exit('not a key')
print('Public key portion is:')
print('ssh-ed25519 ' + base64.b64encode(wire(kind, secret[32:])).decode() + ' root@w1700k-sdr')
print('Fingerprint: sha256 x')
'''


def key_file(fill):
    """An Ed25519 key file as Dropbear writes it."""
    return struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 64) + bytes([fill]) * 64


def public_of(data):
    blob = struct.pack('>I', 11) + b'ssh-ed25519' + struct.pack('>I', 32) + data[-32:]
    return 'ssh-ed25519 ' + base64.b64encode(blob).decode()


@unittest.skipUnless(shutil.which('xxd'), 'needs xxd, as the unit has')
class HostKeys(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        for name in ('chosen', 'durable', 'run'):
            (self.dir / name).mkdir()
        (self.dir / 'cmdline').write_text('console=ttyS0,115200 ro w1700k.keyslot=empty w1700k.hostkey=none\n')
        tool = self.dir / 'dropbearkey'
        tool.write_text(DROPBEARKEY)
        tool.chmod(0o755)
        run = self.dir / 'durable-run'
        run.write_text(f'#!/bin/sh\necho "$@" >> {self.dir}/durable-calls\n'
                       f'[ ! -e {self.dir}/durable-busy ] || {{ echo "durable-open: durable is already open" >&2; exit 1; }}\n'
                       'echo "durable-open: /durable mounted from mtd6"\n"$@"\nstatus=$?\n'
                       'echo "durable-close: /durable closed"\nexit $status\n')
        run.chmod(0o755)
        self.keys, self.store = self.dir / 'etc-dropbear', self.dir / 'durable/ssh/host'
        self.env = dict(os.environ, W1700K_HOSTKEY_RUN=str(self.dir / 'run/record'), W1700K_HOSTKEY_KEYS=str(self.keys),
                        W1700K_HOSTKEY_CHOSEN=str(self.dir / 'chosen'), W1700K_HOSTKEY_CMDLINE=str(self.dir / 'cmdline'),
                        W1700K_HOSTKEY_DURABLE_RUN=str(run), W1700K_HOSTKEY_DIR=str(self.dir / 'durable/ssh'),
                        W1700K_HOSTKEY_DROPBEARKEY=str(tool))

    def hostkey(self, *words, ok=True):
        result = subprocess.run(['sh', str(HOSTKEY), *words], capture_output=True, text=True, env=self.env)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def hand_over(self, data, kind='ed25519', said='handed'):
        """What the loader leaves: the key as a string property, and its word on the command line."""
        text = data if isinstance(data, str) else data.hex()
        (self.dir / 'chosen' / f'security-w1700k-host-{kind}').write_bytes(text.encode() + b'\0')
        (self.dir / 'cmdline').write_text(f'console=ttyS0,115200 ro w1700k.hostkey={said}\n')

    def record(self):
        return (self.dir / 'run/record').read_text().strip()

    def in_use(self):
        return (self.keys / 'dropbear_ed25519_host_key').read_bytes()

    def durable_calls(self):
        path = self.dir / 'durable-calls'
        return path.read_text() if path.exists() else ''

    def test_a_key_the_loader_handed_over_is_the_units(self):
        self.hand_over(key_file(7))
        self.hostkey('boot')
        self.assertEqual(self.in_use(), key_file(7))
        self.assertEqual((self.keys / 'dropbear_ed25519_host_key').stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.keys.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.keys / 'dropbear_ed25519_host_key.pub').read_text().strip(), public_of(key_file(7)))
        self.assertEqual(self.record(), 'lasting handed')
        self.assertEqual(self.hostkey('status').stdout.splitlines(),
                         ['hostkey=lasting', 'loader=handed', 'hostkey ' + public_of(key_file(7))])
        self.assertEqual(self.durable_calls(), '', 'start-up does not open durable storage')

    def test_with_none_handed_over_the_unit_makes_one_for_this_boot(self):
        for cmdline, loader in (('ro w1700k.hostkey=none', 'none'), ('ro w1700k.keyslot=empty', 'silent')):
            with self.subTest(loader=loader):
                (self.dir / 'cmdline').write_text(cmdline + '\n')
                self.hostkey('boot')
                first = self.in_use()
                self.assertEqual(self.record(), f'temporary {loader}')
                self.assertEqual(self.hostkey('status').stdout.splitlines(),
                                 ['hostkey=temporary', f'loader={loader}', 'hostkey ' + public_of(first)])
                self.hostkey('boot')
                self.assertNotEqual(self.in_use(), first, 'another one at the next boot')
        self.assertEqual(self.durable_calls(), '')

    def test_the_root_as_built_links_the_key_directory_into_ram(self):
        (self.dir / 'var-run-dropbear').mkdir()
        self.keys.symlink_to(self.dir / 'var-run-dropbear')
        self.hand_over(key_file(7))
        self.hostkey('boot')
        self.assertFalse(self.keys.is_symlink())
        self.assertEqual(self.in_use(), key_file(7))

    def test_what_is_not_a_key_is_not_used_and_the_unit_says_so(self):
        cases = {'not hex': 'zz' * 83, 'upper case': key_file(7).hex().upper(), 'half a byte': key_file(7).hex()[:-1],
                 'empty': '', 'too long': '00' * 600, 'hex that is no key': '00' * 83,
                 'a shell word': '$(touch ' + str(self.dir / 'run/ran') + ')', 'a truncated key': key_file(7).hex()[:100]}
        for name, text in cases.items():
            with self.subTest(name):
                self.hand_over(text)
                result = self.hostkey('boot', ok=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('no usable ed25519 key', result.stderr)
                self.assertTrue(self.record().startswith('temporary '), 'it can still be reached')
                self.assertEqual(len(self.in_use()), 83)
                self.assertNotEqual(self.in_use(), key_file(7))
                self.assertFalse((self.dir / 'run/ran').exists())
                self.assertFalse(list(self.keys.glob('*.part')))

    def test_a_key_under_the_name_of_another_kind_is_not_used(self):
        self.hand_over(key_file(7), kind='ecdsa')
        self.assertNotEqual(self.hostkey('boot', ok=False).returncode, 0)
        self.assertFalse((self.keys / 'dropbear_ecdsa_host_key').exists())
        self.assertTrue(self.record().startswith('temporary '))

    def test_a_key_from_an_earlier_boot_does_not_outlive_it(self):
        self.hand_over(key_file(7))
        self.hostkey('boot')
        (self.dir / 'chosen/security-w1700k-host-ed25519').unlink()
        self.hostkey('boot')
        self.assertNotEqual(self.in_use(), key_file(7))
        self.assertTrue(self.record().startswith('temporary '))

    def test_keeping_makes_this_boots_key_the_units_own(self):
        self.hostkey('boot')
        made = self.in_use()
        kept = self.hostkey('keep')
        self.assertEqual([line for line in kept.stdout.splitlines() if line.startswith('hostkey ')],
                         ['hostkey ' + public_of(made)])
        self.assertEqual(self.store.read_text(), f'host_ed25519={made.hex()}\n', 'as the loader imports it')
        self.assertEqual(self.store.stat().st_mode & 0o077, 0)
        self.assertEqual(self.store.parent.stat().st_mode & 0o077, 0)
        self.assertEqual(self.record(), 'lasting none')
        self.assertNotIn(made.hex()[:32], self.durable_calls(), 'no command line carries the key')
        # The next boot, by a loader that reads the file: the same key.
        self.hand_over(self.store.read_text().strip().split('=', 1)[1])
        self.hostkey('boot')
        self.assertEqual(self.in_use(), made)

    def test_keeping_what_the_unit_already_has_opens_nothing(self):
        self.hand_over(key_file(7))
        self.hostkey('boot')
        self.assertEqual(self.hostkey('keep').stdout.strip(), 'hostkey ' + public_of(key_file(7)))
        self.assertEqual(self.durable_calls(), '')

    def test_a_key_the_unit_has_is_not_replaced_unasked(self):
        (self.dir / 'durable/ssh').mkdir()
        self.store.write_text(f'host_ed25519={key_file(7).hex()}\n')
        self.hostkey('boot')                    # a loader that did not hand it over
        refused = self.hostkey('keep', ok=False)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn('--replace', refused.stderr)
        self.assertEqual(self.store.read_text(), f'host_ed25519={key_file(7).hex()}\n')
        self.assertFalse(list(self.store.parent.glob('*.part')))
        self.assertTrue(self.record().startswith('temporary '))
        self.hostkey('keep', '--replace')
        self.assertEqual(self.store.read_text(), f'host_ed25519={self.in_use().hex()}\n')
        self.assertEqual(self.record(), 'lasting none')

    def test_a_root_from_before_carries_the_key_built_into_it_across(self):
        # No start-up record: that root never ran `boot`. Its key is in its own /etc/dropbear.
        self.keys.mkdir()
        (self.keys / 'dropbear_ed25519_host_key').write_bytes(key_file(5))
        (self.keys / 'dropbear_ed25519_host_key.pub').write_text(public_of(key_file(5)) + '\n')
        (self.dir / 'cmdline').write_text('console=ttyS0,115200 ro w1700k.keyslot=empty\n')
        self.assertEqual(self.hostkey('status').stdout.splitlines(),
                         ['hostkey=built-in', 'loader=silent', 'hostkey ' + public_of(key_file(5))])
        for _ in range(2):                      # and again, by the next update that asks
            kept = self.hostkey('keep')
            self.assertIn('hostkey ' + public_of(key_file(5)), kept.stdout.splitlines())
            self.assertEqual(self.store.read_text(), f'host_ed25519={key_file(5).hex()}\n')
        self.assertFalse((self.dir / 'run/record').exists())
        self.assertEqual(self.in_use(), key_file(5), 'the running root is left as it is')

    def test_storage_that_cannot_be_opened_keeps_nothing(self):
        self.hostkey('boot')
        (self.dir / 'durable-busy').touch()
        self.assertNotEqual(self.hostkey('keep', ok=False).returncode, 0)
        self.assertFalse(self.store.exists())
        self.assertTrue(self.record().startswith('temporary '))

    def test_anything_else_is_usage(self):
        self.hostkey('boot')
        for words in ((), ('nonsense',), ('keep', '--force')):
            self.assertNotEqual(self.hostkey(*words, ok=False).returncode, 0)

    def test_dropbear_is_given_every_key_in_place(self):
        text = DEFAULTS.read_text().replace('/etc/dropbear/', str(self.keys) + '/')
        script = self.dir / 'defaults'
        script.write_text(text + 'echo "$DROPBEAR_ARGS"\n')
        self.keys.mkdir()
        said = lambda: subprocess.run(['sh', str(script)], capture_output=True, text=True, check=True).stdout.split()
        self.assertEqual(said(), ['-s'], 'with none, Dropbear makes its own as it is asked')
        for kind in ('ed25519', 'ecdsa'):
            (self.keys / f'dropbear_{kind}_host_key').write_bytes(b'key')
            (self.keys / f'dropbear_{kind}_host_key.pub').write_text('public\n')
        self.assertEqual(said(), ['-s', '-r', f'{self.keys}/dropbear_ecdsa_host_key',
                                  '-r', f'{self.keys}/dropbear_ed25519_host_key'])


if __name__ == '__main__':
    sys.exit(unittest.main())
