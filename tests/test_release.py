# SPDX-License-Identifier: MIT
"""Signed releases: the envelope on the host, the verifier a unit runs, the archive, the
signing tool, and the unit's update script taking only what a release lists."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock
import zlib

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'init'))
from initkit import bundle, config, keying, seal  # noqa: E402
from initkit.console import StepFailed  # noqa: E402

SEAL = ROOT / 'seal'
SOURCES = ('release.c', 'wms2.c', 'monocypher.c', 'optional/monocypher-ed25519.c')
SCRIPT = ROOT / 'platform/rootfs/overlay/usr/sbin/system-update'
CC = os.environ.get('CC', 'cc')
# RFC 8032, section 7.1, tests 1 to 3: public key, message, signature.
RFC = (('d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a', '',
        'e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b4'
        '6bd25bf5f0595bbe24655141438e7a100b'),
       ('3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c', '72',
        '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d'
        '8c387b2eaeb4302aeeb00d291612bb0c00'),
       ('fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025', 'af82',
        '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6'
        '594a7c15e9716ed28dc027beceea1ec40a'))
MANIFEST = (json.dumps({'format': 1, 'files': {'rootfs.squashfs': {'sha256': 'ab' * 32, 'bytes': 3}}},
                       indent=1) + '\n').encode()


ROOT_KEY, KEYS_KEY, PRIMARY, SPARE, STRANGER, NEW_ROOT_KEY, NEW_KEYS_KEY = 5, 6, 1, 2, 3, 8, 9
NAMES = {ROOT_KEY: 'the-root', KEYS_KEY: 'the-keys', PRIMARY: 'primary', SPARE: 'spare', STRANGER: 'stranger',
         NEW_ROOT_KEY: 'new-root', NEW_KEYS_KEY: 'new-keys'}
USUAL = ((ROOT_KEY, 'root'), (KEYS_KEY, 'keys'), (PRIMARY, 'release'), (SPARE, 'release'))


def signing(number):
    """(public key, sign) of a fixed test key; the test is skipped where nothing can sign."""
    try:
        return seal.signer(bytes((number,)) * 32)
    except seal.Refused as error:
        raise unittest.SkipTest(str(error)) from None


class Signatures(unittest.TestCase):
    """The host's own Ed25519 check, which reads a release with no library."""

    def test_the_rfcs_vectors_verify(self):
        for public, message, signature in RFC:
            with self.subTest(message):
                self.assertTrue(seal.verifies(bytes.fromhex(public), bytes.fromhex(message),
                                              bytes.fromhex(signature)))

    def test_anything_changed_does_not(self):
        public, message, signature = (bytes.fromhex(part) for part in RFC[2])
        self.assertFalse(seal.verifies(public, message + b'\0', signature))
        self.assertFalse(seal.verifies(public, message, signature[:-1] + bytes((signature[-1] ^ 1,))))
        self.assertFalse(seal.verifies(public, message, bytes((signature[0] ^ 1,)) + signature[1:]))
        self.assertFalse(seal.verifies(bytes.fromhex(RFC[1][0]), message, signature))

    def test_what_is_not_a_signature_or_a_key_is_refused_not_raised(self):
        public, message, signature = (bytes.fromhex(part) for part in RFC[1])
        self.assertFalse(seal.verifies(public[:31], message, signature))
        self.assertFalse(seal.verifies(public, message, signature[:63]))
        self.assertFalse(seal.verifies(b'\xff' * 32, message, signature))
        # The second half is a number below the group's order; the same plus the order is not.
        high = (int.from_bytes(signature[32:], 'little') + seal.ORDER).to_bytes(32, 'little')
        self.assertFalse(seal.verifies(public, message, signature[:32] + high))

    def test_it_agrees_with_whatever_signs(self):
        public, sign = signing(7)
        for message in (b'', b'a', os.urandom(1000)):
            self.assertTrue(seal.verifies(public, message, sign(message)))


def stock_environment(*variables, size=0x4000):
    """The stock boot loader's environment as it sits in flash: a CRC-32, then the variables."""
    data = (b''.join(variable.encode() + b'\0' for variable in variables) + b'\0').ljust(size - 4, b'\0')
    return struct.pack('<I', zlib.crc32(data)) + data


STOCK = ('bootcmd=run w1700k', 'bootdelay=3', 'ethaddr=00:11:22:33:44:55')


def a_list(stamp=1, rows=USUAL, names=NAMES):
    """A list of test keys in its one form: `rows` are (key number, scope); `stamp` is its
    (epoch, generation), or the generation alone, in epoch 1."""
    stamp = stamp if isinstance(stamp, tuple) else (1, stamp)
    return seal.format_list(stamp, [(signing(number)[0], scope, names[number]) for number, scope in rows])


def rotation(text, by, **options):
    """The list `text` sealed by test key number `by`."""
    return seal.seal_list(text, signing(by)[1], **options)


CHAIN_MAGIC = b'w1700k-sdr key chain 1\n'


def kept(*envelopes):
    """What a unit keeps of its lists, as seal/release.c reads it: the sealed envelopes that
    bear out the one it holds, each behind its length."""
    return CHAIN_MAGIC + b''.join(struct.pack('<I', len(envelope)) + envelope for envelope in envelopes)


def links(data):
    """The envelopes in what a unit keeps."""
    assert data.startswith(CHAIN_MAGIC), data[:40]
    found, at = [], len(CHAIN_MAGIC)
    while at < len(data):
        length, = struct.unpack_from('<I', data, at)
        found.append(data[at + 4:at + 4 + length])
        at += 4 + length
    return found


class Kept(type(Path())):
    """The file a unit keeps its list in, written and read here as the list's text: a list a
    test root key is in is kept as the first list a unit was given, sealed by that key. What
    is no list, or one no test key can seal, is written as it is, and is no list to a unit."""

    def write_bytes(self, data):
        try:
            roots = [key.public for key in seal.parse_list(data).keys if key.scope == 'root']
        except seal.Refused:
            roots = []
        by = next((number for number in range(1, 30) if signing(number)[0] in roots), None)
        return super().write_bytes(data if by is None else kept(rotation(data, by)))

    def read_bytes(self):
        data = super().read_bytes()
        return seal.body_of(links(data)[-1]) if data.startswith(CHAIN_MAGIC) else data

    def kept(self):
        return super().read_bytes()

    def keep(self, data):
        return super().write_bytes(data)


def resealed(envelope, by, topic=seal.ROTATE_TOPIC, change=None):
    """`envelope` with its header or body changed by `change(bytearray)`, and signed again by
    test key `by` under `topic`: what a key holder can make that the tools here would not."""
    whole = bytearray(envelope[:-seal.SIGNATURE])
    if change:
        whole = bytearray(change(whole) or whole)
    message = struct.pack('<H', len(topic)) + topic.encode() + bytes(whole)
    return bytes(whole) + signing(by)[1](message)


class Envelope(unittest.TestCase):
    def test_the_layout_is_wms2s(self):
        public, sign = signing(1)
        sealed = seal.seal(MANIFEST, 258, sign, when_ms=0x0102030405)
        self.assertEqual(len(sealed), 40 + len(MANIFEST) + 64)
        self.assertEqual(sealed[:6], b'WMS2\x02\x00')
        self.assertEqual(sealed[6:22], b'w1700k-sdr' + bytes(6))
        self.assertEqual(sealed[22:30], bytes((2, 1, 0, 0, 0, 0, 0, 0)))        # the release, little-endian
        self.assertEqual(sealed[30:38], bytes((5, 4, 3, 2, 1, 0, 0, 0)))
        self.assertEqual(sealed[38:40], b'\0\0')
        topic = b'w1700k-sdr/release'
        self.assertTrue(seal.verifies(public, struct.pack('<H', len(topic)) + topic + sealed[:-64],
                                      sealed[-64:]))

    def test_a_rotation_is_the_list_under_its_own_topic_with_its_generation_as_the_counter(self):
        public, _ = signing(ROOT_KEY)
        text = a_list(7)
        sealed = rotation(text, ROOT_KEY, when_ms=1)
        self.assertEqual((sealed[:22], sealed[22:30], sealed[40:-64]),
                         (b'WMS2\x02\x00w1700k-sdr' + bytes(6), struct.pack('<Q', 7), text))
        topic = b'w1700k-sdr/rotate-keys'
        self.assertTrue(seal.verifies(public, struct.pack('<H', len(topic)) + topic + sealed[:-64], sealed[-64:]))

    def test_the_host_and_the_unit_mean_the_same_things(self):
        header = (SEAL / 'release.h').read_text()
        for name, value in (('RELEASE_TOPIC', seal.TOPIC), ('ROTATE_TOPIC', seal.ROTATE_TOPIC),
                            ('RELEASE_PRODUCT', seal.PRODUCT), ('RELEASE_ENVELOPE_MOST', seal.ENVELOPE_MOST),
                            ('KEYS_MOST', seal.KEYS_MOST), ('KEY_NAME_MOST', seal.KEY_NAME_MOST),
                            ('EPOCH_MOST', seal.EPOCH_MOST), ('GENERATION_MOST', seal.GENERATION_MOST),
                            ('LIST_MOST', seal.LIST_MOST)):
            with self.subTest(name):
                found = re.search(rf'#define {name} "?([^"\n]+)"?', header).group(1)
                self.assertEqual(found, str(value))
        code = (SEAL / 'release.c').read_text()
        self.assertEqual(tuple(re.search(r'scope_names\[SCOPES\] = \{ ([^}]+) \}', code).group(1)
                               .replace('"', '').split(', ')), seal.SCOPES)
        # The longest list there can be is a list.
        longest = seal.format_list((seal.EPOCH_MOST, seal.GENERATION_MOST), [(signing(n)[0], 'release' if n > 1 else 'root', 'n' * 47 + str(n))
                                                          for n in range(1, 9)])
        self.assertLessEqual(len(longest), seal.LIST_MOST)

    def test_a_release_opens_with_any_of_the_keys(self):
        primary, sign = signing(1)
        spare, _ = signing(2)
        sealed = seal.seal(MANIFEST, 4, sign)
        self.assertEqual(seal.unseal(sealed, [spare, primary]), (4, MANIFEST, primary))
        self.assertEqual(seal.body_of(sealed), MANIFEST)

    def test_what_is_refused_and_why(self):
        primary, sign = signing(1)
        spare, _ = signing(2)
        sealed = seal.seal(MANIFEST, 4, sign)
        changed = bytearray(sealed)
        changed[60] ^= 1
        for envelope, keys, why in ((sealed, [spare], 'none of the release keys'),
                                    (sealed, [], 'none given'),
                                    (bytes(changed), [primary], 'none of the release keys'),
                                    (sealed[:80], [primary], 'not the size'),
                                    (b'WMS1' + sealed[4:], [primary], 'not a WMS2 control envelope'),
                                    (sealed[:4] + b'\x01' + sealed[5:], [primary], 'not a WMS2 control'),
                                    (sealed + bytes(seal.ENVELOPE_MOST), [primary], 'not the size')):
            with self.subTest(why), self.assertRaisesRegex(seal.Refused, why):
                seal.unseal(envelope, keys)

    def test_a_release_for_another_product_is_not_one_for_this(self):
        primary, sign = signing(1)
        with mock.patch.object(seal, 'PRODUCT', 'other-product'):
            other = seal.seal(MANIFEST, 4, sign)
        with self.assertRaisesRegex(seal.Refused, 'sealed for other-product'):
            seal.unseal(other, [primary])
        with mock.patch.object(seal, 'TOPIC', 'other/release'):
            other = seal.seal(MANIFEST, 4, sign)
        with self.assertRaisesRegex(seal.Refused, 'none of the release keys'):
            seal.unseal(other, [primary])

    def test_a_release_has_a_number_from_one_and_a_manifest(self):
        _, sign = signing(1)
        for body, number in ((MANIFEST, 0), (MANIFEST, -1), (MANIFEST, 1 << 64), (b'', 1), (b'a\0b', 1),
                             (bytes(seal.ENVELOPE_MOST).replace(b'\0', b'x'), 1)):
            with self.subTest(number=number, size=len(body)), self.assertRaises(seal.Refused):
                seal.seal(body, number, sign)

    def test_a_list_names_its_keys_by_scope(self):
        keys = seal.parse_list(a_list(3))
        self.assertEqual((keys.stamp, keys.label, [key.scope for key in keys.keys], [key.name for key in keys.keys]),
                         ((1, 3), '1.3', ['root', 'keys', 'release', 'release'], ['the-root', 'the-keys', 'primary', 'spare']))
        self.assertEqual(keys.release_keys(), [signing(PRIMARY)[0], signing(SPARE)[0]])
        self.assertEqual({key.name for key in keys.authorities()}, {'the-keys', 'the-root'})
        self.assertEqual(keys.text, a_list(3))
        self.assertEqual(seal.registry_fingerprint(bytes(32)), hashlib.sha256(bytes(32)).hexdigest()[:16])

    def test_the_points_of_small_order_are_the_eight_and_no_honest_key(self):
        identity = lambda point: point[0] % seal.P == 0 and (point[1] - point[2]) % seal.P == 0   # noqa: E731
        found = set()
        for encoded in seal._SMALL:
            for sign in (0, 0x80):
                key = encoded[:31] + bytes((encoded[31] | sign,))
                self.assertTrue(seal.small_order(key))
                point = seal._point(key)
                if point is not None:               # the others are not points at all, or not in one form
                    self.assertTrue(identity(seal._multiply(8, point)), key.hex())
                    found.add((point[0] % seal.P, point[1] % seal.P))
        self.assertEqual(len(found), 8)
        for number in range(1, 40):
            self.assertFalse(seal.small_order(signing(number)[0]))


# Lists as text, and whether each is one. The host and the unit read them alike or the test fails.
def list_cases():
    good = a_list(1).decode()
    root, keys, primary, spare = (line for line in good.splitlines()[1:])
    head = 'w1700k-sdr keys 1.1\n'
    other = [signing(number)[0].hex() for number in range(10, 20)]
    small = sorted(seal._SMALL)
    yield 'the usual list', good, True
    yield 'a root alone', head + root + '\n', True
    yield 'no release key: a freeze', head + root + '\n' + keys + '\n', True
    yield 'two roots', head + root + '\n' + f'{other[0]}  root  second-root\n', True
    yield 'eight keys', head + root + '\n' + ''.join(f'{key}  release  r{n}\n' for n, key in enumerate(other[:7])), True
    yield 'a name of 48', head + root + '\n' + f'{other[0]}  release  {"a" * 48}\n', True
    yield 'the last list there can be', good.replace('keys 1.1\n', 'keys 9999.1000000000\n'), True
    yield 'a later epoch', good.replace('keys 1.1\n', 'keys 12.7\n'), True
    yield 'a key that only tells a host what is current', good + f'{other[0]}  timestamp  current\n', True
    yield 'nine keys', head + root + '\n' + ''.join(f'{key}  release  r{n}\n' for n, key in enumerate(other[:8])), False
    yield 'no key', head, False
    yield 'no root', head + keys + '\n' + primary + '\n', False
    yield 'nothing', '', False
    yield 'a name of 49', head + root + '\n' + f'{other[0]}  release  {"a" * 49}\n', False
    yield 'no name', head + root + '\n' + f'{other[0]}  release  \n', False
    yield 'a name in capitals', good.replace('primary', 'Primary'), False
    yield 'a name with an underscore', good.replace('primary', 'pri_mary'), False
    yield 'a name with a space', good.replace('primary', 'pri mary'), False
    yield 'the scope padded', good.replace('  keys  ', '  keys     '), False
    yield 'one space before the scope', good.replace('  release  primary', ' release  primary'), False
    yield 'one space after the scope', good.replace('  release  primary', '  release primary'), False
    yield 'a tab', good.replace('  release  primary', '\trelease  primary'), False
    yield 'a scope nobody has', good.replace('  release  primary', '  admin  primary'), False
    yield 'a scope in capitals', good.replace('  root  ', '  ROOT  '), False
    yield 'the key in capitals', good.replace(root[:64], root[:64].upper()), False
    yield 'a short key', good.replace(primary[:64], primary[:62]), False
    yield 'a long key', good.replace(primary[:64], primary[:64] + 'ab'), False
    yield 'the same key twice', good + f'{primary[:64]}  release  again\n', False
    yield 'the same key with two scopes', good + f'{primary[:64]}  keys  again\n', False
    yield 'the same name twice', good + f'{other[0]}  release  primary\n', False
    yield 'no line feed at the end', good[:-1], False
    yield 'two line feeds at the end', good + '\n', False
    yield 'an empty line', good.replace('\n', '\n\n', 1), False
    yield 'carriage returns', good.replace('\n', '\r\n'), False
    yield 'a space at the end of a line', good.replace('primary\n', 'primary \n'), False
    for name, first in (('a space at the end of the first line', '1.1 '), ('epoch 0', '0.1'), ('generation 0', '1.0'),
                        ('an epoch with a zero before it', '01.1'), ('a generation with a zero before it', '1.01'),
                        ('a sign', '+1.1'), ('a sign on the generation', '1.-1'), ('no epoch', '1'), ('no generation', '1.'),
                        ('no epoch before the dot', '.1'), ('three numbers', '1.1.1'), ('a comma', '1,1'),
                        ('nothing', ''), ('hex', '0x1.1'), ('an epoch past the last', '10000.1'),
                        ('a generation past the last', '1.1000000001'), ('a generation of 20 digits', '1.' + '9' * 20),
                        ('an epoch of 20 digits', '9' * 20 + '.1'), ('a space in it', '1. 1')):
        yield name, good.replace('keys 1.1\n', f'keys {first}\n'), False
    yield 'another product', good.replace('w1700k-sdr keys', 'watcher keys'), False
    yield 'no first line', good.split('\n', 1)[1], False
    yield 'a comment', head + '# keys\n' + root + '\n', False
    yield 'too long to be a list', good + 'x' * seal.LIST_MOST, False
    for point in small:
        yield f'a key of small order {point.hex()[:8]}', good + f'{point.hex()}  release  weak\n', False
        signed = point[:31] + bytes((point[31] | 0x80,))
        yield f'a key of small order {signed.hex()[:8]}, the sign set', good + f'{signed.hex()}  release  weak\n', False


class Built(unittest.TestCase):
    """seal/release.c built for this host, a list of keys held, and a directory to work in."""

    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        cls.program = Path(cls.build.name) / 'w1700k-release'
        result = subprocess.run([CC, '-std=c99', '-D_POSIX_C_SOURCE=200809L', '-O1', '-Wall', '-Wextra',
                                 '-Werror', '-Wno-comment', '-I', str(SEAL), '-I', str(SEAL / 'include'),
                                 *(str(SEAL / source) for source in SOURCES), '-o', str(cls.program)],
                                capture_output=True, text=True)
        if result.returncode:
            cls.build.cleanup()
            raise AssertionError('seal/ does not compile:\n' + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.primary, self.sign = signing(PRIMARY)
        self.spare, self.sign_spare = signing(SPARE)
        self.keys = Kept(self.dir / 'keys')
        self.keys.write_bytes(a_list(1))
        self.state = self.dir / 'state'
        self.out = self.dir / 'keys.new'

    def run_it(self, verb, *arguments):
        options = (['--keys', str(self.keys)] if verb in ('verify', 'list', 'rotate') else []) + \
                  (['--state', str(self.state)] if verb in ('verify', 'allows', 'number') else [])
        return subprocess.run([str(self.program), verb, *options, *map(str, arguments)],
                              capture_output=True)

    def verify(self, envelope, floor=0):
        path = self.dir / 'release.wms2'
        path.write_bytes(envelope)
        result = self.run_it('verify', '--floor', floor, path)
        result.stdout, result.stderr = result.stdout.decode(), result.stderr.decode()
        return result

    def rotate(self, envelope, first=False):
        """What the unit's verifier makes of a rotation: ('taken', the list it wrote),
        ('unchanged', None) or ('refused', what it said)."""
        path = self.dir / 'keys.wms2'
        path.write_bytes(envelope)
        self.out.unlink(missing_ok=True)
        result = self.run_it('rotate', *(['--first'] if first else []), '--out', self.out, path)
        said = result.stderr.decode(errors='replace')
        if result.returncode:
            self.assertFalse(self.out.exists(), 'nothing is written of what is refused')
            self.assertEqual(result.returncode, 1, said)
            return 'refused', said
        if result.stdout.endswith(b'unchanged\n'):
            self.assertFalse(self.out.exists())
            return 'unchanged', None
        return 'taken', seal.body_of(links(self.out.read_bytes())[-1])

    def both(self, envelope, first=False):
        """The unit's word on a rotation, which the host's has to be as well."""
        outcome, detail = self.rotate(envelope, first)
        held = None if first else seal.parse_list(self.keys.read_bytes())
        try:
            following, by = seal.rotated(held, envelope)
            host = ('unchanged', None) if by is None else ('taken', following.text)
        except seal.Refused as error:
            host = ('refused', str(error))
        self.assertEqual(host[0], outcome, f'the host says {host}, the unit {outcome}: {detail}')
        if outcome == 'taken':
            self.assertEqual(host[1], detail)
        return outcome, detail


@unittest.skipUnless(shutil.which(CC), 'no C compiler')
class Lists(Built):
    def test_the_unit_and_the_host_read_a_list_alike(self):
        for name, text, good in list_cases():
            with self.subTest(name):
                data = text.encode('latin-1')
                self.keys.write_bytes(data)
                shown = self.run_it('list')
                self.assertEqual(shown.returncode, 0 if good else 2, shown.stderr)
                if good:
                    self.assertEqual(seal.parse_list(data).text, data)
                else:
                    with self.assertRaises(seal.Refused):
                        seal.parse_list(data)
                    # Sealed by its own root key, it is no first list either.
                    self.assertEqual(self.rotate(resealed(rotation(a_list(1), ROOT_KEY), ROOT_KEY,
                                                          change=lambda whole: whole[:40] + data), first=True)[0],
                                     'refused')

    def test_the_list_is_shown_with_what_a_person_compares(self):
        shown = self.run_it('list').stdout.decode().splitlines()
        keys = seal.parse_list(self.keys.read_bytes())
        self.assertEqual(shown, ['generation=1.1'] + [f'{key.scope} {key.name} {seal.fingerprint(key.public)} '
                                                    f'{key.public.hex()}' for key in keys.keys])

    def test_no_list_is_not_a_damaged_one(self):
        self.keys.unlink()
        self.assertEqual((self.run_it('list').returncode, self.run_it('list').stdout), (1, b''))
        self.keys.mkdir()
        self.assertEqual(self.run_it('list').returncode, 2)


@unittest.skipUnless(shutil.which(CC), 'no C compiler')
class Verifier(Built):
    """The program a unit verifies a release with."""

    def test_a_release_is_verified_and_kept_for_the_staging(self):
        result = self.verify(seal.seal(MANIFEST, 5, self.sign))
        self.assertEqual((result.returncode, result.stdout),
                         (0, f'release=5 key={seal.fingerprint(self.primary)} name=primary\n'))
        self.assertEqual(result.stderr, '')
        self.assertEqual((self.state / 'manifest').read_bytes(), MANIFEST)
        self.assertEqual(self.run_it('number').stdout, b'5\n')
        self.assertEqual(self.run_it('allows', 'ab' * 32).returncode, 0)
        self.assertEqual(self.run_it('allows', 'cd' * 32).returncode, 1)

    def test_the_spare_key_seals_as_well_and_says_so_quietly(self):
        result = self.verify(seal.seal(MANIFEST, 5, self.sign_spare))
        self.assertEqual(result.stdout, f'release=5 key={seal.fingerprint(self.spare)} name=spare\n')
        self.assertEqual(result.stderr, '', 'the first key not matching is no event')

    def test_a_changed_manifest_another_key_and_another_topic_are_refused(self):
        sealed = seal.seal(MANIFEST, 5, self.sign)
        changed = bytearray(sealed)
        changed[70] ^= 0x20
        with mock.patch.object(seal, 'TOPIC', 'other-product/release'):
            elsewhere = seal.seal(MANIFEST, 5, self.sign)
        for name, envelope in (('changed', bytes(changed)), ('stranger', seal.seal(MANIFEST, 5, signing(STRANGER)[1])),
                               ('topic', elsewhere), ('cut', sealed[:-1]), ('short', sealed[:50]),
                               ('empty', b'')):
            with self.subTest(name):
                result = self.verify(envelope)
                self.assertEqual(result.returncode, 1)
                self.assertIn('not a release sealed by a release key this unit holds', result.stderr)
                self.assertFalse(self.state.exists(), 'nothing is kept of what did not verify')

    def test_only_a_release_key_seals_a_release(self):
        for number in (ROOT_KEY, KEYS_KEY):
            with self.subTest(NAMES[number]):
                result = self.verify(seal.seal(MANIFEST, 5, signing(number)[1]))
                self.assertEqual(result.returncode, 1)
                self.assertFalse(self.state.exists())
        # And a list sealed by a release key under the release topic is a release of nothing here.
        self.assertEqual(self.verify(resealed(rotation(a_list(2), PRIMARY), PRIMARY, seal.TOPIC)).returncode, 0,
                         'a body is only text to the verifier; what it lists is what counts')
        self.assertEqual(self.run_it('allows', 'ab' * 32).returncode, 1)

    def test_a_list_with_no_release_key_takes_no_release(self):
        self.keys.write_bytes(a_list(2, USUAL[:2]))
        result = self.verify(seal.seal(MANIFEST, 5, self.sign))
        self.assertEqual(result.returncode, 1)
        self.assertIn('holds no release key', result.stderr)

    def test_a_release_for_another_product_under_the_same_topic_is_refused(self):
        with mock.patch.object(seal, 'PRODUCT', 'another'):
            result = self.verify(seal.seal(MANIFEST, 5, self.sign))
        self.assertEqual(result.returncode, 1)
        self.assertIn('sealed for another, not for w1700k-sdr', result.stderr)

    def test_a_flag_a_reserved_byte_or_more_in_the_device_field_is_refused_though_signed(self):
        sealed = seal.seal(MANIFEST, 5, self.sign)

        def setting(offset, value):
            def change(whole):
                whole[offset] = value
            return change
        for name, change in (('a flag', setting(5, 1)), ('a reserved byte', setting(39, 1)),
                             ('after the product', setting(21, ord('x')))):
            with self.subTest(name):
                envelope = resealed(sealed, PRIMARY, seal.TOPIC, change)
                self.assertEqual(self.verify(envelope).returncode, 1)
                self.assertFalse(self.state.exists())
                with self.assertRaises(seal.Refused):
                    seal.unseal(envelope, [self.primary])

    def test_nothing_older_than_what_the_unit_settled_on(self):
        sealed = seal.seal(MANIFEST, 5, self.sign)
        self.assertEqual(self.verify(sealed, floor=4).returncode, 0)
        self.assertEqual(self.verify(sealed, floor=5).returncode, 0, 'the same release again is no step back')
        for odd in (' 4', '+4', '-1', '4 ', '0x4', '', '4.0'):
            with self.subTest(floor=odd):
                self.assertEqual(self.verify(sealed, floor=odd).returncode, 2, 'a floor is a number written plainly')
        shutil.rmtree(self.state)
        result = self.verify(sealed, floor=6)
        self.assertEqual(result.returncode, 1)
        self.assertIn('release 5 is older than release 6, which this unit has settled on', result.stderr)
        self.assertFalse(self.state.exists())

    def test_a_telemetry_envelope_is_not_a_release(self):
        # Kind 1 is authenticated by a shared key; a release is signed.
        sealed = bytearray(seal.seal(MANIFEST, 5, self.sign))
        sealed[4] = 1
        self.assertEqual(self.verify(bytes(sealed)).returncode, 1)

    def test_an_oversized_file_is_refused_unread(self):
        result = self.verify(seal.seal(MANIFEST, 5, self.sign) + bytes(seal.ENVELOPE_MOST))
        self.assertEqual(result.returncode, 1)
        self.assertIn('too long', result.stderr)

    def test_a_unit_with_no_list_or_a_damaged_one_verifies_nothing(self):
        self.keys.unlink()
        result = self.verify(seal.seal(MANIFEST, 5, self.sign))
        self.assertEqual(result.returncode, 2)
        self.assertIn('holds no key list', result.stderr)
        self.keys.write_bytes(a_list(1)[:-1])
        result = self.verify(seal.seal(MANIFEST, 5, self.sign))
        self.assertEqual(result.returncode, 2)
        self.assertIn('is not a key list', result.stderr)
        self.assertFalse(self.state.exists())

    def test_a_digest_is_listed_as_an_images_and_not_by_being_somewhere_in_the_manifest(self):
        elsewhere = json.dumps({'format': 1, 'source': 'cd' * 32, 'note': '"sha256": "' + 'ef' * 32,
                                'files': {'rootfs.squashfs': {'sha256': 'ab' * 32, 'bytes': 3}}}, indent=1).encode()
        self.assertEqual(self.verify(seal.seal(elsewhere, 5, self.sign)).returncode, 0)
        self.assertEqual(self.run_it('allows', 'ab' * 32).returncode, 0)
        self.assertEqual(self.run_it('allows', 'cd' * 32).returncode, 1, 'what it was made from is not an image')
        self.assertEqual(self.run_it('allows', 'ef' * 32).returncode, 1, 'nor is what a string says')

    def test_a_release_number_is_one_every_tool_can_count_to(self):
        most = seal.RELEASE_MOST
        self.assertEqual(most, int(re.search(r'#define RELEASE_NUMBER_MOST (\d+)', (SEAL / 'release.h').read_text()).group(1)))
        self.assertEqual(self.verify(seal.seal(MANIFEST, most, self.sign)).returncode, 0)
        with self.assertRaises(seal.Refused):
            seal.seal(MANIFEST, most + 1, self.sign)
        header, message = seal.unsigned(MANIFEST, most + 1)
        over = seal.signed(header, MANIFEST, self.sign(message))
        shutil.rmtree(self.state)
        result = self.verify(over)
        self.assertEqual(result.returncode, 1)
        self.assertIn(f'a number from 1 to {most}', result.stderr)
        self.assertFalse(self.state.exists())
        with self.assertRaises(seal.Refused):
            seal.unseal(over, [self.primary])

    def test_allows_takes_a_digest_and_nothing_else(self):
        self.verify(seal.seal(MANIFEST, 5, self.sign))
        for bad in ('ab' * 31, 'AB' * 32, 'format', '"'):
            with self.subTest(bad):
                self.assertEqual(self.run_it('allows', bad).returncode, 2)
        shutil.rmtree(self.state)
        self.assertEqual(self.run_it('allows', 'ab' * 32).returncode, 1, 'nothing verified, nothing allowed')
        self.assertEqual(self.run_it('number').returncode, 1)


def encoded(point):
    """A point as RFC 8032 writes it."""
    inverse = pow(point[2], seal.P - 2, seal.P)
    x, y = point[0] * inverse % seal.P, point[1] * inverse % seal.P
    return (y | (x & 1) << 255).to_bytes(32, 'little')


def scalar_of(number):
    """The secret scalar of test key `number`."""
    digest = bytearray(hashlib.sha512(bytes((number,)) * 32).digest()[:32])
    digest[0] &= 248
    digest[31] = digest[31] & 127 | 64
    return int.from_bytes(digest, 'little')


def crafted(scalar, public, message, shift=None, nonce=0x1234567):
    """A signature a key holder can make that no honest signer does: its first half moved by
    the point `shift`, or given as the bytes `shift`."""
    commitment = seal._multiply(nonce, seal.BASE)
    if isinstance(shift, tuple):
        commitment = seal._add(commitment, shift)
    first = shift if isinstance(shift, bytes) else encoded(commitment)
    challenge = int.from_bytes(hashlib.sha512(first + public + message).digest(), 'little') % seal.ORDER
    return first + ((nonce + challenge * scalar) % seal.ORDER).to_bytes(32, 'little')


# The points of small order, as points; and their encodings no honest tool writes.
TORSION = [point for point in (seal._point(encoding[:31] + bytes((encoding[31] | sign,)))
                               for encoding in sorted(seal._SMALL) for sign in (0, 0x80)) if point is not None]
ODD_ENCODINGS = [b'\x01' + bytes(30) + b'\x80', b'\xec' + b'\xff' * 30 + b'\xff',
                 b'\xee' + b'\xff' * 30 + b'\x7f', b'\xed' + b'\xff' * 30 + b'\x7f',
                 b'\xef' + b'\xff' * 30 + b'\x7f', b'\xff' * 32]


@unittest.skipUnless(shutil.which(CC), 'no C compiler')
class SignatureEdges(Built):
    """Signatures and keys at the edges of Ed25519, where verifiers differ: the unit's
    (Monocypher, behind what release.c refuses first) and the host's have to say the same."""

    def envelope(self, text, signature_of):
        header, message = seal.unsigned_list(text)
        return seal.signed(header, text, signature_of(message))

    def test_a_first_half_moved_by_a_point_of_small_order_is_judged_alike(self):
        scalar, public = scalar_of(ROOT_KEY), signing(ROOT_KEY)[0]
        self.assertEqual(encoded(seal._multiply(scalar, seal.BASE)), public)
        self.assertEqual(len({encoded(point) for point in TORSION}), 8)
        new = a_list(2)
        for point in TORSION:
            with self.subTest(encoded(point).hex()[:8]):
                sealed = self.envelope(new, lambda message: crafted(scalar, public, message, point))
                self.assertEqual(self.both(sealed), ('taken', new),
                                 'with the cofactor it is a signature, on the unit and here')

    def test_a_first_half_in_no_form_a_point_is_written_in_is_refused_alike(self):
        scalar, public = scalar_of(ROOT_KEY), signing(ROOT_KEY)[0]
        new = a_list(2)
        for odd in ODD_ENCODINGS:
            with self.subTest(odd.hex()[:8] + odd.hex()[-2:]):
                sealed = self.envelope(new, lambda message: crafted(scalar, public, message, odd, nonce=0))
                self.assertEqual(self.both(sealed)[0], 'refused')
                release = seal.unsigned(MANIFEST, 5)
                envelope = seal.signed(release[0], MANIFEST, crafted(scalar_of(PRIMARY), self.primary, release[1], odd, nonce=0))
                self.assertEqual(self.verify(envelope).returncode, 1)
                with self.assertRaises(seal.Refused):
                    seal.unseal(envelope, [self.primary])

    def test_a_key_with_a_part_of_small_order_seals_alike_and_one_in_no_form_is_no_key(self):
        scalar = scalar_of(ROOT_KEY)
        for point in TORSION[2:5]:
            with self.subTest(encoded(point).hex()[:8]):
                mixed = encoded(seal._add(seal._multiply(scalar, seal.BASE), point))
                first = seal.format_list((1, 1), [(mixed, 'root', 'mixed'), (self.primary, 'release', 'primary')])
                sealed = self.envelope(first, lambda message: crafted(scalar, mixed, message))
                self.assertEqual(self.both(sealed, first=True), ('taken', first))
        # A y of p or more is the same point written another way: not a key, in either reader.
        for y in (seal.P + 2, seal.P + 9, 2 ** 255 - 1):
            text = a_list(1) + f'{y.to_bytes(32, "little").hex()}  release  odd\n'.encode()
            self.keys.write_bytes(text)
            self.assertEqual(self.run_it('list').returncode, 2)
            with self.assertRaisesRegex(seal.Refused, 'the one form a key is written in'):
                seal.parse_list(text)

    def test_the_cases_an_audit_found_the_two_to_differ_on(self):
        root = signing(ROOT_KEY)[0].hex()
        held = f'w1700k-sdr keys 1.1\n{root}  root  r\n{self.primary.hex()}  release  p\n'.encode()
        self.keys.write_bytes(held)
        header = b'WMS2\x02\x00w1700k-sdr' + bytes(6)
        # A release whose signature's first half is the identity written as p + 1.
        release = bytes.fromhex(
            '574d5332020077313730306b2d7364720000000000000500000000000000000000000000000000007b7d0aeeffffffffff'
            'ffffffffffffffffffffffffffffffffffffffffffffffffffffff7f803bda0042f13f774cf6691ea086016baed05e1962'
            '2801c146d8fae36afcec04')
        self.assertEqual(self.verify(release).returncode, 1)
        with self.assertRaises(seal.Refused):
            seal.unseal(release, [self.primary])
        # The list held with a counter that is not its generation, and no signature at all.
        for counter in (0, 2 ** 64 - 1):
            with self.subTest(counter=counter):
                self.assertEqual(self.both(header + struct.pack('<QQH', counter, 0, 0) + held + bytes(64))[0], 'refused')
        self.assertEqual(self.both(header + struct.pack('<QQH', 1, 0, 0) + held + bytes(64)), ('unchanged', None))
        # Another list of the generation held that nobody sealed is not a fork.
        other = held.replace(b'  release  p', b'  release  q')
        outcome, said = self.both(header + struct.pack('<QQH', 1, 0, 0) + other + bytes(64))
        self.assertEqual(outcome, 'refused')
        self.assertNotIn('ANOTHER', said)


@unittest.skipUnless(shutil.which(CC), 'no C compiler')
class Rotation(Built):
    """A new list of keys, and who may seal it: the unit's word, and the host's the same."""

    def test_a_keys_key_changes_the_release_keys(self):
        new = a_list(2, ((ROOT_KEY, 'root'), (KEYS_KEY, 'keys'), (STRANGER, 'release')))
        self.assertEqual(self.both(rotation(new, KEYS_KEY)), ('taken', new))
        result = self.run_it('rotate', '--out', self.out, self.dir / 'keys.wms2')
        self.assertEqual(result.stdout.decode(), f'generation=1.2 sealed_by=the-keys scope=keys '
                                                 f'key={seal.fingerprint(signing(KEYS_KEY)[0])}\n')
        freeze = a_list(2, USUAL[:2])
        self.assertEqual(self.both(rotation(freeze, KEYS_KEY)), ('taken', freeze))

    def test_a_keys_key_may_put_the_lines_in_another_order_and_nothing_more(self):
        new = a_list(2, (USUAL[2], USUAL[1], USUAL[0]))
        self.assertEqual(self.both(rotation(new, KEYS_KEY))[0], 'taken')

    def test_a_root_or_keys_line_changes_only_with_the_epoch_and_only_a_root_key_starts_one(self):
        renamed = {**NAMES, KEYS_KEY: 'renamed'}
        for name, rows, names in (
                ('another keys key', ((ROOT_KEY, 'root'), (NEW_KEYS_KEY, 'keys'), (PRIMARY, 'release')), NAMES),
                ('another root key', ((NEW_ROOT_KEY, 'root'), (KEYS_KEY, 'keys'), (PRIMARY, 'release')), NAMES),
                ('a second root', USUAL + ((NEW_ROOT_KEY, 'root'),), NAMES),
                ('a second keys key', USUAL + ((NEW_KEYS_KEY, 'keys'),), NAMES),
                ('no keys key', (USUAL[0], USUAL[2]), NAMES),
                ('the keys key renamed', USUAL, renamed),
                ('a release key made a keys key', USUAL[:2] + ((PRIMARY, 'keys'),), NAMES),
                ('the keys key made a root', ((ROOT_KEY, 'root'), (KEYS_KEY, 'root'), (PRIMARY, 'release')), NAMES),
                ('the keys key made a release key', ((ROOT_KEY, 'root'), (KEYS_KEY, 'release')), NAMES),
                ('the keys key made a timestamp key', ((ROOT_KEY, 'root'), (KEYS_KEY, 'timestamp')), NAMES),
                ('the root and keys keys changing places', ((ROOT_KEY, 'keys'), (KEYS_KEY, 'root')),
                 {ROOT_KEY: 'the-keys', KEYS_KEY: 'the-root'})):
            with self.subTest(name):
                staying, starting = a_list((1, 2), rows, names), a_list((2, 1), rows, names)
                for by in (KEYS_KEY, ROOT_KEY):
                    outcome, said = self.both(rotation(staying, by))
                    self.assertEqual(outcome, 'refused', 'in the epoch held, whoever seals it')
                    self.assertIn('changes a root or keys line and stays in epoch 1', said)
                outcome, said = self.both(rotation(starting, KEYS_KEY))
                self.assertEqual(outcome, 'refused')
                self.assertIn('only a root key of the list held starts one', said)
                self.assertEqual(self.both(rotation(starting, ROOT_KEY)), ('taken', starting))

    def test_a_root_keys_list_comes_after_whatever_a_keys_key_has_sealed(self):
        """What the epoch is for: a keys key, stolen, runs the generation as far as it goes."""
        runaway = a_list((1, seal.GENERATION_MOST), ((ROOT_KEY, 'root'), (KEYS_KEY, 'keys'), (STRANGER, 'release')))
        self.assertEqual(self.both(rotation(runaway, KEYS_KEY)), ('taken', runaway))
        self.keys.write_bytes(runaway)
        with self.assertRaises(seal.Refused):
            a_list((1, seal.GENERATION_MOST + 1))
        remedy = a_list((2, 1), ((ROOT_KEY, 'root'), (NEW_KEYS_KEY, 'keys'), (PRIMARY, 'release')))
        self.assertEqual(self.both(rotation(remedy, KEYS_KEY))[0], 'refused', 'the stolen key cannot follow')
        self.assertEqual(self.both(rotation(remedy, ROOT_KEY)), ('taken', remedy))
        self.keys.write_bytes(remedy)
        for late in (a_list((1, seal.GENERATION_MOST)), runaway, a_list((2, 2))):
            self.assertEqual(self.both(rotation(late, KEYS_KEY))[0], 'refused', 'and seals nothing for it any more')

    def test_an_epoch_follows_the_one_before_it_and_starts_at_its_first_list(self):
        same = a_list((2, 1))
        self.assertEqual(self.both(rotation(same, ROOT_KEY)), ('taken', same), 'with every line as it was, too')
        for stamp in ((2, 2), (3, 1), (2, 5), (9999, 1)):
            with self.subTest(stamp):
                outcome, said = self.both(rotation(a_list(stamp), ROOT_KEY))
                self.assertEqual(outcome, 'refused')
                self.assertIn('after epoch 1 comes list 2.1 and no other', said)
        self.keys.write_bytes(a_list((3, 4)))
        for stamp in ((3, 3), (2, 9), (1, 1000)):
            with self.subTest(stamp):
                outcome, said = self.both(rotation(a_list(stamp, USUAL[:3]), ROOT_KEY))
                self.assertEqual(outcome, 'refused')
                self.assertIn(f'list {stamp[0]}.{stamp[1]} is older than 3.4', said)

    def test_a_timestamp_key_seals_nothing_a_unit_takes_and_is_no_authority(self):
        stamped = a_list((1, 2), USUAL + ((STRANGER, 'timestamp'),))
        self.assertEqual(self.both(rotation(stamped, KEYS_KEY)), ('taken', stamped), 'a keys key may name one')
        self.keys.write_bytes(stamped)
        self.assertEqual(self.both(rotation(a_list((1, 3)), STRANGER))[0], 'refused')
        self.assertEqual(self.both(rotation(a_list((2, 1)), STRANGER))[0], 'refused')
        self.assertEqual(self.verify(seal.seal(MANIFEST, 5, signing(STRANGER)[1])).returncode, 1)
        self.assertEqual(self.verify(seal.seal(MANIFEST, 5, self.sign)).returncode, 0)
        self.assertEqual(self.both(rotation(a_list((1, 3)), KEYS_KEY))[0], 'taken', 'and may take it away')

    def test_a_key_that_is_not_a_root_or_keys_key_of_the_list_held_seals_no_list(self):
        new = a_list(2, ((NEW_ROOT_KEY, 'root'), (NEW_KEYS_KEY, 'keys'), (STRANGER, 'release')))
        for name, by in (('a release key', PRIMARY), ('a stranger', 12), ('the new root', NEW_ROOT_KEY),
                         ('the new keys key', NEW_KEYS_KEY), ('the new release key', STRANGER)):
            with self.subTest(name):
                outcome, said = self.both(rotation(new, by))
                self.assertEqual(outcome, 'refused')
                self.assertIn('not sealed by a root or keys key of the list this unit holds', said)

    def test_the_generation_only_goes_up(self):
        self.keys.write_bytes(a_list(5))
        self.assertEqual(self.both(rotation(a_list(5), KEYS_KEY)), ('unchanged', None))
        self.assertEqual(self.both(rotation(a_list(5), STRANGER)), ('unchanged', None),
                         'the list held, whoever hands it over, changes nothing')
        for generation in (4, 1):
            outcome, said = self.both(rotation(a_list(generation, USUAL[:3]), ROOT_KEY))
            self.assertEqual(outcome, 'refused')
            self.assertIn(f'list 1.{generation} is older than 1.5', said)
        self.assertEqual(self.both(rotation(a_list(6, USUAL[:3]), KEYS_KEY))[0], 'taken')
        self.assertEqual(self.both(rotation(a_list(900, USUAL[:3]), KEYS_KEY))[0], 'taken', 'a gap is no fault')

    def test_another_list_under_the_generation_held_is_refused_loudly(self):
        self.keys.write_bytes(a_list(5))
        outcome, said = self.both(rotation(a_list(5, USUAL[:3]), ROOT_KEY))
        self.assertEqual(outcome, 'refused')
        self.assertIn('ANOTHER list 1.5', said)
        self.assertIn('the-root sealed it: two lists were sealed as one', said)
        # Said only of what a key of the list held did seal.
        for by in (PRIMARY, STRANGER):
            outcome, said = self.both(rotation(a_list(5, USUAL[:3]), by))
            self.assertEqual(outcome, 'refused')
            self.assertNotIn('ANOTHER', said)
        outcome, said = self.both(rotation(a_list(4, USUAL[:3]), STRANGER))
        self.assertNotIn('older', said, 'nor is a stranger\'s list called an old one of ours')

    def test_what_is_sealed_has_to_be_a_list_of_this_product_under_the_rotation_topic(self):
        new = a_list(2)
        good = rotation(new, ROOT_KEY)

        def setting(offset, value):
            def change(whole):
                whole[offset] = value
            return change
        with mock.patch.object(seal, 'PRODUCT', 'another'):
            elsewhere = resealed(good, ROOT_KEY, change=lambda whole: whole[:6] + b'another'.ljust(16, b'\0') + whole[22:])
        for name, envelope in (
                ('the release topic', resealed(good, ROOT_KEY, seal.TOPIC)),
                ('another topic', resealed(good, ROOT_KEY, 'w1700k-sdr/key-proof')),
                ('another product', elsewhere),
                ('a counter that is not the generation', resealed(good, ROOT_KEY, change=setting(22, 3))),
                ('a flag', resealed(good, ROOT_KEY, change=setting(5, 1))),
                ('a reserved byte', resealed(good, ROOT_KEY, change=setting(38, 1))),
                ('more in the device field', resealed(good, ROOT_KEY, change=setting(20, ord('x')))),
                ('telemetry', resealed(good, ROOT_KEY, change=setting(4, 1))),
                ('a manifest', resealed(good, ROOT_KEY, change=lambda whole: whole[:40] + MANIFEST)),
                ('one bit of the list', good[:50] + bytes((good[50] ^ 1,)) + good[51:]),
                ('one bit of the signature', good[:-1] + bytes((good[-1] ^ 1,))),
                ('cut short', good[:-1]), ('a header alone', good[:40]), ('nothing', b''),
                ('too long', good + bytes(seal.ENVELOPE_MOST))):
            with self.subTest(name):
                self.assertEqual(self.both(envelope)[0], 'refused')
        self.assertEqual(self.both(good), ('taken', new))

    def test_a_signature_made_again_with_the_order_added_is_not_one(self):
        good = rotation(a_list(2), ROOT_KEY)
        high = (int.from_bytes(good[-32:], 'little') + seal.ORDER).to_bytes(32, 'little')
        self.assertEqual(self.both(good[:-32] + high)[0], 'refused')

    def test_a_first_list_is_sealed_by_a_root_key_it_names(self):
        self.keys.unlink()
        first = a_list(1)
        self.assertEqual(self.both(rotation(first, ROOT_KEY), first=True), ('taken', first))
        self.assertEqual(self.both(rotation(a_list(40), ROOT_KEY), first=True)[0], 'taken',
                         'whatever its generation: it is the one the bench was given')
        for name, by in (('its keys key', KEYS_KEY), ('its release key', PRIMARY), ('a stranger', STRANGER)):
            with self.subTest(name):
                outcome, said = self.both(rotation(first, by), first=True)
                self.assertEqual(outcome, 'refused')
                self.assertIn('sealed by a root key it names itself', said)

    def test_without_a_list_held_nothing_is_a_rotation(self):
        self.keys.unlink()
        path = self.dir / 'keys.wms2'
        path.write_bytes(rotation(a_list(2), ROOT_KEY))
        result = self.run_it('rotate', '--out', self.out, path)
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'holds no key list', result.stderr)
        self.assertFalse(self.out.exists())

    def test_a_chain_is_followed_one_list_at_a_time(self):
        """The root replaces the keys key, the new keys key the release key, the root itself."""
        second = a_list((2, 1), ((ROOT_KEY, 'root'), (NEW_KEYS_KEY, 'keys'), (PRIMARY, 'release')))
        third = a_list((2, 2), ((ROOT_KEY, 'root'), (NEW_KEYS_KEY, 'keys'), (STRANGER, 'release')))
        fourth = a_list((3, 1), ((NEW_ROOT_KEY, 'root'), (NEW_KEYS_KEY, 'keys'), (STRANGER, 'release')))
        chain = [rotation(a_list(1), ROOT_KEY), rotation(second, ROOT_KEY), rotation(third, NEW_KEYS_KEY),
                 rotation(fourth, ROOT_KEY)]
        # From the first list a unit cannot take the third: it does not know the key that sealed it.
        self.assertEqual(self.both(chain[2])[0], 'refused')
        for envelope in chain[1:]:
            outcome, text = self.both(envelope)
            self.assertEqual(outcome, 'taken')
            self.keys.write_bytes(text)
        self.assertEqual(self.keys.read_bytes(), fourth)
        self.assertEqual(bundle.chain(chain).text, fourth)
        # The old root, and the old keys key, seal nothing for it any more.
        fifth = a_list((3, 2), ((NEW_ROOT_KEY, 'root'), (NEW_KEYS_KEY, 'keys'), (PRIMARY, 'release')))
        for by in (ROOT_KEY, KEYS_KEY):
            self.assertEqual(self.both(rotation(fifth, by))[0], 'refused')
        with self.assertRaisesRegex(StepFailed, 'rotation 2 of 2'):
            bundle.chain([chain[0], chain[2]])


LOADER_IMAGE = b'\xd0\x0d\xfe\xed' + b'W1700K SDR second ARM loader' + bytes(range(256)) * 4
OTHER_LOADER = LOADER_IMAGE + b'another build'
OLD_ROOT, NEW_ROOT, UNIT_ROOT = b'hsqs the root that runs', b'hsqs the release\'s root', b'hsqs this unit\'s root'
# What the script asks the unit about, answered from the test's directory instead.
OVERRIDES = '''
installed() { :; }
loader_applies() { :; }
loader_starts_second() { :; }
partition() { case $1 in uenv) echo "@D@/dev/uenv" ;; *) echo "@D@/dev/mtd5ro" ;; esac; }
volume() { echo "@D@/dev/ubi0_1"; }
loader_note() { cat "@D@/notes/$1" 2>/dev/null || :; }
second_loader() { cat "@D@/second" 2>/dev/null || :; }
tty() { cat "@D@/tty"; }
'''


@unittest.skipUnless(shutil.which(CC), 'no C compiler')
class KeptLists(Built):
    """What a unit keeps of its lists is the sealed envelopes that bear out the one it holds,
    and every read walks them. So nothing altered on flash reads as a list: it is a list this
    unit was shown the seals of, or it is none."""
    SECOND = ((ROOT_KEY, 'root'), (NEW_KEYS_KEY, 'keys'), (PRIMARY, 'release'))

    def take(self, envelope, first=False):
        """A rotation, taken as system-update takes it: what the verifier wrote is kept."""
        path = self.dir / 'keys.wms2'
        path.write_bytes(envelope)
        result = self.run_it('rotate', *(['--first'] if first else []), '--out', self.out, path)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.keys.keep(self.out.read_bytes())

    def labels(self):
        return [seal.parse_list(seal.body_of(link)).label for link in links(self.keys.kept())]

    def read(self):
        """(exit status of `list`, the list's text or what was said)."""
        shown = self.run_it('list')
        text = subprocess.run([str(self.program), 'text', '--keys', str(self.keys)], capture_output=True)
        self.assertEqual(shown.returncode == 0, text.returncode == 0)
        return shown.returncode, text.stdout if shown.returncode == 0 else shown.stderr.decode(errors='replace')

    def grow(self):
        """A unit that has lived a while: three epochs, the last with a later list in it."""
        self.keys.unlink()
        self.take(rotation(a_list(1), ROOT_KEY), first=True)
        self.take(rotation(a_list((2, 1), self.SECOND), ROOT_KEY))
        self.take(rotation(a_list((3, 1), self.SECOND), ROOT_KEY))
        self.take(rotation(a_list((3, 2), self.SECOND[:2] + ((STRANGER, 'release'),)), NEW_KEYS_KEY))
        return self.keys.kept()

    def test_it_keeps_the_first_list_each_epochs_first_and_the_one_it_holds(self):
        self.keys.unlink()
        self.take(rotation(a_list(1), ROOT_KEY), first=True)
        self.assertEqual(self.labels(), ['1.1'])
        self.take(rotation(a_list(2), KEYS_KEY))
        self.assertEqual(self.labels(), ['1.1', '1.2'])
        self.take(rotation(a_list(7), ROOT_KEY))
        self.assertEqual(self.labels(), ['1.1', '1.7'], 'the list between vouches for nothing the first does not')
        self.take(rotation(a_list((2, 1), self.SECOND), ROOT_KEY))
        self.assertEqual(self.labels(), ['1.1', '2.1'], 'nor does the last of an epoch that is over')
        self.take(rotation(a_list((2, 2), self.SECOND), NEW_KEYS_KEY))
        self.take(rotation(a_list((2, 9), self.SECOND), ROOT_KEY))
        self.assertEqual(self.labels(), ['1.1', '2.1', '2.9'])
        self.take(rotation(a_list((3, 1), self.SECOND), ROOT_KEY))
        self.assertEqual(self.labels(), ['1.1', '2.1', '3.1'])
        self.assertEqual(self.read(), (0, a_list((3, 1), self.SECOND)))

    def test_within_an_epoch_it_does_not_grow_however_many_lists_come(self):
        self.keys.unlink()
        self.take(rotation(a_list(1), ROOT_KEY), first=True)
        sizes = set()
        for generation in range(2, 40):
            self.take(rotation(a_list(generation), KEYS_KEY))
            sizes.add(len(self.keys.kept()))
            self.assertEqual(self.labels(), ['1.1', f'1.{generation}'])
        self.assertLessEqual(max(sizes) - min(sizes), 1, 'but for the digits of the generation')

    def test_a_unit_given_a_later_list_first_keeps_that_as_its_first(self):
        self.keys.unlink()
        self.take(rotation(a_list((3, 4)), ROOT_KEY), first=True)
        self.take(rotation(a_list((3, 6)), KEYS_KEY))
        self.take(rotation(a_list((3, 8)), KEYS_KEY))
        self.assertEqual(self.labels(), ['3.4', '3.8'])
        self.assertEqual(self.read(), (0, a_list((3, 8))))

    def test_one_bit_wrong_anywhere_in_it_and_it_is_no_list(self):
        whole = self.grow()
        self.assertEqual(self.read()[0], 0)
        for at in range(len(whole)):
            damaged = bytearray(whole)
            damaged[at] ^= 1 << (at % 8)
            self.keys.keep(bytes(damaged))
            status, said = self.read()
            self.assertEqual(status, 2, f'byte {at} of {len(whole)}: {said}')

    def test_cut_short_it_is_no_list_or_a_list_this_unit_held_before(self):
        whole = self.grow()
        held_before = {}
        at = len(CHAIN_MAGIC)
        for link in links(whole):
            at += 4 + len(link)
            held_before[at] = seal.body_of(link)
        for length in range(len(whole)):
            self.keys.keep(whole[:length])
            status, said = self.read()
            if length in held_before:
                self.assertEqual((status, said), (0, held_before[length]), 'never one it did not hold')
            else:
                self.assertEqual(status, 2, f'cut to {length}: {said}')

    def test_a_list_altered_into_another_that_reads_is_no_list(self):
        """What a checksum beside the text would not have stopped: whoever can write the list
        can write the checksum. The seal cannot be written again."""
        whole = self.grow()
        first, second, third, held = links(whole)
        other = a_list((3, 2), self.SECOND)                 # the release key put back for the stranger
        forged = held[:40] + other + held[-64:]
        self.assertEqual(seal.parse_list(seal.body_of(forged)).label, '3.2', 'it is a list, to look at')
        self.keys.keep(kept(first, second, third, forged))
        status, said = self.read()
        self.assertEqual(status, 2)
        self.assertIn('not borne out by its seal', said)

    def test_what_does_not_follow_is_no_list(self):
        whole = self.grow()
        first, second, third, held = links(whole)
        stranger_first = rotation(a_list(1, ((STRANGER, 'root'),), {STRANGER: 'x'}), STRANGER)
        cases = {'only the name of a chain': kept(), 'nothing': b'', 'the lists out of order': kept(second, first, third, held),
                 'one left out': kept(first, third, held), 'the same one twice': kept(first, second, third, held, held),
                 'an older one after': kept(first, second, third, held, third), 'the first one again': kept(first, second, first),
                 'something after the last': whole + b'\0', 'a length and nothing': whole + struct.pack('<I', 200),
                 'a list a stranger sealed, after': kept(first, second, third, held, rotation(a_list((3, 3), self.SECOND), STRANGER)),
                 'a list sealed by a key of an epoch that is over': kept(first, second, third, rotation(a_list((3, 5), self.SECOND), KEYS_KEY)),
                 'a release under the name of a list': kept(seal.seal(b'{}', 1, signing(ROOT_KEY)[1])),
                 'another kind of chain': whole.replace(b'chain 1\n', b'chain 2\n'),
                 'a length too long to be an envelope': CHAIN_MAGIC + struct.pack('<I', 1 << 20) + first}
        for name, data in cases.items():
            with self.subTest(name):
                self.keys.keep(data)
                self.assertEqual(self.read()[0], 2)
        # Somebody else's lists, whole and well sealed, are a list: the first is the anchor.
        self.keys.keep(kept(stranger_first))
        self.assertEqual(self.read()[0], 0, 'which is why a unit also has a mark outside its storage, and a bench')

    def test_a_list_kept_as_text_from_before_is_given_again_at_the_bench(self):
        Path(self.keys).write_bytes(a_list(1))
        status, said = self.read()
        self.assertEqual(status, 2)
        self.assertIn('not a list kept with its seals', said)
        self.assertIn('at the bench', said)
        path = self.dir / 'keys.wms2'
        path.write_bytes(rotation(a_list(2), KEYS_KEY))
        self.assertEqual(self.run_it('rotate', '--out', self.out, path).returncode, 2, 'it holds no list to judge one by')
        self.assertFalse(self.out.exists())
        self.assertEqual(self.verify(seal.seal(b'{}', 1, self.sign)).returncode, 2)

    def test_a_refused_rotation_and_the_list_held_again_write_nothing(self):
        before = self.grow()
        for envelope in (rotation(a_list((3, 2), self.SECOND[:2] + ((STRANGER, 'release'),)), NEW_KEYS_KEY),    # held
                         rotation(a_list((3, 1), self.SECOND), ROOT_KEY), rotation(a_list((3, 9), self.SECOND), STRANGER)):
            path = self.dir / 'keys.wms2'
            path.write_bytes(envelope)
            self.out.unlink(missing_ok=True)
            self.run_it('rotate', '--out', self.out, path)
            self.assertFalse(self.out.exists())
        self.assertEqual(self.keys.kept(), before)


@unittest.skipUnless(shutil.which(CC), 'no C compiler')
class Scripted(Built):
    """The unit's own system-update, run as it is but for where it looks: the verifier is
    the real one, durable storage and the flash are directories. The unit is keyed: it holds
    the usual list and the mark."""

    def setUp(self):
        super().setUp()
        d = self.dir
        for name in ('durable', 'dev', 'notes', 'sys/mtd/mtd5', 'sys/ubi/ubi0_1', 'work'):
            (d / name).mkdir(parents=True)
        (d / 'dev/ubi0_1').write_bytes(OLD_ROOT)
        (d / 'sys/mtd/mtd5/size').write_text('786432\n')
        (d / 'sys/ubi/ubi0_1/reserved_ebs').write_text('30\n')
        (d / 'sys/ubi/ubi0_1/usable_eb_size').write_text('126976\n')
        (d / 'durable-run').write_text('#!/bin/sh\n"$@"\n')
        self.keys.unlink()
        self.keys, self.environment = Kept(d / 'durable/keys'), d / 'dev/uenv'
        self.keys.write_bytes(a_list(1))
        self.marked(True)
        (d / 'tty').write_text('/dev/pts/0\n')
        text = SCRIPT.read_text()
        for old, new in (('. /etc/w1700k/storage.conf\n', ''),
                         ('/usr/sbin/durable-run', f'{d}/durable-run'),
                         ('RELEASE=/usr/sbin/w1700k-release', f'RELEASE={self.program}'),
                         ('STATE=/run/w1700k-release', f'STATE={self.state}'),
                         ('STAGED=/durable/update', f'STAGED={d}/durable/update'),
                         ('FLOOR=/durable/release', f'FLOOR={d}/durable/release'),
                         ('KEYS=/durable/keys', f'KEYS={self.keys}'),
                         ('HELD=/run/w1700k-keys', f'HELD={d}/held'),
                         ('LOCK=/run/w1700k-update.lock', f'LOCK={d}/lock'),
                         ('df -k /durable', f'df -k {d}/durable'),
                         ('/sys/class/mtd', f'{d}/sys/mtd'), ('/sys/class/ubi', f'{d}/sys/ubi'),
                         ('case ${1:-} in\nstatus)', OVERRIDES.replace('@D@', str(d)) + 'case ${1:-} in\nstatus)')):
            self.assertIn(old, text)
            text = text.replace(old, new)
        self.script = d / 'system-update'
        self.script.write_text(text)
        for path in (self.script, d / 'durable-run'):
            path.chmod(0o755)
        self.archive = d / 'w1700k-update.tar'
        bundle.write(self.archive, LOADER_IMAGE, NEW_ROOT, config.partitions.GEOMETRY)

    def update(self, *arguments):
        return subprocess.run(['sh', str(self.script), *map(str, arguments)], capture_output=True, text=True)

    def at_the_bench(self):
        (self.dir / 'tty').write_text('/dev/console\n')

    def release(self, number, sign=None):
        path = self.dir / f'release-{number}.tar'
        sealed = bundle.sign(self.archive, path, number, sign or self.sign)
        envelope = self.dir / 'work/release.wms2'
        envelope.write_bytes(sealed)
        return self.update('release', envelope)

    def give(self, verb, envelope):
        path = self.dir / 'work/keys.wms2'
        path.write_bytes(envelope)
        return self.update(verb, path)

    def stage(self, verb, data, *flags):
        path = self.dir / 'work/image'
        path.write_bytes(data)
        return self.update(verb, path, hashlib.sha256(data).hexdigest(), *flags)

    def confirm_loader(self, data=LOADER_IMAGE):
        """The reboot: the first loader wrote the staged loader and the second noted that it ran."""
        digest = hashlib.sha256(data).hexdigest()
        (self.dir / 'second').write_text(digest)
        (self.dir / 'notes/loader_booted').write_text(digest)
        shutil.rmtree(self.state, ignore_errors=True)       # /run does not outlive a reboot
        return self.update('confirm')

    def state_of(self):
        text = self.update('status').stdout
        return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)

    def kinds(self):
        state = self.state_of()
        self.assertIn(state['key_mark'], ('yes', 'no', 'unreadable'))
        return state['keys'], state['key_list'], state['key_generation'], state['release_keys']

    def marked(self, on):
        """What the stock boot loader's prompt does: the mark, in its environment."""
        self.environment.write_bytes(stock_environment(*STOCK, *(['w1700k_keyed=1'] if on else []), 'zz=last'))

    def unkeyed(self):
        self.keys.unlink()
        self.marked(False)


@unittest.skipUnless(shutil.which(CC), 'no C compiler')
class UpdateScript(Scripted):
    def test_a_unit_that_was_never_keyed_takes_any_update_as_before(self):
        self.unkeyed()
        result = self.stage('stage-loader', OTHER_LOADER)
        self.assertEqual(result.returncode, 0, result.stderr)
        state = self.state_of()
        self.assertEqual(self.kinds(), ('unkeyed', 'none', '', '0'))
        self.assertEqual((state['release'], state['release_verified']), ('0', ''))
        self.assertIn('holds no list of keys; it takes any update', self.update('release', self.archive).stderr)
        self.assertEqual(self.stage('stage', NEW_ROOT).returncode, 0)

    def test_keyed_nothing_is_staged_that_no_release_lists(self):
        for verb, data in (('stage-loader', LOADER_IMAGE), ('stage', NEW_ROOT)):
            with self.subTest(verb):
                result = self.stage(verb, data)
                self.assertEqual(result.returncode, 1)
                self.assertIn('this unit takes releases', result.stderr)
                self.assertFalse((self.dir / 'durable/update').exists())
        self.assertEqual(self.kinds(), ('keyed', 'good', '1.1', '2'))
        self.assertEqual(self.update('keys').stdout.encode(), a_list(1))

    def test_a_list_without_the_mark_is_a_keyed_unit_all_the_same(self):
        self.marked(False)
        self.assertEqual(self.kinds()[0], 'keyed')
        self.assertEqual(self.stage('stage-loader', LOADER_IMAGE).returncode, 1)

    def test_the_mark_is_one_variable_of_the_stock_environment_and_nothing_like_it(self):
        self.keys.unlink()
        for name, variables, kind in (
                ('the mark', (*STOCK, 'w1700k_keyed=1'), 'lost'), ('the mark first', ('w1700k_keyed=1', *STOCK), 'lost'),
                ('no mark', STOCK, 'unkeyed'), ('an empty environment', (), 'unkeyed'),
                ('off', (*STOCK, 'w1700k_keyed=0'), 'unkeyed'), ('more', (*STOCK, 'w1700k_keyed=10'), 'unkeyed'),
                ('a longer name', (*STOCK, 'not_w1700k_keyed=1'), 'unkeyed'),
                ('inside another value', ('bootcmd=echo w1700k_keyed=1', *STOCK[1:]), 'unkeyed')):
            with self.subTest(name):
                self.environment.write_bytes(stock_environment(*variables))
                self.assertEqual(self.state_of()['keys'], kind)
        # After the end of the environment nothing is a variable.
        self.environment.write_bytes(stock_environment(*STOCK).replace(b'\0' * 20, b'\0\0w1700k_keyed=1\0' + bytes(3), 1))
        data = self.environment.read_bytes()
        self.environment.write_bytes(struct.pack('<I', zlib.crc32(data[4:])) + data[4:])
        self.assertEqual(self.state_of()['keys'], 'unkeyed')

    def test_an_environment_that_does_not_read_is_not_taken_for_no_mark(self):
        self.keys.unlink()
        good = stock_environment(*STOCK)
        for name, data in (('one bit', good[:100] + bytes((good[100] ^ 1,)) + good[101:]), ('cut short', good[:-1]),
                           ('empty', b''), ('erased', b'\xff' * 0x4000),
                           ('no end', struct.pack('<I', zlib.crc32(b'a' * 0x3ffc)) + b'a' * 0x3ffc)):
            with self.subTest(name):
                self.environment.write_bytes(data)
                state = self.state_of()
                self.assertEqual((state['keys'], state['key_mark']), ('lost', 'unreadable'))
                self.assertEqual(self.stage('stage-loader', LOADER_IMAGE).returncode, 1)
        self.environment.unlink()
        self.assertEqual(self.state_of()['keys'], 'lost')
        # With a list that reads, the unit is keyed whatever the environment says.
        self.keys.write_bytes(a_list(1))
        self.assertEqual(self.state_of()['keys'], 'keyed')

    def test_a_keyed_unit_whose_list_is_gone_or_damaged_takes_nothing_but_the_owners_word(self):
        for name, damage, kind in (('gone', self.keys.unlink, 'none'),
                                   ('cut', lambda: self.keys.write_bytes(a_list(1)[:-1]), 'damaged'),
                                   ('empty', lambda: self.keys.write_bytes(b''), 'damaged'),
                                   ('not a list', lambda: self.keys.write_text('ssh-ed25519 AAAA\n'), 'damaged')):
            with self.subTest(name):
                self.keys.write_bytes(a_list(1))
                damage()
                self.assertEqual(self.kinds()[:2], ('lost', kind))
                for refused in (self.release(7), self.stage('stage-loader', LOADER_IMAGE),
                                self.stage('stage', NEW_ROOT),
                                self.give('rotate', rotation(a_list(2), ROOT_KEY))):
                    self.assertEqual(refused.returncode, 1)
                    self.assertIn('was given a list of keys and holds none that reads', refused.stderr)
                    self.assertIn('at the bench', refused.stderr)
                self.assertFalse((self.dir / 'durable/update').exists())
                self.assertNotEqual(self.update('keys').returncode, 0)
                taken = self.stage('stage-loader', OTHER_LOADER, '--unsigned')
                self.assertEqual(taken.returncode, 0, taken.stderr)
                self.assertEqual(self.update('cancel').returncode, 0)

    def test_a_release_is_verified_staged_confirmed_and_becomes_the_floor(self):
        result = self.release(7)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('release 7 verified', result.stdout)
        self.assertEqual(self.state_of()['release_verified'], '7')
        result = self.stage('stage-loader', LOADER_IMAGE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertRegex((self.dir / 'durable/update/release').read_text(), r'^7 [0-9a-f]{64}\n$')
        self.assertEqual(self.state_of()['release'], '0', 'not the floor until it is confirmed')
        result = self.confirm_loader()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('release 7', result.stdout)
        state = self.state_of()
        self.assertEqual((state['release'], state['release_verified'], state['loader_staged']), ('7', '', ''))

    def test_after_that_nothing_older_is_taken_and_the_same_or_newer_is(self):
        self.release(7)
        self.stage('stage-loader', LOADER_IMAGE)
        self.confirm_loader()
        older = self.release(6)
        self.assertEqual(older.returncode, 1)
        self.assertIn('release 6 is older than release 7', older.stderr)
        self.assertIn('not a release this unit takes', older.stderr)
        self.assertEqual(self.stage('stage-loader', OTHER_LOADER).returncode, 1)
        self.assertEqual(self.release(7).returncode, 0)
        self.assertEqual(self.release(8).returncode, 0)

    def test_an_update_that_is_cancelled_does_not_move_the_floor(self):
        self.release(7)
        self.stage('stage-loader', LOADER_IMAGE)
        self.assertEqual(self.update('cancel').returncode, 0)
        self.assertEqual(self.state_of()['release'], '0')
        self.assertEqual(self.release(3).returncode, 0, 'a release never settled on holds nothing back')

    def test_a_loader_the_release_does_not_list_is_refused(self):
        self.release(7)
        result = self.stage('stage-loader', OTHER_LOADER)
        self.assertEqual(result.returncode, 1)
        self.assertIn('whose manifest lists this loader', result.stderr)

    def test_a_release_sealed_by_a_stranger_an_authority_or_changed_verifies_nothing(self):
        for number in (STRANGER, ROOT_KEY, KEYS_KEY):
            with self.subTest(NAMES[number]):
                result = self.release(7, signing(number)[1])
                self.assertEqual(result.returncode, 1)
                self.assertIn('not a release this unit takes', result.stderr)
                self.assertEqual(self.stage('stage-loader', LOADER_IMAGE).returncode, 1)
                self.assertEqual(self.state_of()['release_verified'], '')

    def test_the_owners_word_takes_a_build_of_their_own_and_moves_no_floor(self):
        result = self.stage('stage-loader', OTHER_LOADER, '--unsigned')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unsigned, on the owner's word", result.stderr)
        self.assertFalse((self.dir / 'durable/update/release').exists())
        self.assertEqual(self.confirm_loader(OTHER_LOADER).returncode, 0)
        self.assertEqual(self.state_of()['release'], '0')
        self.assertEqual(self.stage('stage-loader', LOADER_IMAGE, '--anything').returncode, 1)

    def test_a_root_listed_by_the_release_needs_no_word(self):
        self.release(7)
        result = self.stage('stage', NEW_ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        (self.dir / 'dev/ubi0_1').write_bytes(NEW_ROOT)      # the loader wrote it
        shutil.rmtree(self.state)
        self.assertIn('release 7', self.update('confirm').stdout)
        self.assertEqual(self.state_of()['release'], '7')

    def test_a_root_no_release_names_is_taken_on_nobodys_word_but_the_owners(self):
        """A root went to a unit "as built by the host from the release" once, unchecked, while
        each unit's root had its own keys in it. Nothing of a unit is in its root now."""
        self.release(7)
        self.assertEqual(self.stage('stage', UNIT_ROOT).returncode, 1, 'not in the manifest')
        for word in ('--from-release', '--trust-me'):
            refused = self.stage('stage', UNIT_ROOT, word)
            self.assertEqual(refused.returncode, 1)
            self.assertIn('takes releases', refused.stderr)
        self.assertFalse((self.dir / 'durable/update').exists(), 'nothing was staged')
        owned = self.stage('stage', UNIT_ROOT, '--unsigned')
        self.assertEqual(owned.returncode, 0, owned.stderr)
        self.assertIn("on the owner's word", owned.stderr)

    # -- the list itself ------------------------------------------------------------------

    def test_a_rotation_replaces_the_list_and_with_it_who_seals_a_release(self):
        new = a_list(2, ((ROOT_KEY, 'root'), (KEYS_KEY, 'keys'), (STRANGER, 'release')))
        result = self.give('rotate', rotation(new, KEYS_KEY))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('the list of keys is now generation=1.2 sealed_by=the-keys scope=keys', result.stdout)
        self.assertEqual(self.keys.read_bytes(), new)
        self.assertEqual(self.kinds(), ('keyed', 'good', '1.2', '1'))
        self.assertEqual(self.release(7).returncode, 1, 'the key that sealed releases an hour ago')
        self.assertEqual(self.release(7, signing(STRANGER)[1]).returncode, 0)
        self.assertFalse(list((self.dir / 'durable').glob('keys.*')), 'nothing is left beside it')

    def test_what_no_key_of_the_list_sealed_is_not_called_a_fork(self):
        unsigned = rotation(a_list(1, USUAL[:3]), ROOT_KEY)[:-64] + bytes(64)
        result = self.give('rotate', unsigned)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('ANOTHER', result.stderr)
        self.assertIn('not sealed by a root or keys key', result.stderr)

    def test_the_list_held_again_changes_nothing_and_is_no_fault(self):
        before = self.keys.stat().st_mtime_ns
        result = self.give('rotate', rotation(a_list(1), ROOT_KEY))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('this is the list held', result.stdout)
        self.assertEqual(self.keys.stat().st_mtime_ns, before)

    def test_what_is_not_a_rotation_for_this_unit_leaves_its_list_alone(self):
        for name, envelope in (
                ('a release key', rotation(a_list(2), PRIMARY)), ('a stranger', rotation(a_list(2), STRANGER)),
                ('a keys key changing the root', rotation(a_list(2, ((NEW_ROOT_KEY, 'root'), (KEYS_KEY, 'keys'))), KEYS_KEY)),
                ('another list of this generation', rotation(a_list(1, USUAL[:3]), ROOT_KEY)),
                ('a release', seal.seal(MANIFEST, 2, self.sign)), ('nothing', b'')):
            with self.subTest(name):
                result = self.give('rotate', envelope)
                self.assertEqual(result.returncode, 1)
                self.assertIn('not a list this unit takes', result.stderr)
                self.assertEqual(self.keys.read_bytes(), a_list(1))
        older = a_list(1)
        self.keys.write_bytes(a_list(4))
        self.assertEqual(self.give('rotate', rotation(older, ROOT_KEY)).returncode, 1)
        self.assertEqual(self.keys.read_bytes(), a_list(4))

    def test_an_unkeyed_unit_is_given_no_list_over_the_network(self):
        self.unkeyed()
        for verb in ('rotate', 'first'):
            with self.subTest(verb):
                result = self.give(verb, rotation(a_list(1), ROOT_KEY))
                self.assertEqual(result.returncode, 1)
                self.assertIn('at the bench', result.stderr)
                self.assertEqual(self.kinds()[:2], ('unkeyed', 'none'))

    def test_a_first_list_is_for_a_unit_the_stock_prompt_marked(self):
        self.unkeyed()
        self.at_the_bench()
        result = self.give('first', rotation(a_list(1), ROOT_KEY))
        self.assertEqual(result.returncode, 1)
        self.assertIn('is not marked as keyed (mark no)', result.stderr)
        self.assertIn("stock boot loader's prompt", result.stderr)
        self.assertEqual(self.kinds()[:2], ('unkeyed', 'none'))
        before = self.environment.read_bytes()
        self.marked(True)
        self.assertEqual(self.give('first', rotation(a_list(1), ROOT_KEY)).returncode, 0)
        self.assertNotEqual(self.environment.read_bytes(), before)
        after = self.environment.read_bytes()
        for verb, arguments in (('rotate', [rotation(a_list(2), ROOT_KEY)]),):
            self.give(verb, *arguments)
        self.update('unkey')
        self.assertEqual(self.environment.read_bytes(), after, 'nothing the unit runs writes the mark')

    def test_at_the_bench_a_marked_unit_is_given_its_first_list(self):
        self.keys.unlink()
        (self.dir / 'durable/release').write_text('9\n')        # a number from before, under other keys
        self.at_the_bench()
        result = self.give('first', rotation(a_list(1), ROOT_KEY))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('this unit is keyed; its list is generation=1.1 sealed_by=the-root scope=root', result.stdout)
        self.assertIn(f'root the-root {seal.fingerprint(signing(ROOT_KEY)[0])}', result.stdout,
                      'what the person at the bench compares')
        self.assertEqual(self.keys.read_bytes(), a_list(1))
        self.assertEqual(self.kinds(), ('keyed', 'good', '1.1', '2'))
        self.assertEqual(self.state_of()['release'], '0', 'release numbers start again with the keys')
        self.assertEqual(self.release(1).returncode, 0)

    def test_a_first_list_is_one_a_root_it_names_sealed_and_is_given_once(self):
        self.keys.unlink()
        self.at_the_bench()
        for name, envelope in (('its keys key', rotation(a_list(1), KEYS_KEY)), ('a stranger', rotation(a_list(1), STRANGER)),
                               ('a release', seal.seal(MANIFEST, 1, self.sign))):
            with self.subTest(name):
                result = self.give('first', envelope)
                self.assertEqual(result.returncode, 1)
                self.assertIn('not a first list', result.stderr)
                self.assertEqual(self.kinds()[:2], ('lost', 'none'))
        self.assertEqual(self.give('first', rotation(a_list(1), ROOT_KEY)).returncode, 0)
        again = self.give('first', rotation(a_list(1, ((NEW_ROOT_KEY, 'root'),)), NEW_ROOT_KEY))
        self.assertEqual(again.returncode, 1)
        self.assertIn('holds a list of keys (1.1)', again.stderr)
        self.assertEqual(self.keys.read_bytes(), a_list(1))

    def test_a_unit_that_lost_its_list_gets_one_again_at_the_bench_and_only_there(self):
        self.keys.unlink()
        self.assertEqual(self.give('first', rotation(a_list(3), ROOT_KEY)).returncode, 1)
        self.assertEqual(self.kinds()[:2], ('lost', 'none'))
        self.at_the_bench()
        self.assertEqual(self.give('first', rotation(a_list(3), ROOT_KEY)).returncode, 0)
        self.assertEqual(self.kinds(), ('keyed', 'good', '1.3', '2'))

    def test_unkeying_is_done_at_the_bench_and_the_mark_comes_off_last(self):
        (self.dir / 'durable/release').write_text('9\n')
        refused = self.update('unkey')
        self.assertEqual(refused.returncode, 1)
        self.assertIn('at the bench', refused.stderr)
        self.assertEqual(self.kinds()[0], 'keyed')
        self.at_the_bench()
        result = self.update('unkey')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('While it is marked it takes nothing sealed', result.stdout)
        self.assertEqual(self.kinds()[:2], ('lost', 'none'), 'the side to fall on until the mark is cleared')
        self.assertEqual(self.state_of()['release'], '0')
        self.marked(False)
        self.assertEqual(self.kinds(), ('unkeyed', 'none', '', '0'))
        self.assertEqual(self.stage('stage-loader', OTHER_LOADER).returncode, 0)

    def test_a_root_from_before_there_were_lists_is_unkeyed_only_without_a_list_and_a_mark(self):
        text = self.script.read_text().replace(f'RELEASE={self.program}', f'RELEASE={self.dir}/absent')
        self.script.write_text(text)
        for name, list_there, mark, kind in (('neither', False, False, 'unkeyed'), ('the mark', False, True, 'lost'),
                                             ('a list', True, False, 'lost'), ('both', True, True, 'lost')):
            with self.subTest(name):
                self.keys.write_bytes(a_list(1)) if list_there else self.keys.unlink(missing_ok=True)
                self.marked(mark)
                state = self.state_of()
                self.assertEqual((state['keys'], state['key_mark']), (kind, 'yes' if mark else 'no'))
                staged = self.stage('stage-loader', OTHER_LOADER)
                self.assertEqual(staged.returncode, 0 if kind == 'unkeyed' else 1, staged.stderr)
                self.update('cancel')

    def test_the_number_settled_on_is_one_release_and_another_under_it_is_refused(self):
        self.release(7)
        self.stage('stage-loader', LOADER_IMAGE)
        self.confirm_loader()
        self.assertRegex((self.dir / 'durable/release').read_text(), r'^7 [0-9a-f]{64}\n$')
        self.assertEqual(self.state_of()['release_manifest'], (self.dir / 'durable/release').read_text().split()[1])
        self.assertEqual(self.release(7).returncode, 0, 'the same release again')
        other = self.dir / 'other.tar'
        bundle.write(other, OTHER_LOADER, NEW_ROOT, config.partitions.GEOMETRY)
        envelope = self.dir / 'work/release.wms2'
        envelope.write_bytes(bundle.sign(other, self.dir / 'other-7.tar', 7, self.sign))
        result = self.update('release', envelope)
        self.assertEqual(result.returncode, 1)
        self.assertIn('ANOTHER release 7 than the one this unit settled on', result.stderr)
        self.assertEqual(self.state_of()['release_verified'], '', 'and nothing of it can be staged')
        self.assertEqual(self.stage('stage-loader', OTHER_LOADER).returncode, 1)
        envelope.write_bytes(bundle.sign(other, self.dir / 'other-8.tar', 8, self.sign))
        self.assertEqual(self.update('release', envelope).returncode, 0, 'under a higher number it is a release')

    def test_a_number_that_does_not_read_stops_releases_and_is_not_taken_for_none(self):
        for garbage in ('seven\n', '-1\n', '7x deadbeef\n'):
            with self.subTest(garbage):
                (self.dir / 'durable/release').write_text(garbage)
                self.assertEqual(self.state_of()['release'], 'unreadable')
                result = self.release(9)
                self.assertEqual(result.returncode, 1)
                self.assertIn('does not read', result.stderr)
                self.assertEqual(self.stage('stage-loader', LOADER_IMAGE).returncode, 1)
        (self.dir / 'durable/release').write_text('')
        self.assertEqual(self.state_of()['release'], 'unreadable', 'an empty file is not no file')
        self.assertEqual(self.release(9).returncode, 1)
        (self.dir / 'durable/release').unlink()
        self.assertEqual(self.state_of()['release'], '0')
        # Durable storage that does not answer says nothing, which is not zero either.
        (self.dir / 'durable-run').write_text('#!/bin/sh\nexit 1\n')
        status = self.update('status')
        self.assertNotEqual(status.returncode, 0)
        self.assertIn('durable storage could not be read', status.stderr)
        self.assertNotIn('release=0', status.stdout)
        self.assertEqual(self.release(9).returncode, 1)

    def test_a_stored_list_altered_into_another_that_reads_is_a_lost_unit_and_no_second_list(self):
        """Found on a unit while lists were kept as text: one digit changed in a stored list was
        not noticed, and the true list, sent again, was then refused as ANOTHER list of the same
        generation. A unit keeps the seals now, and reads its list by them."""
        new = a_list(2, ((ROOT_KEY, 'root'), (KEYS_KEY, 'keys'), (STRANGER, 'release')))
        self.assertEqual(self.give('rotate', rotation(new, KEYS_KEY)).returncode, 0)
        self.assertEqual(self.kinds()[:3], ('keyed', 'good', '1.2'))
        whole = self.keys.kept()
        first, held = links(whole)
        other = a_list(2, ((ROOT_KEY, 'root'), (KEYS_KEY, 'keys'), (SPARE, 'release')))
        self.keys.keep(kept(first, held[:40] + other + held[-64:]))
        self.assertEqual(self.kinds()[:2], ('lost', 'damaged'))
        again = self.give('rotate', rotation(new, KEYS_KEY))
        self.assertEqual(again.returncode, 1)
        self.assertIn('holds none that reads', again.stderr)
        self.assertNotIn('ANOTHER', again.stderr)
        self.assertEqual(self.release(7, signing(SPARE)[1]).returncode, 1, 'and the key written in seals nothing')
        self.keys.keep(whole)
        self.assertEqual(self.kinds()[:3], ('keyed', 'good', '1.2'))

    def test_this_program_run_on_a_unit_not_yet_updated_still_says_its_list(self):
        """The host runs its own copy of this program on the unit, beside whatever verifier the
        unit's root has. One from before lists were kept sealed keeps the text, and has no word
        for giving it. (Found on a unit: the update to this root stopped at that.)"""
        older = self.dir / 'older-verifier'
        older.write_text(f'''#!/bin/sh
case $1 in
text) echo "usage: w1700k-release verify ..." >&2; exit 2 ;;
list) [ "$(head -c 16 "$3")" = "w1700k-sdr keys " ] && echo "generation=1.1" ;;
*) exec {self.program} "$@" ;;
esac
''')
        older.chmod(0o755)
        self.script.write_text(self.script.read_text().replace(f'RELEASE={self.program}', f'RELEASE={older}'))
        Path(self.keys).write_bytes(a_list(1))
        said = self.update('keys')
        self.assertEqual((said.returncode, said.stdout.encode()), (0, a_list(1)), said.stderr)

    def test_a_unit_whose_list_was_kept_as_text_is_lost_until_the_bench_gives_it_again(self):
        Path(self.keys).write_bytes(a_list(1))
        self.assertEqual(self.kinds()[:2], ('lost', 'damaged'))
        self.assertNotEqual(self.update('keys').returncode, 0)
        refused = self.release(7)
        self.assertEqual(refused.returncode, 1)
        self.assertIn('given a list at the bench again', refused.stderr)

    def test_a_verification_does_not_outlive_the_list_or_the_next_release_asked_about(self):
        self.assertEqual(self.release(7).returncode, 0)
        new = a_list(2, ((ROOT_KEY, 'root'), (KEYS_KEY, 'keys'), (STRANGER, 'release')))
        self.assertEqual(self.give('rotate', rotation(new, KEYS_KEY)).returncode, 0)
        self.assertEqual(self.state_of()['release_verified'], '', 'the key that sealed it is no longer one')
        self.assertEqual(self.stage('stage-loader', LOADER_IMAGE).returncode, 1)
        self.assertEqual(self.stage('stage', UNIT_ROOT).returncode, 1)
        self.assertEqual(self.release(7, signing(STRANGER)[1]).returncode, 0)
        self.assertEqual(self.release(8).returncode, 1, 'sealed by the key that was replaced')
        self.assertEqual(self.state_of()['release_verified'], '', 'a refusal leaves nothing verified')
        self.assertEqual(self.stage('stage-loader', LOADER_IMAGE).returncode, 1)

    def test_one_run_at_a_time_changes_the_unit(self):
        lock = self.dir / 'lock'
        lock.mkdir()
        (lock / 'pid').write_text(f'{os.getpid()}\n')           # a run that is still at work
        for arguments in (('release', self.archive), ('rotate', self.archive), ('cancel',), ('confirm',)):
            with self.subTest(arguments[0]):
                refused = self.update(*arguments)
                self.assertEqual(refused.returncode, 1)
                self.assertIn('another system-update is at work', refused.stderr)
        self.assertEqual(self.update('status').returncode, 0, 'looking is not changing')
        self.assertTrue(lock.is_dir(), 'and the other run keeps its hold')
        (lock / 'pid').write_text('2147483646\n')              # a run that was killed
        self.assertEqual(self.update('cancel').returncode, 0)
        self.assertFalse(lock.exists(), 'a run lets go when it is done')
        self.assertEqual(self.release(7).returncode, 0)
        self.assertFalse(lock.exists())
        self.assertFalse(list(self.dir.glob('held*')), 'and leaves nothing of its own behind')

    def test_what_is_staged_on_the_owners_word_takes_no_number_from_an_earlier_release(self):
        self.release(7)
        self.assertEqual(self.stage('stage-loader', LOADER_IMAGE).returncode, 0)
        self.assertTrue((self.dir / 'durable/update/release').exists())
        self.assertEqual(self.stage('stage-loader', OTHER_LOADER, '--unsigned').returncode, 0)
        self.assertFalse((self.dir / 'durable/update/release').exists())
        self.assertEqual(self.confirm_loader(OTHER_LOADER).returncode, 0)
        self.assertEqual(self.state_of()['release'], '0')

    def test_a_verifier_from_before_there_were_lists_judges_nothing(self):
        old = self.dir / 'old-release'
        old.write_text('#!/bin/sh\necho "usage: w1700k-release verify [--keys FILE] ENVELOPE" >&2\nexit 2\n')
        old.chmod(0o755)
        self.script.write_text(self.script.read_text().replace(f'RELEASE={self.program}', f'RELEASE={old}'))
        self.unkeyed()
        self.assertEqual(self.state_of()['keys'], 'unkeyed', 'a unit that was never keyed is not a lost one')
        self.assertEqual(self.stage('stage-loader', OTHER_LOADER).returncode, 0)
        self.update('cancel')
        self.marked(True)
        self.assertEqual(self.state_of()['keys'], 'lost')
        self.assertEqual(self.stage('stage-loader', OTHER_LOADER).returncode, 1)

    def test_the_number_is_kept_before_what_was_staged_is_forgotten(self):
        self.release(7)
        self.stage('stage-loader', LOADER_IMAGE)
        text = self.script.read_text().replace('forget()\n{', 'forget()\n{\n\tfail "stopped here"')
        self.script.write_text(text)
        self.assertEqual(self.confirm_loader().returncode, 1)
        self.assertEqual(self.state_of()['release'], '7')
        self.assertTrue((self.dir / 'durable/update/request').exists())

    def test_a_list_with_no_release_key_stops_releases_until_the_next_list(self):
        self.assertEqual(self.give('rotate', rotation(a_list(2, USUAL[:2]), KEYS_KEY)).returncode, 0)
        self.assertEqual(self.kinds(), ('keyed', 'good', '1.2', '0'))
        self.assertEqual(self.release(7).returncode, 1)
        self.assertEqual(self.stage('stage-loader', LOADER_IMAGE).returncode, 1)
        self.assertEqual(self.give('rotate', rotation(a_list(3), KEYS_KEY)).returncode, 0)
        self.assertEqual(self.release(7).returncode, 0)


class LocalConsole:
    """A console whose other end is a shell here: what the bench types is run, with the unit's
    paths led to the test's directory."""

    def __init__(self, directory, script):
        self.directory, self.script, self.typed = directory, script, []

    def must_run(self, line, **options):
        self.typed.append(line)
        line = line.replace('/tmp/', f'{self.directory}/').replace('/usr/sbin/system-update', f'sh {self.script}')
        result = subprocess.run(['sh', '-c', line], capture_output=True, text=True)
        return line + '\n' + result.stdout + result.stderr


@unittest.skipUnless(shutil.which(CC), 'no C compiler')
class Bench(Scripted):
    """init/bench: the first list, typed into a unit's console, and the person who answers
    for it."""

    def setUp(self):
        super().setUp()
        self.unkeyed()
        self.at_the_bench()
        self.console = LocalConsole(self.dir, self.script)
        session = mock.MagicMock()
        session.__enter__.return_value = mock.Mock(console=self.console, log=mock.Mock())
        self.marks = []

        def mark(console, log, on):
            self.marks.append(on)
            self.marked(on)
        for name, value in (('open_session', mock.Mock(return_value=session)), ('to_linux', mock.Mock()),
                            ('mark', mark)):
            patch = mock.patch.object(keying, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.asked = []

    def answer(self, word):
        def ask(question):
            self.asked.append(question)
            return word
        return ask

    def key(self, rotations, word='yes'):
        with contextlib.redirect_stdout(io.StringIO()) as said:
            try:
                return keying.key(None, rotations, ask=self.answer(word)), said.getvalue()
            except StepFailed as error:
                return str(error), said.getvalue()

    def test_a_unit_is_keyed_once_its_authorities_are_confirmed(self):
        result, said = self.key([rotation(a_list(1), ROOT_KEY)])
        self.assertEqual(result, 0, said)
        for number in (ROOT_KEY, KEYS_KEY):
            public = signing(number)[0]
            self.assertIn(seal.fingerprint(public), said)
            self.assertIn(seal.registry_fingerprint(public), said)
        self.assertIn(seal.fingerprint(self.primary), said.split('bench: the unit is keyed')[0],
                      'the release keys are shown as well')
        self.assertIn('holds 4 keys', said)
        self.assertIn('all of them and no other', self.asked[0])
        self.assertEqual((len(self.asked), self.marks), (1, [True]))
        self.assertEqual(self.keys.read_bytes(), a_list(1))
        self.assertEqual(self.kinds(), ('keyed', 'good', '1.1', '2'))
        self.assertTrue(all(len(line) < 400 for line in self.console.typed), 'no line the console would cut')

    def test_without_the_word_nothing_is_typed(self):
        result, _ = self.key([rotation(a_list(1), ROOT_KEY)], word='y')
        self.assertIn('not confirmed; nothing was sent', result)
        self.assertEqual((self.console.typed, self.marks), ([], []))
        self.assertEqual(self.kinds()[:2], ('unkeyed', 'none'))

    def test_the_rotations_since_follow_the_first_list(self):
        second = a_list((2, 1), ((ROOT_KEY, 'root'), (NEW_KEYS_KEY, 'keys'), (PRIMARY, 'release')))
        third = a_list((2, 2), ((ROOT_KEY, 'root'), (NEW_KEYS_KEY, 'keys'), (STRANGER, 'release')))
        result, said = self.key([rotation(a_list(1), ROOT_KEY), rotation(second, ROOT_KEY),
                                 rotation(third, NEW_KEYS_KEY)])
        self.assertEqual(result, 0, said)
        self.assertEqual(self.keys.read_bytes(), third)
        self.assertIn('holds list 2.2', said)

    def test_lists_are_given_by_epoch_and_then_generation_whatever_order_they_come_in(self):
        """Generation 1 of the second epoch comes after generation 2 of the first."""
        second = a_list((1, 2), USUAL[:3])
        third = a_list((2, 1), ((ROOT_KEY, 'root'), (NEW_KEYS_KEY, 'keys'), (PRIMARY, 'release')))
        sealed = [rotation(a_list(1), ROOT_KEY), rotation(second, KEYS_KEY), rotation(third, ROOT_KEY)]
        for shuffled in ([sealed[2], sealed[0], sealed[1]], [sealed[1], sealed[2], sealed[0]], list(reversed(sealed))):
            self.assertEqual(keying.in_order(shuffled), sealed)
        result, said = self.key(keying.in_order(reversed(sealed)))
        self.assertEqual(result, 0, said)
        self.assertEqual(self.keys.read_bytes(), third)
        # The development lists in the repository, as the tool reads a directory of them.
        development = keying.in_order(path.read_bytes() for path in sorted((SEAL / 'development').glob('*.wms2')))
        self.assertEqual([seal.parse_list(seal.body_of(envelope)).label for envelope in development], ['1.1', '1.2', '2.1'])
        bundle.chain(development)

    def test_lists_that_do_not_follow_one_from_another_are_not_sent(self):
        for name, rotations, why in (
                ('no first list', [rotation(a_list(1), KEYS_KEY)], 'rotation 1 of 1'),
                ('a gap in who sealed', [rotation(a_list(1), ROOT_KEY), rotation(a_list(2), STRANGER)], 'rotation 2 of 2'),
                ('none', [], 'no sealed list')):
            with self.subTest(name):
                self.assertIn(why, self.key(rotations)[0])
                self.assertEqual((self.console.typed, self.asked, self.marks), ([], [], []))

    def test_a_unit_that_holds_a_list_is_not_given_a_first_one(self):
        self.assertEqual(self.key([rotation(a_list(1), ROOT_KEY)])[0], 0)
        result, _ = self.key([rotation(a_list(1, ((NEW_ROOT_KEY, 'root'),)), NEW_ROOT_KEY)])
        self.assertIn('holds a list of keys (1.1)', result)
        self.assertEqual(self.keys.read_bytes(), a_list(1))

    def test_unkeying_asks_too_and_leaves_a_unit_that_takes_anything(self):
        self.assertEqual(self.key([rotation(a_list(1), ROOT_KEY)])[0], 0)
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaisesRegex(StepFailed, 'not confirmed'):
            keying.unkey(None, ask=self.answer('no'))
        self.assertEqual(self.kinds()[0], 'keyed')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(keying.unkey(None, ask=self.answer('yes')), 0)
        self.assertEqual(self.marks, [True, False], 'the mark went on first and came off last')
        self.assertEqual(self.kinds(), ('unkeyed', 'none', '', '0'))


class Archive(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.plain = self.dir / 'w1700k-update.tar'
        bundle.write(self.plain, b'\xd0\x0d\xfe\xed a loader', b'hsqs a root', config.partitions.GEOMETRY)
        self.primary, self.sign = signing(1)
        self.list = self.dir / 'keys.txt'
        self.list.write_bytes(a_list(1))

    def test_a_release_is_the_archive_with_its_manifest_sealed(self):
        release = self.dir / 'release.tar'
        bundle.sign(self.plain, release, 9, self.sign, source='ab' * 20)
        manifest, files, sealed = bundle.read_release(release)
        self.assertEqual((manifest['release'], manifest['source']), (9, 'ab' * 20))
        self.assertEqual(files, bundle.read(self.plain)[1])
        number, body, key = seal.unseal(sealed, [self.primary])
        self.assertEqual((number, key), (9, self.primary))
        self.assertEqual(json.loads(body)['files'], manifest['files'])
        self.assertEqual(json.loads(body)['source'], 'ab' * 20, 'what it was built from is under the seal')
        self.assertEqual(bundle.read(release)[0]['files'], manifest['files'], 'older readers still read it')
        self.assertIsNone(bundle.read_release(self.plain)[2])
        self.assertEqual(bundle.rotations(release), [])
        for source in ('ab' * 32 + 'x', 'main', '"sha256": "' + 'ab' * 32, ''):
            with self.subTest(source), self.assertRaises(StepFailed) if source else contextlib.nullcontext():
                bundle.sign(self.plain, self.dir / 'bad.tar', 9, self.sign, source=source)
        for number in (0, seal.RELEASE_MOST + 1, '7'):
            with self.subTest(number), self.assertRaises(StepFailed):
                bundle.sign(self.plain, self.dir / 'bad.tar', number, self.sign)

    def test_a_seal_over_another_manifest_is_not_this_archives(self):
        other = self.dir / 'other.tar'
        bundle.write(other, b'\xd0\x0d\xfe\xed another loader', b'hsqs a root', config.partitions.GEOMETRY)
        for path in (self.plain, other):
            bundle.sign(path, path.with_suffix('.signed'), 9, self.sign)
        with tarfile.open(other.with_suffix('.signed')) as archive:
            foreign = archive.extractfile(bundle.SEALED).read()
        mixed = self.dir / 'mixed.tar'
        with tarfile.open(self.plain.with_suffix('.signed')) as source, tarfile.open(mixed, 'w') as target:
            for member in source.getmembers():
                data = foreign if member.name == bundle.SEALED else source.extractfile(member).read()
                member.size = len(data)
                target.addfile(member, io.BytesIO(data))
        with self.assertRaisesRegex(StepFailed, 'not its own manifest'):
            bundle.read_release(mixed)

    def test_an_image_changed_after_signing_is_caught_by_the_manifest(self):
        release = self.dir / 'release.tar'
        bundle.sign(self.plain, release, 9, self.sign)
        data = bytearray(release.read_bytes())
        data[data.index(b'hsqs a root')] ^= 1
        release.write_bytes(bytes(data))
        with self.assertRaisesRegex(StepFailed, 'is not the file its manifest lists'):
            bundle.read_release(release)

    def rewritten(self, name, change):
        """The plain archive as `name`, its manifest changed by `change(manifest)`."""
        manifest, files = bundle.read(self.plain)
        manifest['partitions'] = {key: list(span) for key, span in manifest['partitions'].items()}
        change(manifest)
        bundle._write(self.dir / name, {'manifest.json': (json.dumps(manifest) + '\n').encode(), **files})
        return self.dir / name

    def test_a_manifest_lists_the_images_that_are_there_and_says_nothing_else(self):
        extra = {'sha256': 'cd' * 32, 'bytes': 1}
        for name, change in (('an image that is not there', lambda m: m['files'].update({'extra.bin': extra})),
                             ('a word of its own', lambda m: m.update(note='"sha256": "' + 'cd' * 32 + '"')),
                             ('one image fewer', lambda m: m['files'].pop(bundle.LOADER))):
            with self.subTest(name):
                path = self.rewritten('odd.tar', change)
                with self.assertRaisesRegex(StepFailed, 'lists the images it holds|not a W1700K update archive'):
                    bundle.read_release(path)
                with self.assertRaises(StepFailed):
                    bundle.sign(path, self.dir / 'never.tar', 9, self.sign)
                self.assertFalse((self.dir / 'never.tar').exists())

    def test_an_archive_holds_each_member_once_and_a_rotation_under_its_own_generation(self):
        release = self.dir / 'release.tar'
        turns = [rotation(a_list(1), ROOT_KEY), rotation(a_list(2, USUAL[:3]), KEYS_KEY)]
        bundle.sign(self.plain, release, 9, self.sign, carried=turns)

        def copy(name, also):
            with tarfile.open(release) as source, tarfile.open(self.dir / name, 'w') as target:
                for member in source.getmembers():
                    target.addfile(member, source.extractfile(member))
                for member_name, data in also:
                    info = tarfile.TarInfo(member_name)
                    info.size = len(data)
                    target.addfile(info, io.BytesIO(data))
            return self.dir / name
        with self.assertRaisesRegex(StepFailed, 'holds a member twice'):
            bundle.read_release(copy('twice.tar', [(bundle.LOADER, b'another')]))
        with self.assertRaisesRegex(StepFailed, 'is there twice'):
            bundle.rotations(copy('turn-twice.tar', [('keys/1.2.wms2', turns[1])]))
        with self.assertRaisesRegex(StepFailed, 'keys/1.3.wms2 holds list 1.2'):
            bundle.rotations(copy('misnamed.tar', [('keys/1.3.wms2', turns[1])]))
        with self.assertRaisesRegex(StepFailed, 'not a sealed list'):
            bundle.rotations(copy('garbage.tar', [('keys/1.4.wms2', b'WMS2 and then nothing')]))

    def test_a_release_carries_the_rotations_so_far_as_they_are(self):
        second = a_list(2, USUAL[:3])
        turns = [rotation(a_list(1), ROOT_KEY), rotation(second, KEYS_KEY)]
        release = self.dir / 'release.tar'
        bundle.sign(self.plain, release, 9, self.sign, carried=list(reversed(turns)))
        self.assertEqual(bundle.rotations(release), turns)
        self.assertEqual(bundle.chain(bundle.rotations(release)).text, second)
        self.assertEqual(bundle.read_release(release)[1], bundle.read(self.plain)[1], 'and its images are its images')
        with self.assertRaisesRegex(StepFailed, 'are one list'):
            bundle.sign(self.plain, self.dir / 'twice.tar', 9, self.sign,
                        carried=[turns[0], rotation(a_list(1, USUAL[:3]), ROOT_KEY)])

    def tool(self, *arguments):
        return subprocess.run([sys.executable, str(ROOT / 'init/sign'), *map(str, arguments)],
                              capture_output=True, text=True)

    def test_the_signing_tool_from_key_to_checked_release(self):
        key = self.dir / 'primary.key'
        made = self.tool('keygen', key)
        self.assertEqual(made.returncode, 0, made.stderr)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertRegex(made.stdout, r'^[0-9a-f]{64}\n$')
        self.assertNotIn(key.read_text().strip(), made.stdout + made.stderr, 'the private half is not printed')
        self.assertEqual(self.tool('public', key).stdout, made.stdout)
        again = self.tool('keygen', key)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn('never overwritten', again.stderr)

        keys = self.dir / 'made.txt'
        listed = self.tool('list', '--generation', '1.1', '-o', keys, f'{signing(ROOT_KEY)[0].hex()}:root:the-root',
                           f'{made.stdout.strip()}:release:made-here')
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertIn(seal.registry_fingerprint(signing(ROOT_KEY)[0]), listed.stdout)
        self.assertEqual(seal.parse_list(keys.read_bytes()).keys[1].name, 'made-here')
        self.assertIn('never overwritten', self.tool('list', '--generation', '1.1', '-o', keys,
                                                     f'{signing(ROOT_KEY)[0].hex()}:root:x').stderr)
        self.assertIn('is not KEY:SCOPE:NAME', self.tool('list', '--generation', '1.1', '-o', self.dir / 'x', 'aa').stderr)

        release = self.dir / 'w1700k-release-3.tar'
        signed = self.tool('archive', '--key', key, '--release', 3, self.plain)
        self.assertEqual(signed.returncode, 0, signed.stderr)
        self.assertTrue(release.is_file(), 'named for its number, beside the archive')
        self.assertIn('is release 3', self.tool('check', '--keys', keys, release).stdout)
        self.assertRegex(bundle.read_release(release)[0]['source'], r'^([0-9a-f]{40}(-dirty)?|unknown)$')
        self.assertIn('never overwritten', self.tool('archive', '--key', key, '--release', 3, self.plain).stderr)
        self.assertIn('not sealed', self.tool('check', '--keys', keys, self.plain).stderr)
        refused = self.tool('check', '--keys', self.list, release)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("none of the release keys'", refused.stderr)
        self.assertIn('release 3', self.tool('show', release).stdout)

    def requested(self, number=4):
        """A request for release `number` of the plain archive, as the tool writes it."""
        made = self.tool('request', '--domain', 'development', '--release', number, '--source', 'ab' * 20, self.plain)
        self.assertEqual(made.returncode, 0, made.stderr)
        path = self.dir / f'w1700k-release-{number}.request.json'
        return path, json.loads(path.read_text()), made

    def test_a_key_that_signs_elsewhere_gets_the_bytes_and_returns_a_signature(self):
        path, request, made = self.requested()
        message = bytes.fromhex(request['auth_hex'])
        self.assertEqual((request['counter'], request['release'], request['device'], request['topic'],
                          request['bytes'], request['source_commit'], request['domain']),
                         (4, 4, seal.PRODUCT, seal.TOPIC, len(message), 'ab' * 20, 'development'))
        self.assertEqual(hashlib.sha256(message).hexdigest(), request['auth_sha256'])
        self.assertIn(request['auth_sha256'], made.stdout)
        # What the keeper is asked to sign is the topic, the header and the manifest, in the clear.
        topic = seal.TOPIC.encode()
        self.assertEqual(message[:2 + len(topic)], struct.pack('<H', len(topic)) + topic)
        manifest = message[request['manifest_at']:]
        self.assertEqual(request['manifest_at'], 2 + len(topic) + seal.HEADER)
        self.assertEqual(hashlib.sha256(manifest).hexdigest(), request['manifest_sha256'])
        self.assertEqual((json.loads(manifest)['release'], json.loads(manifest)['source']), (4, 'ab' * 20))
        self.assertIn('never overwritten', self.tool('request', '--domain', 'development', '--release', 4, self.plain).stderr)
        self.assertNotEqual(self.tool('request', '--release', 5, self.plain).returncode, 0, 'which keys are asked is said')

        # The keeper signs those bytes and nothing of ours touches its key.
        signature = self.sign(message)
        release = self.dir / 'w1700k-release-4.tar'
        attached = self.tool('attach', '--request', path, '--signature', signature.hex(), '--keys', self.list, self.plain)
        self.assertEqual(attached.returncode, 0, attached.stderr)
        self.assertIn('is release 4', self.tool('check', '--keys', self.list, release).stdout)
        # It is byte for byte the release a key on this host would have sealed at that moment.
        whole = self.dir / 'whole.tar'
        bundle.sign(self.plain, whole, 4, self.sign, request['time_ms'], source='ab' * 20)
        self.assertEqual(release.read_bytes(), whole.read_bytes())
        self.assertIn('never overwritten', self.tool('attach', '--request', path, '--signature', signature.hex(),
                                                     '--keys', self.list, self.plain).stderr)

    def test_a_signature_is_attached_only_if_it_is_a_release_keys_over_this_request(self):
        release = self.dir / 'w1700k-release-4.tar'
        path, request, _ = self.requested()
        message = bytes.fromhex(request['auth_hex'])
        good, in_file = self.sign(message), self.dir / 'signature'
        attach = lambda signature, archive=self.plain: self.tool(      # noqa: E731
            'attach', '--request', path, '--signature', signature, '--keys', self.list, archive)
        for what, signature, said in (
                ('a stranger', signing(STRANGER)[1](message).hex(), 'not over the bytes'),
                ('the root key', signing(ROOT_KEY)[1](message).hex(), 'not over the bytes'),
                ('the keys key', signing(KEYS_KEY)[1](message).hex(), 'not over the bytes'),
                ('another message', self.sign(message + b' ').hex(), 'not over the bytes'),
                ('one bit', (good[:-1] + bytes((good[-1] ^ 1,))).hex(), 'not over the bytes'),
                ('half of one', good.hex()[:64], 'a signature is 64 bytes'),
                ('not hex', 'yes', 'not a signature')):
            with self.subTest(what):
                refused = attach(signature)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn(said, refused.stderr)
                self.assertFalse(release.exists(), 'nothing is written')
        # The archive the request was made of, and no other.
        other = self.dir / 'other.tar'
        bundle.write(other, b'\xd0\x0d\xfe\xed another loader', b'hsqs a root', config.partitions.GEOMETRY)
        refused = attach(good.hex(), other)
        self.assertIn('is not the archive', refused.stderr)
        self.assertFalse(release.exists())
        # A request someone changed on its way back is not a request, nor is one for a list.
        changed = dict(request, counter=5)
        changed['auth_hex'] = request['auth_hex'][:-2] + '00'
        path.write_text(json.dumps(changed))
        self.assertIn('not a signing request', attach(good.hex()).stderr)
        path.write_text(json.dumps(dict(request, topic=seal.ROTATE_TOPIC)))
        self.assertIn('not a signing request', attach(good.hex()).stderr)
        path.write_text(json.dumps(request))
        # As a file, with the line breaks a keeper's tool may put in it.
        in_file.write_text(good.hex()[:64] + '\n' + good.hex()[64:] + '\n')
        self.assertEqual(attach(in_file).returncode, 0)
        self.assertTrue(release.is_file())

    def key_file(self, number):
        path = self.dir / f'{NAMES[number]}.key'
        path.write_text((bytes((number,)) * 32).hex() + '\n')
        return path

    def test_a_list_is_sealed_here_only_by_a_key_that_may(self):
        new = self.dir / 'new.txt'
        new.write_bytes(a_list(2, ((ROOT_KEY, 'root'), (KEYS_KEY, 'keys'), (STRANGER, 'release'))))
        first = self.tool('rotate', '--key', self.key_file(ROOT_KEY), '--list', self.list)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(seal.rotated(None, (self.dir / 'w1700k-keys-1.1.wms2').read_bytes())[1].name, 'the-root')
        self.assertIn('names itself', self.tool('rotate', '--key', self.key_file(KEYS_KEY), '--list', self.list,
                                                '-o', self.dir / 'x.wms2').stderr)
        turned = self.tool('rotate', '--key', self.key_file(KEYS_KEY), '--list', new, '--held', self.list)
        self.assertEqual(turned.returncode, 0, turned.stderr)
        self.assertIn('list 1.2, sealed by the-keys (keys', turned.stdout)
        for name, arguments, said in (
                ('a release key', ('--key', self.key_file(PRIMARY), '--list', new, '--held', self.list),
                 'not sealed by a root or keys key'),
                ('the generation held', ('--key', self.key_file(ROOT_KEY), '--list', self.list, '--held', self.list),
                 'that is the list held'),
                ('written already', ('--key', self.key_file(ROOT_KEY), '--list', new, '--held', self.list),
                 'never overwritten')):
            with self.subTest(name):
                refused = self.tool('rotate', *arguments)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn(said, refused.stderr)
        shown = self.tool('show', self.dir / 'w1700k-keys-1.2.wms2', self.list)
        self.assertIn('list 1.2 (epoch 1, generation 2), 3 keys', shown.stdout)
        self.assertIn(seal.fingerprint(signing(STRANGER)[0]), shown.stdout)

    def test_a_list_is_sealed_by_a_key_that_signs_elsewhere(self):
        new = self.dir / 'new.txt'
        new.write_bytes(a_list((2, 1), ((ROOT_KEY, 'root'), (NEW_KEYS_KEY, 'keys'), (PRIMARY, 'release'))))
        made = self.tool('rotate-request', '--domain', 'production', '--list', new, '--held', self.list)
        self.assertEqual(made.returncode, 0, made.stderr)
        self.assertIn('a root key of list 1.1 seals it', made.stdout)
        self.assertIn('New in it, to show they are held (rotate-proof): new-keys', made.stdout)
        path = self.dir / 'w1700k-keys-2.1.request.json'
        request = json.loads(path.read_text())
        message = bytes.fromhex(request['auth_hex'])
        self.assertEqual((request['topic'], request['device'], request['counter'], request['epoch'], request['generation'],
                          request['needs'], request['held_list'], request['needs_proofs'], request['new_key_proofs'],
                          request['domain']),
                         (seal.ROTATE_TOPIC, seal.PRODUCT, 1, 2, 1, 'root', a_list(1).decode(), ['new-keys'], {}, 'production'))
        self.assertEqual(hashlib.sha256(message).hexdigest(), request['auth_sha256'])
        self.assertEqual(message[request['list_at']:], new.read_bytes())
        self.assertEqual(hashlib.sha256(new.read_bytes()).hexdigest(), request['list_sha256'])
        sealed = self.dir / 'w1700k-keys-2.1.wms2'
        attach = lambda signature: self.tool('rotate-attach', '--request', path, '--signature', signature,   # noqa: E731
                                              '--held', self.list)
        for name, by, said in (('the keys key', KEYS_KEY, 'only a root key of the list held starts one'),
                               ('a release key', PRIMARY, 'not sealed by a root or keys key'),
                               ('the new keys key', NEW_KEYS_KEY, 'not sealed by a root or keys key')):
            with self.subTest(name):
                refused = attach(signing(by)[1](message).hex())
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn(said, refused.stderr)
                self.assertFalse(sealed.exists())
        attached = attach(signing(ROOT_KEY)[1](message).hex())
        self.assertEqual(attached.returncode, 0, attached.stderr)
        # Byte for byte what a key on this host would have sealed at that moment.
        self.assertEqual(sealed.read_bytes(), rotation(new.read_bytes(), ROOT_KEY, when_ms=request['time_ms']))
        # A request that says one generation and asks for another, or a time no header holds.
        for name, change in (('a generation it does not ask for', {'counter': 999}), ('a negative time', {'time_ms': -1}),
                             ('a time too long', {'time_ms': 1 << 64})):
            with self.subTest(name):
                lying = self.dir / 'lying.request.json'
                lying.write_text(json.dumps(dict(request, **change)))
                refused = self.tool('rotate-attach', '--request', lying, '--signature',
                                    signing(ROOT_KEY)[1](message).hex(), '--held', self.list, '-o', self.dir / 'lie.wms2')
                self.assertNotEqual(refused.returncode, 0)
                self.assertNotIn('Traceback', refused.stderr)
                self.assertFalse((self.dir / 'lie.wms2').exists())
        # The new key shows it is held, by signing the same bytes; nobody else can for it.
        proved = self.tool('rotate-proof', '--request', path, '--name', 'new-keys', '--signature',
                           signing(NEW_KEYS_KEY)[1](message).hex())
        self.assertEqual(proved.returncode, 0, proved.stderr)
        self.assertIn('every new key has one', proved.stdout)
        kept = json.loads(path.read_text())
        self.assertTrue(seal.verifies(signing(NEW_KEYS_KEY)[0], message, bytes.fromhex(kept['new_key_proofs']['new-keys'])))
        self.assertEqual({key: kept[key] for key in request}, {**request, 'new_key_proofs': kept['new_key_proofs']})
        for name, arguments, said in (
                ('another key', ('--name', 'new-keys', '--signature', signing(STRANGER)[1](message).hex()), "is not new-keys's"),
                ('a key file that is not it', ('--name', 'new-keys', '--key', self.key_file(STRANGER)), 'is not the key'),
                ('a name the list has not', ('--name', 'nobody', '--signature', 'ab' * 64), 'names no key nobody')):
            with self.subTest(name):
                refused = self.tool('rotate-proof', '--request', path, *arguments)
                self.assertNotEqual(refused.returncode, 0)
                self.assertIn(said, refused.stderr)
        self.assertEqual(self.tool('rotate-proof', '--request', path, '--name', 'new-keys', '--key',
                                   self.key_file(NEW_KEYS_KEY)).returncode, 0)
        # A request that leaves the root and keys lines alone says a keys key will do.
        other = self.dir / 'other.txt'
        other.write_bytes(a_list(3, USUAL[:3]))
        self.assertIn('a root or keys key of list 1.1 seals it',
                      self.tool('rotate-request', '--domain', 'production', '--list', other, '--held', self.list).stdout)
        self.assertEqual(json.loads((self.dir / 'w1700k-keys-1.3.request.json').read_text())['needs'], 'root or keys')

    def test_a_key_that_signs_elsewhere_signs_for_the_rotations_carried_too(self):
        carry = self.dir / 'carry'
        carry.mkdir()
        (carry / '1.wms2').write_bytes(rotation(a_list(1), ROOT_KEY))
        made = self.tool('request', '--domain', 'production', '--release', 6, '--carry', carry, self.plain)
        self.assertEqual(made.returncode, 0, made.stderr)
        path = self.dir / 'w1700k-release-6.request.json'
        message = bytes.fromhex(json.loads(path.read_text())['auth_hex'])
        manifest = json.loads(message[json.loads(path.read_text())['manifest_at']:])
        self.assertEqual(manifest['rotations'], {'1.1': hashlib.sha256((carry / '1.wms2').read_bytes()).hexdigest()})
        signature = self.sign(message).hex()
        without = self.tool('attach', '--request', path, '--signature', signature, '--keys', self.list, self.plain)
        self.assertNotEqual(without.returncode, 0)
        self.assertIn('not with the rotations it was made with', without.stderr)
        attached = self.tool('attach', '--request', path, '--signature', signature, '--keys', self.list,
                             '--carry', carry, self.plain)
        self.assertEqual(attached.returncode, 0, attached.stderr)
        self.assertEqual(len(bundle.rotations(self.dir / 'w1700k-release-6.tar')), 1)

    def test_a_release_takes_the_rotations_along_and_is_sealed_by_a_key_they_end_with(self):
        carry = self.dir / 'carry'
        carry.mkdir()
        second = a_list(2, ((ROOT_KEY, 'root'), (KEYS_KEY, 'keys'), (STRANGER, 'release')))
        (carry / 'b.wms2').write_bytes(rotation(a_list(1), ROOT_KEY))
        (carry / 'a.wms2').write_bytes(rotation(second, KEYS_KEY))
        old = self.tool('archive', '--key', self.key_file(PRIMARY), '--release', 5, '--carry', carry, self.plain)
        self.assertNotEqual(old.returncode, 0)
        self.assertIn('is no release key of the list the rotations', old.stderr)
        made = self.tool('archive', '--key', self.key_file(STRANGER), '--release', 5, '--carry', carry, self.plain)
        self.assertEqual(made.returncode, 0, made.stderr)
        release = self.dir / 'w1700k-release-5.tar'
        self.assertEqual(bundle.chain(bundle.rotations(release)).text, second)
        checked = self.tool('check', '--keys', self.list, release)
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn('a unit holding list 1.1 holds list 1.2 after the rotations it carries', checked.stdout)
        self.assertIn('it carries 2 rotations', self.tool('show', release).stdout)
        (carry / 'c.wms2').write_bytes(rotation(a_list(4), STRANGER))
        broken = self.tool('archive', '--key', self.key_file(STRANGER), '--release', 6, '--carry', carry, self.plain)
        self.assertIn('rotation 3 of 3 is not one a unit takes', broken.stderr)


class Issued(unittest.TestCase):
    """seal/development/: Whitehat Hardware's development lists as they were sealed, and the
    proofs of possession of the keys in them."""
    CHAIN = SEAL / 'development'
    # What each release key was asked to sign on 2026-11-14 (a WMS2 control envelope on a topic
    # that is not a release's), and the signature its keeper returned.
    PROOF = (b'\x14\x00w1700k-sdr/key-proof' + b'WMS2\x02\x00' + b'w1700k-sdr'.ljust(16, b'\0')
             + struct.pack('<QQH', 1, 0, 0) + b'w1700k-sdr release key proof 04028d2ba19da5ed8463c10838bce40a')
    RETURNED = {
        'w1700k-sdr-release-dev-primary': '318d17b0c31c3dba227ac6324253b0dc2ed6552efd396cc99dd4f61f0e57842d'
                                          '97b0fd72928d9bd553922e98b7a2dce5157b01351a46dc206ddd186c85d1380a',
        'w1700k-sdr-release-dev-spare': '8cb7f12469bae32a9f9d9175dc2e0779233f4dc62044145718be5fa5cf620a97'
                                        '611bbd34d99696cecbe3952bbb07204929194a78c71c7857548a0cbc46489d03'}
    # As issued: name, scope, the fingerprint a unit prints, the one Whitehat's registry keeps.
    KEYS = (('w1700k-sdr-authority-dev-backup', 'root', 'f7e758ffb0751cd2', '3f9d5799a3d97ad3'),
            ('w1700k-sdr-authority-dev-primary', 'keys', 'f32ca834d273c0a6', 'e07447c2e64b13c5'),
            ('w1700k-sdr-release-dev-primary', 'release', '38b64574d835b7ae', 'c4e364f1f6f08554'),
            ('w1700k-sdr-release-dev-spare', 'release', 'ba61fe09d01305b2', '9374a036a2ab78c2'))
    # With the first list, each release key signed what the root signed, to show it is held.
    HELD = {'w1700k-sdr-release-dev-primary': 'acadaa99fdd431a25fa3dce82e75e01cdfb35714de99521f0d1ae7b1c57837cc'
                                              '721bcb11ad214651c9d9cce535e73403bba67cd31534937403bb32d96902c80f',
            'w1700k-sdr-release-dev-spare': '86d548358ed224560dd25e0a31272bb3d67deca36ea6978617b4c434e0ecf453'
                                            '187dc89de60ca5338f200bf35003eda5fe729787bad89c9330ac50654294c20a'}

    # Each list since: its label, who sealed it, and the keys that were new in it, each with the
    # signature over the same bytes by which it showed it is held.
    SINCE = (('1.2', 'w1700k-sdr-authority-dev-primary', 'keys',
              {'w1700k-sdr-release-dev-primary-2': ('2329d353dd0bdf1e', '9b4bb84c85625393',
                                                    '171ad9a8413e4b0ab70072dba9398c76500767b9dade4c5a251f1b02c4ec1d5a'
                                                    '9b21bd4f44da629586b49ec2541ddf615f85e179ec3ef5e6167512228d757909')}),
             ('2.1', 'w1700k-sdr-authority-dev-backup', 'root',
              {'w1700k-sdr-authority-dev-primary-2': ('14c5025409ff981f', 'dfa58a73a9d764e9',
                                                      '4a4ce35bda324daaf0f717dbaa5b0c2768caa0484d9be6a6c297d003f5805694'
                                                      '4611df442a9f32f29d1beda8dbefef87016fc6912637d01bf3793aa1971a0104')}))

    def chain(self):
        sealed = [path.read_bytes() for path in self.CHAIN.glob('*.wms2')]
        return sorted(sealed, key=lambda envelope: seal.parse_list(seal.body_of(envelope)).stamp)

    def test_the_chain_is_one_a_unit_takes_from_its_first_list_on(self):
        chain = self.chain()
        self.assertTrue(chain)
        held, by = seal.rotated(None, chain[0])
        self.assertEqual((held.label, by.name, by.scope), ('1.1', 'w1700k-sdr-authority-dev-backup', 'root'))
        self.assertEqual([(key.name, key.scope, seal.fingerprint(key.public), seal.registry_fingerprint(key.public))
                          for key in held.keys], list(self.KEYS))
        self.assertEqual(hashlib.sha256(b'\x16\x00w1700k-sdr/rotate-keys' + chain[0][:-64]).hexdigest(),
                         '12e4405354816bdb3a84ce9f30f4c6f98bde5b6ff6c19f213623fe3e4ae5101f', 'the bytes that were asked for')
        bundle.chain(chain)
        for name, envelope in zip(sorted(path.name for path in self.CHAIN.glob('*.wms2')), chain):
            self.assertEqual(name, f'w1700k-keys-{seal.parse_list(seal.body_of(envelope)).label}.wms2')

    def test_every_list_since_follows_from_the_one_before_and_its_new_keys_are_held(self):
        chain = self.chain()
        self.assertEqual(len(chain), 1 + len(self.SINCE), 'a list in the chain that this test does not know')
        held, _ = seal.rotated(None, chain[0])
        for envelope, (label, sealer, scope, new) in zip(chain[1:], self.SINCE):
            with self.subTest(label):
                following, by = seal.rotated(held, envelope)
                self.assertEqual((following.label, by.name, by.scope), (label, sealer, scope))
                fresh = {key.name: key for key in following.keys if key.public not in {k.public for k in held.keys}}
                self.assertEqual(set(fresh), set(new))
                message = b'\x16\x00w1700k-sdr/rotate-keys' + envelope[:-64]
                for name, (unit_print, registry, proof) in new.items():
                    key = fresh[name]
                    self.assertEqual((seal.fingerprint(key.public), seal.registry_fingerprint(key.public)),
                                     (unit_print, registry))
                    self.assertTrue(seal.verifies(key.public, message, bytes.fromhex(proof)), name)
                held = following
        self.assertEqual([(key.name, key.scope) for key in held.keys],
                         [('w1700k-sdr-authority-dev-backup', 'root'), ('w1700k-sdr-authority-dev-primary-2', 'keys'),
                          ('w1700k-sdr-release-dev-primary-2', 'release'), ('w1700k-sdr-release-dev-spare', 'release')],
                         'what a development unit holds today')

    def test_each_release_key_proved_it_is_held_twice(self):
        self.assertEqual(hashlib.sha256(self.PROOF).hexdigest(),
                         'be58e07d949e97b6f0440a609799608bb65132ebe02c22585b8734cd998cb3c3')
        first = self.chain()[0]
        keys = seal.parse_list(seal.body_of(first))
        message = b'\x16\x00w1700k-sdr/rotate-keys' + first[:-64]
        for key in keys.scoped('release'):
            for said, signature in ((self.PROOF, self.RETURNED[key.name]), (message, self.HELD[key.name])):
                self.assertTrue(seal.verifies(key.public, said, bytes.fromhex(signature)), key.name)
                self.assertFalse(any(seal.verifies(other.public, said, bytes.fromhex(signature))
                                     for other in keys.keys if other != key))

    @unittest.skipUnless(shutil.which(CC), 'no C compiler')
    def test_the_units_verifier_takes_the_chain(self):
        with tempfile.TemporaryDirectory() as work:
            program, held = Path(work) / 'w1700k-release', Path(work) / 'held'
            subprocess.run([CC, '-std=c99', '-D_POSIX_C_SOURCE=200809L', '-Wno-comment', '-I', str(SEAL),
                            '-I', str(SEAL / 'include'), *(str(SEAL / source) for source in SOURCES),
                            '-o', str(program)], check=True, capture_output=True)
            for number, envelope in enumerate(self.chain()):
                sealed = Path(work) / 'list.wms2'
                sealed.write_bytes(envelope)
                taken = subprocess.run([str(program), 'rotate', *(['--first'] if number == 0 else ['--keys', str(held)]),
                                        '--out', str(held), str(sealed)], capture_output=True, text=True)
                self.assertEqual(taken.returncode, 0, taken.stderr)
            self.assertEqual(seal.body_of(links(held.read_bytes())[-1]), seal.body_of(self.chain()[-1]))
            self.assertEqual([seal.parse_list(seal.body_of(link)).label for link in links(held.read_bytes())], ['1.1', '2.1'],
                             'the first list and the one that began the epoch it is in')


if __name__ == '__main__':
    unittest.main()
