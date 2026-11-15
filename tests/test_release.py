# SPDX-License-Identifier: MIT
"""Signed releases: the envelope on the host, the verifier a unit runs, the archive, the
signing tool, and the unit's update script taking only what a release lists."""
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'init'))
from initkit import bundle, config, seal  # noqa: E402
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

    def test_the_host_and_the_unit_mean_the_same_release(self):
        header = (SEAL / 'release.h').read_text()
        for name, value in (('RELEASE_TOPIC', seal.TOPIC), ('RELEASE_PRODUCT', seal.PRODUCT),
                            ('RELEASE_ENVELOPE_MOST', seal.ENVELOPE_MOST)):
            with self.subTest(name):
                found = re.search(rf'#define {name} "?([^"\n]+)"?', header).group(1)
                self.assertEqual(found, str(value))
        self.assertEqual(seal.KEYS_MOST, int(re.search(r'#define KEYS_MOST (\d+)',
                                                       (SEAL / 'release.c').read_text()).group(1)))

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

    def test_a_key_file_is_keys_notes_and_comments(self):
        primary, _ = signing(1)
        spare, _ = signing(2)
        text = f'# the release keys\n\n{primary.hex()}  primary (abc)\n  {spare.hex()}\n'
        self.assertEqual(seal.read_keys(text), [primary, spare])
        self.assertEqual(seal.read_keys('# none\n'), [])
        for bad in (primary.hex()[:-1], primary.hex().upper(), 'ssh-ed25519 AAAA', primary.hex() + 'x'):
            with self.subTest(bad[:20]), self.assertRaises(seal.Refused):
                seal.read_keys(bad + '\n')
        with self.assertRaisesRegex(seal.Refused, 'more than 8'):
            seal.read_keys(''.join(bytes((n,)) .hex() * 32 + '\n' for n in range(9)))


class Built(unittest.TestCase):
    """seal/release.c built for this host, two keys, and a directory to work in."""

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
        self.primary, self.sign = signing(1)
        self.spare, self.sign_spare = signing(2)
        self.keys = self.dir / 'release-keys'
        self.keys.write_text(f'# two keys\n{self.primary.hex()}  primary\n{self.spare.hex()}\n')
        self.state = self.dir / 'state'

    def run_it(self, verb, *arguments, keys=True):
        options = (['--keys', str(self.keys)] if keys and verb in ('verify', 'pinned') else []) + \
                  (['--state', str(self.state)] if verb != 'pinned' else [])
        return subprocess.run([str(self.program), verb, *options, *map(str, arguments)],
                              capture_output=True, text=True)

    def verify(self, envelope, floor=0):
        path = self.dir / 'release.wms2'
        path.write_bytes(envelope)
        return self.run_it('verify', '--floor', floor, path)


@unittest.skipUnless(shutil.which(CC), 'no C compiler')
class Verifier(Built):
    """The program a unit verifies a release with."""

    def test_a_release_is_verified_and_kept_for_the_staging(self):
        result = self.verify(seal.seal(MANIFEST, 5, self.sign))
        self.assertEqual((result.returncode, result.stdout),
                         (0, f'release=5 key={seal.fingerprint(self.primary)}\n'))
        self.assertEqual(result.stderr, '')
        self.assertEqual((self.state / 'manifest').read_bytes(), MANIFEST)
        self.assertEqual(self.run_it('number').stdout, '5\n')
        self.assertEqual(self.run_it('allows', 'ab' * 32).returncode, 0)
        self.assertEqual(self.run_it('allows', 'cd' * 32).returncode, 1)

    def test_the_spare_key_seals_as_well_and_says_so_quietly(self):
        result = self.verify(seal.seal(MANIFEST, 5, self.sign_spare))
        self.assertEqual(result.stdout, f'release=5 key={seal.fingerprint(self.spare)}\n')
        self.assertEqual(result.stderr, '', 'the first key not matching is no event')

    def test_a_changed_manifest_another_key_and_another_topic_are_refused(self):
        sealed = seal.seal(MANIFEST, 5, self.sign)
        changed = bytearray(sealed)
        changed[70] ^= 0x20
        stranger, sign_stranger = signing(3)
        with mock.patch.object(seal, 'TOPIC', 'other-product/release'):
            elsewhere = seal.seal(MANIFEST, 5, self.sign)
        for name, envelope in (('changed', bytes(changed)), ('stranger', seal.seal(MANIFEST, 5, sign_stranger)),
                               ('topic', elsewhere), ('cut', sealed[:-1]), ('short', sealed[:50]),
                               ('empty', b'')):
            with self.subTest(name):
                result = self.verify(envelope)
                self.assertEqual(result.returncode, 1)
                self.assertIn('not a release sealed by a key this unit pins', result.stderr)
                self.assertFalse(self.state.exists(), 'nothing is kept of what did not verify')

    def test_a_release_for_another_product_under_the_same_topic_is_refused(self):
        with mock.patch.object(seal, 'PRODUCT', 'another'):
            result = self.verify(seal.seal(MANIFEST, 5, self.sign))
        self.assertEqual(result.returncode, 1)
        self.assertIn('sealed for another, not for w1700k-sdr', result.stderr)

    def test_nothing_older_than_what_the_unit_settled_on(self):
        sealed = seal.seal(MANIFEST, 5, self.sign)
        self.assertEqual(self.verify(sealed, floor=4).returncode, 0)
        self.assertEqual(self.verify(sealed, floor=5).returncode, 0, 'the same release again is no step back')
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

    def test_a_unit_with_no_keys_verifies_nothing(self):
        self.keys.unlink()
        self.assertEqual((self.run_it('pinned').returncode, self.run_it('pinned').stdout), (1, '0\n'))
        result = self.verify(seal.seal(MANIFEST, 5, self.sign))
        self.assertEqual(result.returncode, 2)
        self.assertIn('pins no release key', result.stderr)

    def test_the_key_file_is_read_as_the_host_reads_it(self):
        self.assertEqual(self.run_it('pinned').stdout, '2\n')
        for bad in ('ssh-ed25519 AAAA\n', self.primary.hex()[:-2] + '\n', self.primary.hex().upper() + '\n',
                    (self.primary.hex() + '\n') * 9):
            with self.subTest(bad[:12]):
                self.keys.write_text(bad)
                self.assertEqual(self.run_it('pinned').returncode, 2)
                self.assertEqual(self.verify(seal.seal(MANIFEST, 5, self.sign)).returncode, 2)

    def test_allows_takes_a_digest_and_nothing_else(self):
        self.verify(seal.seal(MANIFEST, 5, self.sign))
        for bad in ('ab' * 31, 'AB' * 32, 'format', '"'):
            with self.subTest(bad):
                self.assertEqual(self.run_it('allows', bad).returncode, 2)
        shutil.rmtree(self.state)
        self.assertEqual(self.run_it('allows', 'ab' * 32).returncode, 1, 'nothing verified, nothing allowed')
        self.assertEqual(self.run_it('number').returncode, 1)


LOADER_IMAGE = b'\xd0\x0d\xfe\xed' + b'W1700K SDR second ARM loader' + bytes(range(256)) * 4
OTHER_LOADER = LOADER_IMAGE + b'another build'
OLD_ROOT, NEW_ROOT, UNIT_ROOT = b'hsqs the root that runs', b'hsqs the release\'s root', b'hsqs this unit\'s root'
# What the script asks the unit about, answered from the test's directory instead.
OVERRIDES = '''
installed() { :; }
loader_applies() { :; }
loader_starts_second() { :; }
partition() { echo "@D@/dev/mtd5ro"; }
volume() { echo "@D@/dev/ubi0_1"; }
loader_note() { cat "@D@/notes/$1" 2>/dev/null || :; }
second_loader() { cat "@D@/second" 2>/dev/null || :; }
'''


@unittest.skipUnless(shutil.which(CC), 'no C compiler')
class UpdateScript(Built):
    """The unit's own system-update, run as it is but for where it looks: the verifier is
    the real one, durable storage and the flash are directories."""

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
        (d / 'w1700k-release').write_text(
            '#!/bin/sh\nverb=$1; shift\ncase $verb in\n'
            f'verify) exec {self.program} verify --keys {self.keys} --state {self.state} "$@" ;;\n'
            f'pinned) exec {self.program} pinned --keys {self.keys} ;;\n'
            f'*) exec {self.program} "$verb" --state {self.state} "$@" ;;\nesac\n')
        text = SCRIPT.read_text()
        for old, new in (('. /etc/w1700k/storage.conf\n', ''),
                         ('/usr/sbin/durable-run', f'{d}/durable-run'),
                         ('RELEASE=/usr/sbin/w1700k-release', f'RELEASE={d}/w1700k-release'),
                         ('STAGED=/durable/update', f'STAGED={d}/durable/update'),
                         ('FLOOR=/durable/release', f'FLOOR={d}/durable/release'),
                         ('df -k /durable', f'df -k {d}/durable'),
                         ('/sys/class/mtd', f'{d}/sys/mtd'), ('/sys/class/ubi', f'{d}/sys/ubi'),
                         ('case ${1:-} in\nstatus)', OVERRIDES.replace('@D@', str(d)) + 'case ${1:-} in\nstatus)')):
            self.assertIn(old, text)
            text = text.replace(old, new)
        self.script = d / 'system-update'
        self.script.write_text(text)
        for path in (self.script, d / 'durable-run', d / 'w1700k-release'):
            path.chmod(0o755)
        self.archive = d / 'w1700k-update.tar'
        bundle.write(self.archive, LOADER_IMAGE, NEW_ROOT, config.partitions.GEOMETRY)

    def update(self, *arguments):
        return subprocess.run(['sh', str(self.script), *map(str, arguments)], capture_output=True, text=True)

    def release(self, number, sign=None):
        path = self.dir / f'release-{number}.tar'
        sealed = bundle.sign(self.archive, path, number, sign or self.sign)
        envelope = self.dir / 'work/release.wms2'
        envelope.write_bytes(sealed)
        return self.update('release', envelope)

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

    def test_a_unit_with_no_keys_takes_any_update_as_before(self):
        self.keys.unlink()
        result = self.stage('stage-loader', OTHER_LOADER)
        self.assertEqual(result.returncode, 0, result.stderr)
        state = self.state_of()
        self.assertEqual((state['release_keys'], state['release'], state['release_verified']), ('0', '0', ''))
        self.assertIn('pins no release key', self.update('release', self.archive).stderr)

    def test_with_keys_nothing_is_staged_that_no_release_lists(self):
        for verb, data in (('stage-loader', LOADER_IMAGE), ('stage', NEW_ROOT)):
            with self.subTest(verb):
                result = self.stage(verb, data)
                self.assertEqual(result.returncode, 1)
                self.assertIn('this unit takes releases', result.stderr)
                self.assertFalse((self.dir / 'durable/update').exists())
        self.assertEqual(self.state_of()['release_keys'], '2')

    def test_a_release_is_verified_staged_confirmed_and_becomes_the_floor(self):
        result = self.release(7)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('release 7 verified', result.stdout)
        self.assertEqual(self.state_of()['release_verified'], '7')
        result = self.stage('stage-loader', LOADER_IMAGE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.dir / 'durable/update/release').read_text(), '7\n')
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

    def test_a_release_sealed_by_a_stranger_or_changed_verifies_nothing(self):
        _, stranger = signing(3)
        result = self.release(7, stranger)
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

    def test_a_units_own_root_is_taken_from_a_release_and_says_it_is_not_checked(self):
        refused = self.stage('stage', UNIT_ROOT, '--from-release')
        self.assertEqual(refused.returncode, 1, 'no release was verified')
        self.release(7)
        self.assertEqual(self.stage('stage', UNIT_ROOT).returncode, 1, 'not in the manifest, and no word')
        result = self.stage('stage', UNIT_ROOT, '--from-release')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('built by the host from release 7; it is not checked here', result.stderr)
        self.assertEqual((self.dir / 'durable/update/release').read_text(), '7\n')
        loader = self.stage('stage-loader', LOADER_IMAGE, '--from-release')
        self.assertEqual(loader.returncode, 1, 'a loader is the same for every unit: it is in the manifest or not')


class Archive(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        self.plain = self.dir / 'w1700k-update.tar'
        bundle.write(self.plain, b'\xd0\x0d\xfe\xed a loader', b'hsqs a root', config.partitions.GEOMETRY)
        self.primary, self.sign = signing(1)

    def test_a_release_is_the_archive_with_its_manifest_sealed(self):
        release = self.dir / 'release.tar'
        bundle.sign(self.plain, release, 9, self.sign)
        manifest, files, sealed = bundle.read_release(release)
        self.assertEqual(manifest['release'], 9)
        self.assertEqual(files, bundle.read(self.plain)[1])
        number, body, key = seal.unseal(sealed, [self.primary])
        self.assertEqual((number, key), (9, self.primary))
        self.assertEqual(json.loads(body)['files'], manifest['files'])
        self.assertEqual(bundle.read(release)[0]['files'], manifest['files'], 'older readers still read it')
        self.assertIsNone(bundle.read_release(self.plain)[2])

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

    def tool(self, *arguments):
        return subprocess.run([sys.executable, str(ROOT / 'init/sign'), *map(str, arguments)],
                              capture_output=True, text=True)

    def test_the_signing_tool_from_key_to_checked_release(self):
        key, keys = self.dir / 'primary.key', self.dir / 'release-keys'
        made = self.tool('keygen', key)
        self.assertEqual(made.returncode, 0, made.stderr)
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)
        self.assertRegex(made.stdout, r'^[0-9a-f]{64}  primary \([0-9a-f]{16}\)\n$')
        self.assertNotIn(key.read_text().strip(), made.stdout + made.stderr, 'the private half is not printed')
        self.assertEqual(self.tool('public', key).stdout, made.stdout)
        keys.write_text(made.stdout)
        again = self.tool('keygen', key)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn('never overwritten', again.stderr)

        release = self.dir / 'w1700k-release-3.tar'
        signed = self.tool('archive', '--key', key, '--release', 3, self.plain)
        self.assertEqual(signed.returncode, 0, signed.stderr)
        self.assertTrue(release.is_file(), 'named for its number, beside the archive')
        self.assertIn('is release 3', self.tool('check', '--keys', keys, release).stdout)
        self.assertIn('never overwritten', self.tool('archive', '--key', key, '--release', 3, self.plain).stderr)
        self.assertIn('not sealed', self.tool('check', '--keys', keys, self.plain).stderr)
        stranger = self.dir / 'stranger-keys'
        stranger.write_text(signing(2)[0].hex() + '\n')
        refused = self.tool('check', '--keys', stranger, release)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("none of the release keys'", refused.stderr)


if __name__ == '__main__':
    unittest.main()
