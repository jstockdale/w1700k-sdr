# SPDX-License-Identifier: MIT
"""The login keys on the unit (platform/rootfs/overlay/usr/sbin/w1700k-login), run as the unit
runs it: over a directory for the device tree's /chosen as the loader left it and one for durable
storage, with the paperclip key's program (w1700k-keyslot) writing root's authorized_keys from
the list, as on a unit."""
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
LOGIN = ROOT / 'platform/rootfs/overlay/usr/sbin/w1700k-login'
KEYSLOT = ROOT / 'platform/rootfs/overlay/usr/sbin/w1700k-keyslot'
MOST = 32


def public(kind='ssh-ed25519', fill=1, size=32):
    """A public key's two words: its type and base64 body."""
    blob = struct.pack('>I', len(kind)) + kind.encode() + struct.pack('>I', size) + bytes([fill]) * size
    return f'{kind} {base64.b64encode(blob).decode()}'


def entry(key, name):
    return key.replace(' ', ':') + ':' + name


class LoginKeys(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        for name in ('chosen', 'durable', 'run'):
            (self.dir / name).mkdir()
        (self.dir / 'cmdline').write_text('console=ttyS0,115200 ro w1700k.keyslot=empty w1700k.login=none\n')
        run = self.dir / 'durable-run'
        run.write_text(f'#!/bin/sh\necho "$@" >> {self.dir}/durable-calls\n'
                       f'[ ! -e {self.dir}/durable-busy ] || {{ echo "durable-open: durable is already open" >&2; exit 1; }}\n'
                       'echo "durable-open: /durable mounted from mtd6"\n"$@"\nstatus=$?\n'
                       'echo "durable-close: /durable closed"\nexit $status\n')
        run.chmod(0o755)
        keyslot = self.dir / 'w1700k-keyslot'
        keyslot.write_text(f'#!/bin/sh\nexec sh {KEYSLOT} "$@"\n')
        keyslot.chmod(0o755)
        self.store, self.authorized = self.dir / 'durable/ssh/login', self.dir / 'root/.ssh/authorized_keys'
        self.env = dict(os.environ, W1700K_LOGIN_RUN=str(self.dir / 'run/login'), W1700K_LOGIN_CHOSEN=str(self.dir / 'chosen'),
                        W1700K_LOGIN_CMDLINE=str(self.dir / 'cmdline'), W1700K_LOGIN_DURABLE_RUN=str(run),
                        W1700K_LOGIN_DIR=str(self.dir / 'durable/ssh'), W1700K_LOGIN_KEYSLOT=str(keyslot),
                        W1700K_LOGIN_BUILT_IN=str(self.dir / 'lower-authorized_keys'),
                        W1700K_KEYSLOT_RUN=str(self.dir / 'run/keyslot'), W1700K_KEYSLOT_KEYS=str(self.authorized),
                        W1700K_KEYSLOT_LIST=str(self.dir / 'run/login'), W1700K_KEYSLOT_CMDLINE=str(self.dir / 'cmdline'),
                        W1700K_KEYSLOT_DURABLE_RUN=str(run), W1700K_KEYSLOT_DIR=str(self.dir / 'durable/key'),
                        W1700K_KEYSLOT_HOSTKEY=str(self.dir / 'absent'))

    def login(self, *words, stdin='', ok=True):
        result = subprocess.run(['sh', str(LOGIN), *words], input=stdin, capture_output=True, text=True, env=self.env)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def hand_over(self, *entries, said='handed', slot=''):
        """What the loader leaves: each entry as a string property under its place, and its words."""
        for old in (self.dir / 'chosen').iterdir():
            old.unlink()
        for place, text in enumerate(entries, 1):
            if text is not None:
                (self.dir / 'chosen' / f'w1700k,login-{place}').write_bytes(text.encode() + b'\0')
        (self.dir / 'cmdline').write_text(f'console=ttyS0,115200 ro w1700k.keyslot={slot or "empty"}'
                                          + (f' w1700k.login={said}' if said else '') + '\n')

    def boot(self, ok=True):
        """Start-up, in the unit's order: the list, then root's keys from it and the slot."""
        result = self.login('boot', ok=ok)
        subprocess.run(['sh', str(KEYSLOT), 'boot'], check=True, env=self.env, capture_output=True)
        return result

    def reboot(self):
        """The next boot, by a loader that reads the list as durable storage has it."""
        text = self.store.read_text() if self.store.exists() else ''
        entries = [None] * MOST
        for line in text.splitlines():
            name, value = line.split('=', 1)
            entries[int(name[len('login_'):]) - 1] = value
        self.hand_over(*entries, said='handed' if any(entries) else 'none')
        return self.boot()

    def may_log_in(self):
        return self.authorized.read_text().splitlines()

    def listed(self, result=None):
        return (result or self.login('list')).stdout.splitlines()

    def durable_calls(self):
        path = self.dir / 'durable-calls'
        return path.read_text() if path.exists() else ''

    def test_the_keys_the_loader_handed_over_may_log_in(self):
        self.hand_over(entry(public(fill=1), 'desk'), entry(public('ssh-rsa', 2, 400), 'laptop'))
        self.boot()
        self.assertEqual(self.may_log_in(), [public(fill=1) + ' desk', public('ssh-rsa', 2, 400) + ' laptop'])
        self.assertEqual(self.listed(), ['login desk ' + public(fill=1), 'login laptop ' + public('ssh-rsa', 2, 400)])
        self.assertEqual(self.login('status').stdout.split(), ['login=2', 'loader=handed'])
        self.assertEqual(self.durable_calls(), '', 'start-up does not open durable storage')

    def test_a_unit_with_no_list_lets_nobody_in_by_it(self):
        for said, loader in (('none', 'none'), ('', 'silent')):
            self.hand_over(said=said)
            self.boot()
            self.assertEqual(self.may_log_in(), [])
            self.assertEqual(self.login('status').stdout.split(), ['login=0', f'loader={loader}'])

    def test_a_place_left_empty_loses_nothing_and_thirty_two_are_taken(self):
        entries = [entry(public(fill=n), f'key-{n}') for n in range(1, MOST + 2)]
        entries[4] = None
        self.hand_over(*entries)
        self.boot()
        self.assertEqual(self.may_log_in(), [public(fill=n) + f' key-{n}' for n in range(1, MOST + 1) if n != 5],
                         'and what is past the last place is not looked at')

    def test_what_is_not_a_key_and_a_name_is_left_out_and_said(self):
        good = entry(public(fill=1), 'desk')
        key = public(fill=2).replace(' ', ':')
        bad = {'no name': key, 'an empty name': key + ':', 'a name with a space': key + ':my key',
               'a name in capitals': key + ':Desk', 'a name that begins with a dash': key + ':-desk',
               'a name too long': key + ':' + 'n' * 33, 'another type': 'ssh-dss:' + key.split(':')[1] + ':old',
               'a body of another type': 'ssh-rsa:' + key.split(':')[1] + ':liar', 'not base64': 'ssh-ed25519:AAAA!AAA:bang',
               'an option before the key': 'command="sh":' + key + ':opt', 'a second line': key + ':a\n' + key + ':b',
               'a shell word': 'ssh-ed25519:$(touch ' + str(self.dir / 'ran') + '):x', 'too long': entry(public('ssh-rsa', 3, 700), 'big')}
        for what, text in bad.items():
            with self.subTest(what):
                self.hand_over(good, text)
                result = self.boot(ok=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('no usable key in place 2', result.stderr)
                self.assertEqual(self.may_log_in(), [public(fill=1) + ' desk'], 'the good one still may')
                self.assertFalse((self.dir / 'ran').exists())

    def test_a_key_is_added_works_at_once_and_stays(self):
        self.boot()
        added = self.login('add', stdin=public(fill=1) + ' Me@My-Desk\n')
        self.assertEqual(self.listed(added), ['login me@my-desk ' + public(fill=1)])
        self.assertEqual(self.store.read_text(), 'login_1=' + entry(public(fill=1), 'me@my-desk') + '\n', 'as the loader imports it')
        self.assertEqual(self.may_log_in(), [public(fill=1) + ' me@my-desk'])
        self.login('add', 'laptop', stdin=public('ecdsa-sha2-nistp256', 2, 65) + ' whatever its comment\n')
        self.assertEqual(self.store.read_text().splitlines(),
                         ['login_1=' + entry(public(fill=1), 'me@my-desk'), 'login_2=' + entry(public('ecdsa-sha2-nistp256', 2, 65), 'laptop')])
        self.assertEqual(len(self.may_log_in()), 2)
        self.reboot()
        self.assertEqual(self.may_log_in(), [public(fill=1) + ' me@my-desk', public('ecdsa-sha2-nistp256', 2, 65) + ' laptop'])
        self.assertFalse(list(self.store.parent.glob('*.part')))

    def test_a_key_without_a_comment_gets_a_name_and_two_cannot_share_one(self):
        self.boot()
        self.assertEqual(self.listed(self.login('add', stdin=public(fill=1) + '\n')), ['login key ' + public(fill=1)])
        refused = self.login('add', stdin=public(fill=2) + '\n', ok=False)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn('a key named key is in the list', refused.stderr)
        self.login('add', 'second', stdin=public(fill=2) + '\n')
        self.assertIn('login second-machine-in-the-lab ' + public(fill=3),
                      self.listed(self.login('add', stdin=public(fill=3) + ' Second Machine  (in the lab)\n')))
        self.login('drop', 'second-machine-in-the-lab')
        again = self.login('add', 'third', stdin=public(fill=2) + ' other comment\n', ok=False)
        self.assertIn('that key is in the list already, as second', again.stderr)
        self.assertEqual(len(self.may_log_in()), 2)

    def test_what_is_not_a_public_key_is_not_added(self):
        self.boot()
        for text in ('', 'hello\n', 'ssh-ed25519\n', 'ssh-ed25519 AAAA!!\n', 'ssh-dss ' + public(fill=1).split()[1] + '\n',
                     'ssh-rsa ' + public(fill=1).split()[1] + '\n', 'command="sh" ' + public(fill=1) + '\n',
                     '-----BEGIN OPENSSH PRIVATE KEY-----\n'):
            with self.subTest(text=text):
                self.assertNotEqual(self.login('add', stdin=text, ok=False).returncode, 0)
        for name in ('My Key', '-x', 'a:b', 'n' * 33, 'né'):
            with self.subTest(name=name):
                self.assertNotEqual(self.login('add', name, stdin=public(fill=1) + '\n', ok=False).returncode, 0)
        self.assertFalse(self.store.exists())
        self.assertEqual(self.may_log_in(), [])

    def test_the_list_holds_thirty_two_and_says_when_it_is_full(self):
        self.boot()
        (self.dir / 'durable/ssh').mkdir()
        self.store.write_text(''.join(f'login_{n}={entry(public(fill=n), f"key-{n}")}\n' for n in range(1, MOST)))
        self.login('add', 'the-last', stdin=public(fill=200) + '\n')
        full = self.login('add', 'one-more', stdin=public(fill=201) + '\n', ok=False)
        self.assertIn('the list is full (32 keys)', full.stderr)
        self.assertEqual(len(self.store.read_text().splitlines()), MOST)
        self.assertEqual(len(self.may_log_in()), MOST)

    def test_a_key_is_dropped_by_its_name_at_once_and_for_good(self):
        self.boot()
        for n, name in enumerate(('desk', 'laptop', 'bench'), 1):
            self.login('add', name, stdin=public(fill=n) + '\n')
        dropped = self.login('drop', 'laptop')
        self.assertEqual(self.listed(dropped), ['login desk ' + public(fill=1), 'login bench ' + public(fill=3)])
        self.assertEqual(self.store.read_text().splitlines(),
                         ['login_1=' + entry(public(fill=1), 'desk'), 'login_2=' + entry(public(fill=3), 'bench')], 'no gap is left')
        self.assertEqual(self.may_log_in(), [public(fill=1) + ' desk', public(fill=3) + ' bench'])
        self.assertIn('no key named laptop', self.login('drop', 'laptop', ok=False).stderr)
        self.assertNotEqual(self.login('drop', ok=False).returncode, 0)
        self.reboot()
        self.assertEqual(self.may_log_in(), [public(fill=1) + ' desk', public(fill=3) + ' bench'])

    def test_the_last_key_can_be_dropped_and_the_paperclip_key_is_not_in_the_list(self):
        slot = public(fill=9).replace(' ', ':')
        (self.dir / 'durable/ssh').mkdir()
        self.store.write_text('login_1=' + entry(public(fill=1), 'desk') + '\n')
        self.hand_over(entry(public(fill=1), 'desk'), slot='on w1700k.key=' + slot)
        self.boot()
        self.assertEqual(self.may_log_in(), [public(fill=1) + ' desk', public(fill=9) + ' paperclip'])
        self.assertEqual(self.listed(), ['login desk ' + public(fill=1)])
        self.assertIn('no key named paperclip', self.login('drop', 'paperclip', ok=False).stderr)
        self.assertEqual(self.listed(self.login('drop', 'desk')), [])
        self.assertEqual(self.may_log_in(), [public(fill=9) + ' paperclip'], 'the way in that a hand on the unit gives stays')
        self.assertEqual(self.store.read_text(), '')
        self.login('add', 'desk', stdin=public(fill=2) + '\n')
        self.assertEqual(self.may_log_in(), [public(fill=2) + ' desk', public(fill=9) + ' paperclip'])

    def test_storage_that_cannot_be_opened_changes_nothing(self):
        self.hand_over(entry(public(fill=1), 'desk'))
        self.boot()
        (self.dir / 'durable-busy').touch()
        self.assertNotEqual(self.login('add', 'more', stdin=public(fill=2) + '\n', ok=False).returncode, 0)
        self.assertNotEqual(self.login('drop', 'desk', ok=False).returncode, 0)
        self.assertEqual(self.may_log_in(), [public(fill=1) + ' desk'])

    def test_a_root_from_before_carries_the_key_built_into_it_across(self):
        # No start-up record: that root never ran `boot`. Its key is in the root's own file.
        (self.dir / 'lower-authorized_keys').write_text(f'# the installer\n{public(fill=1)} Me@Desk\n\n{public("ssh-rsa", 2, 300)}\n'
                                                        f'{public(fill=3)} me@desk\n')
        for _ in range(2):                      # and again, by the next update that asks
            kept = self.login('keep')
            self.assertEqual(self.listed(kept), ['login me@desk ' + public(fill=1), 'login key ' + public('ssh-rsa', 2, 300),
                                                 'login key-3 ' + public(fill=3)])
            self.assertEqual(self.store.read_text().splitlines(),
                             ['login_1=' + entry(public(fill=1), 'me@desk'), 'login_2=' + entry(public('ssh-rsa', 2, 300), 'key'),
                              'login_3=' + entry(public(fill=3), 'key-3')])
        self.assertFalse((self.dir / 'run/login').exists(), 'the running root is left as it is')
        self.assertFalse(self.authorized.exists())

    def test_a_root_from_before_with_no_key_or_a_unit_that_has_a_list_carries_nothing(self):
        self.assertEqual(self.listed(self.login('keep')), [])
        self.assertEqual(self.store.read_text(), '', 'an empty list, and a list all the same')
        (self.dir / 'lower-authorized_keys').write_text(public(fill=1) + ' late\n')
        self.assertEqual(self.listed(self.login('keep')), [], 'the list the unit has stands')
        self.store.write_text('login_1=' + entry(public(fill=5), 'mine') + '\n')
        self.assertEqual(self.listed(self.login('keep')), ['login mine ' + public(fill=5)])
        self.assertEqual(self.store.read_text(), 'login_1=' + entry(public(fill=5), 'mine') + '\n')

    def test_on_this_root_keeping_is_saying_the_list(self):
        self.hand_over(entry(public(fill=1), 'desk'))
        self.boot()
        (self.dir / 'lower-authorized_keys').write_text(public(fill=7) + ' stray\n')
        self.assertEqual(self.listed(self.login('keep')), ['login desk ' + public(fill=1)])
        self.assertEqual(self.durable_calls(), '')

    def test_before_start_up_and_anything_else(self):
        for words in (('list',), ('status',), ('drop', 'x')):
            self.assertIn('boot has not run', self.login(*words, ok=False).stderr)
        self.assertIn('boot has not run', self.login('add', stdin=public() + '\n', ok=False).stderr)
        self.assertEqual(self.login('nonsense', ok=False).returncode, 2)
        self.assertEqual(self.login(ok=False).returncode, 2)


if __name__ == '__main__':
    sys.exit(unittest.main())
