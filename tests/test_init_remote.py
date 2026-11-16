# SPDX-License-Identifier: MIT
"""init/flash --rootfs --ssh (init/initkit/remote.py) against a simulated unit: what it sends over
ssh and in which order, and what it makes of a unit that takes the new root, does not come back,
or comes back on the old one."""
import argparse
import hashlib
import io
import tarfile
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'init')]
from initkit import bundle, config, provision, remote, seal  # noqa: E402
from initkit.console import StepFailed  # noqa: E402

OLD = hashlib.sha256(b'the root that runs').hexdigest()


def proc_mtd(geometry=None):
    """/proc/mtd of a unit laid out as `geometry` (default: this tree's)."""
    geometry = geometry or config.partitions.GEOMETRY
    return 'dev:    size   erasesize  name\n' + ''.join(
        f'mtd{n}: {size:08x} 00020000 "{name}"\n' for n, (name, (_, size)) in enumerate(geometry.items()))


HOST_KEY_CALLS = ('sh -s -- keep', 'sh -s -- list', 'cat /proc/cmdline')


def host_key_answer(unit, command, data):
    """What a unit answers about its own keys, or None for another command. The programs are
    sent as this tree has them, and which one a call ran goes to `unit.key_calls`.
    `hostkey_kept`, `login_kept`: (status, output) of `w1700k-hostkey keep` and `w1700k-login
    keep`; `login_listed`: of `w1700k-login list`, which a root from before the list left the
    root cannot answer (the default); `hostkey_said`, `login_said`: what its loader says on the
    kernel command line, None for a loader from before."""
    if command in ('sh -s -- keep', 'sh -s -- list'):
        which = {remote.HOSTKEY.read_bytes(): 'hostkey', remote.LOGIN.read_bytes(): 'login'}[data]
        unit.__dict__.setdefault('key_calls', []).append((which, command.split()[-1]))
        if which == 'hostkey':
            return getattr(unit, 'hostkey_kept', (0, 'durable-open: /durable mounted from mtd6\n'
                                                     'hostkey ssh-ed25519 AAAAHOST\ndurable-close: /durable closed\n'))
        if command.endswith('list'):
            return getattr(unit, 'login_listed', (1, 'w1700k-login: no record of the list (w1700k-login boot has not run)\n'))
        return getattr(unit, 'login_kept', (0, 'durable-open: /durable mounted from mtd6\ndurable-close: /durable closed\n'
                                               'login installer ssh-ed25519 AAAALOGIN\n'))
    if command == 'cat /proc/cmdline':
        said, login = getattr(unit, 'hostkey_said', 'handed'), getattr(unit, 'login_said', 'handed')
        return 0, ('console=ttyS0,115200 ro w1700k.keyslot=empty' + (f' w1700k.hostkey={said}' if said else '')
                   + (f' w1700k.login={login}' if login else '') + '\n')
    return None


class Unit:
    """A unit as remote.Link reaches it. `takes`: the loader writes a staged root; `boots`: the
    new root comes up; a root that does not is undone when the operator power-cycles, which the
    simulation does after `patience` unanswered calls."""

    def __init__(self, loader='applies', takes=True, boots=True, storage='W1700K_STORAGE_READY\n', patience=20):
        self.address = '192.168.1.1'
        self.loader, self.takes, self.boots, self.storage, self.patience = loader, takes, boots, storage, patience
        self.running, self.boot = OLD, 'installed'
        self.staged = self.previous = self.tried = self.failed = ''
        self.files, self.calls, self.down, self.unanswered = {}, [], 0, 0
        self.reachable = True

    def call(self, command, data=None, timeout=120):
        if not self.reachable:
            return 255, ''
        if self.down:
            self.unanswered += 1
            if self.down == 'dead' and self.unanswered < self.patience:
                return 255, ''
            if self.down == 'dead':                 # the power cycle: the loader goes back
                self.running, self.tried, self.failed, self.down = self.previous, '', self.staged, 0
            elif self.unanswered > 3:
                self.down = 0
            if self.down:
                return 255, ''
        self.calls.append(command)
        answer = host_key_answer(self, command, data)
        if answer:
            return answer
        if command == '/usr/sbin/w1700k-keyslot status':
            keyslot = getattr(self, 'keyslot', None)
            return (0, keyslot) if keyslot else (127, 'sh: /usr/sbin/w1700k-keyslot: not found\n')
        if command == 'true':
            return 0, ''
        if command.startswith('cat > '):
            self.files[command.split()[2]] = data
            return 0, ''
        if command == 'reboot':
            self.reboot()
            return 255, ''
        if command == '/usr/sbin/verify-storage':
            return (0 if 'READY' in self.storage else 1), self.storage
        if command == 'cat /proc/mtd':
            return 0, proc_mtd(getattr(self, 'geometry', None))
        assert command.startswith('sh -s -- ') and data == remote.SCRIPT.read_bytes(), command
        verb, *arguments = command.split()[3:]
        if verb == 'status':
            return 0, ''.join(f'{k}={v}\n' for k, v in (
                ('running', self.running), ('boot', self.boot), ('loader', 'applies' if self.loader == 'applies'
                                                                 else 'serial-only'),
                ('staged', self.staged), ('previous', self.previous), ('tried', self.tried), ('failed', self.failed)))
        if verb == 'stage':
            path, digest = arguments
            moved = self.files.get(path + '.part')
            if moved is not None:
                self.files[path] = moved
            assert hashlib.sha256(self.files[path]).hexdigest() == digest
            self.staged, self.previous = digest, self.running
            return 0, 'system-update: staged\n'
        if verb == 'confirm':
            if self.running != self.staged:
                return 1, 'system-update: the staged root does not run\n'
            self.staged = self.previous = ''
            return 0, 'system-update: settled\n'
        if verb == 'cancel':
            self.staged = self.previous = ''
            return 0, 'system-update: nothing is staged\n'
        raise AssertionError(command)

    def reboot(self):
        self.down, self.unanswered = 'rebooting', 0
        if not self.staged:                         # settled: the loader forgets its note
            self.tried = self.failed = ''
        elif self.tried == self.staged:             # never confirmed: back
            self.running, self.tried, self.failed = self.previous, '', self.staged
        elif self.takes and self.failed != self.staged:
            self.running, self.tried = self.staged, self.staged
            if not self.boots:
                self.down = 'dead'


class Remote(unittest.TestCase):
    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.image = Path(work.name) / 'rootfs.squashfs'
        self.image.write_bytes(b'hsqs the new root' * 1000)
        self.new = hashlib.sha256(self.image.read_bytes()).hexdigest()
        self.settings = argparse.Namespace(device_ip='192.168.1.1', data_dir=Path(work.name))
        self.now = 0.0
        for patcher in (mock.patch.object(config, 'require_images'),
                        mock.patch.object(config, 'pick_unit', return_value='SERIAL'),
                        mock.patch.object(provision, 'provision', return_value=self.image),
                        mock.patch('builtins.print')):
            self.printed = patcher.start()
            self.addCleanup(patcher.stop)

    def run_update(self, unit, **options):
        def sleep(seconds):
            self.now += seconds
        return remote.run(self.settings, link=unit, clock=lambda: self.now, sleep=sleep, **options)

    def said(self):
        return ' '.join(str(call.args[0]) for call in self.printed.call_args_list if call.args)

    def verbs(self, unit):
        return [c.split()[3] if c.startswith('sh -s') else c.split()[0] for c in unit.calls
                if c not in ('true', 'cat /proc/mtd') + HOST_KEY_CALLS]

    def test_the_new_root_is_staged_written_by_the_loader_checked_and_confirmed(self):
        unit = Unit()
        self.assertEqual(self.run_update(unit), 0)
        self.assertEqual((unit.running, unit.staged), (self.new, ''))
        self.assertEqual(self.verbs(unit),
                         ['status', 'cat', 'stage', 'reboot', '/usr/sbin/verify-storage', 'status', 'confirm'],
                         'the storage check before anything opens durable storage again')
        self.assertIn('runs and is confirmed', self.said())
        unit.reboot()
        self.assertEqual((unit.running, unit.tried), (self.new, ''), 'and it stays')

    def test_the_units_host_key_is_kept_on_the_unit_before_a_root_without_one_is_staged(self):
        unit = Unit()
        self.assertEqual(self.run_update(unit), 0)
        calls = [c for c in unit.calls if c != 'true']
        self.assertLess(calls.index('sh -s -- keep'), calls.index('sh -s -- stage /work/system-update.squashfs ' + self.new))
        self.assertLess(calls.index('cat /proc/cmdline'), calls.index('sh -s -- stage /work/system-update.squashfs ' + self.new))

    def test_a_root_is_not_sent_to_a_unit_whose_key_could_not_be_kept(self):
        for kept in ((1, 'w1700k-hostkey: the host keys could not be written\n'),
                     (0, 'durable-open: /durable mounted from mtd6\ndurable-close: /durable closed\n')):
            unit = Unit()
            unit.hostkey_kept = kept
            with self.subTest(kept=kept), self.assertRaisesRegex(StepFailed, 'host key'):
                self.run_update(unit)
            self.assertEqual((unit.staged, unit.running), ('', OLD))
            self.assertNotIn('stage', self.verbs(unit))

    def test_a_root_alone_is_not_sent_under_a_loader_that_hands_no_host_key_over(self):
        unit = Unit()
        unit.hostkey_said = None                # a loader from before host keys left the root
        with self.assertRaisesRegex(StepFailed, 'does not hand the unit.s ssh host key to the system.*init/flash --ssh'):
            self.run_update(unit)
        self.assertEqual((unit.staged, unit.running), ('', OLD), 'it would come up as another unit, and be undone')
        self.assertNotIn('stage', self.verbs(unit))
        for said in ('handed', 'none'):
            unit = Unit()
            unit.hostkey_said = said
            self.assertEqual(self.run_update(unit), 0)

    def test_a_root_with_no_login_key_goes_to_a_unit_that_has_its_own_key(self):
        unit = Unit()
        unit.keyslot = 'slot=on\npersist=1\n'
        self.assertEqual(self.run_update(unit, no_login_key=True), 0)
        self.assertEqual(self.verbs(unit)[:3], ['status', '/usr/sbin/w1700k-keyslot', 'cat'], 'asked before anything is sent')
        self.assertNotIn(('login', 'keep'), unit.key_calls, 'the key built into the old root is not carried across')
        self.assertIn(('hostkey', 'keep'), unit.key_calls)
        self.assertEqual(unit.running, self.new)

    def test_with_no_login_key_a_unit_that_has_a_list_needs_no_paperclip_key(self):
        unit = Unit()
        unit.login_listed = (0, 'login desk ssh-ed25519 AAAADESK\n')
        self.assertEqual(self.run_update(unit, no_login_key=True), 0)
        self.assertNotIn('/usr/sbin/w1700k-keyslot', self.verbs(unit))
        self.assertNotIn(('login', 'keep'), unit.key_calls)

    def test_a_root_with_no_login_key_is_not_sent_where_it_would_lock_the_unit(self):
        for keyslot, why in (('slot=off\npersist=1\n', 'switched off'), ('slot=empty\npersist=1\n', 'not set'),
                             ('slot=on\npersist=0\n', 'loader does not keep one'), (None, 'unknown to its root')):
            with self.subTest(keyslot):
                unit = Unit()
                unit.keyslot = keyslot
                with self.assertRaisesRegex(StepFailed, f'no login key in its list.*no way in.*{why}.*init/key'):
                    self.run_update(unit, no_login_key=True)
                self.assertEqual(self.verbs(unit), ['status', '/usr/sbin/w1700k-keyslot'], 'nothing sent')
                self.assertEqual(unit.running, OLD)

    def test_by_default_an_old_roots_login_key_is_carried_into_the_units_list_before_anything_is_staged(self):
        unit = Unit()
        self.assertEqual(self.run_update(unit), 0)
        self.assertEqual(unit.key_calls, [('hostkey', 'keep'), ('login', 'keep')])
        calls = [c for c in unit.calls if c != 'true']
        self.assertLess(len(calls) - 1 - calls[::-1].index('sh -s -- keep'),
                        calls.index('sh -s -- stage /work/system-update.squashfs ' + self.new))
        self.assertNotIn('/usr/sbin/w1700k-keyslot', self.verbs(unit), 'it has a key in its list: its slot is not asked about')
        self.assertEqual(provision.provision.call_args.kwargs, {'address': '192.168.1.1'}, 'no key goes into a root')

    def test_a_unit_whose_list_would_be_empty_needs_its_paperclip_key(self):
        empty = (0, 'durable-open: /durable mounted from mtd6\ndurable-close: /durable closed\n')
        unit = Unit()
        unit.login_kept = empty
        with self.assertRaisesRegex(StepFailed, 'no login key in its list.*no way in.*init/key'):
            self.run_update(unit)
        self.assertEqual((unit.staged, unit.running), ('', OLD))
        unit = Unit()
        unit.login_kept, unit.keyslot = empty, 'slot=on\npersist=1\n'
        self.assertEqual(self.run_update(unit), 0)

    def test_a_root_is_not_sent_to_a_unit_whose_login_keys_could_not_be_kept(self):
        unit = Unit()
        unit.login_kept = (1, 'w1700k-login: the list could not be written\n')
        with self.assertRaisesRegex(StepFailed, 'login keys could not be kept'):
            self.run_update(unit)
        self.assertEqual((unit.staged, unit.running), ('', OLD))

    def test_a_root_alone_is_not_sent_under_a_loader_that_hands_no_login_keys_over(self):
        unit = Unit()
        unit.login_said = None                  # it knows of host keys, and not yet of the list
        with self.assertRaisesRegex(StepFailed, 'does not hand the unit.s login keys to the system.*init/flash --ssh'):
            self.run_update(unit)
        self.assertEqual((unit.staged, unit.running), ('', OLD), 'nobody could log in to confirm it')

    def test_a_root_that_already_runs_is_left_alone(self):
        unit = Unit()
        unit.running = self.new
        self.assertEqual(self.run_update(unit), 0)
        self.assertEqual(self.verbs(unit), ['status'])
        self.assertIn('already current', self.said())

    def test_a_loader_that_does_not_apply_updates_is_named_before_anything_is_sent(self):
        unit = Unit(loader='old')
        with self.assertRaisesRegex(StepFailed, 'init/flash --loader'):
            self.run_update(unit)
        self.assertEqual(self.verbs(unit), ['status'])

    def test_a_unit_that_does_not_answer(self):
        unit = Unit()
        unit.reachable = False
        with self.assertRaisesRegex(StepFailed, 'does not answer over ssh'):
            self.run_update(unit)

    def test_a_root_that_never_comes_up_is_undone_by_the_power_cycle_it_asks_for(self):
        unit = Unit(boots=False, patience=200)
        with self.assertRaisesRegex(StepFailed, 'previous root .* back, and it runs'):
            self.run_update(unit)
        self.assertIn('POWER-CYCLE THE UNIT NOW', self.said())
        self.assertEqual((unit.running, unit.staged), (OLD, ''), 'the old root runs, and nothing is left staged')

    def test_a_loader_that_wrote_nothing(self):
        unit = Unit(takes=False)
        with self.assertRaisesRegex(StepFailed, 'did not write the new root'):
            self.run_update(unit)
        self.assertEqual((unit.running, unit.staged), (OLD, ''))

    def test_a_new_root_whose_storage_check_fails_is_not_confirmed(self):
        unit = Unit(storage='W1700K_STORAGE_FAILED: ubi0 is not read-only\n')
        with self.assertRaisesRegex(StepFailed, 'storage check fails'):
            self.run_update(unit)
        self.assertEqual(unit.staged, self.new, 'left unconfirmed')
        unit.reboot()
        self.assertEqual(unit.running, OLD, 'so the next boot goes back')

    def test_a_run_that_was_interrupted_before_confirming_is_finished_by_the_next(self):
        unit = Unit()
        unit.running = unit.staged = unit.tried = self.new
        unit.previous = OLD
        self.assertEqual(self.run_update(unit), 0)
        self.assertEqual(self.verbs(unit), ['status', 'confirm'])
        self.assertEqual(unit.staged, '')

    def test_an_earlier_update_left_staged_is_cleared_first(self):
        unit = Unit()
        unit.staged, unit.previous, unit.failed = 'f' * 64, OLD, 'f' * 64
        self.assertEqual(self.run_update(unit), 0)
        self.assertEqual(self.verbs(unit)[:3], ['status', 'cancel', 'cat'])
        self.assertEqual(unit.running, self.new)



class LoaderUnit:
    """A unit as remote.Link reaches it, for its loader's update. `takes`: the first loader
    writes the staged second loader and starts it; `boots`: the system comes up under it; one
    that does not is removed by the first loader when the operator power-cycles."""

    def __init__(self, second='', takes=True, boots=True, storage='W1700K_STORAGE_READY\n', patience=20):
        self.address = '192.168.1.1'
        self.second, self.takes, self.boots, self.storage, self.patience = second, takes, boots, storage, patience
        self.staged = self.tried = self.booted = self.failed = ''
        self.files, self.calls, self.down, self.unanswered = {}, [], 0, 0

    def call(self, command, data=None, timeout=120):
        if self.down:
            self.unanswered += 1
            if self.down == 'dead' and self.unanswered < self.patience:
                return 255, ''
            if self.down == 'dead':                 # the power cycle: the first loader removes it
                self.second, self.tried, self.booted, self.failed, self.down = '', '', '', self.staged, 0
            elif self.unanswered > 3:
                self.down = 0
            if self.down:
                return 255, ''
        self.calls.append(command)
        answer = host_key_answer(self, command, data)
        if answer:
            return answer
        if command == '/usr/sbin/w1700k-keyslot status':
            keyslot = getattr(self, 'keyslot', None)
            return (0, keyslot) if keyslot else (127, 'sh: /usr/sbin/w1700k-keyslot: not found\n')
        if command == 'true':
            return 0, ''
        if command.startswith('cat > '):
            self.files[command.split()[2]] = data
            return 0, ''
        if command == 'reboot':
            self.reboot()
            return 255, ''
        if command == '/usr/sbin/verify-storage':
            return (0 if 'READY' in self.storage else 1), self.storage
        if command == 'cat /proc/mtd':
            return 0, proc_mtd(getattr(self, 'geometry', None))
        assert command.startswith('sh -s -- ') and data == remote.SCRIPT.read_bytes(), command
        verb, *arguments = command.split()[3:]
        if verb == 'status':
            return 0, ''.join(f'{k}={v}\n' for k, v in (
                ('running', OLD), ('boot', 'installed'), ('loader', 'applies'), ('staged', ''), ('previous', ''),
                ('tried', ''), ('failed', ''), ('second_loader', self.second), ('loader_staged', self.staged),
                ('loader_tried', self.tried), ('loader_booted', self.booted), ('loader_failed', self.failed)))
        if verb == 'stage-loader':
            path, digest = arguments
            moved = self.files.get(path + '.part')
            if moved is not None:
                self.files[path] = moved
            assert hashlib.sha256(self.files[path]).hexdigest() == digest
            self.staged = digest
            return 0, 'system-update: staged the loader\n'
        if verb == 'confirm':
            if not self.staged or self.booted != self.staged or self.second != self.staged:
                return 1, 'system-update: the staged loader did not start this boot\n'
            self.staged = ''
            return 0, 'system-update: settled\n'
        if verb == 'cancel':
            self.staged = ''
            return 0, 'system-update: nothing is staged\n'
        raise AssertionError(command)

    def reboot(self):
        self.down, self.unanswered = 'rebooting', 0
        if not self.staged:                         # settled: the notes are forgotten
            self.tried = self.booted = self.failed = ''
        elif self.tried == self.staged:             # never confirmed: removed
            self.second, self.tried, self.booted, self.failed = '', '', '', self.staged
        elif self.takes and self.failed != self.staged:
            self.second, self.tried = self.staged, self.staged
            if self.boots:
                self.booted = self.staged
            else:
                self.down = 'dead'


class RemoteLoader(unittest.TestCase):
    """init/flash --loader --ssh: the second loader, delivered, started and confirmed."""

    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.image = Path(work.name) / 'w1700k-loader-b.itb'
        self.image.write_bytes(b'\xd0\x0d\xfe\xed a second loader' * 500)
        self.new = hashlib.sha256(self.image.read_bytes()).hexdigest()
        self.settings = argparse.Namespace(device_ip='192.168.1.1', data_dir=Path(work.name))
        self.now = 0.0
        for patcher in (mock.patch.object(config, 'require_images'),
                        mock.patch.object(config, 'pick_unit', return_value='SERIAL'),
                        mock.patch.object(config, 'LOADER_B', self.image),
                        mock.patch('builtins.print')):
            self.printed = patcher.start()
            self.addCleanup(patcher.stop)

    def run_update(self, unit):
        def sleep(seconds):
            self.now += seconds
        return remote.run_loader(self.settings, link=unit, clock=lambda: self.now, sleep=sleep)

    def said(self):
        return ' '.join(str(call.args[0]) for call in self.printed.call_args_list if call.args)

    def verbs(self, unit):
        return [c.split()[3] if c.startswith('sh -s') else c.split()[0] for c in unit.calls
                if c not in ('true', 'cat /proc/mtd') + HOST_KEY_CALLS]

    def test_the_new_loader_is_staged_started_checked_and_confirmed(self):
        unit = LoaderUnit()
        self.assertEqual(self.run_update(unit), 0)
        self.assertEqual((unit.second, unit.staged), (self.new, ''))
        self.assertEqual(self.verbs(unit), ['status', 'cat', 'stage-loader', 'reboot', '/usr/sbin/verify-storage',
                                            'status', 'confirm'])
        self.assertIn(f'loader {self.new[:12]} runs and is confirmed', self.said())
        unit.reboot()
        self.assertEqual((unit.second, unit.tried), (self.new, ''), 'and it stays')

    def test_a_loader_already_in_place_is_left_alone(self):
        unit = LoaderUnit(second=self.new)
        self.assertEqual(self.run_update(unit), 0)
        self.assertEqual(self.verbs(unit), ['status'])
        self.assertIn('already current', self.said())

    def test_a_unit_whose_loader_starts_no_second_one_is_sent_nothing(self):
        unit = LoaderUnit(second='unsupported')
        with self.assertRaisesRegex(StepFailed, 'starts no second loader.*serial console'):
            self.run_update(unit)
        self.assertEqual(self.verbs(unit), ['status'])

    def test_a_loader_under_which_the_system_does_not_come_up_is_removed(self):
        unit = LoaderUnit(boots=False, patience=200)
        with self.assertRaisesRegex(StepFailed, 'not kept: the first loader has removed it'):
            self.run_update(unit)
        self.assertIn('POWER-CYCLE THE UNIT NOW', self.said())
        self.assertEqual((unit.second, unit.staged), ('', ''), 'removed, and the request cleared')

    def test_a_loader_the_first_one_did_not_start_is_reported(self):
        unit = LoaderUnit(takes=False)
        with self.assertRaisesRegex(StepFailed, 'did not start; the unit runs on what it had'):
            self.run_update(unit)
        self.assertEqual(unit.staged, '')

    def test_a_loader_is_not_confirmed_over_a_failed_storage_check(self):
        unit = LoaderUnit(storage='W1700K_STORAGE_FAILED\n')
        with self.assertRaisesRegex(StepFailed, 'storage check fails; it is left unconfirmed'):
            self.run_update(unit)
        self.assertEqual(unit.staged, self.new, 'left for the next reboot to remove')
        unit.reboot()
        self.assertEqual((unit.second, unit.failed), ('', self.new))

    def test_a_run_that_did_not_get_to_confirm_is_finished_by_the_next(self):
        unit = LoaderUnit(second=self.new)
        unit.staged = unit.tried = unit.booted = self.new
        self.assertEqual(self.run_update(unit), 0)
        self.assertEqual(self.verbs(unit), ['status', 'confirm'])



class JointUnit:
    """A unit that takes a second loader and a root in one reboot. `loader_takes`, `root_takes`:
    its loaders write and start what is staged."""

    def __init__(self, loader_takes=True, root_takes=True, geometry=None):
        self.address, self.geometry = '192.168.1.1', geometry
        self.loader_takes, self.root_takes = loader_takes, root_takes
        self.running, self.second = OLD, ''
        self.staged = self.previous = self.tried = self.failed = ''
        self.lstaged = self.ltried = self.lbooted = self.lfailed = ''
        self.files, self.calls, self.down, self.unanswered = {}, [], 0, 0

    def call(self, command, data=None, timeout=120):
        if self.down:
            self.unanswered += 1
            if self.unanswered > 3:
                self.down = 0
            else:
                return 255, ''
        self.calls.append(command)
        answer = host_key_answer(self, command, data)
        if answer:
            return answer
        if command == '/usr/sbin/w1700k-keyslot status':
            keyslot = getattr(self, 'keyslot', None)
            return (0, keyslot) if keyslot else (127, 'sh: /usr/sbin/w1700k-keyslot: not found\n')
        if command == 'true':
            return 0, ''
        if command == 'cat /proc/mtd':
            return 0, proc_mtd(self.geometry)
        if command.startswith('cat > '):
            self.files[command.split()[2]] = data
            return 0, ''
        if command == 'reboot':
            self.reboot()
            return 255, ''
        if command == '/usr/sbin/verify-storage':
            return 0, 'W1700K_STORAGE_READY\n'
        assert command.startswith('sh -s -- ') and data == remote.SCRIPT.read_bytes(), command
        verb, *arguments = command.split()[3:]
        if verb == 'status':
            return 0, ''.join(f'{k}={v}\n' for k, v in (
                ('running', self.running), ('boot', 'installed'), ('loader', 'applies'), ('staged', self.staged),
                ('previous', self.previous), ('tried', self.tried), ('failed', self.failed),
                ('second_loader', self.second), ('loader_staged', self.lstaged), ('loader_tried', self.ltried),
                ('loader_booted', self.lbooted), ('loader_failed', self.lfailed)))
        if verb in ('stage', 'stage-loader'):
            path, digest = arguments
            self.files[path] = self.files.get(path + '.part', self.files.get(path))
            assert hashlib.sha256(self.files[path]).hexdigest() == digest
            if verb == 'stage':
                self.staged, self.previous = digest, self.running
            else:
                self.lstaged = digest
            return 0, 'system-update: staged\n'
        if verb == 'confirm':
            if (self.staged and self.running != self.staged) or \
                    (self.lstaged and (self.lbooted != self.lstaged or self.second != self.lstaged)):
                return 1, 'system-update: not what was staged\n'
            self.staged = self.previous = self.lstaged = ''
            return 0, 'system-update: settled\n'
        if verb == 'cancel':
            self.staged = self.previous = self.lstaged = ''
            return 0, 'system-update: nothing is staged\n'
        raise AssertionError(command)

    def reboot(self):
        self.down, self.unanswered = 'rebooting', 0
        self.lbooted = ''
        if self.lstaged and self.ltried == self.lstaged:        # never confirmed: removed
            self.second, self.ltried, self.lfailed = '', '', self.lstaged
        elif self.lstaged and self.loader_takes and self.lfailed != self.lstaged:
            self.second = self.ltried = self.lbooted = self.lstaged
        if self.staged and self.tried == self.staged:           # never confirmed: back
            self.running, self.tried, self.failed = self.previous, '', self.staged
        elif self.staged and self.root_takes and self.failed != self.staged:
            self.running = self.tried = self.staged
        if not self.staged and not self.lstaged:                # settled
            self.tried = self.failed = self.ltried = self.lfailed = ''


class RemoteJoint(unittest.TestCase):
    """init/flash --ssh and --bundle: the loader and the root together, with one reboot."""

    def setUp(self):
        work = tempfile.TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.work = Path(work.name)
        self.root_image = self.work / 'rootfs.squashfs'
        self.root_image.write_bytes(b'hsqs the new root' * 1000)
        self.loader_image = self.work / 'w1700k-loader-b.itb'
        self.loader_image.write_bytes(b'\xd0\x0d\xfe\xed a second loader' * 500)
        self.root = hashlib.sha256(self.root_image.read_bytes()).hexdigest()
        self.loader = hashlib.sha256(self.loader_image.read_bytes()).hexdigest()
        self.settings = argparse.Namespace(device_ip='192.168.1.1', data_dir=self.work)
        self.now = 0.0
        self.provisioned = []

        self.network_conf = False               # the unit has network settings of its own

        def provisioned(directory, address=None, generic=None):
            """As provision.provision: the root as built, or one made for the unit from it."""
            self.provisioned.append(Path(generic).read_bytes() if generic else None)
            if self.network_conf:
                made = self.work / 'made-for-the-unit.squashfs'
                made.write_bytes(b'hsqs a root with the unit\'s network settings' * 500)
                return made
            return generic or self.root_image
        for patcher in (mock.patch.object(config, 'require_images'),
                        mock.patch.object(config, 'pick_unit', return_value='SERIAL'),
                        mock.patch.object(config, 'LOADER_B', self.loader_image),
                        mock.patch.object(provision, 'provision', side_effect=provisioned),
                        mock.patch('builtins.print')):
            self.printed = patcher.start()
            self.addCleanup(patcher.stop)

    def run_update(self, unit, bundle_path=None, **options):
        def sleep(seconds):
            self.now += seconds
        return remote.run_joint(self.settings, bundle_path=bundle_path, link=unit, clock=lambda: self.now,
                                sleep=sleep, **options)

    def said(self):
        return ' '.join(str(call.args[0]) for call in self.printed.call_args_list if call.args)

    def verbs(self, unit):
        return [c.split()[3] if c.startswith('sh -s') else c.split()[0] for c in unit.calls
                if c not in ('true', 'cat /proc/mtd') + HOST_KEY_CALLS]

    def test_both_are_staged_and_one_reboot_brings_up_both(self):
        unit = JointUnit()
        self.assertEqual(self.run_update(unit), 0)
        self.assertEqual((unit.running, unit.second), (self.root, self.loader))
        self.assertEqual(self.verbs(unit), ['status', 'cat', 'stage-loader', 'cat', 'stage', 'reboot',
                                            '/usr/sbin/verify-storage', 'status', 'confirm'])
        self.assertEqual((unit.staged, unit.lstaged), ('', ''))
        self.assertIn(f'loader {self.loader[:12]} and root {self.root[:12]} run and are confirmed', self.said())
        self.assertEqual(self.provisioned, [None], "this build's root")

    def test_a_root_goes_with_the_loader_that_will_hand_its_host_key_over(self):
        unit = JointUnit()
        unit.hostkey_said = None                # the loader it runs now knows nothing of host keys
        self.assertEqual(self.run_update(unit), 0)
        calls = [c for c in unit.calls if c != 'true']
        self.assertLess(calls.index('sh -s -- keep'), calls.index('cat > /work/system-update.loader.part && mv '
                                                                  '/work/system-update.loader.part /work/system-update.loader'),
                        'the key is in durable storage before anything is staged')
        self.assertEqual((unit.running, unit.second), (self.root, self.loader))

    def test_a_root_without_its_loader_needs_one_that_hands_the_key_over(self):
        unit = JointUnit()
        unit.second, unit.lbooted = self.loader, self.loader      # the loader is this build's already,
        unit.hostkey_said = None                                    # yet says nothing: it cannot be
        with self.assertRaisesRegex(StepFailed, 'does not hand'):
            self.run_update(unit)
        self.assertEqual((unit.staged, unit.lstaged, unit.running), ('', '', OLD))

    def test_a_loader_alone_asks_nothing_of_host_keys(self):
        unit = JointUnit()
        unit.running = self.root
        unit.hostkey_kept = (1, 'must not be asked\n')
        self.assertEqual(self.run_update(unit), 0)
        self.assertNotIn('sh -s -- keep', unit.calls)

    def test_both_with_no_login_key_only_where_the_unit_has_its_own(self):
        unit = JointUnit()
        with self.assertRaisesRegex(StepFailed, 'no way in'):
            self.run_update(unit, no_login_key=True)
        self.assertEqual((unit.staged, unit.lstaged, unit.running), ('', '', OLD), 'neither part was sent')
        unit = JointUnit()
        unit.keyslot = 'slot=on\npersist=1\n'
        self.assertEqual(self.run_update(unit, no_login_key=True), 0)
        self.assertNotIn(('login', 'keep'), unit.key_calls)
        self.assertEqual((unit.running, unit.second), (self.root, self.loader))

    def test_an_archive_brings_the_same_two_files(self):
        archive = self.work / 'w1700k-update.tar'
        generic = b'hsqs the root as built, without keys'
        bundle.write(archive, self.loader_image.read_bytes(), generic, config.partitions.GEOMETRY)
        unit = JointUnit()
        self.assertEqual(self.run_update(unit, archive), 0)
        self.assertEqual(self.provisioned, [generic])
        self.assertEqual((unit.running, unit.second), (hashlib.sha256(generic).hexdigest(), self.loader),
                         "the archive's root goes to the unit as it is")
        self.assertEqual(self.verbs(unit).count('reboot'), 1)

    def test_an_archive_for_another_layout_is_not_sent(self):
        archive = self.work / 'w1700k-update.tar'
        other = dict(config.partitions.GEOMETRY, system=(0x800000, 0x2200000))
        bundle.write(archive, self.loader_image.read_bytes(), b'hsqs', other)
        unit = JointUnit()
        with self.assertRaisesRegex(StepFailed, 'not laid out as these images expect \\(system\\).*init/install --force'):
            self.run_update(unit, archive)
        self.assertEqual(self.verbs(unit), ['status'])

    def test_a_unit_installed_under_an_older_layout_is_not_sent_this_build(self):
        older = {name: span for name, span in config.partitions.GEOMETRY.items() if name != 'loader-b'}
        older.update(loader=(0x600000, 0x200000), system=(0x800000, 0x2200000))
        unit = JointUnit(geometry=older)
        with self.assertRaisesRegex(StepFailed, 'not laid out as these images expect'):
            self.run_update(unit)
        self.assertEqual(self.verbs(unit), ['status'])

    def test_an_archive_that_does_not_hold_together_is_refused(self):
        archive = self.work / 'w1700k-update.tar'
        bundle.write(archive, self.loader_image.read_bytes(), b'hsqs', config.partitions.GEOMETRY)
        data = bytearray(archive.read_bytes())
        at = data.index(b'a second loader')
        data[at] ^= 1
        archive.write_bytes(bytes(data))
        unit = JointUnit()
        with self.assertRaisesRegex(StepFailed, 'is not the file its manifest lists'):
            self.run_update(unit, archive)
        (self.work / 'other.tar').write_bytes(b'not an archive')
        with self.assertRaisesRegex(StepFailed, 'cannot be read as an update archive'):
            self.run_update(unit, self.work / 'other.tar')
        self.assertEqual(unit.calls, [])

    def test_only_what_differs_is_sent(self):
        unit = JointUnit()
        unit.running = self.root
        self.assertEqual(self.run_update(unit), 0)
        self.assertEqual(self.verbs(unit), ['status', 'cat', 'stage-loader', 'reboot', '/usr/sbin/verify-storage',
                                            'status', 'confirm'])
        self.assertIn('rootfs: already current', self.said())
        unit.calls.clear()
        self.assertEqual(self.run_update(unit), 0)
        self.assertEqual(self.verbs(unit), ['status'], 'nothing left to do')

    def test_a_part_that_did_not_take_leaves_nothing_confirmed(self):
        unit = JointUnit(root_takes=False)
        with self.assertRaisesRegex(StepFailed, 'the new root does not run.*Nothing was confirmed'):
            self.run_update(unit)
        self.assertEqual((unit.staged, unit.lstaged), ('', ''), 'the request is cleared')
        unit = JointUnit(loader_takes=False)
        with self.assertRaisesRegex(StepFailed, 'the new loader did not start'):
            self.run_update(unit)


def keys_list(stamp, *rows):
    """A list of test keys: `rows` are (key number, scope, name); `stamp` is its (epoch,
    generation), or the generation alone, in epoch 1."""
    stamp = stamp if isinstance(stamp, tuple) else (1, stamp)
    return seal.parse_list(seal.format_list(stamp, [(seal.signer(bytes((number,)) * 32)[0], scope, name)
                                                    for number, scope, name in rows]))


USUAL = ((5, 'root', 'the-root'), (6, 'keys', 'the-keys'), (1, 'release', 'primary'))


class ReleaseUnit(JointUnit):
    """A keyed unit: system-update's rules for its list of keys and for staging, as the script
    has them (tests/test_release.py runs the script itself)."""

    def __init__(self, held, floor=0, kind=None, **options):
        super().__init__(**options)
        self.held, self.floor, self.settled = held, floor, ''
        self.kind = kind or ('keyed' if held else 'unkeyed')
        self.verified = self.noted = None
        self.flags = {}

    def call(self, command, data=None, timeout=120):
        if not command.startswith('sh -s -- ') or self.down:
            return super().call(command, data, timeout)
        verb, *arguments = command.split()[3:]
        lost = 'system-update: this unit was given a list of keys and holds none that reads\n'
        if verb == 'status':
            code, text = super().call(command, data, timeout)
            return code, text + (f'keys={self.kind}\nkey_list={"good" if self.held else "none"}\n'
                                 f'key_generation={self.held.label if self.held else ""}\n'
                                 f'release_keys={len(self.held.release_keys()) if self.held else 0}\n'
                                 f'release={self.floor}\nrelease_manifest={self.settled}\n')
        if verb == 'keys':
            self.calls.append(command)
            return (0, self.held.text.decode()) if self.held else (1, 'system-update: this unit holds no list\n')
        if verb == 'rotate':
            self.calls.append(command)
            if self.kind != 'keyed':
                return 1, lost
            try:
                self.held, _ = seal.rotated(self.held, self.files[arguments[0]])
            except seal.Refused as error:
                return 1, f'w1700k-release: {error}\nsystem-update: not a list this unit takes\n'
            return 0, f'system-update: the list of keys is now generation={self.held.label}\n'
        if verb == 'release':
            self.calls.append(command)
            if self.kind != 'keyed':
                return 1, lost
            try:
                number, body, _ = seal.unseal(self.files[arguments[0]], self.held.release_keys())
            except seal.Refused:
                return 1, 'system-update: not a release this unit takes\n'
            if number < self.floor:
                return 1, f'w1700k-release: release {number} is older than release {self.floor}\n'
            self.verified = (number, body.decode())
            return 0, f'system-update: release {number} verified\n'
        if verb in ('stage', 'stage-loader') and self.kind != 'unkeyed':
            path, digest, *flags = arguments
            self.flags[verb] = flags
            listed = self.verified and f'"{digest}"' in self.verified[1]
            if not (flags == ['--unsigned'] or (self.kind == 'keyed' and not flags and listed)):
                self.calls.append(command)
                return 1, lost if self.kind == 'lost' else 'system-update: this unit takes releases: verify one first\n'
            if flags != ['--unsigned'] and self.verified:
                self.noted, self.noted_manifest = self.verified
            return super().call(' '.join(command.split()[:6]), data, timeout)
        code, text = super().call(command, data, timeout)
        if verb == 'confirm' and code == 0 and self.noted:
            if self.noted > self.floor:
                self.floor, self.settled = self.noted, hashlib.sha256(self.noted_manifest.encode()).hexdigest()
        if verb in ('confirm', 'cancel'):
            self.noted = None
        return code, text

    def reboot(self):
        super().reboot()
        self.verified = None                # /run does not outlive a reboot


class Releases(RemoteJoint):
    """A keyed unit takes over ssh what a release key of its list sealed, and nothing else
    without the owner's word; and its list moves on with the rotations a release carries."""

    def setUp(self):
        super().setUp()
        try:
            self.primary, self.sign = seal.signer(bytes((1,)) * 32)
            self.stranger, self.sign_stranger = seal.signer(bytes((3,)) * 32)
            self.signers = {number: seal.signer(bytes((number,)) * 32)[1] for number in (1, 3, 5, 6, 8)}
        except seal.Refused as error:
            self.skipTest(str(error))
        self.held = keys_list(1, *USUAL)
        self.plain = self.work / 'w1700k-update.tar'
        bundle.write(self.plain, self.loader_image.read_bytes(), self.root_image.read_bytes(),
                     config.partitions.GEOMETRY)

    def release(self, number, sign=None, carried=()):
        path = self.work / f'w1700k-release-{number}.tar'
        path.unlink(missing_ok=True)
        bundle.sign(self.plain, path, number, sign or self.sign, carried=carried)
        return path

    def turn(self, keys, by):
        return seal.seal_list(keys.text, self.signers[by])

    def test_a_release_is_checked_here_then_by_the_unit_and_then_sent(self):
        unit = ReleaseUnit(self.held)
        self.assertEqual(self.run_update(unit, self.release(4)), 0)
        self.assertEqual(self.verbs(unit), ['status', 'keys', 'cat', 'release', 'cat', 'stage-loader', 'cat',
                                            'stage', 'reboot', '/usr/sbin/verify-storage', 'status', 'confirm'])
        self.assertEqual(unit.flags, {'stage-loader': [], 'stage': []},
                         'both are in the manifest, and the unit checks both')
        self.assertEqual((unit.running, unit.second, unit.floor), (self.root, self.loader, 4))
        self.assertIn('release 4, sealed by ' + seal.fingerprint(self.primary), self.said())

    def test_a_root_made_for_a_unit_with_network_settings_of_its_own_is_the_owners_build(self):
        self.network_conf = True
        unit = ReleaseUnit(self.held)
        with self.assertRaisesRegex(StepFailed, 'network.conf.*in no release.*--unsigned'):
            self.run_update(unit, self.release(4))
        self.assertEqual((unit.staged, unit.lstaged, unit.running), ('', '', OLD), 'nothing was sent')
        self.assertEqual(self.run_update(unit, self.release(4), unsigned=True), 0)
        self.assertEqual(unit.flags, {'stage-loader': ['--unsigned'], 'stage': ['--unsigned']})
        self.assertNotEqual(unit.running, self.root)
        self.assertEqual(unit.floor, 0, 'and it is no release to the unit')

    def test_a_release_whose_root_was_changed_on_its_way_is_refused_by_the_unit_itself(self):
        """What the test on a unit showed staged, before roots went to units untouched: a root
        that is not the release's, offered as the release's. The host tool would not send it; a
        dishonest one that does is refused."""
        unit = ReleaseUnit(self.held)
        manifest, files, sealed = bundle.read_release(self.release(4))
        unit.call(f'cat > {remote.RELEASE_STAGING}', data=sealed)
        self.assertEqual(remote.tool(unit, 'release', remote.RELEASE_STAGING)[0], 0)
        changed = files[bundle.ROOT] + b'one more byte'
        unit.call(f'cat > {remote.STAGING}', data=changed)
        code, said = remote.tool(unit, 'stage', remote.STAGING, hashlib.sha256(changed).hexdigest())
        self.assertNotEqual(code, 0)
        self.assertIn('takes releases', said)
        code, _ = remote.tool(unit, 'stage', remote.STAGING, hashlib.sha256(changed).hexdigest(), '--from-release')
        self.assertNotEqual(code, 0, 'and there is no word of the host\'s that makes it one')

    def test_an_unsigned_archive_or_build_is_not_sent_without_the_owners_word(self):
        for archive in (self.plain, None):
            with self.subTest(archive=archive):
                unit = ReleaseUnit(self.held)
                with self.assertRaisesRegex(StepFailed, 'takes only releases sealed by a release key of its '
                                                        'list.*--unsigned'):
                    self.run_update(unit, archive)
                self.assertEqual(self.verbs(unit), ['status', 'keys'], 'its keys were read; nothing was sent')
                self.assertEqual(self.run_update(unit, archive, unsigned=True), 0)
                self.assertEqual(unit.flags, {'stage-loader': ['--unsigned'], 'stage': ['--unsigned']})
                self.assertEqual(unit.floor, 0, 'a build of the owner\'s moves no floor')
                self.assertIn('as a build of your own', self.said())

    def test_a_release_sealed_by_a_stranger_or_an_authority_is_refused_before_anything_is_sent(self):
        for by in (3, 5, 6):
            with self.subTest(by=by):
                unit = ReleaseUnit(self.held)
                with self.assertRaisesRegex(StepFailed, "not a release this unit takes.*none of the release keys'"):
                    self.run_update(unit, self.release(4, self.signers[by]))
                self.assertEqual(self.verbs(unit), ['status', 'keys'])
                self.assertEqual(unit.files, {})

    def test_a_release_older_than_the_units_is_refused_before_anything_is_sent(self):
        unit = ReleaseUnit(self.held, floor=9)
        with self.assertRaisesRegex(StepFailed, 'release 4; this unit has settled on release 9'):
            self.run_update(unit, self.release(4))
        self.assertEqual(unit.files, {})
        self.assertEqual(self.run_update(unit, self.release(9)), 0, 'the same release again is no step back')

    def test_an_archive_the_unit_would_refuse_is_refused_even_when_it_has_all_of_it(self):
        unit = ReleaseUnit(self.held, floor=9)
        unit.running, unit.second = self.root, self.loader
        for archive, why in ((self.release(4), 'settled on release 9'),
                             (self.release(12, self.sign_stranger), 'none of the release keys'),
                             (self.plain, 'takes only releases')):
            with self.subTest(why), self.assertRaisesRegex(StepFailed, why):
                self.run_update(unit, archive)
        self.assertEqual(self.run_update(unit, self.release(12)), 0)
        self.assertIn('already current', self.said())

    def test_the_units_own_refusal_stops_the_update_too(self):
        unit = ReleaseUnit(self.held)
        archive = self.release(4)
        # The host believes a key the unit does not act on: the unit's word is the last.
        with mock.patch.object(seal, 'unseal', side_effect=[(4, b'', self.primary), seal.Refused('no')]):
            with self.assertRaisesRegex(StepFailed, 'the unit does not take this release'):
                self.run_update(unit, archive)
        self.assertEqual((unit.staged, unit.lstaged), ('', ''))

    def test_an_unkeyed_unit_takes_a_release_as_any_archive_and_is_told_nothing_checks_it(self):
        chain = [self.turn(self.held, 5)]
        for unit in (JointUnit(), ReleaseUnit(None)):
            with self.subTest(type(unit).__name__):
                self.assertEqual(self.run_update(unit, self.release(4, self.sign_stranger, chain)), 0)
                self.assertIn('holds no list of keys: nothing checks the seal', self.said())
                self.assertFalse({'release', 'rotate', 'keys'} & set(self.verbs(unit)),
                                 'and it is given no list: that is done at the bench')

    def test_a_keyed_unit_that_lost_its_list_takes_nothing_sealed_and_says_so_loudly(self):
        unit = ReleaseUnit(None, kind='lost')
        with self.assertRaisesRegex(StepFailed, 'WAS GIVEN A LIST OF KEYS AND HOLDS NONE THAT READS.*'
                                                'at the bench.*--unsigned'):
            self.run_update(unit, self.release(4, carried=[self.turn(self.held, 5)]))
        self.assertEqual(self.verbs(unit), ['status'], 'nothing was sent, and no list either')
        self.assertEqual(self.run_update(unit, self.plain, unsigned=True), 0)
        self.assertIn('HOLDS NONE THAT READS', self.said())
        self.assertEqual(unit.flags, {'stage-loader': ['--unsigned'], 'stage': ['--unsigned']})

    def test_the_rotations_a_release_carries_reach_the_unit_first_and_the_release_is_judged_by_them(self):
        """The release key was replaced: the unit learns that from the release itself."""
        second = keys_list(2, USUAL[0], USUAL[1], (3, 'release', 'second'))
        third = keys_list((2, 1), USUAL[0], (8, 'keys', 'new-keys'), (3, 'release', 'second'))
        chain = [self.turn(self.held, 5), self.turn(second, 6), self.turn(third, 5)]
        unit = ReleaseUnit(self.held)
        self.assertEqual(self.run_update(unit, self.release(4, self.sign_stranger, chain)), 0)
        self.assertEqual(unit.held.text, third.text)
        self.assertEqual(self.verbs(unit)[:10], ['status', 'keys', 'cat', 'rotate', 'cat', 'rotate', 'status',
                                                 'keys', 'cat', 'release'],
                         'the first list is the one it holds and is not sent again')
        self.assertIn('keys: list 1.2, sealed by the-keys (keys', self.said())
        self.assertIn('keys: list 2.1, sealed by the-root (root', self.said())
        # The old release key seals nothing for it now, whatever the archive carries.
        with self.assertRaisesRegex(StepFailed, "none of the release keys'"):
            self.run_update(unit, self.release(5, carried=chain))
        # A unit that already holds the last list is sent none.
        self.assertEqual(self.run_update(unit, self.release(5, self.sign_stranger, chain)), 0)
        self.assertNotIn('rotate', self.verbs(unit)[-12:])

    def test_rotations_reach_a_unit_that_already_has_everything_else(self):
        second = keys_list(2, USUAL[0], USUAL[1], (3, 'release', 'second'))
        unit = ReleaseUnit(self.held)
        unit.running, unit.second = self.root, self.loader
        self.assertEqual(self.run_update(unit, self.release(4, self.sign_stranger,
                                                            [self.turn(self.held, 5), self.turn(second, 6)])), 0)
        self.assertIn('already current', self.said())
        self.assertEqual(unit.held.text, second.text)

    def test_a_rotation_the_unit_would_refuse_is_said_and_never_sent_and_stops_nothing_else(self):
        second = keys_list(2, USUAL[0], USUAL[1], (3, 'release', 'second'))
        for name, chain, why in (
                ('sealed by a release key', [self.turn(keys_list(2, *USUAL[:2], (3, 'release', 'second')), 1)],
                 'not sealed by a root or keys key'),
                ('a keys key changing the root', [self.turn(keys_list(2, (8, 'root', 'new-root'), *USUAL[1:]), 6)],
                 'stays in epoch 1'),
                ('another list of the generation held', [self.turn(keys_list(1, *USUAL[:2]), 5)],
                 'ANOTHER list 1.1'),
                ('an epoch a keys key starts', [self.turn(keys_list((2, 1), *USUAL), 6)],
                 'only a root key of the list held starts one')):
            with self.subTest(name):
                unit = ReleaseUnit(self.held)
                self.assertEqual(self.run_update(unit, self.release(4, carried=chain)), 0,
                                 'the release is one its own list takes')
                self.assertRegex(self.said(), 'KEYS: a rotation with this update is NOT one this unit takes.*' + why)
                self.assertNotIn('rotate', self.verbs(unit))
                self.assertEqual(unit.held.text, self.held.text)
        # One it does not take does not stand before one it does.
        unit = ReleaseUnit(self.held)
        chain = [self.turn(keys_list(1, *USUAL[:2]), 5), self.turn(second, 6)]
        self.assertEqual(self.run_update(unit, self.release(4, self.sign_stranger, chain)), 0)
        self.assertEqual(unit.held.text, second.text)

    def test_a_release_names_the_rotations_it_carries_and_is_not_itself_without_them(self):
        second = keys_list(2, USUAL[0], USUAL[1], (3, 'release', 'second'))
        chain = [self.turn(self.held, 5), self.turn(second, 6)]
        release = self.release(4, self.sign_stranger, chain)
        manifest = bundle.read_release(release)[0]
        self.assertEqual(manifest['rotations'], {'1.1': hashlib.sha256(chain[0]).hexdigest(),
                                                 '1.2': hashlib.sha256(chain[1]).hexdigest()})

        def remade(name, keep, also=()):
            with tarfile.open(release) as source, tarfile.open(self.work / name, 'w') as target:
                for member in source.getmembers():
                    if keep(member.name):
                        target.addfile(member, source.extractfile(member))
                for member_name, data in also:
                    info = tarfile.TarInfo(member_name)
                    info.size = len(data)
                    target.addfile(info, io.BytesIO(data))
            return self.work / name
        third = self.turn(keys_list(3, USUAL[0], USUAL[1], (1, 'release', 'primary')), 6)
        for name, archive in (('one taken away', remade('less.tar', lambda member: member != 'keys/1.2.wms2')),
                              ('all taken away', remade('none.tar', lambda member: not member.startswith('keys/'))),
                              ('one added', remade('more.tar', lambda member: True, [('keys/1.3.wms2', third)])),
                              ('one changed', remade('other.tar', lambda member: member != 'keys/1.2.wms2',
                                                     [('keys/1.2.wms2', self.turn(second, 5))]))):
            with self.subTest(name):
                unit = ReleaseUnit(self.held)
                with self.assertRaisesRegex(StepFailed, 'one was added, taken away or changed'):
                    self.run_update(unit, archive)
                self.assertEqual((unit.calls, unit.held.text), ([], self.held.text), 'the unit is not even asked')

    def test_another_release_under_the_number_settled_on_is_refused_though_the_unit_has_its_images(self):
        unit = ReleaseUnit(self.held)
        self.assertEqual(self.run_update(unit, self.release(4)), 0)
        self.assertEqual(unit.settled, hashlib.sha256(bundle.read_release(self.release(4))[2][40:-64]).hexdigest())
        self.assertEqual(self.run_update(unit, self.release(4)), 0, 'the same release again is itself')
        other = self.work / 'other-4.tar'
        bundle.sign(self.plain, other, 4, self.sign, source='cd' * 20)
        with self.assertRaisesRegex(StepFailed, 'ANOTHER release 4 than the one this unit settled on'):
            self.run_update(unit, other)
        self.assertEqual(self.verbs(unit)[-2:], ['status', 'keys'], 'nothing was sent')

    def test_a_release_number_the_unit_cannot_read_stops_a_release(self):
        unit = ReleaseUnit(self.held, floor='unreadable')
        with self.assertRaisesRegex(StepFailed, 'does not read.*at the bench'):
            self.run_update(unit, self.release(4))
        self.assertEqual(unit.files, {})

    def test_the_units_word_on_a_rotation_is_the_last(self):
        second = keys_list(2, USUAL[0], USUAL[1], (3, 'release', 'second'))
        unit = ReleaseUnit(self.held)
        with mock.patch.object(seal, 'rotated', side_effect=[(second, second.keys[1]), seal.Refused('no')]):
            with self.assertRaisesRegex(StepFailed, 'the unit does not take the rotation to list 1.2'):
                self.run_update(unit, self.release(4, self.sign_stranger, [self.turn(second, 6)]))
        self.assertEqual(unit.held.text, self.held.text)

    def test_the_root_alone_and_the_loader_alone_need_the_word_as_well(self):
        def sleep(seconds):
            self.now += seconds
        for run, verb in ((remote.run, 'stage'), (remote.run_loader, 'stage-loader')):
            with self.subTest(verb), mock.patch.object(config, 'ROOTFS', self.root_image):
                unit = ReleaseUnit(self.held)
                with self.assertRaisesRegex(StepFailed, 'takes only releases'):
                    run(self.settings, link=unit, clock=lambda: self.now, sleep=sleep)
                self.assertEqual(run(self.settings, link=unit, clock=lambda: self.now, sleep=sleep,
                                     unsigned=True), 0)
                self.assertEqual(unit.flags[verb], ['--unsigned'])


if __name__ == '__main__':
    unittest.main()
