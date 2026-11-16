# SPDX-License-Identifier: MIT
"""A unit's own network settings on the unit (platform/rootfs/overlay/usr/sbin/w1700k-network),
run as the unit runs it: over a directory for the device tree's /chosen as the loader left it and
one for durable storage, with `ip` standing in as a program that writes down what it is told."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NETWORK = ROOT / 'platform/rootfs/overlay/usr/sbin/w1700k-network'
DEFAULTS = ROOT / 'platform/rootfs/overlay/etc/w1700k/network.conf'
STOCK = {'MGMT_IF': 'lan3', 'MGMT_ADDRESS': '192.168.1.1/24', 'EXPORT_IF': 'eth1',
         'EXPORT_ADDRESS': '10.77.0.1/24', 'EXPORT_MTU': '9216'}


class NetworkSettings(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        for name in ('chosen', 'durable', 'run', 'bin'):
            (self.dir / name).mkdir()
        (self.dir / 'cmdline').write_text('console=ttyS0,115200 ro w1700k.net=none\n')
        ip = self.dir / 'bin/ip'
        ip.write_text(f'#!/bin/sh\necho "$@" >> {self.dir}/ip-calls\n')
        ip.chmod(0o755)
        run = self.dir / 'durable-run'
        run.write_text(f'#!/bin/sh\necho "$@" >> {self.dir}/durable-calls\n'
                       f'[ ! -e {self.dir}/durable-busy ] || {{ echo "durable-open: durable is already open" >&2; exit 1; }}\n'
                       'echo "durable-open: /durable mounted from mtd6"\n"$@"\nstatus=$?\n'
                       'echo "durable-close: /durable closed"\nexit $status\n')
        run.chmod(0o755)
        self.store, self.defaults = self.dir / 'durable/net/conf', DEFAULTS
        self.env = dict(os.environ, PATH=f'{self.dir}/bin:{os.environ["PATH"]}', W1700K_NETWORK_RUN=str(self.dir / 'run/network.conf'),
                        W1700K_NETWORK_CHOSEN=str(self.dir / 'chosen'), W1700K_NETWORK_CMDLINE=str(self.dir / 'cmdline'),
                        W1700K_NETWORK_DURABLE_RUN=str(run), W1700K_NETWORK_DIR=str(self.dir / 'durable/net'))

    def network(self, *words, stdin='', ok=True):
        env = dict(self.env, W1700K_NETWORK_DEFAULTS=str(self.defaults))
        result = subprocess.run(['sh', str(NETWORK), *words], input=stdin, capture_output=True, text=True, env=env)
        if ok:
            self.assertEqual(result.returncode, 0, result.stderr)
        return result

    def hand_over(self, said='handed', **settings):
        """What the loader leaves: each setting as a string property, and its word."""
        for old in (self.dir / 'chosen').iterdir():
            old.unlink()
        for name, value in settings.items():
            (self.dir / 'chosen' / ('w1700k,net-' + name.lower().replace('_', '-'))).write_bytes(value.encode() + b'\0')
        (self.dir / 'cmdline').write_text('console=ttyS0,115200 ro' + (f' w1700k.net={said}' if said else '') + '\n')

    def reboot(self):
        """The next boot, by a loader that reads the settings as durable storage has them."""
        own = dict(line[len('net_'):].split('=', 1) for line in self.store.read_text().splitlines()) if self.store.exists() else {}
        self.hand_over('handed' if own else 'none', **{name.upper(): value for name, value in own.items()})
        return self.network('boot')

    def in_force(self):
        return dict(line.split('=', 1) for line in (self.dir / 'run/network.conf').read_text().splitlines())

    def ip(self):
        path = self.dir / 'ip-calls'
        calls = path.read_text().splitlines() if path.exists() else []
        path.unlink(missing_ok=True)
        return calls

    def said(self, result):
        return dict(line.split('=', 1) if line.startswith(('own=', 'changed=')) else (line, '') for line in result.stdout.splitlines()
                    if not line.startswith('durable-'))

    def test_the_defaults_this_program_knows_are_the_roots(self):
        text = DEFAULTS.read_text()
        self.assertEqual({line.split('=')[0]: line.split('=')[1] for line in text.splitlines() if '=' in line and not line.startswith('#')}, STOCK)
        stock = [line for line in NETWORK.read_text().splitlines() if line.startswith("STOCK='")][0]
        self.assertEqual(dict(word.split('=') for word in stock[len("STOCK='"):-1].split()), STOCK)

    def test_a_unit_with_no_settings_of_its_own_comes_up_on_the_defaults(self):
        for said, loader in (('none', 'none'), ('', 'silent')):
            self.hand_over(said)
            self.network() if said else self.network('boot')
            self.assertEqual(self.in_force(), STOCK)
            self.assertEqual(self.ip(), ['link set lan3 up', 'address replace 192.168.1.1/24 dev lan3', 'link set eth1 mtu 9216',
                                         'link set eth1 up', 'address replace 10.77.0.1/24 dev eth1'])
            self.assertEqual(self.network('status').stdout.splitlines()[-2:], ['own=0', f'loader={loader}'])
        self.assertFalse((self.dir / 'durable-calls').exists(), 'start-up does not open durable storage')

    def test_what_the_loader_handed_over_is_in_force_and_the_rest_are_defaults(self):
        self.hand_over(MGMT_ADDRESS='10.0.0.1/24', EXPORT_MTU='9000')
        self.network('boot')
        self.assertEqual(self.in_force(), dict(STOCK, MGMT_ADDRESS='10.0.0.1/24', EXPORT_MTU='9000'))
        self.assertEqual(self.ip(), ['link set lan3 up', 'address replace 10.0.0.1/24 dev lan3', 'link set eth1 mtu 9000',
                                     'link set eth1 up', 'address replace 10.77.0.1/24 dev eth1'])
        self.assertEqual(self.network('status').stdout.splitlines()[-2:], ['own=2', 'loader=handed'])

    def test_a_value_a_setting_cannot_have_is_refused_and_the_default_stands(self):
        bad = {'MGMT_IF': ['lan3 init=/bin/sh', 'Lan3', '3lan', 'a' * 16, '', 'lan3;reboot', '$(reboot)'],
               'MGMT_ADDRESS': ['10.0.0.1', '10.0.0.1/33', '10.0.0/24', '10.0.0.1.2/24', '10.0.0.1/24/8', 'fe80::1/64', '10.0.0.1/24 dev eth1',
                                '10..0.1/24', '10.0.0.1/', '/24'],
               'EXPORT_MTU': ['90000', '0', '100', '9217', '09000', '9000 up', '-1', 'nine']}
        for name, values in bad.items():
            for value in values:
                with self.subTest(name=name, value=value):
                    self.hand_over(**{name: value, 'EXPORT_ADDRESS': '10.99.0.1/24'})
                    result = self.network('boot', ok=False)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(f'no usable {name}', result.stderr)
                    self.assertEqual(self.in_force(), dict(STOCK, EXPORT_ADDRESS='10.99.0.1/24'), 'the good one still applies')
                    self.assertFalse(any('init=' in call or 'reboot' in call for call in self.ip()))
                    self.assertNotEqual(self.network('set', f'{name}={value}', ok=False).returncode, 0, 'nor can it be stored')
        self.assertFalse(self.store.exists())

    def test_settings_are_stored_as_the_loader_imports_them_and_apply_from_the_next_start(self):
        self.network('boot')
        self.ip()
        result = self.network('set', 'MGMT_ADDRESS=10.0.0.1/24', 'EXPORT_MTU=9000')
        self.assertEqual(self.said(result), {'own MGMT_ADDRESS=10.0.0.1/24': '', 'own EXPORT_MTU=9000': '', 'own': '2', 'changed': 'yes'})
        self.assertEqual(self.store.read_text(), 'net_mgmt_address=10.0.0.1/24\nnet_export_mtu=9000\n')
        self.assertEqual(self.in_force(), STOCK, 'not under a host that is talking to the unit')
        self.assertEqual(self.ip(), [])
        self.assertEqual(self.said(self.network('set', 'MGMT_ADDRESS=10.0.0.1/24', 'EXPORT_MTU=9000'))['changed'], 'no')
        self.reboot()
        self.assertEqual(self.in_force(), dict(STOCK, MGMT_ADDRESS='10.0.0.1/24', EXPORT_MTU='9000'))
        self.assertFalse(list(self.store.parent.glob('*.part')))

    def test_a_network_conf_on_stdin_is_taken_whole(self):
        text = '# my unit\nMGMT_IF=lan4\nMGMT_ADDRESS=10.0.0.1/24   # the bench\n\nEXPORT_IF=eth1\nEXPORT_ADDRESS=10.99.0.1/24\nEXPORT_MTU=9216\n'
        self.assertEqual(self.said(self.network('set', stdin=text))['own'], '5')
        self.assertEqual(self.store.read_text().splitlines(), ['net_mgmt_if=lan4', 'net_mgmt_address=10.0.0.1/24', 'net_export_if=eth1',
                                                               'net_export_address=10.99.0.1/24', 'net_export_mtu=9216'])
        for text in ('', '# nothing\n', 'DNS=1.1.1.1\n', 'MGMT_IF=lan4\nMGMT_IF=lan3\n', 'MGMT_IF\n', 'rm -rf /\n'):
            self.assertNotEqual(self.network('set', stdin=text, ok=False).returncode, 0)
        self.assertEqual(len(self.store.read_text().splitlines()), 5)

    def test_cleared_the_unit_is_on_the_defaults_again(self):
        self.network('set', 'MGMT_IF=lan4')
        self.assertEqual(self.network('clear').stdout.split()[-1], 'own=0')
        self.assertFalse(self.store.exists())
        self.reboot()
        self.assertEqual(self.in_force(), STOCK)

    def test_a_root_from_before_carries_what_it_set_other_than_the_defaults(self):
        self.defaults = self.dir / 'old-network.conf'
        self.defaults.write_text(DEFAULTS.read_text().replace('MGMT_ADDRESS=192.168.1.1/24', 'MGMT_ADDRESS=10.0.0.1/24')
                                 .replace('EXPORT_MTU=9216', 'EXPORT_MTU=9000'))
        for changed in ('yes', 'no'):
            result = self.said(self.network('keep'))
            self.assertEqual(result, {'own MGMT_ADDRESS=10.0.0.1/24': '', 'own EXPORT_MTU=9000': '', 'own': '2', 'changed': changed})
        self.assertEqual(self.store.read_text(), 'net_mgmt_address=10.0.0.1/24\nnet_export_mtu=9000\n')

    def test_a_root_on_the_defaults_carries_nothing_and_settings_the_unit_has_stand(self):
        self.assertEqual(self.said(self.network('keep')), {'own': '0', 'changed': 'no'})
        self.assertFalse(self.store.exists(), 'nothing is written for a unit with nothing of its own')
        self.network('set', 'EXPORT_MTU=1500')
        self.defaults = self.dir / 'old-network.conf'
        self.defaults.write_text(DEFAULTS.read_text().replace('MGMT_IF=lan3', 'MGMT_IF=lan4'))
        self.assertEqual(self.said(self.network('keep')), {'own EXPORT_MTU=1500': '', 'own': '1', 'changed': 'no'})
        self.assertEqual(self.store.read_text(), 'net_export_mtu=1500\n')

    def test_storage_that_cannot_be_opened_and_anything_else(self):
        (self.dir / 'durable-busy').touch()
        for words in (('set', 'MGMT_IF=lan4'), ('keep',), ('clear',)):
            self.assertNotEqual(self.network(*words, ok=False).returncode, 0)
        self.assertIn('boot has not run', self.network('status', ok=False).stderr)
        self.assertEqual(self.network('nonsense', ok=False).returncode, 2)


if __name__ == '__main__':
    sys.exit(unittest.main())
