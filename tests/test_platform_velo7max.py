# SPDX-License-Identifier: MIT
"""The Velo7 Max's build (platform/velo7max): what its kernel is made from and asked for, what its
device tree changes in OpenWrt's, and the image its stock U-Boot starts from RAM, which is written
here without mkimage and must be one U-Boot and our own reader both take."""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import stat
import struct
import sys
import tempfile
import unittest
import zlib

ROOT = Path(__file__).resolve().parents[1]
UNIT = ROOT / 'platform' / 'velo7max'
sys.path[:0] = [str(ROOT / 'platform')]
import buildlib     # noqa: E402
import fdt          # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(f'velo7max_{name}', UNIT / f'{name}.py')
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(UNIT))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(UNIT))
    return module


build = load('build')
image = load('image')
DTS = (UNIT / 'dts/mt7988a-ltc-vl7m19k-sdr.dts').read_text()
KEY = b'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPretendKeyPretendKeyPretendKeyPretendKeyPre test\n'


def unpack(archive):
    """{name: (mode, uid, gid, rdev, data)} of a gzipped newc archive."""
    data, out, at = gzip.decompress(archive), {}, 0
    while True:
        assert data[at:at + 6] == b'070701', at
        fields = [int(data[at + 6 + 8 * i:at + 14 + 8 * i], 16) for i in range(13)]
        name_end = at + 110 + fields[11]
        name = data[at + 110:name_end - 1].decode()
        start = name_end + (-name_end % 4)
        body = data[start:start + fields[6]]
        at = start + fields[6] + (-fields[6] % 4)
        if name == 'TRAILER!!!':
            return out
        out[name] = (fields[1], fields[2], fields[3], (fields[9], fields[10]), body)


class Sources(unittest.TestCase):
    def test_the_pins_hold_every_openwrt_path_the_build_reads(self):
        pin = json.loads((ROOT / 'platform/sources.json').read_text())['openwrt']
        for path in build.OPENWRT_PATCH_DIRS + build.OPENWRT_FILE_DIRS + (build.OPENWRT_DTS,):
            self.assertIn(path, pin['paths'], path)
        for path in build.OPENWRT_CONFIGS:
            self.assertIn(path, pin['files'], path)

    def test_openwrts_series_is_the_generic_one_then_the_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            openwrt = Path(tmp)
            for directory, names in (('target/linux/generic/backport-6.18', ('200-b.patch', '100-a.patch')),
                                     ('target/linux/generic/pending-6.18', ('300-c.patch',)),
                                     ('target/linux/generic/hack-6.18', ('400-d.patch',)),
                                     ('target/linux/mediatek/patches-6.18', ('050-e.patch', 'note.txt'))):
                (openwrt / directory).mkdir(parents=True)
                for name in names:
                    (openwrt / directory / name).write_text('')
            self.assertEqual([p.name for p in build.openwrt_series(openwrt)],
                             ['100-a.patch', '200-b.patch', '300-c.patch', '400-d.patch', '050-e.patch'])

    def test_our_patches_are_the_projects_and_touch_what_they_say(self):
        patches = build.local_patches()
        self.assertTrue(patches)
        for patch in patches:
            text = patch.read_text()
            self.assertTrue(text.startswith('SPDX-License-Identifier: GPL-2.0-only\nSubject: [PATCH] '), patch.name)
            self.assertEqual(len(re.findall(r'^--- a/', text, re.M)), 1, patch.name)
        jumbo = patches[0].read_text()
        self.assertIn('+++ b/drivers/net/ethernet/mediatek/mtk_eth_soc.c', jumbo)
        self.assertIn('max_mtu = 9216 - MTK_RX_ETH_HLEN', jumbo)
        self.assertEqual(image.STREAM_MTU, 9216 - 22, 'what that leaves: the header the driver counts is 22 bytes')


class Configuration(unittest.TestCase):
    def setUp(self):
        self.asked = buildlib.kconfig(UNIT / 'receiver.config')

    def test_it_asks_for_what_a_ram_start_and_the_driver_need(self):
        for key in ('CONFIG_BLK_DEV_INITRD', 'CONFIG_DEVTMPFS', 'CONFIG_MODULES', 'CONFIG_MODULE_UNLOAD',
                    'CONFIG_PCIE_MEDIATEK_GEN3', 'CONFIG_SERIAL_8250_CONSOLE', 'CONFIG_FW_LOADER'):
            self.assertEqual(self.asked.get(key), 'y', key)

    def test_the_phy_patch_is_built_in_and_is_the_pinned_one(self):
        """Without it the PHY driver puts its probe off and the 10 GbE ports are dead; it is the
        file platform/linux/build.py makes for the W1700K's kernel."""
        self.assertEqual(self.asked['CONFIG_EXTRA_FIRMWARE'], '"rtl8261n.bin"')
        self.assertIn('rtl8261n', json.loads((ROOT / 'platform/sources.json').read_text()))
        self.assertEqual(build.FIRMWARE_DIR, build.w1700k_linux().FIRMWARE_DIR)

    def test_every_line_is_a_setting_or_a_comment(self):
        for line in (UNIT / 'receiver.config').read_text().splitlines():
            self.assertRegex(line, r'^(|#.*|CONFIG_[A-Z0-9_]+=("[^"]*"|[ymn0-9]+))$')

    def test_ours_comes_after_openwrts_and_names_no_build_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            openwrt = Path(tmp)
            for name, text in zip(build.OPENWRT_CONFIGS, ('CONFIG_MODULES=n\nCONFIG_A=y', 'CONFIG_B=y\n')):
                (openwrt / name).parent.mkdir(parents=True, exist_ok=True)
                (openwrt / name).write_text(text)
            merged = build.merged_config(openwrt)
        lines = merged.splitlines()
        self.assertLess(lines.index('CONFIG_MODULES=n'), lines.index('CONFIG_MODULES=y'), 'a later line wins')
        self.assertLess(lines.index('CONFIG_A=y'), lines.index('CONFIG_B=y'))
        self.assertTrue(lines[-1].startswith('CONFIG_EXTRA_FIRMWARE_DIR="'))
        self.assertNotIn(str(ROOT), merged, 'relative to the source tree')


class DeviceTree(unittest.TestCase):
    def node(self, label):
        match = re.search(rf'^&{label} \{{\n(.*?)^\}};', DTS, re.M | re.S)
        self.assertIsNotNone(match, label)
        return match.group(1)

    def test_it_is_openwrts_tree_for_the_board_with_changes(self):
        self.assertIn(f'#include "{build.OPENWRT_BOARD_DTS}"', DTS)
        self.assertNotIn('/dts-v1/', DTS, 'the included tree has it')

    def test_the_flash_has_no_node_and_nothing_waits_for_it(self):
        self.assertIn('status = "disabled";', self.node('spi0'))
        for mac in ('gmac0', 'gmac1', 'gmac2'):
            self.assertIn('/delete-property/ nvmem-cells;', self.node(mac), 'else the port waits for the flash')
        self.assertNotIn('partitions', DTS)

    def test_the_radio_is_left_to_our_driver(self):
        self.assertIn('/delete-node/ pcie@0,0;', self.node('pcie0'))
        self.assertNotIn('mt76', re.sub(r'/\*.*?\*/', '', DTS, flags=re.S))

    def test_the_phys_have_no_reset_and_their_lines_are_held_high(self):
        for phy in ('phy6', 'phy7'):
            for name in ('reset-gpios', 'reset-assert-us', 'reset-deassert-us'):
                self.assertIn(f'/delete-property/ {name};', self.node(phy))
        hogs = re.findall(r'gpio-hog;\n\s*gpios = <(\d+) GPIO_ACTIVE_HIGH>;\n\s*output-high;', self.node('pio'))
        self.assertEqual(sorted(map(int, hogs)), [10, 77])

    def test_the_root_is_the_initramfs(self):
        self.assertRegex(DTS, r'bootargs = "[^"]*console=ttyS0,115200n1[^"]*rdinit=/init"')
        self.assertNotRegex(DTS, r'bootargs = "[^"]*(root=|ubi)')


class Root(unittest.TestCase):
    FILES = {'bin/busybox': b'BUSYBOX', 'usr/sbin/ethtool': b'ETHTOOL', 'usr/sbin/dropbear': b'DROPBEAR',
             image.MODULE_PATH: b'MODULE', 'usr/sbin/mt7996-ctl': b'CTL'}

    def test_without_a_key_it_lets_nobody_in_but_the_console(self):
        root = unpack(image.initramfs(image.root_entries(dict(self.FILES))))
        self.assertNotIn('usr/sbin/dropbear', root)
        self.assertFalse([name for name in root if 'ssh' in name or 'dropbear' in name])
        self.assertEqual(root['init'][4], (UNIT / 'ramroot/init').read_bytes())
        self.assertTrue(stat.S_ISCHR(root['dev/console'][0]) and root['dev/console'][3] == (5, 1))

    def test_with_a_key_it_runs_ssh_for_that_key_under_the_units_identity(self):
        root = unpack(image.initramfs(image.root_entries(dict(self.FILES), login_key=KEY, host_key=b'HOSTKEY')))
        self.assertEqual(root['root/.ssh/authorized_keys'][4], KEY)
        self.assertEqual(root[image.HOST_KEY][4], b'HOSTKEY')
        self.assertEqual(root['usr/sbin/dropbear'][4], b'DROPBEAR')
        for name in ('root/.ssh/authorized_keys', image.HOST_KEY):
            self.assertEqual(stat.S_IMODE(root[name][0]), 0o600, name)
        for name in ('root', 'root/.ssh', 'etc/dropbear'):
            self.assertEqual(stat.S_IMODE(root[name][0]), 0o700, name)

    def test_a_key_without_the_units_identity_is_refused(self):
        for keys in ({'login_key': KEY}, {'host_key': b'HOSTKEY'}):
            with self.assertRaisesRegex(buildlib.BuildError, 'go together'):
                image.root_entries(dict(self.FILES), **keys)

    def test_everything_is_roots_and_the_programs_are_where_the_host_looks(self):
        root = unpack(image.initramfs(image.root_entries(dict(self.FILES))))
        self.assertTrue(all(entry[1] == 0 and entry[2] == 0 for entry in root.values()))
        self.assertEqual(stat.S_IMODE(root['usr/sbin/mt7996-ctl'][0]), 0o755)
        self.assertEqual(stat.S_IMODE(root[image.MODULE_PATH][0]), 0o644)
        sys.path.insert(0, str(ROOT / 'host'))
        from w1700k import config
        unit = config.UnitConfig()
        self.assertEqual('/' + image.BIN_DIR, unit.bin_dir)
        self.assertEqual('/' + image.MODULE_PATH, unit.module)

    def test_its_ports_and_addresses_are_the_ones_given(self):
        entries = image.root_entries(dict(self.FILES), ('lan2', '192.0.2.7/24'), ('eth1', '198.51.100.1/24'))
        text = entries['etc/velo7max.conf'][1].decode()
        self.assertEqual(text, 'MANAGEMENT_PORT=lan2\nMANAGEMENT_ADDRESS=192.0.2.7/24\nSTREAM_PORT=eth1\n'
                               f'STREAM_ADDRESS=198.51.100.1/24\nSTREAM_MTU={image.STREAM_MTU}\n')
        init = (UNIT / 'ramroot/init').read_text()
        for name in re.findall(r'^([A-Z_]+)=', text, re.M):
            self.assertIn(f'${name}', init, name)
        for bad in (('lan0', '192.0.2.7'), ('lan0', 'nonsense/24'), ('lan 0', '192.0.2.7/24')):
            with self.assertRaises((buildlib.BuildError, ValueError)):
                image.port_and_address(bad)

    def test_the_same_inputs_give_the_same_archive(self):
        one = image.initramfs(image.root_entries(dict(self.FILES)))
        self.assertEqual(one, image.initramfs(image.root_entries(dict(reversed(list(self.FILES.items()))))))

    def test_the_start_up_script_never_names_the_flash(self):
        init = (UNIT / 'ramroot/init').read_text()
        self.assertNotRegex(init, r'mtd|ubi|nand|flash_erase|fw_setenv')


class Fit(unittest.TestCase):
    KERNEL, DTB, RAMDISK = b'\x5d' + bytes(range(200)), b'\xd0\x0d\xfe\xed' + b'tree', b'\x1f\x8b' + b'root' * 5

    def setUp(self):
        self.blob = image.fit(self.KERNEL, self.DTB, self.RAMDISK, '6.18.52')
        self.tree = fdt.nodes(self.blob)

    def test_our_reader_takes_it_and_finds_each_image_whole(self):
        for name, data in (('kernel-1', self.KERNEL), ('fdt-1', self.DTB), ('ramdisk-1', self.RAMDISK)):
            self.assertEqual(self.tree[f'/images/{name}']['data'], data, name)
        self.assertEqual(struct.unpack_from('>2I', self.blob), (0xd00dfeed, len(self.blob)))
        self.assertEqual(len(self.blob) % 4, 0)

    def test_each_image_carries_the_hashes_the_stock_bootloader_checks(self):
        for name, data in (('kernel-1', self.KERNEL), ('fdt-1', self.DTB), ('ramdisk-1', self.RAMDISK)):
            crc, sha = self.tree[f'/images/{name}/hash-1'], self.tree[f'/images/{name}/hash-2']
            self.assertEqual((fdt.string(crc['algo']), fdt.cells(crc['value'])), ('crc32', [zlib.crc32(data)]))
            self.assertEqual((fdt.string(sha['algo']), sha['value']), ('sha1', hashlib.sha1(data).digest()))

    def test_the_kernel_is_named_as_bootm_needs_it(self):
        kernel = self.tree['/images/kernel-1']
        self.assertEqual([fdt.string(kernel[key]) for key in ('type', 'arch', 'os', 'compression')],
                         ['kernel', 'arm64', 'linux', 'lzma'])
        self.assertEqual(fdt.cells(kernel['load']), [image.KERNEL_LOAD])
        self.assertEqual(fdt.cells(kernel['entry']), [image.KERNEL_LOAD])
        self.assertEqual(fdt.string(self.tree['/images/fdt-1']['type']), 'flat_dt')
        self.assertEqual(fdt.string(self.tree['/images/ramdisk-1']['type']), 'ramdisk')
        self.assertEqual(fdt.string(self.tree['/images/ramdisk-1']['compression']), 'none',
                         'the kernel unpacks its own initramfs')

    def test_one_configuration_names_all_three(self):
        self.assertEqual(fdt.string(self.tree['/configurations']['default']), 'config-1')
        chosen = self.tree['/configurations/config-1']
        self.assertEqual([fdt.string(chosen[key]) for key in ('kernel', 'fdt', 'ramdisk')],
                         ['kernel-1', 'fdt-1', 'ramdisk-1'])
        self.assertEqual(fdt.cells(self.tree['/']['#address-cells']), [1])

    def test_the_kernel_unpacks_below_where_the_image_is_given(self):
        self.assertLess(image.KERNEL_LOAD, image.FIT_LOAD)
        self.assertGreaterEqual(image.FIT_LOAD - image.KERNEL_LOAD, 64 << 20, 'room for the kernel unpacked')


if __name__ == '__main__':
    unittest.main()
