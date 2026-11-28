# SPDX-License-Identifier: MIT
"""The W1700K's module for the memory's refresh (kernel/w1700k_memtune): the one word it writes and its
values against the register reference (include/hw/an7581/dramc.h) and what was measured on a unit, that it
writes nowhere else and only for that board and that memory, and that the root image carries and loads it."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / 'kernel/w1700k_memtune/w1700k_memtune.c').read_text()
HEADER = (ROOT / 'include/hw/an7581/dramc.h').read_text()


def define(name, text=SOURCE):
    return int(re.search(rf'^#define {name}\s+(0x[0-9a-f]+)u', text, re.M).group(1), 16)


class Words(unittest.TestCase):
    def test_the_word_and_its_values_are_the_measured_ones(self):
        base = define('AN7581_DRAMC_AO_BASE', HEADER)
        self.assertEqual(define('DRAMC_REFRESH'), base + int(re.search(r'AN7581_DRAMC_REFRESH\s+(0x[0-9a-f]+)', HEADER).group(1), 16))
        self.assertEqual(define('DRAMC_REFRESH_LEFT') & 0x7ff, define('AN7581_DRAMC_REFRESH_LOADER', HEADER))
        self.assertEqual(define('DRAMC_REFRESH_USUAL') & 0x7ff, define('AN7581_DRAMC_REFRESH_JEDEC', HEADER))
        tick = int(re.search(r'AN7581_DRAMC_REFRESH_TICK_HZ\s+(\d+)u', HEADER).group(1))
        # 7.8 us is the most DDR4 allows below 85 C: the usual value is under it, and as near as a tick allows.
        usual = (define('DRAMC_REFRESH_USUAL') & 0x7ff) / tick
        self.assertLessEqual(usual, 7.8e-6)
        self.assertGreater(usual + 1 / tick, 7.76e-6)
        for name, times in (('DRAMC_REFRESH_TWICE', 2), ('DRAMC_REFRESH_FOUR', 4)):
            self.assertEqual(define(name) >> 11, define('DRAMC_REFRESH_USUAL') >> 11)
            self.assertEqual(define(name) & 0x7ff, times * (define('DRAMC_REFRESH_USUAL') & 0x7ff))
        self.assertEqual(define('DRAMC_REFRESH_LEFT') >> 11, define('DRAMC_REFRESH_USUAL') >> 11)

    def test_it_writes_that_word_alone(self):
        writes = re.findall(r'writel\(([^,]+), (\w+)\)', SOURCE)
        self.assertTrue(writes)
        self.assertEqual({target for _, target in writes}, {'refresh'})
        self.assertEqual(SOURCE.count('ioremap(DRAMC_REFRESH, 4)'), 1)

    def test_only_this_board_and_this_memory(self):
        """The board by its device tree; the controller by the words every unit read the same; the parts and
        the memory's speed by the word with the refresh's length. Then the word itself: the loader's or ours."""
        init = SOURCE[SOURCE.index('static int __init memtune_init'):SOURCE.index('static void __exit')]
        self.assertIn('"gemtek,w1700k-sdr"', SOURCE)
        self.assertLess(init.index('of_machine_is_compatible(MEMTUNE_BOARD)'), init.index('ioremap'))
        for name in ('DRAMC_CHECK0', 'DRAMC_CHECK1', 'DRAMC_CHECK2', 'DRAMC_ACTIM3'):
            self.assertIn(f'!= {name}_KNOWN', init)
            self.assertLess(init.index(f'!= {name}_KNOWN'), init.index('writel'))
        self.assertEqual((define('DRAMC_ACTIM3_KNOWN') >> 17) & 0x1ff, 106, '351 ns at DDR4-2666: 8 Gbit parts')
        self.assertLess(init.index('rate != DRAMC_REFRESH_LEFT && rate != DRAMC_REFRESH_USUAL'), init.index('writel'))

    def test_a_longer_interval_only_where_asked_and_never_when_hot(self):
        self.assertRegex(SOURCE, r'static int long_x;\n')                      # 0 unless a load asks
        watch = SOURCE[SOURCE.index('static void memtune_watch'):SOURCE.index('static int __init')]
        hot = watch[watch.index('if (!known || temperature >= hot_mc)'):watch.index('} else {')]
        self.assertIn('rate = RATE_LEFT;', hot)
        self.assertNotIn('memtune_step', hot)
        exit_ = SOURCE[SOURCE.index('static void __exit'):]
        self.assertIn('writel(DRAMC_REFRESH_LEFT, refresh);', exit_)


class Image(unittest.TestCase):
    def test_the_root_carries_it_and_loads_it_before_the_driver(self):
        build = (ROOT / 'platform/rootfs/build.py').read_text()
        self.assertIn("files['lib/modules/w1700k_memtune.ko'] = (MEMTUNE.read_bytes(), 0o644)", build)
        rcs = (ROOT / 'platform/rootfs/overlay/etc/init.d/rcS').read_text()
        # another board declines: no fault. The long interval is asked for on a W1700K alone: an XR1710G passes
        # the module's checks (same SoC, same memory setup) but has other memory parts, never soaked.
        load = 'insmod /lib/modules/w1700k_memtune.ko $memtune_long 2>/dev/null || true'
        self.assertIn('*" w1700k.board=w1700k "*) memtune_long=long_x=4 ;;', rcs)
        self.assertEqual(rcs.count('long_x='), 1 + rcs.count('# long_x='), 'asked for in that one place')
        self.assertIn(load, rcs)
        self.assertLess(rcs.index(load), rcs.index('insmod /lib/modules/w1700k_sdr.ko'))
        make = (ROOT / 'platform/linux/Makefile').read_text()
        self.assertIn('M=$(MEMTUNE) MO=$(MEMTUNE_OUT) modules', make)


if __name__ == '__main__':
    unittest.main()
