// SPDX-License-Identifier: GPL-2.0-only
/*
 * W1700K: the memory's refresh, as the fitted chips need it.
 *
 * The stock first stage sets one refresh every 3.88 us, the rate DDR4 needs
 * above 85 C: twice as often as the board's parts (two 8 Gbit x16 DDR4) need
 * below that. Refresh then takes a tenth of the memory controller's time, and
 * at the usual 7.76 us a twentieth: one core reads 2.55 GB/s where it read
 * 2.43, writes 6.68 where it wrote 6.33, and four copy 1.10 where they copied
 * 1.02 [measured: include/hw/an7581/dramc.h and memmap.h, which name the
 * words and say how they were found]. The refresh's length is already what
 * 8 Gbit parts need and is left alone.
 *
 * One word of the memory controller is written, nothing else:
 *   0x1fc802f0, low 11 bits: the refresh interval in ticks of 25 MHz
 *               (0x61: 3.88 us, as the first stage leaves it; 0xc2: 7.76 us)
 *
 * and only where all of this holds, so that no other board or memory gets it:
 *   - the board is this one (its device tree's compatible);
 *   - three words of the controller read as they do on every unit seen, and
 *     the word with the refresh's length reads as the 8 Gbit parts' at
 *     DDR4-2666 (which also ties the tick to what was measured);
 *   - the word reads as the first stage leaves it (then it is written) or as
 *     we write it (then it is left): any other value means a first stage we
 *     do not know, and nothing is written at all.
 *
 * THE RATE FOLLOWS THE TEMPERATURE. 7.76 us is DDR4's rate up to 85 C at the
 * chip's case. The SoC's own sensor is the only one there is. While it reads
 * `hot_mc` or more, or cannot be read, the rate is the first stage's 3.88 us
 * again, until it reads `cool_mc` or less.
 *
 * A LONGER INTERVAL WHILE THE UNIT IS COOL, where it is asked for (`long_x`
 * 2 or 4: a refresh every 15.5 or 31.0 us at the most; 0, the default,
 * never). That is outside what DDR4 specifies for the interval a controller
 * keeps, at any temperature, and rests only on what was measured on a unit
 * (dramc.h has the soak). The interval is given up a step at a time as the
 * unit warms: four times DDR4's only while the sensor reads under
 * `long_hot_mc` (taken again at `long_cool_mc` or less), twice only under
 * `twice_hot_mc` (again at `twice_cool_mc`), DDR4's own above that.
 * The marks against the measurement, one unit warmed in a box to 84 C at
 * this sensor: four times held every pattern up to 84 C and is given up at
 * 70; with no refresh at all the weakest cells there held a quarter of a
 * second, which is what a row waits at four times, and they hold twice as
 * long for every 10 C less. Twice held to 84 C as well, with half that wait,
 * and is given up at 75. Eight times lost its first bit at 74 C and is not
 * offered.
 *
 * Unloading puts the word back as the first stage left it; so does the first
 * stage itself at every reset.
 */
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/thermal.h>
#include <linux/workqueue.h>

#define MEMTUNE_BOARD		"gemtek,w1700k-sdr"
#define MEMTUNE_ZONE		"cpu-thermal"

/* include/hw/an7581/dramc.h: AN7581_DRAMC_CHECK0..2, _ACTIM3, _REFRESH at the controller's base. */
#define DRAMC_CHECK0		0x1fc80264u
#define DRAMC_CHECK0_KNOWN	0x0571300au
#define DRAMC_CHECK1		0x1fc80268u
#define DRAMC_CHECK1_KNOWN	0x30832565u
#define DRAMC_CHECK2		0x1fc8026cu
#define DRAMC_CHECK2_KNOWN	0xffff0504u
#define DRAMC_ACTIM3		0x1fc81650u	/* the refresh's length: 106 cycles, 351 ns, at DDR4-2666 */
#define DRAMC_ACTIM3_KNOWN	0x18d41002u

#define DRAMC_REFRESH		0x1fc802f0u
#define DRAMC_REFRESH_LEFT	0x00ca0061u	/* as the first stage leaves it: every 3.88 us */
#define DRAMC_REFRESH_USUAL	0x00ca00c2u	/* every 7.76 us */
#define DRAMC_REFRESH_TWICE	0x00ca0184u	/* every 15.5 us */
#define DRAMC_REFRESH_FOUR	0x00ca0308u	/* every 31.0 us */

static int hot_mc = 80000;
static int cool_mc = 75000;
module_param(hot_mc, int, 0644);
MODULE_PARM_DESC(hot_mc, "SoC temperature (millidegrees) from which the refresh rate is the first stage's again");
module_param(cool_mc, int, 0644);
MODULE_PARM_DESC(cool_mc, "SoC temperature (millidegrees) down to which it stays so");

static int long_x;
module_param(long_x, int, 0444);
MODULE_PARM_DESC(long_x, "2 or 4: a refresh interval up to so many times 7.76 us while the SoC is cool; 0: never");
static int long_hot_mc = 70000;
static int long_cool_mc = 67000;
module_param(long_hot_mc, int, 0644);
MODULE_PARM_DESC(long_hot_mc, "SoC temperature (millidegrees) from which the interval is no more than twice 7.76 us");
module_param(long_cool_mc, int, 0644);
MODULE_PARM_DESC(long_cool_mc, "SoC temperature (millidegrees) down to which it stays so");
static int twice_hot_mc = 75000;
static int twice_cool_mc = 72000;
module_param(twice_hot_mc, int, 0644);
MODULE_PARM_DESC(twice_hot_mc, "SoC temperature (millidegrees) from which the interval is 7.76 us again");
module_param(twice_cool_mc, int, 0644);
MODULE_PARM_DESC(twice_cool_mc, "SoC temperature (millidegrees) down to which it stays so");

enum { RATE_LEFT, RATE_USUAL, RATE_TWICE, RATE_FOUR };	/* every 3.88, 7.76, 15.5 or 31.0 us */
static int rate_now;
/* What a host reads (host/w1700k/stream.py): how many times DDR4's 7.76 us the interval is now,
 * 1, 2 or 4; 0 while it is the first stage's 3.88 us. */
static int interval_x;
module_param(interval_x, int, 0444);
MODULE_PARM_DESC(interval_x, "the refresh interval now, in times 7.76 us (0: the first stage's 3.88 us)");
static unsigned int rate_changes;
module_param(rate_changes, uint, 0444);

static void __iomem *refresh;
static struct thermal_zone_device *zone;
static struct delayed_work watch;

static u32 memtune_read(u32 address)
{
	void __iomem *p = ioremap(address, 4);
	u32 value = p ? readl(p) : 0;

	if (p)
		iounmap(p);
	return value;
}

static const u32 memtune_word[] = {
	[RATE_LEFT] = DRAMC_REFRESH_LEFT, [RATE_USUAL] = DRAMC_REFRESH_USUAL,
	[RATE_TWICE] = DRAMC_REFRESH_TWICE, [RATE_FOUR] = DRAMC_REFRESH_FOUR,
};
static const int memtune_times[] = { [RATE_LEFT] = 0, [RATE_USUAL] = 1, [RATE_TWICE] = 2, [RATE_FOUR] = 4 };
static const char *const memtune_us[] = { [RATE_LEFT] = "3.88", [RATE_USUAL] = "7.76", [RATE_TWICE] = "15.5",
					  [RATE_FOUR] = "31.0" };

static void memtune_rate(int rate)
{
	if (rate == rate_now)
		return;
	writel(memtune_word[rate], refresh);
	pr_info("w1700k_memtune: the memory is refreshed every %s us (was %s)\n", memtune_us[rate], memtune_us[rate_now]);
	rate_now = rate;
	interval_x = memtune_times[rate];
	rate_changes++;
}

/* The rate after `rate` at this temperature (the sensor read, and under hot_mc): down a step at
 * a step's upper mark, or where the step is not asked for; up a step only from a reading at or
 * under its lower mark, and under its upper one whatever the two are set to. */
static int memtune_step(int rate, int temperature)
{
	if (rate == RATE_FOUR && (long_x < 4 || temperature >= long_hot_mc))
		rate = RATE_TWICE;
	if (rate == RATE_TWICE && (long_x < 2 || temperature >= twice_hot_mc))
		rate = RATE_USUAL;
	if (rate == RATE_LEFT && temperature <= cool_mc)
		rate = RATE_USUAL;
	if (rate == RATE_USUAL && long_x >= 2 && temperature <= twice_cool_mc && temperature < twice_hot_mc)
		rate = RATE_TWICE;
	if (rate == RATE_TWICE && long_x >= 4 && temperature <= long_cool_mc && temperature < long_hot_mc)
		rate = RATE_FOUR;
	return rate;
}

/* The rate the temperature allows now (memtune_step), and all the way back to the first stage's
 * at once when the sensor reads hot_mc or more or cannot be read. */
static void memtune_watch(struct work_struct *work)
{
	int temperature = 0, rate = rate_now;
	bool known = !IS_ERR_OR_NULL(zone) && !thermal_zone_get_temp(zone, &temperature);

	if (!known || temperature >= hot_mc) {
		if (rate_now != RATE_LEFT)
			pr_warn("w1700k_memtune: %s\n",
				known ? "the SoC is hot" : "the SoC's temperature cannot be read");
		rate = RATE_LEFT;
	} else {
		rate = memtune_step(rate, temperature);
	}
	memtune_rate(rate);
	schedule_delayed_work(&watch, 2 * HZ);
}

static int __init memtune_init(void)
{
	u32 check0, check1, check2, length, rate;

	if (!of_machine_is_compatible(MEMTUNE_BOARD))
		return -ENODEV;
	if (long_x != 0 && long_x != 2 && long_x != 4)
		return -EINVAL;
	check0 = memtune_read(DRAMC_CHECK0);
	check1 = memtune_read(DRAMC_CHECK1);
	check2 = memtune_read(DRAMC_CHECK2);
	length = memtune_read(DRAMC_ACTIM3);
	if (check0 != DRAMC_CHECK0_KNOWN || check1 != DRAMC_CHECK1_KNOWN || check2 != DRAMC_CHECK2_KNOWN ||
	    length != DRAMC_ACTIM3_KNOWN) {
		pr_info("w1700k_memtune: not the memory this is for (%08x %08x %08x %08x): nothing written\n",
			check0, check1, check2, length);
		return -ENODEV;
	}
	refresh = ioremap(DRAMC_REFRESH, 4);
	if (!refresh)
		return -ENOMEM;
	rate = readl(refresh);
	if (rate != DRAMC_REFRESH_LEFT && rate != DRAMC_REFRESH_USUAL &&
	    rate != DRAMC_REFRESH_TWICE && rate != DRAMC_REFRESH_FOUR) {
		pr_info("w1700k_memtune: the refresh is set as no first stage we know sets it (%08x): nothing written\n",
			rate);
		iounmap(refresh);
		return -ENODEV;
	}
	/* A long interval found here (an earlier load's) is kept only where this load asks for as
	 * much; the watch below then holds it to the temperature. */
	if (rate == DRAMC_REFRESH_LEFT) {
		rate_now = RATE_LEFT;
	} else if (rate == DRAMC_REFRESH_FOUR && long_x >= 4) {
		rate_now = RATE_FOUR;
	} else if (rate == DRAMC_REFRESH_TWICE && long_x >= 2) {
		rate_now = RATE_TWICE;
	} else {
		if (rate != DRAMC_REFRESH_USUAL)
			writel(DRAMC_REFRESH_USUAL, refresh);
		rate_now = RATE_USUAL;
	}
	interval_x = memtune_times[rate_now];
	zone = thermal_zone_get_zone_by_name(MEMTUNE_ZONE);
	INIT_DELAYED_WORK(&watch, memtune_watch);
	memtune_watch(&watch.work);
	pr_info("w1700k_memtune: the memory is refreshed every %s us%s%s\n", memtune_us[rate_now],
		long_x == 4 ? " (up to 31.0 while the SoC is cool)" : long_x == 2 ? " (up to 15.5 while the SoC is cool)" : "",
		IS_ERR_OR_NULL(zone) ? "; no temperature sensor, so the rate stays 3.88" : "");
	return 0;
}

static void __exit memtune_exit(void)
{
	cancel_delayed_work_sync(&watch);
	writel(DRAMC_REFRESH_LEFT, refresh);
	iounmap(refresh);
	pr_info("w1700k_memtune: the memory's refresh is as the first stage left it\n");
}

module_init(memtune_init);
module_exit(memtune_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("W1700K: the memory's refresh as its 8 Gbit DDR4 parts need it");
