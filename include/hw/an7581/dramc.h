/* SPDX-License-Identifier: MIT */
/*
 * AN7581 memory controller: what the first-stage loader sets, what was read
 * and measured on a W1700K under Linux, and what that means for a stream.
 *
 * The controller and its PHY are MediaTek's DRAMC and DDRPHY, set up by
 * MediaTek's DRAM library in the stock first-stage loader ("AN7581DRAMC
 * V0.9"; V0.8 on an older unit) [static: the loader's code, disassembled].
 * The same family is in MediaTek's own SoCs, and the word and field layouts
 * used here are those of MediaTek's public memory library for them. There is
 * no MediaTek EMI block in front of it here: no per-master arbitration words
 * and no per-master bus monitor were found.
 *
 * ADDRESS SPACE: AN7581_DRAMC_* are offsets from AN7581_DRAMC_AO_BASE (the
 * control words) and AN7581_DRAMC_NAO_* from AN7581_DRAMC_NAO_BASE (status),
 * both of channel 0. All words are 32 bits. Every word named here was read
 * from Linux (EL1, non-secure) on a W1700K without a fault [measured:
 * 2026-11-25]. Channel 1 (+0x10000) has only its PHY in use (the upper 16
 * data bits): its DRAMC is not set up and was not read.
 *
 * NOT TO BE WRITTEN, whatever a trial is after [static]:
 *   AN7581_DRAMC_REFRESH_OFF (stops refresh: this board lost its first bits
 *   between 1 and 2 s), any DDRPHY word (0x1fc88000, 0x1fc8a000, 0x1fc98000,
 *   0x1fc9a000), the DDR clock PLL (0x1fcac000), the memory's power manager
 *   at 0x1fca0000..0x1fca7fff (MediaTek's DPM: a small core and its low-power
 *   interface to the controller; the loader sets it, nothing reads it), the
 *   address map (SCU +0x74).
 *
 * The operating point [static: the loader's tables and its boot log; the
 * tick and the refresh rate measured]: DDR4-2666 (1333 MHz), CL 20, CWL 18,
 * the controller at a quarter of that (333 MHz, "MCK"), 32 data bits, one
 * rank, two 8 Gbit x16 parts: 10.67 GB/s on the pins at the most, at this one
 * frequency (the loader's table has no faster entry).
 */
#ifndef HW_AN7581_DRAMC_H
#define HW_AN7581_DRAMC_H

#include "../hw_bits.h"

#define AN7581_DRAMC_AO_BASE            0x1fc80000u
#define AN7581_DRAMC_NAO_BASE           0x1fc84000u

/* ---- control words ---------------------------------------------------- */

/* Three words the loader leaves the same on every unit read so far: a check
 * that these addresses are the controller and not something else. [measured:
 * 0x0571300a, 0x30832565, 0xffff0504; +0x278 and +0x27c 0x33333333] */
#define AN7581_DRAMC_CHECK0             0x264
#define AN7581_DRAMC_CHECK1             0x268
#define AN7581_DRAMC_CHECK2             0x26c

/* The refresh interval, in ticks of a free-running 25 MHz clock [measured:
 * 25.00 MHz by AN7581_DRAMC_NAO_TICKS against the kernel's clock].
 * The loader writes 0x61 = 97 ticks = 3.88 us [measured: 257,700 refreshes a
 * second, one every 97.0 ticks], which is what DDR4 asks for above 85 C: twice
 * as often as these parts need below that (7.8 us). The word read 0x00ca0061.
 * A write takes effect at once [measured: 0xc2 gave one refresh every 194.0
 * ticks = 7.76 us, 0x184 one every 388.0 = 15.5 us]. The loader sets it again
 * at every start. What it bought: memmap.h's memory notes.
 *
 * How long the memory holds without it [measured: 2026-11-25 and 26, one
 * W1700K; temperatures are the SoC's sensor, the board's own monitor
 * (nct7802) read 9 to 10 C less; ten or four patterns by physical row and
 * column, each held and read back]:
 *   - In open air at 42 to 46 C, 1.8 of its 2 GiB: at 15.5, 31 and 62 us
 *     (twice, four and eight times the 7.76) every pattern held 150 s was
 *     whole, 30 of 30.
 *   - Closed in a box and warmed, 52 to 84 C over ten hours, the last five
 *     at 84 C with a 320 Msps stream running beside it (0.75 GiB then): at
 *     15.5 us 172 holds of 60 s and at 31 us 172, not one wrong bit in any.
 *     At 62 us the first wrong bit came at 74 C; 1 to 2 a sweep of four
 *     holds to 79 C, about 27 a sweep at 84 C (669 in all), each a single
 *     cell that lost its charge, in both parts alike.
 *   - With the refresh off altogether (AN7581_DRAMC_REFRESH_OFF, for the
 *     test alone), zeros and ones, wrong bits per Gbit:
 *       42 C: 1 s none, 2 s 0.1, 4 s 5.5
 *       62 C: 0.5 s none, 1 s 1.5, 2 s 79
 *       84 C: 0.25 s 0.7, 0.5 s 86; at 1 s the unit stopped and restarted
 *     So the weakest cells hold about 1 to 2 s at 42 C, 0.5 to 1 s at 62 C
 *     and a quarter of a second at 84 C: half as long for every 10 C or so.
 *     Every row is rewritten within 64 ms at 7.76 us, 0.13 s at twice that,
 *     0.25 s at four times and 0.51 s at eight, which is where each was seen
 *     to fail or not.
 *   Such a hold loses bits in ALL memory, the running kernel's too: after
 *   the 2 and 4 s holds one page showed another's contents (a page table
 *   entry with one bit turned over) until the unit was restarted. Restart
 *   after any such test before trusting the unit.
 *   Not measured: a second unit, weeks, the parts' own case temperature. */
#define AN7581_DRAMC_REFRESH            0x2f0
#define AN7581_DRAMC_REFRESH_TICKS      HW_BITS(10, 0)
#define AN7581_DRAMC_REFRESH_TICK_HZ    25000000u
#define AN7581_DRAMC_REFRESH_LOADER     0x061u	/* 3.88 us */
#define AN7581_DRAMC_REFRESH_JEDEC      0x0c2u	/* 7.76 us: the most below 85 C */

/* Bit 0 set stops the refresh of rank 0 [static]. Read 0. NEVER SET. */
#define AN7581_DRAMC_REFRESH_OFF        0x56c

/* How long a refresh takes (tRFC), in MCK less 11, and its half-MCK bit in
 * the word at +0x1664 bit 2. The loader's first stage sets 172 with the half
 * (550 ns, the 16 Gbit value) and the secure monitor after it 106 without
 * (351 ns, what 8 Gbit parts ask for); the second is what stands [measured:
 * the word read 0x18d41002, field 106; +0x1664 read 0x34208022, bit 2 clear].
 * At the parts' own minimum: nothing to gain, and never to be lowered. */
#define AN7581_DRAMC_ACTIM3             0x1650
#define AN7581_DRAMC_ACTIM3_TRFC        HW_BITS(25, 17)
#define AN7581_DRAMC_AC_05T             0x1664
#define AN7581_DRAMC_AC_05T_TRFC        HW_BIT(2)

/* ---- status words ------------------------------------------------------ */

/* The controller's own counters run only while bit 3 is set here (0 stops
 * and clears them; it read 0). They saturate: a window of a few seconds.
 * [measured: writing 8 and then 0 changed nothing else that was seen] */
#define AN7581_DRAMC_NAO_MONITOR        0x024
#define AN7581_DRAMC_NAO_MONITOR_RUN    HW_BIT(3)

#define AN7581_DRAMC_NAO_REFRESHES      0x300	/* refreshes issued */
#define AN7581_DRAMC_NAO_TICKS          0x304	/* the 25 MHz tick */
/* MCK cycles in which the controller had nothing to do. At rest 90 % of all
 * cycles (the rest was refresh at 3.88 us); under ONE core reading memory at
 * 2.1 GB/s 2 %; under a 320 Msps capture that nothing reads 25 % [measured]. */
#define AN7581_DRAMC_NAO_IDLE           0x308
/* MCK cycles with rank 0's rows all closed (+0x33c) and with a row open
 * (+0x344); +0x34c counted every cycle. The twelve counters of command kinds
 * at +0x30c..+0x338, which MediaTek's library names, stayed 0 here. */
#define AN7581_DRAMC_NAO_PRECHARGED     0x33c
#define AN7581_DRAMC_NAO_ACTIVE         0x344
#define AN7581_DRAMC_NAO_CYCLES         0x34c

#endif /* HW_AN7581_DRAMC_H */
