# LTC Velo7 Max (VL7M19K)

The Velo7 Max has the W1700K's radio, a MediaTek MT7996, on another maker's
board around another SoC, a MediaTek MT7988A. This is the intake record of one
unit: what was read from its board and labels, what public sources say about
the model, and what has to be found out before anything of ours runs on it.

**A kernel of ours starts on it from RAM; the receiver does not run on it
yet.** The project's images are the AN7581's and none of them runs here. What
has been measured is the stock bootloader and the flash, from the unit's first
power-on with us (2026-11-20), stopped at U-Boot before stock Linux started;
one whole stock boot, logged with nothing sent to the unit; and a Linux built
for the board, started from RAM by stock U-Boot with no driver for the flash.

Every line carries where it comes from:

- **[measured]** on one unit: from its serial console at its first power-on
  with us, stopped at stock U-Boot's prompt; from an image of its whole flash
  read out there; from the console log of the stock boot that followed; and
  from a shell in a Linux of ours started from RAM.
- **[photo]** a marking or a part read from the board of that unit (its label
  says made by Tozed Kangwei; opened 2026-11-20).
- **[static]** from a document or another source tree, which is named. Two
  carry most of it: OpenWrt's commit `25f6620614ac` ("mediatek: add support
  for LTC Velo7 Max", 2026-07-31) with its device tree
  `mt7988a-ltc-vl7m19k.dts`, and the model's FCC grant, `2A5LO-VL7M19K`.
- **[forum]** from the OpenWrt forum thread on the model ("LTC Velo7 Max
  router", topic 250792): owners' posts, not checked by anyone here. Good for
  knowing what to look for, not for relying on.

Nothing here is a unit's own: no serial number, MAC address, network name,
calibration or credential.

## Identity

| | | |
| --- | --- | --- |
| Sold as | LTC Velo7 Max, "Wireless Router" | [photo] |
| Model on the label | VL7M19K | [photo] |
| Maker | Tozed Kangwei Tech Co., Ltd; its own name for the design is ZLT W19B6VM | [photo]; [static: OpenWrt commit] |
| Marked on the antenna boards | `W19b6VM-V01` | [photo] |
| FCC ID | 2A5LO-VL7M19K, granted 2025-12-11 as a 6 GHz low-power indoor access point | [photo]; [static: FCC grant] |
| Supply | 12 V, 3 A, barrel connector | [photo] |
| Address on the label | 192.168.0.1 | [photo] |
| Serial number's form | four digits, `-VL7M19K-`, five digits: the model is in the middle, not at the start | [photo] |

The last line matters to [`platform/boards.py`](../../platform/boards.py), which
names a board by how its serial begins.

## Parts

| Part | What it is | |
| --- | --- | --- |
| SoC | MediaTek MT7988AV, date code 2441: four Cortex-A73 (part `0xd09`), run at 800, 1100, 1500 or 1800 MHz | [photo]; [measured] |
| DRAM | two Nanya NT5AD256M16E4-JR, DDR4, 4 Gbit each: 1 GiB; the first stage finds 1024 MB with "DDR unknown settings" | [photo]; [measured] |
| Flash | Winbond SPI-NAND (ID begins `ef`), 256 MiB, 2048 + 128 byte pages, 128 KiB blocks, bad blocks managed by MediaTek's NMBM; a W25N02KV by OpenWrt's account | [measured]; [static: OpenWrt commit]; not found in our photos |
| eMMC | a footprint beside the SoC, not populated | [photo] |
| Radio | MediaTek MT7996: PCI `14c3:7990` behind the bridge at `pcie@11300000` and its second interface `14c3:7991` behind `pcie@11310000`, the W1700K's IDs; its reset on GPIO 7 | [measured]; [static: device tree] |
| Radio's PCIe links | both interfaces at 8.0 GT/s, two lanes (Gen3 x2), which is all either end can do; on each, BAR0 is 2 MiB and BAR2 32 KiB | [measured] |
| RF front ends | an MT7976 and two MT7977, as on the W1700K: stock's driver names the set `ADIE_76_77_77` | [measured] |
| Radio, on the board | one chip under a thermal pad in its own shield frame between the SoC and the RF section, and three closed shield cans; none opened, no marking read | [photo] |
| 10 GbE PHYs | two Realtek RTL8261BE, at MDIO 6 and 7, USXGMII; resets on GPIO 77 and GPIO 10. Stock's driver, which calls itself RTL8261N/RTL826XB, takes both, and so does the "RTL8261BE 10Gbps PHY" driver of OpenWrt's kernel, with the device tree's reset lines as they are | [static: device tree]; [measured] |
| 10 GbE magnetics | two JXD TG2484S | [photo] |
| 1 GbE | four ports from the SoC's built-in switch | [static: OpenWrt commit] |
| Regulator | Richtek RT5190A at I2C0 `0x64`; buck 3 is the cores' supply | [static: device tree] |
| USB | two USB 3.0 Type-A | [photo]; [static] |
| Buttons | reset GPIO 13, WPS GPIO 14, restart GPIO 8, each low when pressed | [static: device tree] |
| Cooling | one finned cast heatsink over the whole top of the board, a steel plate with raised pads under it; no fan | [photo] |

Other units of the model carry two ESMT M16U4G16256A for the same 1 GiB, and
the model was also sold with 4 GiB and 8 GiB [static: OpenWrt commit]. The
PHYs' own markings were not readable in our photos (one sits under a thermal
pad).

The RTL8261BE is the PHY of the [XR1710G](xr1710g.md), so the Realtek patch
this project's kernel carries applies to the part. Owners report that on some
units the PHYs answer with ID 0 until the device tree leaves their reset lines
alone and sets `mdi-reversal` (OpenWrt pull request 25791) [forum].

The SoC's own sensor read 41 °C with the board idle at a shell and its case
open [measured].

No GPS receiver and no Bluetooth or Zigbee chip was seen outside the shield
cans [photo]. Not populated on this board: the eMMC, two telephone line
circuits with their sockets (which is what the `TEL` LEDs in the device tree
are for), and pads marked `NFC` beside the 6 GHz antenna connectors [photo];
[static: OpenWrt commit].

### Antennas

Ten, each a small board on a cable to a connector on the main board [photo]:

| Connectors | Cables | Antenna boards | |
| --- | --- | --- | --- |
| `2.4/5.8G-1` … `2.4/5.8G-5` | grey | numbered 6 … 10, marked `2.4/5.8G-n (GY)` | 2.4 and 5 GHz share an antenna |
| `6G-1` … `6G-5` | black | numbered 1 … 5, marked `6G-n (BK)` | |

That is five connectors a group for a radio sold as four streams a band. What
the fifth of each group is connected to has not been found out. A receive path of the radio beyond
its four chains would fit, and is a guess.

Because 2.4 and 5 GHz share antennas here, a cable into one `2.4/5.8G`
connector reaches two of the radio's bands at once.

### LEDs

The front names them POWER, STATUS, 2.4 GHz Wi-Fi, 5 GHz Wi-Fi, 6 GHz Wi-Fi,
WPS/MESH and STORAGE [photo]. As the device tree has them, each lit when its
line is high [static: device tree]:

| LED | GPIO |
| --- | --- |
| Power (red) | 81 |
| Status green, blue, red | 68, 75, 76 |
| 2.4 GHz, 5 GHz, 6 GHz | 79, 63, 62 |
| WPS | 21 |
| TEL1 green, red; TEL2 green, red | 0, 2; 1, 3 |

The status LED has three colours, where the W1700K's has four emitters. The
1 GbE sockets' LEDs are the switch's own; the 10 GbE sockets' are the PHYs',
which the PHY driver cannot set. Owners report that under plain OpenWrt only
the power LED lights [forum].

## Serial console

Three plated holes in a row at the board's edge, at the corner of the RF
section farthest from the Ethernet sockets, marked `RX` and `TX` at the ends;
the middle one has no mark and is ground [photo]; [static: OpenWrt commit]. No header is fitted.
115200 8N1, 3.3 V, and no supply pin: only the three are connected [static];
[forum]; it worked so on our unit [measured]. It is the SoC's UART at
`0x11000000`, clocked at 40 MHz (its divisor reads 22) [measured].

Stock U-Boot refuses every console speed above 115200 (`setenv baudrate`
answers "not supported" from 230400 up) [measured]. The UART itself runs
faster when its registers are set as U-Boot's own driver would set them for a
high speed: at 2 Mbaud (high-speed mode 3, divisor 1, sample count 19, sample
point 8) the console worked in both directions for an hour, and of 1881
blocks printed one came damaged and was printed again [measured]. That is in RAM only; a reset puts 115200
back.

## Stock boot chain

- **First stages.** After the boot ROM's own lines, `BL2: v2.10.0(release):b860d5f7`,
  built 2025-11-21, which finds the DRAM and the flash and attaches NMBM
  read-only; then `BL31` of the same build [measured].
- **Stock U-Boot** is `U-Boot 2024.04 (Nov 21 2025 - 19:57:50 +0800)`, 1.1 s
  after the first byte on the console. It calls the board `mt7988-rfb`
  (`mediatek,mt7988-spim-nand-rfb`), MediaTek's reference board, and runs the
  maker's `tozed_w19b6vm_gpio_init` [measured].
- **It attaches the UBI area on every start**, before anything can be typed,
  to read its environment from the volume `u-boot-env` [measured]. An attach
  may write to the flash, so no power-on leaves the UBI area provably
  untouched.
- **The boot menu** comes 2.9 s after the first byte: "Startup system
  (Default)", which runs `mtkboardboot`; upgrades of the firmware, of BL2, of
  the FIP and of single images (`mtkupgrade`); "Load image" (`mtkload`); and
  "Start Web failsafe" (`httpd`). It waits five seconds. **Ctrl+C leaves it
  for the prompt, `MT7988>`, without choosing an entry** [measured].
- **At the prompt** there are `bootm`, `booti`, `go`, `tftpboot`, `loadb`,
  `loadx`, `loady`, `mtd`, `nand`, `nmbm`, `ubi`, `fip`, `bl2`, `md`, `mw`
  and `crc32`, among others. There is no `tftpput`: nothing sends data out
  over the network [measured].
- **The environment as received** has `dual_boot.current_slot=1`, and its
  `bootcmd` is a BOOTP and NFS line that the menu's default entry does not
  use [measured]. Owners give U-Boot's own address as 192.168.1.1 and its
  server as 192.168.1.10 [forum]; neither was set in ours.
- **Two slots.** MediaTek's dual-boot scheme: UBI volumes `kernel`/`rootfs`
  and `kernel2`/`rootfs2`, chosen by the variable `dual_boot.current_slot`.
  The environment is itself a UBI volume, `u-boot-env`, not the raw partition
  of that name [static: OpenWrt commit].
- **What it checks.** U-Boot verifies the kernel FIT and, separately, a hash
  over the squashfs, which it takes from a top-level `rootfs` node of that
  FIT; if either fails it tries the other slot [static: OpenWrt commit]. An
  image whose hash does not fit is refused with "rootfs verification failed"
  [forum].
- **It starts an image of ours from RAM.** Its own device tree has no
  `/signature` node, so it asks for no key. A FIT of our kernel, device tree
  and initramfs, each with a CRC32 and a SHA-1 as stock's have, sent to
  `0x50000000` with `loadx` and passed by `iminfo`, was started by `bootm`
  [measured]. U-Boot adds stock's `boot_param.*` words (the slots and their
  volume names) to the kernel's command line.
- Whether the first stages are signed is not known, and does not matter while
  they are left as they are.
- **What it checked on our unit.** It read `kernel2` and `rootfs2` (slot 1),
  checked the CRC32 and SHA-1 of the FIT's kernel and device tree and of the
  root file system, and said "Firmware integrity verification passed". Those
  are hashes, not signatures: nothing in the log verifies a key [measured].
- **Stock Linux** is 5.4.281, an OpenWrt from MediaTek's SDK built for the
  reference board `mediatek_mt7988a-dsa-10g-spim-nand` ("MediaTek MT7988A DSA
  10G SPIM-NAND RFB") [measured]; firmware versions 3.2.6, 3.2.7 and 3.3.3
  are spoken of [forum]. Its `sysupgrade` takes an OpenWrt image as it is,
  writes the slot that is not running, and restarts only with `-R` [static:
  OpenWrt commit]; [forum].
- **The radio under stock** is driven by MediaTek's own driver (`mt_wifi`,
  `mtk_hwifi`, `mt7990`), not mt76, with its settings in
  `/etc/wireless/mediatek/mt7990.b0.dat` to `.b2.dat` [measured].
- **The console under stock** offers failsafe mode ("Press the [f] key and
  hit [enter]") and then "Please press Enter to activate this console"
  [measured]; neither was answered.
- **Timeline of a stock boot**, from power-on: U-Boot's banner at 1.1 s, the
  menu at 5.9 s, the kernel started at 10.7 s, the failsafe offer at 30.4 s,
  the console offered at 37.7 s, the last kernel module loaded at 40.7 s
  [measured].
- **A stock boot writes to the flash.** It mounts `rootfs_data`, `config`,
  `config_bak` and `data` for writing, and each needed recovery when mounted
  ("recovery needed"), as after a power cut [measured]. A unit that has
  booted stock once is no longer as it arrived; ours was imaged first.
- **OpenWrt** supports the board since that commit: target
  `mediatek/filogic`, device `ltc_vl7m19k`, board name `ltc,vl7m19k`.

## Flash

256 MiB, of which 240 MiB are laid out and the rest is NMBM's. The offsets are
the device tree's [static], and stock U-Boot lists the same eight partitions
on its `nmbm0` [measured]:

| Partition | Offset | Size | |
| --- | --- | --- | --- |
| `BL2` | `0x0000000` | 1 MiB | first stage |
| `u-boot-env` | `0x0100000` | 512 KiB | not where the environment is |
| `Factory` | `0x0180000` | 4 MiB | the radio's calibration |
| `FIP` | `0x0580000` | 2 MiB | U-Boot |
| `ubi` | `0x0780000` | 192.5 MiB | both slots, the environment, the overlay |
| `config` | `0xc800000` | 10 MiB | stock's settings |
| `config_bak` | `0xd200000` | 10 MiB | |
| `data` | `0xdc00000` | 20 MiB | |

`Factory` holds the MT7996 calibration in its first `0x1e00` bytes, with the
radio's three addresses at `0x4`, `0xa` and `0x2c0`; the Ethernet addresses are
not stored but taken from the first of those, less 2 for the LAN and less 1
for the WAN [static: OpenWrt commit]. It is the one thing on the flash that
cannot be had again from anywhere else.

On our unit as received [measured]:

- **NMBM**: 2048 blocks, 1920 of them for data; its tables from block 1920
  (info tables at 1920 and 1923, write count 0), its signature in block 2047.
  No block was bad and none remapped, so the physical chip and `nmbm0` are the
  same over the first 240 MiB.
- **The `ubi` partition**: 1540 blocks, erase counters at most 8 and 5 on
  average, six volumes: `u-boot-env` (9 blocks reserved), `kernel` (29),
  `rootfs` (422), `rootfs_data` (579), `kernel2` (29) and `rootfs2` (366).
  `rootfs` and `rootfs2` each held 366 blocks of data, and `rootfs_data`
  already 11: the unit had run its own Linux before it reached us, at the
  factory by every sign.
- **`BL2`** holds 261 KiB, the **`FIP`** 784 KiB, and `u-boot-env` (the raw
  partition) nothing.
- **`Factory`** begins `90 79`, as the W1700K's calibration does, and holds
  data up to `0xf0fff`, well past the `0x1e00` bytes of the calibration.
- **Spare areas**: all 128 bytes `0xff` on each of five pages sampled across
  the chip.

## A Linux for it

The kernel that ran is the project's own Linux with another target of the same
OpenWrt [measured]:

- **Source**: Linux 6.18.52 and OpenWrt at the commit `platform/sources.json`
  pins, as for the W1700K, with OpenWrt's `target/linux/mediatek` in place of
  its `target/linux/airoha`: the generic patches and the 137 of
  `mediatek/patches-6.18` all apply.
- **Configuration**: OpenWrt's generic and `mediatek/filogic` configurations,
  and what a kernel with its root in an initramfs needs on top.
- **Device tree**: OpenWrt's `mt7988a-ltc-vl7m19k.dts` for the board, which
  that commit already has.
- **For a first start** the SPI-NAND was given no node, so no driver could
  find the flash (`/proc/mtd` was empty), the Ethernet addresses were random,
  and the radio was enumerated and left to no driver.

It reached its shell in 2.8 s with 946 MiB of its 980 MiB free, both of the radio's
interfaces, the four switch ports and both 10 GbE ports, and one complaint
(a reference clock of the USB 3 PHY). Its 5.3 MiB image went over the console
at 2 Mbaud in 36 s.

None of this is in the tree yet: the build was an experiment beside it.

## Reading a unit out

A unit can be backed up whole from stock U-Boot's prompt, with nothing written
to it and nothing of ours started on it. That is how the image of our unit was
made, before stock Linux first ran [measured]:

1. Stop U-Boot with Ctrl+C from its banner on.
2. Raise the console to 2 Mbaud in the UART's registers (above).
3. For each megabyte of `spi-nand0`, the physical chip: `mtd read` it into
   RAM, have `crc32` give the checksum of each 128 KiB block there, and print
   with `md.l` every block that is not all `0xff` (only its first 4 KiB where
   the rest is `0xff`, as in an empty UBI block).
4. Hold every printed block to U-Boot's checksum, and print it again if it
   differs.
5. Read the whole chip a second time and compare the checksums with the image.

The 256 MiB took 49 minutes, with 857 blocks printed whole and 1024 in part,
and the second pass three minutes more; it found all 2048 blocks equal.

## What differs from the W1700K

| | W1700K | Velo7 Max | |
| --- | --- | --- | --- |
| SoC | Airoha AN7581, four Cortex-A53 | MediaTek MT7988A, four Cortex-A73 | [photo]; [static] |
| DRAM | 2 GiB | 1 GiB on this unit | [photo] |
| Flash | 512 MiB, Airoha's bad-block table | 256 MiB, MediaTek's NMBM | [static] |
| Stock bootloader | U-Boot 2014.04, `ECNT>`, `tclinux` images | MediaTek U-Boot, `MT7988>`, FIT in UBI, two slots | [forum] |
| Radio | MT7996, `14c3:7990` and `14c3:7991`, MT7976 + 2 x MT7977 | the same | [measured] |
| Radio's second PCIe interface | Gen2, one lane | Gen3, two lanes | [measured] |
| 10 GbE | two RTL8261, Airoha's Ethernet | two RTL8261BE, MediaTek's Ethernet | [static] |
| Second processor | the AN7581's NPU | none of ours to use | |
| GPS, low-power radio | AG3352, EFR32MG21 | neither seen | [photo] |
| Status LED | four emitters | three colours | [static] |

What follows from it, before any measurement:

- **The platform is another one.** The toolchain's target is the same
  (aarch64), but the kernel configuration and device tree, the Ethernet
  driver, the flash handling ([`platform/bmt`](../../platform/bmt) is Airoha's
  table), the loader, the dumper and the restorer are the AN7581's, and
  [`include/hw/an7581`](../../include/hw/an7581) describes that chip.
- **The radio side should carry over, and that is not shown.** The radio
  firmware ([`firmware/`](../../firmware)) runs on the MT7996's own
  processors, and the driver ([`kernel/w1700k_sdr`](../../kernel/w1700k_sdr))
  is a PCI driver that polls. Two of its files know the AN7581: `led.c` (the
  LED's lines and generators) and `export.c` (a setting of Airoha's Ethernet).
  The unit-side tools for the GPS receiver, the low-power radio, the status
  LED and the reset-button key are the W1700K board's.
- **The stream ring does not fit.** The driver keeps received samples in a
  1 GiB ring, which is all the memory this unit has.
- **The reduced formats lean on the SoC.** Where the W1700K's packs part of a
  320 Msps stream on its own cores, this board has faster cores, half the
  memory and no NPU; what it can carry to a host has to be measured.

## Not yet known

In the order bring-up needs them:

1. Whether the project's driver and radio firmware run the radio here as
   they do on the W1700K.
2. The radio's crystal.
3. The `Factory` partition's layout against the W1700K's calibration, which
   begins `90 79`.
4. What the fifth antenna connector of each group is connected to.
5. Where the flash chip is on the board, and its full ID.
6. How fast the SoC can pass samples to a 10 GbE port, and how hot the board
   runs doing it without a fan.
