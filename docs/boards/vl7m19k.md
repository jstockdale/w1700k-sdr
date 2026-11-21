# LTC Velo7 Max (VL7M19K)

The Velo7 Max has the W1700K's radio, a MediaTek MT7996, on another maker's
board around another SoC, a MediaTek MT7988A. This is the intake record of one
unit: what was read from its board and labels, what public sources say about
the model, and what has to be found out before anything of ours runs on it.

**Nothing here has been measured on a unit yet.** No image of this project has
been built for the board, and none of the existing ones runs on it: they are
the AN7581's.

Every line carries where it comes from:

- **[photo]** a marking or a part read from the board of one unit in hand
  (its label says made by Tozed Kangwei; opened 2026-11-20, never powered by
  us).
- **[static]** from a document or another source tree, which is named. Two
  carry most of it: OpenWrt's commit `25f6620614ac` ("mediatek: add support
  for LTC Velo7 Max", 2026-07-31) with its device tree
  `mt7988a-ltc-vl7m19k.dts`, and the model's FCC grant, `2A5LO-VL7M19K`.
- **[forum]** from the OpenWrt forum thread on the model ("LTC Velo7 Max
  router", topic 250792): owners' posts, not checked by anyone here. Good for
  knowing what to look for, not for relying on.
- **[measured]** on a unit, by us. None so far.

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
| SoC | MediaTek MT7988AV, date code 2441: four Cortex-A73 at 1.8 GHz | [photo]; [static: OpenWrt commit] |
| DRAM | two Nanya NT5AD256M16E4-JR, DDR4, 4 Gbit each: 1 GiB | [photo] |
| Flash | Winbond W25N02KV, 256 MiB SPI-NAND, bad blocks managed by MediaTek's NMBM | [static: OpenWrt commit]; not found in our photos |
| eMMC | a footprint beside the SoC, not populated | [photo] |
| Radio | MediaTek MT7996, on both of the SoC's two-lane PCIe interfaces; its reset on GPIO 7 | [static: OpenWrt commit, device tree] |
| Radio, on the board | one chip under a thermal pad in its own shield frame between the SoC and the RF section, and three closed shield cans; none opened, no marking read | [photo] |
| 10 GbE PHYs | two Realtek RTL8261BE, at MDIO 6 and 7, USXGMII; resets on GPIO 77 and GPIO 10 | [static: device tree] |
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
[forum]. It is the SoC's UART at `0x11000000` [static: device tree].

## Stock boot chain

All of this is from others' units, and none of it has been seen on ours.

- **Bootloader.** MediaTek's: a first stage (`BL2`), then a `FIP` holding
  U-Boot [static: flash layout]. Its prompt is `MT7988>`, it waits five
  seconds (`bootdelay=5`), and its menu has a web recovery (`httpd`) and an
  image loader (`mtkload`). Its own address is 192.168.1.1 and it looks for a
  server at 192.168.1.10 [forum].
- **Two slots.** MediaTek's dual-boot scheme: UBI volumes `kernel`/`rootfs`
  and `kernel2`/`rootfs2`, chosen by the variable `dual_boot.current_slot`.
  The environment is itself a UBI volume, `u-boot-env`, not the raw partition
  of that name [static: OpenWrt commit].
- **What it checks.** U-Boot verifies the kernel FIT and, separately, a hash
  over the squashfs, which it takes from a top-level `rootfs` node of that
  FIT; if either fails it tries the other slot [static: OpenWrt commit]. An
  image whose hash does not fit is refused with "rootfs verification failed"
  [forum]. Whether the first stages are signed, and whether U-Boot will start
  an image given to it in RAM, is in none of the sources.
- **Stock Linux** is OpenWrt 21.02 from MediaTek's SDK, built for the
  reference board `mediatek_mt7988a-dsa-10g-spim-nand`; firmware versions
  3.2.6, 3.2.7 and 3.3.3 are spoken of. Its `sysupgrade` takes an OpenWrt
  image as it is, writes the slot that is not running, and restarts only with
  `-R` [static: OpenWrt commit]; [forum].
- **OpenWrt** supports the board since that commit: target
  `mediatek/filogic`, device `ltc_vl7m19k`, board name `ltc,vl7m19k`.

## Flash

256 MiB, of which 240 MiB are laid out and the rest is NMBM's [static: device
tree]:

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

On a stock unit the `ubi` partition held six volumes: `u-boot-env`, `kernel`
(3.5 MiB), `rootfs`, `rootfs_data`, `kernel2` and `rootfs2` [forum].

## What differs from the W1700K

| | W1700K | Velo7 Max | |
| --- | --- | --- | --- |
| SoC | Airoha AN7581, four Cortex-A53 | MediaTek MT7988A, four Cortex-A73 | [photo]; [static] |
| DRAM | 2 GiB | 1 GiB on this unit | [photo] |
| Flash | 512 MiB, Airoha's bad-block table | 256 MiB, MediaTek's NMBM | [static] |
| Stock bootloader | U-Boot 2014.04, `ECNT>`, `tclinux` images | MediaTek U-Boot, `MT7988>`, FIT in UBI, two slots | [forum] |
| Radio | MT7996 on PCIe | MT7996 on PCIe | [static] |
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

1. The stock boot log, from the first byte, with nothing sent to the unit.
2. Whether stock U-Boot starts an image staged in RAM, and what it checks of
   one.
3. Whether the first stages are signed and the SoC's secure boot is on.
4. The radio's PCI IDs and link (the W1700K's are `14c3:7990` and `14c3:7991`,
   Gen3 x2), and whether its two interfaces are wired as the W1700K's are.
5. The front ends in the three cans (the W1700K has an MT7976 and two
   MT7977), and the radio's crystal.
6. The `Factory` partition's layout against the W1700K's calibration, which
   begins `90 79`.
7. What the fifth antenna connector of each group is connected to.
8. Where the flash chip is, and its ID.
9. How fast the SoC can pass samples to a 10 GbE port, and how hot the board
   runs doing it without a fan.
