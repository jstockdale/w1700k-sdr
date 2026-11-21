# Platform: the Velo7 Max, started from RAM

The LTC Velo7 Max ([`docs/boards/vl7m19k.md`](../../docs/boards/vl7m19k.md)) has
the W1700K's radio, an MT7996, around another SoC, a MediaTek MT7988A. The
receiver runs on it as on the W1700K: the same driver, the same radio firmware
and the same host tools. What differs is everything under them, and this
directory is that: a kernel for the board and an image its stock U-Boot starts
from RAM.

Nothing is installed on the unit. The stock bootloader, the stock firmware and
the flash stay as they are, the kernel built here has no node for the flash,
and a power cycle brings the unit back up as it was sold.

## Building

| Step | Script | Output (under `platform/build/`) |
| --- | --- | --- |
| toolchain | `../rootfs/build.py toolchain` | the Buildroot cross toolchain and its busybox, dropbear and ethtool, as for the W1700K |
| kernel, driver | `build.py` | `velo7max/linux/arch/arm64/boot/Image`, `velo7max/linux/sdr/mt7988a-ltc-vl7m19k-sdr.dtb`, `velo7max/sdr/` (the module and the clients) |
| image | `image.py` | `images/velo7max-ram.itb` |

`make velo7max` in the repository root runs the three.

The kernel is the W1700K's Linux with another target of the same OpenWrt: both
come from the pins in [`../sources.json`](../sources.json), with OpenWrt's
`target/linux/mediatek` in place of its `target/linux/airoha`.

| File | What it is |
| --- | --- |
| `receiver.config` | what is asked of the kernel beyond OpenWrt's generic and `mediatek/filogic` configurations; the build fails if Kconfig drops a line of it |
| `dts/mt7988a-ltc-vl7m19k-sdr.dts` | OpenWrt's device tree for the board, less the flash, less the radio's mt76 node, and with the 10 GbE PHYs' reset lines held high as the vendor's tree has them |
| `patches/` | ours, after OpenWrt's: the Ethernet driver lets the stack send jumbo frames |
| `ramroot/init` | the RAM root's start-up: the 10 GbE ports, and management and ssh where the image has a login key |

Three things the board needs that are easy to lose, each with its reason in
the file that holds it:

- **The 10 GbE PHYs' patch built into the kernel** (`receiver.config`). Without
  it their driver puts its probe off without a word and the ports are dead.
- **Jumbo frames** (`patches/`). The export sends an 8 KiB slice as one
  datagram, and the driver's limit was 2030 bytes. Receiving is unchanged: the
  unit still takes nothing above 2 KiB.
- **No reset lines on the PHYs** (the device tree).

## The image

```sh
platform/velo7max/image.py                       # the serial console only
platform/velo7max/image.py --login-key ~/.ssh/id_ed25519.pub \
    --unit-dir ~/.local/share/w1700k/units/SERIAL     # and ssh, for that key
```

Without a login key the image lets nobody in but its serial console. With one
it runs an ssh server for that key alone, under the unit's own ssh identity
key: the one in the unit directory, made there on first use and kept, so the
host can check it. Its public half is written to `known_hosts` there. An image
made with a key is that unit's image.

| Option | Default | |
| --- | --- | --- |
| `--management PORT ADDRESS/LEN` | `lan0 192.168.1.1/24` | the switch port (the socket marked LAN 1) and address ssh is reached at |
| `--stream PORT ADDRESS/LEN` | `eth2 10.77.0.1/24` | the 10 GbE port the samples leave by, and its address; both 10 GbE ports come up with an MTU of 9194 |

The image is a FIT of the kernel (LZMA), the device tree and the initramfs,
each with a CRC32 and a SHA-1, which is what the stock U-Boot's own images
carry. It is written by `image.py` itself, without `mkimage`.

## Starting it

On the unit's serial console (three holes at the board's edge, 115200 8N1,
3.3 V; see the board's record):

1. Power the unit and send Ctrl+C from U-Boot's banner on. Ctrl+C leaves the
   boot menu for the prompt, `MT7988>`, without choosing an entry of it.
2. `loadx 0x50000000`, and send `velo7max-ram.itb` by XMODEM.
3. `iminfo 0x50000000`, which checks every hash, then `bootm 0x50000000`.

At 115200 the transfer takes about nine minutes. The console runs at 2 Mbaud
when the UART's registers are set directly, and the transfer then takes
40 seconds; the board's record has the register values. From the running
system `reboot -f` returns to U-Boot, so a new image needs no power cycle.

Then, from the host, with a configuration naming the unit
([`host/w1700k/README.md`](../../host/w1700k/README.md)):

```json
{"unit": {"host": "192.168.1.1", "known_hosts": "~/.local/share/w1700k/units/SERIAL/known_hosts"},
 "eeprom": "~/.local/share/w1700k/units/SERIAL/calibration.bin",
 "export": {"interface": "eth2"}}
```

`w1700k load`, `band`, `start` and the rest are the W1700K's. The calibration
is a file because the system cannot read the flash: it is the first `0x1e00`
bytes of the unit's `Factory` partition, taken from a backup of the unit.

## What is not here

- **An installation.** Nothing writes the unit's flash, and nothing here could.
- **The console's side.** Stopping U-Boot, the fast console, the XMODEM
  transfer and the backup of a unit's flash were done with scripts that are
  not in the tree yet.
- **A status LED, a GPS receiver, a low-power radio.** The board has none of
  the W1700K's, and the driver's LED code finds nothing to drive.
- **A link faster than 5 Gbit/s, both 10 GbE ports at once, and long runs**:
  not tried.
