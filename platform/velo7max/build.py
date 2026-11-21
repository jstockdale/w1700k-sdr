#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build the Velo7 Max's Linux kernel, its device tree, and the driver and clients against it.

    platform/velo7max/build.py

The LTC Velo7 Max (docs/boards/vl7m19k.md) has the W1700K's radio around another SoC, a MediaTek
MT7988A. Its kernel is the project's Linux with another target of the same OpenWrt: Linux from
kernel.org and OpenWrt at the pinned commit, as for the W1700K (platform/linux), with OpenWrt's
`target/linux/mediatek` in place of its `target/linux/airoha`; then our patches. Requires the
Buildroot toolchain (platform/rootfs/build.py toolchain).

The configuration is OpenWrt's generic one and its `mediatek/filogic` one, then receiver.config.
The device tree is OpenWrt's for the board with what dts/mt7988a-ltc-vl7m19k-sdr.dts changes.

Outputs, under platform/build/velo7max/:

  linux/arch/arm64/boot/Image
  linux/sdr/mt7988a-ltc-vl7m19k-sdr.dtb
  sdr/w1700k_sdr.ko and the clients, built from kernel/w1700k_sdr against this kernel
"""
import importlib.util
import os
from pathlib import Path
import shutil
import sys

UNIT = Path(__file__).resolve().parent
sys.path.insert(0, str(UNIT.parent))
from buildlib import (BUILD, CROSS_COMPILE, LOGS, PLATFORM, SRC, apply_patches,  # noqa: E402
                      build_env, jobs, kconfig, main_guard, mark_prepared, patch_stamp, prepared,
                      require, run, sources, write_if_changed)
import fetch  # noqa: E402

OUT = BUILD / 'velo7max'
LINUX_SRC = SRC / 'linux-mt7988'
LINUX_OUT = OUT / 'linux'
KERNEL_IMAGE = LINUX_OUT / 'arch/arm64/boot/Image'
DTS = UNIT / 'dts/mt7988a-ltc-vl7m19k-sdr.dts'
DTB = LINUX_OUT / 'sdr' / (DTS.stem + '.dtb')
SDR_OUT = OUT / 'sdr'
MODULE = SDR_OUT / 'w1700k_sdr.ko'
FIRMWARE_DIR = BUILD / 'linux-firmware'
LOG = LOGS / 'velo7max.log'
# OpenWrt's kernel patch series, applied in this order before ours.
OPENWRT_PATCH_DIRS = ('target/linux/generic/backport-6.18',
                      'target/linux/generic/pending-6.18',
                      'target/linux/generic/hack-6.18',
                      'target/linux/mediatek/patches-6.18')
OPENWRT_FILE_DIRS = ('target/linux/generic/files',
                     'target/linux/mediatek/files',
                     'target/linux/mediatek/files-6.18')
OPENWRT_CONFIGS = ('target/linux/generic/config-6.18',
                   'target/linux/mediatek/filogic/config-6.18')
OPENWRT_DTS = 'target/linux/mediatek/dts'
# The device tree ours includes, and so the one that must be there.
OPENWRT_BOARD_DTS = 'mt7988a-ltc-vl7m19k.dts'


def w1700k_linux():
    """platform/linux/build.py, for what the two kernels share: the 10 GbE PHYs' patch."""
    spec = importlib.util.spec_from_file_location('w1700k_linux_build', PLATFORM / 'linux/build.py')
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(PLATFORM / 'linux'))
    spec.loader.exec_module(module)
    return module


def local_patches():
    return sorted((UNIT / 'patches').glob('*.patch'))


def openwrt_series(openwrt):
    """OpenWrt's patches for this target, in the order they are applied."""
    return [patch for directory in OPENWRT_PATCH_DIRS
            for patch in sorted((openwrt / directory).glob('*.patch'))]


def prepare_source():
    """Extract Linux, apply OpenWrt's series and ours; re-extract when either changes."""
    archive = fetch.linux_archive()
    openwrt = fetch.openwrt()
    require((openwrt / OPENWRT_DTS / OPENWRT_BOARD_DTS).is_file(),
            f'the pinned OpenWrt has no {OPENWRT_BOARD_DTS}: its commit is older than the board\'s support')
    stamp = patch_stamp(local_patches()) + sources()['linux']['sha256'] + \
        sources()['openwrt']['commit'] + ' mediatek'
    if not prepared(LINUX_SRC, stamp):
        print('velo7max: preparing the kernel source tree')
        fetch.extract(archive, LINUX_SRC)
        for directory in OPENWRT_FILE_DIRS:
            if (openwrt / directory).is_dir():
                shutil.copytree(openwrt / directory, LINUX_SRC, dirs_exist_ok=True)
        series = openwrt_series(openwrt)
        require(series, 'the OpenWrt checkout holds no kernel patches')
        apply_patches(LINUX_SRC, series + local_patches(), LOG)
        mark_prepared(LINUX_SRC, stamp)
    return openwrt


def kernel_make(*targets):
    run(['make', '-C', LINUX_SRC, f'O={LINUX_OUT}', 'ARCH=arm64',
         f'CROSS_COMPILE={CROSS_COMPILE}', f'-j{jobs()}', *targets],
        env=build_env(), log=LOG)


def merged_config(openwrt):
    """OpenWrt's two configurations and ours, as one text: a later line of it wins."""
    # Relative to the source tree, so no build path ends up in the kernel's own configuration.
    firmware = os.path.relpath(FIRMWARE_DIR, LINUX_SRC)
    parts = [(openwrt / name).read_text() for name in OPENWRT_CONFIGS]
    parts += [(UNIT / 'receiver.config').read_text(), f'CONFIG_EXTRA_FIRMWARE_DIR="{firmware}"\n']
    return ''.join(part if part.endswith('\n') else part + '\n' for part in parts)


def configure(openwrt):
    """OpenWrt's configuration with ours on top, then require that every request of ours survived."""
    LINUX_OUT.mkdir(parents=True, exist_ok=True)
    write_if_changed(LINUX_OUT / '.config', merged_config(openwrt))
    kernel_make('olddefconfig')
    resolved = kconfig(LINUX_OUT / '.config')
    dropped = [f'{key}={value}' for key, value in kconfig(UNIT / 'receiver.config').items()
               if resolved.get(key, 'n') != value]
    require(not dropped, 'Kconfig dropped requested settings: ' + ', '.join(dropped))


def device_tree(openwrt):
    """Preprocess and compile the board DTS against OpenWrt's device tree for the board."""
    kernel_make('scripts_dtc')
    DTB.parent.mkdir(parents=True, exist_ok=True)
    preprocessed = DTB.with_suffix('.dts.tmp')
    run([CROSS_COMPILE + 'gcc', '-E', '-nostdinc', '-undef', '-D__DTS__',
         '-x', 'assembler-with-cpp', '-I', LINUX_SRC / 'include',
         '-I', openwrt / OPENWRT_DTS, '-I', LINUX_SRC / 'arch/arm64/boot/dts/mediatek',
         DTS, '-o', preprocessed], env=build_env(), log=LOG)
    run([LINUX_OUT / 'scripts/dtc/dtc', '-@', '-I', 'dts', '-O', 'dtb', '-o', DTB,
         preprocessed], log=LOG)


def driver():
    """The w1700k_sdr module and the unit-side clients, against this kernel, in a place of their own."""
    run(['make', '-C', PLATFORM / 'linux', 'module', 'reader', f'KDIR={LINUX_OUT}',
         f'SDR_OUT={SDR_OUT}', f'CROSS_COMPILE={CROSS_COMPILE}'], env=build_env(), log=LOG)
    require(MODULE.is_file(), f'{MODULE} was not built')


def main():
    require(Path(CROSS_COMPILE + 'gcc').is_file(),
            'no cross compiler; run platform/rootfs/build.py toolchain first')
    openwrt = prepare_source()
    w1700k_linux().phy_firmware(openwrt)
    configure(openwrt)
    kernel_make('Image', 'modules')
    device_tree(openwrt)
    driver()
    print(f'velo7max: {KERNEL_IMAGE} ({KERNEL_IMAGE.stat().st_size} bytes), {DTB}, {MODULE}')
    return 0


if __name__ == '__main__':
    main_guard(main)
