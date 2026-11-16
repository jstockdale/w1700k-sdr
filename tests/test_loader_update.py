# SPDX-License-Identifier: MIT
"""The loader's staged updates (platform/loader/an7581_w1700k_sdr_env), run as they are written:
of the root (update_apply), and of the loader itself, which goes to a second partition that the
first loader starts (loader_next). The scripts are sh-compatible, so a POSIX shell executes them
here with U-Boot's commands (ubi, ubifsload, mtd, fdt, hash, env, saveenv, bootm ...) standing in
as functions over a model of the flash: the durable filesystem as a directory, the root volume and
the `loader-b` partition as files, the saved environment as a file. Each boot starts from what the
last one left. The system is started as the loader starts it, one stage of `bootm` at a time,
and what is added to the device tree's /chosen on the way is kept in `chosen`."""
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / 'platform' / 'loader' / 'an7581_w1700k_sdr_env'

# U-Boot's commands over the model in $M: durable/ (the UBIFS), rootfs (the volume), loaderb (the
# `loader-b` partition; absent: erased), saved (the environment in flash: name=value lines;
# absent: never saved or erased), ram/ADDR, log. A loader image is "FIT:<description>", a line of
# payload and "END": whole when the last line is there. $SLOT is b in the second loader, which is
# this same script started again by `bootm`, as the second loader is the same build.
HARNESS = r'''
note() { echo "$*" >> "$M/log"; }
# As in U-Boot: a variable set to nothing is gone, and `run` takes a script a boot made itself.
setenv() { if [ $# -ge 2 ] && [ -n "$2" ]; then eval "$1=\$2"; else unset "$1"; fi; }
run() {
    for name; do
        if [ -f "$M/env/$name" ]; then eval "$(cat "$M/env/$name")" || return 1
        else eval "eval \"\$$name\"" || return 1; fi
    done
}
saveenv() {
    note saveenv
    for name in update_tried update_failed loader_tried loader_failed loader_booted; do
        eval "[ -z \"\${$name+x}\" ]" || eval "echo \"$name=\$$name\""
    done > "$M/saved"
    for name in update_new update_old update_file update_want update_got loader_new loader_kind key_line key_on gps_v \
            host_ed25519 host_ecdsa \
            login_1 login_2 login_3 login_4 login_5 login_6 login_7 login_8 login_9 login_10 login_11 login_12 login_13 login_14 login_15 login_16 login_17 login_18 login_19 login_20 login_21 login_22 login_23 login_24 login_25 login_26 login_27 login_28 login_29 login_30 login_31 login_32; do
        eval "[ -z \"\${$name+x}\" ]" || { echo "saved a scratch variable: $name" >> "$M/log"; }
    done
}
env() {
    # A command of this loader takes sixteen words at most, its own name among them (seen on a
    # unit: an import naming more variables than that was refused, and read nothing).
    [ $# -lt 16 ] || { echo "env: more arguments than the loader takes" >&2; return 1; }
    case $1 in
    exists) eval "[ -n \"\${$2+x}\" ]" ;;
    erase) note "env erase"; rm -f "$M/saved" ;;
    import)
        [ "$2" = -t ] || return 1
        addr=$3; shift 4
        for name; do
            value=$(tr -d '\000' < "$M/ram/$addr" | sed -n "s/^$name=//p")
            [ -z "$value" ] || eval "$name=\$value"
        done ;;
    *) echo "env $*: not modelled" >&2; return 1 ;;
    esac
}
ubi() {
    case $1 in
    part.ro|part.rw)
        [ "$2" != durable ] || [ -d "$M/durable" ] || return 1
        attached=$2 mode=${1#part.} ;;
    write)
        [ "$attached" = system ] && [ "$mode" = rw ] && [ "$3" = rootfs ] || { echo "ubi write outside system rw" >&2; return 1; }
        note "write rootfs"
        head -c "$((0x$4))" "$M/ram/$2" > "$M/rootfs"
        if [ -e "$M/fail-write" ]; then
            rm "$M/fail-write"; printf garbage > "$M/rootfs"
        fi
        [ ! -e "$M/power-loss-after-write" ] || { rm "$M/power-loss-after-write"; note "power lost"; exit 0; } ;;
    read)
        [ "$attached" = system ] && [ "$3" = rootfs ] || return 1
        head -c "$((0x$4))" "$M/rootfs" > "$M/ram/$2" ;;
    *) echo "ubi $*: not modelled" >&2; return 1 ;;
    esac
}
ubifsmount() { [ "$attached" = durable ] && [ "$1" = ubi0:durable ] && mounted=1; }
ubifsumount() { mounted=0; }
ubifsload() {
    [ "$mounted" = 1 ] || return 1
    if [ -f "$M/durable/$2" ]; then
        cp "$M/durable/$2" "$M/ram/$1"
    else
        # As seen on a unit: this U-Boot's lookup of a name that is not there succeeds, and
        # what is loaded is the directory above it, 160 bytes of nothing. Only content counts.
        head -c 160 /dev/zero > "$M/ram/$1"
    fi
    filesize=$(printf %x "$(wc -c < "$M/ram/$1")")
}
# Registers, one file each in mem/ (hex, as `mw` was given it); one that was never written reads 0.
# setexpr NAME *ADDR OP VALUE, with the result in hex and no 0x, as U-Boot leaves it.
setexpr() {
    [ $# = 4 ] || { echo "setexpr $*: not modelled" >&2; return 1; }
    case $2 in \**) seen=$(cat "$M/mem/${2#\*}" 2>/dev/null || echo 0) ;; *) echo "setexpr $*: not modelled" >&2; return 1 ;; esac
    case $3 in
    '&') eval "$1=\$(printf %x \$(( 0x$seen & $4 )))" ;;
    '|') eval "$1=\$(printf %x \$(( 0x$seen | $4 )))" ;;
    *) echo "setexpr $*: not modelled" >&2; return 1 ;;
    esac
}
# The level register of GPIO 32 to 63 keeps a written bit only for a line that is an output; the
# others go on reading their pins (seen on a unit: a level written before the line was enabled
# was lost, and the line then drove what its pin had read).
mw() {
    [ $# = 2 ] || return 1
    mkdir -p "$M/mem"
    if [ "$1" = 0x1fbf0270 ]; then
        was=$(cat "$M/mem/$1" 2>/dev/null || echo 0) enabled=$(cat "$M/mem/0x1fbf0278" 2>/dev/null || echo 0)
        printf '%x\n' $(( (0x$2 & 0x$enabled) | (0x$was & ~0x$enabled & 0xffffffff) )) > "$M/mem/$1"
    else
        echo "$2" > "$M/mem/$1"
    fi
}
hash() {
    [ "$1" = sha256 ] || return 1
    eval "$4=\$(head -c \"\$((0x$3))\" \"\$M/ram/$2\" | sha256sum | cut -d' ' -f1)"
}
mtd() {
    [ "$2" = loader-b ] || { echo "mtd $*: not modelled" >&2; return 1; }
    case $1 in
    erase) note "erase loader-b"; rm -f "$M/loaderb" ;;
    write)
        [ "$4" = 0 ] || return 1
        note "write loader-b"
        head -c "$((0x${5#0x}))" "$M/ram/$3" > "$M/loaderb"
        if [ -e "$M/fail-loader-write" ]; then
            rm "$M/fail-loader-write"; printf 'FIT:torn' > "$M/loaderb"
        fi
        [ ! -e "$M/power-loss-after-loader-write" ] || { rm "$M/power-loss-after-loader-write"; note "power lost"; exit 0; } ;;
    read)
        if [ -f "$M/loaderb" ]; then
            if [ $# -ge 5 ]; then head -c "$((0x${5#0x}))" "$M/loaderb" > "$M/ram/$3"; else cp "$M/loaderb" "$M/ram/$3"; fi
        else
            head -c 4096 /dev/zero | tr '\000' '\377' > "$M/ram/$3"      # erased flash
        fi ;;
    *) echo "mtd $*: not modelled" >&2; return 1 ;;
    esac
}
fdt() {
    case $1 in
    addr) [ "$(head -c 4 "$M/ram/$2")" = FIT: ] && fdt_at=$2 ;;
    set)
        # Only the system's tree takes a property, and only once it is where it will be handed over.
        [ "$stage" = fdt ] && [ "$2" = /chosen ] && [ $# = 4 ] || { echo "fdt $*: not modelled" >&2; return 1; }
        printf '%s=%s\n' "$3" "$4" >> "$M/chosen" ;;
    get)
        [ "$2 $4 $5" = "value / description" ] || { echo "fdt $*: not modelled" >&2; return 1; }
        # The names of a tree's properties are at its end: nothing is found by name in an
        # image of which only the head is in RAM (seen on a unit: FDT_ERR_NOTFOUND).
        [ "$(tail -n 1 "$M/ram/$fdt_at")" = END ] || return 1
        eval "$3=\$(head -n 1 \"\$M/ram/\$fdt_at\" | cut -c5-)" ;;
    *) echo "fdt $*: not modelled" >&2; return 1 ;;
    esac
}
iminfo() { [ "$(tail -n 1 "$M/ram/$1")" = END ]; }
bootm() {
    # The system, a stage at a time and in order; `go` is the boot.
    case $1 in
    start) [ "$stage" = none ] && [ "$2" = "$loadaddr#$bootconf" ] || return 1; stage=start; return 0 ;;
    loados) [ "$stage" = start ] || return 1; stage=loados; return 0 ;;
    ramdisk) [ "$stage" = loados ] || return 1; stage=ramdisk; return 0 ;;
    fdt) [ "$stage" = ramdisk ] || return 1; stage=fdt; return 0 ;;
    prep) [ "$stage" = fdt ] || return 1; stage=prep; prepared=$bootargs; return 0 ;;
    go)
        [ "$stage" = prep ] || return 1
        for name in key_line key_on gps_v host_ed25519 host_ecdsa \
            login_1 login_2 login_3 login_4 login_5 login_6 login_7 login_8 login_9 login_10 login_11 login_12 login_13 login_14 login_15 login_16 login_17 login_18 login_19 login_20 login_21 login_22 login_23 login_24 login_25 login_26 login_27 login_28 login_29 login_30 login_31 login_32; do
            eval "[ -z \"\${$name+x}\" ]" || note "left a scratch variable: $name"
        done
        echo "$prepared" >> "$M/bootargs"
        note "booted $(sha256sum < "$M/rootfs" | cut -d' ' -f1)${SLOT:+ by the second loader}"
        exit 0 ;;
    esac
    [ "$1" = "$loader_b_at" ] && [ -z "$SLOT" ] || { echo "bootm $*: not modelled" >&2; return 1; }
    if [ -e "$M/second-hangs" ]; then note "the second loader hangs"; exit 0; fi
    note "the second loader starts"
    SLOT=b sh "$M/harness.sh"
    exit $?
}
attached=none mode=ro mounted=0 fdt_at= stage=none prepared=
mkdir -p "$M/ram"
rm -f "$M/chosen"
. "$M/defaults"
[ ! -f "$M/saved" ] || . "$M/saved"
[ -z "$SLOT" ] || loader_slot=$SLOT
run gps_off
run loader_next
run update_apply
run key_pass
run system_start
echo "the system was not started" >&2
exit 1
'''


def digest(data):
    return hashlib.sha256(data).hexdigest()


class Model(unittest.TestCase):
    """A unit's flash as the harness models it, and one boot of the loader on it."""
    OLD, NEW, NEWER = b'the root that runs' * 5000, b'the new root' * 9000, b'a later root' * 7000

    def setUp(self):
        self.model = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.model)
        (self.model / 'env').mkdir()
        (self.model / 'durable').mkdir()
        (self.model / 'rootfs').write_bytes(self.OLD)
        defaults = []
        for line in ENV_FILE.read_text().splitlines():
            name, _, value = line.partition('=')
            if '${' in value or ';' in value or name.startswith('update_') and ' ' in value:
                (self.model / 'env' / name).write_text(value)     # a script: run by name
            else:
                defaults.append(f"{name}='{value}'")
        (self.model / 'defaults').write_text('\n'.join(defaults) + '\n')
        (self.model / 'harness.sh').write_text(HARNESS)

    def stage(self, new, old, request=True):
        """What system-update stage leaves in durable storage."""
        staged = self.model / 'durable' / 'update'
        staged.mkdir(exist_ok=True)
        (staged / 'rootfs.new').write_bytes(new)
        (staged / 'rootfs.old').write_bytes(old)
        if request:
            (staged / 'request').write_text(f'update_new={digest(new)}\nupdate_old={digest(old)}\n')

    def settle(self):
        """What system-update confirm and cancel do."""
        shutil.rmtree(self.model / 'durable' / 'update')

    def boot(self):
        """One boot of the loader: what it logged since the last."""
        log = self.model / 'log'
        log.write_text('')
        environment = {k: v for k, v in os.environ.items() if k != 'SLOT'}
        result = subprocess.run(['sh', str(self.model / 'harness.sh')], env=dict(environment, M=str(self.model)),
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('not found', result.stderr)
        self.assertNotIn('not modelled', result.stderr)
        self.lines = log.read_text().splitlines()
        self.assertNotIn('saved a scratch variable', ' '.join(self.lines))
        return self.lines

    def root(self):
        return (self.model / 'rootfs').read_bytes()

    def saved(self):
        path = self.model / 'saved'
        return dict(line.split('=', 1) for line in path.read_text().splitlines()) if path.exists() else None

class LoaderUpdate(Model):
    def test_the_boot_command_applies_updates_first_and_then_boots_as_before(self):
        bootcmd = (self.model / 'env' / 'bootcmd').read_text()
        self.assertTrue(bootcmd.startswith('run gps_off; run loader_next; run update_apply; run key_pass; '
                                           'ubi part.ro ${bootpart} && ubi read'))
        self.assertTrue(bootcmd.endswith('iminfo ${loadaddr} && run system_start'))
        start = (self.model / 'env' / 'system_start').read_text()
        self.assertEqual(start, 'if bootm start ${loadaddr}#${bootconf} && bootm loados && bootm ramdisk && bootm fdt; '
                                'then run host_pass; run login_pass; bootm prep && bootm go; fi',
                         "the same boot, a stage at a time, with the unit's keys put in before the last two")

    def test_nothing_staged_nothing_written(self):
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'])
        self.assertIsNone(self.saved())
        shutil.rmtree(self.model / 'durable')                   # durable storage never formatted
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'])

    def test_a_staged_root_is_written_once_and_kept_when_confirmed(self):
        self.stage(self.NEW, self.OLD)
        self.assertEqual(self.boot(), ['write rootfs', 'saveenv', f'booted {digest(self.NEW)}'])
        self.assertEqual(self.root(), self.NEW)
        self.assertEqual(self.saved(), {'update_tried': digest(self.NEW)})
        self.settle()                                           # Linux came up and confirmed
        self.assertEqual(self.boot(), ['env erase', f'booted {digest(self.NEW)}'])
        self.assertIsNone(self.saved(), 'the saved environment is gone again: the loader runs on its defaults')
        self.assertEqual(self.boot(), [f'booted {digest(self.NEW)}'], 'and nothing more is written')

    def test_a_root_never_confirmed_is_undone_by_the_next_boot(self):
        self.stage(self.NEW, self.OLD)
        self.boot()
        self.assertEqual(self.root(), self.NEW)
        self.assertEqual(self.boot(), ['write rootfs', 'saveenv', f'booted {digest(self.OLD)}'], 'the power cycle')
        self.assertEqual(self.root(), self.OLD)
        self.assertEqual(self.saved(), {'update_failed': digest(self.NEW)})
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'], 'and it is not tried again')
        self.settle()
        self.assertEqual(self.boot(), ['env erase', f'booted {digest(self.OLD)}'])
        self.assertIsNone(self.saved())

    def test_another_root_after_a_failed_one_is_tried(self):
        self.stage(self.NEW, self.OLD)
        self.boot()
        self.boot()                                             # undone
        self.stage(self.NEWER, self.OLD)                        # staged without a boot in between
        self.assertEqual(self.boot(), ['write rootfs', 'saveenv', f'booted {digest(self.NEWER)}'])
        self.assertEqual(self.saved(), {'update_tried': digest(self.NEWER)})

    def test_a_staged_root_that_is_not_the_one_announced_is_not_written(self):
        self.stage(self.NEW, self.OLD)
        (self.model / 'durable' / 'update' / 'rootfs.new').write_bytes(self.NEW[:-1] + b'?')
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'])
        self.assertIsNone(self.saved())
        os.remove(self.model / 'durable' / 'update' / 'rootfs.new')
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'], 'nor one that is missing')

    def test_files_without_a_request_are_not_an_update(self):
        self.stage(self.NEW, self.OLD, request=False)           # staging was interrupted
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'])

    def test_a_write_that_does_not_read_back_puts_the_previous_root_back(self):
        self.stage(self.NEW, self.OLD)
        (self.model / 'fail-write').touch()
        self.assertEqual(self.boot(), ['write rootfs', 'write rootfs', 'saveenv', f'booted {digest(self.OLD)}'])
        self.assertEqual(self.saved(), {'update_failed': digest(self.NEW)})

    def test_power_lost_between_the_write_and_its_note_writes_again(self):
        self.stage(self.NEW, self.OLD)
        (self.model / 'power-loss-after-write').touch()
        self.assertEqual(self.boot(), ['write rootfs', 'power lost'])
        self.assertIsNone(self.saved())
        self.assertEqual(self.boot(), ['write rootfs', 'saveenv', f'booted {digest(self.NEW)}'])
        self.assertEqual(self.saved(), {'update_tried': digest(self.NEW)})

    def test_power_lost_while_going_back_goes_back_again(self):
        self.stage(self.NEW, self.OLD)
        self.boot()
        (self.model / 'power-loss-after-write').touch()
        self.assertEqual(self.boot(), ['write rootfs', 'power lost'])
        self.assertEqual(self.saved(), {'update_tried': digest(self.NEW)}, 'still marked as tried')
        self.assertEqual(self.boot(), ['write rootfs', 'saveenv', f'booted {digest(self.OLD)}'])


SECOND = 'W1700K SDR second ARM loader'


def loader_image(text, kind=SECOND):
    """Longer than the page the first loader reads to see whether anything is there."""
    return f'FIT:{kind}\n{text} {"." * 6000}\nEND\n'.encode()


class SecondLoader(LoaderUpdate):
    """The loader's own update: a second loader in `loader-b`, started by the first (which is
    never written here), kept once confirmed and removed when it was not."""
    B1, B2 = loader_image('a newer loader'), loader_image('a still newer loader')

    def stage_loader(self, image, announced=None, root=None):
        staged = self.model / 'durable' / 'update'
        staged.mkdir(exist_ok=True)
        (staged / 'loader.new').write_bytes(image)
        lines = [f'loader_new={announced or digest(image)}']
        if root:
            new, old = root
            (staged / 'rootfs.new').write_bytes(new)
            (staged / 'rootfs.old').write_bytes(old)
            lines += [f'update_new={digest(new)}', f'update_old={digest(old)}']
        (staged / 'request').write_text('\n'.join(lines) + '\n')

    def second(self):
        path = self.model / 'loaderb'
        return path.read_bytes() if path.exists() else None

    def by_second(self, root):
        return f'booted {digest(root)} by the second loader'

    def test_the_environment_and_the_build_agree(self):
        defaults = (self.model / 'defaults').read_text()
        self.assertIn("loader_slot='a'", defaults)
        self.assertIn(f"loader_b_kind='{SECOND}'", defaults)

    def test_a_staged_loader_is_written_started_and_kept_when_confirmed(self):
        self.stage_loader(self.B1)
        self.assertEqual(self.boot(), ['erase loader-b', 'write loader-b', 'saveenv', 'the second loader starts',
                                       'saveenv', self.by_second(self.OLD)])
        self.assertEqual(self.second(), self.B1)
        self.assertEqual(self.saved(), {'loader_tried': digest(self.B1), 'loader_booted': digest(self.B1)},
                         'the second loader says that it ran: what a confirmation waits for')
        self.settle()                                           # Linux came up on it and confirmed
        self.assertEqual(self.boot(), ['the second loader starts', 'env erase', self.by_second(self.OLD)])
        self.assertIsNone(self.saved())
        self.assertEqual(self.boot(), ['the second loader starts', self.by_second(self.OLD)],
                         'from then on: started at every boot, nothing written')
        self.assertEqual(self.second(), self.B1)

    def test_a_loader_never_confirmed_is_removed_by_the_next_boot(self):
        self.stage_loader(self.B1)
        self.boot()
        self.assertEqual(self.boot(), ['erase loader-b', 'saveenv', f'booted {digest(self.OLD)}'],
                         'the first loader, alone again')
        self.assertIsNone(self.second())
        self.assertEqual(self.saved(), {'loader_failed': digest(self.B1)})
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'], 'and it is not tried again')
        self.settle()
        self.assertEqual(self.boot(), ['env erase', f'booted {digest(self.OLD)}'])
        self.assertIsNone(self.saved())

    def test_a_second_loader_that_hangs_is_removed_after_the_power_cycle(self):
        self.stage_loader(self.B1)
        (self.model / 'second-hangs').touch()
        self.assertEqual(self.boot(), ['erase loader-b', 'write loader-b', 'saveenv', 'the second loader hangs'])
        self.assertEqual(self.saved(), {'loader_tried': digest(self.B1)}, 'it never said that it ran')
        self.assertEqual(self.boot(), ['erase loader-b', 'saveenv', f'booted {digest(self.OLD)}'])
        self.assertEqual(self.saved(), {'loader_failed': digest(self.B1)})

    def test_another_loader_after_a_failed_one_is_tried(self):
        self.stage_loader(self.B1)
        self.boot()
        self.boot()                                             # removed
        self.stage_loader(self.B2)
        self.assertEqual(self.boot()[-1], self.by_second(self.OLD))
        self.assertEqual(self.second(), self.B2)
        self.assertEqual(self.saved(), {'loader_tried': digest(self.B2), 'loader_booted': digest(self.B2)})

    def test_power_lost_between_the_write_and_its_note_writes_again(self):
        self.stage_loader(self.B1)
        (self.model / 'power-loss-after-loader-write').touch()
        self.assertEqual(self.boot(), ['erase loader-b', 'write loader-b', 'power lost'])
        self.assertIsNone(self.saved())
        self.assertEqual(self.boot()[:3], ['erase loader-b', 'write loader-b', 'saveenv'])
        self.assertEqual(self.lines[-1], self.by_second(self.OLD))

    def test_a_write_that_does_not_read_back_leaves_no_second_loader(self):
        self.stage_loader(self.B1)
        (self.model / 'fail-loader-write').touch()
        self.assertEqual(self.boot(), ['erase loader-b', 'write loader-b', 'erase loader-b',
                                       f'booted {digest(self.OLD)}'])
        self.assertIsNone(self.second())
        self.assertIsNone(self.saved())

    def test_what_is_not_the_announced_second_loader_is_not_written(self):
        self.stage_loader(self.B1, announced=digest(self.B2))   # not the one announced
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'])
        first = loader_image('the loader stock boots', 'W1700K SDR persistent ARM loader, staged-update 1')
        self.stage_loader(first)                                # whole, but a first loader
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'])
        self.stage_loader(b'not an image at all')
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'])
        self.assertIsNone(self.second())
        self.assertIsNone(self.saved())

    def test_a_damaged_or_foreign_second_loader_is_not_started(self):
        (self.model / 'loaderb').write_bytes(self.B1[:-4])       # the end is missing
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'])
        (self.model / 'loaderb').write_bytes(loader_image('stock firmware, or a first loader', 'something else'))
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'])
        (self.model / 'loaderb').write_bytes(b'\x01\x00\x64\xaa what stock left there')
        self.assertEqual(self.boot(), [f'booted {digest(self.OLD)}'])

    def test_a_loader_and_a_root_staged_together_are_both_applied(self):
        self.stage_loader(self.B1, root=(self.NEW, self.OLD))
        self.assertEqual(self.boot(), ['erase loader-b', 'write loader-b', 'saveenv', 'the second loader starts',
                                       'saveenv', 'write rootfs', 'saveenv', self.by_second(self.NEW)],
                         'the new loader writes the new root')
        self.assertEqual(self.saved(), {'loader_tried': digest(self.B1), 'loader_booted': digest(self.B1),
                                        'update_tried': digest(self.NEW)})
        self.settle()
        self.assertEqual(self.boot(), ['the second loader starts', 'env erase', self.by_second(self.NEW)])
        self.assertIsNone(self.saved())

    def test_a_loader_and_a_root_never_confirmed_are_both_undone(self):
        self.stage_loader(self.B1, root=(self.NEW, self.OLD))
        self.boot()
        self.assertEqual(self.boot(), ['erase loader-b', 'saveenv', 'write rootfs', 'saveenv',
                                       f'booted {digest(self.OLD)}'])
        self.assertIsNone(self.second())
        self.assertEqual(self.root(), self.OLD)
        self.assertEqual(self.saved(), {'loader_failed': digest(self.B1), 'update_failed': digest(self.NEW)})

    def test_a_root_update_does_not_disturb_a_second_loader_in_place(self):
        (self.model / 'loaderb').write_bytes(self.B1)
        self.stage(self.NEW, self.OLD)
        self.assertEqual(self.boot(), ['the second loader starts', 'write rootfs', 'saveenv', self.by_second(self.NEW)])
        self.assertEqual(self.saved(), {'update_tried': digest(self.NEW)})
        self.assertEqual(self.boot(), ['the second loader starts', 'write rootfs', 'saveenv', self.by_second(self.OLD)],
                         'never confirmed: the second loader puts the previous root back')
        self.assertEqual(self.second(), self.B1)


class GpsReceiver(Model):
    """The board's GPS receiver runs from power-on unless its power line is held low, and nothing
    of ours listens to it. The loader holds it off at the start of every boot, before any root
    runs, so every root has it off: line 43 of the pin controller, driven low."""
    DATA, ENABLE, DIRECTION = '0x1fbf0270', '0x1fbf0278', '0x1fbf0260'

    def registers(self, **values):
        (self.model / 'mem').mkdir(exist_ok=True)
        for name, value in values.items():
            (self.model / 'mem' / getattr(self, name)).write_text(f'{value:x}\n')

    def register(self, name):
        return int((self.model / 'mem' / getattr(self, name)).read_text(), 16)

    def test_the_line_is_driven_low_and_no_other_line_is_touched(self):
        # As the board comes up: line 43 high (bit 11), and line 46, the PHY's reset, driven high.
        self.registers(DATA=0x00004800, ENABLE=0x00004000, DIRECTION=0x10000000)
        self.boot()
        self.assertEqual(self.register('DATA'), 0x00004000, 'bit 11 low, bit 14 as it was')
        self.assertEqual(self.register('ENABLE'), 0x00004800, 'line 43 is an output')
        self.assertEqual(self.register('DIRECTION'), 0x10400000, 'two bits a line: bit 22 is line 43')
        self.assertIn(f'booted {digest(self.OLD)}', self.lines)

    def test_it_is_done_again_at_every_boot_and_by_the_second_loader(self):
        self.registers(DATA=0xffffffff, ENABLE=0, DIRECTION=0)
        (self.model / 'loaderb').write_bytes(b'FIT:W1700K SDR second ARM loader\nthe second loader\nEND\n')
        self.boot()
        self.assertIn('the second loader starts', self.lines)
        self.assertEqual((self.register('DATA'), self.register('ENABLE'), self.register('DIRECTION')),
                         (0xfffff7ff, 0x800, 0x400000))
        self.registers(DATA=0xffffffff, ENABLE=0x800, DIRECTION=0x400000)      # switched on since, by its owner
        self.boot()
        self.assertEqual(self.register('DATA'), 0xfffff7ff, 'on lasts until the unit next starts')

    def test_the_line_is_made_an_output_before_its_level_is_set(self):
        """A level written to a line that is not yet an output is lost on this chip, and the line
        then drives what its pin read, which for this one is high: the receiver, held on."""
        script = (self.model / 'env' / 'gps_off').read_text()
        self.assertLess(script.index('0x1fbf0278'), script.index('0x1fbf0270'))
        self.assertLess(script.index('0x1fbf0260'), script.index('0x1fbf0270'))
        wrong = ' && '.join(sorted(script.split('; setenv')[0].split(' && '), key=lambda step: '0x1fbf0270' not in step))
        (self.model / 'env' / 'gps_off').write_text(wrong + '; setenv gps_v')
        self.registers(DATA=0x00005ff9, ENABLE=0, DIRECTION=0)                # as read on a unit at its loader
        self.boot()
        self.assertEqual(self.register('DATA') & 0x800, 0x800, 'the other order leaves the line high, as it did on a unit')

    def test_it_comes_first_and_nothing_of_it_is_saved(self):
        bootcmd = (self.model / 'env' / 'bootcmd').read_text()
        self.assertTrue(bootcmd.startswith('run gps_off; '), 'before a second loader is started or an update applied')
        self.stage(self.NEW, self.OLD)
        self.boot()
        self.assertIn('saveenv', self.lines)
        self.assertNotIn('gps', ' '.join(self.saved()))


class KeySlot(Model):
    """The paperclip key's slot (durable `key/slot`, written by w1700k-keyslot): the loader reads it
    at every boot and hands it to Linux on the kernel command line, which never opens durable
    storage to find it."""
    KEY = 'ssh-ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIHRoaXMgaXMgbm90IGEgcmVhbCBrZXksIGJ1dCBvaw=='
    PLAIN = 'console=ttyS0,115200 earlycon panic=5 ro rdinit=/init ubi.mtd=system ubi.block=0,rootfs'
    NO_HOST = ' w1700k.hostkey=none w1700k.login=none'

    def slot(self, on, key=KEY):
        directory = self.model / 'durable' / 'key'
        directory.mkdir(exist_ok=True)
        (directory / 'slot').write_text(f'key_line={key}\nkey_on={on}\n')

    def bootargs(self):
        handed = self.model / 'bootargs'
        handed.unlink(missing_ok=True)
        self.boot()
        lines = handed.read_text().splitlines()
        self.assertEqual(len(lines), 1, 'one system is booted, with one command line')
        self.assertNotIn('left a scratch variable', ' '.join(self.lines))
        return lines[0]

    def test_no_slot_is_said_to_be_empty(self):
        self.assertEqual(self.bootargs(), self.PLAIN + ' w1700k.keyslot=empty' + self.NO_HOST)
        (self.model / 'durable' / 'key').mkdir()
        self.assertEqual(self.bootargs(), self.PLAIN + ' w1700k.keyslot=empty' + self.NO_HOST, 'a directory without the file')

    def test_a_key_that_is_on_is_handed_over(self):
        self.slot(1)
        self.assertEqual(self.bootargs(), f'{self.PLAIN} w1700k.keyslot=on w1700k.key={self.KEY}{self.NO_HOST}')

    def test_a_key_that_is_off_stays_in_the_slot(self):
        self.slot(0)
        args = self.bootargs()
        self.assertEqual(args, self.PLAIN + ' w1700k.keyslot=off' + self.NO_HOST)
        self.assertNotIn('AAAA', args)

    def test_every_boot_reads_the_slot_anew(self):
        self.slot(1)
        self.assertIn('w1700k.keyslot=on', self.bootargs())
        self.slot(0)
        self.assertEqual(self.bootargs(), self.PLAIN + ' w1700k.keyslot=off' + self.NO_HOST)
        shutil.rmtree(self.model / 'durable' / 'key')
        self.assertEqual(self.bootargs(), self.PLAIN + ' w1700k.keyslot=empty' + self.NO_HOST)

    def test_the_key_is_handed_over_beside_an_update_and_never_saved(self):
        self.slot(1)
        self.stage(self.NEW, self.OLD)
        args = self.bootargs()
        self.assertIn('write rootfs', self.lines)
        self.assertIn('saveenv', self.lines)
        self.assertEqual(args, f'{self.PLAIN} w1700k.keyslot=on w1700k.key={self.KEY}{self.NO_HOST}')
        self.assertNotIn('key', ' '.join(self.saved()))
        self.settle()
        self.assertEqual(self.bootargs(), f'{self.PLAIN} w1700k.keyslot=on w1700k.key={self.KEY}{self.NO_HOST}')

    def test_storage_that_cannot_be_read_hands_over_no_key(self):
        self.slot(1)
        (self.model / 'durable').rename(self.model / 'durable.gone')
        self.assertEqual(self.bootargs(), self.PLAIN + ' w1700k.keyslot=empty' + self.NO_HOST)

    def test_the_second_loader_hands_it_over_when_it_boots_the_system(self):
        self.slot(1)
        (self.model / 'loaderb').write_bytes(b'FIT:W1700K SDR second ARM loader\nthe second loader\nEND\n')
        args = self.bootargs()
        self.assertIn('the second loader starts', self.lines)
        self.assertEqual(args, f'{self.PLAIN} w1700k.keyslot=on w1700k.key={self.KEY}{self.NO_HOST}')


class HostKeys(KeySlot):
    """The unit's ssh host keys (durable `ssh/host`, written by w1700k-hostkey): the loader reads
    them at every boot and puts them into the device tree it hands to Linux, under names only
    root can read there. They are private keys: nothing of them goes on the kernel command line,
    which the kernel logs."""
    ED25519 = '0000000b7373682d6564323535313900000040' + 'a1' * 64
    ECDSA = '0000001365636473612d736861322d6e69737470323536' + 'b2' * 110
    HANDED = ' w1700k.hostkey=handed w1700k.login=none'
    test_no_slot_is_said_to_be_empty = test_a_key_that_is_on_is_handed_over = None
    test_a_key_that_is_off_stays_in_the_slot = test_every_boot_reads_the_slot_anew = None
    test_the_key_is_handed_over_beside_an_update_and_never_saved = None
    test_storage_that_cannot_be_read_hands_over_no_key = None
    test_the_second_loader_hands_it_over_when_it_boots_the_system = None

    def keys(self, text):
        directory = self.model / 'durable' / 'ssh'
        directory.mkdir(exist_ok=True)
        (directory / 'host').write_text(text)

    def chosen(self):
        path = self.model / 'chosen'
        return dict(line.split('=', 1) for line in path.read_text().splitlines()) if path.exists() else {}

    def test_a_unit_without_keys_is_told_so(self):
        self.assertEqual(self.bootargs(), self.PLAIN + ' w1700k.keyslot=empty' + self.NO_HOST)
        self.assertEqual(self.chosen(), {})
        (self.model / 'durable' / 'ssh').mkdir()
        self.assertTrue(self.bootargs().endswith(self.NO_HOST), 'a directory without the file')
        self.keys('')
        self.assertTrue(self.bootargs().endswith(self.NO_HOST), 'an empty file')
        self.assertEqual(self.chosen(), {})

    def test_a_key_goes_into_the_tree_and_not_onto_the_command_line(self):
        self.keys(f'host_ed25519={self.ED25519}\n')
        args = self.bootargs()
        self.assertEqual(args, self.PLAIN + ' w1700k.keyslot=empty' + self.HANDED)
        self.assertEqual(self.chosen(), {'security-w1700k-host-ed25519': self.ED25519})
        self.assertNotIn('a1a1', args)

    def test_a_key_of_each_kind_goes_in_under_its_own_name(self):
        self.keys(f'host_ecdsa={self.ECDSA}\nhost_ed25519={self.ED25519}\n')
        self.assertTrue(self.bootargs().endswith(self.HANDED))
        self.assertEqual(self.chosen(), {'security-w1700k-host-ed25519': self.ED25519,
                                         'security-w1700k-host-ecdsa': self.ECDSA})
        self.keys(f'host_ecdsa={self.ECDSA}\n')
        self.assertTrue(self.bootargs().endswith(self.HANDED))
        self.assertEqual(self.chosen(), {'security-w1700k-host-ecdsa': self.ECDSA})

    def test_nothing_else_in_the_file_reaches_the_loader(self):
        self.keys(f'bootargs=init=/bin/sh\nbootconf=conf-other\nloadaddr=0\nkey_line=ssh-ed25519:AAAA\nkey_on=1\n'
                  f'host_rsa=00\nhost_ed25519={self.ED25519}\n')
        self.assertEqual(self.bootargs(), self.PLAIN + ' w1700k.keyslot=empty' + self.HANDED)
        self.assertEqual(self.chosen(), {'security-w1700k-host-ed25519': self.ED25519})

    def test_every_boot_reads_them_anew_and_none_is_saved(self):
        self.keys(f'host_ed25519={self.ED25519}\n')
        self.stage(self.NEW, self.OLD)
        self.assertTrue(self.bootargs().endswith(self.HANDED))
        self.assertIn('write rootfs', self.lines)
        self.assertIn('saveenv', self.lines)
        self.assertEqual(self.chosen(), {'security-w1700k-host-ed25519': self.ED25519})
        self.assertNotIn('host', ' '.join(self.saved()))
        self.settle()
        (self.model / 'durable' / 'ssh' / 'host').unlink()
        self.assertTrue(self.bootargs().endswith(self.NO_HOST))
        self.assertEqual(self.chosen(), {})

    def test_the_keys_and_the_login_slot_are_handed_over_together(self):
        self.slot(1)
        self.keys(f'host_ed25519={self.ED25519}\n')
        self.assertEqual(self.bootargs(), f'{self.PLAIN} w1700k.keyslot=on w1700k.key={self.KEY}{self.HANDED}')
        self.assertEqual(self.chosen(), {'security-w1700k-host-ed25519': self.ED25519})

    def test_storage_that_cannot_be_read_hands_over_none(self):
        self.keys(f'host_ed25519={self.ED25519}\n')
        (self.model / 'durable').rename(self.model / 'durable.gone')
        self.assertTrue(self.bootargs().endswith(self.NO_HOST))
        self.assertEqual(self.chosen(), {})

    def test_the_second_loader_hands_them_over_when_it_boots_the_system(self):
        self.keys(f'host_ed25519={self.ED25519}\n')
        (self.model / 'loaderb').write_bytes(b'FIT:W1700K SDR second ARM loader\nthe second loader\nEND\n')
        self.assertTrue(self.bootargs().endswith(self.HANDED))
        self.assertIn('the second loader starts', self.lines)
        self.assertEqual(self.chosen(), {'security-w1700k-host-ed25519': self.ED25519})


class LoginKeys(HostKeys):
    """The keys that may log in as root (durable `ssh/login`, written by w1700k-login): up to
    thirty-two, one a line, which the loader reads at every boot and puts into the device tree.
    The loader names each line it takes, so the file can set nothing else in it."""
    A = 'ssh-ed25519:AAAAC3NzaC1lZDI1NTE5AAAAIGEgbG9naW4ga2V5IGZvciB0aGUgbW9kZWwsIG9uZSEh:desk'
    B = 'ssh-rsa:' + 'AAAAB3NzaC1yc2E' + 'A' * 701 + ':laptop'
    test_a_unit_without_keys_is_told_so = test_a_key_goes_into_the_tree_and_not_onto_the_command_line = None
    test_a_key_of_each_kind_goes_in_under_its_own_name = test_nothing_else_in_the_file_reaches_the_loader = None
    test_every_boot_reads_them_anew_and_none_is_saved = test_the_keys_and_the_login_slot_are_handed_over_together = None
    test_storage_that_cannot_be_read_hands_over_none = None
    test_the_second_loader_hands_them_over_when_it_boots_the_system = None

    def logins(self, *entries, text=None):
        directory = self.model / 'durable' / 'ssh'
        directory.mkdir(exist_ok=True)
        (directory / 'login').write_text(text if text is not None else
                                         ''.join(f'login_{n}={entry}\n' for n, entry in enumerate(entries, 1)))

    def test_a_unit_with_no_list_is_told_so(self):
        self.assertTrue(self.bootargs().endswith(' w1700k.hostkey=none w1700k.login=none'))
        self.logins()
        self.assertTrue(self.bootargs().endswith(' w1700k.login=none'), 'an empty list')
        self.assertEqual(self.chosen(), {})

    def test_each_key_goes_into_the_tree_under_its_place_in_the_list(self):
        self.logins(self.A, self.B)
        args = self.bootargs()
        self.assertTrue(args.endswith(' w1700k.hostkey=none w1700k.login=handed'))
        self.assertEqual(self.chosen(), {'w1700k,login-1': self.A, 'w1700k,login-2': self.B})
        self.assertNotIn('AAAA', args, 'eight keys would not fit a kernel command line')

    def test_thirty_two_are_handed_over_and_one_more_is_not(self):
        entries = [f'ssh-ed25519:AAAAC3NzaC1lZDI1NTE5AAAAI{n}:key-{n}' for n in range(1, 34)]
        self.logins(*entries)
        self.bootargs()
        self.assertEqual(self.chosen(), {f'w1700k,login-{n}': entries[n - 1] for n in range(1, 33)})
        # The loader's shell cannot look a variable up by a number made in a loop (tried on a
        # unit: every place got a junk value), so each place is written out; all are the same.
        scripts = {name: (self.model / 'env' / name).read_text() for name in
                   ('login_load', 'login_clear', 'login_pass', 'login_give_1', 'login_give_2', 'login_give_3', 'login_give_4')}
        self.assertEqual(scripts['login_load'].count('ubifsload ${update_spare} ssh/login'), 4,
                         'read again for each group: an import changes what it reads')
        for n in range(1, 33):
            self.assertRegex(scripts['login_load'], rf' login_{n}(;| )')
            self.assertRegex(scripts['login_clear'] + ';', rf'setenv login_{n};')
            self.assertIn(f'${{login_{n}}}"; then fdt set /chosen w1700k,login-{n} "${{login_{n}}}"; fi',
                          scripts[f'login_give_{(n + 7) // 8}'])
            self.assertIn(f'${{login_{n}}}', scripts['login_pass'])
        self.assertNotIn('login_33', ''.join(scripts.values()))
        build = (ROOT / 'platform/loader/an7581_w1700k_sdr_defconfig').read_text()
        self.assertIn('CONFIG_SYS_FDT_PAD=0x10000\n', build, 'room in the tree for all of them at their longest')

    def test_a_gap_in_the_list_loses_nothing(self):
        self.logins(text=f'login_2={self.A}\nlogin_7={self.B}\n')
        self.assertTrue(self.bootargs().endswith(' w1700k.login=handed'))
        self.assertEqual(self.chosen(), {'w1700k,login-2': self.A, 'w1700k,login-7': self.B})

    def test_nothing_else_in_the_list_reaches_the_loader(self):
        self.logins(text=f'bootargs=init=/bin/sh\nhost_ed25519={self.ED25519}\nkey_line=ssh-ed25519:AAAA\nkey_on=1\n'
                         f'login_33={self.A}\nlogin_0={self.A}\nlogin_1={self.A}\nlogin_give_1=reset\nlogin_clear=reset\n')
        self.assertEqual(self.bootargs(), self.PLAIN + ' w1700k.keyslot=empty w1700k.hostkey=none w1700k.login=handed')
        self.assertEqual(self.chosen(), {'w1700k,login-1': self.A})

    def test_every_boot_reads_the_list_anew_and_none_of_it_is_saved(self):
        self.logins(self.A)
        self.stage(self.NEW, self.OLD)
        self.bootargs()
        self.assertIn('saveenv', self.lines)
        self.assertEqual(self.chosen(), {'w1700k,login-1': self.A})
        self.assertNotIn('login', ' '.join(self.saved()))
        self.settle()
        self.logins(self.B)
        self.bootargs()
        self.assertEqual(self.chosen(), {'w1700k,login-1': self.B})
        (self.model / 'durable' / 'ssh' / 'login').unlink()
        self.assertTrue(self.bootargs().endswith(' w1700k.login=none'))
        self.assertEqual(self.chosen(), {})

    def test_the_list_the_identity_key_and_the_paperclip_key_are_handed_over_together(self):
        self.slot(1)
        self.keys(f'host_ed25519={self.ED25519}\n')
        self.logins(self.A)
        self.assertEqual(self.bootargs(), f'{self.PLAIN} w1700k.keyslot=on w1700k.key={self.KEY} w1700k.hostkey=handed w1700k.login=handed')
        self.assertEqual(self.chosen(), {'security-w1700k-host-ed25519': self.ED25519, 'w1700k,login-1': self.A})

    def test_storage_that_cannot_be_read_hands_over_no_list(self):
        self.logins(self.A)
        (self.model / 'durable').rename(self.model / 'durable.gone')
        self.assertTrue(self.bootargs().endswith(' w1700k.login=none'))
        self.assertEqual(self.chosen(), {})

    def test_the_second_loader_hands_the_list_over_when_it_boots_the_system(self):
        self.logins(self.A)
        (self.model / 'loaderb').write_bytes(b'FIT:W1700K SDR second ARM loader\nthe second loader\nEND\n')
        self.assertTrue(self.bootargs().endswith(' w1700k.login=handed'))
        self.assertIn('the second loader starts', self.lines)
        self.assertEqual(self.chosen(), {'w1700k,login-1': self.A})


if __name__ == '__main__':
    unittest.main()
