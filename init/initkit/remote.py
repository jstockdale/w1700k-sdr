# SPDX-License-Identifier: MIT
"""Update an installed unit's root over the network alone (init/flash --rootfs --ssh).

Linux on the unit never writes its own system flash, so the new root is left in
durable storage with the running one beside it (platform/rootfs/overlay/usr/sbin/
system-update, sent along and run over ssh), and the unit is rebooted: its loader
writes the new root, reads it back and boots it. Once it is up and its storage
checks out it is confirmed. A new root that never answers is undone by a power
cycle: the loader finds it unconfirmed and puts the previous one back.

The loader must be one that applies staged updates; an older one is updated once
over the serial console (init/flash --loader).
"""
import hashlib
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

from . import bundle, config, layout, provision, seal
from .console import StepFailed

SCRIPT = config.ROOT / 'platform/rootfs/overlay/usr/sbin/system-update'
HOSTKEY = config.ROOT / 'platform/rootfs/overlay/usr/sbin/w1700k-hostkey'
LOGIN = config.ROOT / 'platform/rootfs/overlay/usr/sbin/w1700k-login'
NETWORK = config.ROOT / 'platform/rootfs/overlay/usr/sbin/w1700k-network'
STAGING = '/work/system-update.squashfs'      # in RAM on the unit
LOADER_STAGING = '/work/system-update.loader'
RELEASE_STAGING = '/work/system-update.release'
STATEMENT_STAGING = '/work/system-update.current'
STATEMENT_MOST = 4096           # bytes: a statement is a few hundred
CLOCK_SLACK_MS = 10 * 60 * 1000     # how far ahead of this host's clock a statement may be sealed
ROTATION_STAGING = '/work/system-update.keys'
DOWN_SECONDS = 90           # for a rebooting unit to stop answering
UP_SECONDS = 240            # for it to answer again: the loader's write, then the boot
POWER_CYCLE_SECONDS = 900   # for the operator to power-cycle a unit that did not come back


class Link:
    """Commands on the unit over ssh, as root, against the host key the unit told its installer."""

    def __init__(self, settings, directory, authorized_key=None):
        self.address = settings.device_ip
        self.argv = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                     '-o', f'UserKnownHostsFile={Path(directory) / provision.KNOWN_HOSTS}',
                     '-o', 'StrictHostKeyChecking=yes']
        private = Path(authorized_key).expanduser().with_suffix('') if authorized_key else None
        if private and private.is_file():       # the key the root is built to accept
            self.argv += ['-i', str(private)]
        self.argv.append(f'root@{self.address}')

    def call(self, command, data=None, timeout=120):
        """(exit status, stdout); 255 with '' when the unit does not answer."""
        try:
            result = subprocess.run(self.argv + [command], input=data, capture_output=True,
                                    timeout=timeout, **({} if data is not None else
                                                        {'stdin': subprocess.DEVNULL}))
        except subprocess.TimeoutExpired:
            return 255, ''
        text = result.stdout.decode(errors='replace')
        if result.returncode not in (0, 255):
            text += result.stderr.decode(errors='replace')
        return result.returncode, text


def login_keys(link):
    """The names of the login keys in the unit's list as its running root has it, or None on a
    root from before the list left the root (which has no such record)."""
    code, text = link.call('sh -s -- list', data=LOGIN.read_bytes(), timeout=60)
    return None if code else [line.split()[1] for line in text.splitlines() if line.startswith('login ')]


def check_paperclip_key(link):
    """Before a root goes over ssh to a unit that will have no login key in its list: the unit
    must have its paperclip key, switched on and kept by its loader, or nothing could log in to
    confirm the update (it would be undone by the next boot, and a unit that was reachable would
    have been made unreachable for that long)."""
    if login_keys(link):
        return
    code, text = link.call('/usr/sbin/w1700k-keyslot status')
    state = dict(line.split('=', 1) for line in text.splitlines() if '=' in line) if code == 0 else {}
    if state.get('slot') != 'on' or state.get('persist') != '1':
        raise StepFailed('with no login key in its list this unit would have no way in: its paperclip key is '
                         + {'off': 'switched off', 'empty': 'not set'}.get(state.get('slot'), 'unknown to its root')
                         + ('' if state.get('persist', '1') == '1' else ' and its loader does not keep one')
                         + '. Give it a key with its reset button first (init/key), and log in with that key')


def tool(link, *arguments, timeout=180):
    """Run system-update on the unit from this tree's copy; (exit status, its output)."""
    command = 'sh -s -- ' + ' '.join(shlex.quote(str(a)) for a in arguments)
    return link.call(command, data=SCRIPT.read_bytes(), timeout=timeout)


def keep_unit_keys(link, directory, loader_coming=False, no_login_key=False):
    """Before a root is staged: what is the unit's own is in its durable storage, and its loader
    hands it to the system: its ssh host key, its login keys and its network settings. No root
    holds any of them any more, so a unit that ran a root from before has what was built into
    that root carried across here, on the unit itself; the host key does not leave it. Without
    that the new root would come up as another unit, at another address, that lets nobody in,
    and the update would be undone.

    `directory`: the unit's, on this host; a network.conf in it states the unit's settings and
    is sent. `loader_coming`: a loader that hands all this over is staged with the root.
    `no_login_key`: the login key built into an old root is not carried; the unit's paperclip
    key is its way in."""
    code, text = link.call('sh -s -- keep', data=HOSTKEY.read_bytes(), timeout=180)
    if code:
        raise StepFailed("the unit's ssh host key could not be kept in its durable storage: "
                         f'{text.strip()[-300:]}')
    if not any(line.startswith('hostkey ') for line in text.splitlines()):
        raise StepFailed(f'the unit named no ssh host key that it keeps: {text.strip()[-300:]}')
    if not no_login_key:
        code, text = link.call('sh -s -- keep', data=LOGIN.read_bytes(), timeout=180)
        if code:
            raise StepFailed("the unit's login keys could not be kept in its durable storage: "
                             f'{text.strip()[-300:]}')
        if not any(line.startswith('login ') for line in text.splitlines()):
            check_paperclip_key(link)
    words = provision.network_settings(directory)
    verb = 'set ' + ' '.join(shlex.quote(word) for word in words) if words else 'keep'
    code, text = link.call(f'sh -s -- {verb}', data=NETWORK.read_bytes(), timeout=180)
    own = re.search(r'^own=(\d+)\s*$', text, re.M)
    if code or not own or (words and int(own.group(1)) != len(words)):
        raise StepFailed("the unit's network settings could not be kept in its durable storage: "
                         f'{text.strip()[-300:]}')
    code, text = link.call('cat /proc/cmdline', timeout=30)
    if code:
        raise StepFailed(f'the unit did not say how it was started: {text.strip()[-200:]}')
    handed = [('hostkey', 'ssh host key'), ('login', 'login keys')]
    if int(own.group(1)):               # a unit on the defaults needs nothing handed over
        handed.append(('net', 'network settings'))
    for word, what in handed:
        if not loader_coming and not re.search(rf'(?:^|\s)w1700k\.{word}=(?:handed|none)(?:\s|$)', text):
            raise StepFailed(f"the loader on this unit does not hand the unit's {what} to the system, and "
                             'this root holds none: update the loader with it (init/flash --ssh, or '
                             'init/flash --bundle FILE)')


def status(link):
    """system-update status as a dict; None when the unit does not answer."""
    code, text = tool(link, 'status')
    if code == 255:
        return None
    if code:
        raise StepFailed(f'the unit could not report its state: {text.strip()[-300:]}')
    return dict(line.split('=', 1) for line in text.splitlines() if '=' in line)


# What system-update is told when staging the loader and the root, by the terms admit() found.
STAGING_FLAGS = {'any': ([], []), 'unsigned': (['--unsigned'], ['--unsigned']), 'release': ([], [])}


def held_list(link):
    """The list of keys a keyed unit holds, read here as the unit reads it."""
    code, text = tool(link, 'keys')
    try:
        if code:
            raise seal.Refused(text.strip()[-300:])
        return seal.parse_list(text.encode('ascii', 'replace'))
    except seal.Refused as error:
        raise StepFailed(f"the unit's list of keys could not be read: {error}") from None


def catch_up(link, state, rotations):
    """Give a keyed unit the rotations it has not had, oldest first, before anything is judged
    by its keys: each is a complete list sealed by a key of the list before it, which the unit
    checks itself. Returns the unit's state afterwards. A rotation changes who is trusted and
    nothing else, so it needs nobody's word; a unit that holds no list is given none here."""
    if state.get('keys') != 'keyed' or not rotations:
        return state
    held, taken = held_list(link), 0
    for envelope in rotations:
        try:
            offered = seal.parse_list(seal.body_of(envelope))
            if offered.stamp < held.stamp:
                continue
            following, by = seal.rotated(held, envelope)
        except seal.Refused as error:
            # Said, and passed over: a rotation this unit does not take changes nothing on it,
            # and must not stand between it and a later one, or a release, that it does take.
            print(f'  KEYS: a rotation with this update is NOT one this unit takes (it holds list '
                  f'{held.label}): {error}')
            continue
        if by is None:
            continue
        code, text = link.call(f'cat > {ROTATION_STAGING}', data=envelope)
        if code:
            raise StepFailed(f'the rotation did not reach the unit: {text.strip()[-300:]}')
        code, text = tool(link, 'rotate', ROTATION_STAGING)
        if code:
            raise StepFailed(f'the unit does not take the rotation to list {offered.label}: '
                             f'{text.strip()[-300:]}')
        print(f'  keys: list {following.label}, sealed by {by.name} ({by.scope}, '
              f'{seal.fingerprint(by.public)})')
        held, taken = following, taken + 1
    if not taken:
        return state
    state = status(link)
    if state is None or state.get('key_generation') != held.label:
        raise StepFailed(f'the unit took the rotations and does not say it holds list {held.label}')
    return state


def fetch_statement(where, opener=urllib.request.urlopen):
    """(the sealed statement found at `where`, None), or (None, why not). `where` is a file's
    path or an http(s) address; nothing of the unit or its owner is sent to get it."""
    try:
        if re.match(r'https?://', str(where)):
            request = urllib.request.Request(str(where), headers={'User-Agent': 'w1700k-sdr'})
            with opener(request, timeout=15) as answer:
                data = answer.read(STATEMENT_MOST + 1)
        else:
            data = Path(where).expanduser().read_bytes()
    except (OSError, ValueError, urllib.error.URLError) as error:
        return None, str(error)
    if not 0 < len(data) <= STATEMENT_MOST:
        return None, f'{len(data)} bytes are not a statement'
    return data, None


def consult(link, state, where, terms, archive_release=None, now_ms=None, fetch=fetch_statement):
    """Hold a keyed unit and its update to the statement of what is current found at `where`.

    A unit takes the newest list and release it is given, so somebody who keeps a list from it
    decides where its keys stop. The statement says what there is: a timestamp key of the unit's
    own list sealed it, and this host has the clock to hold it to its dates. Whatever its dates,
    the unit is shown it and keeps the newest: a unit that has been shown a newer list than its
    own exists takes no release until it holds it.

    Nothing here locks an owner out. No statement, one that cannot be had, or one out of date
    is said, loudly, and the update goes on. Only a statement that is good stops an update: when
    it says the unit's list is superseded and this update does not bring the newer one, or that
    the archive (release `archive_release`) is older than the newest release."""
    def say(text):
        print('  CURRENT: ' + text)

    if state.get('keys') != 'keyed':
        return
    if not where:
        say('NOTHING WAS ASKED about what is current (no address: --current, or "current" in the settings). A list '
            'or a release this unit was never given would go unnoticed')
        return
    data, why = fetch(where)
    if data is None:
        say(f'the statement of what is current COULD NOT BE HAD from {where} ({why}). Going on without it')
        return
    held = held_list(link)
    try:
        statement, by = seal.read_statement(held, data)
        standing = seal.standing(held, statement)
    except seal.Refused as error:
        say(f'the statement at {where} SAYS NOTHING TO THIS UNIT: {error}. Going on without it')
        return
    if standing == 'older':
        say(f'the statement at {where} names list {statement.label}, older than the {held.label} this unit holds: '
            'it is OUT OF DATE and says nothing. Going on without it')
        return
    stamp = lambda ms: time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(ms / 1000))
    print(f'  current: list {statement.label}' + (f', release {statement.release}' if statement.release else ', no release')
          + f' (statement {statement.number}, sealed {stamp(statement.sealed_ms)} by {by.name}, good until '
          f'{stamp(statement.until_ms)})')
    # The unit keeps the newest it is shown, whatever its dates: it has no clock to hold them to.
    if 'current' in state and int(state.get('current_statement') or 0) < statement.number:
        code, text = link.call(f'cat > {STATEMENT_STAGING}', data=data)
        if code == 0:
            code, text = tool(link, 'current', STATEMENT_STAGING)
        if code:
            say(f'the unit did not keep the statement: {text.strip()[-200:]}')
    now = int(time.time() * 1000) if now_ms is None else now_ms
    if now >= statement.until_ms:
        say(f'THE STATEMENT IS OUT OF DATE: it was good until {stamp(statement.until_ms)}. What it says is not '
            'held against this update')
        return
    if statement.sealed_ms > now + CLOCK_SLACK_MS:
        say(f'the statement says it was sealed {stamp(statement.sealed_ms)}, which this host\'s clock has not '
            'reached: THE CLOCK OR THE STATEMENT IS WRONG. What it says is not held against this update')
        return
    if terms != 'release':
        if standing == 'behind':
            say(f'list {statement.label} is current and this unit holds {held.label}; this is a build of your own, '
                'which the unit takes on your word')
        return
    if standing == 'behind':
        raise StepFailed(f'list {statement.label} is current, and this unit holds list {held.label}: the keys it '
                         'trusts have been superseded, and this archive does not bring the newer list. Use a '
                         'release that carries it')
    if archive_release is not None and archive_release < statement.release:
        raise StepFailed(f'the archive is release {archive_release}, and release {statement.release} is current. '
                         'Use the current release')


def admit(link, state, sealed=None, unsigned=False):
    """On what terms this unit takes the update: 'any', 'unsigned' or 'release'. Nothing is
    sent here, and it is asked before anything else is decided, so that an archive the unit
    would refuse is refused even when the unit already has everything in it.

    A keyed unit takes what a release key of the list it holds sealed, and nothing older than
    the release it has settled on. `sealed` is the archive's sealed manifest, checked here
    against the unit's own list; present() then has the unit check it, which is what counts.
    A unit that was keyed and holds no list that reads takes nothing sealed at all. `unsigned`
    is the owner's word for a build of their own, which either kind takes."""
    regime = state.get('keys') or 'unkeyed'
    if regime == 'unkeyed':
        if sealed is not None:
            print('  the archive is a signed release, but this unit holds no list of keys: '
                  'nothing checks the seal')
        return 'any'
    if regime != 'keyed':
        said = (f'THIS UNIT WAS GIVEN A LIST OF KEYS AND HOLDS NONE THAT READS (its list: '
                f'{state.get("key_list") or "unknown"}). It takes nothing sealed until it is given a list '
                'again at the bench (init/bench key)')
        if not unsigned:
            raise StepFailed(said + '; --unsigned sends it a build of your own')
        print(f'  {said}.\n  Sending this as a build of your own (--unsigned)')
        return 'unsigned'
    keys = held_list(link)
    pinned = f'list {keys.label}: ' + (', '.join(
        f'{key.name} {seal.fingerprint(key.public)}' for key in keys.scoped('release')) or 'no release key')
    if unsigned:
        print(f'  this unit takes releases ({pinned}); sending this as a build of your own (--unsigned)')
        return 'unsigned'
    if sealed is None:
        raise StepFailed(f'this unit takes only releases sealed by a release key of its list ({pinned}): '
                         'give it a signed archive (init/flash --bundle), or pass --unsigned for a build '
                         'of your own')
    try:
        number, body, key = seal.unseal(sealed, keys.release_keys())
    except seal.Refused as error:
        raise StepFailed(f'the archive is not a release this unit takes ({pinned}): {error}') from None
    if not (state.get('release') or '0').isdigit():
        raise StepFailed('the number of the release this unit settled on does not read: it takes no release '
                         'until it is keyed at the bench again (init/bench key)')
    floor = int(state.get('release') or 0)
    if number < floor:
        raise StepFailed(f'the archive is release {number}; this unit has settled on release {floor} '
                         'and takes nothing older')
    # The number a unit settled on is one release: its manifest, by digest.
    if number == floor and state.get('release_manifest') not in (None, '', hashlib.sha256(body).hexdigest()):
        raise StepFailed(f'the archive is ANOTHER release {number} than the one this unit settled on: two '
                         'were sealed under one number')
    print(f'  release {number}, sealed by {seal.fingerprint(key)}')
    return 'release'


def present(link, terms, sealed):
    """Before staging: have the unit verify the release itself. Returns the flags for staging
    the loader and the root. Both are the release's own, and the unit checks each against the
    manifest."""
    if terms == 'release':
        code, text = link.call(f'cat > {RELEASE_STAGING}', data=sealed)
        if code:
            raise StepFailed(f'the release did not reach the unit: {text.strip()[-300:]}')
        code, text = tool(link, 'release', RELEASE_STAGING)
        if code:
            raise StepFailed(f'the unit does not take this release: {text.strip()[-300:]}')
    return STAGING_FLAGS[terms]


def wait(link, answering, seconds, clock, sleep):
    """True once the unit answers (or, with answering False, stops answering)."""
    deadline = clock() + seconds
    while clock() < deadline:
        code, _ = link.call('true', timeout=10)
        if (code == 0) == answering:
            return True
        sleep(2)
    return False


def run(settings, serial=None, authorized_key=None, link=None, clock=time.monotonic, sleep=time.sleep,
        no_login_key=False, unsigned=False):
    config.require_images(config.ROOTFS)
    serial = config.pick_unit(settings.data_dir, serial)
    directory = config.unit_dir(settings.data_dir, serial)
    image = provision.provision(directory, address=settings.device_ip)
    data = Path(image).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    link = link or Link(settings, directory, authorized_key)

    state = status(link)
    if state is None:
        raise StepFailed(f'the unit does not answer over ssh at {link.address}; '
                         'without it, update over the serial console (init/flash --rootfs)')
    print(f'flash: the unit runs root {state["running"][:12]}')
    if no_login_key and state['running'] != digest:
        check_paperclip_key(link)
    if state.get('boot') != 'installed':
        raise StepFailed('the unit runs from RAM, not from its installed root')
    if state['running'] == digest and state.get('staged') == digest:
        print('  rootfs: already written, by a run that did not get to confirm it')
        return confirm(link, digest)       # (its storage was checked when it booted)
    if state.get('staged') or state.get('tried') or state.get('failed'):
        print('  clearing an earlier update that was left staged')
        cancel(link)
    if state['running'] == digest:
        print('  rootfs: already current')
        return 0
    if state.get('loader') != 'applies':
        raise StepFailed('the loader on this unit does not apply staged updates: flash it '
                         'once over the serial console (init/flash --loader)')
    check_layout(link)
    keep_unit_keys(link, directory, no_login_key=no_login_key)
    _, root_flags = present(link, admit(link, state, unsigned=unsigned), None)

    print(f'  rootfs: sending {Path(image).name} ({len(data)} bytes)')
    code, text = link.call(f'cat > {STAGING}.part && mv {STAGING}.part {STAGING}', data=data, timeout=300)
    if code:
        raise StepFailed(f'the image did not reach the unit: {text.strip()[-300:]}')
    code, text = tool(link, 'stage', STAGING, digest, *root_flags, timeout=600)
    if code:
        raise StepFailed(f'the unit did not stage it: {text.strip()[-300:]}')
    print('  rootfs: staged; rebooting, and the loader writes it')
    link.call('reboot', timeout=20)
    if not wait(link, False, DOWN_SECONDS, clock, sleep):
        cancel(link)
        raise StepFailed('the unit did not reboot; nothing was written')

    if not wait(link, True, UP_SECONDS, clock, sleep):
        print(f'  the unit has not answered for {UP_SECONDS} s.\n'
              '  POWER-CYCLE THE UNIT NOW: its loader then puts the previous root back.\n'
              f'  waiting up to {POWER_CYCLE_SECONDS // 60} min')
        if not wait(link, True, POWER_CYCLE_SECONDS, clock, sleep):
            raise StepFailed('the unit does not answer; reach it over the serial console '
                             '(init/flash --detect-only)')
    # Its storage check first: it holds only while nothing has written flash since the boot,
    # and asking for the state opens durable storage.
    storage = link.call('/usr/sbin/verify-storage', timeout=120)
    state = status(link)
    if state is None:
        raise StepFailed('the unit stopped answering again')
    if state['running'] == digest:
        return confirm(link, digest, storage)
    failed = state.get('failed') == digest
    cancel(link)
    if failed:
        raise StepFailed('the new root was written but not kept: the loader has put the '
                         f'previous root ({state["running"][:12]}) back, and it runs')
    raise StepFailed(f'the loader did not write the new root; the previous one ({state["running"][:12]}) '
                     'runs. The serial console shows why (init/flash --detect-only)')


MTD_LINE = re.compile(r'^mtd\d+: ([0-9a-f]+) [0-9a-f]+ "([^"]+)"$', re.M)


def check_layout(link, expected=None):
    """The unit's flash is divided as these images expect (`expected`: {partition: (offset,
    size)}, default this tree's). A root built for another layout looks for its durable storage
    in the wrong place, and a loader for another would write there."""
    expected = expected or config.partitions.GEOMETRY
    code, text = link.call('cat /proc/mtd', timeout=30)
    if code:
        raise StepFailed(f'the unit did not list its flash partitions: {text.strip()[-200:]}')
    found = {name: int(size, 16) for size, name in MTD_LINE.findall(text)}
    wanted = {name: size for name, (_, size) in expected.items()}
    if found != wanted:
        raise StepFailed(layout.laid_out_differently(layout.differing(found, wanted)))


def run_joint(settings, serial=None, authorized_key=None, bundle_path=None, link=None,
              clock=time.monotonic, sleep=time.sleep, no_login_key=False, unsigned=False, current=None):
    """The loader and the root in one go, with one reboot: from the update archive at
    `bundle_path` (init/flash --bundle), or from this build's images. Both are staged, the
    first loader writes and starts the second, which writes the root, and once the system is
    up on both they are confirmed together. A part that is already what the unit has is left
    out; what is not confirmed is undone by the next boot, each part as it is alone."""
    serial = config.pick_unit(settings.data_dir, serial)
    directory = config.unit_dir(settings.data_dir, serial)
    layout = sealed = None
    rotations = []
    with tempfile.TemporaryDirectory(prefix='w1700k-update-') as temporary:
        if bundle_path is not None:
            manifest, files, sealed = bundle.read_release(bundle_path)
            rotations = bundle.rotations(bundle_path)
            layout, loader_data = manifest['partitions'], files[bundle.LOADER]
            generic = Path(temporary) / bundle.ROOT
            generic.write_bytes(files[bundle.ROOT])
        else:
            config.require_images(config.ROOTFS, config.LOADER_B)
            loader_data, generic = config.LOADER_B.read_bytes(), None
        root_data = Path(provision.provision(directory, address=settings.device_ip, generic=generic)).read_bytes()
    root, loader = hashlib.sha256(root_data).hexdigest(), hashlib.sha256(loader_data).hexdigest()
    link = link or Link(settings, directory, authorized_key)

    state = status(link)
    if state is None:
        raise StepFailed(f'the unit does not answer over ssh at {link.address}; '
                         'without it, update over the serial console (init/flash --system --loader)')
    if state.get('boot') != 'installed':
        raise StepFailed('the unit runs from RAM, not from its installed root')
    if state.get('loader') != 'applies' or state.get('second_loader', 'unsupported') == 'unsupported':
        raise StepFailed('the loader on this unit does not take updates of both: flash it once over '
                         'the serial console (init/flash --loader)')
    check_layout(link, layout)
    print(f'flash: the unit runs root {state["running"][:12]}, second loader '
          f'{state["second_loader"][:12] or "absent"}')
    state = catch_up(link, state, rotations)
    terms = admit(link, state, sealed, unsigned)
    consult(link, state, current, terms, int.from_bytes(sealed[22:30], 'little') if sealed else None)
    need_root, need_loader = state['running'] != root, state['second_loader'] != loader
    if no_login_key and need_root:
        check_paperclip_key(link)
    # Something still staged is an earlier run's; the loader's own notes without it are those of
    # an update that was settled, and go with the next boot.
    if state.get('staged') or state.get('loader_staged'):
        ours = (state.get('staged') in ('', root) and state.get('loader_staged') in ('', loader)
                and (state.get('staged') or state.get('loader_staged')))
        if ours and not need_root and not (state.get('loader_staged') and state.get('loader_booted') != loader) \
                and not need_loader:
            print('  already written, by a run that did not get to confirm it')
            return confirm_joint(link, root if state.get('staged') else None,
                                 loader if state.get('loader_staged') else None)
        print('  clearing an earlier update that was left staged')
        cancel(link)
    if not need_root and not need_loader:
        print('  loader and rootfs: already current')
        return 0
    if need_root:
        keep_unit_keys(link, directory, loader_coming=need_loader, no_login_key=no_login_key)
    loader_flags, root_flags = present(link, terms, sealed)

    for wanted, name, data, path, verb, flags in (
            (need_loader, 'loader', loader_data, LOADER_STAGING, 'stage-loader', loader_flags),
            (need_root, 'rootfs', root_data, STAGING, 'stage', root_flags)):
        if not wanted:
            print(f'  {name}: already current')
            continue
        print(f'  {name}: sending {len(data)} bytes')
        code, text = link.call(f'cat > {path}.part && mv {path}.part {path}', data=data, timeout=300)
        if code:
            raise StepFailed(f'the {name} image did not reach the unit: {text.strip()[-300:]}')
        code, text = tool(link, verb, path, hashlib.sha256(data).hexdigest(), *flags, timeout=600)
        if code:
            cancel(link)
            raise StepFailed(f'the unit did not stage the {name}: {text.strip()[-300:]}')
    print('  staged; rebooting once, and the loader does the writing')
    link.call('reboot', timeout=20)
    if not wait(link, False, DOWN_SECONDS, clock, sleep):
        cancel(link)
        raise StepFailed('the unit did not reboot; nothing was written')
    if not wait(link, True, UP_SECONDS, clock, sleep):
        print(f'  the unit has not answered for {UP_SECONDS} s.\n'
              '  POWER-CYCLE THE UNIT NOW: its first loader then undoes what was not confirmed.\n'
              f'  waiting up to {POWER_CYCLE_SECONDS // 60} min')
        if not wait(link, True, POWER_CYCLE_SECONDS, clock, sleep):
            raise StepFailed('the unit does not answer; reach it over the serial console '
                             '(init/flash --detect-only)')
    storage = link.call('/usr/sbin/verify-storage', timeout=120)
    state = status(link)
    if state is None:
        raise StepFailed('the unit stopped answering again')
    root_ok = not need_root or state['running'] == root
    loader_ok = not need_loader or (state.get('second_loader') == loader and state.get('loader_booted') == loader)
    if root_ok and loader_ok:
        return confirm_joint(link, root if need_root else None, loader if need_loader else None, storage)
    cancel(link)
    what = [text for ok, text in ((loader_ok, 'the new loader did not start, or was removed again'),
                                  (root_ok, f'the new root does not run (root {state["running"][:12]} does)'))
            if not ok]
    raise StepFailed('; '.join(what) + '. Nothing was confirmed: the unit is on what it had, or will be '
                     'after its next reboot. The serial console shows why (init/flash --detect-only)')


def confirm_joint(link, root, loader, storage=None):
    """The system is up on what was staged: with its storage check passed, have it kept."""
    if storage is not None and (storage[0] or 'W1700K_STORAGE_READY' not in storage[1]):
        raise StepFailed('the update runs but the storage check fails; it is left unconfirmed, and the '
                         f'next reboot undoes it: {storage[1].strip()[-300:]}')
    code, text = tool(link, 'confirm')
    if code:
        raise StepFailed(f'the update runs but could not be confirmed: {text.strip()[-300:]}')
    parts = [f'{name} {digest[:12]}' for name, digest in (('loader', loader), ('root', root)) if digest]
    print('flash: done; ' + ' and '.join(parts)
          + (' run and are confirmed' if len(parts) > 1 else ' runs and is confirmed'))
    return 0


def run_loader(settings, serial=None, authorized_key=None, link=None, clock=time.monotonic,
               sleep=time.sleep, unsigned=False):
    """A newer loader over ssh: the second loader (config.LOADER_B) is staged, the unit's first
    loader writes it to `loader-b` at the reboot and starts it, and once the system is up on
    it, it is confirmed. One that is never confirmed is removed by the first loader at the
    next boot; the loader stock boots is not written here at all."""
    config.require_images(config.LOADER_B)
    serial = config.pick_unit(settings.data_dir, serial)
    directory = config.unit_dir(settings.data_dir, serial)
    data = config.LOADER_B.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    link = link or Link(settings, directory, authorized_key)

    state = status(link)
    if state is None:
        raise StepFailed(f'the unit does not answer over ssh at {link.address}; '
                         'without it, update over the serial console (init/flash --loader)')
    if state.get('boot') != 'installed':
        raise StepFailed('the unit runs from RAM, not from its installed root')
    if state.get('second_loader', 'unsupported') == 'unsupported':
        raise StepFailed('the loader on this unit starts no second loader: flash it once over '
                         'the serial console (init/flash --loader)')
    check_layout(link)
    print(f'flash: the unit\'s second loader is {state["second_loader"][:12] or "absent"}')
    if state['second_loader'] == digest and state.get('loader_staged') == digest:
        print('  loader: already written, by a run that did not get to confirm it')
        return confirm_loader(link, digest)
    if any(state.get(key) for key in ('staged', 'tried', 'failed', 'loader_staged', 'loader_tried',
                                      'loader_failed')):
        print('  clearing an earlier update that was left staged')
        cancel(link)
    if state['second_loader'] == digest:
        print('  loader: already current')
        return 0

    loader_flags, _ = present(link, admit(link, state, unsigned=unsigned), None)
    print(f'  loader: sending {config.LOADER_B.name} ({len(data)} bytes)')
    code, text = link.call(f'cat > {LOADER_STAGING}.part && mv {LOADER_STAGING}.part {LOADER_STAGING}',
                           data=data, timeout=300)
    if code:
        raise StepFailed(f'the image did not reach the unit: {text.strip()[-300:]}')
    code, text = tool(link, 'stage-loader', LOADER_STAGING, digest, *loader_flags, timeout=600)
    if code:
        raise StepFailed(f'the unit did not stage it: {text.strip()[-300:]}')
    print('  loader: staged; rebooting, and the first loader writes and starts it')
    link.call('reboot', timeout=20)
    if not wait(link, False, DOWN_SECONDS, clock, sleep):
        cancel(link)
        raise StepFailed('the unit did not reboot; nothing was written')
    if not wait(link, True, UP_SECONDS, clock, sleep):
        print(f'  the unit has not answered for {UP_SECONDS} s.\n'
              '  POWER-CYCLE THE UNIT NOW: its first loader then removes the new one.\n'
              f'  waiting up to {POWER_CYCLE_SECONDS // 60} min')
        if not wait(link, True, POWER_CYCLE_SECONDS, clock, sleep):
            raise StepFailed('the unit does not answer; reach it over the serial console '
                             '(init/flash --detect-only)')
    storage = link.call('/usr/sbin/verify-storage', timeout=120)
    state = status(link)
    if state is None:
        raise StepFailed('the unit stopped answering again')
    if state.get('second_loader') == digest and state.get('loader_booted') == digest:
        return confirm_loader(link, digest, storage)
    failed = state.get('loader_failed') == digest
    cancel(link)
    if failed:
        raise StepFailed('the new loader was written but not kept: the first loader has removed '
                         'it, and the unit runs on the first loader alone')
    raise StepFailed('the new loader did not start; the unit runs on what it had. The serial '
                     'console shows why (init/flash --detect-only)')


def confirm_loader(link, digest, storage=None):
    """The system is up on the new loader: with its storage check passed, have it kept."""
    if storage is not None and (storage[0] or 'W1700K_STORAGE_READY' not in storage[1]):
        raise StepFailed('the new loader started the system but its storage check fails; it is left '
                         f'unconfirmed, and the next reboot removes it: {storage[1].strip()[-300:]}')
    code, text = tool(link, 'confirm')
    if code:
        raise StepFailed(f'the new loader runs but could not be confirmed: {text.strip()[-300:]}')
    print(f'flash: done; loader {digest[:12]} runs and is confirmed')
    return 0


def confirm(link, digest, storage=None):
    """The new root runs: with its storage check passed (`storage`, verify-storage's status
    and output from before anything else touched the unit), have it kept."""
    if storage is not None and (storage[0] or 'W1700K_STORAGE_READY' not in storage[1]):
        raise StepFailed('the new root runs but its storage check fails; it is left unconfirmed, '
                         f'and the next reboot puts the previous root back: {storage[1].strip()[-300:]}')
    code, text = tool(link, 'confirm')
    if code:
        raise StepFailed(f'the new root runs but could not be confirmed: {text.strip()[-300:]}')
    print(f'flash: done; root {digest[:12]} runs and is confirmed')
    return 0


def cancel(link):
    code, text = tool(link, 'cancel')
    if code:
        raise StepFailed(f'a staged update could not be cleared: {text.strip()[-300:]}')
