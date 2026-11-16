# SPDX-License-Identifier: MIT
"""At the bench: give a unit its first list of keys, on its serial console.

A keyed unit takes only what a key of its list sealed, and its list changes only by a list
sealed by a key of it. The first list has nothing before it to be checked against: it names
the root key that sealed it. What makes it the right list is the person at the bench, who
holds the fingerprints of its root and keys keys to the record of how they were issued before
anything is sent. That, and a hand on the unit, is what a unit's trust starts from; so the
unit takes a first list on its serial console and nowhere else (`system-update first`).

Before the list the unit is marked as keyed: `w1700k_keyed=1` in the stock boot loader's
environment, set here at that loader's prompt. Nothing a unit is sent over the network, and no
update, writes there; it is where the unit's bootcmd is kept, and it outlives durable storage.
A marked unit with no list takes nothing sealed, so the mark goes first and comes off last.

Rotations that came after the first list are given straight after it, as a unit in the field
would get them.
"""
import hashlib

from . import bundle, console as unit, seal, stock
from .console import StepFailed, command
from .session import open_session

STAGING = '/tmp/w1700k-keys.wms2'
MARK = 'w1700k_keyed'
CHUNK = 40      # bytes to a line: the console's line discipline holds a line of 4096 characters


def in_order(envelopes):
    """Sealed lists as a unit is given them: by epoch, and in an epoch by generation."""
    return sorted(envelopes, key=lambda envelope: seal.parse_list(seal.body_of(envelope)).stamp)


def put(console, path, data):
    """Write `data` to `path` on the unit through its console, and check what arrived."""
    command(console, f': > {path}', limit=20, strict=False)
    for start in range(0, len(data), CHUNK):
        octal = ''.join(f'\\{byte:03o}' for byte in data[start:start + CHUNK])
        command(console, f"printf '{octal}' >> {path}", limit=20, strict=False)
    command(console, f'sha256sum {path}', expect=hashlib.sha256(data).hexdigest(), limit=20, strict=False)


def to_linux(console, log):
    state = unit.identify(console, log)
    if state != 'linux':
        unit.to_stock(console, log, state)
        unit.boot_linux(console, log)


def mark(console, log, on):
    """At the stock boot loader's prompt, which the unit is restarted to reach: set or clear
    the mark that it is keyed, and see that stock kept it. Then boot the installed system."""
    unit.to_stock(console, log, unit.identify(console, log))
    command(console, f'setenv {MARK} 1' if on else f'setenv {MARK}', limit=20)
    command(console, 'saveenv', limit=120)
    saved = stock.environment(console).get(MARK)
    if saved != ('1' if on else None):
        raise StepFailed(f"stock's environment has {MARK}={saved!r} after saving it")
    log.event('keyed_mark', on=on)
    unit.boot_linux(console, log)


def state_of(console):
    text = command(console, '/usr/sbin/system-update status', limit=120, strict=False)
    return dict(line.strip().split('=', 1) for line in text.splitlines() if '=' in line)


def authorities(keys):
    """The lines a person holds to the issuance record: every key of the list, the root and
    keys keys first, numbered, so that one too many is seen as surely as one that differs."""
    lines = []
    for number, key in enumerate(keys.scoped('root', 'keys') + keys.scoped('release', 'timestamp'), 1):
        lines += [f'  {number}. {key.scope:<7} {key.name}', f'        {key.public.hex()}',
                  f'        {seal.fingerprint(key.public)} (as a unit prints it) / '
                  f'{seal.registry_fingerprint(key.public)} (registry)']
    return '\n'.join(lines)


def key(settings, rotations, ask=input):
    """Give the unit on the console the list the sealed lists `rotations` (the first list,
    then any that followed it) leave it holding."""
    if not rotations:
        raise StepFailed('no sealed list was given')
    final = bundle.chain(rotations)             # each follows from the one before, or nothing is sent
    first, _ = seal.rotated(None, rotations[0])
    several = len(first.scoped('root', 'keys'))
    print(f'bench: the first list is {first.label} and holds {len(first.keys)} keys. Its '
          f'{several} root and keys keys decide everything this unit will ever trust, and any ONE root '
          f'key can replace all the others:\n{authorities(first)}')
    if ask(f'bench: hold each of the {len(first.keys)} to the issuance record, key and fingerprint in '
           f'full. Are these the keys, all of them and no other? (yes to go on) ').strip() != 'yes':
        raise StepFailed('not confirmed; nothing was sent to the unit')
    with open_session(settings, 'bench', write=True, network=False) as session:
        console = session.console
        to_linux(console, session.log)
        state = state_of(console)
        if state.get('key_list') == 'good':
            raise StepFailed(f'this unit holds a list of keys ({state.get("key_generation")}): '
                             'a new one reaches it as a rotation, or unkey it first (init/bench unkey)')
        if 'key_mark' not in state:
            raise StepFailed('the system on this unit knows nothing of lists of keys: update it first')
        if state.get('key_mark') != 'yes':
            print('bench: marking the unit as keyed, at the stock boot loader')
            mark(console, session.log, True)
        put(console, STAGING, rotations[0])
        command(console, f'/usr/sbin/system-update first {STAGING}', limit=180, strict=False)
        for envelope in rotations[1:]:
            put(console, STAGING, envelope)
            command(console, f'/usr/sbin/system-update rotate {STAGING}', limit=180, strict=False)
        command(console, '/usr/sbin/system-update keys | sha256sum',
                expect=hashlib.sha256(final.text).hexdigest(), limit=120, strict=False)
        state = state_of(console)
    if state.get('keys') != 'keyed' or state.get('key_generation') != final.label:
        raise StepFailed(f'the unit does not say it is keyed with list {final.label}: {state}')
    print(f'bench: the unit is keyed and holds list {final.label}:')
    for held in final.keys:
        print(f'  {held.scope:<7} {held.name}  {seal.fingerprint(held.public)}')
    return 0


def unkey(settings, ask=input):
    """Take the unit on the console back to holding no list and no mark: it takes any update."""
    if ask('bench: this unit will take ANY update afterwards, sealed or not. Unkey it? (yes to go on) ') \
            .strip() != 'yes':
        raise StepFailed('not confirmed; nothing was sent to the unit')
    with open_session(settings, 'bench', write=True, network=False) as session:
        to_linux(session.console, session.log)
        command(session.console, '/usr/sbin/system-update unkey', limit=180, strict=False)
        print('bench: the list is gone; clearing the mark, at the stock boot loader')
        mark(session.console, session.log, False)
        state = state_of(session.console)
    if state.get('keys') != 'unkeyed':
        raise StepFailed(f'the unit does not say it is unkeyed: {state}')
    print('bench: the unit holds no list and no mark')
    return 0


def show(settings):
    with open_session(settings, 'bench', network=False) as session:
        to_linux(session.console, session.log)
        state = state_of(session.console)
        print(f'bench: keys={state.get("keys")} mark={state.get("key_mark")} list={state.get("key_list")} '
              f'generation={state.get("key_generation") or "none"} release={state.get("release")}')
        if state.get('key_list') == 'good':
            print(command(session.console, '/usr/sbin/system-update keys', limit=120, strict=False))
    return 0
