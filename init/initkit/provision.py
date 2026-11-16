# SPDX-License-Identifier: MIT
"""The root filesystem a unit is sent, and what this host knows a unit by.

The built rootfs.squashfs is the same for every unit, and every unit is sent it
as it is. Nothing of a unit is in its root:

- Who may log in is a list in the unit's durable storage (w1700k-login on the
  unit), to which the installer adds one key.
- Who the unit is, its ssh host key, is made on the unit and kept there
  (w1700k-hostkey). This host knows only the public half, as the unit said it
  over the serial console when it was installed.
- A unit's own network settings are kept there too (w1700k-network). They come
  from a `network.conf` in the unit's directory here, which the tools send.

    unit directory (see config.py)
      known_hosts                 the unit's host key, public half
      network.conf                optional: the unit's own network settings
      dropbear_ed25519_host_key   only from before host keys left the root: the
                                  key an older root of this unit carried
"""
import base64
import hashlib
from pathlib import Path
import re
import struct

from . import config, paperclip

HOST_KEY = 'dropbear_ed25519_host_key'
KNOWN_HOSTS = 'known_hosts'
NETWORK = 'network.conf'
NETWORK_NAMES = ('MGMT_IF', 'MGMT_ADDRESS', 'EXPORT_IF', 'EXPORT_ADDRESS', 'EXPORT_MTU')
NETWORK_VALUE = re.compile(r'[A-Za-z0-9._/-]{1,32}')        # one word; the unit holds it to more
KEY_TYPES = (b'ssh-ed25519', b'ecdsa-sha2-nistp256', b'ecdsa-sha2-nistp384',
             b'ecdsa-sha2-nistp521', b'ssh-rsa')


class ProvisionError(ValueError):
    """An input key or file is unusable."""


def _string(data, offset):
    length, = struct.unpack_from('>I', data, offset)
    return data[offset + 4:offset + 4 + length], offset + 4 + length


def _wire(*fields):
    return b''.join(struct.pack('>I', len(field)) + field for field in fields)


def host_public_key(dropbear_key):
    """The OpenSSH public key line of a Dropbear Ed25519 private key."""
    kind, offset = _string(dropbear_key, 0)
    secret, _ = _string(dropbear_key, offset)
    if kind != b'ssh-ed25519' or len(secret) != 64:
        raise ProvisionError('not a Dropbear Ed25519 key')
    return b'ssh-ed25519 ' + base64.b64encode(_wire(b'ssh-ed25519', secret[32:]))


def fingerprint(public_line):
    blob = base64.b64decode(public_line.split()[1])
    return 'SHA256:' + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip('=')


def known_host(unit_directory, address, lines):
    """Write the unit's known_hosts from its host keys' public halves ("TYPE BASE64" each);
    returns the lines written. Nothing else is taken for one: a line is a key type this
    project knows and base64 that decodes to a key of that type."""
    entries = []
    for line in lines:
        fields = line.split()
        try:
            kind = _string(base64.b64decode(fields[1], validate=True), 0)[0]
        except (IndexError, ValueError, struct.error):
            kind = None
        if len(fields) != 2 or kind != fields[0].encode() or kind not in KEY_TYPES:
            raise ProvisionError(f'not a host key as a unit reports one: {line[:80]!r}')
        entries.append(f'{address} {fields[0]} {fields[1]}')
    if not entries:
        raise ProvisionError('the unit reported no host key')
    path = Path(unit_directory) / KNOWN_HOSTS
    path.write_text('\n'.join(entries) + '\n')
    return entries


def public_lines(text):
    """The host keys in `text`, "TYPE BASE64" each: .pub files, known_hosts lines, or the lines
    a unit's installer printed, in any mix."""
    found = []
    for line in text.splitlines():
        fields = line.split()
        for at, field in enumerate(fields[:-1]):
            if field.encode() in KEY_TYPES:
                found.append(f'{field} {fields[at + 1]}')
                break
    return found


def legacy_known_host(unit_directory, address):
    """A unit directory from before host keys left the root has the key itself and may lack
    known_hosts: write it from the key, so the unit can be reached to carry the key across."""
    directory = Path(unit_directory)
    key = directory / HOST_KEY
    if key.is_file() and not (directory / KNOWN_HOSTS).is_file():
        (directory / KNOWN_HOSTS).write_text(f'{address} {host_public_key(key.read_bytes()).decode()}\n')


def authorized_key(path=None):
    """The public key for root logins: the one given, or the user's default."""
    candidates = [Path(path).expanduser()] if path else \
        [Path('~/.ssh').expanduser() / name
         for name in ('id_ed25519.pub', 'id_ecdsa.pub', 'id_rsa.pub')]
    for candidate in candidates:
        if candidate.is_file():
            line = candidate.read_bytes().strip()
            try:
                paperclip.public_key(line)
            except paperclip.KeyProblem as problem:
                raise ProvisionError(f'{candidate}: {problem}')
            return line + b'\n'
    raise ProvisionError('no SSH public key for root logins; pass --authorized-key '
                         'or create ~/.ssh/id_ed25519.pub')


def network_settings(unit_directory):
    """The unit's own network settings as its directory states them: the NAME=VALUE words of its
    `network.conf`, or [] when it has none and runs on the defaults."""
    path = Path(unit_directory) / NETWORK
    if not path.is_file():
        return []
    words = []
    for line in path.read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        name, equals, value = line.partition('=')
        if not equals or name not in NETWORK_NAMES or not NETWORK_VALUE.fullmatch(value):
            raise ProvisionError(f'{path}: not a setting ({", ".join(NETWORK_NAMES)}) and its value: {line[:60]!r}')
        words.append(f'{name}={value}')
    return words


def provision(unit_directory, address='192.168.1.1', generic=None):
    """The root a unit is sent: the built one (`generic`, default this build's), as it is. Returns
    its path.

    Nothing of a unit is in its root: its login keys, its ssh host key and its network settings
    are in its durable storage. So this is the root a release's manifest names, the same for
    every unit, and the unit can check it. What is done here is for the unit's directory."""
    unit_directory = Path(unit_directory)
    unit_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    legacy_known_host(unit_directory, address)
    generic = Path(generic) if generic else config.ROOTFS
    if not generic.exists():
        raise ProvisionError(f'{generic} is missing; run `make`')
    return generic
