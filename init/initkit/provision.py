# SPDX-License-Identifier: MIT
"""The unit's own root filesystem: the built root plus its login key and network.

The built rootfs.squashfs is the same for every unit and lets nobody log in.
This adds, for one unit, the public key allowed to log in as root and, if
present, the unit's own network.conf. The result is written to UBI volume
`rootfs` in place of the generic image.

The unit's ssh host key is not in its root. The unit makes it and keeps it in
its durable storage (w1700k-hostkey on the unit); the host knows only its
public half, as the unit told it over the serial console when it was installed.

    unit directory (see config.py)
      known_hosts                 the unit's host key, public half
      network.conf                optional; replaces /etc/w1700k/network.conf
      rootfs.squashfs             the unit's root, rebuilt by every install/update
      dropbear_ed25519_host_key   only from before host keys left the root: the
                                  key an older root of this unit carried
"""
import base64
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import tempfile

from . import config, paperclip

HOST_KEY = 'dropbear_ed25519_host_key'
LOGIN_KEY = 'login-key'         # in the unit directory: the fingerprint of the key in its root, or `none'
KNOWN_HOSTS = 'known_hosts'
NETWORK = 'network.conf'
IMAGE = 'rootfs.squashfs'
# The options Buildroot uses for the generic image (128 KiB blocks, zstd).
MKSQUASHFS_OPTIONS = ['-noappend', '-processors', '1', '-b', '128K', '-comp', 'zstd',
                      '-Xcompression-level', '22', '-all-root', '-repro-time', '0',
                      '-no-progress', '-exit-on-error']
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


def private_files(unit_directory, public_key):
    """{path in the root: (bytes, mode)} for one unit."""
    files = {}
    if public_key is not None:              # None: no login key in the root (--no-login-key)
        files['root/.ssh/authorized_keys'] = (public_key, 0o600)
    network = Path(unit_directory) / NETWORK
    if network.is_file():
        files['etc/w1700k/network.conf'] = (network.read_bytes(), 0o644)
    return files


def _write(tree, name, data, mode):
    """Write one file into the unpacked root, keeping its directories' modes."""
    path = tree / name
    missing = [parent for parent in reversed(path.relative_to(tree).parents)
               if not (tree / parent).exists()]
    for parent in missing:
        (tree / parent).mkdir(mode=0o700 if parent.name in ('.ssh', 'dropbear') else 0o755)
    parent = path.parent
    saved = parent.stat().st_mode & 0o7777
    parent.chmod(saved | 0o700)
    try:
        if path.is_symlink() or path.exists():
            path.unlink()
        path.write_bytes(data)
        path.chmod(mode)
    finally:
        parent.chmod(saved)


def build(unit_directory, public_key, generic=config.ROOTFS,
          tools=config.SQUASHFS_TOOLS):
    """Write the unit's rootfs.squashfs into its directory and return the path."""
    unsquashfs, mksquashfs = tools / 'unsquashfs', tools / 'mksquashfs'
    for path in (generic, unsquashfs, mksquashfs):
        if not Path(path).exists():
            raise ProvisionError(f'{path} is missing; run `make`')
    unit_directory = Path(unit_directory)
    output = unit_directory / IMAGE
    with tempfile.TemporaryDirectory(prefix='w1700k-root-', dir=unit_directory) as temporary:
        tree = Path(temporary) / 'root'
        subprocess.run([str(unsquashfs), '-no-xattrs', '-quiet', '-no-progress', '-d',
                        str(tree), str(generic)], check=True, stdout=subprocess.DEVNULL)
        for name, (data, mode) in private_files(unit_directory, public_key).items():
            _write(tree, name, data, mode)
        env = dict(os.environ, TZ='UTC', LC_ALL='C')
        env.pop('SOURCE_DATE_EPOCH', None)
        partial = Path(temporary) / IMAGE
        subprocess.run([str(mksquashfs), str(tree), str(partial), *MKSQUASHFS_OPTIONS],
                       env=env, check=True, stdout=subprocess.DEVNULL)
        if partial.read_bytes()[:4] != b'hsqs':
            raise ProvisionError('mksquashfs did not produce a SquashFS image')
        if partial.stat().st_size > config.partitions.ROOTFS_VOLUME_BYTES:
            raise ProvisionError('the unit root does not fit its volume')
        partial.chmod(0o600)
        partial.replace(output)
    return output


def provision(unit_directory, authorized_key_path=None, address='192.168.1.1',
              generic=None, no_login_key=False, say=print):
    """Build the unit's root (from `generic`, default this build's); returns the image's path.

    With `no_login_key` the root has no login key built in: the unit takes its key from its reset
    button alone (init/key). What the root carries is noted in the unit's directory, and a root
    with a key made for a unit whose last one had none is said, since that is easily done by
    leaving the option out."""
    unit_directory = Path(unit_directory)
    unit_directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    legacy_known_host(unit_directory, address)
    key = None if no_login_key else authorized_key(authorized_key_path)
    image = build(unit_directory, key, **({'generic': generic} if generic else {}))
    carries = 'none' if key is None else paperclip.fingerprint(key.split()[1].decode())
    note = unit_directory / LOGIN_KEY
    if key is not None and note.is_file() and note.read_text().strip() == 'none':
        say(f'note: this root has a login key built in ({carries}); the last one made for this unit '
            'had none (--no-login-key)')
    note.write_text(carries + '\n')
    return image
