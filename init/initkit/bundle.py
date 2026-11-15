# SPDX-License-Identifier: MIT
"""The update archive (w1700k-update.tar, written by platform/images.py): the second loader and
the generic root with a manifest of their digests and of the flash layout they are built for.
Read whole and checked before anything is used: what does not hold together is refused.

A release is such an archive with one member more, `manifest.wms2`: the manifest again, sealed
with a release key (`seal.py`, `init/sign`). The manifest lists the digest of every image, so
the one signature covers them all. Whether the seal is a key's that matters is not decided
here, where no key is known: a unit decides it, and the tool that sends it the archive."""
import hashlib
import io
import json
import tarfile

from . import seal
from .console import StepFailed

FORMAT = 1
LOADER, ROOT = 'w1700k-loader-b.itb', 'rootfs.squashfs'
SEALED = 'manifest.wms2'
LIMIT = 64 << 20


def read(path):
    """(manifest, {name: bytes}) of the archive at `path`."""
    manifest, data, _ = read_release(path)
    return manifest, data


def read_release(path):
    """(manifest, {name: bytes}, the sealed manifest or None) of the archive at `path`. A seal
    is only known here to be over this archive's own manifest, not whose it is."""
    try:
        with tarfile.open(path, mode='r:') as archive:
            members = {m.name: m for m in archive.getmembers()}
            if set(members) - {SEALED} != {'manifest.json', LOADER, ROOT} \
                    or not all(m.isfile() for m in members.values()):
                raise StepFailed(f'{path} is not a W1700K update archive: it holds {sorted(members)}')
            if any(m.size > LIMIT for m in members.values()):
                raise StepFailed(f'{path}: a member is larger than any image of a unit')
            data = {name: archive.extractfile(member).read() for name, member in members.items()}
    except (OSError, tarfile.TarError) as error:
        raise StepFailed(f'{path} cannot be read as an update archive: {error}') from None
    sealed, text = data.pop(SEALED, None), data.pop('manifest.json')
    if sealed is not None:
        try:
            if seal.body_of(sealed) != text:
                raise StepFailed(f'{path}: what is sealed in it is not its own manifest')
        except seal.Refused as error:
            raise StepFailed(f'{path}: {SEALED} is {error}') from None
    try:
        manifest = json.loads(text)
        listed = manifest['files']
        partitions = {name: tuple(span) for name, span in manifest['partitions'].items()}
        if manifest['format'] != FORMAT:
            raise StepFailed(f'{path} is an update archive of format {manifest["format"]}; these tools '
                             f'read format {FORMAT}')
        for name, content in data.items():
            if hashlib.sha256(content).hexdigest() != listed[name]['sha256'] or len(content) != listed[name]['bytes']:
                raise StepFailed(f'{path}: {name} is not the file its manifest lists')
    except (KeyError, TypeError, ValueError) as error:
        raise StepFailed(f'{path}: the manifest does not read as one ({error!r})') from None
    manifest['partitions'] = partitions
    return manifest, data, sealed


def _numbered(path, release):
    """(the manifest of the archive at `path` with `release` in it, as text; its images)."""
    manifest, data, _ = read_release(path)
    manifest = {**manifest, 'release': release,
                'partitions': {name: list(span) for name, span in manifest['partitions'].items()}}
    return (json.dumps(manifest, indent=1) + '\n').encode(), data


def sign(path, output, release, sign_with, when_ms=None, keys=None):
    """The archive at `path` as release number `release` in `output`: the same images, the
    manifest with the number in it, and that manifest sealed by `sign_with(message)`. Given
    `keys`, nothing is written unless one of them sealed it."""
    text, data = _numbered(path, release)
    try:
        sealed = seal.seal(text, release, sign_with, when_ms)
        if keys is not None:
            seal.unseal(sealed, keys)
    except seal.Refused as error:
        raise StepFailed(str(error)) from None
    _write(output, {'manifest.json': text, SEALED: sealed, **data})
    return sealed


def to_sign(path, release, when_ms):
    """(the manifest, the bytes a key signs) to make the archive at `path` release `release`
    at `when_ms`: what `sign` would hand its signer, for a key that signs somewhere else."""
    text, _ = _numbered(path, release)
    try:
        return text, seal.unsigned(text, release, when_ms)[1]
    except seal.Refused as error:
        raise StepFailed(str(error)) from None


def write(path, loader, root, partitions):
    """An archive as platform/images.py writes it (for tests)."""
    files = {LOADER: loader, ROOT: root}
    manifest = {'format': FORMAT, 'partitions': {name: list(span) for name, span in partitions.items()},
                'files': {name: {'sha256': hashlib.sha256(data).hexdigest(), 'bytes': len(data)}
                          for name, data in files.items()}}
    _write(path, {'manifest.json': (json.dumps(manifest) + '\n').encode(), **files})


def _write(path, files):
    with tarfile.open(path, mode='w', format=tarfile.USTAR_FORMAT) as archive:
        for name, data in files.items():
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o644
            archive.addfile(info, io.BytesIO(data))
