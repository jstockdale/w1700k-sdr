# SPDX-License-Identifier: MIT
"""The update archive (w1700k-update.tar, written by platform/images.py): the second loader and
the generic root with a manifest of their digests and of the flash layout they are built for.
Read whole and checked before anything is used: what does not hold together is refused.

A release is such an archive with one member more, `manifest.wms2`: the manifest again, sealed
with a release key (`seal.py`, `init/sign`). The manifest lists the digest of every image, so
the one signature covers them all. Whether the seal is a key's that matters is not decided
here, where no key is known: a unit decides it, and the tool that sends it the archive.

A release also carries the rotations so far (`keys/E.G.wms2`: each a complete list of the keys
a unit is to trust, sealed; `seal.py`), so that a unit which missed one catches up before it
judges the release. Each is sealed itself, and a unit takes one only from a key of the list
it holds. The manifest names them by digest all the same, so that an archive from which one
was taken away, or to which one was added, on its way is not the release that was sealed."""
import hashlib
import io
import json
import re
import tarfile

from . import seal
from .console import StepFailed

FORMAT = 1
LOADER, ROOT = 'w1700k-loader-b.itb', 'rootfs.squashfs'
SEALED = 'manifest.wms2'
FIELDS = {'format', 'what', 'partitions', 'files', 'release', 'source', 'rotations'}     # all a manifest says
ROTATION = re.compile(r'keys/([1-9][0-9]{0,3})\.([1-9][0-9]{0,9})\.wms2')
# What a release says it was made from: a commit, or that nobody could tell. Never anything
# that reads like the digest of an image.
SOURCE = re.compile(r'(?:[0-9a-f]{40}|[0-9a-f]{64})(?:-dirty)?|unknown')
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
            listed = [m for m in archive.getmembers() if not ROTATION.fullmatch(m.name)]
            members = {m.name: m for m in listed}
            if len(members) != len(listed):
                raise StepFailed(f'{path} holds a member twice: which of the two is meant is not for a tool to say')
            if set(members) - {SEALED} != {'manifest.json', LOADER, ROOT} \
                    or not all(m.isfile() for m in members.values()):
                raise StepFailed(f'{path} is not a W1700K update archive: it holds {sorted(members)}')
            if any(m.size > LIMIT for m in members.values()):
                raise StepFailed(f'{path}: a member is larger than any image of a unit')
            data = {name: archive.extractfile(member).read() for name, member in members.items()}
            carried = {m.name[len('keys/'):-len('.wms2')]: hashlib.sha256(archive.extractfile(m).read()).hexdigest()
                       for m in archive.getmembers() if ROTATION.fullmatch(m.name) and m.isfile()
                       and m.size <= seal.ENVELOPE_MOST}
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
        # What is sealed is what was looked at: the images that are here, and no word besides.
        if set(listed) != set(data) or set(manifest) - FIELDS:
            raise StepFailed(f'{path}: its manifest lists {sorted(listed)} and has {sorted(set(manifest) - FIELDS)} '
                             f'besides; an archive lists the images it holds ({sorted(data)}) and nothing else')
        if 'rotations' in manifest and manifest['rotations'] != carried:
            raise StepFailed(f'{path}: its manifest names the rotations {sorted(manifest["rotations"])} and it '
                             f'carries {sorted(carried)}, or not those: one was added, taken away or changed')
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


def rotations(path):
    """The rotations the archive at `path` carries, oldest first, each as it is sealed.
    Unverified: whose they are is for `chain` and for the unit."""
    try:
        with tarfile.open(path, mode='r:') as archive:
            found = {}
            for member in archive.getmembers():
                match = ROTATION.fullmatch(member.name)
                if match:
                    stamp = int(match[1]), int(match[2])
                    if not member.isfile() or member.size > seal.ENVELOPE_MOST or stamp in found:
                        raise StepFailed(f'{path}: {member.name} is not a sealed list of keys, or is there twice')
                    found[stamp] = archive.extractfile(member).read()
    except (OSError, tarfile.TarError) as error:
        raise StepFailed(f'{path} cannot be read as an update archive: {error}') from None
    for stamp, envelope in found.items():
        name = f'keys/{stamp[0]}.{stamp[1]}.wms2'
        try:
            inside = seal.parse_list(seal.body_of(envelope))
        except seal.Refused as error:
            raise StepFailed(f'{path}: {name} is not a sealed list of keys: {error}') from None
        if inside.stamp != stamp:
            raise StepFailed(f'{path}: {name} holds list {inside.label}')
    return [found[stamp] for stamp in sorted(found)]


def chain(envelopes, held=None):
    """The list a unit ends up holding when it is given `envelopes` in order, starting from
    the list `held` (None: from no list, so the first is a first list). Every one has to be
    taken, or changes nothing: what a unit would refuse is refused here."""
    for number, envelope in enumerate(envelopes, 1):
        try:
            held, _ = seal.rotated(held, envelope)
        except seal.Refused as error:
            raise StepFailed(f'rotation {number} of {len(envelopes)} is not one a unit takes: {error}') from None
    return held


def _named(carried):
    """{the member a carried rotation goes in as: the rotation}."""
    try:
        names = {f'keys/{seal.parse_list(seal.body_of(envelope)).label}.wms2': envelope for envelope in carried}
    except seal.Refused as error:
        raise StepFailed(f'a rotation to carry is not a sealed list of keys: {error}') from None
    if len(names) != len(list(carried)):
        raise StepFailed('two of the rotations to carry are one list')
    return names


def _numbered(path, release, source=None, carried=()):
    """(the manifest of the archive at `path` with `release` in it, as text; its images).
    `source` names what the images were built from, for whoever signs to keep; `carried`
    are the rotations that go with it, which the manifest names by digest."""
    manifest, data, _ = read_release(path)
    if source and not SOURCE.fullmatch(source):
        raise StepFailed(f'{source!r} does not name a commit: 40 or 64 hex digits, with -dirty for a tree '
                         'that differs from it, or `unknown\'')
    if type(release) is not int or not 0 < release <= seal.RELEASE_MOST:
        raise StepFailed(f'a release number is a whole number from 1 to {seal.RELEASE_MOST}')
    turns = {name[len('keys/'):-len('.wms2')]: hashlib.sha256(envelope).hexdigest()
             for name, envelope in _named(carried).items()}
    manifest = {**manifest, 'release': release, **({'source': source} if source else {}),
                **({'rotations': turns} if turns else {}),
                'partitions': {name: list(span) for name, span in manifest['partitions'].items()}}
    return (json.dumps(manifest, indent=1) + '\n').encode(), data


def sign(path, output, release, sign_with, when_ms=None, keys=None, source=None, carried=()):
    """The archive at `path` as release number `release` in `output`: the same images, the
    manifest with the number in it, and that manifest sealed by `sign_with(message)`. Given
    `keys`, a list's release keys, nothing is written unless one of them sealed it. `carried`
    are the rotations so far, which go in as they are."""
    carried = list(carried)
    text, data = _numbered(path, release, source, carried)
    try:
        sealed = seal.seal(text, release, sign_with, when_ms)
        if keys is not None:
            seal.unseal(sealed, keys)
    except seal.Refused as error:
        raise StepFailed(str(error)) from None
    _write(output, {'manifest.json': text, SEALED: sealed, **data, **_named(carried)})
    return sealed


def to_sign(path, release, when_ms, source=None, carried=()):
    """(the manifest, the bytes a key signs) to make the archive at `path` release `release`
    at `when_ms`: what `sign` would hand its signer, for a key that signs somewhere else."""
    text, _ = _numbered(path, release, source, list(carried))
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
