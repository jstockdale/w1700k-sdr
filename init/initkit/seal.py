# SPDX-License-Identifier: MIT
"""Releases and the keys a unit trusts, each in a WMS2 control envelope.

WMS2 is the envelope Whitehat Hardware's devices take their commands in (`seal/wms2.c`,
which is what a unit verifies with). It is a 40-byte header, the body, and an Ed25519
signature (RFC 8032) over the topic, the header and the body:

    "WMS2" | kind 2 | flags 0 | device, 16 bytes | counter u64 | time u64, ms | 2 reserved
    signature over: u16(len(topic)) | topic | header | body          (integers little-endian)

A release (topic `w1700k-sdr/release`): the body is an update archive's manifest and the
counter the release number. A unit has no clock, so it holds a release to the number alone:
one older than what it has settled on is refused. The time is the signer's, for whoever
reads it.

A rotation (topic `w1700k-sdr/rotate-keys`): the body is the complete list of the keys a unit
is to trust from then on. A list is of an epoch and, in it, of a generation, and the counter
is the generation. Each key has a scope, which is what it may seal:

    release     a release
    timestamp   nothing a unit takes: what a host is told is current
    keys        the next list of the epoch, which leaves every root and keys line as it is
    root        that, and the first list of the next epoch, which may change any line

A unit takes a later generation of the epoch it holds, or generation 1 of the next epoch,
sealed by a root or keys key of the list it holds; only a root key starts an epoch. Lists
are in order by epoch and then generation, so however far a keys key runs the generation
up, a root key's list comes after it. The topic is part of what is signed, so a release key
cannot seal a list and a list key cannot seal a release.

Verifying here is plain Python and needs no library, so that reading a signed archive takes
nothing more than these tools do. Signing takes `cryptography` or PyNaCl. What a unit accepts
is decided on the unit, by `seal/release.c`, which reads a list in the same one form and
holds a rotation to the same rules; this is the host's own check before it sends anything.
"""
import hashlib
import os
import re
import struct
import time
from typing import NamedTuple

MAGIC, CONTROL = b'WMS2', 2
HEADER, SIGNATURE, DEVICE = 40, 64, 16
# These are `seal/release.h`'s; a test holds the two files to each other.
TOPIC = 'w1700k-sdr/release'
ROTATE_TOPIC = 'w1700k-sdr/rotate-keys'
PRODUCT = 'w1700k-sdr'
ENVELOPE_MOST = 16384
RELEASE_MOST = 9007199254740991     # the highest number of a release
KEYS_MOST = 8
KEY_NAME_MOST = 48
LIST_MOST = 1100
SCOPES = ('root', 'keys', 'release', 'timestamp')
EPOCH_MOST = 9999
GENERATION_MOST = 1000000000


class Refused(Exception):
    """Not a release, or not one sealed by a key that was given."""


# -- Ed25519 verification (RFC 8032, section 6) ---------------------------------------------

P = 2 ** 255 - 19
ORDER = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
ROOT_OF_MINUS_ONE = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * ROOT_OF_MINUS_ONE % P
    if (x * x - x2) % P != 0:
        return None
    return P - x if (x & 1) != sign else x


def _point(encoded):
    y = int.from_bytes(encoded, 'little')
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % P)


def _add(a, b):
    e = (a[1] - a[0]) * (b[1] - b[0]) % P
    f = (a[1] + a[0]) * (b[1] + b[0]) % P
    g = 2 * a[3] * b[3] * D % P
    h = 2 * a[2] * b[2] % P
    return ((f - e) * (h - g) % P, (h + g) * (f + e) % P, (h - g) * (h + g) % P, (f - e) * (f + e) % P)


def _multiply(scalar, point):
    result = (0, 1, 1, 0)
    while scalar:
        if scalar & 1:
            result = _add(result, point)
        point = _add(point, point)
        scalar >>= 1
    return result


BASE = _point((4 * pow(5, P - 2, P) % P).to_bytes(32, 'little'))


def verifies(public, message, signature):
    """Whether `signature` is `public`'s over `message`: RFC 8032's check with the cofactor,
    8 [S]B = 8 R + 8 [k]A, which is the one Monocypher makes on the unit, on points in their
    one encoding (`_point` takes no other; `seal/release.c` refuses the others before
    Monocypher, which would take them). The two have to say the same of every signature."""
    if len(public) != 32 or len(signature) != SIGNATURE:
        return False
    key, commitment = _point(public), _point(signature[:32])
    scalar = int.from_bytes(signature[32:], 'little')
    if key is None or commitment is None or scalar >= ORDER:
        return False
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(),
                               'little') % ORDER
    left = _multiply(8, _multiply(scalar, BASE))
    right = _multiply(8, _add(commitment, _multiply(challenge, key)))
    return ((left[0] * right[2] - right[0] * left[2]) % P == 0
            and (left[1] * right[2] - right[1] * left[2]) % P == 0)


# -- keys -----------------------------------------------------------------------------------

def fingerprint(public):
    """Sixteen hex digits to tell one key from another by, as the unit prints them."""
    return hashlib.blake2b(public, digest_size=8).hexdigest()


def registry_fingerprint(public):
    """The same key as Whitehat Hardware's key registry names it."""
    return hashlib.sha256(public).hexdigest()[:16]


# The eight points of small order, the sign of x set aside, as `seal/release.c` lists them. A
# signature under such a key verifies for any message.
_SMALL = {bytes(32), b'\x01' + bytes(31),
          bytes.fromhex('26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05'),
          bytes.fromhex('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a'),
          b'\xec' + b'\xff' * 30 + b'\x7f', b'\xed' + b'\xff' * 30 + b'\x7f', b'\xee' + b'\xff' * 30 + b'\x7f'}


def small_order(public):
    if public[:31] + bytes((public[31] & 0x7f,)) in _SMALL:
        return True
    point = _point(public)
    if point is None:
        return False
    eighth = _multiply(8, point)
    return eighth[0] % P == 0 and (eighth[1] - eighth[2]) % P == 0


class Key(NamedTuple):
    public: bytes
    scope: str
    name: str

    def line(self):
        return f'{self.public.hex()}  {self.scope}  {self.name}'


class KeyList(NamedTuple):
    """The keys a unit trusts: `text` is the list in its one form, as it is sealed and kept."""
    epoch: int
    generation: int
    keys: tuple
    text: bytes

    @property
    def stamp(self):
        """Where the list stands among lists: they are in order by epoch, then generation."""
        return self.epoch, self.generation

    @property
    def label(self):
        return f'{self.epoch}.{self.generation}'

    def scoped(self, *scopes):
        return [key for key in self.keys if key.scope in scopes]

    def release_keys(self):
        return [key.public for key in self.scoped('release')]

    def authorities(self):
        """The root and keys lines: what only the first list of an epoch may change."""
        return sorted(key for key in self.keys if key.scope in ('root', 'keys'))


_LINE = re.compile(rb'([0-9a-f]{64})  (root|keys|release|timestamp)  ([a-z0-9-]{1,%d})' % KEY_NAME_MOST)
_FIRST = re.compile(rb'%s keys ([1-9][0-9]{0,10})\.([1-9][0-9]{0,10})' % PRODUCT.encode())


def parse_list(text):
    """The list in `text`, which is in its one form or is refused. `seal/release.c` reads
    the same bytes the same way: every byte printable or a line feed, one line feed at the end,
    `w1700k-sdr keys E.G` first (the epoch and the generation), then a key, two spaces, a
    scope, two spaces and a name to a line. One to eight keys, none and no name twice, none of small order, a root among them."""
    if not 0 < len(text) <= LIST_MOST:
        raise Refused('it is not the size of a list')
    if any(byte != 0x0a and not 0x20 <= byte <= 0x7e for byte in text):
        raise Refused('it holds a byte that is neither printable nor a line feed')
    if not text.endswith(b'\n'):
        raise Refused('it does not end in a line feed')
    first, *lines = text[:-1].split(b'\n')
    match = _FIRST.fullmatch(first)
    if not match:
        raise Refused(f'its first line is not `{PRODUCT} keys E.G\', each a number from 1 written plainly')
    if int(match[1]) > EPOCH_MOST or int(match[2]) > GENERATION_MOST:
        raise Refused('its epoch or its generation is beyond what a list may reach')
    keys = []
    for line in lines:
        fields = _LINE.fullmatch(line)
        if not fields:
            raise Refused(f'a line of it is not a key, two spaces, a scope, two spaces and a name: '
                          f'{line[:80].decode()!r}')
        keys.append(Key(bytes.fromhex(fields[1].decode()), fields[2].decode(), fields[3].decode()))
    if not keys or len(keys) > KEYS_MOST:
        raise Refused(f'it holds {len(keys)} keys; a list holds one to {KEYS_MOST}')
    if len({key.public for key in keys}) != len(keys):
        raise Refused('it names the same key twice')
    if len({key.name for key in keys}) != len(keys):
        raise Refused('it gives two keys the same name')
    for key in keys:
        if small_order(key.public):
            raise Refused(f'{key.name} is a point of small order, which anyone can sign for')
        if int.from_bytes(key.public, 'little') & ((1 << 255) - 1) >= P:
            raise Refused(f'{key.name} is not in the one form a key is written in')
    if not any(key.scope == 'root' for key in keys):
        raise Refused('it holds no root key')
    return KeyList(int(match[1]), int(match[2]), tuple(keys), bytes(text))


def format_list(stamp, keys):
    """The one form of a list of `(public, scope, name)` at `stamp`, an (epoch, generation),
    checked."""
    text = f'{PRODUCT} keys {stamp[0]}.{stamp[1]}\n' + ''.join(Key(*key).line() + '\n' for key in keys)
    return parse_list(text.encode('ascii', 'replace')).text


def signer(seed):
    """(public key, sign(message)) for a 32-byte signing seed, the private half of a key."""
    if len(seed) != 32:
        raise Refused('a signing key is 32 bytes')
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        key = Ed25519PrivateKey.from_private_bytes(seed)
        public = key.public_key().public_bytes(serialization.Encoding.Raw,
                                               serialization.PublicFormat.Raw)
        return public, key.sign
    except ImportError:
        pass
    try:
        from nacl.signing import SigningKey
    except ImportError:
        raise Refused('signing takes the Python package `cryptography` or PyNaCl '
                      '(python3-cryptography or python3-nacl)') from None
    key = SigningKey(seed)
    return bytes(key.verify_key), lambda message: key.sign(message).signature


def new_seed():
    return os.urandom(32)


# -- the envelope ---------------------------------------------------------------------------

def _signed(header, body, topic=None):
    topic = (topic or TOPIC).encode()
    return struct.pack('<H', len(topic)) + topic + header + body


def unsigned(body, counter, when_ms=None, topic=None):
    """(header, the bytes a key signs) for `body` under `topic` (a release's unless given) with
    `counter`. The two halves of sealing are apart so that a key held elsewhere can sign:
    `signed` takes what this returns."""
    if not 0 < counter < 1 << 64:
        raise Refused('a release number, or a generation, is a whole number from 1')
    if not body or b'\0' in body:
        raise Refused('what is sealed is text')
    if HEADER + len(body) + SIGNATURE > ENVELOPE_MOST:
        raise Refused(f'{len(body)} bytes are too many to seal')
    when_ms = int(time.time() * 1000) if when_ms is None else when_ms
    header = (MAGIC + bytes((CONTROL, 0)) + PRODUCT.encode().ljust(DEVICE, b'\0')
              + struct.pack('<QQH', counter, when_ms, 0))
    return header, _signed(header, body, topic)


def signed(header, body, signature):
    """The envelope of `header`, `body` and a signature over what `unsigned` gave for them."""
    if len(signature) != SIGNATURE:
        raise Refused(f'a signature is {SIGNATURE} bytes, not {len(signature)}')
    return header + body + signature


def seal(body, release, sign, when_ms=None):
    """`body` as release number `release`, signed with `sign(message) -> 64 bytes`."""
    if release > RELEASE_MOST:
        raise Refused(f'a release number is at most {RELEASE_MOST}')
    header, message = unsigned(body, release, when_ms)
    return signed(header, body, sign(message))


def unsigned_list(text, when_ms=None):
    """(header, the bytes a key signs) to seal the list `text` as a rotation."""
    return unsigned(text, parse_list(text).generation, when_ms, ROTATE_TOPIC)


def seal_list(text, sign, when_ms=None):
    """The list `text` as a rotation, signed with `sign(message) -> 64 bytes`."""
    header, message = unsigned_list(text, when_ms)
    return signed(header, text, sign(message))


def body_of(envelope):
    """The body an envelope carries, unverified: for comparing it with what it claims to seal."""
    if len(envelope) < HEADER + SIGNATURE:
        raise Refused('too short to be sealed')
    return envelope[HEADER:-SIGNATURE]


def _open(envelope, topic):
    """(counter, body, signature, the bytes signed) of a plain control envelope for this
    product: no flag, nothing in the reserved bytes, the product alone in the device field."""
    if not HEADER + SIGNATURE < len(envelope) <= ENVELOPE_MOST:
        raise Refused('not the size of a sealed envelope')
    header, body, signature = envelope[:HEADER], envelope[HEADER:-SIGNATURE], envelope[-SIGNATURE:]
    if header[:4] != MAGIC or header[4] != CONTROL or header[5] != 0 or header[38:40] != b'\0\0':
        raise Refused('not a WMS2 control envelope')
    if header[6:6 + DEVICE] != PRODUCT.encode().ljust(DEVICE, b'\0'):
        product = header[6:6 + DEVICE].split(b'\0')[0].decode('ascii', 'replace')
        raise Refused(f'it is sealed for {product}, not for {PRODUCT}')
    return struct.unpack_from('<Q', header, 22)[0], body, signature, _signed(header, body, topic)


def unseal(envelope, keys):
    """(release number, body, the key that sealed it) of a release sealed by one of the public
    keys `keys`: a list's release keys."""
    release, body, signature, message = _open(envelope, TOPIC)
    sealed_by = next((key for key in keys if verifies(key, message, signature)), None)
    if sealed_by is None:
        raise Refused('its signature is none of the release keys\' ('
                      + (', '.join(fingerprint(key) for key in keys) or 'none given') + ')')
    if not 0 < release <= RELEASE_MOST or b'\0' in body:
        raise Refused(f'a release has a number from 1 to {RELEASE_MOST} and a manifest of text')
    return release, body, sealed_by


def rotated(held, envelope):
    """What a unit that holds the list `held` makes of the rotation `envelope`: (the list it
    then holds, the key that sealed it). `held` None is a unit with no list, which takes a
    first list: one sealed by a root key it names itself. The list held changes nothing:
    (held, None). Everything else is Refused, as on the unit."""
    counter, body, signature, message = _open(envelope, ROTATE_TOPIC)
    try:
        following = parse_list(body)
    except Refused as error:
        raise Refused(f'what it seals is not a key list: {error}') from None
    if following.generation != counter:
        raise Refused(f"the envelope's counter is {counter} and the list says generation "
                      f'{following.generation}')
    if held is not None and following.text == held.text:
        return held, None       # the list held, whoever hands it over and however it is sealed
    judges = following.scoped('root') if held is None else held.scoped('root', 'keys')
    sealed_by = next((key for key in judges if verifies(key.public, message, signature)), None)
    if sealed_by is None:
        raise Refused('a first list is sealed by a root key it names itself; this one is not'
                      if held is None else
                      f'it is not sealed by a root or keys key of the list held ({held.label})')
    if held is None:
        return following, sealed_by
    # Only of what a key of the list held sealed is anything more said.
    if following.stamp == held.stamp:
        raise Refused(f'it is ANOTHER list {held.label} than the one held, and {sealed_by.name} sealed '
                      'it: two lists were sealed as one')
    if following.stamp < held.stamp:
        raise Refused(f'list {following.label} is older than {held.label}, which is held')
    if following.epoch == held.epoch:
        if following.authorities() != held.authorities():
            raise Refused(f'this list changes a root or keys line and stays in epoch {held.epoch}: only '
                          'the first list of the next epoch, sealed by a root key, may change one')
    elif sealed_by.scope != 'root':
        raise Refused(f'{sealed_by.name} is a keys key, and this list is of another epoch: only a root '
                      'key of the list held starts one')
    elif following.stamp != (held.epoch + 1, 1):
        raise Refused(f'after epoch {held.epoch} comes list {held.epoch + 1}.1 and no other; this is '
                      f'{following.label}')
    return following, sealed_by
