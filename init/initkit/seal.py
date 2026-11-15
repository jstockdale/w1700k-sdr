# SPDX-License-Identifier: MIT
"""A release: an update archive's manifest in a WMS2 control envelope.

WMS2 is the envelope Whitehat Hardware's devices take their commands in (`seal/wms2.c`,
which is what a unit verifies a release with). It is a 40-byte header, the body, and an
Ed25519 signature (RFC 8032) over the topic, the header and the body:

    "WMS2" | kind 2 | flags 0 | device, 16 bytes | counter u64 | time u64, ms | 2 reserved
    signature over: u16(len(topic)) | topic | header | body          (integers little-endian)

For a release the body is the manifest, the device field names the product, and the counter
is the release number. A unit has no clock, so it holds a release to the number alone: one
older than what it has settled on is refused. The time is the signer's, for whoever reads it.

Verifying here is plain Python and needs no library, so that reading a signed archive takes
nothing more than these tools do. Signing takes `cryptography` or PyNaCl. What a unit accepts
is decided on the unit, by `seal/release.c`; this is the host's own check before it sends
anything.
"""
import hashlib
import os
import struct
import time

MAGIC, CONTROL = b'WMS2', 2
HEADER, SIGNATURE, DEVICE = 40, 64, 16
# These three are `seal/release.h`'s; a test holds the two files to each other.
TOPIC = 'w1700k-sdr/release'
PRODUCT = 'w1700k-sdr'
ENVELOPE_MOST = 16384
KEYS_MOST = 8


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
    """Whether `signature` is `public`'s over `message`."""
    if len(public) != 32 or len(signature) != SIGNATURE:
        return False
    key, commitment = _point(public), _point(signature[:32])
    scalar = int.from_bytes(signature[32:], 'little')
    if key is None or commitment is None or scalar >= ORDER:
        return False
    challenge = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(),
                               'little') % ORDER
    left, right = _multiply(scalar, BASE), _add(commitment, _multiply(challenge, key))
    return ((left[0] * right[2] - right[0] * left[2]) % P == 0
            and (left[1] * right[2] - right[1] * left[2]) % P == 0)


# -- keys -----------------------------------------------------------------------------------

def fingerprint(public):
    """Sixteen hex digits to tell one key from another by, as the unit prints them."""
    return hashlib.blake2b(public, digest_size=8).hexdigest()


def read_keys(text):
    """The public keys of a release-keys file: one of 64 hex digits to a line, then nothing
    or a note; `#` starts a comment. `seal/release.c` reads the same file the same way."""
    keys = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        word = line.split()[0]
        if len(word) != 64 or set(word) - set('0123456789abcdef'):
            raise Refused(f'not a release key: {line[:40]!r}')
        keys.append(bytes.fromhex(word))
    if len(keys) > KEYS_MOST:
        raise Refused(f'more than {KEYS_MOST} release keys')
    return keys


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

def _signed(header, body):
    topic = TOPIC.encode()
    return struct.pack('<H', len(topic)) + topic + header + body


def unsigned(body, release, when_ms=None):
    """(header, the bytes a key signs) for `body` as release number `release`. The two halves
    of sealing are apart so that a key held elsewhere can sign: `signed` takes what it returns."""
    if not 0 < release < 1 << 64:
        raise Refused('a release number is a whole number from 1')
    if not body or b'\0' in body:
        raise Refused('a manifest is text')
    if HEADER + len(body) + SIGNATURE > ENVELOPE_MOST:
        raise Refused(f'the manifest is too long for a release ({len(body)} bytes)')
    when_ms = int(time.time() * 1000) if when_ms is None else when_ms
    header = (MAGIC + bytes((CONTROL, 0)) + PRODUCT.encode().ljust(DEVICE, b'\0')
              + struct.pack('<QQH', release, when_ms, 0))
    return header, _signed(header, body)


def signed(header, body, signature):
    """The envelope of `header`, `body` and a signature over what `unsigned` gave for them."""
    if len(signature) != SIGNATURE:
        raise Refused(f'a signature is {SIGNATURE} bytes, not {len(signature)}')
    return header + body + signature


def seal(body, release, sign, when_ms=None):
    """`body` as release number `release`, signed with `sign(message) -> 64 bytes`."""
    header, message = unsigned(body, release, when_ms)
    return signed(header, body, sign(message))


def body_of(envelope):
    """The body an envelope carries, unverified: for comparing it with what it claims to seal."""
    if len(envelope) < HEADER + SIGNATURE:
        raise Refused('too short to be a release')
    return envelope[HEADER:-SIGNATURE]


def unseal(envelope, keys):
    """(release number, body, the key that sealed it) of a release sealed by one of `keys`."""
    if not HEADER + SIGNATURE < len(envelope) <= ENVELOPE_MOST:
        raise Refused('not the size of a release')
    header, body, signature = envelope[:HEADER], envelope[HEADER:-SIGNATURE], envelope[-SIGNATURE:]
    if header[:4] != MAGIC or header[4] != CONTROL or header[5] != 0 or header[38:40] != b'\0\0':
        raise Refused('not a WMS2 control envelope')
    product = header[6:6 + DEVICE].rstrip(b'\0').decode('ascii', 'replace')
    release = struct.unpack_from('<Q', header, 22)[0]
    message = _signed(header, body)
    sealed_by = next((key for key in keys if verifies(key, message, signature)), None)
    if sealed_by is None:
        raise Refused('its signature is none of the release keys\' ('
                      + (', '.join(fingerprint(key) for key in keys) or 'none given') + ')')
    if product != PRODUCT:
        raise Refused(f'it is sealed for {product}, not for {PRODUCT}')
    if release == 0 or b'\0' in body:
        raise Refused('a release has a number and a manifest of text')
    return release, body, sealed_by
