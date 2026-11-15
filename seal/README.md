# Signed releases: the unit's verifier

A unit built with release keys takes over ssh only an update whose manifest one
of those keys sealed. This directory is what verifies that on the unit:
`w1700k-release`, in the root as `/usr/sbin/w1700k-release`.

| File | Whose | Licence |
| --- | --- | --- |
| `release.c`, `release.h` | this project: the program, and what makes an envelope a release of this product | MIT |
| `wms2.c`, `include/wms2.h` | Whitehat Hardware: the WMS2 envelope verifier its devices take their commands with | MIT |
| `monocypher.c`, `monocypher.h`, `optional/monocypher-ed25519.c`, `optional/monocypher-ed25519.h` | Monocypher, by Loup Vaillant, with its RFC 8032 Ed25519 module | BSD-2-Clause OR CC0-1.0 |

The last two rows are vendored as they came, byte for byte, from Whitehat
Hardware's `whitehat-watcher` firmware (its `seal` component at commit
`bf6bc16`, 2026-11-10). They are not edited here: a change belongs there first.
They build under `-Wall -Wextra -Werror -Wno-comment`, as their own test
harness builds them; the one exemption is for a comment in `wms2.h`.

## A release

A release is an update archive's manifest in a WMS2 control envelope:

```
"WMS2" | kind 2 | flags 0 | device, 16 bytes | counter u64 | time u64, ms | 2 reserved    (40 bytes)
the manifest
an Ed25519 signature (RFC 8032) over:  u16(len(topic)) | topic | header | manifest
```

- The **manifest** lists the SHA-256 of every image in the archive, so the one
  signature covers them all.
- The **topic** is `w1700k-sdr/release` and the **device** field `w1700k-sdr`:
  a release for another product, sealed by the same key, does not verify as
  one for this.
- The **counter** is the release number. A unit has no clock, so the number is
  all it can hold a release to: it keeps the number of the newest release it
  has settled on, and refuses an older one. The time is the signer's, for
  whoever reads it.

`init/initkit/seal.py` is the host's side of the same envelope, and
`init/sign` makes a release of an archive. A test holds the two sides to each
other, and runs the verifier against what the host seals.

## The program

```
w1700k-release verify [--keys FILE] [--state DIR] [--floor N] ENVELOPE
w1700k-release allows [--state DIR] SHA256
w1700k-release number [--state DIR]
w1700k-release pinned [--keys FILE]
```

`verify` checks an envelope against the pinned keys
(`/etc/w1700k/release-keys`: one public key of 64 hex digits to a line, any of
which may have sealed it) and against the floor, and leaves what passes in
`/run/w1700k-release`, which is in RAM. `allows` then says whether the verified
manifest lists an image with that digest. `system-update` on the unit is the
one caller: `release` runs `verify`, and staging an image asks `allows`.

A root built without `W1700K_RELEASE_KEYS` has no key file. `pinned` then says
0, and the unit takes any update, as it always has.
