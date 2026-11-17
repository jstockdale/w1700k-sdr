# Signed releases and the keys a unit trusts: the unit's verifier

A keyed unit takes over ssh only an update whose manifest a release key sealed,
and changes whom it trusts only on the word of a key above the release keys.
This directory is what verifies both on the unit: `w1700k-release`, in the root
as `/usr/sbin/w1700k-release`.

| File | Whose | Licence |
| --- | --- | --- |
| `release.c`, `release.h` | this project: the program, what makes an envelope a release or a rotation of this product, and what a list of keys is | MIT |
| `wms2.c`, `include/wms2.h` | Whitehat Hardware: the WMS2 envelope verifier its devices take their commands with | MIT |
| `monocypher.c`, `monocypher.h`, `optional/monocypher-ed25519.c`, `optional/monocypher-ed25519.h` | Monocypher, by Loup Vaillant, with its RFC 8032 Ed25519 module | BSD-2-Clause OR CC0-1.0 |

`development/` is not code: it is Whitehat Hardware's development lists of keys,
each as it was sealed, oldest first. The first, 1.1 of 2026-11-15, names the
development root, the development keys key and two development release keys;
1.2 replaces the first release key, sealed by the keys key; 2.1 replaces the
keys key, sealed by the root, and starts the second epoch.
A test holds the chain to what was issued: the keys, their fingerprints, and
who sealed each list. These keys seal development releases; no unit that ships
holds them. `init/bench key --carry seal/development` keys a development unit
with them, and `--carry seal/development` puts them into a development
release.

The last two rows of the table are vendored as they came, byte for byte, from
Whitehat Hardware's `whitehat-watcher` firmware (its `seal` component at commit
`bf6bc16`, 2026-11-10). They are not edited here: a change belongs there first.
They build under `-Wall -Wextra -Werror -Wno-comment`, as their own test
harness builds them; the one exemption is for a comment in `wms2.h`.

## The envelope

Everything sealed is a WMS2 control envelope:

```
"WMS2" | kind 2 | flags 0 | device, 16 bytes | counter u64 | time u64, ms | 2 reserved    (40 bytes)
the body
an Ed25519 signature (RFC 8032) over:  u16(len(topic)) | topic | header | body
```

The **device** field is `w1700k-sdr`, the product and not one unit. The
**topic** is part of what is signed, so what is sealed under one topic does not
verify under another. A unit has no clock: the **counter** is all it orders
things by, and the time is the signer's, for whoever reads it. The verifier
here is stricter than the envelope's own: a flag, a reserved byte that is not
zero, or anything after the product in the device field is refused though
signed.

| | Topic | Body | Counter |
| --- | --- | --- | --- |
| A release | `w1700k-sdr/release` | an update archive's manifest: the SHA-256 of every image in it | the release number |
| A rotation | `w1700k-sdr/rotate-keys` | the complete list of keys a unit is to trust from then on | the list's generation |
| A statement | `w1700k-sdr/current` | what is current: the list there is and the newest release | the statement's number |

## A list of keys

What a unit trusts is a list, kept in its durable storage (`/durable/keys`),
where no update reaches it. It is kept sealed: not as text the unit would have
to believe, but as the envelopes that bear it out, which every read checks
again (below, "What a unit keeps"). A list reads:

```
w1700k-sdr keys 2.3
<64 hex digits>  root  <name>
<64 hex digits>  keys  <name>
<64 hex digits>  release  <name>
```

A list is of an **epoch** and, in it, of a **generation**: `2.3` is the third
list of the second epoch. Lists are in order by epoch and then generation.

A key's **scope** is what it may seal:

| Scope | Seals |
| --- | --- |
| `release` | a release |
| `timestamp` | nothing a unit takes: a statement, for a host, of what is current |
| `keys` | the next list of the epoch, which leaves every `root` and `keys` line as it is: it replaces release and timestamp keys |
| `root` | that, and the first list of the next epoch, which may change any line |

So a key that seals releases cannot change who is trusted, a key that replaces
release keys cannot replace itself or the key above it, and the `root` key,
which is the only one that can, is needed a handful of times in a product's
life and can live offline. And because only a `root` key starts an epoch, its
list comes after anything a `keys` key has sealed: a stolen `keys` key that
runs the generation as far as it goes is still put out by the next epoch.

A list is read in one form, byte for byte, by the unit and by the host alike
(`parse_list` in `release.c`, `parse_list` in `init/initkit/seal.py`; a test
gives both the same lists):

- every byte printable ASCII or a line feed, and one line feed at the end;
- the first line `w1700k-sdr keys E.G`, the epoch (to 9999) and the generation
  (to 1000000000), each a number from 1 written plainly;
- then one key to a line: 64 lowercase hex digits (an Ed25519 public key), two
  spaces, the scope, two spaces, a name of 1 to 48 lowercase letters, digits
  and hyphens;
- one to eight keys, no key and no name twice, no key of small order (a
  signature under such a key verifies for any message), and at least one
  `root` key.

A list with no `release` key is a list: a unit that holds it takes no release
until a later list gives it one.

### What a unit keeps

A unit does not keep its list as text. It keeps the sealed envelopes that bear
the list out, and reads the list from them every time, by the rules a rotation
is held to (`read_list` in `release.c`):

- the first list it was given, which a `root` key it names sealed;
- the list that began each epoch since, which a `root` key of the epoch before
  sealed;
- the list it holds now, if that is a later one of its epoch, which a `root`
  or `keys` key of that epoch sealed.

A list within an epoch cannot change a `root` or `keys` line, so the list that
began the epoch vouches for every later one of it, and the ones between are
not kept: within an epoch the file does not grow, however many lists come.

So what is on flash is a list this unit was once shown the seals of, or it is
no list. One bit wrong anywhere in it, a list altered into another that still
reads, lists out of order or one left out: each leaves the unit with no list,
which is a unit that takes nothing sealed until the bench gives it one again
(tests: every bit, and every length it can be cut to). The file is the line
`w1700k-sdr key chain 1`, then each envelope behind its length, four bytes,
low byte first.

Two things this does not do. Somebody else's lists, whole and well sealed, are
a list too: the first one is believed because a root key it names sealed it,
which is all a first list ever has, so whoever can write a unit's storage can
still give it a list of their own. That is what the keyed mark and the bench
are for. And a file cut back to where an earlier list ended reads as that
earlier list, one this unit did hold; nothing on the unit says which was the
last.

## What is current

A unit has no clock and no network. It takes the newest list and release it
has been given, so whoever delivers to it decides where its keys stop: a list
that drops a stolen key does nothing for a unit it never reaches. A statement
says what there is, for one domain. It is text in one form, as a list is, read
alike by the unit (`parse_statement` in `release.c`) and the host
(`init/initkit/seal.py`; a test gives both the same cases):

```
w1700k-sdr current 7
domain development
list 2.2 <64 hex: SHA-256 of that list's text>
release 5 <64 hex: SHA-256 of that release's manifest>
sealed 1794816426827
until 1794902826827
```

`release 0` and 64 zeros say no release has been sealed. The times are
milliseconds since 1970, UTC, and the envelope's counter and time are the
statement's number and `sealed`. A `timestamp` key seals it, which seals
nothing a unit installs and so can be used often.

- **It is read by the list its holder has.** A timestamp key of that list
  sealed it, or it says nothing. One that names a list older than the
  holder's says nothing either, whatever sealed it: so a list that drops a
  timestamp key puts that key's statements out at once, not when they run out.
- **The host holds it to its dates**, having a clock (`init/flash --current`).
  Out of date, missing or unreadable, it is said loudly and the update goes
  on: nothing here locks an owner out, and one key and one web address are
  not made a thing every unit depends on. A statement that is good stops an
  update in two cases: it names a newer list than the unit's and the update
  does not bring that list, or the archive is older than the newest release.
- **The newest shown is the system's, not the unit's alone.** The host asks
  the unit which statement it keeps, and one older than that says nothing to
  the host either, however good its dates: a stale copy of the statement
  cannot put the host's judgement back. Another statement under the number
  the unit keeps is said, and says nothing.
- **The unit keeps the newest it was shown**, whatever its dates, sealed, in
  its durable storage, and reads it by its seal each time as it reads its
  list. Once that names a newer list than the unit holds, the unit takes no
  release until it holds that list. Keeping a list from a unit therefore
  stops working the first time the unit meets a host that does not.
- **What a unit keeps and cannot read** stops releases until it is shown a
  statement that reads; an owner's own build (`--unsigned`) is taken as ever.
  Written over to name a list the unit already has, a kept statement is as
  good as gone, which is what deleting it gives too: nothing in a unit's
  storage can be more than that.

Statements are numbered and a unit takes only a higher number than it keeps;
they need not follow on, since a unit is not shown every one.

## What a unit takes

- **A release** sealed by a `release` key of the list it holds, whose number is
  not below the newest release it has confirmed, and, under that very number,
  only the release it confirmed. A release number is at most 2^53 - 1.
- **A rotation** sealed by a `root` or `keys` key of the list it holds, which
  is one of two things: a later generation of the epoch it holds, with the
  `root` and `keys` lines the ones it holds (in any order); or generation 1 of
  the next epoch, sealed by a `root` key, with any lines.
- **The list it holds, again:** nothing changes, and it is no fault.
- **Another list with the epoch and generation it holds**, sealed by a `root`
  or `keys` key of that list, is refused, loudly: two lists were sealed as
  one. What no such key sealed is refused as that, and nothing more is
  said of it.
- **A first list**, by a unit that holds none: sealed by a `root` key the list
  names itself. Nothing on the unit can say whose keys those are, so a unit
  takes a first list only at the bench, on its serial console, from a person
  who has held the fingerprints to the record of how the keys were issued
  (`init/bench key`, [init/README.md](../init/README.md#signed-releases)).

Rotations follow one from another: a unit an epoch behind has to be given the
first list of each epoch since, in order, because each may be sealed by a key
only the one before it brought. A release archive carries every rotation so
far for that, and its sealed manifest names each by digest, so one taken out
of the archive or put into it on the way is seen.

What this does not do: firmware runs as root on a unit, so a unit that has
installed a thief's release is the thief's, list and all. The list protects
the units that have not. And if a `root` key is stolen, whoever holds it can
start the next epoch with a list of their own; a unit takes whichever it is
given first. Nothing here tells a unit, or its host, that a list or a release
it has not been given exists: that takes a statement of what is current,
sealed and dated, which the `timestamp` scope is kept for and which is not
built yet.

## The program

```
w1700k-release verify [--keys FILE] [--state DIR] [--floor N] ENVELOPE
w1700k-release rotate [--keys FILE] [--first] --out FILE ENVELOPE
w1700k-release list [--keys FILE]
w1700k-release mark --environment FILE
w1700k-release allows [--state DIR] SHA256
w1700k-release number [--state DIR]
```

`verify` checks a release against the list's release keys and the floor, and
leaves what passes in `/run/w1700k-release`, which is in RAM. `allows` then
says whether the verified manifest lists an image with that digest. `rotate`
checks a rotation against the list held and writes the new list to `--out`;
`--first` is the first list of a unit that holds none. `list` prints the list
held with each key's fingerprint; it exits 1 for no list and 2 for one that
does not read. `mark` says whether the stock boot loader's environment
(the start of the `uenv` partition: a CRC-32, then the variables) holds
`w1700k_keyed=1`, the mark the bench sets before it gives a unit its first
list; it exits 2 when the environment does not read. `system-update` on the unit is the one caller, and it is what
keeps the list and the release number. The mark is set and cleared at the
stock boot loader's prompt, by `init/bench`; nothing on the unit writes it.

`init/initkit/seal.py` is the host's side of the same envelope and the same
rules, and `init/sign` seals with it. Tests hold the two sides to each other:
the constants, lists read alike, and rotations and signatures whose fate the
host and the unit have to agree on, among them the ones at the edges of
Ed25519 where verifiers differ.

On signatures: the unit verifies with Monocypher, which checks RFC 8032's
equation with the cofactor and would also take a point written in more than
one way. `release.c` refuses those other forms first, in a key and in a
signature, and the host's verifier checks the same equation, so the two take
the same signatures. A signature whose first half has a part of small order
verifies on both: only the holder of the key can make one.
