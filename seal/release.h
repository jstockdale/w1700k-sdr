/* SPDX-License-Identifier: MIT */
/* What makes a WMS2 envelope a release of this product, or a rotation of the
 * keys a unit trusts. init/initkit/seal.py holds the same values, and a test
 * holds the two files to each other. */
#ifndef W1700K_RELEASE_H
#define W1700K_RELEASE_H

/* What the signature is bound to besides the manifest: a release for another
 * product, sealed by the same key, does not verify as one for this. */
#define RELEASE_TOPIC "w1700k-sdr/release"
/* The envelope's device field: every unit of the product, not one of them. */
#define RELEASE_PRODUCT "w1700k-sdr"
/* Header, manifest and signature together. A manifest is under a kilobyte. */
#define RELEASE_ENVELOPE_MOST 16384
/* The highest number a release may have: every tool that compares release
 * numbers, the unit's shell among them, counts this far without fault. */
#define RELEASE_NUMBER_MOST 9007199254740991

/* A rotation: the complete list of the keys a unit is to trust from then on,
 * sealed under its own topic, so that a key which may seal a release cannot
 * seal a list and the other way round. A list is of an epoch and, in it, of a
 * generation; the counter is the generation. Only a root key starts an epoch,
 * so whatever a lesser key has sealed, a root key's list comes after it. */
#define ROTATE_TOPIC "w1700k-sdr/rotate-keys"
#define EPOCH_MOST 9999
#define GENERATION_MOST 1000000000
/* A list is its generation and at most this many keys, each a line of text. */
/* That a unit was given a list at the bench is marked where only a bench reaches:
 * a variable in the stock boot loader's environment, which sits at the start of
 * the `uenv` partition as a CRC-32 (little-endian) and then the variables. */
#define KEYED_MARK "w1700k_keyed=1"
#define STOCK_ENVIRONMENT 0x4000
#define KEYS_MOST 8
#define KEY_NAME_MOST 48
#define LIST_MOST 1100

#endif
