/* SPDX-License-Identifier: MIT */
/* What makes a WMS2 envelope a release of this product. init/initkit/seal.py
 * holds the same three values, and a test holds the two files to each other. */
#ifndef W1700K_RELEASE_H
#define W1700K_RELEASE_H

/* What the signature is bound to besides the manifest: a release for another
 * product, sealed by the same key, does not verify as one for this. */
#define RELEASE_TOPIC "w1700k-sdr/release"
/* The envelope's device field: every unit of the product, not one of them. */
#define RELEASE_PRODUCT "w1700k-sdr"
/* Header, manifest and signature together. A manifest is under a kilobyte. */
#define RELEASE_ENVELOPE_MOST 16384

#endif
