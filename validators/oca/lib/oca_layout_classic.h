// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Classic-variant-specific layout: the magic value, body size,
 * signed-region boundary, trailer, and the Classic offsets of the
 * variant-positioned signature_classic / manifest_hash fields.
 *
 * Shared fields (identity, selector_bits, the classic-crypto key family, etc.)
 * live in oca_layout.h.
 *
 * Mirrors the Classic variant constants in `src/oca/constants.py`.
 */

#ifndef OCA_LAYOUT_CLASSIC_H
#define OCA_LAYOUT_CLASSIC_H

#include "oca_layout.h"

#define OCA_CLASSIC_BODY_SIZE             4096u
#define OCA_CLASSIC_SIGNED_REGION_END     3172u   /* signed region: bytes [0, 3172) */
/* payload_offset — i64 LE, in the UNSIGNED tail. Signed on purpose: a negative
 * value places the payload before the manifest. Resolved and bounds-checked by
 * oca_locate_payload(); never trusted as-is. */
#define OCA_CLASSIC_OFF_PAYLOAD_OFFSET    3748u

/* Appended-entry sizes for this variant (2048 B classic). */
#define OCA_CLASSIC_VERIFIER_ENTRY_SIZE   2048u
#define OCA_CLASSIC_CO_SIGNER_ENTRY_SIZE  2048u
#define OCA_CLASSIC_MAGIC                 "OCAC"

/* classic_manifest_trailer: four 0xCA bytes closing the signed region. */
#define OCA_CLASSIC_OFF_TRAILER           3168u
#define OCA_CLASSIC_TRAILER_BYTE          0xCAu
#define OCA_CLASSIC_TRAILER_LEN              4u

/* Unsigned-tail field offsets (Classic positions; lengths are shared). */
#define OCA_CLASSIC_OFF_SIGNATURE         3172u   /* signature_classic, OCA_LEN_SIGNATURE */
#define OCA_CLASSIC_OFF_MANIFEST_HASH     3684u   /* OCA_LEN_MANIFEST_HASH */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(
    OCA_CLASSIC_OFF_TRAILER + OCA_CLASSIC_TRAILER_LEN == OCA_CLASSIC_SIGNED_REGION_END,
    "classic trailer must end exactly at the signed-region boundary");
_Static_assert(
    OCA_CLASSIC_OFF_SIGNATURE == OCA_CLASSIC_SIGNED_REGION_END,
    "signature_classic must begin at the signed-region boundary");
_Static_assert(
    OCA_LEN_MANIFEST_HASH >= OCA_MANIFEST_HASH_DIGEST_SIZE,
    "manifest_hash field must accommodate the manifest-hash digest");
#endif

#endif /* OCA_LAYOUT_CLASSIC_H */
