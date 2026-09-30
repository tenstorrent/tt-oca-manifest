// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief PQC-variant-specific layout: fields unique to the OCA-PQC manifest,
 * plus the PQC positions of shared fields (signature_classic / manifest_hash /
 * payload_offset) that shift down because the PQC signed block is inserted
 * ahead of the unsigned tail.
 *
 * Shared fields (identity, selector_bits, the classic-crypto key family, etc.)
 * live in oca_layout.h.
 *
 * Mirrors the PQC variant constants in `src/oca/constants.py` (verified against
 * the OCA boot manifest specification).
 */

#ifndef OCA_LAYOUT_PQC_H
#define OCA_LAYOUT_PQC_H

#include "oca_layout.h"

#define OCA_PQC_BODY_SIZE                  36864u
#define OCA_PQC_SIGNED_REGION_END           5903u   /* signed region: bytes [0, 5903) */
#define OCA_PQC_MAGIC                      "OCAP"

/* classic_manifest_trailer slot: same offset as Classic, 0x35-filled in PQC. */
#define OCA_PQC_OFF_CLASSIC_TRAILER_SLOT    3168u
#define OCA_PQC_CLASSIC_TRAILER_SLOT_BYTE   0x35u
#define OCA_PQC_CLASSIC_TRAILER_SLOT_LEN       4u

/* PQC-only signed fields (after the 0x35 slot, before the PQC trailer). */
#define OCA_PQC_OFF_SIGNATURE_TYPE          3172u   /* u8 */
#define OCA_PQC_OFF_SIGNATURE_ENCODING      3173u   /* u8 */
#define OCA_PQC_OFF_SIGNATURE_SIZE          3174u   /* u16 LE — valid bytes in signature_pqc */
#define OCA_PQC_OFF_PUBLIC_KEY_SELECT       3176u
#define OCA_PQC_LEN_PUBLIC_KEY_SELECT         16u
#define OCA_PQC_OFF_PUBLIC_KEY              3192u
#define OCA_PQC_LEN_PUBLIC_KEY             2624u
#define OCA_PQC_OFF_PUBLIC_KEY_ENCODING     5816u   /* u8 */
#define OCA_PQC_OFF_PUBLIC_KEY_SIZE         5817u   /* u16 LE — valid bytes in public_key_pqc */
#define OCA_PQC_OFF_PUBLIC_KEY_REVOKE       5819u
#define OCA_PQC_LEN_PUBLIC_KEY_REVOKE         16u

/* pqc_manifest_trailer: four 0x96 bytes closing the PQC signed region. */
#define OCA_PQC_OFF_TRAILER                 5899u
#define OCA_PQC_TRAILER_BYTE                0x96u
#define OCA_PQC_TRAILER_LEN                    4u

/* Unsigned-tail field offsets (PQC positions; shifted down vs Classic;
 * lengths are shared — see OCA_LEN_* in oca_layout.h). */
#define OCA_PQC_OFF_SIGNATURE               5903u   /* signature_classic, OCA_LEN_SIGNATURE */
#define OCA_PQC_OFF_MANIFEST_HASH           6415u   /* OCA_LEN_MANIFEST_HASH */
#define OCA_PQC_OFF_PAYLOAD_OFFSET          6479u   /* i64 LE */

/* Appended-entry sizes for this variant (34816 B PQC). */
#define OCA_PQC_VERIFIER_ENTRY_SIZE        34816u
#define OCA_PQC_CO_SIGNER_ENTRY_SIZE       34816u
#define OCA_PQC_OFF_SIGNATURE_PQC           6495u   /* signature_pqc (deferred -> 0x00) */
#define OCA_PQC_LEN_SIGNATURE_PQC          29824u

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(
    OCA_PQC_OFF_TRAILER + OCA_PQC_TRAILER_LEN == OCA_PQC_SIGNED_REGION_END,
    "pqc_manifest_trailer must end exactly at the PQC signed-region boundary");
_Static_assert(
    OCA_PQC_OFF_SIGNATURE == OCA_PQC_SIGNED_REGION_END,
    "signature_classic must begin at the PQC signed-region boundary");
_Static_assert(
    OCA_PQC_OFF_PUBLIC_KEY + OCA_PQC_LEN_PUBLIC_KEY <= OCA_PQC_OFF_TRAILER,
    "public_key_pqc must fit before the PQC trailer");
_Static_assert(
    OCA_PQC_OFF_SIGNATURE_PQC + OCA_PQC_LEN_SIGNATURE_PQC <= OCA_PQC_BODY_SIZE,
    "signature_pqc must fit within the PQC body");
#endif

#endif /* OCA_LAYOUT_PQC_H */
