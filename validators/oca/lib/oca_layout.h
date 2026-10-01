// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Byte offsets, sizes, and masks SHARED by every OCA boot manifest
 * variant (fields present in both Classic and PQC at the SAME offset).
 *
 * Variant-specific fields — those that only exist in one variant, or whose
 * offset changes between variants — live in the per-variant headers
 * `oca_layout_classic.h` and `oca_layout_pqc.h`. PQC is a superset of Classic;
 * keeping the shared base here (with neutral `OCA_OFF_*` / `OCA_LEN_*` names)
 * and only the variable parts in the variant headers makes that relationship
 * explicit. `oca_validate()` selects a variant by reading the magic bytes.
 *
 * Every value here mirrors a counterpart in `src/oca/constants.py`;
 * `lib/scripts/sync_layout.py` diff-checks this file against the packer
 * constants on every CI run — drift is a build failure.
 */

#ifndef OCA_LAYOUT_H
#define OCA_LAYOUT_H

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Magic (offset shared; the 4-byte value is variant-specific)        */
/* ------------------------------------------------------------------ */

#define OCA_OFF_MAGIC                       0u
#define OCA_MAGIC_LEN                       4u
#define OCA_MANIFEST_UNUSED_BYTE            0xA5u

/* ------------------------------------------------------------------ */
/* Identification & version (early body header)                       */
/* ------------------------------------------------------------------ */

#define OCA_OFF_MANIFEST_IDENTIFIER         4u
#define OCA_LEN_MANIFEST_IDENTIFIER         8u
#define OCA_OFF_MANIFEST_VERSION_MAJOR     12u   /* u16 LE */
#define OCA_OFF_MANIFEST_VERSION_MINOR     14u   /* u16 LE */
#define OCA_OFF_MANIFEST_LENGTH            16u   /* u32 LE — value is the variant body size */

/* ------------------------------------------------------------------ */
/* selector_bits + identity fields                                    */
/* ------------------------------------------------------------------ */

#define OCA_OFF_SELECTOR_BITS              24u
#define OCA_LEN_SELECTOR_BITS              16u   /* 128 bits */

#define OCA_OFF_CHIPLET_ID                 40u
#define OCA_OFF_PACKAGE_ID                 72u
#define OCA_OFF_SYSTEM_ID                 104u
#define OCA_LEN_IDENTITY                   32u   /* per identity field */

/* selector_bits subfields */
#define OCA_SELECTOR_BIT_LIFECYCLE_CHIPLET   96u
#define OCA_SELECTOR_BIT_LIFECYCLE_PACKAGE   97u
#define OCA_SELECTOR_BIT_LIFECYCLE_SYSTEM    98u
#define OCA_SELECTOR_BIT_VERSION_CHIPLET_MIN 99u
#define OCA_SELECTOR_BIT_VERSION_CHIPLET_MAX 100u
#define OCA_SELECTOR_BIT_VERSION_PACKAGE_MIN 101u
#define OCA_SELECTOR_BIT_VERSION_PACKAGE_MAX 102u
#define OCA_SELECTOR_BIT_VERSION_SYSTEM_MIN  103u
#define OCA_SELECTOR_BIT_VERSION_SYSTEM_MAX  104u
#define OCA_SELECTOR_BITS_USED_LIMIT        105u  /* bits 0..104 valid */

/* ------------------------------------------------------------------ */
/* lifecycle_*_states + version_range_*                               */
/* ------------------------------------------------------------------ */

#define OCA_OFF_LIFECYCLE_CHIPLET_STATES   136u  /* u32 LE */
#define OCA_OFF_LIFECYCLE_PACKAGE_STATES   140u
#define OCA_OFF_LIFECYCLE_SYSTEM_STATES    144u
#define OCA_LEN_LIFECYCLE_STATES             4u
#define OCA_LIFECYCLE_STATES_VALID_MASK   0x0000007Fu  /* bits 0..6 */

#define OCA_OFF_VERSION_RANGE_CHIPLET      148u
#define OCA_OFF_VERSION_RANGE_PACKAGE      156u
#define OCA_OFF_VERSION_RANGE_SYSTEM       164u
#define OCA_LEN_VERSION_RANGE                8u
/* Layout within each 8-byte version_range field: */
#define OCA_VR_OFF_MINOR_MIN                 0u
#define OCA_VR_OFF_MAJOR_MIN                 2u
#define OCA_VR_OFF_MINOR_MAX                 4u
#define OCA_VR_OFF_MAJOR_MAX                 6u

/* ------------------------------------------------------------------ */
/* demotion_control + secure-boot control + classic-crypto key fields */
/* (all shared: present at the same offset in both variants)          */
/* ------------------------------------------------------------------ */

#define OCA_OFF_DEMOTION_CONTROL           172u  /* u16 LE */
#define OCA_LEN_DEMOTION_CONTROL             2u
#define OCA_DEMOTION_CONTROL_VALID_MASK   0x000Fu /* bits 0..3 */

#define OCA_OFF_SECURE_BOOT_CONTROL        182u  /* u8 */
#define OCA_SECURE_BOOT_ENFORCED_BIT      0x01u  /* bit0: secure_boot_enforced */
#define OCA_SECURE_BOOT_CLASSIC_BIT       0x02u  /* bit1: secure_boot_classic — classical signature class */
#define OCA_SECURE_BOOT_PQC_BIT           0x04u  /* bit2: secure_boot_pqc — PQC signature class */
#define OCA_OFF_MANIFEST_SECURITY_CONTROL  191u  /* u16 LE — device-state update-disable bits */
#define OCA_LEN_MANIFEST_SECURITY_CONTROL    2u
/* manifest_security_control bits (only respected when secure boot is enabled).
 * Bits 2 and 3 are defined by the format but NOT honoured here: both govern
 * verifier-key device state, and verifier-entry verification is not implemented
 * (see README "Not supported"). They are named so the gap reads as known rather
 * than missed. Bits [15:6] are reserved and, per the reserved-bit policy in
 * parser.c, are ignored rather than rejected. */
#define OCA_SECURITY_CONTROL_MSV_UPDATE_DISABLE_BIT       0x0001u /* bit0: suppress security-version OR-in */
#define OCA_SECURITY_CONTROL_REVOKE_KEYS_DISABLE_BIT      0x0002u /* bit1: suppress ROOT-key revocation OR-in */
#define OCA_SECURITY_CONTROL_VERIFIER_SECVER_DISABLE_BIT  0x0004u /* bit2: not honoured — verifier deferred */
#define OCA_SECURITY_CONTROL_VERIFIER_REVOKE_DISABLE_BIT  0x0008u /* bit3: not honoured — verifier deferred */
#define OCA_SECURITY_CONTROL_COHORT_ENFORCE_DISABLE_BIT   0x0010u /* bit4: suppress cohort-enforce OR-in */
#define OCA_SECURITY_CONTROL_CLASS_REVOKE_DISABLE_BIT     0x0020u /* bit5: suppress class-revoke OR-in */
#define OCA_OFF_SIGNATURE_TYPE             2092u /* u8 — classic-crypto signature type */
#define OCA_OFF_SIGNATURE_ENCODING         2093u /* u8 */
#define OCA_OFF_SIGNATURE_SIZE             2094u /* u16 LE — valid bytes in signature_classic */
#define OCA_OFF_PUBLIC_KEY_SELECT          2104u /* 16 bytes */
#define OCA_LEN_PUBLIC_KEY_SELECT           16u
#define OCA_OFF_PUBLIC_KEY                 2120u /* 532 bytes — classic public key */
#define OCA_LEN_PUBLIC_KEY                  532u
#define OCA_OFF_PUBLIC_KEY_ENCODING        2652u /* u8 */
#define OCA_OFF_PUBLIC_KEY_SIZE            2653u /* u16 LE — valid bytes in public_key_classic */

/* ------------------------------------------------------------------ */
/* Secure-boot device-state fields (shared classic offsets)          */
/*                                                                    */
/* ROOT-key revocation + anti-rollback security version. Consumed only */
/* when secure boot is enabled: checked against host-supplied device   */
/* state and advanced by the explicit post-verify commit. See          */
/* revocation.c / security_version.c.                                  */
/* ------------------------------------------------------------------ */

#define OCA_OFF_MANIFEST_SECURITY_VERSION  2042u /* 16 bytes — 128 independent security flags */
#define OCA_LEN_MANIFEST_SECURITY_VERSION    16u
#define OCA_OFF_PUBLIC_KEY_CLASSIC_REVOKE  2655u /* 16 bytes — classic ROOT-key revoke bitmap */
#define OCA_LEN_PUBLIC_KEY_CLASSIC_REVOKE    16u
/* public_key_select_classic and public_key_classic_revoke are 128-bit bitmaps:
 * bits 0..111 are seven 16-bit key groups (bytes 0..13); bits 127:112
 * (bytes 14..15) are reserved and ignored. Comparisons use the used bytes only. */
#define OCA_ROOT_KEY_BITMAP_USED_BYTES       14u /* bytes 0..13 = 112 used bits */

/* ------------------------------------------------------------------ */
/* Signature posture registers (shared classic offsets)               */
/*                                                                    */
/* Two device control registers the Consumer folds into vendor storage */
/* (typically OTP) after a fully verified boot. Neither participates in */
/* verifying the manifest that carries it: they govern how signatures   */
/* are treated on SUBSEQUENT boots. Updates are OR-in and therefore     */
/* monotonic — restrictions only ever accumulate.                      */
/* ------------------------------------------------------------------ */

#define OCA_OFF_SIGNATURE_COHORT_ENFORCE   2076u /* 8 bytes — 4-bit cohort nibble per signed entity */
#define OCA_LEN_SIGNATURE_COHORT_ENFORCE      8u
#define OCA_OFF_SIGNATURE_CLASS_REVOKE     2084u /* 8 bytes — per-class bits + two group-code bytes */
#define OCA_LEN_SIGNATURE_CLASS_REVOKE        8u

/* signature_class_revoke group codes. A group code is a single constant, not a
 * bitmask: only its exact value carries meaning, and an intact code disables the
 * whole algorithm group. Because the device-side register accumulates by OR, the
 * interlock holds only if no manifest ever carries a FRAGMENT of a code —
 * fragments from separate manifests would otherwise accumulate into an intact
 * constant that no single manifest declared. Hence the reject below. */
#define OCA_CLASS_REVOKE_OFF_CLASSIC_GROUP_CODE  1u    /* b[15:8]  = byte 1 */
#define OCA_CLASS_REVOKE_OFF_PQC_GROUP_CODE      4u    /* b[39:32] = byte 4 */
#define OCA_CLASS_REVOKE_CLASSIC_GROUP_CODE   0xCAu
#define OCA_CLASS_REVOKE_PQC_GROUP_CODE       0xACu

/* ------------------------------------------------------------------ */
/* Appended-entry controls (shared offsets)                           */
/*                                                                    */
/* The verifier-key entry and any co-signer entries are appended       */
/* immediately after the manifest body, so they extend the manifest's  */
/* footprint in storage. Their VERIFICATION is not implemented (see    */
/* README "Not supported"), but their SIZES are needed to bound where  */
/* the payload may legally sit — see oca_manifest_region_len().        */
/* Both counts live in the signed region, so the bound is derivable    */
/* from authenticated data without reading any appended byte.          */
/* ------------------------------------------------------------------ */

#define OCA_OFF_VERIFIER_KEY_CONTROL       2011u /* u8 */
#define OCA_VERIFIER_KEY_CONTROL_USE_BIT   0x01u /* bit0: use_verifier_key */
#define OCA_OFF_CO_SIGNER_CONTROL          2020u /* u16 LE */
#define OCA_CO_SIGNER_ENABLE_MASK        0x00FFu /* bits[7:0]: up to 8 co-signers */
#define OCA_CO_SIGNER_MAX                     8u

/* ------------------------------------------------------------------ */
/* Payload metadata + descriptive fields                              */
/* ------------------------------------------------------------------ */

#define OCA_OFF_MANIFEST_CONTENT_VERSION  2968u  /* 8 bytes (major, minor, patch) */
#define OCA_OFF_MANIFEST_DESCRIPTION      2976u  /* 128 bytes, NUL-terminated */
#define OCA_LEN_MANIFEST_DESCRIPTION       128u

/* ------------------------------------------------------------------ */
/* Shared lengths for the variant-positioned signature / hash fields  */
/* (the OFFSETS live in the per-variant headers; the LENGTHS are the  */
/*  same in both variants)                                            */
/* ------------------------------------------------------------------ */

#define OCA_LEN_SIGNATURE                  512u  /* classic signature_classic */
#define OCA_LEN_MANIFEST_HASH               64u  /* manifest-hash digest + zero pad; digest type per manifest_hash_type */
#define OCA_MANIFEST_HASH_DIGEST_SIZE       32u  /* digest size this pass validates (SHA-256, manifest_hash_type=0x01) */

/* ------------------------------------------------------------------ */
/* Payload encryption + payload-hash fields (shared offsets)          */
/*                                                                    */
/* Consumed only when validating an encrypted payload. payload_hash   */
/* covers the ciphertext; payload_hash_chain covers the plaintext.    */
/* ------------------------------------------------------------------ */

#define OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL 201u  /* u16 LE */
#define OCA_ENCRYPTION_ENCRYPTED_PAYLOAD_BIT 0x0001u  /* bit[0] of payload_encryption_control */
#define OCA_OFF_ENCRYPTION_SHARED_SECRET_SELECT 205u  /* u16 LE; which provisioned secret */
#define OCA_OFF_ENCRYPTION_IV              235u  /* 32-byte field; AES-CBC uses the low 16 */
#define OCA_LEN_ENCRYPTION_IV               16u
#define OCA_OFF_ENCRYPTION_KDF_INPUT       275u  /* 64-byte field; full field = KDF context */
#define OCA_LEN_ENCRYPTION_KDF_INPUT        64u
#define OCA_OFF_ENCRYPTION_TYPE           2058u  /* u8; the cipher values are public
                                                  * API — oca_encryption_type_t in
                                                  * oca_validator.h */
#define OCA_AES_BLOCK_SIZE                  16u  /* AES-CBC ciphertext is block-aligned */
#define OCA_OFF_PAYLOAD_HASH              2775u  /* 64-byte field; digest over the stored payload */
#define OCA_OFF_PAYLOAD_HASH_CHAIN        2847u  /* 64-byte field; chained digest over the plaintext */
#define OCA_OFF_PAYLOAD_HASHED_LENGTH     2911u  /* u64 LE; ciphertext length when encrypted, TOC byte count otherwise */
#define OCA_OFF_PAYLOAD_LENGTH            2960u  /* u64 LE; total stored payload length */

/* ------------------------------------------------------------------ */
/* Payload table-of-contents (PTOC) layout                            */
/*                                                                    */
/* Parsed from the cleartext payload, or from the decrypted plaintext  */
/* when the payload is encrypted, to validate the TOC structure,       */
/* recompute payload_hash_chain, and verify each entry's image hash.   */
/* Mirrors the "Payload TOC" / "Payload TOC entry" spec tables; every  */
/* offset has a counterpart in src/oca/constants.py.                   */
/* ------------------------------------------------------------------ */

#define OCA_TOC_HEADER_SIZE                 32u
#define OCA_TOC_ENTRY_SIZE                 280u

/* Within the 32-byte PTOC header. */
#define OCA_TOC_OFF_MAGIC                    0u  /* 4 bytes, "PTOC" */
#define OCA_TOC_OFF_VERSION_MAJOR            4u  /* u16 LE */
#define OCA_TOC_OFF_VERSION_MINOR            6u  /* u16 LE */
#define OCA_TOC_OFF_PAYLOAD_LENGTH           8u  /* u64 LE */
#define OCA_TOC_OFF_IMAGE_COUNT             16u  /* u64 LE */

/* Within one 280-byte TOC entry. Bytes 20..24 and 272..280 are reserved. */
#define OCA_TOC_ENTRY_OFF_TYPE               0u  /* 16 ASCII bytes */
#define OCA_TOC_ENTRY_LEN_TYPE              16u
#define OCA_TOC_ENTRY_OFF_GROUP             16u  /* u32 LE */
#define OCA_TOC_ENTRY_OFF_OFFSET            24u  /* u64 LE */
#define OCA_TOC_ENTRY_OFF_LENGTH            32u  /* u64 LE */
#define OCA_TOC_ENTRY_OFF_VERSION           40u  /* u64 LE */
#define OCA_TOC_ENTRY_OFF_SECURITY_VERSION  48u  /* u64 LE */
#define OCA_TOC_ENTRY_OFF_LOAD_ADDR         56u  /* u64 LE */
#define OCA_TOC_ENTRY_OFF_ENTRY_POINT       64u  /* u64 LE */
#define OCA_TOC_ENTRY_OFF_TARGET_CHIPLET_ID 72u  /* u64 LE */
#define OCA_TOC_ENTRY_OFF_HASH              80u  /* 64-byte field; digest at offset 0 */
#define OCA_TOC_ENTRY_OFF_DESCRIPTION      144u  /* 128 bytes, NUL-terminated */
#define OCA_TOC_ENTRY_LEN_DESCRIPTION      128u

/* ------------------------------------------------------------------ */
/* Self-consistency                                                    */
/*                                                                     */
/* The offsets above are transcribed by hand from the spec's field      */
/* table, where every field is packed back-to-back. Asserting that      */
/* neighbors are contiguous catches a mistyped digit at compile time   */
/* rather than as a mis-parsed manifest. Only runs of fields with no    */
/* intervening reserved region can be checked this way — reserved       */
/* regions are deliberately not given macros here.                      */
/* ------------------------------------------------------------------ */

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(OCA_OFF_SIGNATURE_COHORT_ENFORCE + OCA_LEN_SIGNATURE_COHORT_ENFORCE
               == OCA_OFF_SIGNATURE_CLASS_REVOKE,
               "signature_class_revoke must follow signature_cohort_enforce");
_Static_assert(OCA_OFF_SIGNATURE_CLASS_REVOKE + OCA_LEN_SIGNATURE_CLASS_REVOKE
               == OCA_OFF_SIGNATURE_TYPE,
               "signature_type_classic must follow signature_class_revoke");
_Static_assert(OCA_OFF_SIGNATURE_TYPE + 1u == OCA_OFF_SIGNATURE_ENCODING,
               "signature_encoding_classic must follow signature_type_classic");
_Static_assert(OCA_OFF_SIGNATURE_ENCODING + 1u == OCA_OFF_SIGNATURE_SIZE,
               "signature_size_classic must follow signature_encoding_classic");
_Static_assert(OCA_OFF_PUBLIC_KEY_SELECT + OCA_LEN_PUBLIC_KEY_SELECT == OCA_OFF_PUBLIC_KEY,
               "public_key_classic must follow public_key_select_classic");
_Static_assert(OCA_OFF_PUBLIC_KEY + OCA_LEN_PUBLIC_KEY == OCA_OFF_PUBLIC_KEY_ENCODING,
               "public_key_encoding_classic must follow public_key_classic");
_Static_assert(OCA_OFF_PUBLIC_KEY_ENCODING + 1u == OCA_OFF_PUBLIC_KEY_SIZE,
               "public_key_size_classic must follow public_key_encoding_classic");
_Static_assert(OCA_OFF_PUBLIC_KEY_SIZE + 2u == OCA_OFF_PUBLIC_KEY_CLASSIC_REVOKE,
               "public_key_classic_revoke must follow public_key_size_classic");
_Static_assert(OCA_OFF_MANIFEST_CONTENT_VERSION + 8u == OCA_OFF_MANIFEST_DESCRIPTION,
               "manifest_description must follow manifest_content_version");
_Static_assert(OCA_TOC_ENTRY_OFF_OFFSET + 8u == OCA_TOC_ENTRY_OFF_LENGTH
               && OCA_TOC_ENTRY_OFF_LENGTH + 8u == OCA_TOC_ENTRY_OFF_VERSION
               && OCA_TOC_ENTRY_OFF_VERSION + 8u == OCA_TOC_ENTRY_OFF_SECURITY_VERSION
               && OCA_TOC_ENTRY_OFF_SECURITY_VERSION + 8u == OCA_TOC_ENTRY_OFF_LOAD_ADDR
               && OCA_TOC_ENTRY_OFF_LOAD_ADDR + 8u == OCA_TOC_ENTRY_OFF_ENTRY_POINT
               && OCA_TOC_ENTRY_OFF_ENTRY_POINT + 8u == OCA_TOC_ENTRY_OFF_TARGET_CHIPLET_ID
               && OCA_TOC_ENTRY_OFF_TARGET_CHIPLET_ID + 8u == OCA_TOC_ENTRY_OFF_HASH,
               "TOC entry u64 fields must run back-to-back from offset to hash");
_Static_assert(OCA_TOC_ENTRY_OFF_HASH + 64u == OCA_TOC_ENTRY_OFF_DESCRIPTION,
               "TOC entry description must follow hash");
/* The spec requires 8-byte alignment of every u64 entry field and of every
 * entry start, which holds only while the entry size is a multiple of 8. */
_Static_assert(OCA_TOC_ENTRY_OFF_OFFSET % 8u == 0u && OCA_TOC_HEADER_SIZE % 8u == 0u
               && OCA_TOC_ENTRY_SIZE % 8u == 0u,
               "TOC entries and their u64 fields must be 8-byte aligned");
/* Both group-code bytes must land inside the field they index into. */
_Static_assert(OCA_CLASS_REVOKE_OFF_PQC_GROUP_CODE < OCA_LEN_SIGNATURE_CLASS_REVOKE,
               "PQC group code byte must lie within signature_class_revoke");
#endif

#endif /* OCA_LAYOUT_H */
