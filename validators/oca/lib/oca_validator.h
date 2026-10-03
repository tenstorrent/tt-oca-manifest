// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/**
 * @file
 * @brief Validate an OCA boot manifest against caller-supplied cryptographic
 * and hardware-identity callbacks.
 *
 * The library is freestanding: it requires only <stdint.h>, <stddef.h>, and
 * <stdbool.h> from the toolchain, makes no heap allocations, and holds no
 * static state across calls. Every external operation (cryptography, hardware
 * ID readback) is delegated to a caller-supplied callback table.
 *
 * A single library handles every OCA format variant. The format-specific
 * dispatch is internal, keyed on the manifest's magic bytes; integrators
 * never pick a variant at build time.
 */

#ifndef OCA_VALIDATOR_H
#define OCA_VALIDATOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "oca_secure_bool.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Two entry points — pick one                                        */
/*                                                                    */
/* STAGED — booting from external storage. Nothing is verified        */
/* where an attacker can still reach it: each region is copied        */
/* into internal memory first, then checked there.                    */
/*                                                                    */
/*   oca_peek_manifest()      size the body from a 20-byte head       */
/*     -> copy body_size bytes inward                                 */
/*   oca_validate_manifest()  authenticate the copy                   */
/*   oca_locate_payload()     bound the untrusted payload_offset      */
/*     -> copy the payload span inward                                */
/*   oca_check_payload_at()   verify the copy                         */
/*                                                                    */
/* WHOLE-BUNDLE — host tools, tests, and targets already holding      */
/* the bundle in trusted memory. oca_validate() runs the same         */
/* checks in the same order, but needs the body and payload           */
/* contiguous in one buffer and requires payload_offset to equal      */
/* the body size, so it cannot boot an image whose payload sits       */
/* at an arbitrary flash offset.                                      */
/*                                                                    */
/* Full treatment: INTEGRATION.md, "Choosing an entry point".         */
/* Reference implementation: test/main.c                              */
/* validate_from_storage(), run by `make check`.                      */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Library version                                                    */
/* ------------------------------------------------------------------ */

/**
 * @brief Manifest format major version the library was built against.
 *
 * Compatibility policy:
 *   - manifest_version_major  > OCA_LIB_MANIFEST_MAJOR  ->  FAIL.
 *   - manifest_version_major  <= OCA_LIB_MANIFEST_MAJOR ->  validate.
 */
#define OCA_LIB_MANIFEST_MAJOR  1u

/**
 * @brief Manifest format minor version the library was built against.
 *
 * A manifest_version_minor above this one is accepted, on the producer-side
 * contract that minor bumps are additive only.
 */
#define OCA_LIB_MANIFEST_MINOR  0u

/**
 * @brief Payload TOC format major version the library was built against.
 *
 * A toc_version_major above this one is rejected; a larger minor is accepted.
 */
#define OCA_LIB_TOC_MAJOR       1u

/* ------------------------------------------------------------------ */
/* Consumer resource limits                                           */
/* ------------------------------------------------------------------ */

/**
 * @brief Maximum payload TOC entries this build will process.
 *
 * The manifest format puts no upper bound on image_count — the spec says only
 * that it is a uint64 greater than zero — so the only structural bound is that
 * the TOC span fit inside the payload. That bound scales linearly with the
 * payload, while the TOC's pairwise overlap check is O(image_count^2): a
 * payload of 8 MiB admits 30393 entries and 4.6e8 pair comparisons.
 *
 * That work is reachable BEFORE any signature check when secure boot is
 * disabled, because manifest_hash and payload_hash are unkeyed SHA-256 that
 * anyone able to write flash can recompute. Left uncapped it is an availability
 * problem on non-secure parts, not merely a fuzzing artifact.
 *
 * 256 entries is far above any real boot payload (a handful of images) and
 * bounds the overlap scan at ~32k comparisons. Override at build time for a
 * tighter budget:  -DOCA_TOC_MAX_IMAGES=32
 *
 * Exceeding it fails with OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES — deliberately
 * distinct from OCA_FAIL_PAYLOAD_TOC so an integrator can tell "this consumer
 * refuses to process a manifest this large" from "this TOC is malformed".
 */
#ifndef OCA_TOC_MAX_IMAGES
#define OCA_TOC_MAX_IMAGES  256u
#endif

/**
 * @brief Re-evaluate the anti-rollback comparison after the signature verified.
 *
 * The comparison runs once BEFORE signature verification so a replayed manifest
 * is rejected without paying for a public-key operation. That early evaluation
 * is sound: the compared value lies inside the signed region, so a manifest
 * altered to change the outcome fails verification, and one that genuinely fails
 * is a rollback either way.
 *
 * This second evaluation is therefore defence in depth, not correctness — it
 * catches a fault that skipped, corrupted, or glitched past the first. On by
 * default; set to 0 only on a target that cannot afford one extra device-state
 * read and one 16-byte compare.
 */
#ifndef OCA_RECHECK_SECURITY_VERSION
#define OCA_RECHECK_SECURITY_VERSION  1
#endif

/* ------------------------------------------------------------------ */
/* Result enum                                                        */
/* ------------------------------------------------------------------ */

/**
 * @brief Outcome of a validation step: OCA_OK, or the specific reason it failed.
 *
 * Every check function and both entry points return one of these. The codes are
 * deliberately fine-grained rather than a single generic failure, because a
 * field failure is diagnosed from this value alone and several pairs of causes
 * would otherwise be indistinguishable while needing entirely different
 * remedies. Where two codes are easily confused, the enumerator below says what
 * separates them.
 *
 * A non-zero value never means "probably fine". Any code other than OCA_OK
 * means the manifest or payload MUST NOT be booted.
 */
typedef enum oca_result {
    OCA_OK                              = 0,  /**< Every check in this step passed. */
    OCA_FAIL_TRUNCATED                  = 1,  /**< Buffer is shorter than the structure being read. */
    OCA_FAIL_MAGIC                      = 2,  /**< Magic bytes match no known OCA variant. */
    OCA_FAIL_TRAILER                    = 3,  /**< Trailer closing the signed region is wrong. */
    OCA_FAIL_FORMAT_VERSION_MISMATCH    = 4,  /**< Manifest major version exceeds this build's. */
    OCA_FAIL_RESERVED_BITS              = 5,  /**< A reserved bit is set; the manifest uses a feature this build cannot honour. */
    OCA_FAIL_SECURE_BOOT_INVARIANT      = 6,  /**< Signing fields left non-zero on a manifest declaring secure_boot = 0. */
    OCA_FAIL_CHIPLET_ID                 = 7,  /**< Hardware chiplet ID does not satisfy the manifest constraint. */
    OCA_FAIL_PACKAGE_ID                 = 8,  /**< Hardware package ID does not satisfy the manifest constraint. */
    OCA_FAIL_SYSTEM_ID                  = 9,  /**< Hardware system ID does not satisfy the manifest constraint. */
    OCA_FAIL_LIFECYCLE                  = 10, /**< Device lifecycle state is not permitted by the manifest. */
    OCA_FAIL_VERSION_RANGE              = 11, /**< Hardware version falls outside the manifest's permitted range. */
    OCA_FAIL_DEMOTION_CONTROL           = 12, /**< Demotion control field is malformed or disallowed. */
    OCA_FAIL_MANIFEST_HASH              = 13, /**< Recomputed manifest hash does not match the stored digest. */
    OCA_FAIL_SIGNATURE                  = 14, /**< Signature verification over the signed region failed. */
    OCA_FAIL_CALLBACK_UNAVAILABLE       = 15, /**< A callback required by this check is NULL or reported unavailable. */
    OCA_FAIL_INVALID_ARG                = 16, /**< A NULL pointer or otherwise unusable argument was passed. */
    /** The manifest's magic names a format variant this build was not compiled
     *  to support (see the OCA_SUPPORT_* build gates). Distinct from
     *  OCA_FAIL_MAGIC, which means the magic matches no known variant. */
    OCA_FAIL_UNSUPPORTED_VARIANT        = 17,
    /** The hash over the stored payload did not match — the ciphertext when
     *  encrypted (checked BEFORE decryption), the TOC region when cleartext. */
    OCA_FAIL_PAYLOAD_HASH               = 18,
    /** Key derivation, AES-CBC decryption, or PKCS#7 unpadding failed. */
    OCA_FAIL_DECRYPT                    = 19,
    /** The chained hash over the plaintext payload did not match. Distinct from
     *  OCA_FAIL_PAYLOAD_TOC: this is a cryptographic mismatch on a
     *  structurally-valid TOC, not a malformed one. */
    OCA_FAIL_PAYLOAD_HASH_CHAIN         = 20,
    /** Payload TOC structural validation failed: image_count == 0; the TOC
     *  length (TOC_Header_Size + image_count*TOC_Entry_Size) overflows or
     *  exceeds the payload; a TOC entry's [offset, offset+length) runs out of
     *  bounds or overflows; a TOC entry's offset is not a multiple of 8; or two
     *  entries' image ranges overlap. */
    OCA_FAIL_PAYLOAD_TOC                = 21,
    /** A ROOT key selected in public_key_select is revoked, in the manifest
     *  revoke bitmap or the device-stored revocation state. Decided BEFORE the
     *  key is used to verify the signature. Secure boot only. */
    OCA_FAIL_ROOT_KEY_REVOKED           = 22,
    /** manifest_security_version is not a bit-superset of the device-stored
     *  value — an anti-rollback rejection. Secure boot only. */
    OCA_FAIL_SECURITY_VERSION           = 23,
    /** The post-verify device-state commit write-back failed. Secure boot only. */
    OCA_FAIL_SECURITY_STATE_UPDATE      = 24,
    /** A TOC entry's stored `hash` field does not match the digest of the image
     *  bytes it describes. Distinct from OCA_FAIL_PAYLOAD_HASH_CHAIN: the chain
     *  proves the payload is the one the manifest signed, but it covers the
     *  stored hash field as data, so a producer-side mismatch survives it. This
     *  is the per-image check a Consumer owes before loading or executing an
     *  image. */
    OCA_FAIL_PAYLOAD_ENTRY_HASH         = 25,
    /** image_count exceeds OCA_TOC_MAX_IMAGES — this build refuses to process a
     *  TOC that large. A policy limit, NOT a malformed manifest: the TOC may be
     *  perfectly well-formed and spec-legal. Kept distinct from
     *  OCA_FAIL_PAYLOAD_TOC so a field failure points at the right cause. */
    OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES    = 26,
    /** payload_offset does not resolve to a usable storage location: the
     *  arithmetic overflowed, the range falls outside the caller's permitted
     *  region, or it collides with the manifest and its appended entries. Kept
     *  distinct from OCA_FAIL_PAYLOAD_HASH so that "I was told to look in the
     *  wrong place" never presents as "these bytes are corrupt". */
    OCA_FAIL_PAYLOAD_LOCATION           = 27,
    /** manifest_length disagrees with the body size the magic implies. The
     *  manifest is mislabelled or truncated: distinct from OCA_FAIL_TRUNCATED
     *  (the buffer is short) and from OCA_FAIL_FORMAT_VERSION_MISMATCH (the
     *  format is newer), both of which would misdescribe it. */
    OCA_FAIL_MANIFEST_LENGTH            = 28,
    /** The manifest declares an encrypted payload, but secure-boot
     *  authentication was not CONFIRMED for it — either secure boot is not in
     *  force, or no signature check ran and passed. Distinct from
     *  OCA_FAIL_SECURE_BOOT_INVARIANT, which reports signing fields left
     *  non-zero on a non-secure manifest: different cause, different fix. */
    OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT = 29,
    /** The manifest selected a provisioned-secret slot this part holds no secret
     *  for. With this code, the callback ran, understood the request, and reports
     *  that this part was never provisioned for this manifest. A provisioning
     *  problem, and the manifest may be perfectly valid on a part that was. */
    OCA_FAIL_NO_PROVISIONED_SECRET      = 30,
    /** A check that consumes the secure-boot determination was handed a context
     *  no determination has settled. It REFUSED rather than guessing: with
     *  nothing recorded it cannot tell "secure boot is not in force, skip me"
     *  from "the sequence forgot to determine", and those have opposite safe
     *  answers. Distinct from OCA_FAIL_INVALID_ARG, which reports an unusable
     *  ARGUMENT; this reports a well-formed context in the wrong STATE, and the
     *  fix is a missing oca_determine_secure_boot() call rather than a corrected
     *  pointer. Never produced by oca_validate() or oca_validate_manifest(),
     *  which determine before composing anything that consumes it. */
    OCA_FAIL_SECURE_BOOT_UNDETERMINED   = 31,
    /** The live secure-boot determination stopped matching the one this
     *  validation recorded. Every consumer re-derives the determination
     *  immediately before acting and compares it against the record; this is
     *  that comparison failing.
     *
     *  It means the answer changed mid-validation. A reporter that is not stable
     *  across calls will produce it, and so will an induced fault — which is the
     *  case it exists for, since skipping signature verification by glitching one
     *  reporter read is otherwise indistinguishable from a part that is honestly
     *  not secure. Neither cause is a state in which to decide whether to verify
     *  a signature.
     *
     *  Escalate rather than retry: a retry that succeeds has not established that
     *  the first answer was wrong. */
    OCA_FAIL_SECURE_BOOT_STATE_CHANGED  = 32,
    /** A signature_class_revoke group-code byte holds neither 0x00 nor its
     *  group's constant.
     *
     *  This reports a MALFORMED FIELD, not a revocation verdict — it does not
     *  mean an algorithm class is revoked, and it is not the code a future
     *  boot-time revocation check would return. A group code is a single
     *  constant rather than a bitmask, and the device-side register accumulates
     *  by OR, so a manifest carrying a fragment of one would let a group-wide
     *  revocation be assembled across several updates that no single manifest
     *  ever declared. Rejecting fragments is what keeps that from happening. */
    OCA_FAIL_GROUP_CODE                 = 33,
    /** signature_size_classic or public_key_size_classic does not describe what
     *  the declared algorithm and encoding can produce.
     *
     *  Each size field bounds how far a Consumer reads into its companion field,
     *  so a value that is zero, overruns the field, or disagrees with the
     *  algorithm is rejected before any parse relies on it. Distinct from
     *  OCA_FAIL_SIGNATURE, which reports a signature that was parsed and did not
     *  verify; this one means the manifest never described a parseable value. */
    OCA_FAIL_CRYPTO_FIELD_SIZE          = 34,
    /** The manifest's ROOT key is not one this device authorizes.
     *
     *  A manifest carries the public key its signature is checked against, so
     *  verifying that signature proves only internal consistency: it says the
     *  holder of some private key signed this manifest, not that the Consumer
     *  trusts that key. Without a separate authorization step any key that signs
     *  its own manifest verifies, which is not secure boot.
     *
     *  Distinct from OCA_FAIL_ROOT_KEY_REVOKED in both direction and meaning.
     *  Revocation withdraws a key the device once trusted and is decided from a
     *  bitmap the format defines; authorization asks whether the device ever
     *  trusted the key at all, and is decided by the Consumer against whatever
     *  anchor it holds — keys embedded in ROM, key digests in OTP, or a
     *  device-specific store this library cannot know about. A key can be
     *  unauthorized without any bit ever being set. */
    OCA_FAIL_ROOT_KEY_UNAUTHORIZED      = 35,
    /** The manifest's signature-class selection cannot be honoured.
     *
     *  secure_boot_control carries two class bits — secure_boot_classic and
     *  secure_boot_pqc — naming which signature families this manifest is
     *  verified by. This code reports every way that selection can be
     *  unusable:
     *
     *    - secure boot is in force but neither class bit is set, so nothing
     *      names a signature to verify (a manifest that demands verification
     *      while describing none);
     *    - a variant with no PQC crypto region sets secure_boot_pqc, which the
     *      format forbids regardless of secure-boot state;
     *    - a check gated on the recorded enforcement finds a context in which
     *      no class is enforced — the fail-closed backstop for a hand-composed
     *      sequence that skipped the determination's rejection.
     *
     *  Distinct from OCA_FAIL_SECURE_BOOT_INVARIANT, which reports populated
     *  signing fields on a manifest that disclaims secure boot: that is stale
     *  data left behind, this is a live policy that cannot be satisfied. */
    OCA_FAIL_SIGNATURE_CLASS_CONTROL    = 36
} oca_result_t;

/**
 * @brief Human-readable name for a result code.
 *
 * Intended for logging and CLI output. The returned pointer has static lifetime
 * and is never NULL, so it is safe to print without a NULL guard and safe to
 * retain past this call. An unrecognised value yields a placeholder string
 * rather than NULL, so a corrupted code cannot crash a diagnostic path.
 *
 * @param[in] r  Result code to name.
 * @return A NUL-terminated static string. Never NULL.
 */
const char *oca_result_str(oca_result_t r);

/* ------------------------------------------------------------------ */
/* Validation context                                                 */
/*                                                                    */
/* What a validation ESTABLISHED, carried across the check sequence.  */
/* The library holds no state between calls, so a later stage asking  */
/* "was this manifest authenticated?" can only be answered if an      */
/* earlier stage wrote it down.                                       */
/* ------------------------------------------------------------------ */



/**
 * @brief What a validation ESTABLISHED, carried across the check sequence.
 *
 * Caller-allocated, one per validation. Zero-initialised means "nothing
 * established", which is the safe default: a consumer that never ran a check
 * sees exactly what one whose check failed would see.
 *
 * Holds no device-read or manifest-derived values by design. It records what
 * this validation DID, not what it SAW, so a faulted read cannot be carried
 * forward into the very check meant to catch it.
 *
 * Not shareable between concurrent validations.
 *
 * `secure_boot_enabled` is a REFERENCE, not a cached answer. Every check that
 * consumes it re-derives the determination immediately before acting and
 * requires the two to agree — see oca_secure_boot_confirm(). A record that has
 * gone stale, by fault or by an unstable reporter, fails the validation rather
 * than deciding it.
 *
 * @warning `secure_boot_enabled` and `secure_boot_authenticated` are
 *          INDEPENDENT. Reading one to infer the other defeats the point — see
 *          oca_check_payload_encryption_policy().
 * @warning Every field below means nothing until `secure_boot_determined` reads
 *          OCA_SECURE_TRUE.
 */
typedef struct oca_validation_context {
    /** A secure-boot determination has run and settled this context.
     *
     *  Set by oca_determine_secure_boot(), and by nothing else. Set LAST within
     *  it, after the values it vouches for, so it is never observable over a
     *  half-written record.
     *
     *  This exists so a check can tell "secure boot is not in force, so I am
     *  correctly a no-op" from "nobody has asked yet, and I am about to wave a
     *  manifest through on the strength of a field nothing wrote". Those are
     *  identical without it, and the second is a silent bypass: a hand-composed
     *  sequence that omitted the determination would pass the signature,
     *  revocation, and anti-rollback checks by doing none of them. */
    oca_secure_bool_t secure_boot_determined;
    /** Secure boot is in force for this boot. Says nothing about whether a
     *  signature was actually checked. */
    oca_secure_bool_t secure_boot_enabled;
    /** This body is the OCA-Classic variant.
     *
     *  One of a complementary PAIR with `manifest_is_pqc`, decided once by
     *  oca_determine_secure_boot() from the resolved variant descriptor and
     *  held to two invariants in any settled context: exactly one of the pair
     *  is TRUE, and the two are always opposite patterns. The secure-bool
     *  values are bitwise complements, so an intact pair XORs to all-ones and
     *  no single corrupted word can produce a coherent one. The confirm every
     *  gated check runs re-derives the variant class and refuses a record
     *  that disagrees with the body or violates the pair — so a consumer that
     *  only needs the class reads these rather than re-resolving the
     *  variant. */
    oca_secure_bool_t manifest_is_classic;
    /** This body is the OCA-PQC variant — the other half of the pair,
     *  recorded on the same terms as `manifest_is_classic`. Every PQC code
     *  path engages only when this is exactly TRUE. */
    oca_secure_bool_t manifest_is_pqc;
    /** This manifest is verified by its classical signature.
     *
     *  The manifest's secure_boot_classic bit, recorded by
     *  oca_determine_secure_boot() in the same consultation that decided
     *  `secure_boot_enabled`, so the enforcement a later check acts on is the
     *  one the determination actually observed. Meaningful only while secure
     *  boot is in force.
     *
     *  The per-class checks re-read the manifest bit and refuse a record that
     *  disagrees with it, for the same reason the determination itself is
     *  confirmed at time of use: a single corrupted word must not be able to
     *  downgrade a hybrid manifest to single-class verification. */
    oca_secure_bool_t secure_boot_enforce_classic;
    /** This manifest is verified by its PQC signature.
     *
     *  The manifest's secure_boot_pqc bit, recorded exactly as
     *  `secure_boot_enforce_classic` is. When both are TRUE the manifest is
     *  hybrid-signed and BOTH signatures must verify — the policy is a logical
     *  AND, never or-else. */
    oca_secure_bool_t secure_boot_enforce_pqc;
    /** The classical ROOT key was checked against the device's trust anchor
     *  and accepted.
     *
     *  Set by oca_check_root_key_authorized(), and only after
     *  cb->is_key_authorized returned OCA_OK for the classical key — never
     *  optimistically ahead of the call. Read by oca_check_signature(), which
     *  refuses to exercise a key this does not vouch for.
     *
     *  Recorded rather than merely returned because the ordering is the security
     *  property. Authorization before verification only means something if
     *  verification cannot happen without it, and a hand-composed sequence that
     *  omitted the authorization check would otherwise verify against a key
     *  nothing had ever vouched for. This makes that sequence fail instead.
     *
     *  Distinct from `secure_boot_authenticated`: this says the key was one the
     *  device trusts, that says a signature by it verified. Both are required,
     *  and neither implies the other. */
    oca_secure_bool_t secure_boot_key_authorized_classic;
    /** The PQC ROOT key was checked against the device's PQC trust anchor and
     *  accepted.
     *
     *  The PQC counterpart of `secure_boot_key_authorized_classic`, recorded on
     *  the same terms. Kept separate because a hybrid manifest verifies each
     *  class against its own anchor: one flag cannot say which family vouched,
     *  and the signature check must refuse a PQC verify the PQC anchor never
     *  approved even while the classical anchor has. */
    oca_secure_bool_t secure_boot_key_authorized_pqc;
    /** A signature check actually ran and passed. Set only after the verify
     *  callback returned OCA_OK, never optimistically ahead of the call. */
    oca_secure_bool_t secure_boot_authenticated;
    /** The device asserted itself definitively non-secure-boot. Records WHY the
     *  determination came back as it did, which `secure_boot_enabled` alone
     *  cannot say: "not in force because the device is provisioned that way"
     *  and "not in force because nothing established otherwise" have different
     *  remedies but boot identically.
     *
     *  Independent of `secure_boot_enabled`, in both directions. TRUE alongside
     *  `secure_boot_enabled` TRUE is legitimate and worth reading: a part
     *  provisioned as non-secure is being asked to run a manifest built for
     *  secure parts, and the manifest wins. */
    oca_secure_bool_t secure_boot_device_disabled;
} oca_validation_context_t;

/**
 * @brief Reset a validation context to "nothing established".
 *
 * Call before each validation. Reusing a context without this carries the
 * previous run's verdict forward, which is how a failed validation can be made
 * to look authenticated.
 *
 * @param[out] ctx  Context to reset. All fields become OCA_SECURE_FALSE,
 *                  including `secure_boot_determined` — a reset context is one
 *                  no determination has settled, which is why every check that
 *                  consumes the determination refuses one. NULL is tolerated
 *                  and does nothing.
 */
void oca_validation_context_init(oca_validation_context_t *ctx);

/* ------------------------------------------------------------------ */
/* Identifying a manifest before committing to a full read            */
/*                                                                    */
/* A consumer must know the variant before it knows how many bytes to */
/* copy. This answers that from a 20-byte head.                       */
/*                                                                    */
/* No cryptography, authenticates nothing — which is what makes it    */
/* the one operation safe to run against a mapped flash window.       */
/* Everything it reports is re-derived from the copied bytes by the   */
/* validation path.                                                   */
/*                                                                    */
/* See INTEGRATION.md, "The staged flow".                             */
/* ------------------------------------------------------------------ */

/** @brief manifest_identifier width, excluding the NULL this API appends. */
#define OCA_MANIFEST_IDENTIFIER_LEN  8u

/**
 * @brief Head bytes oca_manifest_peek() requires.
 *
 * Covers magic(0..4), identifier(4..12), version(12..16), and
 * manifest_length(16..20). Pinned to the layout by _Static_assert in parser.c.
 */
#define OCA_MANIFEST_PEEK_MIN  20u

/**
 * @brief What a 20-byte manifest head reveals before anything is authenticated.
 *
 * Enough to size the copy a staged consumer is about to make, and to log what
 * it found. Nothing here is trustworthy — no cryptography has run — and every
 * field is re-derived from the copied bytes by the validation path.
 */
typedef struct oca_manifest_peek {
    /** Bytes to copy for the full body, derived from the MAGIC — not from the
     *  manifest's self-declared length, which is untrusted here. Size your read
     *  from this field. */
    size_t      body_size;
    /** manifest_length as read. Informational: log it, never size from it.
     *  oca_check_manifest_length() confirms it once the body is authenticated. */
    uint32_t    declared_length;
    uint16_t    version_major;   /**< Manifest format major version, as read. */
    uint16_t    version_minor;   /**< Manifest format minor version, as read. */
    /** "OCA-Classic" / "OCA-PQC". Static lifetime, never NULL. For logging; a
     *  consumer that must refuse a variant uses the OCA_SUPPORT_* gates, after
     *  which this reports OCA_FAIL_UNSUPPORTED_VARIANT instead. */
    const char *variant_name;
    /** NUL-terminated, trailing NULs and spaces trimmed, non-printable bytes
     *  replaced with '?' — unauthenticated data headed for a log. */
    char        identifier[OCA_MANIFEST_IDENTIFIER_LEN + 1u];
} oca_manifest_peek_t;

/**
 * @brief Identify a manifest and learn its body size from a 20-byte head.
 *
 * A staged consumer must know the variant before it knows how many bytes to
 * copy inward. This answers that without cryptography and without trusting the
 * manifest's self-declared length.
 *
 * Because it authenticates nothing, this is the one operation safe to run
 * against a mapped flash window an attacker can still reach. Everything it
 * reports is re-derived from the copied bytes by the validation path, so a
 * tampered head can misdirect the copy but cannot survive validation.
 *
 * Reads at most OCA_MANIFEST_PEEK_MIN bytes and never past `head_len`.
 *
 * @param[in]  head      First bytes of the manifest as stored.
 * @param[in]  head_len  Bytes readable at @p head. May exceed the minimum.
 * @param[out] out       Filled on success; untouched on failure.
 * @retval OCA_OK                        Head parsed; @p out is populated.
 * @retval OCA_FAIL_INVALID_ARG          @p head or @p out was NULL.
 * @retval OCA_FAIL_TRUNCATED            @p head_len is below OCA_MANIFEST_PEEK_MIN.
 * @retval OCA_FAIL_MAGIC                Magic matches no known variant.
 * @retval OCA_FAIL_UNSUPPORTED_VARIANT  Magic names a variant compiled out of this build.
 * @return Otherwise the failure reported by resolving the magic.
 */
oca_result_t oca_peek_manifest(const uint8_t *head, size_t head_len,
                               oca_manifest_peek_t *out);

/* ------------------------------------------------------------------ */
/* Addressing enums                                                   */
/* ------------------------------------------------------------------ */

/**
 * @brief Which hardware identity field a check addresses.
 *
 * Selects the identity the library asks the integrator for and compares against
 * the manifest's constraint. The three form a containment hierarchy — a chiplet
 * sits in a package, a package in a system — and a manifest may constrain any
 * combination of them independently.
 */
typedef enum oca_id_kind {
    OCA_ID_CHIPLET = 0,  /**< Per-die identity. */
    OCA_ID_PACKAGE = 1,  /**< Identity of the package the die is assembled into. */
    OCA_ID_SYSTEM  = 2   /**< Identity of the board or system. */
} oca_id_kind_t;

/**
 * @brief Which level's lifecycle state a check addresses.
 *
 * Mirrors oca_id_kind_t's hierarchy. Kept as a distinct type rather than reused
 * because the two are read through different callbacks and a mix-up would
 * compare a lifecycle state against an identity constraint.
 */
typedef enum oca_lifecycle_level {
    OCA_LIFECYCLE_LEVEL_CHIPLET = 0,  /**< Per-die lifecycle state. */
    OCA_LIFECYCLE_LEVEL_PACKAGE = 1,  /**< Package-level lifecycle state. */
    OCA_LIFECYCLE_LEVEL_SYSTEM  = 2   /**< System-level lifecycle state. */
} oca_lifecycle_level_t;

/**
 * @brief Which level's version a range check addresses.
 *
 * Mirrors oca_id_kind_t's hierarchy, for the same reason oca_lifecycle_level_t
 * does: a separate type keeps the three level enums from being interchanged.
 */
typedef enum oca_version_level {
    OCA_VERSION_LEVEL_CHIPLET = 0,  /**< Per-die version. */
    OCA_VERSION_LEVEL_PACKAGE = 1,  /**< Package-level version. */
    OCA_VERSION_LEVEL_SYSTEM  = 2   /**< System-level version. */
} oca_version_level_t;

/**
 * @brief Lifecycle state a device reports for a given level.
 *
 * The values are the manifest's own lifecycle encoding, so a reported state is
 * compared directly against the manifest's permitted set with no translation.
 */
typedef enum oca_lifecycle_token {
    OCA_LIFECYCLE_TEST_DEV    = 0,     /**< Test or development part. */
    OCA_LIFECYCLE_PROD        = 1,     /**< Production. */
    OCA_LIFECYCLE_PROD_END    = 2,     /**< End of production life. */
    OCA_LIFECYCLE_RMA_SIP     = 3,     /**< Returned for analysis, system-in-package. */
    OCA_LIFECYCLE_RMA_CHIPLET = 4,     /**< Returned for analysis, chiplet. */
    OCA_LIFECYCLE_PROD_DBG_1  = 5,     /**< Production with debug level 1 enabled. */
    OCA_LIFECYCLE_PROD_DBG_2  = 6,     /**< Production with debug level 2 enabled. */
    /** The device could not report a state. Never satisfies a manifest
     *  constraint — an unreadable lifecycle fails the check rather than being
     *  treated as permissive. */
    OCA_LIFECYCLE_UNKNOWN     = 0xFF
} oca_lifecycle_token_t;

/**
 * @brief Outcome of a hardware-readback callback.
 *
 * Separate from oca_result_t because these report whether the integrator could
 * supply a value, not whether a manifest check passed.
 *
 * @note The library treats OCA_HW_UNAVAILABLE as a hard failure, never as
 *       "constraint not applicable". A device that cannot report its identity
 *       must not boot a manifest that constrains it.
 */
typedef enum oca_hw_result {
    OCA_HW_OK          = 0,  /**< Value supplied. */
    OCA_HW_UNAVAILABLE = 1,  /**< Caller cannot supply this value (e.g. CLI flag absent). */
    OCA_HW_ERROR       = 2   /**< Read was attempted and failed. */
} oca_hw_result_t;

/**
 * @brief Signature algorithm family a key, signature, or device state belongs to.
 *
 * The device maintains classic and PQC state separately, so a key revoked or
 * authorized in one family says nothing about a key in the other. Carried on
 * every oca_crypto_blob_t so a callback knows which anchor family or crypto
 * backend to consult without interpreting primitive bytes — the classical and
 * PQC signature_type value spaces both reserve 0xF0+ for integrators, so the
 * primitive value alone cannot distinguish the families there.
 *
 * @note PQC revocation state is not consulted yet; the family is live for
 *       authorization and signature dispatch.
 */
typedef enum oca_key_algorithm {
    OCA_KEY_ALGO_CLASSIC = 0,  /**< The RSA / ECDSA family. */
    OCA_KEY_ALGO_PQC     = 1   /**< The post-quantum family (ML-DSA / SLH-DSA). */
} oca_key_algorithm_t;

/* ------------------------------------------------------------------ */
/* Crypto blob descriptor                                             */
/* ------------------------------------------------------------------ */

/**
 * @brief Which kind of cryptographic blob a descriptor refers to.
 *
 * Lets one descriptor type carry both operands of a signature check while
 * keeping them distinguishable to the verifying callback.
 */
typedef enum oca_blob_kind {
    OCA_BLOB_PUBLIC_KEY = 1,  /**< The public key the signature is checked against. */
    OCA_BLOB_SIGNATURE  = 2   /**< The signature over the signed region. */
} oca_blob_kind_t;

/**
 * @brief Encoding of a signature or public-key blob.
 *
 * As recorded in the manifest's signature_encoding_classic /
 * public_key_encoding_classic byte.
 *
 * THE ENUMERATOR VALUES ARE THE ON-DISK BYTE VALUES. A manifest byte is cast
 * straight to this type with no translation, the same convention
 * oca_primitive_type_t follows for signature_type_classic.
 *
 * Two consequences worth keeping in mind before editing this enum:
 *
 *   - 0x00 means the field was never populated — a secure_boot = 0 bundle
 *     zeroes the signing fields. It does NOT mean "raw". An earlier revision
 *     used RAW = 0, which silently aliased "unset" onto a real encoding and
 *     left the format's raw-little-endian value (0x02) unrepresentable.
 *   - Casting a byte outside this set is well-defined in C (the value is
 *     representable in the implementation-chosen underlying type), but is
 *     undefined behaviour if this header is compiled as C++ — which the
 *     extern "C" guard above invites. Every value the packer can emit must
 *     therefore have an enumerator here.
 *
 * @note A drift test fails if these values diverge from the packer's
 *       OcaClassicSignatureEncoding / OcaClassicPublicKeyEncoding. That test
 *       parses this enum line by line and expects nothing after the value, so
 *       each enumerator below documents itself on the PRECEDING line rather
 *       than with a trailing comment.
 */
typedef enum oca_encoding {
    /** Field never populated. Not an encoding — see the warning above. */
    OCA_ENCODING_UNSET  = 0x00,
    /** ASN.1 DER. */
    OCA_ENCODING_DER    = 0x01,
    /** Raw bytes, in the algorithm's own byte order (big-endian). */
    OCA_ENCODING_RAW    = 0x02
} oca_encoding_t;

/**
 * @brief Signature primitive named by the manifest's signature_type_classic
 *        or signature_type_pqc byte.
 *
 * As with oca_encoding_t, the enumerator values are the on-disk byte values and
 * a manifest byte is cast straight to this type. The numbering is the format's,
 * which is why it is not contiguous. The classical values (0x01, 0x05) and the
 * PQC values (0x31+) come from two different manifest fields with two different
 * value spaces; the blob's key_algorithm says which space a value is from,
 * which matters because both spaces reserve 0xF0+ for integrators.
 */
typedef enum oca_primitive_type {
    /** No primitive — the signing fields are unpopulated. */
    OCA_PRIMITIVE_NONE                     = 0x00,
    OCA_PRIMITIVE_RSA_3072_PKCS1V15_SHA256 = 0x01,  /**< RSA-3072, PKCS#1 v1.5, SHA-256. */
    OCA_PRIMITIVE_ECDSA_P256_SHA256        = 0x05,  /**< ECDSA P-256, SHA-256. */
    OCA_PRIMITIVE_ML_DSA_44                = 0x31,  /**< FIPS 204 ML-DSA-44. */
    OCA_PRIMITIVE_ML_DSA_65                = 0x32,  /**< FIPS 204 ML-DSA-65. */
    OCA_PRIMITIVE_ML_DSA_87                = 0x33,  /**< FIPS 204 ML-DSA-87. */
    OCA_PRIMITIVE_SLH_DSA_SHA2_128S        = 0x51,  /**< FIPS 205 SLH-DSA-SHA2-128s. */
    OCA_PRIMITIVE_SLH_DSA_SHA2_192S        = 0x52,  /**< FIPS 205 SLH-DSA-SHA2-192s. */
    OCA_PRIMITIVE_SLH_DSA_SHA2_256S        = 0x53,  /**< FIPS 205 SLH-DSA-SHA2-256s. */
    OCA_PRIMITIVE_SLH_DSA_SHAKE_128S       = 0x54,  /**< FIPS 205 SLH-DSA-SHAKE-128s. */
    OCA_PRIMITIVE_SLH_DSA_SHAKE_192S       = 0x55,  /**< FIPS 205 SLH-DSA-SHAKE-192s. */
    OCA_PRIMITIVE_SLH_DSA_SHAKE_256S       = 0x56   /**< FIPS 205 SLH-DSA-SHAKE-256s. */
} oca_primitive_type_t;

/**
 * @brief A signature or public-key blob, with everything needed to interpret it.
 *
 * Passed to the verify callback so the integrator's crypto backend can select
 * the right primitive and parse the bytes without re-reading the manifest.
 */
typedef struct oca_crypto_blob {
    /** The blob bytes. Point into the manifest body; valid only as long as it is. */
    const uint8_t       *bytes;
    /** Size of the manifest FIELD holding the blob, which for a DER-encoded
     *  value is generally larger than the encoded content. */
    size_t               field_length;
    oca_blob_kind_t      kind;            /**< Whether this is the key or the signature. */
    oca_encoding_t       encoding;        /**< How @c bytes is encoded. */
    oca_primitive_type_t primitive_type;  /**< Which signature primitive applies. */
    /** Which algorithm family the blob belongs to — the classical fields or the
     *  PQC fields. Says which anchor family an authorization consults and which
     *  backend a verify dispatches to; @c primitive_type alone cannot, because
     *  both families reserve 0xF0+ for integrator-defined primitives. */
    oca_key_algorithm_t  key_algorithm;
} oca_crypto_blob_t;

/* ------------------------------------------------------------------ */
/* Payload decryption descriptor                                      */
/* ------------------------------------------------------------------ */

/**
 * @brief Cipher named by the manifest's encryption_type byte.
 *
 * As with the other on-disk enums here, the values ARE the byte values.
 */
typedef enum oca_encryption_type {
    OCA_ENCRYPTION_TYPE_NONE        = 0x00,  /**< No encryption. */
    OCA_ENCRYPTION_TYPE_AES_128_CBC = 0x01,  /**< AES-128-CBC. */
    OCA_ENCRYPTION_TYPE_AES_256_CBC = 0x02   /**< AES-256-CBC. */
} oca_encryption_type_t;

/**
 * @brief Everything the payload-decryption callback reads, in one place.
 *
 * Follows the same principle as oca_crypto_blob_t: a callback should not have to
 * reach back into the manifest to interpret its own arguments. Every value the
 * operation needs is a named field here, so nothing is derived by offsetting
 * from another field, and nothing requires indexing into the manifest body.
 *
 * Named fields rather than a flat argument list for one further reason: @c iv
 * and @c kdf_input are both @c const @c uint8_t* and would be silently
 * transposable as positional arguments, which no compiler would catch and which
 * would produce a wrong key rather than an error.
 *
 * All of it is read-only to the callback. Every field is either held by the
 * library already or read out of the manifest's signed region, and the callback
 * is reached only after that region has been authenticated.
 */
typedef struct oca_decrypt_input {
    /** Stored ciphertext, already verified against the manifest's payload_hash
     *  before this callback is reached. */
    const uint8_t         *ciphertext;
    /** Length of @c ciphertext. Guaranteed non-zero and a whole number of
     *  16-byte blocks: the library enforces that shared block-mode invariant so
     *  each backend does not have to re-check it. */
    size_t                 ciphertext_len;
    /** 16-byte AES-CBC initialisation vector. Points into the MANIFEST BODY,
     *  never the payload, which is what makes decrypting in place over the
     *  ciphertext safe. */
    const uint8_t         *iv;
    /** 64-byte KDF context. Also in the manifest body, same reasoning. */
    const uint8_t         *kdf_input;
    /** Which cipher the manifest names. A value outside oca_encryption_type_t
     *  cannot reach here: the library rejects an unsupported cipher before
     *  invoking the callback. */
    oca_encryption_type_t  cipher;
    /** Which provisioned secret the manifest selects, 1-based.
     *
     *  An INDEX, never a secret. Resolving it against the part's key store is
     *  the callback's job, which is precisely why no key material crosses this
     *  boundary in either direction. A slot this part holds no secret for is
     *  reported with OCA_FAIL_NO_PROVISIONED_SECRET. */
    uint16_t               secret_select;
} oca_decrypt_input_t;

/**
 * @brief Where the validated plaintext payload is, and how long it is.
 *
 * The payload entry points report this so a Consumer can reach the images
 * without the decryption callback having to smuggle the pointer out for itself.
 *
 * Written ONLY when validation succeeded — after the TOC structural pass, the
 * payload hash chain, and every per-entry image hash have all passed. On any
 * failure the struct is left untouched, so a caller cannot act on a location the
 * library had not finished checking.
 *
 * The bytes are not the library's: for an encrypted payload this is whatever
 * address the decryption callback returned (possibly the ciphertext's own, when
 * decrypting in place), and for a cleartext payload it is inside the caller's
 * own buffer. Only the knowledge of where they are is being handed back.
 */
typedef struct oca_payload_plaintext {
    /** First byte of the plaintext payload region — the PTOC header. */
    const uint8_t *bytes;
    /** Bytes readable at @c bytes. For an encrypted payload this is the
     *  recovered length the callback reported, normally SHORTER than the stored
     *  ciphertext because PKCS#7 padding was removed. */
    size_t         len;
} oca_payload_plaintext_t;

/* ------------------------------------------------------------------ */
/* Callback table                                                     */
/* ------------------------------------------------------------------ */

/**
 * @brief The callback table, forward-declared.
 *
 * Every check takes a @c const pointer to one of these, and several of the
 * table's own members take types declared below it, so the name has to exist
 * before the definition. See @c struct @c oca_callbacks for the contract.
 */
typedef struct oca_callbacks oca_callbacks_t;

/**
 * @brief The operations the library delegates to the integrator.
 *
 * Everything the library cannot do itself: cryptography, hardware readback, and
 * device-state access. Populate with memset() first, then assign what you
 * implement. A NULL member is a valid state, not a stub to fill in — a check
 * that needs one fails with OCA_FAIL_CALLBACK_UNAVAILABLE rather than passing.
 *
 * Each member takes only what its operation reads, and the table holds function
 * pointers only. State your implementation needs of its own — an engine handle,
 * a key-store session — lives in your image, not here: a slot on this table is
 * reachable by every callback, so one callback's state becomes another's.
 * Where a callback needs more input than a few arguments, it receives a type
 * the library declares and fills (oca_crypto_blob_t, oca_decrypt_input_t).
 */
struct oca_callbacks {
    /**
     * @brief Compute SHA-256 over a message.
     *
     * Called for the manifest hash, the payload hash, the payload hash chain,
     * and every TOC entry hash, so it is by far the hottest callback in the
     * library. It must be re-entrant with respect to the library, which keeps
     * no state between calls.
     *
     * @param[in]  msg         Bytes to digest.
     * @param[in]  msg_len     Length of @p msg. May be zero.
     * @param[out] out_digest  Receives the 32-byte digest.
     * @retval OCA_OK                        Digest written.
     * @retval OCA_FAIL_CALLBACK_UNAVAILABLE No real implementation is wired.
     */
    oca_result_t (*sha256)(
        const uint8_t *msg, size_t msg_len,
        uint8_t out_digest[32]);

    /**
     * @brief Verify a signature over the manifest's signed region.
     *
     * The library has already decided which key slot applies and confirmed it
     * is not revoked; this callback performs only the cryptographic operation.
     * Both blobs carry their own encoding, primitive type, and algorithm
     * family, so the backend need not re-read the manifest to interpret them.
     *
     * Invoked once per signature class the manifest enforces: a hybrid
     * manifest produces one call for the classical signature and one for the
     * PQC signature, and BOTH must verify — the library composes the AND, the
     * backend only ever judges the pair of blobs in front of it. The blobs'
     * key_algorithm says which family a call is about; a backend with no PQC
     * implementation returns OCA_FAIL_CALLBACK_UNAVAILABLE for
     * OCA_KEY_ALGO_PQC and the manifest fails closed.
     *
     * @param[in] signature          Signature blob and its encoding.
     * @param[in] public_key         Public-key blob and its encoding.
     * @param[in] signed_region      Bytes the signature covers.
     * @param[in] signed_region_len  Length of @p signed_region.
     * @retval OCA_OK                        Signature verified.
     * @retval OCA_FAIL_SIGNATURE            Verification mismatch.
     * @retval OCA_FAIL_CALLBACK_UNAVAILABLE No real implementation is wired
     *                                       for this algorithm family.
     */
    oca_result_t (*verify_signature)(
        const oca_crypto_blob_t *signature,
        const oca_crypto_blob_t *public_key,
        const uint8_t *signed_region, size_t signed_region_len);

    /**
     * @brief Derive the payload key and decrypt the payload.
     *
     * Resolve @c in->secret_select against the part's provisioned secrets,
     * derive the AES payload key from that secret and @c in->kdf_input via
     * SP 800-108r1 Counter Mode over the expanded input block, then
     * AES-CBC-decrypt @c in->ciphertext with @c in->iv, removing PKCS#7 padding.
     * The cipher and key length follow @c in->cipher.
     *
     * Everything the operation reads is a named field on @p in, so the callback
     * never re-reads the manifest and never needs state handed to it from
     * elsewhere. The selector is an INDEX: the library holds no secret and no
     * key material crosses this boundary in either direction.
     *
     * The library invokes this ONLY after the ciphertext payload_hash has
     * verified — never on unauthenticated bytes.
     *
     * IN-PLACE DECRYPTION IS SUPPORTED AND EXPECTED ON MEMORY-CONSTRAINED
     * TARGETS. The callback may decrypt over @c in->ciphertext and return that
     * same address as @p out_plaintext, avoiding a second full-size buffer and
     * halving peak memory. @c in->ciphertext is const-qualified only because the
     * library does not write through it; casting it back to a writable pointer
     * is legal when the underlying object is the caller's own mutable bundle
     * buffer — it is, since the caller supplied it to oca_validate(). This is
     * safe because:
     *   - payload_hash has already been verified over the ciphertext, and the
     *     library never reads the ciphertext again after this callback returns;
     *   - @c in->iv and @c in->kdf_input point into the MANIFEST BODY, not the
     *     payload, so overwriting the payload cannot clobber the derivation
     *     inputs;
     *   - oca_check_payload() is the final stage of oca_validate().
     *
     * The one cost of decrypting in place: the bundle buffer no longer holds
     * the ciphertext, so it cannot be validated a second time — payload_hash
     * covers bytes that are gone. A single-shot boot flow does not care; a
     * retry must re-read the payload from flash.
     *
     * @param[in]  in                Everything the operation reads. Read-only;
     *                               see oca_decrypt_input_t for each field and
     *                               where it comes from.
     * @param[out] out_plaintext     Receives a pointer to the recovered
     *                               plaintext, caller-owned and valid until
     *                               teardown. May alias @c in->ciphertext.
     * @param[out] out_plaintext_len Receives the recovered length. Normally
     *                               SHORTER than @c in->ciphertext_len because
     *                               PKCS#7 padding is removed — report the
     *                               recovered length, not the region size.
     * @retval OCA_OK                          Plaintext recovered.
     * @retval OCA_FAIL_NO_PROVISIONED_SECRET  No secret is provisioned for
     *                                         @c in->secret_select.
     * @retval OCA_FAIL_DECRYPT                Derivation, cipher, or padding failure.
     * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   Reserved for an unwired callback;
     *                                         a wired one reports a missing
     *                                         secret with the code above.
     */
    oca_result_t (*decrypt_payload)(
        const oca_decrypt_input_t *in,
        const uint8_t **out_plaintext, size_t *out_plaintext_len);

    /**
     * @brief Report the hardware identity value for a field.
     *
     * Invoked only when the manifest actually constrains @p field, so a
     * permissive manifest never spends a hardware read.
     *
     * @param[in]  field     Which identity to report.
     * @param[out] out       Receives the 32-byte identity value.
     * @retval OCA_HW_OK           Value written to @p out.
     * @retval OCA_HW_UNAVAILABLE  Caller cannot supply this value.
     * @retval OCA_HW_ERROR        Read attempted and failed.
     *
     * @warning The library treats OCA_HW_UNAVAILABLE as a hard failure, not as
     *          "constraint not applicable". A device that cannot report an
     *          identity the manifest constrains must not boot it.
     */
    oca_hw_result_t (*get_identity_bytes)(
        oca_id_kind_t field,
        uint8_t out[32]);

    /**
     * @brief Report the hardware's current lifecycle state for a level.
     *
     * Invoked only when the manifest constrains lifecycle at @p level. As with
     * get_identity_bytes, an unavailable answer fails the check rather than
     * waiving it.
     *
     * @param[in]  level      Which level's lifecycle state to report.
     * @param[out] out_state  Receives the state. Set OCA_LIFECYCLE_UNKNOWN
     *                        rather than leaving it untouched if the value
     *                        cannot be determined.
     * @retval OCA_HW_OK           State written to @p out_state.
     * @retval OCA_HW_UNAVAILABLE  Caller cannot supply this value.
     * @retval OCA_HW_ERROR        Read attempted and failed.
     */
    oca_hw_result_t (*get_lifecycle_state)(
        oca_lifecycle_level_t level,
        oca_lifecycle_token_t *out_state);

    /**
     * @brief Report the hardware's current version for a level.
     *
     * Invoked only when the manifest constrains a version range at @p level.
     * Both output parameters are written together; the library compares the
     * pair as a single ordered version.
     *
     * @param[in]  level      Which level's version to report.
     * @param[out] out_major  Receives the major version.
     * @param[out] out_minor  Receives the minor version.
     * @retval OCA_HW_OK           Version written.
     * @retval OCA_HW_UNAVAILABLE  Caller cannot supply this value.
     * @retval OCA_HW_ERROR        Read attempted and failed.
     */
    oca_hw_result_t (*get_version)(
        oca_version_level_t level,
        uint16_t *out_major,
        uint16_t *out_minor);

    /**
     * @brief Report whether secure boot is enforced for this boot.
     *
     * Secure boot is a global device state that may be enforced by lifecycle,
     * fuses, or other features — the manifest's secure_boot_control bit is only
     * one input, not authoritative — so this callback lets the integrator
     * report it. When it returns OCA_SECURE_TRUE, the signature,
     * ROOT-key-revocation, and anti-rollback checks all engage.
     *
     * OPTIONAL: if NULL, this input simply does not participate.
     *
     * Ranks below the manifest's bit and below is_secure_boot_disabled — see
     * oca_secure_boot_active() for the full precedence.
     *
     * Answers in oca_secure_bool_t rather than `bool` because this is a
     * fuse or life-cycle read on a part an attacker may be glitching, and in a
     * `bool` the answer that disables verification is every byte value except
     * one. Implementing it needs only lib/oca_secure_bool.h, not this header.
     *
     * @return OCA_SECURE_TRUE when secure boot is enforced for this boot,
     *         OCA_SECURE_FALSE when it is not.
     *
     * @warning Return one of the two named constants and nothing else. Anything
     *          the library cannot recognise is read as ENFORCED, on the same
     *          fail-safe reasoning as an absent callback — so a corrupted or
     *          uninitialised answer costs a boot rather than a verification.
     *          `return 1;` is such a value, and it means the opposite of what it
     *          looks like.
     */
    oca_secure_bool_t (*is_secure_boot_active)(void);

    /**
     * @brief Report whether secure boot is DEFINITIVELY DISABLED on this device.
     *
     * Settled in hardware by life-cycle state, a discrete disable fuse, or an
     * equivalent fact about the part itself.
     *
     * Only an affirmative answer carries meaning. Returning OCA_SECURE_FALSE
     * establishes nothing; the remaining inputs decide exactly as they would
     * without this callback. A part that cannot determine the answer returns
     * OCA_SECURE_FALSE.
     *
     * This is the ONLY input that can turn secure boot off. It outranks the one
     * other device-side input, is_secure_boot_active, and the library's
     * default-to-active fail-safe. It does NOT outrank the manifest's own
     * secure_boot_control bit: a manifest built for secure boot can only ever
     * boot via secure boot, and no device-side answer downgrades it.
     *
     * OPTIONAL: NULL means "no opinion", identical to the behaviour before this
     * callback existed.
     *
     * Answers in oca_secure_bool_t rather than `bool`, and here the reasoning is
     * sharper than for its sibling: this is the one input in the whole
     * determination that can turn secure boot OFF, so it is the single most
     * valuable byte on the part to glitch. In a `bool` every value except zero
     * asserts the disable. Implementing it needs only lib/oca_secure_bool.h.
     *
     * @return OCA_SECURE_TRUE only when the device affirmatively reports secure
     *         boot disabled; OCA_SECURE_FALSE otherwise, including when the
     *         answer is unknown.
     *
     * @warning Return one of the two named constants and nothing else. Only an
     *          exact OCA_SECURE_TRUE asserts the disable; every other value,
     *          corrupted or otherwise, is read as "not asserted" and leaves
     *          secure boot to the remaining inputs. That is the safe direction
     *          for this callback and the opposite of the one its sibling takes,
     *          because for both of them the unrecognised answer must be the one
     *          that keeps verification on.
     *
     * @warning Wiring this is a deployment decision that REMOVES a protection.
     *          It does not restrict what the part can boot: a manifest
     *          asserting secure boot still gets full signature verification
     *          and, with it, payload decryption — that pairing is unaffected.
     *          What it withdraws is the device's insistence that this part boot
     *          verified at all. A manifest with the control bit clear then
     *          boots unverified where is_secure_boot_active or the fail-safe
     *          would previously have refused, so anyone able to present such a
     *          manifest gets an unverified boot.
     */
    oca_secure_bool_t (*is_secure_boot_disabled)(void);

    /**
     * @brief Decide whether the manifest's ROOT key is one this device trusts.
     *
     * The trust anchor, and the only callback that can supply one. Everything
     * else about the signature is self-consistent by construction: the manifest
     * carries the public key its own signature is checked against, so
     * verification proves a private key signed this manifest and nothing about
     * whose. Answering this is what makes the difference between a valid
     * signature and an authentic manifest.
     *
     * Consulted BEFORE revocation and before any public-key operation, so an
     * unknown key is refused without being used and without paying for a
     * modexp. Revocation then narrows the authorized set further; the two are
     * different questions and are asked in that order.
     *
     * Invoked once per signature class the manifest enforces — the classical
     * key, the PQC key, or both for a hybrid manifest — each call carrying
     * that class's key and select bitmap, with the blob's key_algorithm naming
     * which anchor family to consult. A device with no PQC anchor returns
     * OCA_FAIL_ROOT_KEY_UNAUTHORIZED for OCA_KEY_ALGO_PQC and the manifest
     * fails closed.
     *
     * The library deliberately holds no opinion on how the answer is reached,
     * because the anchor is not something the format can describe: it may be a
     * key embedded in mask ROM, a digest burned into OTP, an on-die table, or a
     * chain this build does not walk. @p select is passed alongside the key so
     * an implementation with per-slot anchors can tell which one the manifest
     * is claiming, rather than having to search every anchor it holds.
     *
     * REQUIRED under secure boot. NULL fails closed with
     * OCA_FAIL_CALLBACK_UNAVAILABLE rather than passing, because a build that
     * forgot to wire its trust anchor must not verify anything.
     *
     * @param[in] public_key  The key from the manifest, as
     *                        oca_check_signature() will present it: @c bytes
     *                        points into the manifest body, @c field_length is
     *                        the field width, and @c encoding /
     *                        @c primitive_type say how to read it.
     * @param[in] select      The 16-byte little-endian public_key_select
     *                        bitmap, verbatim from the manifest.
     *
     * @retval OCA_OK                          The device authorizes this key.
     * @retval OCA_FAIL_ROOT_KEY_UNAUTHORIZED  It does not.
     * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   The anchor could not be read at
     *                                         all (an OTP fault, say) — distinct
     *                                         from an anchor that was read and
     *                                         did not match.
     *
     * @warning Compare in constant time. The anchor is not secret but the
     *          comparison is attacker-driven, and a byte-at-a-time exit leaks
     *          how much of a forged key matched. lib/oca_compare.h holds the
     *          folds the library uses for exactly this.
     *
     * @warning Do not fold revocation in here. Returning "unauthorized" for a
     *          revoked-but-known key loses the distinction the two result codes
     *          exist to draw, and the revocation check reads device state this
     *          one is not given.
     */
    oca_result_t (*is_key_authorized)(
        const oca_crypto_blob_t *public_key,
        const uint8_t            select[16]);

    /* Device-stored secure-boot state (consumed only when secure boot is
     * enabled). The get_* callbacks are read by the read-only revocation and
     * anti-rollback checks; the set_* callbacks are used ONLY by
     * oca_commit_security_state() after a successful validation. All are
     * OPTIONAL (NULL when unused); a check whose required get_* callback is
     * NULL under secure boot fails with OCA_FAIL_CALLBACK_UNAVAILABLE. Each
     * value is the little-endian field mirroring the manifest layout, so the
     * widths differ: 16 bytes for the ROOT-key revocation bitmap and the
     * 128-bit security-version flags, 8 for the two signature posture
     * registers. */

    /**
     * @brief Read the device-stored ROOT-key revocation bitmap.
     *
     * Consulted before the selected key is used to verify anything, so a
     * revoked key is never exercised.
     *
     * @param[in]  algo      Which algorithm family's state to read.
     * @param[out] out       Receives the 16-byte little-endian bitmap.
     * @retval OCA_OK  Bitmap written to @p out.
     * @return Any non-OK result fails the revocation check.
     */
    oca_result_t (*get_root_key_revocation)(
        oca_key_algorithm_t algo, uint8_t out[16]);

    /**
     * @brief Read the device-stored security-version flags.
     *
     * The anti-rollback comparison re-reads through this on every call and
     * caches nothing, so a faulted read cannot propagate into a later check.
     *
     * @param[out] out       Receives the 16-byte little-endian flag field.
     * @retval OCA_OK  Flags written to @p out.
     * @return Any non-OK result fails the anti-rollback check.
     */
    oca_result_t (*get_security_version)(
        uint8_t out[16]);

    /**
     * @brief Persist a new device-stored ROOT-key revocation bitmap.
     *
     * Called only by oca_commit_security_state(), after a validation has
     * already succeeded. The value has been bitwise-OR-ed by the library, so it
     * only ever sets bits and never clears one.
     *
     * @param[in] algo      Which algorithm family's state to write.
     * @param[in] in        The 16-byte little-endian bitmap to persist.
     * @retval OCA_OK  Write-back succeeded.
     * @return Any non-OK result surfaces as OCA_FAIL_SECURITY_STATE_UPDATE.
     */
    oca_result_t (*set_root_key_revocation)(
        oca_key_algorithm_t algo, const uint8_t in[16]);

    /**
     * @brief Persist a new device-stored security-version flag field.
     *
     * Same contract as set_root_key_revocation: commit-time only, already
     * OR-ed, sets bits and never clears them.
     *
     * @param[in] in        The 16-byte little-endian flag field to persist.
     * @retval OCA_OK  Write-back succeeded.
     * @return Any non-OK result surfaces as OCA_FAIL_SECURITY_STATE_UPDATE.
     */
    oca_result_t (*set_security_version)(
        const uint8_t in[16]);

    /* The two signature posture registers. Unlike the state above, neither
     * takes part in verifying the manifest that carries them: they are written
     * after a fully verified boot and govern how signatures are treated on
     * SUBSEQUENT boots. Neither is keyed by algorithm family — each carries its
     * classical and post-quantum halves inside one 8-byte word, and splitting
     * them across two calls would let a group code be written in fragments. */

    /**
     * @brief Read the device-stored signature cohort enforcement register.
     *
     * Read only at commit time, to be OR-ed with the manifest's value. Nothing
     * in the current boot's verification consults it: the accumulated posture
     * governs subsequent boots.
     *
     * @param[out] out       Receives the 8-byte little-endian register.
     * @retval OCA_OK  Register written to @p out.
     * @return Any non-OK result fails the commit.
     */
    oca_result_t (*get_signature_cohort_enforce)(
        uint8_t out[8]);

    /**
     * @brief Persist a new device-stored signature cohort enforcement register.
     *
     * Same contract as set_security_version: commit-time only, already OR-ed by
     * the library, sets bits and never clears them.
     *
     * @param[in] in        The 8-byte little-endian register to persist.
     * @retval OCA_OK  Write-back succeeded.
     * @return Any non-OK result surfaces as OCA_FAIL_SECURITY_STATE_UPDATE.
     */
    oca_result_t (*set_signature_cohort_enforce)(
        const uint8_t in[8]);

    /**
     * @brief Read the device-stored signature class revocation register.
     *
     * Read only at commit time, to be OR-ed with the manifest's value. Like the
     * cohort register above it does not gate the current boot; a Consumer that
     * enforces the accumulated revocations does so on subsequent boots.
     *
     * @param[out] out       Receives the 8-byte little-endian register.
     * @retval OCA_OK  Register written to @p out.
     * @return Any non-OK result fails the commit.
     */
    oca_result_t (*get_signature_class_revoke)(
        uint8_t out[8]);

    /**
     * @brief Persist a new device-stored signature class revocation register.
     *
     * Same contract as set_security_version. The library ORs the whole field,
     * reserved bytes included, so that a group code can never be assembled from
     * fragments contributed by separate manifests.
     *
     * @param[in] in        The 8-byte little-endian register to persist.
     * @retval OCA_OK  Write-back succeeded.
     * @return Any non-OK result surfaces as OCA_FAIL_SECURITY_STATE_UPDATE.
     */
    oca_result_t (*set_signature_class_revoke)(
        const uint8_t in[8]);

    /**
     * @brief Human-readable name for an identity field, for error messages.
     *
     * OPTIONAL. Used only when a caller renders diagnostics; the library has no
     * built-in string tables and forwards a NULL result straight up rather than
     * substituting one.
     *
     * @param[in] field     Which identity field to name.
     * @return A caller-owned NUL-terminated string, or NULL if none is
     *         available. The library never dereferences a NULL return.
     */
    const char *(*describe_field)(oca_id_kind_t field);
};

/* ------------------------------------------------------------------ */
/* Composable check functions                                         */
/*                                                                    */
/* Each function operates on a manifest body and an (optional)        */
/* callback table. The body size is variant-specific — 4096 bytes for */
/* Classic, 36864 for PQC — so these functions do NOT hard-code 4096. */
/*                                                                    */
/* LENGTH CONTRACT: the functions taking `body` alone cannot check the */
/* buffer size, so the caller must guarantee `body` addresses a whole  */
/* variant body before calling them. Establish that with              */
/* oca_check_length() (the shared minimum) plus, once the magic has    */
/* selected a variant, that variant's body_size — which is exactly the */
/* order oca_validate() uses. The two functions that DO take a length  */
/* (oca_check_payload, oca_payload_region) validate it themselves.     */
/*                                                                    */
/* Functions that don't read from the callback table accept the body   */
/* pointer alone. Functions that require a callback return             */
/* OCA_FAIL_CALLBACK_UNAVAILABLE rather than silently passing if the   */
/* relevant callback is NULL or returns the unavailable sentinel.      */
/*                                                                    */
/* Composing these in the canonical order below is what oca_validate()*/
/* does. Callers MAY invoke them directly to skip a check or to       */
/* reorder for a specialized flow (e.g., dev builds bypassing         */
/* signature_verify while crypto-engine bring-up is in progress).     */
/* ------------------------------------------------------------------ */

/**
 * @brief Reject a buffer too short to hold any manifest.
 *
 * The shared minimum across every variant, checked before the magic selects
 * one. Passing this does NOT mean the buffer holds a whole body — it means it
 * is long enough to read the magic and decide which variant's size applies.
 * See the length contract above.
 *
 * @param[in] actual_length  Bytes available in the caller's buffer.
 * @retval OCA_OK             Buffer meets the shared minimum.
 * @retval OCA_FAIL_TRUNCATED Buffer is shorter than any variant's body.
 */
oca_result_t oca_check_length         (size_t actual_length);

/**
 * @brief Confirm the manifest's magic names a variant this build supports.
 *
 * The first content check and the one that selects the variant every later
 * check reads through. The two failures are kept distinct because they call for
 * different responses: an unrecognised magic means these are not OCA bytes at
 * all, while an unsupported one means they are, and this build was compiled to
 * refuse them.
 *
 * @param[in] body  Manifest body, at least OCA_MAGIC_LEN bytes readable.
 * @retval OCA_OK                        Magic names a supported variant.
 * @retval OCA_FAIL_INVALID_ARG          @p body was NULL.
 * @retval OCA_FAIL_MAGIC                Magic matches no known variant.
 * @retval OCA_FAIL_UNSUPPORTED_VARIANT  Variant compiled out of this build.
 * @return Otherwise the failure reported by the variant resolver, which is
 *         where this check delegates.
 */
oca_result_t oca_check_magic          (const uint8_t *body);

/**
 * @brief Confirm the trailer closing the signed region is intact.
 *
 * A fixed byte pattern at a variant-specific offset. It bounds the signed
 * region, so a wrong trailer means the region a signature would cover is not
 * the region the producer signed — worth rejecting before spending a
 * public-key operation.
 *
 * @param[in] body  Whole variant body. See the length contract above.
 * @retval OCA_OK                        Trailer matches.
 * @retval OCA_FAIL_INVALID_ARG          @p body was NULL.
 * @retval OCA_FAIL_TRAILER              Trailer bytes are wrong.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_check_trailer        (const uint8_t *body);

/**
 * @brief Confirm the manifest format version is one this build can validate.
 *
 * Enforces the compatibility policy stated at the top of this header: a greater
 * MAJOR is refused outright, because a format that has changed incompatibly
 * cannot be checked by these rules. A greater MINOR is accepted on the
 * producer-side contract that minor bumps are additive only.
 *
 * @param[in] body  Whole variant body. See the length contract above.
 * @retval OCA_OK                               Version is acceptable.
 * @retval OCA_FAIL_FORMAT_VERSION_MISMATCH     Manifest major exceeds this build's.
 */
oca_result_t oca_check_format_version (const uint8_t *body);

/**
 * @brief Require the manifest's self-declared length to match its variant.
 *
 * manifest_length must equal the body size its magic implies (4096 Classic,
 * 36864 PQC).
 *
 * This closes the loop on a staged read. A consumer sizes its copy from
 * metadata taken out of storage BEFORE anything is authenticated; this is where
 * the copied, authenticated manifest is required to agree about its own size.
 * The field sits inside the signed region, so once the signature verifies this
 * check is an authenticated statement rather than a hint.
 *
 * @param[in] body  Whole variant body. See the length contract above.
 * @retval OCA_OK                        Declared length matches the variant.
 * @retval OCA_FAIL_INVALID_ARG          @p body was NULL.
 * @retval OCA_FAIL_MANIFEST_LENGTH      Declared length disagrees with the magic.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_check_manifest_length(const uint8_t *body);

/**
 * @brief Reserved-bit stage. Always passes, by design.
 *
 * Reserved bit-ranges inside operative fields — selector_bits[127:105],
 * lifecycle_<level>_states[31:7], demotion_control[15:4] — are the Producer's
 * responsibility to zero. The Consumer does NOT reject a manifest merely
 * because such a bit is set, for two reasons drawn from the format spec:
 * a Consumer must not process, depend on, infer, or act upon a reserved field,
 * and is not obliged to verify reserved regions hold zero; and reserved regions
 * are explicitly available for backward-compatible minor-version extension, so
 * rejecting a set reserved bit would break forward compatibility with a future
 * minor that defines it.
 *
 * The operative decoders already mask to the currently-defined bits, so
 * reserved bits are ignored rather than rejected. This stage is retained as a
 * documented no-op to keep the composable-check API and the canonical
 * validation order stable.
 *
 * @param[in] body  Unused. Accepted so the signature matches the other checks.
 * @retval OCA_OK  Always.
 *
 * @note OCA_FAIL_RESERVED_BITS exists for a Consumer that chooses to enforce a
 *       stricter policy; this function never returns it.
 */
oca_result_t oca_check_reserved_bits  (const uint8_t *body);

/**
 * @brief Reject a non-secure manifest that left its signing fields populated.
 *
 * A manifest declaring secure_boot = 0 must zero the signature, public-key, and
 * related fields. Non-zero content there is a producer error worth catching:
 * the bundle looks signed to a casual reader while nothing will ever verify it,
 * which is exactly the confusion that leads to an unsigned image being trusted.
 *
 * Distinct from OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT, which reports the
 * opposite mistake — encryption declared without authentication.
 *
 * Also owns the one class-bit rule that is structural rather than a property
 * of the effective secure-boot state: secure_boot_pqc set on a variant that
 * carries no PQC crypto region is a format violation regardless of whether
 * secure boot is enabled, so it is rejected here, before the enable bit is
 * even consulted.
 *
 * @param[in] body  Whole variant body. See the length contract above.
 * @retval OCA_OK                              Invariant holds.
 * @retval OCA_FAIL_INVALID_ARG                @p body was NULL.
 * @retval OCA_FAIL_SECURE_BOOT_INVARIANT      Signing fields non-zero on a
 *                                             secure_boot = 0 manifest.
 * @retval OCA_FAIL_SIGNATURE_CLASS_CONTROL    secure_boot_pqc set on a variant
 *                                             with no PQC fields to satisfy it.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_check_secure_boot_invariant(const uint8_t *body);

/**
 * @brief Reject a secure manifest whose crypto size fields are inconsistent.
 *
 * signature_size_classic and public_key_size_classic give the number of valid
 * bytes in their companion fields, which are sized for the largest supported
 * value and zero-padded beyond. Both bound how far a Consumer reads, so a size
 * that is zero, overruns its field, or disagrees with what the declared
 * algorithm and encoding can produce is rejected before any parse uses it.
 *
 * Every size is an exact byte count except one: a DER ECDSA signature carries
 * the algorithm's MAXIMUM DER length instead. That field lies inside the region
 * its own signature covers, so its value has to be fixed before the signature
 * exists, and a DER ECDSA length is value-dependent. The DER length octets give
 * the real size within the declared maximum.
 *
 * Keyed on the manifest's own secure_boot bits, like
 * oca_check_secure_boot_invariant(), and the two partition the question between
 * them: a manifest declaring itself non-secure must zero these fields, one
 * declaring itself secure must describe them consistently. Each class's
 * description is validated only when its class bit names it — a PQC-only
 * manifest zeroes the classical fields, and the classical rules must not fire
 * on fields the manifest never uses.
 *
 * The PQC size fields (signature_size_pqc, public_key_size_pqc) get bounds
 * validation only — nonzero, within their fields. Per-algorithm exact sizes
 * are pinned when a PQC verification backend exists to consume them.
 *
 * Structural validation of the DER itself — well-formed, and decoding to no
 * more than the declared size — belongs to the crypto backend, the only
 * component that parses ASN.1.
 *
 * @param[in] body  Whole variant body. See the length contract above.
 * @retval OCA_OK                       Sizes consistent, or manifest non-secure.
 * @retval OCA_FAIL_INVALID_ARG         @p body was NULL.
 * @retval OCA_FAIL_CRYPTO_FIELD_SIZE   A size field is zero, overruns its
 *                                      field, or disagrees with the declared
 *                                      algorithm and encoding.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_check_crypto_field_sizes(const uint8_t *body);

/**
 * @brief Reject a signature_class_revoke group-code byte that is neither 0x00
 * nor its group's constant.
 *
 * Each half of signature_class_revoke carries a group code alongside its
 * per-algorithm bits: 0xCA for the classical group, 0xAC for the post-quantum
 * one. A group code is a single constant, not a bitmask — an intact code
 * disables every algorithm in its group, which is what makes a group-wide
 * revocation an explicit act rather than something a device accumulates its way
 * into. The device-side register is updated by OR and is typically OTP-backed,
 * so a manifest carrying a FRAGMENT of a code would let fragments from separate
 * manifests add up to an intact constant that no single manifest declared.
 *
 * Un-gated by secure boot on purpose. It reads only manifest bytes, needs no
 * callback and no device state, and the requirement carries no secure-boot
 * qualifier. Gating it on the determination would also mean a single glitched
 * reporter could disarm the one check standing between a malformed group code
 * and an irreversible fuse write. On a conformant non-secure manifest the field
 * is zero, so the check passes trivially and only ever rejects a producer defect.
 *
 * @param[in] body  Whole variant body. See the length contract above.
 * @retval OCA_OK                Both group-code bytes are 0x00 or intact.
 * @retval OCA_FAIL_INVALID_ARG  @p body was NULL.
 * @retval OCA_FAIL_GROUP_CODE   A group-code byte held some other value.
 */
oca_result_t oca_check_signature_class_group_codes(const uint8_t *body);

/**
 * @brief Decide whether secure boot is enforced for this boot.
 *
 * The precedence itself, with no side effects. oca_determine_secure_boot() calls
 * it once to establish this validation's reference, and every check that
 * consumes that reference calls it again to confirm the answer has not moved.
 * Exposed so callers composing checks by hand can ask the same question the
 * library asks.
 *
 * Three inputs, consulted in this order, the first to settle the question
 * deciding it:
 *
 *   1. the manifest's secure_boot_control bit 0   -> in force
 *   2. cb->is_secure_boot_disabled() == true      -> NOT in force
 *   3. cb->is_secure_boot_active()                -> its answer
 *
 * If none of the three settles it — neither reporter wired — the answer is IN
 * FORCE. That default is deliberate: an integrator who has not affirmatively
 * established "off" gets the secure path, not a silent bypass.
 *
 * Only (2) can turn secure boot off, and only against (3) and that default. The
 * manifest outranks it: an image built to be verified is never downgraded by
 * anything the device reports, so no fault, mis-provisioned fuse, or defective
 * reporter can cause a secure manifest to run unverified.
 *
 * Consults the callbacks on every call and caches nothing. Nothing in the
 * library treats a previous answer as authoritative either: the recorded
 * determination is a reference to compare against, not a cache to trust, so a
 * misread can neither propagate into a later check nor hide there — the
 * disagreement it causes is itself the failure. See oca_determine_secure_boot().
 *
 * @param[in] body  Whole variant body. See the length contract above.
 * @param[in] cb    Callback table. May be NULL; both reporters are optional.
 * @return OCA_SECURE_TRUE when secure boot is in force for this boot,
 *         OCA_SECURE_FALSE otherwise. Not a plain `bool`: the answer decides
 *         whether a signature is verified, and in a `bool` a single flipped bit
 *         is the difference. Test it per the rule on oca_secure_bool_t rather
 *         than for truthiness.
 */
oca_secure_bool_t oca_secure_boot_active(const uint8_t *body,
                                         const oca_callbacks_t *cb);

/**
 * @brief Settle secure boot for this validation and record it in @p ctx.
 *
 * Runs oca_secure_boot_active()'s precedence once and writes what it observed.
 * Call it before any check that consumes the determination; oca_validate() and
 * oca_validate_manifest() do so themselves, immediately after the integrity and
 * structural checks and before anything that gates on the answer.
 *
 * The recorded verdict is a REFERENCE, not a decision the later checks inherit.
 * Each of them re-derives the determination and requires it to still match, so
 * establishing it here costs an attacker a consistent fault at every consumer
 * rather than a single one at whichever check they prefer to skip.
 *
 * Placed after the manifest-hash check by its callers because the precedence's
 * highest-priority input is a manifest bit, and settling the question out of
 * bytes that failed their integrity check would settle it from damage.
 *
 * Also records which signature classes verify this manifest —
 * secure_boot_enforce_classic and secure_boot_enforce_pqc, from the
 * secure_boot_control class bits — in the same consultation, and rejects the
 * one selection nothing can satisfy: secure boot in force with neither class
 * named. That rejection returns BEFORE secure_boot_determined is set, so a
 * sequence that ignores it holds an unsettled context every gated check
 * refuses.
 *
 * @param[in]  body  Whole variant body. See the length contract above.
 * @param[in]  cb    Callback table. May be NULL; both reporters are optional.
 * @param[out] ctx   Receives secure_boot_enabled always, the two enforcement
 *                   flags always, and secure_boot_device_disabled when input
 *                   (2) of the precedence was both reached and affirmative — a
 *                   manifest that settles the question at (1) never consults
 *                   the device, so that field distinguishes "did not need to
 *                   ask" from "the device said no". secure_boot_determined is
 *                   set last, after the values it vouches for.
 * @retval OCA_OK                  The determination ran and @p ctx holds it.
 * @retval OCA_FAIL_INVALID_ARG    @p body or @p ctx was NULL. Nothing recorded,
 *                                 so every consumer will refuse.
 * @retval OCA_FAIL_SIGNATURE_CLASS_CONTROL  Secure boot is in force and neither
 *                                 class bit is set, or secure_boot_pqc is set
 *                                 on a variant with no PQC crypto region — an
 *                                 enforcement never recorded, so no settled
 *                                 context can claim it. Either way
 *                                 secure_boot_determined is left unset and the
 *                                 context stays unusable.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_determine_secure_boot(const uint8_t *body,
                                       const oca_callbacks_t *cb,
                                       oca_validation_context_t *ctx);

/**
 * @brief Report whether the device asserts secure boot is definitively disabled.
 *
 * Input (2) of oca_secure_boot_active()'s precedence, on its own. Exposed for
 * callers composing their own policy, and so integrators can probe a part's
 * provisioning directly.
 *
 * @param[in] cb  Callback table. NULL, or a NULL is_secure_boot_disabled slot,
 *                yields OCA_SECURE_FALSE.
 * @return OCA_SECURE_TRUE only when the device affirmatively asserts secure boot
 *         disabled; OCA_SECURE_FALSE otherwise. Hardened rather than a plain
 *         `bool` because TRUE here is the one answer that turns secure boot off.
 *
 * @warning OCA_SECURE_FALSE means "not asserted", which is also the answer for
 *          an integration that never wired the reporter. It is not a statement
 *          that secure boot is enabled.
 */
oca_secure_bool_t oca_secure_boot_device_disabled(const oca_callbacks_t *cb);

/**
 * @brief Check one hardware identity against the manifest's constraint.
 *
 * Reads the device value through cb->get_identity_bytes and compares it with
 * the manifest's constraint for @p kind. When the manifest does not constrain
 * this field the check passes without consulting the callback, so a permissive
 * manifest costs no hardware reads.
 *
 * An unavailable device value is a hard failure, never a waiver — see
 * oca_hw_result_t.
 *
 * @param[in] body   Whole variant body. See the length contract above.
 * @param[in] kind   Which identity to check.
 * @param[in] cb     Callback table. Required only when the constraint is active.
 * @retval OCA_OK                          Constraint satisfied or not applicable.
 * @retval OCA_FAIL_INVALID_ARG            @p body was NULL.
 * @retval OCA_FAIL_CHIPLET_ID             Chiplet identity did not match.
 * @retval OCA_FAIL_PACKAGE_ID             Package identity did not match.
 * @retval OCA_FAIL_SYSTEM_ID              System identity did not match.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   Constraint is active but the callback
 *                                         is NULL or reported unavailable.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_check_identity(
    const uint8_t *body,
    oca_id_kind_t kind,
    const oca_callbacks_t *cb);

/**
 * @brief Check the device's lifecycle state against the manifest's constraint.
 *
 * Reads the device state through cb->get_lifecycle_state and confirms the
 * manifest permits it at @p level. As with oca_check_identity, an unconstrained
 * level passes without a hardware read, and an unavailable state fails.
 *
 * @param[in] body   Whole variant body. See the length contract above.
 * @param[in] level  Which level's lifecycle to check.
 * @param[in] cb     Callback table. Required only when the constraint is active.
 * @retval OCA_OK                          Constraint satisfied or not applicable.
 * @retval OCA_FAIL_INVALID_ARG            @p body was NULL.
 * @retval OCA_FAIL_LIFECYCLE              Device state is not permitted.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   Constraint is active but the callback
 *                                         is NULL or reported unavailable.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_check_lifecycle(
    const uint8_t *body,
    oca_lifecycle_level_t level,
    const oca_callbacks_t *cb);

/**
 * @brief Check the device's version against the manifest's permitted range.
 *
 * Reads the device version through cb->get_version and confirms it falls within
 * the manifest's minimum and maximum for @p level. Either bound may be enabled
 * independently, so a manifest can set a floor without a ceiling.
 *
 * @param[in] body   Whole variant body. See the length contract above.
 * @param[in] level  Which level's version to check.
 * @param[in] cb     Callback table. Required only when a bound is enabled.
 * @retval OCA_OK                          Version in range, or no bound enabled.
 * @retval OCA_FAIL_INVALID_ARG            @p body was NULL.
 * @retval OCA_FAIL_VERSION_RANGE          Device version is outside the range.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   A bound is enabled but the callback
 *                                         is NULL or reported unavailable.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_check_version_range(
    const uint8_t *body,
    oca_version_level_t level,
    const oca_callbacks_t *cb);

/**
 * @brief Demotion-control stage. Always passes, by design.
 *
 * demotion_control carries an operative directive in bits [3:0] that the boot
 * ROM consumes device-side, plus reserved bits [15:4]. This host validator acts
 * on neither: the directive is not its to interpret, and reserved bits are
 * ignored rather than rejected for the forward-compatibility reason given on
 * oca_check_reserved_bits(). Retained as a documented no-op so the composable
 * API and the canonical order stay stable.
 *
 * @param[in] body  Unused. Accepted so the signature matches the other checks.
 * @retval OCA_OK  Always.
 * @return The result of the demotion stage it delegates to, which is
 *         unconditionally OCA_OK.
 *
 * @note OCA_FAIL_DEMOTION_CONTROL exists for a Consumer enforcing a stricter
 *       policy; this function never returns it.
 */
oca_result_t oca_check_demotion_control(const uint8_t *body);

/**
 * @brief Verify the manifest's integrity digest over [0, signed_region_end).
 *
 * Intended to run early in the manifest handling process. oca_validate_manifest() 
 * runs it directly after oca_check_manifest_length() and before any field is decoded, so a damaged
 * manifest reports OCA_FAIL_MANIFEST_HASH instead of whichever field happens to
 * decode wrong out of the damaged bytes, and hardware-identity callbacks are
 * not spent on it.
 *
 * @param[in] body  Whole variant body. See the length contract above.
 * @param[in] cb    Callback table; cb->sha256 is required.
 * @retval OCA_OK                          Recomputed digest matches.
 * @retval OCA_FAIL_INVALID_ARG            @p body or @p cb was NULL.
 * @retval OCA_FAIL_MANIFEST_HASH          Digest mismatch.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   cb->sha256 is NULL or unavailable.
 * @return Otherwise the magic or variant failure from resolving @p body.
 *
 * @warning NOT a trust boundary. The expected digest lives in the manifest's
 *          UNSIGNED tail, so anyone editing the manifest recomputes it freely.
 *          This catches corruption — a bad flash read, bit rot. Authenticity
 *          comes only from oca_check_signature().
 */
oca_result_t oca_check_manifest_hash(
    const uint8_t *body,
    const oca_callbacks_t *cb);

/**
 * @brief Verify every enforced manifest signature, when secure boot is in force.
 *
 * The source of manifest authenticity. A no-op returning OCA_OK when @p ctx
 * records that secure boot is not in force — and the live determination still
 * agrees, which this re-derives and checks before acting either way.
 *
 * Runs one verification per enforced signature class: the classical signature
 * when secure_boot_classic is set, the PQC signature when secure_boot_pqc is,
 * BOTH when both are — a hybrid manifest is a logical AND, never or-else.
 * Each class is verified only if oca_check_root_key_authorized() recorded that
 * class's OWN anchor vouching for its key; a classical vouching never unlocks
 * a PQC verify. The recorded enforcement is confirmed against the manifest's
 * class bits before it is acted on, the same time-of-use rule the secure-boot
 * determination gets.
 *
 * @param[in]     body  Whole variant body. See the length contract above.
 * @param[in]     cb    Callback table; cb->verify_signature is required under
 *                      secure boot — invoked once per enforced class, with the
 *                      blob's key_algorithm naming the family — and the
 *                      secure-boot reporters are consulted again here to
 *                      confirm the recorded determination.
 * @param[in,out] ctx   Read for the determination, the enforcement, and the
 *                      per-class authorizations; written for the outcome.
 *                      secure_boot_authenticated is set to OCA_SECURE_TRUE only
 *                      AFTER every enforced class's verifier has returned
 *                      OCA_OK, never on the strength of one signature of a
 *                      hybrid pair — this is its sole writer. Must be a context
 *                      oca_determine_secure_boot() has settled; NULL, or one it
 *                      has not, is refused rather than treated as "not in
 *                      force".
 * @retval OCA_OK                          Every enforced signature verified,
 *                                         or secure boot is not in force.
 * @retval OCA_FAIL_INVALID_ARG            @p body was NULL.
 * @retval OCA_FAIL_SIGNATURE              A verification failed.
 * @retval OCA_FAIL_ROOT_KEY_UNAUTHORIZED  An enforced class's key was never
 *                                         vouched for by its anchor.
 * @retval OCA_FAIL_SIGNATURE_CLASS_CONTROL  No class is enforced in an engaged
 *                                         context, or PQC is enforced on a
 *                                         variant with no PQC fields — both
 *                                         only reachable around the checks
 *                                         that reject them earlier.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   Verify callback missing under secure boot.
 * @retval OCA_FAIL_SECURE_BOOT_UNDETERMINED  @p ctx holds no determination.
 * @retval OCA_FAIL_SECURE_BOOT_STATE_CHANGED The live determination — or the
 *                                         recorded enforcement — no longer
 *                                         matches the manifest.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_check_signature(
    const uint8_t *body,
    const oca_callbacks_t *cb,
    oca_validation_context_t *ctx);

/**
 * @brief Reject a manifest whose ROOT keys this device does not authorize.
 *
 * A no-op returning OCA_OK when @p ctx records that secure boot is not in force.
 * Otherwise hands each ENFORCED class's public key and public_key_select bitmap
 * to cb->is_key_authorized — the classical key when secure_boot_classic is set,
 * the PQC key when secure_boot_pqc is, both for a hybrid manifest, each blob
 * carrying its key_algorithm so the implementation knows which anchor family to
 * consult — and rejects unless the device claims every one of them.
 *
 * Compose this FIRST of the key checks, before oca_check_root_key_revocation()
 * and oca_check_signature(). Verifying a signature establishes only that some
 * private key signed the manifest; this is the check that says whose. Deciding
 * it first means an unknown key is never used and never costs a modexp.
 *
 * Authorization and revocation are separate questions in that order:
 * authorization asks whether the device ever trusted the key, revocation whether
 * it still does. A key can be unauthorized with no revocation bit set anywhere.
 *
 * @param[in]     body  Whole variant body. See the length contract above.
 * @param[in]     cb    Callback table; cb->is_key_authorized is required under
 *                      secure boot, and the secure-boot reporters are consulted
 *                      again here to confirm the recorded determination.
 * @param[in,out] ctx   Read for the determination and the recorded enforcement
 *                      — which is confirmed against the manifest's class bits
 *                      before it is acted on — and written for the outcome:
 *                      secure_boot_key_authorized_classic /
 *                      secure_boot_key_authorized_pqc are each set to
 *                      OCA_SECURE_TRUE only after the callback vouched for that
 *                      class's key. Must be a context
 *                      oca_determine_secure_boot() has settled; NULL, or one it
 *                      has not, is refused rather than treated as "not in
 *                      force".
 * @retval OCA_OK                          The device authorizes every enforced
 *                                         class's key, or secure boot is not
 *                                         in force.
 * @retval OCA_FAIL_ROOT_KEY_UNAUTHORIZED  It does not, or the callback answered
 *                                         with a code of its own invention.
 * @retval OCA_FAIL_SIGNATURE_CLASS_CONTROL  No class is enforced in an engaged
 *                                         context, or PQC is enforced on a
 *                                         variant with no PQC fields — both
 *                                         only reachable around the checks
 *                                         that reject them earlier.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   Callback missing under secure boot, or
 *                                         the anchor could not be read.
 * @retval OCA_FAIL_SECURE_BOOT_UNDETERMINED  @p ctx holds no determination.
 * @retval OCA_FAIL_SECURE_BOOT_STATE_CHANGED The live determination — or the
 *                                         recorded enforcement — no longer
 *                                         matches the manifest.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_check_root_key_authorized(
    const uint8_t *body,
    const oca_callbacks_t *cb,
    oca_validation_context_t *ctx);

/**
 * @brief Reject a manifest whose selected ROOT key has been revoked.
 *
 * A no-op returning OCA_OK when @p ctx records that secure boot is not in force.
 * Otherwise rejects if a ROOT key selected in public_key_select_classic is
 * revoked either in the manifest's public_key_classic_revoke or in the
 * device-stored classic revocation state, read via cb->get_root_key_revocation.
 *
 * Decided BEFORE the key is used to verify the signature, so compose it before
 * oca_check_signature() — a revoked key must never be exercised, not merely
 * have its verdict discarded afterwards.
 *
 * Reserved select and revoke bits (127:112) are ignored.
 *
 * @param[in] body  Whole variant body. See the length contract above.
 * @param[in] cb    Callback table; cb->get_root_key_revocation is required
 *                  under secure boot, and the secure-boot reporters are
 *                  consulted again here to confirm the recorded determination.
 * @param[in] ctx   The determination oca_determine_secure_boot() recorded. Read,
 *                  never written. NULL, or a context it has not settled, is
 *                  refused rather than treated as "not in force".
 * @retval OCA_OK                          No selected key is revoked, or secure
 *                                         boot is not in force.
 * @retval OCA_FAIL_ROOT_KEY_REVOKED       A selected ROOT key is revoked.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   Read callback missing under secure boot.
 * @retval OCA_FAIL_SECURE_BOOT_UNDETERMINED  @p ctx holds no determination.
 * @retval OCA_FAIL_SECURE_BOOT_STATE_CHANGED The live determination no longer
 *                                         matches the recorded one.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_check_root_key_revocation(
    const uint8_t *body,
    const oca_callbacks_t *cb,
    const oca_validation_context_t *ctx);

/**
 * @brief Enforce anti-rollback against the device-stored security version.
 *
 * A no-op returning OCA_OK when secure boot is not in force. Otherwise reads
 * the device-stored security-version flags via cb->get_security_version and
 * requires manifest_security_version to be a bit-superset of the device value
 * (manifest & device == device).
 *
 * oca_validate_manifest() composes this TWICE: once before oca_check_signature(),
 * so a replayed manifest is rejected without paying for a public-key operation,
 * and once after (see OCA_RECHECK_SECURITY_VERSION).
 *
 * Rejecting before authentication is sound in the rejection direction only. The
 * compared value lies inside the signed region, so a manifest altered to change
 * the outcome fails verification, and one that genuinely fails is a rollback
 * whoever wrote it. A *pass* before the signature is not a decision — it
 * becomes one retroactively once the signature verifies over that region.
 *
 * Stateless, and re-reads the DEVICE value on every call, so composing it twice
 * never reuses a possibly-faulted read. The secure-boot determination is handled
 * differently — @p ctx carries it, and this re-derives it only to confirm the
 * record still holds, never to decide afresh.
 *
 * @param[in] body  Whole variant body. See the length contract above.
 * @param[in] cb    Callback table; cb->get_security_version is required under
 *                  secure boot, and the secure-boot reporters are consulted
 *                  again here to confirm the recorded determination.
 * @param[in] ctx   The determination oca_determine_secure_boot() recorded. Read,
 *                  never written. NULL, or a context it has not settled, is
 *                  refused rather than treated as "not in force".
 * @retval OCA_OK                          Manifest is a bit-superset, or secure
 *                                         boot is not in force.
 * @retval OCA_FAIL_SECURITY_VERSION       Anti-rollback rejection.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   Read callback missing under secure boot.
 * @retval OCA_FAIL_SECURE_BOOT_UNDETERMINED  @p ctx holds no determination.
 * @retval OCA_FAIL_SECURE_BOOT_STATE_CHANGED The live determination no longer
 *                                         matches the recorded one.
 * @return Otherwise the magic or variant failure from resolving @p body.
 *
 * @warning When composing by hand, an early call MAY reject, but do NOT treat
 *          an early pass as final unless a signature check has since succeeded.
 */
oca_result_t oca_check_security_version(
    const uint8_t *body,
    const oca_callbacks_t *cb,
    const oca_validation_context_t *ctx);

/**
 * @brief Refuse an encrypted payload on a part where secure boot is not in force.
 *
 * The cheap half of the encryption rule, and the cheapest gated check in the
 * library: a manifest read and a context comparison, no hardware identity read
 * and no public-key operation. Compose it EARLY — oca_validate_manifest() runs
 * it directly after the determination — so an encrypted payload declared on a
 * non-secure part is rejected before anything expensive is spent on it.
 *
 * Necessary but NOT sufficient. Secure boot being in force does not mean a
 * signature was checked, and only the confirmed form may release plaintext, so
 * this never replaces oca_check_payload_encryption_policy(). Both report the
 * same code, because from an integrator's point of view the fault is identical —
 * this bundle needs a secure part and did not get one.
 *
 * The encryption control bit is the sole trigger: neither a zero-length payload
 * nor a stray encryption_type changes whether this rule applies.
 *
 * @param[in] body  Whole variant body. See the length contract above.
 * @param[in] cb    Callback table; the secure-boot reporters are consulted here
 *                  to confirm the recorded determination.
 * @param[in] ctx   The determination oca_determine_secure_boot() recorded. Read,
 *                  never written. NULL, or a context it has not settled, is
 *                  refused rather than treated as "not in force".
 * @retval OCA_OK                                      No encryption declared, or
 *                                                     secure boot is in force.
 * @retval OCA_FAIL_INVALID_ARG                        @p body was NULL.
 * @retval OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT    Encryption declared on a
 *                                                     part where secure boot is
 *                                                     not in force.
 * @retval OCA_FAIL_SECURE_BOOT_UNDETERMINED           @p ctx holds no
 *                                                     determination.
 * @retval OCA_FAIL_SECURE_BOOT_STATE_CHANGED          The live determination no
 *                                                     longer matches the record.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_check_payload_encryption_precondition(
    const uint8_t *body,
    const oca_callbacks_t *cb,
    const oca_validation_context_t *ctx);

/**
 * @brief Refuse an encrypted payload without CONFIRMED authentication.
 *
 * Reads ctx->secure_boot_authenticated rather than re-deriving anything, so a
 * check sequence that never reached oca_check_signature() is refused exactly
 * like one on a device with secure boot disabled. A NULL or zero-initialised
 * context therefore refuses — the intended default, not an error.
 *
 * This is the authoritative form, and the only one that may gate decryption.
 * oca_check_payload_encryption_precondition() rejects the same manifests earlier
 * and more cheaply, but "secure boot is in force" is a weaker fact than "a
 * signature ran and passed" and the two must not be conflated.
 *
 * The encryption control bit is the sole trigger: neither a zero-length payload
 * nor a stray encryption_type changes whether this rule applies.
 *
 * Compose it LAST among the manifest checks, because it reads what
 * oca_check_signature() recorded.
 *
 * @param[in] body  Whole variant body. See the length contract above.
 * @param[in] cb    Callback table. Unused today; accepted for signature
 *                  symmetry with the other check functions.
 * @param[in] ctx   Validation context. Read, never written. NULL refuses.
 * @retval OCA_OK                                      No encryption declared,
 *                                                     or authentication confirmed.
 * @retval OCA_FAIL_INVALID_ARG                        @p body was NULL.
 * @retval OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT    Encryption declared
 *                                                     without confirmed
 *                                                     authentication.
 * @return Otherwise the magic or variant failure from resolving @p body.
 */
oca_result_t oca_check_payload_encryption_policy(
    const uint8_t *body,
    const oca_callbacks_t *cb,
    const oca_validation_context_t *ctx);

/**
 * @brief Validate a payload held in one buffer with the manifest body.
 *
 * A convenience entry point for the case where the caller already holds the
 * manifest and its payload adjacent in memory — the layout `oca_validate()`
 * expects, and what a host tool assembling a bundle naturally produces.
 *
 * THIS IS NOT A PROPERTY OF THE FORMAT. A payload may sit at any offset
 * relative to its manifest; that is precisely what the signed-region-external
 * payload_offset field exists to express, and a manifest whose payload lives
 * elsewhere is entirely well-formed. What this function requires is narrower:
 * that the manifest it is handed happens to declare the adjacent layout, so the
 * payload can be found without storage bounds it was not given. The general
 * path is oca_locate_payload() to resolve the offset, then
 * oca_check_payload_at() to verify the bytes wherever they were staged. Reach
 * for that one whenever the layout is not known in advance.
 *
 * Encrypted payloads (payload_encryption_control bit 0 set) enforce
 * authenticate-then-decrypt: verify payload_hash over the stored ciphertext,
 * decrypt via cb->decrypt_payload, then validate the recovered plaintext.
 * Cleartext payloads skip the first two steps and validate the payload in
 * place; payload_hash covers the TOC region, whose length
 * payload_hashed_length records.
 *
 * Both paths then run the same plaintext checks: TOC structural validation,
 * payload_hash_chain, and each TOC entry's stored hash against the image bytes
 * it describes.
 *
 * A manifest declaring payload_offset other than the body size is refused with
 * OCA_FAIL_PAYLOAD_LOCATION rather than validated against the wrong bytes — the
 * mismatch means this entry point is the wrong one for that manifest, not that
 * the manifest is malformed. The test is skipped entirely when no payload is
 * declared, since the question is then moot.
 *
 * @param[in] body         Manifest body with its payload immediately after it,
 *                         in one buffer.
 * @param[in] body_length  Total size of @p body, validated internally.
 * @param[in] cb           Callback table; cb->sha256 always, cb->decrypt_payload
 *                         when the payload is encrypted.
 * @param[in] ctx          Validation context, read for the encryption policy.
 * @param[out] out_plaintext     Receives the validated plaintext location and
 *                               recovered length. Written ONLY when this
 *                               function returns OCA_OK, so a caller is never
 *                               handed a location the payload checks had not
 *                               finished verifying. NULL declines the report,
 *                               which is supported and changes no verdict.
 * @retval OCA_OK                            Payload validated, or the manifest
 *                                           declares no payload.
 * @retval OCA_FAIL_INVALID_ARG              @p body or @p cb was NULL.
 * @retval OCA_FAIL_TRUNCATED                Declared payload bytes are absent
 *                                           from @p body.
 * @retval OCA_FAIL_PAYLOAD_LOCATION         The manifest places its payload
 *                                           somewhere other than immediately
 *                                           after the body, so this entry point
 *                                           does not apply to it. Use
 *                                           oca_locate_payload() with
 *                                           oca_check_payload_at() instead.
 * @return Otherwise the result of the payload checks it composes —
 *         OCA_FAIL_PAYLOAD_HASH, OCA_FAIL_DECRYPT, OCA_FAIL_PAYLOAD_TOC,
 *         OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES, OCA_FAIL_PAYLOAD_HASH_CHAIN,
 *         OCA_FAIL_PAYLOAD_ENTRY_HASH — or the magic or variant failure from
 *         resolving @p body.
 */
oca_result_t oca_check_payload(
    const uint8_t *body,
    size_t         body_length,
    const oca_callbacks_t *cb,
    const oca_validation_context_t *ctx,
    oca_payload_plaintext_t *out_plaintext);

/* ------------------------------------------------------------------ */
/* Payload encryption, from the manifest body alone                   */
/* ------------------------------------------------------------------ */

/**
 * @brief How, and whether, the payload is encrypted.
 *
 * What a Consumer needs to wire decrypt_payload, and afterwards to know whether
 * the payload buffer it holds is ciphertext or plaintext.
 *
 * @warning All three fields lie inside the signed region, so they mean nothing
 *          until oca_check_signature() has verified it.
 */
typedef struct oca_payload_encryption {
    /** payload_encryption_control bit 0. The sole trigger for the encryption
     *  policy check. */
    bool     encrypted;
    /** An oca_encryption_type_t value, reported verbatim rather than validated.
     *  OCA_ENCRYPTION_TYPE_NONE unless @c encrypted. A value outside the enum
     *  means the manifest names a cipher this build does not implement, which
     *  oca_check_payload() rejects when it gets there — deciding it here would
     *  duplicate that check in a second place. */
    uint8_t  type;
    /** Provisioned-secret index, 1-based. Zero unless @c encrypted. Resolving
     *  this to an actual secret is the ingestor's job, done before validation. */
    uint16_t secret_select;
} oca_payload_encryption_t;

/**
 * @brief Report how, and whether, the payload is encrypted, from the body alone.
 *
 * Unlike oca_payload_region()'s @c encrypted out-parameter this needs no
 * payload resident and assumes no contiguity, so it answers in the staged flow
 * too, where the payload is a separate buffer and oca_payload_region() does not
 * apply.
 *
 * NOT needed to drive decryption. The decryption callback receives the cipher
 * and the provisioned-secret selector as named fields on oca_decrypt_input_t, so
 * it never has to read them back out of the manifest for itself. This function is
 * for a consumer deciding something BEFORE the payload stage — most usefully
 * whether to wire decrypt_payload at all, or whether a bundle is encrypted before
 * committing to staging it.
 *
 * @param[in]  body  Whole variant body. See the length contract above.
 * @param[out] out   Filled on success; untouched on failure.
 * @retval OCA_OK                  Fields reported.
 * @retval OCA_FAIL_INVALID_ARG    @p body or @p out was NULL.
 * @return Otherwise the magic or variant failure from resolving @p body.
 *
 * @warning Every field lies inside the signed region and means nothing until
 *          oca_check_signature() has verified it. Reading them off an
 *          unauthenticated manifest is a choice, not a requirement, and not one
 *          this API asks you to make.
 */
oca_result_t oca_payload_encryption_info(const uint8_t *body,
                                         oca_payload_encryption_t *out);

/* ------------------------------------------------------------------ */
/* Payload TOC access (post-validation)                               */
/*                                                                    */
/* Validation decides PASS/FAIL; these read the values a Consumer     */
/* needs afterwards to act on a payload — where to stage each image   */
/* and where to enter it.                                             */
/*                                                                    */
/* THE CALLER MUST HAVE VALIDATED FIRST. These functions are          */
/* stateless: they re-derive the TOC bounds so they can never hand    */
/* back an out-of-range pointer or length, but they verify nothing    */
/* beyond that — they decode structure, and well-formed structure is  */
/* not a trust statement.                                             */
/*                                                                    */
/* The bytes they hand back are made trustworthy in two steps, both   */
/* outside these functions. oca_check_payload() /                     */
/* oca_check_payload_at() verify payload_hash, payload_hash_chain and */
/* each entry hash — that is cryptography, and it establishes         */
/* INTEGRITY. AUTHENTICITY is transitive: those digests live in the   */
/* manifest's signed region, so they are only trustworthy once        */
/* oca_check_signature() has verified it. With secure boot off the    */
/* signature never runs and you have integrity alone — enough to      */
/* catch a corrupt read, not a substituted payload.                   */
/*                                                                    */
/* The library cannot enforce that ordering for you — it holds no     */
/* state across calls by design.                                      */
/*                                                                    */
/* They operate on the PLAINTEXT payload region (the PTOC header, its */
/* entries, and the image bytes), not on the manifest body:           */
/*                                                                    */
/*   - Cleartext payload: use oca_payload_region() to locate it       */
/*     inside the bundle.                                             */
/*   - Encrypted payload: pass the buffer your decrypt_payload        */
/*     callback produced. The library does not retain that pointer    */
/*     after oca_check_payload() returns, so it cannot supply it.     */
/*                                                                    */
/* See INTEGRATION.md, "Reading the payload after validation".        */
/* ------------------------------------------------------------------ */

/**
 * @brief The decoded PTOC header at the start of a plaintext payload.
 *
 * Describes the table of contents itself, not any one image.
 *
 * @note Check @c version_major and @c version_minor before relying on any
 *       oca_image_info_t field: a future major could change the entry encoding
 *       entirely, and the fields would then be decoded under the wrong layout.
 */
typedef struct oca_toc_info {
    uint16_t version_major;   /**< TOC layout major version. */
    uint16_t version_minor;   /**< TOC layout minor version. */
    /** The TOC's own record of the total plaintext payload size. */
    uint64_t payload_length;
    /** Number of image entries. A safe exclusive upper bound for
     *  oca_toc_image_at(), because oca_toc_info() has already confirmed the
     *  entries fit inside the payload. */
    uint64_t image_count;
} oca_toc_info_t;

/**
 * @brief One decoded TOC entry: where an image is, and what it claims to be.
 *
 * Returned by oca_toc_image_at() after that function has bounds-checked the
 * entry, so the pointer and length pair is always safe to use.
 *
 * @warning @c bytes, @c hash, and @c description point INTO the payload buffer
 *          and are valid only as long as it is.
 */
typedef struct oca_image_info {
    /** The image bytes, already bounds-checked against the payload region —
     *  safe to hash, copy, or stage. */
    const uint8_t *bytes;
    /** Length of @c bytes. A size_t because it pairs with @c bytes; the bounds
     *  check guarantees the stored uint64 fits. */
    size_t         length;
    /** The entry's 64-byte hash field. Its leading
     *  OCA_MANIFEST_HASH_DIGEST_SIZE bytes are the digest, the remainder
     *  padding. oca_check_payload() has ALREADY verified this digest against
     *  @c bytes, so a Consumer re-checking it gains nothing. */
    const uint8_t *hash;
    const uint8_t *description;     /**< The entry's description field. */
    uint64_t       offset;          /**< Image offset within the payload. */
    uint64_t       load_addr;       /**< Address the image should be staged at. */
    uint64_t       entry_point;     /**< Address to enter the image at. */
    uint64_t       security_version;/**< The image's own security version. */
    uint64_t       target_chiplet_id;/**< Chiplet this image is intended for. */
    uint32_t       group;           /**< Image group identifier. */
    uint32_t       version_minor;   /**< Decoded 24-bit minor version. */
    uint32_t       version_patch;   /**< Decoded 24-bit patch version. */
    uint16_t       version_major;   /**< Decoded 16-bit major version. */
    /** The entry's 16-byte ASCII type, trailing spaces and NULs trimmed,
     *  NUL-terminated. */
    char           type[17];
} oca_image_info_t;

/* ------------------------------------------------------------------ */
/* Resolving payload_offset in storage                                */
/*                                                                    */
/* payload_offset is a SIGNED 64-bit byte offset from the start of the */
/* manifest to the start of the payload. It lives in the manifest's    */
/* UNVERIFIED tail by design: the spec permits it to be rewritten when */
/* the manifest and payload are placed in flash so it is never trusted. */
/* A negative value means the payload precedes the manifest.          */
/*                                                                    */
/* Following an untrusted locator is safe only once it is bounded: a   */
/* tampered offset can then do no more than send the Consumer to the   */
/* wrong bytes, which fail the authenticated payload_hash /            */
/* payload_hash_chain. Bounding it is what these functions do.         */
/*                                                                    */
/* See INTEGRATION.md, "The staged flow".                             */
/* ------------------------------------------------------------------ */

/**
 * @brief The Consumer's trusted boot region, and where the manifest sits in it.
 *
 * All three fields are supplied by the integrator and are therefore trusted:
 * they describe the device and the boot policy, not the manifest. They are what
 * bounds the manifest's untrusted payload_offset into something safe to follow.
 *
 * @warning Narrow @c region_base / @c region_limit to the bank being booted,
 *          not the whole device. Otherwise bank A's manifest can name bank B's
 *          payload and the hashes will not object — bank B's payload is
 *          genuinely well-formed. Only these bounds can reject a cross-bank
 *          locator.
 */
typedef struct oca_storage_bounds {
    int64_t manifest_addr;   /**< Address this manifest was read FROM. */
    int64_t region_base;     /**< Lowest address the payload may occupy. */
    int64_t region_limit;    /**< One past the highest address it may occupy. */
} oca_storage_bounds_t;

/**
 * @brief Bytes the manifest and its appended entries occupy in storage.
 *
 * Measured from bounds->manifest_addr. The payload may not overlap this span,
 * which is what oca_locate_payload() uses it for.
 *
 *   body_size
 * + (use_verifier_key      ? verifier_entry_size  : 0)
 * + popcount(co_signer_enable) * co_signer_entry_size
 *
 * Both entry sizes are variant constants and both counts come from fields
 * inside the SIGNED region, so the bound is derivable from authenticated data
 * without reading a single appended byte — which matters, because those bytes
 * are themselves untrusted until hashed. This build does not verify the
 * appended entries, but it must still account for the space they occupy.
 *
 * @param[in]  body     Whole variant body. See the length contract above.
 * @param[out] out_len  Receives the span in bytes. Untouched on failure.
 * @retval OCA_OK                  Length reported.
 * @retval OCA_FAIL_INVALID_ARG    @p body or @p out_len was NULL.
 * @return Otherwise the magic or variant failure from resolving @p body.
 *
 * @note The length comes back through @p out_len rather than the return value
 *       so a failure stays distinguishable: every other function here returns
 *       oca_result_t, and a bare size_t would have to overload 0 as both
 *       "error" and a legitimate length.
 */
oca_result_t oca_manifest_region_len(const uint8_t *body, size_t *out_len);

/**
 * @brief Resolve payload_offset to a bounded, safe-to-follow storage address.
 *
 * payload_offset is a SIGNED 64-bit offset living in the manifest's UNVERIFIED
 * tail — the spec permits it to be rewritten when the manifest and payload are
 * placed in flash, so it is never trusted. Following it is safe only once it is
 * bounded: a tampered offset can then do no more than send the Consumer to the
 * wrong bytes, which fail the authenticated payload_hash. Bounding it is what
 * this function does.
 *
 * Call AFTER the manifest has been authenticated, so payload_length and
 * payload_hashed_length (both in the signed region) can be trusted. The offset
 * itself is never trusted; that is the point.
 *
 * @param[in]  body      Whole variant body. See the length contract above.
 * @param[in]  bounds    The permitted region and this manifest's address in it.
 * @param[out] out_addr  Receives the absolute address to read the payload from.
 * @param[out] out_span  Receives how many bytes to read: payload_hashed_length
 *                       when the payload is encrypted (the ciphertext),
 *                       payload_length otherwise.
 * @retval OCA_OK                        Offset resolved and bounded.
 * @retval OCA_FAIL_INVALID_ARG          A NULL argument, or an inverted or
 *                                       empty region.
 * @retval OCA_FAIL_PAYLOAD_LOCATION     Signed overflow computing
 *                                       manifest_addr + payload_offset or
 *                                       addr + span; resolved address below
 *                                       region_base; resolved end above
 *                                       region_limit; or the payload range
 *                                       intersecting the manifest region.
 * @return Otherwise the magic or variant failure from resolving @p body.
 *
 * @note The intersection case is the one a bare "addr >= region_base" test
 *       misses: a negative offset can land legally inside the region and still
 *       have its length run forward into the manifest or its appended entries.
 */
oca_result_t oca_locate_payload(const uint8_t *body,
                                const oca_storage_bounds_t *bounds,
                                int64_t *out_addr,
                                size_t  *out_span);

/**
 * @brief Verify a payload the caller has already staged, wherever it staged it.
 *
 * @p payload need NOT be contiguous with @p body. That assumption is what
 * oca_check_payload() hardcodes, and it is wrong for any manifest whose
 * payload_offset differs from the variant body size — which oca-combined
 * bundles routinely have. Use oca_locate_payload() to find the payload in
 * storage, copy it into secured memory, then pass both pointers here.
 *
 * This is the payload half of the staged flow, and semantics are otherwise
 * identical to oca_check_payload().
 *
 * @param[in] body         Whole variant body, already authenticated.
 * @param[in] payload      The staged payload bytes. Need not adjoin @p body.
 * @param[in] payload_len  Length of @p payload.
 * @param[in] cb           Callback table; cb->sha256 always,
 *                         cb->decrypt_payload when the payload is encrypted.
 * @param[in] ctx          Validation context, read for the encryption policy.
 * @param[out] out_plaintext  Receives the validated plaintext location and
 *                            recovered length. Written ONLY on OCA_OK, so a
 *                            caller is never handed a location the payload
 *                            checks had not finished verifying. NULL declines
 *                            the report and changes no verdict.
 * @retval OCA_OK                          Payload validated.
 * @retval OCA_FAIL_INVALID_ARG            @p body, @p payload, or @p cb was NULL.
 * @retval OCA_FAIL_TRUNCATED              @p payload_len is short of what the
 *                                         manifest declares.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   A required callback is unavailable.
 * @return Otherwise the result of the payload checks it composes, as
 *         oca_check_payload() documents, or the magic or variant failure from
 *         resolving @p body.
 */
oca_result_t oca_check_payload_at(
    const uint8_t *body,
    const uint8_t *payload,
    size_t         payload_len,
    const oca_callbacks_t *cb,
    const oca_validation_context_t *ctx,
    oca_payload_plaintext_t *out_plaintext);

/**
 * @brief Locate the stored payload region that follows the manifest body.
 *
 * The whole-bundle counterpart to oca_locate_payload(): it assumes the payload
 * adjoins the body in one buffer, so it reports a pointer rather than a storage
 * address.
 *
 * @param[in]  body                Full bundle: body followed by the payload.
 * @param[in]  body_length         Total size of @p body.
 * @param[out] out_payload         Receives a pointer to the stored payload.
 * @param[out] out_payload_length  Receives the stored payload length. Zero when
 *                                 the manifest declares no payload.
 * @param[out] out_encrypted       Receives whether those bytes are ciphertext.
 * @retval OCA_OK                  Region located, or the manifest declares no
 *                                 payload.
 * @retval OCA_FAIL_INVALID_ARG    A NULL argument.
 * @retval OCA_FAIL_TRUNCATED      Buffer is shorter than the variant body or
 *                                 the declared payload.
 * @return Otherwise the magic or variant failure from resolving @p body.
 *
 * @warning WHEN @p out_encrypted IS TRUE THE REGION IS CIPHERTEXT. Do not pass
 *          it to oca_toc_info() or oca_toc_image_at(). Decrypt it first — the
 *          same derivation your decrypt_payload callback performs — and pass
 *          the plaintext instead.
 */
oca_result_t oca_payload_region(
    const uint8_t  *body,
    size_t          body_length,
    const uint8_t **out_payload,
    size_t         *out_payload_length,
    bool           *out_encrypted);

/**
 * @brief Decode the PTOC header at the start of a plaintext payload region.
 *
 * Verifies the PTOC magic and that the header plus image_count entries fit
 * inside @p payload_length, which is what makes out->image_count a safe
 * exclusive upper bound for oca_toc_image_at().
 *
 * Stateless and re-derives its bounds, so it can never hand back an
 * out-of-range count — but it verifies nothing cryptographic. The caller must
 * have validated the payload first; well-formed structure is not a trust
 * statement.
 *
 * @param[in]  payload         Plaintext payload region.
 * @param[in]  payload_length  Length of @p payload.
 * @param[out] out             Receives the decoded header.
 * @retval OCA_OK                    Header decoded.
 * @retval OCA_FAIL_INVALID_ARG      @p payload or @p out was NULL.
 * @retval OCA_FAIL_PAYLOAD_TOC      Bad magic, or an unrepresentable span.
 * @return Otherwise the span-bounding result, which also reports
 *         OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES when image_count exceeds this
 *         build's OCA_TOC_MAX_IMAGES.
 */
oca_result_t oca_toc_info(
    const uint8_t   *payload,
    size_t           payload_length,
    oca_toc_info_t  *out);

/**
 * @brief Decode one TOC entry, bounds-checked against the payload.
 *
 * Validates the entry's offset alignment and that [offset, offset+length) lies
 * within the payload before filling @p out, so out->bytes and out->length are
 * always in range and safe to hash, copy, or stage.
 *
 * Entries are addressed in STORED order, which the format does not require to
 * be sorted by offset.
 *
 * @param[in]  payload         Plaintext payload region.
 * @param[in]  payload_length  Length of @p payload.
 * @param[in]  index           Entry to decode. 0-based, below
 *                             oca_toc_info()'s image_count.
 * @param[out] out             Receives the decoded entry.
 * @retval OCA_OK                    Entry decoded.
 * @retval OCA_FAIL_INVALID_ARG      A NULL argument, or @p index at or beyond
 *                                   image_count.
 * @retval OCA_FAIL_PAYLOAD_TOC      Entry is structurally invalid.
 * @return Otherwise the span-bounding result, which also reports
 *         OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES when image_count exceeds this
 *         build's OCA_TOC_MAX_IMAGES.
 */
oca_result_t oca_toc_image_at(
    const uint8_t     *payload,
    size_t             payload_length,
    uint64_t           index,
    oca_image_info_t  *out);

/* ------------------------------------------------------------------ */
/* Device-state commit (post-verify; NOT part of oca_validate)        */
/* ------------------------------------------------------------------ */

/**
 * @brief Advance device secure-boot state after a SUCCESSFUL validation.
 *
 * A no-op returning OCA_OK when @p ctx records that secure boot is not in force.
 * Otherwise, unless the matching manifest_security_control disable bit is set, it
 * bitwise-ORs the manifest's public_key_classic_revoke into the device classic
 * revocation state (bit 1) and manifest_security_version into the device
 * security-version flags (bit 0), writing back via cb->set_*. The OR-in only
 * ever sets bits, never clears one, so state cannot be rolled backwards by a
 * commit.
 *
 * The library never calls this itself: validation is read-only and mutates no
 * device state, which is what lets a caller validate speculatively.
 *
 * @param[in] body  Whole variant body that has just validated.
 * @param[in] cb    Callback table; cb->set_root_key_revocation and
 *                  cb->set_security_version are required under secure boot, and
 *                  the secure-boot reporters are consulted again here to confirm
 *                  the recorded determination.
 * @param[in] ctx   The determination the validation of @p body recorded — pass
 *                  the same context, not a fresh one. Read, never written. NULL,
 *                  or a context no determination has settled, is refused rather
 *                  than treated as "not in force": this function burns fuses,
 *                  and guessing is not available to it.
 * @retval OCA_OK                            Committed, or secure boot not in
 *                                           force.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE     A needed callback is NULL.
 * @retval OCA_FAIL_SECURITY_STATE_UPDATE    A write-back failed.
 * @retval OCA_FAIL_SECURE_BOOT_UNDETERMINED  @p ctx holds no determination.
 * @retval OCA_FAIL_SECURE_BOOT_STATE_CHANGED The live determination no longer
 *                                           matches the recorded one. Nothing
 *                                           was written.
 * @return Otherwise the magic or variant failure from resolving @p body.
 *
 * @warning Call this ONLY after oca_validate() returned OCA_OK for @p body —
 *          authenticate before update. A failed commit does not retroactively
 *          invalidate the manifest.
 * @warning Determining afresh here instead of passing the validation's context
 *          is available and discouraged: it is a second determination, taken at
 *          a different moment from the one the validation was decided on, which
 *          is the disagreement the confirm mechanism exists to detect.
 */
oca_result_t oca_commit_security_state(
    const uint8_t *body,
    const oca_callbacks_t *cb,
    const oca_validation_context_t *ctx);

/* ------------------------------------------------------------------ */
/* Convenience wrapper                                                */
/* ------------------------------------------------------------------ */

/**
 * @brief Run every MANIFEST-level check in canonical order, without the payload.
 *
 * The first half of the staged boot flow: authenticate the manifest from a
 * body-sized buffer (4096 / 36864 B) with no payload resident, then use
 * oca_locate_payload() to find the payload in storage and
 * oca_check_payload_at() to verify it once copied. Because it stops before the
 * payload, @p body_length need only cover the variant body.
 *
 * oca_validate() is exactly this followed by oca_check_payload(), so the
 * canonical order lives in one place and the two entry points cannot drift.
 *
 * Cheapest first, so a manifest that cannot boot costs as little as possible to
 * reject. Ordering that matters and is easy to get wrong when composing by hand:
 *   - oca_check_manifest_hash() runs EARLY, right after
 *     oca_check_manifest_length() and before any field is decoded, so
 *     corruption is reported as corruption rather than as whichever field
 *     decodes wrong out of the damaged bytes;
 *   - oca_determine_secure_boot() runs ONCE, after the integrity and structural
 *     checks — its highest-priority input is a manifest bit, so it must not read
 *     one out of a body that failed its hash — and before every check that
 *     consumes the determination. Those checks each re-derive it and require the
 *     record to still match, so this establishes a reference rather than a
 *     verdict they inherit;
 *   - oca_check_payload_encryption_precondition() runs directly after the
 *     determination: it is the only gated check that spends no hardware read at
 *     all, so an encrypted payload on a non-secure part is rejected before any
 *     identity callback and long before a public-key operation;
 *   - the identity, lifecycle, and version-range checks run BEFORE the crypto
 *     block. They are cheap device reads against manifest constraints, and a
 *     manifest aimed at the wrong part is not worth a signature verification;
 *   - oca_check_root_key_revocation() runs BEFORE oca_check_signature(), so a
 *     revoked key is never exercised;
 *   - oca_check_security_version() runs BEFORE the signature as a cheap early
 *     reject, and again after it by default;
 *   - oca_check_payload_encryption_policy() runs LAST, because it reads what
 *     oca_check_signature() recorded.
 *
 * Each of those orderings is pinned by a test in test/unit_test.c that observes
 * callback invocation counts, not just result codes — an ordering claim a
 * return value alone cannot substantiate.
 *
 * @param[in]     body         Manifest body. See the length contract above.
 * @param[in]     body_length  Bytes available; need only cover the body.
 * @param[in]     cb           Callback table. May be NULL: each check reports
 *                             OCA_FAIL_CALLBACK_UNAVAILABLE for the callback IT
 *                             needs, which names the missing capability, and a
 *                             permissive manifest that constrains nothing needs
 *                             no callbacks at all.
 * @param[in,out] ctx          Caller-owned, so the staged flow can carry what
 *                             this established into a later
 *                             oca_check_payload_at() or
 *                             oca_commit_security_state(). Reset on entry, so a
 *                             forgotten oca_validation_context_init() cannot
 *                             carry a previous run's verdict into this one. NULL
 *                             declines the record, not the determination — an
 *                             internal context is used and every check runs
 *                             identically.
 * @retval OCA_OK                  Every manifest-level check passed.
 * @retval OCA_FAIL_INVALID_ARG    @p body was NULL.
 * @retval OCA_FAIL_TRUNCATED      @p body_length is short of the variant body.
 * @retval OCA_FAIL_SECURE_BOOT_STATE_CHANGED  A secure-boot reporter stopped
 *                                 agreeing with the determination made for this
 *                                 validation.
 * @return Otherwise the result of the first failing check, in the order listed
 *         above — the manifest-level codes from OCA_FAIL_MAGIC through
 *         OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT.
 */
oca_result_t oca_validate_manifest(
    const uint8_t *body,
    size_t         body_length,
    const oca_callbacks_t *cb,
    oca_validation_context_t *ctx);

/**
 * @brief Validate a whole bundle: every check, including the payload stage.
 *
 * The WHOLE-BUNDLE entry point. Composes every oca_check_* function in the
 * canonical order and stops on the first failure.
 *
 * Applies to manifests whose payload adjoins the body in one already-trusted
 * buffer — the bundle layout a host tool produces. It is one code path, not the
 * only legal arrangement: payload_offset lets a manifest place its payload
 * anywhere, and one that does is refused here with OCA_FAIL_PAYLOAD_LOCATION
 * rather than mis-validated. Booting from external storage, where the offset
 * has to be bounded before it is followed, wants the staged flow described at
 * the top of this header — oca_validate_manifest(), oca_locate_payload(),
 * oca_check_payload_at().
 *
 * @param[in] body         Manifest body with its payload immediately after it,
 *                         in one buffer.
 * @param[in] body_length  Total size of @p body.
 * @param[in] cb           Callback table.
 * @param[in,out] ctx      Optional. NULL uses an internal context and behaves
 *                         exactly as before this parameter existed. Supply one
 *                         when the caller intends to follow a successful
 *                         validation with oca_commit_security_state(), which
 *                         needs the determination this validation made — without
 *                         it the commit would have to determine afresh, at a
 *                         different moment from the decision it is committing.
 * @param[out] out_plaintext  Receives the validated plaintext location and
 *                            recovered length — where the payload's images are.
 *                            Written ONLY on OCA_OK, so a caller is never handed
 *                            a location the payload checks had not finished
 *                            verifying. NULL declines the report and changes no
 *                            verdict. Supplied for a cleartext payload as well
 *                            as an encrypted one, so finding the images does not
 *                            require asking which it was.
 * @retval OCA_OK  Every check passed; the bundle may be booted.
 * @return Otherwise the result of the first failing check — everything
 *         oca_validate_manifest() can return, followed by the payload-stage
 *         codes oca_check_payload() documents.
 */
oca_result_t oca_validate(
    const uint8_t *body,
    size_t         body_length,
    const oca_callbacks_t *cb,
    oca_validation_context_t *ctx,
    oca_payload_plaintext_t *out_plaintext);

#ifdef __cplusplus
}
#endif

#endif /* OCA_VALIDATOR_H */
