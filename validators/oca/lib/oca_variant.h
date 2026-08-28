/**
 * @file
 * @brief Internal per-variant layout descriptor.
 *
 * A single library handles every OCA manifest variant. Most fields sit at the
 * same offset in every variant (see oca_layout.h) and the checks that read
 * them need no variant knowledge. This descriptor captures the values that DO
 * differ between variants — magic, body size, the signed-region extent, the
 * trailer, and the variant-positioned signature_classic / manifest_hash
 * offsets — so the otherwise-shared framing and crypto checks can stay one
 * code path.
 *
 * The variant is resolved from the manifest's magic bytes at validation time;
 * integrators never select one at build time. The only build-time knob is the
 * optional OCA_SUPPORT_* gate, which compiles a variant out entirely (e.g., a
 * pre-PQC ROM that must never accept a PQC manifest).
 *
 * This is an internal header — it is not part of the public library API.
 */

#ifndef OCA_VARIANT_H
#define OCA_VARIANT_H

#include <stddef.h>
#include <stdint.h>

#include "oca_layout.h"
#include "oca_validator.h"   /* oca_result_t */

/* ------------------------------------------------------------------ */
/* Build-time variant gates                                           */
/* ------------------------------------------------------------------ */

/**
 * @brief Whether OCA-Classic manifests are honored by this build.
 *
 * On by default. A consumer that will only ever see one variant can compile
 * the other out with -DOCA_SUPPORT_CLASSIC=0; the resolver then reports
 * OCA_FAIL_UNSUPPORTED_VARIANT for the excluded magic instead of validating it.
 */
#ifndef OCA_SUPPORT_CLASSIC
#define OCA_SUPPORT_CLASSIC 1
#endif
/**
 * @brief Whether OCA-PQC manifests are honored by this build.
 *
 * On by default; -DOCA_SUPPORT_PQC=0 compiles the variant out on the same
 * terms as @c OCA_SUPPORT_CLASSIC.
 */
#ifndef OCA_SUPPORT_PQC
#define OCA_SUPPORT_PQC 1
#endif
#if !OCA_SUPPORT_CLASSIC && !OCA_SUPPORT_PQC
#error "at least one OCA variant must be compiled in"
#endif

/* ------------------------------------------------------------------ */
/* Variant descriptor                                                 */
/* ------------------------------------------------------------------ */

/**
 * @brief Everything that differs between OCA format variants.
 *
 * Most manifest fields sit at the same offset in every variant and the checks
 * that read them need no variant knowledge. This descriptor captures only the
 * values that DO differ, so the shared framing and crypto checks can stay one
 * code path rather than being duplicated per variant.
 */
typedef struct oca_variant {
    const char *name;                 /**< Diagnostic label, e.g. "OCA-PQC". */
    uint8_t     magic[OCA_MAGIC_LEN]; /**< Magic bytes identifying the variant. */
    size_t      body_size;            /**< Full manifest body size. */
    /** End of the region manifest_hash and the signature cover: [0, end). */
    size_t      signed_region_end;
    size_t      off_trailer;          /**< Offset of the trailer closing the signed region. */
    uint8_t     trailer_byte;         /**< Byte the trailer is filled with. */
    unsigned    trailer_len;          /**< Trailer length in bytes. */
    size_t      off_signature;        /**< signature_classic, OCA_LEN_SIGNATURE wide. */
    size_t      off_manifest_hash;    /**< manifest_hash, OCA_LEN_MANIFEST_HASH wide. */
    /** payload_offset: signed 64-bit little-endian, in the unsigned tail. */
    size_t      off_payload_offset;
    /** Size of the verifier-key entry appended after the body when
     *  use_verifier_key is set. Used only to bound the manifest's storage
     *  footprint (oca_manifest_region_len); this build does not verify the
     *  entry. */
    size_t      verifier_entry_size;
    /** Size of one co-signer entry appended after the body. Same bounding-only
     *  purpose as @c verifier_entry_size. */
    size_t      co_signer_entry_size;
    /** Offset of an optional fixed-fill region unique to a variant — PQC's
     *  0x35-filled classic-trailer slot. Meaningful only when @c fill_len is
     *  non-zero. */
    size_t      off_fill;
    uint8_t     fill_byte;            /**< Byte the fill region must contain. */
    /** Fill region length. Zero means the variant has no such region (Classic). */
    unsigned    fill_len;

    /** PQC crypto capability, and signature_pqc's field width when non-zero.
     *
     *  Zero means the variant carries no PQC crypto region — the same "region
     *  absent" convention @c fill_len uses, and the value every PQC-class
     *  check keys off rather than the magic bytes. The PQC field OFFSETS are
     *  deliberately not descriptor data: those fields exist in exactly one
     *  variant, so they are the fixed OCA_PQC_* constants in oca_layout_pqc.h,
     *  and this descriptor carries only what genuinely varies between
     *  variants. */
    size_t      len_pqc_signature;
} oca_variant_t;

/**
 * @brief Layout descriptor for the OCA-Classic variant.
 *
 * Always defined, even when @c OCA_SUPPORT_CLASSIC is 0, so the resolver can
 * match the magic regardless of the gates; the gate only decides whether a
 * match is honored or reported unsupported.
 */
extern const oca_variant_t OCA_VARIANT_CLASSIC;

/**
 * @brief Layout descriptor for the OCA-PQC variant.
 *
 * Always defined on the same terms as @c OCA_VARIANT_CLASSIC.
 */
extern const oca_variant_t OCA_VARIANT_PQC;

/**
 * @brief Resolve the variant descriptor for a manifest from its magic bytes.
 *
 * The single point at which a variant is selected. Every later check reads its
 * variant-specific offsets from the returned descriptor, so integrators never
 * pick a variant at build time — the manifest decides.
 *
 * Reports the outcome through @p status rather than the return value so
 * "unknown magic" and "known but compiled out" stay distinguishable; both
 * return NULL, but they call for different responses.
 *
 * @param[in]  body    Manifest body, at least OCA_MAGIC_LEN bytes readable.
 * @param[out] status  Receives OCA_OK, OCA_FAIL_UNSUPPORTED_VARIANT, or
 *                     OCA_FAIL_MAGIC.
 * @return The descriptor when the magic names a supported variant; NULL when it
 *         names a variant gated out of this build, or no known variant at all.
 */
const oca_variant_t *oca_variant_for_body(const uint8_t *body,
                                          oca_result_t *status);

#endif /* OCA_VARIANT_H */
