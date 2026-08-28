/**
 * @file
 * @brief Variant descriptors and magic-based resolver.
 */

#include "oca_variant.h"

#include "oca_layout_classic.h"
#include "oca_layout_pqc.h"

const oca_variant_t OCA_VARIANT_CLASSIC = {
    .name              = "OCA-Classic",
    .magic             = {'O', 'C', 'A', 'C'},
    .body_size         = OCA_CLASSIC_BODY_SIZE,
    .signed_region_end = OCA_CLASSIC_SIGNED_REGION_END,
    .off_trailer       = OCA_CLASSIC_OFF_TRAILER,
    .trailer_byte      = OCA_CLASSIC_TRAILER_BYTE,
    .trailer_len       = OCA_CLASSIC_TRAILER_LEN,
    .off_signature     = OCA_CLASSIC_OFF_SIGNATURE,
    .off_manifest_hash = OCA_CLASSIC_OFF_MANIFEST_HASH,
    .off_payload_offset   = OCA_CLASSIC_OFF_PAYLOAD_OFFSET,
    .verifier_entry_size  = OCA_CLASSIC_VERIFIER_ENTRY_SIZE,
    .co_signer_entry_size = OCA_CLASSIC_CO_SIGNER_ENTRY_SIZE,
    .off_fill          = 0,
    .fill_byte         = 0,
    .fill_len          = 0,
    /* No PQC crypto region: zero is the sentinel. */
    .len_pqc_signature = 0,
};

const oca_variant_t OCA_VARIANT_PQC = {
    .name              = "OCA-PQC",
    .magic             = {'O', 'C', 'A', 'P'},
    .body_size         = OCA_PQC_BODY_SIZE,
    .signed_region_end = OCA_PQC_SIGNED_REGION_END,
    .off_trailer       = OCA_PQC_OFF_TRAILER,
    .trailer_byte      = OCA_PQC_TRAILER_BYTE,
    .trailer_len       = OCA_PQC_TRAILER_LEN,
    .off_signature     = OCA_PQC_OFF_SIGNATURE,
    .off_manifest_hash = OCA_PQC_OFF_MANIFEST_HASH,
    .off_payload_offset   = OCA_PQC_OFF_PAYLOAD_OFFSET,
    .verifier_entry_size  = OCA_PQC_VERIFIER_ENTRY_SIZE,
    .co_signer_entry_size = OCA_PQC_CO_SIGNER_ENTRY_SIZE,
    /* PQC keeps the Classic-trailer slot, 0x35-filled. */
    .off_fill          = OCA_PQC_OFF_CLASSIC_TRAILER_SLOT,
    .fill_byte         = OCA_PQC_CLASSIC_TRAILER_SLOT_BYTE,
    .fill_len          = OCA_PQC_CLASSIC_TRAILER_SLOT_LEN,
    .len_pqc_signature = OCA_PQC_LEN_SIGNATURE_PQC,
};

/**
 * @brief Compare a manifest's magic bytes against a variant's expected magic.
 *
 * A plain byte loop rather than a constant-time compare: the magic is a public
 * format identifier, not a secret, and this runs before any variant has been
 * selected — there is nothing here an attacker learns from the timing that the
 * bytes themselves do not already tell them.
 *
 * @param[in] body   Manifest body, at least OCA_MAGIC_LEN bytes readable.
 * @param[in] magic  The variant's expected magic bytes.
 * @return true when every byte matches.
 */
static bool magic_matches(const uint8_t *body,
                          const uint8_t magic[OCA_MAGIC_LEN])
{
    for (unsigned i = 0; i < OCA_MAGIC_LEN; ++i) {
        if (body[OCA_OFF_MAGIC + i] != magic[i]) {
            return false;
        }
    }
    return true;
}

const oca_variant_t *oca_variant_for_body(const uint8_t *body,
                                          oca_result_t *status)
{
    if (magic_matches(body, OCA_VARIANT_CLASSIC.magic)) {
#if OCA_SUPPORT_CLASSIC
        *status = OCA_OK;
        return &OCA_VARIANT_CLASSIC;
#else
        *status = OCA_FAIL_UNSUPPORTED_VARIANT;
        return 0;
#endif
    }
    if (magic_matches(body, OCA_VARIANT_PQC.magic)) {
#if OCA_SUPPORT_PQC
        *status = OCA_OK;
        return &OCA_VARIANT_PQC;
#else
        *status = OCA_FAIL_UNSUPPORTED_VARIANT;
        return 0;
#endif
    }
    *status = OCA_FAIL_MAGIC;
    return 0;
}
