/**
 * @file
 * @brief Payload validation stage.
 *
 * Runs for every manifest that declares a payload, encrypted or not.
 *
 * Encrypted payloads enforce authenticate-then-decrypt: verify payload_hash
 * over the stored ciphertext BEFORE any decryption, derive + decrypt through
 * the host callback, then validate the recovered plaintext. Cleartext payloads
 * verify payload_hash over the TOC region and validate the payload in place.
 * The library holds no cipher or KDF code — decryption is the caller's
 * decrypt_payload callback.
 *
 * Both paths converge on check_plaintext_payload() which performs:
 *     - TOC structural validation
 *     - a pass over all images that recomputes and checks each TOC 
 *       entry's stored `hash` against the image bytes it describes, hashing
 *       every image exactly once and iteratively computing chain of payload 
 *       hashes 
 *     - final confirmation of the payload_hash_chain integrity once
 *       all images have been hashed and verified
 */

#include "oca_validator.h"

#include "oca_compare.h"
#include "oca_layout.h"
#include "oca_variant.h"
#include "parser.h"
#include "secure_boot.h"

/**
 * @brief Record where the validated plaintext is, if the caller asked.
 *
 * Called from exactly one place on each payload path: immediately after the last
 * plaintext check returned OCA_OK. Keeping it to that position is what makes the
 * report's guarantee hold — a caller is never handed a location the library had
 * not finished checking.
 *
 * @param[out] out  Destination, or NULL when the caller declined the report.
 *                  NULL is a supported configuration and changes no verdict.
 * @param[in]  pt   First byte of the validated plaintext payload region.
 * @param[in]  len  Bytes readable at @p pt.
 */
static void report_plaintext(oca_payload_plaintext_t *out,
                             const uint8_t *pt, size_t len)
{
    if (out == 0) {
        return;
    }
    out->bytes = pt;
    out->len   = len;
}

/**
 * @brief Read image_count and bound the TOC span it implies.
 *
 * Enforces image_count > 0 and that TOC_Header_Size + image_count *
 * TOC_Entry_Size neither overflows nor exceeds @p pt_len. The bound is written
 * as a division precisely so the multiplication can never overflow while
 * checking it.
 *
 * Every read of image_count in this file goes through here. That is the point:
 * an unauthenticated TOC header must never yield an unchecked span, and a
 * single choke point is the only way to be sure none was missed.
 *
 * @param[in]  pt               Plaintext payload region.
 * @param[in]  pt_len           Length of @p pt.
 * @param[out] out_image_count  Receives the validated entry count.
 * @param[out] out_toc_bytes    Receives the TOC span in bytes.
 * @retval OCA_OK                             Count and span are safe to use.
 * @retval OCA_FAIL_PAYLOAD_TOC               Header does not fit, count is
 *                                            zero, or the span overflows or
 *                                            exceeds the payload.
 * @retval OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES   Count exceeds OCA_TOC_MAX_IMAGES.
 */
static oca_result_t read_toc_span(const uint8_t *pt, size_t pt_len,
                                  uint64_t *out_image_count, size_t *out_toc_bytes)
{
    if (pt_len < OCA_TOC_HEADER_SIZE) {
        return OCA_FAIL_PAYLOAD_TOC;
    }
    uint64_t image_count = oca_le_u64(pt + OCA_TOC_OFF_IMAGE_COUNT);
    if (image_count == 0u
        || image_count > (pt_len - OCA_TOC_HEADER_SIZE) / OCA_TOC_ENTRY_SIZE) {
        return OCA_FAIL_PAYLOAD_TOC;
    }
    /* Cap the count before anything iterates over it. The structural bound above
     * only requires the TOC to fit the payload, which grows with the input, while
     * validate_toc_structure()'s overlap check is O(image_count^2) — so an 8 MiB
     * payload buys 4.6e8 pair comparisons, reachable pre-authentication when
     * secure boot is off. Enforced here because this is the one chokepoint every
     * TOC reader shares: check_cleartext_payload, oca_toc_info, and
     * oca_toc_image_at all arrive through it. */
    if (image_count > OCA_TOC_MAX_IMAGES) {
        return OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES;
    }
    *out_image_count = image_count;
    *out_toc_bytes = OCA_TOC_HEADER_SIZE + (size_t)image_count * OCA_TOC_ENTRY_SIZE;
    return OCA_OK;
}

/**
 * @brief Structurally validate the plaintext TOC before anything trusts it.
 *
 * Enforces the payload structural-validation requirements the library can check
 * on the payload it holds:
 *   - image_count > 0, and TOC_Header_Size + image_count * TOC_Entry_Size
 *     neither overflows nor exceeds the plaintext payload length;
 *   - every entry's offset is a multiple of 8;
 *   - every entry's [offset, offset+length) is in-bounds and does not overflow;
 *   - no two entries' image ranges overlap.
 *
 * Overlap is checked pairwise against every earlier entry so the result does
 * not depend on entry order — the format does not permit assuming entries are
 * sorted by offset. The library is freestanding with no heap, so this is an
 * O(image_count^2) scan over the in-buffer entries rather than a sort, which is
 * fine for the small image counts a boot payload carries and is why
 * read_toc_span() caps the count before anything iterates.
 *
 * @param[in]  pt               Plaintext payload region.
 * @param[in]  pt_len           Length of @p pt.
 * @param[out] out_image_count  Receives the validated entry count.
 * @param[out] out_toc_bytes    Receives the TOC span in bytes.
 * @retval OCA_OK                             TOC is structurally sound.
 * @retval OCA_FAIL_PAYLOAD_TOC               Any structural violation above.
 *                                            Distinct from
 *                                            OCA_FAIL_PAYLOAD_HASH_CHAIN, which
 *                                            is a cryptographic mismatch over a
 *                                            structurally-valid TOC.
 * @retval OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES   Count exceeds OCA_TOC_MAX_IMAGES.
 * @return Otherwise the result of bounding the TOC span.
 */
static oca_result_t validate_toc_structure(
    const uint8_t *pt, size_t pt_len,
    uint64_t *out_image_count, size_t *out_toc_bytes)
{
    uint64_t image_count = 0u;
    size_t toc_bytes = 0u;
    oca_result_t sr = read_toc_span(pt, pt_len, &image_count, &toc_bytes);
    if (sr != OCA_OK) {
        return sr;
    }

    for (uint64_t i = 0u; i < image_count; ++i) {
        const uint8_t *entry_i = pt + OCA_TOC_HEADER_SIZE + (size_t)i * OCA_TOC_ENTRY_SIZE;
        uint64_t off_i = oca_le_u64(entry_i + OCA_TOC_ENTRY_OFF_OFFSET);
        uint64_t len_i = oca_le_u64(entry_i + OCA_TOC_ENTRY_OFF_LENGTH);

        if ((off_i % 8u) != 0u) {                       /* offset multiple of 8 */
            return OCA_FAIL_PAYLOAD_TOC;
        }
        if (off_i > pt_len || len_i > pt_len - off_i) { /* in-bounds, no overflow */
            return OCA_FAIL_PAYLOAD_TOC;
        }
        /* Disjoint from every earlier entry. Both sums are <= pt_len (each entry
         * passed the bound above), so neither addition overflows. Zero-length
         * ranges are empty and therefore never overlap. */
        for (uint64_t j = 0u; j < i; ++j) {
            const uint8_t *entry_j = pt + OCA_TOC_HEADER_SIZE + (size_t)j * OCA_TOC_ENTRY_SIZE;
            uint64_t off_j = oca_le_u64(entry_j + OCA_TOC_ENTRY_OFF_OFFSET);
            uint64_t len_j = oca_le_u64(entry_j + OCA_TOC_ENTRY_OFF_LENGTH);
            if (off_i < off_j + len_j && off_j < off_i + len_i) {
                return OCA_FAIL_PAYLOAD_TOC;
            }
        }
    }

    *out_image_count = image_count;
    *out_toc_bytes = toc_bytes;
    return OCA_OK;
}

/**
 * @brief Compare a recomputed digest against a stored 64-byte hash field.
 *
 * Runs in time independent of the contents, via the primitives in
 * oca_compare.h. The trailing bytes of the field are padding whose width
 * depends on the configured digest type; this pass compares only the leading
 * digest bytes and does not interpret the remainder.
 *
 * @param[in] field        The stored 64-byte hash field.
 * @param[in] digest       The recomputed digest.
 * @param[in] on_mismatch  Result code to return when they differ, so one
 *                         comparison serves the manifest, payload, chain, and
 *                         per-entry checks while each still reports its own
 *                         failure.
 * @retval OCA_OK  Digest matches.
 * @return @p on_mismatch when it does not.
 */
static oca_result_t compare_digest(const uint8_t *field,
                                   const uint8_t digest[OCA_MANIFEST_HASH_DIGEST_SIZE],
                                   oca_result_t on_mismatch)
{
    return oca_ct_diff(field, digest, OCA_MANIFEST_HASH_DIGEST_SIZE) != 0
        ? on_mismatch : OCA_OK;
}

/**
 * @brief Recompute payload_hash_chain and verify every TOC entry's stored
 *        hash, hashing each image exactly once.
 *
 * Mirrors the producer exactly:
 *
 *     chain = H(TOC header + all entries)
 *     for each TOC entry (stored order): chain = H(chain || H(image bytes))
 *
 * Entries are chained in the order they are STORED, not in offset order. The
 * format permits unsorted entries and the producer chains in emission order, so
 * sorting here would compute a different chain for a legal manifest.
 *
 * The H(image bytes) the chain folds in is byte-identical to the digest each
 * entry's stored hash must match — the per-image check a Consumer owes before
 * loading, executing, or handing off an image — so one digest serves both
 * checks. The checks themselves are not redundant with each other: the chain
 * proves the payload is the one the manifest signed but hashes the stored
 * hash field as ordinary TOC data, so an entry whose hash simply does not
 * describe its image passes the chain and fails the per-entry comparison.
 *
 * Verdict order is load-bearing. Entry comparisons run inside the loop, but
 * the first failure is withheld until the chain verdict is in: a chain
 * mismatch is reported over any entry-hash mismatch, so an entry-hash
 * failure is only ever reported against payload bytes already tied to the
 * signed manifest.
 *
 * The digest occupies the leading OCA_MANIFEST_HASH_DIGEST_SIZE bytes of the
 * 64-byte entry hash field; the remainder is padding this pass does not
 * interpret. The TOC is structurally validated before this runs, so the
 * offset and length reads are already known to be in bounds.
 *
 * @param[in] pt           Plaintext payload region.
 * @param[in] image_count  Validated entry count.
 * @param[in] toc_bytes    Validated TOC span in bytes.
 * @param[in] body         Manifest body holding the expected chain value.
 * @param[in] cb           Callback table; cb->sha256 is required.
 * @retval OCA_OK                          Chain and every entry hash match.
 * @retval OCA_FAIL_PAYLOAD_HASH_CHAIN     Chain mismatch.
 * @retval OCA_FAIL_PAYLOAD_ENTRY_HASH     The chain matches, but an entry's
 *                                         hash does not describe its image
 *                                         bytes.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   cb->sha256 failed or is unavailable.
 * @return Otherwise the digest-comparison result for the chain or the first
 *         failing entry.
 */
static oca_result_t check_payload_hash_chain_and_entries(
    const uint8_t *pt, uint64_t image_count, size_t toc_bytes,
    const uint8_t *body, const oca_callbacks_t *cb)
{
    uint8_t chain[OCA_MANIFEST_HASH_DIGEST_SIZE];
    if (cb->sha256(pt, toc_bytes, chain) != OCA_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    oca_result_t entry_verdict = OCA_OK;
    for (uint64_t i = 0u; i < image_count; ++i) {
        const uint8_t *entry = pt + OCA_TOC_HEADER_SIZE + (size_t)i * OCA_TOC_ENTRY_SIZE;
        uint64_t off = oca_le_u64(entry + OCA_TOC_ENTRY_OFF_OFFSET);
        uint64_t len = oca_le_u64(entry + OCA_TOC_ENTRY_OFF_LENGTH);
        uint8_t img_hash[OCA_MANIFEST_HASH_DIGEST_SIZE];
        if (cb->sha256(pt + off, (size_t)len, img_hash) != OCA_OK) {
            return OCA_FAIL_CALLBACK_UNAVAILABLE;
        }
        if (entry_verdict == OCA_OK) {
            entry_verdict = compare_digest(entry + OCA_TOC_ENTRY_OFF_HASH,
                                           img_hash,
                                           OCA_FAIL_PAYLOAD_ENTRY_HASH);
        }
        uint8_t buf[2 * OCA_MANIFEST_HASH_DIGEST_SIZE];
        for (unsigned k = 0u; k < OCA_MANIFEST_HASH_DIGEST_SIZE; ++k) {
            buf[k] = chain[k];
            buf[OCA_MANIFEST_HASH_DIGEST_SIZE + k] = img_hash[k];
        }
        if (cb->sha256(buf, sizeof buf, chain) != OCA_OK) {
            return OCA_FAIL_CALLBACK_UNAVAILABLE;
        }
    }

    oca_result_t r = compare_digest(body + OCA_OFF_PAYLOAD_HASH_CHAIN, chain,
                                    OCA_FAIL_PAYLOAD_HASH_CHAIN);
    return r != OCA_OK ? r : entry_verdict;
}

/**
 * @brief The plaintext checks the cleartext and encrypted paths both run.
 *
 * Structural validation, then the chain and the per-entry image hashes in a
 * single pass over the payload.
 *
 * The order is load-bearing. Structural validation runs FIRST so every
 * subsequent offset read is in bounds, and the hash pass reports an
 * entry-hash failure only once the chain has tied the payload bytes to the
 * signed manifest.
 *
 * @param[in] pt      Plaintext payload region.
 * @param[in] pt_len  Length of @p pt.
 * @param[in] body    Manifest body holding the expected digests.
 * @param[in] cb      Callback table; cb->sha256 is required.
 * @retval OCA_OK  Every plaintext check passed.
 * @return Otherwise the first failing check's result — the structural,
 *         chain, and per-entry codes documented on the two functions it
 *         composes.
 */
static oca_result_t check_plaintext_payload(
    const uint8_t *pt, size_t pt_len,
    const uint8_t *body, const oca_callbacks_t *cb)
{
    uint64_t image_count = 0u;
    size_t toc_bytes = 0u;
    oca_result_t r = validate_toc_structure(pt, pt_len, &image_count, &toc_bytes);
    if (r != OCA_OK) {
        return r;
    }
    return check_payload_hash_chain_and_entries(pt, image_count, toc_bytes,
                                                body, cb);
}

/**
 * @brief Validate a cleartext payload, where the stored bytes are the plaintext.
 *
 * payload_hash covers the TOC region only, and payload_hashed_length records
 * that region's length — the format requires it to equal TOC_Header_Size +
 * image_count * TOC_Entry_Size, which is confirmed once the TOC has been
 * structurally validated.
 *
 * @param[in] payload      Stored payload region, which is already plaintext.
 * @param[in] payload_len  Length of @p payload.
 * @param[in] body         Manifest body holding the expected digests.
 * @param[in] cb           Callback table; cb->sha256 is required.
 * @param[out] out_plaintext  Receives the plaintext location and length, only
 *                            when every plaintext check passed. NULL declines.
 * @retval OCA_OK                          Payload validated.
 * @retval OCA_FAIL_PAYLOAD_TOC            payload_hashed_length is zero,
 *                                         exceeds the payload, or does not
 *                                         describe exactly the TOC region.
 * @retval OCA_FAIL_PAYLOAD_HASH           payload_hash mismatch over the TOC region.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   cb->sha256 failed or is unavailable.
 * @return Otherwise the result of the shared plaintext checks.
 */
static oca_result_t check_cleartext_payload(const uint8_t *payload, size_t payload_len,
                                            const uint8_t *body, const oca_callbacks_t *cb,
                                            oca_payload_plaintext_t *out_plaintext)
{
    uint64_t hashed_len = oca_le_u64(body + OCA_OFF_PAYLOAD_HASHED_LENGTH);
    if (hashed_len == 0u || hashed_len > payload_len) {
        return OCA_FAIL_PAYLOAD_TOC;
    }

    uint8_t digest[OCA_MANIFEST_HASH_DIGEST_SIZE];
    if (cb->sha256(payload, (size_t)hashed_len, digest) != OCA_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    oca_result_t r = compare_digest(body + OCA_OFF_PAYLOAD_HASH, digest,
                                    OCA_FAIL_PAYLOAD_HASH);
    if (r != OCA_OK) {
        return r;
    }

    /* payload_hashed_length must describe exactly the TOC region. The full
     * structural pass inside check_plaintext_payload re-derives the span and
     * additionally validates every entry. */
    uint64_t image_count = 0u;
    size_t toc_bytes = 0u;
    r = read_toc_span(payload, payload_len, &image_count, &toc_bytes);
    if (r != OCA_OK) {
        return r;
    }
    if (hashed_len != toc_bytes) {
        return OCA_FAIL_PAYLOAD_TOC;
    }

    /* The TOC's own payload_length must agree with the manifest's. */
    if (oca_le_u64(payload + OCA_TOC_OFF_PAYLOAD_LENGTH) != (uint64_t)payload_len) {
        return OCA_FAIL_PAYLOAD_TOC;
    }

    oca_result_t final = check_plaintext_payload(payload, payload_len, body, cb);
    if (final == OCA_OK) {
        report_plaintext(out_plaintext, payload, payload_len);
    }
    return final;
}

/**
 * @brief Validate an encrypted payload: authenticate, decrypt, then validate.
 *
 * Enforces authenticate-then-decrypt. payload_hash is verified over the STORED
 * CIPHERTEXT before cb->decrypt_payload is ever called, so the decryption
 * routine is never handed unauthenticated bytes. payload_hashed_length is the
 * full ciphertext length here, unlike the cleartext path where it covers only
 * the TOC region.
 *
 * The recovered plaintext then runs the same checks a cleartext payload does.
 *
 * @param[in] ciphertext  Stored ciphertext region.
 * @param[in] available   Bytes readable at @p ciphertext.
 * @param[in] body        Manifest body holding the digests, IV, and KDF input.
 * @param[in] cb          Callback table; cb->sha256 and cb->decrypt_payload are
 *                        both required.
 * @param[out] out_plaintext  Receives the RECOVERED plaintext location and
 *                            length — the address the callback chose, which is
 *                            not recomputable afterwards, so this is the only
 *                            place it can be captured. Written only when every
 *                            plaintext check passed. NULL declines.
 * @retval OCA_OK                          Payload decrypted and validated.
 * @retval OCA_FAIL_TRUNCATED              Declared ciphertext exceeds @p available.
 * @retval OCA_FAIL_PAYLOAD_TOC            payload_hashed_length is unusable.
 * @retval OCA_FAIL_PAYLOAD_HASH           Ciphertext hash mismatch, detected
 *                                         BEFORE any decryption.
 * @retval OCA_FAIL_DECRYPT                Derivation, cipher, or padding failure.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE   A required callback is unavailable.
 * @return Otherwise the result of the shared plaintext checks.
 */
static oca_result_t check_encrypted_payload(const uint8_t *ciphertext, size_t available,
                                            const uint8_t *body, const oca_callbacks_t *cb,
                                            oca_payload_plaintext_t *out_plaintext)
{
    uint64_t cipher_len = oca_le_u64(body + OCA_OFF_PAYLOAD_HASHED_LENGTH);
    if (cipher_len == 0u || cipher_len > available) {
        return OCA_FAIL_TRUNCATED;
    }

    /* For an encrypted payload the two manifest lengths describe the same
     * stored ciphertext, so they must agree exactly — payload_length includes
     * the encryption overhead. Without this, payload_length is never read at all
     * on the encrypted path, and a manifest could describe a payload footprint
     * unrelated to the bytes actually authenticated and decrypted. The floor
     * keeps a declared payload too small to hold even a single-image TOC from
     * reaching the cipher. */
    if (cipher_len != oca_le_u64(body + OCA_OFF_PAYLOAD_LENGTH)
        || cipher_len < (uint64_t)(OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE)) {
        return OCA_FAIL_PAYLOAD_TOC;
    }

    /* 1. Verify payload_hash over the ciphertext BEFORE any decryption. */
    uint8_t digest[OCA_MANIFEST_HASH_DIGEST_SIZE];
    if (cb->sha256(ciphertext, (size_t)cipher_len, digest) != OCA_OK) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    oca_result_t r = compare_digest(body + OCA_OFF_PAYLOAD_HASH, digest,
                                    OCA_FAIL_PAYLOAD_HASH);
    if (r != OCA_OK) {
        return r;
    }

    /* Only plain AES-CBC ciphers (AES-128-CBC / AES-256-CBC) are implemented;
     * reject any other encryption_type (CBC-HMAC composite, AEAD, unknown)
     * before touching the ciphertext. */
    uint8_t enc_type = body[OCA_OFF_ENCRYPTION_TYPE];
    if (enc_type != OCA_ENCRYPTION_TYPE_AES_128_CBC &&
        enc_type != OCA_ENCRYPTION_TYPE_AES_256_CBC) {
        return OCA_FAIL_DECRYPT;
    }

    /* 2. Derive + decrypt via the host callback — only now, on authenticated
     * ciphertext. AES block-cipher modes such as CBC require the ciphertext to
     * be a whole number of 16-byte blocks; enforce that here (a shared
     * invariant for block-based modes) rather than in any one crypto backend.
     * Stream modes (CTR / GCM / GCM-SIV) operate on arbitrary lengths and would
     * not gate on this — a future mode would apply it per encryption_type. */
    if ((cipher_len % OCA_AES_BLOCK_SIZE) != 0u) {
        return OCA_FAIL_DECRYPT;
    }
    if (cb->decrypt_payload == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    const uint8_t *plaintext = 0;
    size_t plaintext_len = 0u;
    /* Every value the callback reads, gathered from fields this function has
     * already decoded. enc_type is known good here — the check above rejected
     * anything outside the implemented ciphers, so the callback cannot be handed
     * a cipher it has no case for. */
    oca_decrypt_input_t in;
    in.ciphertext     = ciphertext;
    in.ciphertext_len = (size_t)cipher_len;
    in.iv             = body + OCA_OFF_ENCRYPTION_IV;
    in.kdf_input      = body + OCA_OFF_ENCRYPTION_KDF_INPUT;
    in.cipher         = (oca_encryption_type_t)enc_type;
    in.secret_select  = oca_le_u16(body + OCA_OFF_ENCRYPTION_SHARED_SECRET_SELECT);
    r = cb->decrypt_payload(&in, &plaintext, &plaintext_len);
    /* Codes that name a specific cause pass through by name; everything else
     * collapses to OCA_FAIL_DECRYPT. Anything a caller must be able to tell
     * apart therefore has to be listed here — a code added to the enum but not
     * to this list reads correctly in the header and is swallowed in the field,
     * which is the failure this list exists to prevent. */
    if (r == OCA_FAIL_CALLBACK_UNAVAILABLE ||
        r == OCA_FAIL_NO_PROVISIONED_SECRET) {
        return r;
    }
    if (r != OCA_OK || plaintext == 0) {
        return OCA_FAIL_DECRYPT;
    }

    /* 3. Validate the recovered plaintext, and report where it is only if every
     * check over it passed. The plaintext address is the callback's choice and is
     * not re-computable afterwards, so this is the one place it can be captured. */
    r = check_plaintext_payload(plaintext, plaintext_len, body, cb);
    if (r == OCA_OK) {
        report_plaintext(out_plaintext, plaintext, plaintext_len);
    }
    return r;
}

/**
 * @brief Read whether the payload is encrypted, and how long the stored bytes are.
 *
 * Shared by every entry point so they cannot disagree about how a payload is
 * sized — the encrypted and cleartext paths take the span from different
 * manifest fields, and one function reading both is what keeps them consistent.
 *
 * @param[in]  body           Manifest body.
 * @param[out] out_encrypted  Receives the payload_encryption_control bit.
 * @param[out] out_span       Receives the stored span: payload_hashed_length
 *                            when encrypted (the ciphertext length),
 *                            payload_length otherwise.
 */
static void read_payload_shape(const uint8_t *body, bool *out_encrypted,
                               uint64_t *out_span)
{
    uint16_t enc_control = oca_le_u16(body + OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL);
    bool encrypted = (enc_control & OCA_ENCRYPTION_ENCRYPTED_PAYLOAD_BIT) != 0u;
    *out_encrypted = encrypted;
    *out_span = encrypted
        ? oca_le_u64(body + OCA_OFF_PAYLOAD_HASHED_LENGTH)
        : oca_le_u64(body + OCA_OFF_PAYLOAD_LENGTH);
}

oca_result_t oca_check_payload_at(const uint8_t *body,
                                  const uint8_t *payload, size_t payload_len,
                                  const oca_callbacks_t *cb,
                                  const oca_validation_context_t *ctx,
                                  oca_payload_plaintext_t *out_plaintext)
{
    if (body == 0) {
        return OCA_FAIL_INVALID_ARG;
    }
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }

    bool encrypted;
    uint64_t declared_span;
    read_payload_shape(body, &encrypted, &declared_span);

    /* A cleartext manifest that declares no payload has nothing to check. */
    if (!encrypted && declared_span == 0u) {
        return OCA_OK;
    }

    /* Second check for secure boot must completed for payload encryption to be valid
     * enforcement point, deliberately redundant with the one composed
     * into oca_validate_manifest(). A consumer may call this function having
     * composed no manifest checks at all, so a gate that exists only in the
     * composed order would be one the integrator can skip by accident. */
    status = oca_check_payload_encryption_policy(body, cb, ctx);
    if (status != OCA_OK) {
        return status;
    }

    if (payload == 0) {
        return OCA_FAIL_INVALID_ARG;
    }
    if (cb == 0 || cb->sha256 == 0) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    if (declared_span > payload_len) {
        return OCA_FAIL_TRUNCATED;
    }

    if (encrypted) {
        return check_encrypted_payload(payload, payload_len, body, cb, out_plaintext);
    }
    return check_cleartext_payload(payload, (size_t)declared_span, body, cb,
                                   out_plaintext);
}

oca_result_t oca_check_payload(const uint8_t *body, size_t body_length,
                               const oca_callbacks_t *cb,
                               const oca_validation_context_t *ctx,
                               oca_payload_plaintext_t *out_plaintext)
{
    if (body == 0) {
        return OCA_FAIL_INVALID_ARG;
    }

    /* Bound the buffer BEFORE reading any field, and before the magic read
     * inside oca_variant_for_body(). The manifest fields consulted below live as
     * far out as offset 2940, so a caller that passes a shorter buffer must be
     * turned away here rather than after the reads.
     *
     * oca_validate() already runs both of these checks before it gets here, so
     * this costs the composed path nothing. It matters because this function is
     * part of the documented composable API (see oca_validator.h) and takes a
     * length, which invites being called on its own — and a short buffer read
     * out of bounds rather than returning TRUNCATED. */
    oca_result_t r = oca_check_length(body_length);
    if (r != OCA_OK) {
        return r;
    }
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    if (body_length < v->body_size) {
        return OCA_FAIL_TRUNCATED;
    }

    /* The manifest states where its payload lives, and if that is not directly after 
     * the body then this entry point cannot be correct for this manifest. 
     *
     * A caller whose payload genuinely lives elsewhere resolves it with
     * oca_locate_payload() (which needs storage bounds this entry point does not
     * have) and verifies it with oca_check_payload_at().
     *
     * Skipped when no payload is declared: the question is then moot, and
     * oca_check_payload_at() returns OCA_OK for that case anyway. */
    bool encrypted;
    uint64_t declared_span;
    read_payload_shape(body, &encrypted, &declared_span);
    if (encrypted || declared_span != 0u) {
        int64_t declared_offset =
            (int64_t)oca_le_u64(body + v->off_payload_offset);
        if (declared_offset != (int64_t)v->body_size) {
            return OCA_FAIL_PAYLOAD_LOCATION;
        }
    }

    /* The subtraction cannot underflow — body_length >= body_size, checked above. */
    return oca_check_payload_at(body, body + v->body_size,
                                body_length - v->body_size, cb, ctx,
                                out_plaintext);
}

/* ------------------------------------------------------------------ */
/* Resolving payload_offset in storage                                */
/* ------------------------------------------------------------------ */

oca_result_t oca_manifest_region_len(const uint8_t *body, size_t *out_len)
{
    if (body == 0 || out_len == 0) {
        return OCA_FAIL_INVALID_ARG;
    }
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }

    size_t len = v->body_size;
    if ((body[OCA_OFF_VERIFIER_KEY_CONTROL]
         & OCA_VERIFIER_KEY_CONTROL_USE_BIT) != 0u) {
        len += v->verifier_entry_size;
    }
    /* One appended entry per set co_signer_enable bit, capped by the field's
     * width. Counted rather than assumed so the bound stays right when
     * co-signer verification lands. */
    uint16_t co_signer = oca_le_u16(body + OCA_OFF_CO_SIGNER_CONTROL);
    unsigned enabled = 0u;
    for (unsigned bit = 0u; bit < OCA_CO_SIGNER_MAX; ++bit) {
        if ((co_signer & (uint16_t)(1u << bit)) != 0u) {
            enabled++;
        }
    }
    len += (size_t)enabled * v->co_signer_entry_size;
    *out_len = len;
    return OCA_OK;
}

/**
 * @brief Test whether two half-open address ranges share any byte.
 *
 * Half-open, so ranges that merely touch — one ending exactly where the next
 * begins — do not count as overlapping. That is what lets a payload sit
 * immediately after the manifest region without being rejected as colliding
 * with it.
 *
 * @param[in] a_start  First range's inclusive start.
 * @param[in] a_end    First range's exclusive end.
 * @param[in] b_start  Second range's inclusive start.
 * @param[in] b_end    Second range's exclusive end.
 * @return true when the ranges share at least one byte.
 */
static bool ranges_intersect(int64_t a_start, int64_t a_end,
                             int64_t b_start, int64_t b_end)
{
    return a_start < b_end && b_start < a_end;
}

oca_result_t oca_locate_payload(const uint8_t *body,
                                const oca_storage_bounds_t *bounds,
                                int64_t *out_addr,
                                size_t  *out_span)
{
    if (body == 0 || bounds == 0 || out_addr == 0 || out_span == 0) {
        return OCA_FAIL_INVALID_ARG;
    }
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    /* An inverted or empty permitted region is a caller error, not a bad
     * manifest — say so rather than blaming the payload. */
    if (bounds->region_limit <= bounds->region_base) {
        return OCA_FAIL_INVALID_ARG;
    }
    if (bounds->manifest_addr < bounds->region_base
        || bounds->manifest_addr >= bounds->region_limit) {
        return OCA_FAIL_INVALID_ARG;
    }

    bool encrypted;
    uint64_t declared_span;
    read_payload_shape(body, &encrypted, &declared_span);
    if (!encrypted && declared_span == 0u) {
        /* No payload declared: nothing to locate. */
        *out_addr = 0;
        *out_span = 0u;
        return OCA_OK;
    }
    if (declared_span == 0u) {
        return OCA_FAIL_PAYLOAD_LOCATION;   /* encrypted but zero-length */
    }
    /* The span must survive as a signed quantity for the range arithmetic
     * below, and as a size_t for the caller's copy. */
    if (declared_span > (uint64_t)INT64_MAX) {
        return OCA_FAIL_PAYLOAD_LOCATION;
    }
    int64_t span = (int64_t)declared_span;

    /* payload_offset is a SIGNED i64 read from the unsigned tail — untrusted.
     * Every arithmetic step below is overflow-checked before it is performed;
     * signed overflow is undefined behaviour, so it cannot be detected after
     * the fact. */
    int64_t offset = (int64_t)oca_le_u64(body + v->off_payload_offset);
    int64_t base = bounds->manifest_addr;

    if (offset > 0 && base > INT64_MAX - offset) {
        return OCA_FAIL_PAYLOAD_LOCATION;   /* addr would overflow */
    }
    if (offset < 0 && base < INT64_MIN - offset) {
        return OCA_FAIL_PAYLOAD_LOCATION;   /* addr would underflow */
    }
    int64_t addr = base + offset;

    if (addr > INT64_MAX - span) {
        return OCA_FAIL_PAYLOAD_LOCATION;   /* addr + span would overflow */
    }
    int64_t addr_end = addr + span;

    /* Inside the caller's permitted region, in full. */
    if (addr < bounds->region_base || addr_end > bounds->region_limit) {
        return OCA_FAIL_PAYLOAD_LOCATION;
    }

    /* Disjoint from the manifest and its appended entries. A negative offset
     * can land legally inside the region and still run forward into the
     * manifest, which a bounds-only test would accept. */
    size_t region_len = 0u;
    oca_result_t region_status = oca_manifest_region_len(body, &region_len);
    if (region_status != OCA_OK) {
        return region_status;
    }
    if (region_len > (size_t)INT64_MAX) {
        return OCA_FAIL_PAYLOAD_LOCATION;
    }
    if (base > INT64_MAX - (int64_t)region_len) {
        return OCA_FAIL_PAYLOAD_LOCATION;
    }
    if (ranges_intersect(addr, addr_end, base, base + (int64_t)region_len)) {
        return OCA_FAIL_PAYLOAD_LOCATION;
    }

    *out_addr = addr;
    *out_span = (size_t)span;
    return OCA_OK;
}

/* Manifest-only, so it works in the staged flow where no payload is resident
 * and oca_payload_region() cannot be used. Reads the same encryption_control
 * bit as read_payload_shape() above, plus the two fields a Consumer needs to
 * wire decrypt_payload before validation runs. */
oca_result_t oca_payload_encryption_info(const uint8_t *body,
                                         oca_payload_encryption_t *out)
{
    if (body == 0 || out == 0) {
        return OCA_FAIL_INVALID_ARG;
    }
    oca_result_t status;
    if (oca_variant_for_body(body, &status) == 0) {
        return status;
    }

    uint16_t control = oca_le_u16(body + OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL);
    out->encrypted = (control & OCA_ENCRYPTION_ENCRYPTED_PAYLOAD_BIT) != 0u;
    if (!out->encrypted) {
        /* A cleartext manifest leaves these zero; report that rather than
         * whatever the fields happen to hold, so a caller can branch on
         * `encrypted` alone. */
        out->type          = (uint8_t)OCA_ENCRYPTION_TYPE_NONE;
        out->secret_select = 0u;
        return OCA_OK;
    }
    out->type          = body[OCA_OFF_ENCRYPTION_TYPE];
    out->secret_select =
        oca_le_u16(body + OCA_OFF_ENCRYPTION_SHARED_SECRET_SELECT);
    return OCA_OK;
}

/**
 * @brief Whether the manifest declares an encrypted payload.
 *
 * The encryption CONTROL BIT is the sole trigger. Not payload_length — a
 * manifest declaring encryption over an empty payload still declares
 * encryption. Not encryption_type — a cleartext manifest may carry stray values
 * there without becoming an encrypted one.
 *
 * Hardened rather than a plain `bool` because OCA_SECURE_FALSE here is what
 * makes both encryption rules return OCA_OK without examining anything further.
 *
 * @param[in] body  Whole variant body.
 * @return OCA_SECURE_TRUE when the manifest declares its payload encrypted.
 */
static oca_secure_bool_t declares_encryption(const uint8_t *body)
{
    uint16_t control = oca_le_u16(body + OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL);
    return (control & OCA_ENCRYPTION_ENCRYPTED_PAYLOAD_BIT) != 0u
         ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
}

oca_result_t oca_check_payload_encryption_precondition(
    const uint8_t *body,
    const oca_callbacks_t *cb,
    const oca_validation_context_t *ctx)
{
    if (body == 0) {
        return OCA_FAIL_INVALID_ARG;
    }
    oca_result_t status;
    if (oca_variant_for_body(body, &status) == 0) {
        return status;
    }
    /* Tested before the confirm, so a cleartext manifest — the common case —
     * costs nothing here. There is no determination to consult when the rule
     * does not apply. */
    if (declares_encryption(body) == OCA_SECURE_FALSE) {
        return OCA_OK;
    }

    oca_secure_bool_t engaged;
    oca_result_t confirmed = oca_secure_boot_confirm(body, cb, ctx, &engaged);
    if (confirmed != OCA_OK) {
        return confirmed;
    }
    /* Note the INVERSION relative to every other consumer of the confirm, and
     * that the comparison below states it rather than hiding it. For them,
     * secure boot not being in force means "this check does not apply, pass", so
     * FALSE is the permissive answer and FALSE is what they match exactly. Here
     * it means the opposite: the manifest asked for something only a secure part
     * may have, so TRUE is the permissive answer and TRUE is what must match.
     * `engaged` is the same fact either way; the rule differs, so the pattern
     * guarded against a corrupted word differs with it. Written `!engaged` in a
     * plain bool, both sites read identically and this distinction is invisible. */
    if (engaged != OCA_SECURE_TRUE) {
        return OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT;
    }
    return OCA_OK;
}

oca_result_t oca_check_payload_encryption_policy(
    const uint8_t *body,
    const oca_callbacks_t *cb,
    const oca_validation_context_t *ctx)
{
    (void)cb;
    if (body == 0) {
        return OCA_FAIL_INVALID_ARG;
    }
    oca_result_t status;
    if (oca_variant_for_body(body, &status) == 0) {
        return status;
    }

    if (declares_encryption(body) == OCA_SECURE_FALSE) {
        return OCA_OK;
    }

    /* Confirmed, not merely enabled. A NULL context, a zero-initialised one, or
     * one holding any value other than OCA_SECURE_TRUE all mean the same thing:
     * no signature check ran and passed for this manifest. Compared for equality
     * with TRUE — never inequality with FALSE, which would read every corrupted
     * value as confirmed. */
    if (ctx == 0 || ctx->secure_boot_authenticated != OCA_SECURE_TRUE) {
        return OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT;
    }
    return OCA_OK;
}

/* ------------------------------------------------------------------ */
/* Post-validation TOC access                                         */
/*                                                                    */
/* These live beside the validation stage on purpose: their safety     */
/* rests on exactly the same bounds arithmetic as                      */
/* validate_toc_structure() above (read_toc_span for the index bound,  */
/* the 8-byte alignment and in-range rules per entry). Keeping them    */
/* adjacent means a change to one rule is visibly next to the other.   */
/*                                                                    */
/* They do no cryptography. See the contract in oca_validator.h: the   */
/* caller must have validated the bundle first.                        */
/* ------------------------------------------------------------------ */

oca_result_t oca_payload_region(const uint8_t *body, size_t body_length,
                                const uint8_t **out_payload,
                                size_t *out_payload_length,
                                bool *out_encrypted)
{
    if (body == 0 || out_payload == 0 || out_payload_length == 0
        || out_encrypted == 0) {
        return OCA_FAIL_INVALID_ARG;
    }

    /* Bound the buffer BEFORE reading any field, so a short buffer cannot
     * provoke an out-of-range read (the same ordering oca_validate relies on). */
    oca_result_t r = oca_check_length(body_length);
    if (r != OCA_OK) {
        return r;
    }
    oca_result_t status;
    const oca_variant_t *v = oca_variant_for_body(body, &status);
    if (v == 0) {
        return status;
    }
    if (body_length < v->body_size) {
        return OCA_FAIL_TRUNCATED;
    }

    uint16_t enc_control = oca_le_u16(body + OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL);
    bool encrypted = (enc_control & OCA_ENCRYPTION_ENCRYPTED_PAYLOAD_BIT) != 0u;
    size_t available = body_length - v->body_size;

    /* An encrypted payload is sized by payload_hashed_length (the full
     * ciphertext); a cleartext one by payload_length. Mirrors the sizing
     * oca_check_payload uses. */
    uint64_t stored_length = encrypted
        ? oca_le_u64(body + OCA_OFF_PAYLOAD_HASHED_LENGTH)
        : oca_le_u64(body + OCA_OFF_PAYLOAD_LENGTH);
    if (stored_length > available) {
        return OCA_FAIL_TRUNCATED;
    }

    *out_payload        = body + v->body_size;
    *out_payload_length = (size_t)stored_length;
    *out_encrypted      = encrypted;
    return OCA_OK;
}

oca_result_t oca_toc_info(const uint8_t *payload, size_t payload_length,
                          oca_toc_info_t *out)
{
    if (payload == 0 || out == 0) {
        return OCA_FAIL_INVALID_ARG;
    }

    uint64_t image_count = 0u;
    size_t toc_bytes = 0u;
    oca_result_t r = read_toc_span(payload, payload_length,
                                   &image_count, &toc_bytes);
    if (r != OCA_OK) {
        return r;
    }

    /* Confirm the PTOC magic. The validation stage does not gate on it — it
     * relies on payload_hash_chain to tie the whole region to the signed
     * manifest — but a caller reaching in here to READ the TOC deserves a
     * direct answer about whether these bytes are a TOC at all. */
    static const uint8_t ptoc_magic[4] = { 'P', 'T', 'O', 'C' };
    for (unsigned i = 0u; i < 4u; ++i) {
        if (payload[OCA_TOC_OFF_MAGIC + i] != ptoc_magic[i]) {
            return OCA_FAIL_PAYLOAD_TOC;
        }
    }

    out->version_major  = oca_le_u16(payload + OCA_TOC_OFF_VERSION_MAJOR);
    out->version_minor  = oca_le_u16(payload + OCA_TOC_OFF_VERSION_MINOR);
    out->payload_length = oca_le_u64(payload + OCA_TOC_OFF_PAYLOAD_LENGTH);
    out->image_count    = image_count;
    return OCA_OK;
}

oca_result_t oca_toc_image_at(const uint8_t *payload, size_t payload_length,
                              uint64_t index, oca_image_info_t *out)
{
    if (payload == 0 || out == 0) {
        return OCA_FAIL_INVALID_ARG;
    }

    uint64_t image_count = 0u;
    size_t toc_bytes = 0u;
    oca_result_t r = read_toc_span(payload, payload_length,
                                   &image_count, &toc_bytes);
    if (r != OCA_OK) {
        return r;
    }
    if (index >= image_count) {
        return OCA_FAIL_INVALID_ARG;
    }

    const uint8_t *entry =
        payload + OCA_TOC_HEADER_SIZE + (size_t)index * OCA_TOC_ENTRY_SIZE;
    uint64_t off = oca_le_u64(entry + OCA_TOC_ENTRY_OFF_OFFSET);
    uint64_t len = oca_le_u64(entry + OCA_TOC_ENTRY_OFF_LENGTH);

    /* Same per-entry rules as validate_toc_structure: 8-byte aligned offset,
     * and [off, off+len) inside the payload without overflowing. Re-checked
     * here so this function is safe on any buffer, not only one that already
     * went through oca_check_payload. */
    if ((off % 8u) != 0u) {
        return OCA_FAIL_PAYLOAD_TOC;
    }
    if (off > payload_length || len > payload_length - off) {
        return OCA_FAIL_PAYLOAD_TOC;
    }

    /* Both casts are safe: the bound above puts off and len inside
     * payload_length, which is itself a size_t. */
    out->bytes       = payload + (size_t)off;
    out->length      = (size_t)len;
    out->hash        = entry + OCA_TOC_ENTRY_OFF_HASH;
    out->description = entry + OCA_TOC_ENTRY_OFF_DESCRIPTION;
    out->offset      = off;

    out->group             = oca_le_u32(entry + OCA_TOC_ENTRY_OFF_GROUP);
    out->security_version  = oca_le_u64(entry + OCA_TOC_ENTRY_OFF_SECURITY_VERSION);
    out->load_addr         = oca_le_u64(entry + OCA_TOC_ENTRY_OFF_LOAD_ADDR);
    out->entry_point       = oca_le_u64(entry + OCA_TOC_ENTRY_OFF_ENTRY_POINT);
    out->target_chiplet_id = oca_le_u64(entry + OCA_TOC_ENTRY_OFF_TARGET_CHIPLET_ID);

    /* version packs major:16 | minor:24 | patch:24 into a little-endian u64. */
    uint64_t packed_version = oca_le_u64(entry + OCA_TOC_ENTRY_OFF_VERSION);
    out->version_patch = (uint32_t)(packed_version & 0xFFFFFFu);
    out->version_minor = (uint32_t)((packed_version >> 24) & 0xFFFFFFu);
    out->version_major = (uint16_t)((packed_version >> 48) & 0xFFFFu);

    /* type: 16 ASCII bytes, space-padded by the producer. Copy by hand — the
     * library is freestanding and calls no libc — then trim trailing spaces
     * and NULs so the result is a usable C string. */
    unsigned type_len = OCA_TOC_ENTRY_LEN_TYPE;
    for (unsigned i = 0u; i < OCA_TOC_ENTRY_LEN_TYPE; ++i) {
        out->type[i] = (char)entry[OCA_TOC_ENTRY_OFF_TYPE + i];
    }
    while (type_len > 0u
           && (out->type[type_len - 1u] == ' ' || out->type[type_len - 1u] == '\0')) {
        type_len--;
    }
    out->type[type_len] = '\0';
    /* Zero the slack so the struct has no indeterminate bytes. */
    for (unsigned i = type_len + 1u; i <= OCA_TOC_ENTRY_LEN_TYPE; ++i) {
        out->type[i] = '\0';
    }
    return OCA_OK;
}
