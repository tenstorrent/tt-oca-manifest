/**
 * @file
 * @brief Top-level entry point, public oca_check_* wrappers, and the
 * canonical-order composition.
 *
 * Per-check logic lives in the per-field translation units (parser.c,
 * selector.c, identity.c, lifecycle.c, version_range.c, demotion.c,
 * crypto_dispatch.c). This file does the wiring.
 */

#include "oca_validator.h"

#include "crypto_dispatch.h"
#include "demotion.h"
#include "identity.h"
#include "lifecycle.h"
#include "oca_layout.h"
#include "oca_variant.h"
#include "parser.h"
#include "selector.h"
#include "version_range.h"

const char *oca_result_str(oca_result_t r)
{
    switch (r) {
        case OCA_OK:                            return "OK";
        case OCA_FAIL_TRUNCATED:                return "TRUNCATED";
        case OCA_FAIL_MAGIC:                    return "MAGIC";
        case OCA_FAIL_TRAILER:                  return "TRAILER";
        case OCA_FAIL_FORMAT_VERSION_MISMATCH:  return "FORMAT_VERSION_MISMATCH";
        case OCA_FAIL_RESERVED_BITS:            return "RESERVED_BITS";
        case OCA_FAIL_SECURE_BOOT_INVARIANT:    return "SECURE_BOOT_INVARIANT";
        case OCA_FAIL_CHIPLET_ID:               return "CHIPLET_ID";
        case OCA_FAIL_PACKAGE_ID:               return "PACKAGE_ID";
        case OCA_FAIL_SYSTEM_ID:                return "SYSTEM_ID";
        case OCA_FAIL_LIFECYCLE:                return "LIFECYCLE";
        case OCA_FAIL_VERSION_RANGE:            return "VERSION_RANGE";
        case OCA_FAIL_DEMOTION_CONTROL:         return "DEMOTION_CONTROL";
        case OCA_FAIL_MANIFEST_HASH:            return "MANIFEST_HASH";
        case OCA_FAIL_SIGNATURE:                return "SIGNATURE";
        case OCA_FAIL_CALLBACK_UNAVAILABLE:     return "CALLBACK_UNAVAILABLE";
        case OCA_FAIL_INVALID_ARG:              return "INVALID_ARG";
        case OCA_FAIL_UNSUPPORTED_VARIANT:      return "UNSUPPORTED_VARIANT";
        case OCA_FAIL_PAYLOAD_HASH:             return "PAYLOAD_HASH";
        case OCA_FAIL_DECRYPT:                  return "DECRYPT";
        case OCA_FAIL_PAYLOAD_HASH_CHAIN:       return "PAYLOAD_HASH_CHAIN";
        case OCA_FAIL_PAYLOAD_TOC:              return "PAYLOAD_TOC";
        case OCA_FAIL_PAYLOAD_ENTRY_HASH:       return "PAYLOAD_ENTRY_HASH";
        case OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES:  return "PAYLOAD_TOO_MANY_IMAGES";
        case OCA_FAIL_PAYLOAD_LOCATION:         return "PAYLOAD_LOCATION";
        case OCA_FAIL_MANIFEST_LENGTH:          return "MANIFEST_LENGTH";
        case OCA_FAIL_ROOT_KEY_REVOKED:         return "ROOT_KEY_REVOKED";
        case OCA_FAIL_SECURITY_VERSION:         return "SECURITY_VERSION";
        case OCA_FAIL_SECURITY_STATE_UPDATE:    return "SECURITY_STATE_UPDATE";
        case OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT:
                                                return "ENCRYPTION_REQUIRES_SECURE_BOOT";
        case OCA_FAIL_NO_PROVISIONED_SECRET:    return "NO_PROVISIONED_SECRET";
        case OCA_FAIL_SECURE_BOOT_UNDETERMINED: return "SECURE_BOOT_UNDETERMINED";
        case OCA_FAIL_SECURE_BOOT_STATE_CHANGED:
                                                return "SECURE_BOOT_STATE_CHANGED";
        case OCA_FAIL_GROUP_CODE:               return "GROUP_CODE";
        case OCA_FAIL_CRYPTO_FIELD_SIZE:        return "CRYPTO_FIELD_SIZE";
        case OCA_FAIL_ROOT_KEY_UNAUTHORIZED:    return "ROOT_KEY_UNAUTHORIZED";
        case OCA_FAIL_SIGNATURE_CLASS_CONTROL:  return "SIGNATURE_CLASS_CONTROL";
    }
    return "UNKNOWN";
}

/* ------------------------------------------------------------------ */
/* Public oca_check_* wrappers                                        */
/* ------------------------------------------------------------------ */

/* The structural checks live in parser.c with the same name and are
 * exported through that translation unit; nothing to add here. */

oca_result_t oca_check_identity(const uint8_t *body,
                                oca_id_kind_t kind,
                                const oca_callbacks_t *cb)
{
    oca_selector_bits_t sb;
    oca_selector_decode(body, &sb);
    uint32_t mask;
    unsigned offset;
    switch (kind) {
        case OCA_ID_CHIPLET:
            mask   = sb.chiplet_id_mask;
            offset = OCA_OFF_CHIPLET_ID;
            break;
        case OCA_ID_PACKAGE:
            mask   = sb.package_id_mask;
            offset = OCA_OFF_PACKAGE_ID;
            break;
        case OCA_ID_SYSTEM:
            mask   = sb.system_id_mask;
            offset = OCA_OFF_SYSTEM_ID;
            break;
        default:
            return OCA_FAIL_INVALID_ARG;
    }
    return oca_identity_compare(body, offset, kind, mask, cb);
}

oca_result_t oca_check_lifecycle(const uint8_t *body,
                                 oca_lifecycle_level_t level,
                                 const oca_callbacks_t *cb)
{
    oca_selector_bits_t sb;
    oca_selector_decode(body, &sb);
    bool enabled = false;
    switch (level) {
        case OCA_LIFECYCLE_LEVEL_CHIPLET: enabled = sb.lifecycle_chiplet_enabled; break;
        case OCA_LIFECYCLE_LEVEL_PACKAGE: enabled = sb.lifecycle_package_enabled; break;
        case OCA_LIFECYCLE_LEVEL_SYSTEM:  enabled = sb.lifecycle_system_enabled;  break;
        default: return OCA_FAIL_INVALID_ARG;
    }
    if (!enabled) {
        return OCA_OK;
    }
    return oca_lifecycle_check(body, level, cb);
}

oca_result_t oca_check_version_range(const uint8_t *body,
                                     oca_version_level_t level,
                                     const oca_callbacks_t *cb)
{
    oca_selector_bits_t sb;
    oca_selector_decode(body, &sb);
    bool min_specified = false;
    bool max_specified = false;
    switch (level) {
        case OCA_VERSION_LEVEL_CHIPLET:
            min_specified = sb.version_chiplet_min_enabled;
            max_specified = sb.version_chiplet_max_enabled;
            break;
        case OCA_VERSION_LEVEL_PACKAGE:
            min_specified = sb.version_package_min_enabled;
            max_specified = sb.version_package_max_enabled;
            break;
        case OCA_VERSION_LEVEL_SYSTEM:
            min_specified = sb.version_system_min_enabled;
            max_specified = sb.version_system_max_enabled;
            break;
        default:
            return OCA_FAIL_INVALID_ARG;
    }
    return oca_version_range_check(body, level, min_specified, max_specified, cb);
}

oca_result_t oca_check_demotion_control(const uint8_t *body)
{
    return oca_demotion_check(body);
}

oca_result_t oca_check_manifest_hash(const uint8_t *body,
                                     const oca_callbacks_t *cb)
{
    return oca_manifest_hash_check(body, cb);
}

oca_result_t oca_check_signature(const uint8_t *body,
                                 const oca_callbacks_t *cb,
                                 oca_validation_context_t *ctx)
{
    return oca_signature_check(body, cb, ctx);
}

void oca_validation_context_init(oca_validation_context_t *ctx)
{
    if (ctx == 0) {
        return;
    }
    ctx->secure_boot_determined              = OCA_SECURE_FALSE;
    ctx->secure_boot_enabled                 = OCA_SECURE_FALSE;
    ctx->manifest_is_classic                 = OCA_SECURE_FALSE;
    ctx->manifest_is_pqc                     = OCA_SECURE_FALSE;
    ctx->secure_boot_enforce_classic         = OCA_SECURE_FALSE;
    ctx->secure_boot_enforce_pqc             = OCA_SECURE_FALSE;
    ctx->secure_boot_key_authorized_classic  = OCA_SECURE_FALSE;
    ctx->secure_boot_key_authorized_pqc      = OCA_SECURE_FALSE;
    ctx->secure_boot_authenticated           = OCA_SECURE_FALSE;
    ctx->secure_boot_device_disabled         = OCA_SECURE_FALSE;
}

/* ------------------------------------------------------------------ */
/* Canonical-order composition                                        */
/* ------------------------------------------------------------------ */

oca_result_t oca_validate_manifest(const uint8_t *body,
                                   size_t         body_length,
                                   const oca_callbacks_t *cb,
                                   oca_validation_context_t *ctx)
{
    /* The secure boot determination has to land somewhere every check below can 
     * read it, whether or not the caller wanted the record. A caller passing NULL
     * is declining the REPORT, not the determination, so the composition owns a
     * context for that case and every check downstream is reached identically on
     * both paths. One composition, not one for callers who supply a context and
     * another for callers who do not: two would be free to drift */
    oca_validation_context_t owned;
    oca_validation_context_t *vctx = (ctx != 0) ? ctx : &owned;

    /* Cleared here rather than trusting the caller, and BEFORE the argument
     * guard so every exit — including the earliest — leaves a context saying
     * "nothing established".
     *
     * The context records what THIS validation established; anything carried in
     * from a previous run is never correct. The field that would carry is
     * secure_boot_authenticated, which is exactly the one deciding whether an
     * encrypted payload may be decrypted, so a forgotten
     * oca_validation_context_init() must not be the difference between refusing
     * and decrypting. */
    oca_validation_context_init(vctx);

    if (body == 0) {
        return OCA_FAIL_INVALID_ARG;
    }
    /* A NULL pointer cb is deliberately NOT an error. Each check reports
     * OCA_FAIL_CALLBACK_UNAVAILABLE for the callback IT needs, which names the
     * missing capability; a blanket refusal here would collapse a dozen specific
     * diagnoses into one, and would reject the legitimate composition where a
     * permissive manifest constrains nothing and needs no callbacks. */

    oca_result_t r;

    /* Structural framing. Every later check assumes valid framing. */
    r = oca_check_length(body_length);
    if (r != OCA_OK) return r;
    r = oca_check_magic(body);
    if (r != OCA_OK) return r;

    /* Magic is valid and the variant is supported: resolve it and require
     * the full per-variant body before any later check reads a high-offset
     * (e.g., PQC) field. */
    oca_result_t variant_status;
    const oca_variant_t *variant = oca_variant_for_body(body, &variant_status);
    if (variant == 0) return variant_status;
    if (body_length < variant->body_size) return OCA_FAIL_TRUNCATED;

    r = oca_check_trailer(body);
    if (r != OCA_OK) return r;
    r = oca_check_format_version(body);
    if (r != OCA_OK) return r;
    /* After format_version: a newer major could redefine field semantics, so the
     * version is settled before the manifest's self-description is trusted. */
    r = oca_check_manifest_length(body);
    if (r != OCA_OK) return r;

    /* Integrity check , before anything utilizes the contents. manifest_hash covers
     * [0, signed_region_end); if it does not match, every field decoded below
     * is being read out of damaged bytes, including the secure_boot_control bit
     * the determination is about to read as its highest-priority input and the
     * identity/lifecycle/version checks would spend hardware callbacks on it
     * only to report a mismatch that misstates the real fault.
     *
     * This is NOT a trust boundary. manifest_hash sits in the unsigned tail, so
     * anyone editing the manifest recomputes it freely — it catches corruption,
     * not tampering. Authenticity is established by oca_check_signature below. */
    r = oca_check_manifest_hash(body, cb);
    if (r != OCA_OK) return r;

    /* Structural statements about the manifest's own fields, decided from the
     * manifest alone and therefore ahead of the determination — neither asks
     * what secure boot resolved to.
     *
     * oca_check_secure_boot_invariant() in particular reads the RAW
     * secure_boot_control bit and MUST keep doing so. Its question is "did a
     * manifest declaring itself non-secure zero its signing fields?", a
     * producer-side property of these bytes. Rewiring it to the determination
     * would silently change it into a different question on any part whose
     * device state disagrees with the manifest — and on a disabled part the two
     * usually agree, so nothing would notice. */
    r = oca_check_reserved_bits(body);
    if (r != OCA_OK) return r;
    r = oca_check_secure_boot_invariant(body);
    if (r != OCA_OK) return r;
    /* The positive counterpart of the invariant above: where that one requires a
     * non-secure manifest to zero its signing fields, this requires a secure one
     * to describe them consistently. */
    r = oca_check_crypto_field_sizes(body);
    if (r != OCA_OK) return r;
    /* Confirm the consistency of the signature revocation group codes; if these
    values are mal-formed then the manifest is suspect. We don't care what
    algorithms are actually revoked here. That check can only be done against the 
    on device fuse values */
    r = oca_check_signature_class_group_codes(body);
    if (r != OCA_OK) return r;

    /* Secure boot determination
     *
     * Every check below that gates on secure boot re-derives the same values as this 
     * and requires the answer to still match what was recorded 
     * (see oca_secure_boot_confirm()).
     * So this establishes a REFERENCE, not a verdict they inherit.
     *
     * That combination is the point. Deriving independently at each check, let a 
     * single glitched reporter read at the signature site skip signature 
     * verification alone, with revocation and anti-rollback none the wiser and nothing comparing the two. Recording once and having
     * everyone simply READ it would be worse: one glitched determination would
     * disarm all of them at once. Doing both costs an attacker a consistent fault
     * at the determination AND at every confirm.
     *
     * Placed after framing, integrity, and the invariant, because the
     * determination's highest-priority input is a manifest bit and settling the
     * question out of a body that failed its integrity check would settle it from
     * damage. Placed before every check that consults it, because there is
     * otherwise nothing for them to confirm against.
     *
     * This CAN fail: a manifest whose effective secure boot is in force while
     * its secure_boot_control names no signature class is rejected here with
     * OCA_FAIL_SIGNATURE_CLASS_CONTROL, before the determination settles —
     * the context stays unsettled, so nothing downstream can act on it. */
    r = oca_determine_secure_boot(body, cb, vctx);
    if (r != OCA_OK) return r;

    /* Cheapest gated check in the library, so it goes first among them: a
     * manifest read and a context comparison, no hardware identity read and no
     * public-key operation. An encrypted payload declared on a part where secure
     * boot is not in force cannot boot, and finding that out here costs nothing.
     *
     * Necessary but not sufficient — the confirmed form runs at the end, once
     * the signature has actually been checked. */
    r = oca_check_payload_encryption_precondition(body, cb, vctx);
    if (r != OCA_OK) return r;

    /* Identity-byte checks per family. The check functions short-circuit
     * when the corresponding selector_bits mask is zero. */
    r = oca_check_identity(body, OCA_ID_CHIPLET, cb);
    if (r != OCA_OK) return r;
    r = oca_check_identity(body, OCA_ID_PACKAGE, cb);
    if (r != OCA_OK) return r;
    r = oca_check_identity(body, OCA_ID_SYSTEM, cb);
    if (r != OCA_OK) return r;

    /* Lifecycle (per level). */
    r = oca_check_lifecycle(body, OCA_LIFECYCLE_LEVEL_CHIPLET, cb);
    if (r != OCA_OK) return r;
    r = oca_check_lifecycle(body, OCA_LIFECYCLE_LEVEL_PACKAGE, cb);
    if (r != OCA_OK) return r;
    r = oca_check_lifecycle(body, OCA_LIFECYCLE_LEVEL_SYSTEM, cb);
    if (r != OCA_OK) return r;

    /* Version range (per level). */
    r = oca_check_version_range(body, OCA_VERSION_LEVEL_CHIPLET, cb);
    if (r != OCA_OK) return r;
    r = oca_check_version_range(body, OCA_VERSION_LEVEL_PACKAGE, cb);
    if (r != OCA_OK) return r;
    r = oca_check_version_range(body, OCA_VERSION_LEVEL_SYSTEM, cb);
    if (r != OCA_OK) return r;

    /* demotion_control reserved-bit rule. */
    r = oca_check_demotion_control(body);
    if (r != OCA_OK) return r;

    /* Authenticity check based on cryptographic signatures 
     * Integrity was settled earlier, by oca_check_manifest_hash.
     *
     * ROOT-key authorization runs first, so a key the device does not trust is
     * never used to verify and never costs a modexp; revocation follows, so a
     * key that was trusted and has since been withdrawn is caught too. The two
     * are different questions -- ever trusted, still trusted -- in that order.
     *
     * Anti-rollback also run before the signature, so a replayed manifest is
     * rejected without paying for a public-key operation. Rejecting on
     * not-yet-authenticated data is sound in the rejection direction ONLY: a
     * manifest altered to change this outcome fails verification below, and one
     * that genuinely fails is a rollback whoever wrote it. A *pass* here is not
     * a decision — it becomes one retroactively when the signature verifies over
     * the region that contains the compared value.
     *
     * The comparison then runs again on the authenticated manifest. That repeat
     * is defense in depth against a fault that skipped or glitched the first,
     * not a correction for unauthenticated data; it re-reads the DEVICE value
     * rather than reusing one, so a faulted read cannot be carried forward into
     * the check meant to catch it. What it deliberately does not re-derive
     * afresh is the secure-boot determination: that it confirms against the
     * record instead, so a reporter that has started disagreeing fails the
     * validation rather than quietly disarming this check.
     *
     * All four are no-ops when the determination came back not-in-force, and all
     * four refuse outright if it no longer matches the device. There is no
     * `if (secure)` around them: the confirm lives inside each check, because
     * each is public and has to be safe when composed by hand, and a second copy
     * of the condition here would be free to drift from the one with a test
     * naming it. */
    r = oca_check_root_key_authorized(body, cb, vctx);
    if (r != OCA_OK) return r;
    r = oca_check_root_key_revocation(body, cb, vctx);
    if (r != OCA_OK) return r;
    r = oca_check_security_version(body, cb, vctx);
    if (r != OCA_OK) return r;
    r = oca_check_signature(body, cb, vctx);
    if (r != OCA_OK) return r;
#if OCA_RECHECK_SECURITY_VERSION
    r = oca_check_security_version(body, cb, vctx);
    if (r != OCA_OK) return r;
#endif

    /* Once authentication is settled, an encrypted payload requires
     * CONFIRMED secure boot, not merely enabled. Reads what oca_check_signature
     * recorded rather than re-deriving it, so a sequence that never reached the
     * signature check is refused exactly like one on a non-secure device. Last
     * rather than merely after the signature, because it is the only check whose
     * input is another check's OUTPUT. */
    r = oca_check_payload_encryption_policy(body, cb, vctx);
    if (r != OCA_OK) return r;

    return OCA_OK;
}

oca_result_t oca_validate(const uint8_t *body,
                          size_t         body_length,
                          const oca_callbacks_t *cb,
                          oca_validation_context_t *ctx,
                          oca_payload_plaintext_t *out_plaintext)
{
    /* Manifest first, in canonical order, then the payload stage. The payload
     * stage here assumes the payload sits immediately after the body — true
     * only when payload_offset == body_size. A consumer whose payload lives
     * elsewhere runs oca_validate_manifest(), then oca_locate_payload(), then
     * oca_check_payload_at().
     *
     * The context is now OPTIONAL rather than private. A whole-bundle consumer
     * needs no seam between the two VALIDATION stages, which is why it used to be
     * owned here — but oca_commit_security_state() is a third step, after both,
     * and it needs the determination this validation made. Supplying a context is
     * how a caller that intends to commit gets one without a second, separately
     * timed determination; passing NULL keeps the original behaviour exactly.
     *
     * This is still not where a plaintext report belongs: out_plaintext stays a
     * separate out-parameter because a field on the context would be filled and
     * then destroyed with this frame on the NULL path, which is the problem the
     * report exists to fix. */
    oca_validation_context_t owned;
    oca_validation_context_t *vctx = (ctx != 0) ? ctx : &owned;

    /* No init here: oca_validate_manifest() clears the context before its first
     * guard, so both paths start from "nothing established". */
    oca_result_t r = oca_validate_manifest(body, body_length, cb, vctx);
    if (r != OCA_OK) return r;
    return oca_check_payload(body, body_length, cb, vctx, out_plaintext);
}
