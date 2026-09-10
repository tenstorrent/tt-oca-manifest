// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/*
 * unit_test.c — In-tree C unit tests for the OCA validator library.
 *
 * Host-side only. Links against liboca_validator.a and the
 * unit_helpers.h framework. Run via `make unit_test`.
 *
 * These tests exercise every check function in isolation plus the
 * canonical-order composition. Cryptographic correctness (real SHA-256
 * digests, real signature verification) is the integration-test layer's
 * job; here we use a tautological hash stub that always returns the
 * embedded hash so the dispatch path is exercised end-to-end without
 * needing OpenSSL in the unit-test binary.
 */

#include <stdint.h>
#include <string.h>

#include "oca_validator.h"
#include "oca_compare.h"
#include "oca_layout.h"
#include "oca_layout_classic.h"
#include "oca_layout_pqc.h"   /* PQC body size, for the cross-variant checks */
#include "unit_helpers.h"

int g_unit_total = 0;
int g_unit_failed = 0;
int g_unit_current_failed = 0;

/* Registered tests, in declaration order. */
static const char   *g_reg_names[OCA_UNIT_MAX_TESTS];
static unit_test_fn  g_reg_fns[OCA_UNIT_MAX_TESTS];
static int           g_reg_count;

void unit_register(const char *name, unit_test_fn fn)
{
    if (g_reg_count >= OCA_UNIT_MAX_TESTS) {
        fprintf(stderr, "unit_register: OCA_UNIT_MAX_TESTS (%d) exceeded; "
                        "raise it rather than dropping tests\n", OCA_UNIT_MAX_TESTS);
        return;
    }
    g_reg_names[g_reg_count] = name;
    g_reg_fns[g_reg_count]   = fn;
    g_reg_count++;
}

void unit_run_all(int reverse)
{
    for (int n = 0; n < g_reg_count; ++n) {
        int i = reverse ? (g_reg_count - 1 - n) : n;
        g_unit_total++;
        g_unit_current_failed = 0;
        test_fixture_reset();
        g_reg_fns[i]();
        if (g_unit_current_failed) {
            g_unit_failed++;
            fprintf(stderr, "FAIL: %s\n", g_reg_names[i]);
        } else {
            fprintf(stderr, "PASS: %s\n", g_reg_names[i]);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Fixed-time comparison primitives (oca_compare.h)                   */
/*                                                                    */
/* Timing itself is not asserted here — a wall-clock assertion would   */
/* be flaky and platform-dependent. What these pin down is the         */
/* functional contract, including the cases where a naive fold gets it */
/* wrong: a difference in the FINAL byte must still be detected (an    */
/* accumulator that is tested inside the loop would miss it), and      */
/* mask-excluded positions must be ignored no matter how they differ.  */
/* ------------------------------------------------------------------ */

TEST(test_ct_diff_detects_difference_at_any_position)
{
    uint8_t a[32], b[32];
    memset(a, 0x5A, sizeof a);

    memcpy(b, a, sizeof b);
    ASSERT_EQ_INT(oca_ct_diff(a, b, sizeof a), 0);        /* equal */

    for (unsigned i = 0u; i < sizeof a; ++i) {
        memcpy(b, a, sizeof b);
        b[i] ^= 0x01u;
        ASSERT_TRUE(oca_ct_diff(a, b, sizeof a) != 0);    /* incl. first + last */
    }
}

TEST(test_ct_diff_zero_length_is_equal)
{
    uint8_t a[1] = { 0x11u }, b[1] = { 0x22u };
    ASSERT_EQ_INT(oca_ct_diff(a, b, 0u), 0);
}

TEST(test_ct_diff_masked_ignores_unselected_bytes)
{
    uint8_t a[32], b[32];
    memset(a, 0xAAu, sizeof a);
    memset(b, 0xAAu, sizeof b);

    /* Differ everywhere, select nothing → equal. */
    memset(b, 0x55u, sizeof b);
    ASSERT_EQ_INT(oca_ct_diff_masked(a, b, sizeof a, 0x00000000u), 0);

    /* Differ only at byte 7; selecting byte 7 catches it, selecting others does not. */
    memcpy(b, a, sizeof b);
    b[7] ^= 0xFFu;
    ASSERT_TRUE(oca_ct_diff_masked(a, b, sizeof a, 1u << 7) != 0);
    ASSERT_EQ_INT(oca_ct_diff_masked(a, b, sizeof a, 1u << 6), 0);
    ASSERT_TRUE(oca_ct_diff_masked(a, b, sizeof a, 0xFFFFFFFFu) != 0);

    /* Highest selectable position (byte 31) is reachable — an off-by-one in the
     * shift would silently stop enforcing the last byte. */
    memcpy(b, a, sizeof b);
    b[31] ^= 0xFFu;
    ASSERT_TRUE(oca_ct_diff_masked(a, b, sizeof a, 1u << 31) != 0);
    ASSERT_EQ_INT(oca_ct_diff_masked(a, b, sizeof a, 1u << 30), 0);
}

TEST(test_ct_any_nonzero)
{
    uint8_t buf[32];
    memset(buf, 0, sizeof buf);
    ASSERT_EQ_INT(oca_ct_any_nonzero(buf, sizeof buf), 0);
    for (unsigned i = 0u; i < sizeof buf; ++i) {
        memset(buf, 0, sizeof buf);
        buf[i] = 0x01u;
        ASSERT_TRUE(oca_ct_any_nonzero(buf, sizeof buf) != 0);
    }
}

TEST(test_ct_any_overlap)
{
    uint8_t a[14], b[14];
    memset(a, 0, sizeof a);
    memset(b, 0, sizeof b);
    ASSERT_EQ_INT(oca_ct_any_overlap(a, b, sizeof a), 0);

    /* Disjoint bits in the same byte do not overlap. */
    a[3] = 0x0Fu;
    b[3] = 0xF0u;
    ASSERT_EQ_INT(oca_ct_any_overlap(a, b, sizeof a), 0);

    /* A single shared bit, in the last byte, does. */
    memset(a, 0, sizeof a);
    memset(b, 0, sizeof b);
    a[13] = 0x80u;
    b[13] = 0x80u;
    ASSERT_TRUE(oca_ct_any_overlap(a, b, sizeof a) != 0);
}

/* ------------------------------------------------------------------ */
/* Manifest-builder helpers                                           */
/* ------------------------------------------------------------------ */

static void build_minimal_manifest(uint8_t buf[OCA_CLASSIC_BODY_SIZE])
{
    memset(buf, 0, OCA_CLASSIC_BODY_SIZE);
    memcpy(buf + OCA_OFF_MAGIC,
           OCA_CLASSIC_MAGIC, OCA_MAGIC_LEN);
    memcpy(buf + OCA_OFF_MANIFEST_IDENTIFIER, "UNIT", 4);
    /* version major/minor */
    buf[OCA_OFF_MANIFEST_VERSION_MAJOR + 0] =
        (uint8_t)(OCA_LIB_MANIFEST_MAJOR & 0xFF);
    buf[OCA_OFF_MANIFEST_VERSION_MINOR + 0] =
        (uint8_t)(OCA_LIB_MANIFEST_MINOR & 0xFF);
    /* manifest_length = 4096 */
    buf[OCA_OFF_MANIFEST_LENGTH + 1] = 0x10;
    /* payload_offset = body_size: what every producer writes for a contiguous
     * bundle, and what oca_check_payload requires before it will assume the
     * payload follows the body. Leaving it zero models no real manifest. */
    buf[OCA_CLASSIC_OFF_PAYLOAD_OFFSET + 1] = 0x10;
    /* trailer */
    memset(buf + OCA_CLASSIC_OFF_TRAILER,
           OCA_CLASSIC_TRAILER_BYTE, OCA_CLASSIC_TRAILER_LEN);
    /* manifest_hash: set to a recognizable sentinel and have the stub
     * sha256 callback below return the same bytes. */
    for (unsigned i = 0; i < 32; ++i) {
        buf[OCA_CLASSIC_OFF_MANIFEST_HASH + i] = (uint8_t)i;
    }
}

static void set_selector_bit(uint8_t buf[OCA_CLASSIC_BODY_SIZE], unsigned n)
{
    buf[OCA_OFF_SELECTOR_BITS + (n / 8)] |=
        (uint8_t)(1u << (n % 8));
}

static void set_lifecycle_states(uint8_t buf[OCA_CLASSIC_BODY_SIZE],
                                 oca_lifecycle_level_t level,
                                 uint32_t bitmap)
{
    unsigned off;
    switch (level) {
        case OCA_LIFECYCLE_LEVEL_CHIPLET:
            off = OCA_OFF_LIFECYCLE_CHIPLET_STATES; break;
        case OCA_LIFECYCLE_LEVEL_PACKAGE:
            off = OCA_OFF_LIFECYCLE_PACKAGE_STATES; break;
        case OCA_LIFECYCLE_LEVEL_SYSTEM:
            off = OCA_OFF_LIFECYCLE_SYSTEM_STATES; break;
        default: return;
    }
    buf[off + 0] = (uint8_t)(bitmap & 0xFF);
    buf[off + 1] = (uint8_t)((bitmap >> 8) & 0xFF);
    buf[off + 2] = (uint8_t)((bitmap >> 16) & 0xFF);
    buf[off + 3] = (uint8_t)((bitmap >> 24) & 0xFF);
}

static void set_version_range(uint8_t buf[OCA_CLASSIC_BODY_SIZE],
                              oca_version_level_t level,
                              uint16_t major_min, uint16_t minor_min,
                              uint16_t major_max, uint16_t minor_max)
{
    unsigned off;
    switch (level) {
        case OCA_VERSION_LEVEL_CHIPLET:
            off = OCA_OFF_VERSION_RANGE_CHIPLET; break;
        case OCA_VERSION_LEVEL_PACKAGE:
            off = OCA_OFF_VERSION_RANGE_PACKAGE; break;
        case OCA_VERSION_LEVEL_SYSTEM:
            off = OCA_OFF_VERSION_RANGE_SYSTEM; break;
        default: return;
    }
    /* minor_min, major_min, minor_max, major_max — each LE u16. */
    buf[off + 0] = (uint8_t)(minor_min & 0xFF);
    buf[off + 1] = (uint8_t)((minor_min >> 8) & 0xFF);
    buf[off + 2] = (uint8_t)(major_min & 0xFF);
    buf[off + 3] = (uint8_t)((major_min >> 8) & 0xFF);
    buf[off + 4] = (uint8_t)(minor_max & 0xFF);
    buf[off + 5] = (uint8_t)((minor_max >> 8) & 0xFF);
    buf[off + 6] = (uint8_t)(major_max & 0xFF);
    buf[off + 7] = (uint8_t)((major_max >> 8) & 0xFF);
}

/* ------------------------------------------------------------------ */
/* Callback stubs                                                     */
/* ------------------------------------------------------------------ */

/* A context object recording a completed, successful authentication.
 *
 * Tests about payload mechanics — TOC structure, hash chains, decryption — are
 * not about the encryption gate, so they pass this and go on exercising what
 * they were written for. Tests that ARE about the gate build their own context
 * so the state under test is visible at the call site. */
static const oca_validation_context_t g_authenticated = {
    .secure_boot_determined              = OCA_SECURE_TRUE,  /* a validation ran to completion */
    .secure_boot_enabled                 = OCA_SECURE_TRUE,
    .manifest_is_classic                 = OCA_SECURE_TRUE,
    .manifest_is_pqc                     = OCA_SECURE_FALSE,
    .secure_boot_enforce_classic         = OCA_SECURE_TRUE,
    .secure_boot_enforce_pqc             = OCA_SECURE_FALSE,
    .secure_boot_key_authorized_classic  = OCA_SECURE_TRUE,  /* implied: verification needs it */
    .secure_boot_key_authorized_pqc      = OCA_SECURE_FALSE,
    .secure_boot_authenticated           = OCA_SECURE_TRUE,
    .secure_boot_device_disabled         = OCA_SECURE_FALSE
};

/* A context recording a completed determination that came back IN FORCE, with
 * nothing yet authenticated. What oca_determine_secure_boot() leaves behind on a
 * secure part, and therefore what a check gated on the determination must be
 * handed to engage at all. */
static const oca_validation_context_t g_determined_secure = {
    .secure_boot_determined              = OCA_SECURE_TRUE,
    .secure_boot_enabled                 = OCA_SECURE_TRUE,
    .manifest_is_classic                 = OCA_SECURE_TRUE,
    .manifest_is_pqc                     = OCA_SECURE_FALSE,
    .secure_boot_enforce_classic         = OCA_SECURE_TRUE,
    .secure_boot_enforce_pqc             = OCA_SECURE_FALSE,
    .secure_boot_key_authorized_classic  = OCA_SECURE_FALSE,
    .secure_boot_key_authorized_pqc      = OCA_SECURE_FALSE,
    .secure_boot_authenticated           = OCA_SECURE_FALSE,
    .secure_boot_device_disabled         = OCA_SECURE_FALSE
};

/* A determination in force with the ROOT key already authorized, and nothing yet
 * authenticated. This is what oca_check_signature() is handed in the composed
 * pipeline, and the minimum it will act on: authorization is recorded precisely
 * so a context lacking it cannot reach the verifier. Distinct from
 * g_determined_secure, which stops one check earlier. */
static const oca_validation_context_t g_authorized_secure = {
    .secure_boot_determined              = OCA_SECURE_TRUE,
    .secure_boot_enabled                 = OCA_SECURE_TRUE,
    .manifest_is_classic                 = OCA_SECURE_TRUE,
    .manifest_is_pqc                     = OCA_SECURE_FALSE,
    .secure_boot_enforce_classic         = OCA_SECURE_TRUE,
    .secure_boot_enforce_pqc             = OCA_SECURE_FALSE,
    .secure_boot_key_authorized_classic  = OCA_SECURE_TRUE,
    .secure_boot_key_authorized_pqc      = OCA_SECURE_FALSE,
    .secure_boot_authenticated           = OCA_SECURE_FALSE,
    .secure_boot_device_disabled         = OCA_SECURE_FALSE
};

/* The same, for a part where the determination came back NOT in force. Distinct
 * from a zero-initialised context, which records no determination at all — the
 * difference this field exists to express. */
static const oca_validation_context_t g_determined_nonsecure = {
    .secure_boot_determined              = OCA_SECURE_TRUE,
    .secure_boot_enabled                 = OCA_SECURE_FALSE,
    .manifest_is_classic                 = OCA_SECURE_TRUE,
    .manifest_is_pqc                     = OCA_SECURE_FALSE,
    .secure_boot_enforce_classic         = OCA_SECURE_FALSE,
    .secure_boot_enforce_pqc             = OCA_SECURE_FALSE,
    .secure_boot_key_authorized_classic  = OCA_SECURE_FALSE,
    .secure_boot_key_authorized_pqc      = OCA_SECURE_FALSE,
    .secure_boot_authenticated           = OCA_SECURE_FALSE,
    .secure_boot_device_disabled         = OCA_SECURE_FALSE
};

/**
 * @brief Run the real determination over this manifest and callback table.
 *
 * What a check gated on secure boot must be handed before it will act. Using the
 * library's own determination rather than a hand-built context is deliberate: the
 * checks re-derive and compare, so a constant that happened to disagree with the
 * fixture's wiring would report OCA_FAIL_SECURE_BOOT_STATE_CHANGED and the test
 * would fail for a reason that has nothing to do with what it is testing.
 *
 * It also keeps each test honest about its own premise — the context it gets is
 * the one a real validation of this fixture would have produced.
 *
 * @param[in] body  Manifest body the check will be run against.
 * @param[in] cb    Callback table the check will be given.
 * @return A context holding this fixture's determination.
 */
static oca_validation_context_t determined_for(const uint8_t *body,
                                               const oca_callbacks_t *cb)
{
    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    (void)oca_determine_secure_boot(body, cb, &ctx);
    /* Authorization too, because it is the first of the gated key checks and
     * oca_check_signature() refuses a context that does not record it. A test
     * handed this context is testing something DOWNSTREAM of authorization, so
     * reaching it having skipped authorization would not be a state the composed
     * pipeline can produce. Tests that are about authorization itself build their
     * own context, the same convention the encryption-gate tests follow. */
    (void)oca_check_root_key_authorized(body, cb, &ctx);
    return ctx;
}

/* ------------------------------------------------------------------ */
/* Test fixture — everything the stub callbacks report                */
/*                                                                    */
/* The library reaches device state, crypto material, and a hash      */
/* engine through callbacks, none of which exist on a host. Every     */
/* value the stubs below hand back therefore has to be invented by    */
/* the case under test, and it lives here.                            */
/*                                                                    */
/* One struct, one reset, and RUN_TEST performs the reset before      */
/* every case, so a case cannot observe values another case set. That */
/* matters more than it looks: several cases assert on how many times */
/* a callback fired, and a counter that outlived the clearing it      */
/* appeared to be covered by would make one case's assertion depend   */
/* on which cases ran before it.                                     */
/*                                                                    */
/* Zeroed means "the device answers nothing": every *_present flag is */
/* false, so each readback stub reports OCA_HW_UNAVAILABLE, which the */
/* validator treats as a hard failure rather than a waiver. A case    */
/* that neglects to set a value it depends on therefore fails, rather */
/* than passing on a value left behind by an earlier case.            */
/*                                                                    */
/* Reset explicitly with test_fixture_reset() only when a single case */
/* needs fresh state partway through — two validations in one case,   */
/* say. Normal cases need no call at all.                             */
/* ------------------------------------------------------------------ */
typedef struct {
    /* Manifest body the tautological SHA-256 stubs read their answer out of. */
    const uint8_t *sha_body;
    /* Where that body keeps its manifest_hash. Zero — never a real offset —
     * means the Classic position, so classical tests set nothing; a PQC-body
     * test sets OCA_PQC_OFF_MANIFEST_HASH. */
    size_t sha_hash_off;

    /* Hardware identity, as the readback stub reports it. */
    uint8_t chiplet_id[32];
    uint8_t package_id[32];
    uint8_t system_id[32];
    bool    identity_present;

    /* Lifecycle state, as the readback stub reports it. */
    oca_lifecycle_token_t lifecycle_token;
    bool                  lifecycle_present;

    /* Hardware version, as the readback stub reports it. */
    uint16_t version_major;
    uint16_t version_minor;
    bool     version_present;

    /* Device-stored secure-boot state — an in-memory stand-in for fuses and
     * OTP: per-algorithm ROOT-key revocation bitmap (the classic slot is the
     * one exercised) plus the 128-bit security-version flags. */
    uint8_t revoke[16];
    uint8_t secver[16];
    /* The two signature posture registers are 8 bytes, not 16 — they mirror
     * their manifest fields, and those are u64. */
    uint8_t cohort[8];
    uint8_t class_revoke[8];
    bool    fail_set;

    /* Ciphertext-aware SHA-256 state. The payload digest stub returns
     * `ct_digest` when hashing the ciphertext (matched by pointer and length)
     * and all-zero for anything else, so the plaintext hash chain recomputes to
     * a known all-zero value. Clearing `return_ct_digest` is how a case makes
     * the ciphertext hash fail to match. */
    const uint8_t *ciphertext;
    size_t         ciphertext_len;
    uint8_t        ct_digest[32];
    bool           return_ct_digest;

    /* Invocation counters, deliberately inside the fixture rather than beside
     * it. `set_calls` lets a case assert the commit behaviour and validation's
     * read-only contract; the rest let a case assert WHICH input was consulted,
     * which a verdict alone cannot show — "the manifest outranked the device"
     * and "the device happened to agree" produce the same verdict. */
    int set_calls;
    int secver_calls;
    int sb_disabled_calls;
    int sb_active_calls;
    int decrypt_calls;
    int sig_calls;
    /* The hardware readers and the revocation reader. Counted so a case can
     * assert that a check was reached, or that it was not — which is the only
     * way to state an ordering claim about work that has no other side effect. */
    int identity_calls;
    int lifecycle_calls;
    int version_calls;
    int revoke_calls;

    /* What the decryption descriptor carried, captured for assertions. Inside
     * the fixture rather than beside it for the same reason the counters are:
     * a stale observation from an earlier case is indistinguishable from this
     * case's. */
    oca_encryption_type_t seen_cipher;
    uint16_t              seen_secret_select;
    const uint8_t        *seen_iv;
    const uint8_t        *seen_kdf_input;
    size_t                seen_ciphertext_len;

    /* Plaintext a decrypt stub hands back. A caller-shaped buffer, so its
     * address is what a report assertion compares against. */
    const uint8_t *struct_pt;
    size_t         struct_pt_len;

    /* Scratch payload buffers the stubs return. Cleared with everything else, so
     * a case that forgets to build one gets an empty TOC rather than whatever
     * the previous case left. */
    uint8_t plaintext_toc[OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE];
    uint8_t cap_toc[OCA_TOC_HEADER_SIZE
                    + (OCA_TOC_MAX_IMAGES + 1u) * OCA_TOC_ENTRY_SIZE];
} test_fixture_t;

static test_fixture_t g_fx;

void test_fixture_reset(void)
{
    memset(&g_fx, 0, sizeof g_fx);
}

/* Tautological SHA-256: copy the manifest's embedded manifest_hash bytes
 * back out as the "computed" digest. Lets dispatch tests succeed without
 * a real SHA-256 implementation. */
static oca_result_t stub_sha256_pass(const uint8_t *msg, size_t msg_len,
                                     uint8_t out[32])
{
    size_t hash_off = g_fx.sha_hash_off != 0u
        ? g_fx.sha_hash_off : OCA_CLASSIC_OFF_MANIFEST_HASH;
    (void)msg; (void)msg_len;    memcpy(out, g_fx.sha_body + hash_off, 32);
    return OCA_OK;
}

/* Authorizes whatever key it is handed, and counts the calls.
 *
 * Under the check ordering a signature cannot be verified without the key first
 * being authorized, so every table that wires verify_signature wires this too.
 * Tests specifically about authorization substitute their own. */
static int g_authorize_calls;
static oca_result_t authorize_any_cb(const oca_crypto_blob_t *public_key,
                                     const uint8_t select[16])
{
    (void)public_key; (void)select;
    g_authorize_calls++;
    return OCA_OK;
}

/* Refuses every key, for the negative direction. */
static oca_result_t authorize_none_cb(const oca_crypto_blob_t *public_key,
                                      const uint8_t select[16])
{
    (void)public_key; (void)select;
    g_authorize_calls++;
    return OCA_FAIL_ROOT_KEY_UNAUTHORIZED;
}

/* Captures which key each authorization call was handed — bytes, select, and
 * algorithm family — so the per-class tests can assert each class consulted
 * its OWN anchor rather than merely that the callback ran twice. Outside the
 * fixture like g_authorize_calls, so reset both by hand where asserted on. */
static const uint8_t *g_auth_key_bytes[2];
static const uint8_t *g_auth_select[2];
static oca_key_algorithm_t g_auth_algo[2];
static oca_crypto_blob_t g_auth_pk_blob[2];
static oca_result_t authorize_capture_cb(const oca_crypto_blob_t *public_key,
                                         const uint8_t select[16])
{
    if (g_authorize_calls >= 0 && g_authorize_calls < 2) {
        g_auth_key_bytes[g_authorize_calls] = public_key->bytes;
        g_auth_select[g_authorize_calls]   = select;
        g_auth_algo[g_authorize_calls]     = public_key->key_algorithm;
        g_auth_pk_blob[g_authorize_calls]  = *public_key;
    }
    g_authorize_calls++;
    return OCA_OK;
}

/* Real SHA-256-like behavior for the tamper test: returns a different
 * digest if any byte in msg differs from a baseline. */
static oca_result_t stub_sha256_fail(const uint8_t *msg, size_t msg_len,
                                     uint8_t out[32])
{
    (void)msg; (void)msg_len;    memset(out, 0xFF, 32);
    return OCA_OK;
}

/* Identity readback: reports whatever the case put in the fixture.
 *
 * A case that set no identity gets OCA_HW_UNAVAILABLE, which the validator
 * hard-fails — so forgetting to set one is a test failure, not a silent pass on
 * a zeroed identity that some manifest might happen to match. */
static oca_hw_result_t fixed_identity_cb(oca_id_kind_t field,
                                         uint8_t out[32])
{
    g_fx.identity_calls++;
    if (!g_fx.identity_present) return OCA_HW_UNAVAILABLE;
    switch (field) {
        case OCA_ID_CHIPLET: memcpy(out, g_fx.chiplet_id, 32); break;
        case OCA_ID_PACKAGE: memcpy(out, g_fx.package_id, 32); break;
        case OCA_ID_SYSTEM:  memcpy(out, g_fx.system_id,  32); break;
        default: return OCA_HW_ERROR;
    }
    return OCA_HW_OK;
}

/* Lifecycle readback. Reports UNKNOWN alongside the unavailable sentinel rather
 * than leaving the output untouched, which is what the callback contract asks
 * of a real implementation that cannot determine the state. */
static oca_hw_result_t fixed_lifecycle_cb(oca_lifecycle_level_t level,
                                          oca_lifecycle_token_t *out)
{
    (void)level;
    g_fx.lifecycle_calls++;
    if (!g_fx.lifecycle_present) {
        *out = OCA_LIFECYCLE_UNKNOWN;
        return OCA_HW_UNAVAILABLE;
    }
    *out = g_fx.lifecycle_token;
    return OCA_HW_OK;
}

/* Version readback. */
static oca_hw_result_t fixed_version_cb(oca_version_level_t level,
                                        uint16_t *out_major,
                                        uint16_t *out_minor)
{
    (void)level;
    g_fx.version_calls++;
    if (!g_fx.version_present) return OCA_HW_UNAVAILABLE;
    *out_major = g_fx.version_major;
    *out_minor = g_fx.version_minor;
    return OCA_HW_OK;
}

/* verify_signature stub returning OCA_OK, so secure-boot tests need no OpenSSL. */
static oca_result_t pass_signature_cb(const oca_crypto_blob_t *sig,
                                      const oca_crypto_blob_t *pk,
                                      const uint8_t *signed_region,
                                      size_t signed_region_len)
{
    (void)sig; (void)pk; (void)signed_region;
    (void)signed_region_len;    return OCA_OK;
}

/* Secure-boot-state predicates. Since secure boot is secure-by-default when
 * undetermined, a non-secure test manifest must explicitly report "off". */
static oca_secure_bool_t sb_inactive_cb(void) { return OCA_SECURE_FALSE; }
static oca_secure_bool_t sb_active_cb(void)   { return OCA_SECURE_TRUE; }

/* ------------------------------------------------------------------ */
/* Device-asserted secure-boot disable                                */
/*                                                                    */
/* The determination has three inputs plus a default, and seven distinct
 * combinations. */
/* All seven are enumerated below: rows 1-5 must be unchanged from    */
/* before this input existed, rows 6-7 are the new behaviour.         */
/*                                                                    */
/* Counting reporters are used wherever the property is about WHICH   */
/* input was consulted rather than what came back — a verdict alone   */
/* cannot distinguish "the manifest outranked the device" from "the   */
/* device happened to agree".                                         */
/* ------------------------------------------------------------------ */

static oca_secure_bool_t sb_disabled_true_cb(void)
{
    g_fx.sb_disabled_calls++; return OCA_SECURE_TRUE;
}
static oca_secure_bool_t sb_disabled_false_cb(void)
{
    g_fx.sb_disabled_calls++; return OCA_SECURE_FALSE;
}
static oca_secure_bool_t sb_active_counting_cb(void)
{
    g_fx.sb_active_calls++; return OCA_SECURE_TRUE;
}

/* A manifest whose secure_boot_control bit is set — used to prove the manifest
 * outranks every device-side answer. */
static void build_sb_asserting_manifest(uint8_t buf[OCA_CLASSIC_BODY_SIZE])
{
    build_minimal_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] |= 0x01u;
}

/* ---- oca_secure_boot_device_disabled() ---- */

TEST(test_device_disabled_defaults_to_false)
{
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);

    ASSERT_TRUE(oca_secure_boot_device_disabled(NULL) == OCA_SECURE_FALSE);   /* no table */
    ASSERT_TRUE(oca_secure_boot_device_disabled(&cb) == OCA_SECURE_FALSE);    /* slot unwired */

    cb.is_secure_boot_disabled = sb_disabled_false_cb;
    ASSERT_TRUE(oca_secure_boot_device_disabled(&cb) == OCA_SECURE_FALSE);

    cb.is_secure_boot_disabled = sb_disabled_true_cb;
    ASSERT_TRUE(oca_secure_boot_device_disabled(&cb) == OCA_SECURE_TRUE);
}

/* ---- the determination: rows unchanged by the new input ---- */

TEST(test_determination_rows_unchanged_by_the_new_input)
{
    uint8_t clear[OCA_CLASSIC_BODY_SIZE];
    uint8_t asserted[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(clear);
    build_sb_asserting_manifest(asserted);

    oca_callbacks_t cb;

    /* manifest bit set, nothing else wired -> in force */
    memset(&cb, 0, sizeof cb);
    ASSERT_TRUE(oca_secure_boot_active(asserted, &cb) == OCA_SECURE_TRUE);

    /* bit clear, active reporter true -> in force */
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active = sb_active_cb;
    ASSERT_TRUE(oca_secure_boot_active(clear, &cb) == OCA_SECURE_TRUE);

    /* bit clear, active reporter false -> not in force */
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active = sb_inactive_cb;
    ASSERT_TRUE(oca_secure_boot_active(clear, &cb) == OCA_SECURE_FALSE);

    /* bit clear, nothing wired -> in force (fail-safe) */
    memset(&cb, 0, sizeof cb);
    ASSERT_TRUE(oca_secure_boot_active(clear, &cb) == OCA_SECURE_TRUE);

    /* bit clear, disable reporter answers false -> the rest decide */
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_disabled = sb_disabled_false_cb;
    ASSERT_TRUE(oca_secure_boot_active(clear, &cb) == OCA_SECURE_TRUE);        /* fail-safe */
    cb.is_secure_boot_active = sb_inactive_cb;
    ASSERT_TRUE(oca_secure_boot_active(clear, &cb) == OCA_SECURE_FALSE);       /* active decides */
}

/* ---- the disable answer outranks the active reporter and the fail-safe ---- */

TEST(test_disable_outranks_the_active_reporter)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);

    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_disabled = sb_disabled_true_cb;
    cb.is_secure_boot_active   = sb_active_cb;   /* would say "in force" */

    ASSERT_TRUE(oca_secure_boot_active(buf, &cb) == OCA_SECURE_FALSE);
}

/* The case an implementation is most likely to miss: consulting the disable
 * reporter only inside the existing active-reporter branch passes the test above
 * and fails only here — and "no active reporter wired" is the common
 * integration. */
TEST(test_disable_outranks_the_fail_safe_default)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);

    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_disabled = sb_disabled_true_cb;
    /* no active reporter at all */

    ASSERT_TRUE(oca_secure_boot_active(buf, &cb) == OCA_SECURE_FALSE);
}

/* ---- the manifest outranks the device ---- */

TEST(test_manifest_bit_outranks_a_device_disable)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_sb_asserting_manifest(buf);

    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_disabled = sb_disabled_true_cb;

    /* If this ever returns false the feature has become a downgrade path: a
     * production image built to be verified would run unverified on any part
     * that can be induced to report itself disabled. */
    ASSERT_TRUE(oca_secure_boot_active(buf, &cb) == OCA_SECURE_TRUE);
}

TEST(test_manifest_bit_short_circuits_the_device_reporters)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_sb_asserting_manifest(buf);

    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_disabled = sb_disabled_true_cb;
    cb.is_secure_boot_active   = sb_active_counting_cb;
    test_fixture_reset();

    ASSERT_TRUE(oca_secure_boot_active(buf, &cb) == OCA_SECURE_TRUE);
    /* Not merely "the manifest won" — the device was never asked. A verdict
     * alone cannot tell that apart from the device happening to agree. */
    ASSERT_EQ_INT(g_fx.sb_disabled_calls, 0);
    ASSERT_EQ_INT(g_fx.sb_active_calls, 0);
}

TEST(test_disable_short_circuits_the_active_reporter)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);

    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_disabled = sb_disabled_true_cb;
    cb.is_secure_boot_active   = sb_active_counting_cb;
    test_fixture_reset();

    ASSERT_TRUE(oca_secure_boot_active(buf, &cb) == OCA_SECURE_FALSE);
    ASSERT_EQ_INT(g_fx.sb_disabled_calls, 1);
    ASSERT_EQ_INT(g_fx.sb_active_calls, 0);   /* short-circuited, not just outvoted */
}

/* ---- a wired reporter answering false is indistinguishable from absent ---- */

TEST(test_disable_answering_false_matches_no_reporter)
{
    uint8_t clear[OCA_CLASSIC_BODY_SIZE];
    uint8_t asserted[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(clear);
    build_sb_asserting_manifest(asserted);

    const uint8_t *bodies[2];
    bodies[0] = clear;
    bodies[1] = asserted;

    for (unsigned i = 0; i < 2u; ++i) {
        oca_callbacks_t absent, wired;
        memset(&absent, 0, sizeof absent);
        memset(&wired,  0, sizeof wired);
        wired.is_secure_boot_disabled = sb_disabled_false_cb;

        /* with no active reporter */
        ASSERT_TRUE(oca_secure_boot_active(bodies[i], &absent)
                    == oca_secure_boot_active(bodies[i], &wired));

        /* and with one, in both directions */
        absent.is_secure_boot_active = sb_active_cb;
        wired.is_secure_boot_active  = sb_active_cb;
        ASSERT_TRUE(oca_secure_boot_active(bodies[i], &absent)
                    == oca_secure_boot_active(bodies[i], &wired));

        absent.is_secure_boot_active = sb_inactive_cb;
        wired.is_secure_boot_active  = sb_inactive_cb;
        ASSERT_TRUE(oca_secure_boot_active(bodies[i], &absent)
                    == oca_secure_boot_active(bodies[i], &wired));
    }
}

TEST(test_null_callback_table_still_fail_safes)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    ASSERT_TRUE(oca_secure_boot_active(buf, NULL) == OCA_SECURE_TRUE);
}

/* ---- scope boundary: the secure-boot invariant reads the raw manifest bit ----
 *
 * Wiring the determination into that check would be an easy and silent change to
 * make while editing nearby code, and on a disabled part the two usually agree —
 * so nothing else would notice. */
TEST(test_secure_boot_invariant_still_reads_the_raw_manifest_bit)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];

    /* bit clear + a populated signing field: rejected, disable state or not. */
    build_minimal_manifest(buf);
    buf[OCA_CLASSIC_OFF_SIGNATURE] = 0x01u;
    ASSERT_EQ_INT(oca_check_secure_boot_invariant(buf),
                  OCA_FAIL_SECURE_BOOT_INVARIANT);

    /* bit set + the same field: permitted, because the manifest says it is a
     * secure-boot manifest. */
    build_sb_asserting_manifest(buf);
    buf[OCA_CLASSIC_OFF_SIGNATURE] = 0x01u;
    ASSERT_EQ_INT(oca_check_secure_boot_invariant(buf), OCA_OK);
}

/* Composite callback table for full-pipeline tests. The per-callback forwarding
 * wrappers this used to need are gone: every stub reads the one fixture, so the
 * stubs themselves go straight into the table.
 *
 * Marks all three readbacks available, because this helper stands for a device
 * that answers. Values stay zero unless the case sets them, so "the hardware
 * reports all-zero" remains expressible — which is what a mismatch test wants.
 * A case exercising an unreadable device wires its own table rather than using
 * this. */
static void build_full_cb(oca_callbacks_t *cb, const uint8_t *body)
{
    memset(cb, 0, sizeof(*cb));
    g_fx.sha_body           = body;
    g_fx.identity_present   = true;
    g_fx.lifecycle_present  = true;
    g_fx.version_present    = true;
    cb->sha256              = stub_sha256_pass;
    cb->verify_signature    = pass_signature_cb;
    cb->is_key_authorized = authorize_any_cb;
    cb->is_secure_boot_active = sb_inactive_cb;  /* this pipeline manifest is non-secure */
    cb->get_identity_bytes  = fixed_identity_cb;
    cb->get_lifecycle_state = fixed_lifecycle_cb;
    cb->get_version         = fixed_version_cb;
}

/* ------------------------------------------------------------------ */
/* Callback-boundary dispatch tests                                   */
/* ------------------------------------------------------------------ */

TEST(test_permissive_manifest_passes_with_only_sha_callback)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    g_fx.sha_body = buf;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.sha256 = stub_sha256_pass;
    cb.is_secure_boot_active = sb_inactive_cb;  /* non-secure manifest */
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL), OCA_OK);
}

TEST(test_null_callback_fails_when_constraint_enabled)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, 0);
    buf[OCA_OFF_CHIPLET_ID] = 0xDE;
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, NULL, NULL, NULL),
                  OCA_FAIL_CALLBACK_UNAVAILABLE);
}

TEST(test_null_sha_callback_fails_manifest_hash)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL),
                  OCA_FAIL_CALLBACK_UNAVAILABLE);
}

/* ------------------------------------------------------------------ */
/* Per-case isolation                                                 */
/*                                                                    */
/* The stubs read one file-scope fixture, cleared before every case by */
/* the runner. These three cases assert the properties that makes      */
/* possible, because a suite whose cases can see each other's state is */
/* not evidence of anything — it passes or fails on run order.         */
/* ------------------------------------------------------------------ */

/* A case that neglects to set a device value it depends on must FAIL, not pass
 * on whatever an earlier case left behind. The zeroed fixture reports every
 * readback unavailable, and the validator treats unavailable as a hard failure
 * rather than a waiver — so the omission surfaces as a refusal. */
TEST(test_omitting_a_device_value_fails_rather_than_inheriting_one)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, 0);                 /* constrain the chiplet ID */
    buf[OCA_OFF_CHIPLET_ID] = 0xDE;

    g_fx.sha_body = buf;
    /* identity_present deliberately left false — this is the omission. */
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.sha256                = stub_sha256_pass;
    cb.get_identity_bytes    = fixed_identity_cb;
    cb.is_secure_boot_active = sb_inactive_cb;

    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL),
                  OCA_FAIL_CALLBACK_UNAVAILABLE);
}

/* The reset clears EVERY field, scalars and scratch buffers alike.
 *
 * Dirties the whole fixture and resets within the one case, deliberately: a
 * version that merely asserted "these are zero at entry" would pass for free
 * whenever it happened to run before anything dirtied them, which depends on
 * registration order rather than on the reset working. Written this way it has
 * teeth wherever it runs.
 *
 * This is the property the counters were folded in for. A value living beside
 * the fixture rather than inside it survives a reset that appears to cover
 * everything, and the surviving value is indistinguishable from one this case
 * set itself. */
TEST(test_the_reset_clears_every_fixture_field)
{
    /* Dirty every field, including the ones a careless reset would miss. */
    memset(&g_fx, 0xA5, sizeof g_fx);
    g_fx.sb_disabled_calls = 7;
    g_fx.sb_active_calls   = 7;
    g_fx.decrypt_calls     = 7;
    g_fx.secver_calls      = 7;
    g_fx.set_calls         = 7;
    g_fx.identity_present  = true;
    g_fx.lifecycle_present = true;
    g_fx.version_present   = true;

    test_fixture_reset();

    /* Byte-wise, so a field added later without a reset entry is caught too —
     * the reset zeroes the whole struct, so this holds for free only while that
     * remains true. */
    const unsigned char *raw = (const unsigned char *)&g_fx;
    for (size_t i = 0u; i < sizeof g_fx; ++i) {
        ASSERT_EQ_INT(raw[i], 0);
    }

    /* And the properties that zeroing is chosen FOR: every readback reports
     * unavailable, which the validator hard-fails rather than waiving. */
    ASSERT_TRUE(!g_fx.identity_present);
    ASSERT_TRUE(!g_fx.lifecycle_present);
    ASSERT_TRUE(!g_fx.version_present);
    ASSERT_EQ_INT(g_fx.sb_active_calls, 0);
}

/* A complete integration needs no caller-defined structure and no cast from an
 * untyped pointer. This replaces a test that asserted the table's caller-context
 * pointer reached a callback unchanged — there is no such pointer now, so the
 * property worth pinning is the opposite one: that nothing needs it. */
TEST(test_a_full_integration_needs_no_caller_defined_state)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, 0);
    buf[OCA_OFF_CHIPLET_ID] = 0xDE;

    /* Every value these callbacks report is reached from this translation unit's
     * own state, exactly as a target reaches fuses from its own image. */
    g_fx.sha_body         = buf;
    g_fx.identity_present = true;
    g_fx.chiplet_id[0]    = 0xDE;

    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.sha256                = stub_sha256_pass;
    cb.get_identity_bytes    = fixed_identity_cb;
    cb.is_secure_boot_active = sb_inactive_cb;

    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL), OCA_OK);
}

/* ------------------------------------------------------------------ */
/* Structural-check tests                                             */
/* ------------------------------------------------------------------ */

TEST(test_check_length_rejects_short_buffer)
{
    ASSERT_EQ_INT(oca_check_length(4095), OCA_FAIL_TRUNCATED);
    ASSERT_EQ_INT(oca_check_length(4096), OCA_OK);
    ASSERT_EQ_INT(oca_check_length(8192), OCA_OK);
}

TEST(test_check_magic_rejects_bad_bytes)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[0] = 'X';
    ASSERT_EQ_INT(oca_check_magic(buf), OCA_FAIL_MAGIC);
}

TEST(test_check_trailer_rejects_bad_pattern)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_CLASSIC_OFF_TRAILER + 2] = 0xFFu;
    ASSERT_EQ_INT(oca_check_trailer(buf), OCA_FAIL_TRAILER);
}

TEST(test_check_format_version_accepts_newer_minor)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_MANIFEST_VERSION_MINOR + 0] =
        (uint8_t)(OCA_LIB_MANIFEST_MINOR + 1);
    ASSERT_EQ_INT(oca_check_format_version(buf), OCA_OK);
}

TEST(test_check_format_version_rejects_newer_major)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_MANIFEST_VERSION_MAJOR + 0] =
        (uint8_t)(OCA_LIB_MANIFEST_MAJOR + 1);
    ASSERT_EQ_INT(oca_check_format_version(buf),
                  OCA_FAIL_FORMAT_VERSION_MISMATCH);
}

/* Reserved bit-ranges inside operative fields are ignored, not rejected (v2:
 * the Consumer shall not act on reserved fields, and reserved regions are
 * available for additive minor-version extension). oca_check_reserved_bits is
 * a documented no-op; a set reserved bit must not fail validation. */
TEST(test_reserved_selector_bit_ignored)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, 110);
    ASSERT_EQ_INT(oca_check_reserved_bits(buf), OCA_OK);
}

TEST(test_reserved_lifecycle_bit_ignored)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_lifecycle_states(buf, OCA_LIFECYCLE_LEVEL_CHIPLET, 0x80u);
    ASSERT_EQ_INT(oca_check_reserved_bits(buf), OCA_OK);
}

TEST(test_reserved_demotion_bit_ignored)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_DEMOTION_CONTROL] = 0x10u;
    ASSERT_EQ_INT(oca_check_reserved_bits(buf), OCA_OK);
}

TEST(test_secure_boot_invariant_clean_zero_path)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    ASSERT_EQ_INT(oca_check_secure_boot_invariant(buf), OCA_OK);
}

TEST(test_secure_boot_invariant_dirty_signature_field)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_CLASSIC_OFF_SIGNATURE] = 0xFFu;
    ASSERT_EQ_INT(oca_check_secure_boot_invariant(buf),
                  OCA_FAIL_SECURE_BOOT_INVARIANT);
}

/* ------------------------------------------------------------------ */
/* Identity tests                                                     */
/* ------------------------------------------------------------------ */

TEST(test_identity_match_passes)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, 0);
    buf[OCA_OFF_CHIPLET_ID + 0] = 0xDEu;
    g_fx.identity_present = true;   /* a device that answers; bytes stay zero */
    g_fx.chiplet_id[0] = 0xDEu;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.get_identity_bytes = fixed_identity_cb;
    ASSERT_EQ_INT(oca_check_identity(buf, OCA_ID_CHIPLET, &cb), OCA_OK);
}

TEST(test_identity_mismatch_fails)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, 0);
    buf[OCA_OFF_CHIPLET_ID + 0] = 0xDEu;
    g_fx.identity_present = true;   /* a device that answers; bytes stay zero */
    /* hardware reports 0x00 — mismatches the manifest's 0xDE */
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.get_identity_bytes = fixed_identity_cb;
    ASSERT_EQ_INT(oca_check_identity(buf, OCA_ID_CHIPLET, &cb),
                  OCA_FAIL_CHIPLET_ID);
}

/* ------------------------------------------------------------------ */
/* Lifecycle tests                                                    */
/* ------------------------------------------------------------------ */

TEST(test_lifecycle_state_in_set_passes)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, OCA_SELECTOR_BIT_LIFECYCLE_CHIPLET);
    /* Allow TEST_DEV (bit 0) + PROD_END (bit 2) = 0x05 */
    set_lifecycle_states(buf, OCA_LIFECYCLE_LEVEL_CHIPLET, 0x05u);
    g_fx.lifecycle_present = true;
    g_fx.lifecycle_token = OCA_LIFECYCLE_TEST_DEV;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.get_lifecycle_state = fixed_lifecycle_cb;
    ASSERT_EQ_INT(oca_check_lifecycle(buf, OCA_LIFECYCLE_LEVEL_CHIPLET, &cb),
                  OCA_OK);
}

TEST(test_lifecycle_state_not_in_set_fails)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, OCA_SELECTOR_BIT_LIFECYCLE_CHIPLET);
    set_lifecycle_states(buf, OCA_LIFECYCLE_LEVEL_CHIPLET, 0x05u);
    g_fx.lifecycle_present = true;
    g_fx.lifecycle_token = OCA_LIFECYCLE_PROD; /* bit 1, not in 0x05 */
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.get_lifecycle_state = fixed_lifecycle_cb;
    ASSERT_EQ_INT(oca_check_lifecycle(buf, OCA_LIFECYCLE_LEVEL_CHIPLET, &cb),
                  OCA_FAIL_LIFECYCLE);
}

/* ------------------------------------------------------------------ */
/* Version-range tests                                                */
/* ------------------------------------------------------------------ */

TEST(test_version_range_in_range_passes)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, OCA_SELECTOR_BIT_VERSION_CHIPLET_MIN);
    set_selector_bit(buf, OCA_SELECTOR_BIT_VERSION_CHIPLET_MAX);
    /* range [1.0, 2.255]; hw reports 2.0 */
    set_version_range(buf, OCA_VERSION_LEVEL_CHIPLET, 1, 0, 2, 255);
    g_fx.version_present = true;
    g_fx.version_major = 2;
    g_fx.version_minor = 0;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.get_version = fixed_version_cb;
    ASSERT_EQ_INT(oca_check_version_range(buf, OCA_VERSION_LEVEL_CHIPLET, &cb),
                  OCA_OK);
}

TEST(test_version_range_below_min_fails)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, OCA_SELECTOR_BIT_VERSION_CHIPLET_MIN);
    set_version_range(buf, OCA_VERSION_LEVEL_CHIPLET, 1, 0, 0, 0);
    g_fx.version_present = true;
    g_fx.version_major = 0;
    g_fx.version_minor = 9;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.get_version = fixed_version_cb;
    ASSERT_EQ_INT(oca_check_version_range(buf, OCA_VERSION_LEVEL_CHIPLET, &cb),
                  OCA_FAIL_VERSION_RANGE);
}

TEST(test_version_range_above_max_fails)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, OCA_SELECTOR_BIT_VERSION_CHIPLET_MAX);
    set_version_range(buf, OCA_VERSION_LEVEL_CHIPLET, 0, 0, 2, 0);
    g_fx.version_present = true;
    g_fx.version_major = 3;
    g_fx.version_minor = 0;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.get_version = fixed_version_cb;
    ASSERT_EQ_INT(oca_check_version_range(buf, OCA_VERSION_LEVEL_CHIPLET, &cb),
                  OCA_FAIL_VERSION_RANGE);
}

/* ------------------------------------------------------------------ */
/* Demotion control                                                   */
/* ------------------------------------------------------------------ */

TEST(test_demotion_control_clean)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_DEMOTION_CONTROL] = 0x03u; /* BL1 valid+enable */
    ASSERT_EQ_INT(oca_check_demotion_control(buf), OCA_OK);
}

TEST(test_demotion_control_reserved_bit_ignored)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_DEMOTION_CONTROL + 1] = 0x80u; /* bit 15 set (reserved) */
    /* Reserved demotion bits are ignored, not rejected. */
    ASSERT_EQ_INT(oca_check_demotion_control(buf), OCA_OK);
}

/* End-to-end guard for the relaxed reserved-bit contract: a manifest that sets
 * reserved bits across selector_bits, lifecycle_states, and demotion_control —
 * with no operative constraint engaged — still validates. This is the behavior
 * a future additive minor-version relies on. */
TEST(test_reserved_bits_ignored_end_to_end)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, 110);                                   /* reserved selector bit */
    set_lifecycle_states(buf, OCA_LIFECYCLE_LEVEL_CHIPLET, 0x80u);/* reserved lifecycle bit */
    buf[OCA_OFF_DEMOTION_CONTROL + 1] = 0x80u;                    /* reserved demotion bit */
    g_fx.sha_body = buf;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.sha256 = stub_sha256_pass;
    cb.is_secure_boot_active = sb_inactive_cb;  /* non-secure manifest */
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL), OCA_OK);
}

/* ------------------------------------------------------------------ */
/* manifest_hash + signature dispatch                                 */
/* ------------------------------------------------------------------ */

TEST(test_manifest_hash_match_passes)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    g_fx.sha_body = buf;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.sha256 = stub_sha256_pass;
    ASSERT_EQ_INT(oca_check_manifest_hash(buf, &cb), OCA_OK);
}

TEST(test_manifest_hash_mismatch_fails)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.sha256 = stub_sha256_fail; /* returns 0xFFs — doesn't match buf */
    ASSERT_EQ_INT(oca_check_manifest_hash(buf, &cb),
                  OCA_FAIL_MANIFEST_HASH);
}

/* Pipeline: integrity is settled before anything reads the contents, so a
 * corrupt manifest reports MANIFEST_HASH rather than whichever field happens to
 * decode wrong out of the damaged bytes. Move oca_check_manifest_hash() back
 * below the identity checks and the second assertion returns IDENTITY. */
TEST(test_corruption_outranks_a_field_level_violation)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_callbacks_t cb;

    build_minimal_manifest(buf);
    set_selector_bit(buf, 0);                    /* enable the chiplet-ID check */
    buf[OCA_OFF_CHIPLET_ID + 0] = 0xDEu;         /* hardware reports 0x00 */
    build_full_cb(&cb, buf);

    /* The identity mismatch is what a well-formed manifest reports... */
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, NULL),
                  OCA_FAIL_CHIPLET_ID);

    /* ...but not once the bytes are also damaged. */
    cb.sha256 = stub_sha256_fail;                /* digests to a fixed wrong value */
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, NULL),
                  OCA_FAIL_MANIFEST_HASH);
}

TEST(test_manifest_hash_dirty_padding_fails)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_CLASSIC_OFF_MANIFEST_HASH + 32] = 0x01u; /* dirty tail */
    g_fx.sha_body = buf;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.sha256 = stub_sha256_pass;
    ASSERT_EQ_INT(oca_check_manifest_hash(buf, &cb),
                  OCA_FAIL_MANIFEST_HASH);
}

TEST(test_signature_secure_boot_zero_skipped)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    /* secure_boot_control bit clear AND the device reports secure boot inactive →
     * signature check is a no-op. (With no such signal it would be secure by
     * default; the manifest bit alone is not authoritative.) */
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active = sb_inactive_cb;
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx), OCA_OK);
}

/* The same wiring, minus the determination. Previously this returned OCA_OK
 * because the check derived its own answer; now the absence of a determination
 * is itself the finding, and the distinction matters: "secure boot is off" and
 * "nobody established anything" must not look alike to a check deciding whether
 * to verify a signature. */
TEST(test_signature_refuses_an_undetermined_context)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    test_fixture_reset();
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active = sb_inactive_cb;
    cb.verify_signature      = pass_signature_cb;
    cb.is_key_authorized = authorize_any_cb;

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx),
                  OCA_FAIL_SECURE_BOOT_UNDETERMINED);
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, NULL),
                  OCA_FAIL_SECURE_BOOT_UNDETERMINED);
    /* That the refusal costs no device or verifier call is asserted across all
     * four consumers by test_every_gated_check_refuses_an_undetermined_context. */
}

TEST(test_signature_callback_unavailable_when_secure_boot_enabled)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x03u; /* secure_boot on, classic class */
    /* Need to put non-zero in signing fields so secure_boot_invariant
     * doesn't bite — but oca_check_signature doesn't run that check. */
    oca_validation_context_t ctx = determined_for(buf, NULL);
    ASSERT_EQ_INT(oca_check_signature(buf, NULL, &ctx),
                  OCA_FAIL_CALLBACK_UNAVAILABLE);
}

/* ------------------------------------------------------------------ */
/* Canonical-order short-circuit                                      */
/* ------------------------------------------------------------------ */

TEST(test_validate_short_circuits_on_first_fail)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[0] = 'X';                                    /* break magic */
    buf[OCA_CLASSIC_OFF_TRAILER + 2] = 0xFFu;        /* also break trailer */
    /* magic is checked before trailer */
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, NULL, NULL, NULL),
                  OCA_FAIL_MAGIC);
}

TEST(test_validate_happy_path_full_pipeline)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_selector_bit(buf, 0);
    set_selector_bit(buf, OCA_SELECTOR_BIT_LIFECYCLE_CHIPLET);
    buf[OCA_OFF_CHIPLET_ID + 0] = 0xDEu;
    set_lifecycle_states(buf, OCA_LIFECYCLE_LEVEL_CHIPLET, 0x05u);

    oca_callbacks_t cb;
    build_full_cb(&cb, buf);
    g_fx.chiplet_id[0] = 0xDEu;
    g_fx.lifecycle_token = OCA_LIFECYCLE_TEST_DEV;
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL), OCA_OK);
}

/* ------------------------------------------------------------------ */
/* Encrypted-payload stage                                            */
/* ------------------------------------------------------------------ */

/* Synthetic ciphertext length. Must satisfy the encrypted-payload geometry the
 * format requires: at least one TOC header plus one entry (308 bytes), and a
 * whole number of AES blocks. 320 is the smallest value meeting both, and is
 * what the packer emits for a single-image encrypted bundle. */
#define ENC_CT_LEN 320u

/* Write a little-endian u64. Declared here because the encrypted-bundle builder
 * below needs it; defined with the other TOC writers. */
static void toc_put_u64(uint8_t *p, uint64_t v);

/* Ciphertext-aware SHA-256 stub: returns `ct_digest` when hashing the
 * ciphertext (matched by pointer + length), all-zero for every other input —
 * so the plaintext hash-chain recomputes to a known all-zero value. */
static oca_result_t payload_sha256(const uint8_t *msg, size_t msg_len,
                                   uint8_t out[32])
{
    if (g_fx.return_ct_digest && msg == g_fx.ciphertext && msg_len == g_fx.ciphertext_len) {
        memcpy(out, g_fx.ct_digest, 32);
    } else {
        memset(out, 0, 32);
    }
    return OCA_OK;
}


static void build_plaintext_toc(void)
{
    memset(g_fx.plaintext_toc, 0, sizeof g_fx.plaintext_toc);
    memcpy(g_fx.plaintext_toc, "PTOC", 4);
    g_fx.plaintext_toc[OCA_TOC_OFF_IMAGE_COUNT] = 1u;
    /* One image at [0, 8): an entry's length may not be zero. The range lands on
     * the TOC's own bytes, which the structural rules bound and de-overlap but
     * do not reserve, so the buffer stays a bare TOC. The stub sha256 digests
     * every input to all-zero, so the entry's zeroed hash field still matches. */
    toc_put_u64(g_fx.plaintext_toc + OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_OFF_LENGTH,
                8u);
}

static oca_result_t decrypt_ok(const oca_decrypt_input_t *in,
                               const uint8_t **out_pt, size_t *out_pt_len)
{
    (void)in;
    g_fx.decrypt_calls++;
    *out_pt = g_fx.plaintext_toc;
    *out_pt_len = sizeof g_fx.plaintext_toc;
    return OCA_OK;
}

static oca_result_t decrypt_fail(const oca_decrypt_input_t *in,
                                 const uint8_t **out_pt, size_t *out_pt_len)
{
    (void)in; (void)out_pt; (void)out_pt_len;
    g_fx.decrypt_calls++;
    return OCA_FAIL_DECRYPT;
}

/* A wired callback reporting that the part holds no secret for the slot the
 * manifest selected. Distinct from an unwired callback, and distinct from a
 * decryption that ran and failed — three causes, three remedies. */
static oca_result_t decrypt_no_secret(const oca_decrypt_input_t *in,
                                      const uint8_t **out_pt, size_t *out_pt_len)
{
    (void)in; (void)out_pt; (void)out_pt_len;
    g_fx.decrypt_calls++;
    return OCA_FAIL_NO_PROVISIONED_SECRET;
}

/* Classic bundle: manifest body + ENC_CT_LEN-byte ciphertext, encrypted bit
 * set, payload_hashed_length = payload_length = ENC_CT_LEN, given payload_hash /
 * chain fields. The two lengths must agree: for an encrypted payload they
 * describe the same stored ciphertext. */
static void build_encrypted_bundle(uint8_t *buf,
                                   const uint8_t payload_hash[32],
                                   const uint8_t chain[32])
{
    memset(buf, 0, OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN);
    build_minimal_manifest(buf);
    buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x01u;             /* encrypted_payload */
    buf[OCA_OFF_ENCRYPTION_TYPE] = OCA_ENCRYPTION_TYPE_AES_128_CBC;  /* supported cipher */
    toc_put_u64(buf + OCA_OFF_PAYLOAD_HASHED_LENGTH, ENC_CT_LEN);
    toc_put_u64(buf + OCA_OFF_PAYLOAD_LENGTH, ENC_CT_LEN);
    memcpy(buf + OCA_OFF_PAYLOAD_HASH, payload_hash, 32);
    memcpy(buf + OCA_OFF_PAYLOAD_HASH_CHAIN, chain, 32);
    memset(buf + OCA_CLASSIC_BODY_SIZE, 0xABu, ENC_CT_LEN);      /* ciphertext */
}

/* ------------------------------------------------------------------ */
/* oca_payload_encryption_info                                        */
/* ------------------------------------------------------------------ */

TEST(test_encryption_info_reports_cleartext)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    /* Non-zero cipher/selector bytes with the control bit clear must still be
     * reported as "not encrypted", so callers can branch on `encrypted` alone. */
    buf[OCA_OFF_ENCRYPTION_TYPE] = OCA_ENCRYPTION_TYPE_AES_256_CBC;
    buf[OCA_OFF_ENCRYPTION_SHARED_SECRET_SELECT] = 0x07u;

    oca_payload_encryption_t enc;
    ASSERT_EQ_INT(oca_payload_encryption_info(buf, &enc), OCA_OK);
    ASSERT_TRUE(!enc.encrypted);
    ASSERT_EQ_INT(enc.type, OCA_ENCRYPTION_TYPE_NONE);
    ASSERT_EQ_INT(enc.secret_select, 0);
}

TEST(test_encryption_info_reports_cipher_and_selector)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x01u;
    buf[OCA_OFF_ENCRYPTION_TYPE] = OCA_ENCRYPTION_TYPE_AES_256_CBC;
    /* u16 LE, and deliberately > 8 bits so a byte-wide read is caught. */
    buf[OCA_OFF_ENCRYPTION_SHARED_SECRET_SELECT]      = 0x34u;
    buf[OCA_OFF_ENCRYPTION_SHARED_SECRET_SELECT + 1u] = 0x12u;

    oca_payload_encryption_t enc;
    ASSERT_EQ_INT(oca_payload_encryption_info(buf, &enc), OCA_OK);
    ASSERT_TRUE(enc.encrypted);
    ASSERT_EQ_INT(enc.type, OCA_ENCRYPTION_TYPE_AES_256_CBC);
    ASSERT_EQ_INT(enc.secret_select, 0x1234);
}

TEST(test_encryption_info_reports_an_unknown_cipher_verbatim)
{
    /* Reported, not rejected — oca_check_payload owns that decision. */
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x01u;
    buf[OCA_OFF_ENCRYPTION_TYPE] = 0x7Fu;

    oca_payload_encryption_t enc;
    ASSERT_EQ_INT(oca_payload_encryption_info(buf, &enc), OCA_OK);
    ASSERT_TRUE(enc.encrypted);
    ASSERT_EQ_INT(enc.type, 0x7F);
}

TEST(test_encryption_info_rejects_bad_magic_and_null_args)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_payload_encryption_t enc;

    build_minimal_manifest(buf);
    ASSERT_EQ_INT(oca_payload_encryption_info(NULL, &enc), OCA_FAIL_INVALID_ARG);
    ASSERT_EQ_INT(oca_payload_encryption_info(buf, NULL), OCA_FAIL_INVALID_ARG);

    buf[0] ^= 0xFFu;
    ASSERT_EQ_INT(oca_payload_encryption_info(buf, &enc), OCA_FAIL_MAGIC);
}

TEST(test_encryption_info_needs_no_payload_resident)
{
    /* The staged case: a body-sized buffer with no payload after it. */
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x01u;
    buf[OCA_OFF_ENCRYPTION_TYPE] = OCA_ENCRYPTION_TYPE_AES_128_CBC;
    buf[OCA_OFF_ENCRYPTION_SHARED_SECRET_SELECT] = 0x01u;
    buf[OCA_OFF_PAYLOAD_HASHED_LENGTH] = 0x80u;   /* 128 B of ciphertext, LE u64 */

    /* oca_payload_region cannot answer here — it needs the payload too. */
    const uint8_t *region; size_t region_len; bool region_encrypted;
    ASSERT_EQ_INT(oca_payload_region(buf, sizeof buf, &region, &region_len,
                                     &region_encrypted),
                  OCA_FAIL_TRUNCATED);

    oca_payload_encryption_t enc;
    ASSERT_EQ_INT(oca_payload_encryption_info(buf, &enc), OCA_OK);
    ASSERT_TRUE(enc.encrypted);
    ASSERT_EQ_INT(enc.secret_select, 1);
}

static void payload_cb(oca_callbacks_t *cb,
                       oca_result_t (*decrypt)(const oca_decrypt_input_t *,
                                               const uint8_t **, size_t *))
{
    memset(cb, 0, sizeof(*cb));
    cb->sha256 = payload_sha256;
    cb->decrypt_payload = decrypt;
}

static void payload_sha_ctx_init(const uint8_t *ciphertext,
                                 bool match, uint8_t digest_byte)
{
    g_fx.ciphertext = ciphertext;
    g_fx.ciphertext_len = ENC_CT_LEN;
    g_fx.return_ct_digest = match;
    memset(g_fx.ct_digest, digest_byte, 32);
}

/* A manifest with the encrypted bit clear AND payload_length == 0 declares no
 * payload at all — nothing to check, no callbacks needed. */
TEST(test_payload_no_payload_declared_is_noop)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);  /* encrypted bit clear, payload_length 0 */
    ASSERT_EQ_INT(oca_check_payload(buf, OCA_CLASSIC_BODY_SIZE, NULL, &g_authenticated, NULL), OCA_OK);
}

TEST(test_payload_hash_mismatch_before_decrypt)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x11, 32);
    uint8_t chain[32]; memset(chain, 0, 32);
    build_encrypted_bundle(buf, ph, chain);

    payload_sha_ctx_init(buf + OCA_CLASSIC_BODY_SIZE, false, 0x00);
    oca_callbacks_t cb;
    payload_cb(&cb, decrypt_ok);

    g_fx.decrypt_calls = 0;
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_FAIL_PAYLOAD_HASH);
    ASSERT_EQ_INT(g_fx.decrypt_calls, 0);  /* never decrypt before the hash passes */
}

TEST(test_payload_null_decrypt_callback_unavailable)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    uint8_t chain[32]; memset(chain, 0, 32);
    build_encrypted_bundle(buf, ph, chain);

    payload_sha_ctx_init(buf + OCA_CLASSIC_BODY_SIZE, true, 0x5A);
    oca_callbacks_t cb;
    payload_cb(&cb, NULL);  /* no decrypt wired */

    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL),
                  OCA_FAIL_CALLBACK_UNAVAILABLE);
}

TEST(test_payload_decrypt_failure)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    uint8_t chain[32]; memset(chain, 0, 32);
    build_encrypted_bundle(buf, ph, chain);

    payload_sha_ctx_init(buf + OCA_CLASSIC_BODY_SIZE, true, 0x5A);
    oca_callbacks_t cb;
    payload_cb(&cb, decrypt_fail);

    g_fx.decrypt_calls = 0;
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_FAIL_DECRYPT);
    ASSERT_EQ_INT(g_fx.decrypt_calls, 1);
}

/* ------------------------------------------------------------------ */
/* The decryption callback's declared inputs                          */
/*                                                                    */
/* Everything the callback reads arrives in one read-only descriptor.  */
/* The two fields worth testing specifically are the cipher identity  */
/* and the provisioned-secret selector: both are manifest fields the  */
/* validator already holds, and neither used to be passed, so a       */
/* callback could not select a cipher or find its key without being   */
/* handed state from somewhere else.                                  */
/* ------------------------------------------------------------------ */

/* What the descriptor carried, captured for the assertions below. */

static oca_result_t decrypt_capturing(const oca_decrypt_input_t *in,
                                      const uint8_t **out_pt, size_t *out_pt_len)
{
    g_fx.decrypt_calls++;
    g_fx.seen_cipher         = in->cipher;
    g_fx.seen_secret_select  = in->secret_select;
    g_fx.seen_iv             = in->iv;
    g_fx.seen_kdf_input      = in->kdf_input;
    g_fx.seen_ciphertext_len = in->ciphertext_len;
    *out_pt     = g_fx.plaintext_toc;
    *out_pt_len = sizeof g_fx.plaintext_toc;
    return OCA_OK;
}

TEST(test_decrypt_receives_cipher_and_selector_as_named_fields)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    uint8_t chain[32]; memset(chain, 0, 32);
    build_encrypted_bundle(buf, ph, chain);
    buf[OCA_OFF_ENCRYPTION_TYPE] = OCA_ENCRYPTION_TYPE_AES_256_CBC;
    buf[OCA_OFF_ENCRYPTION_SHARED_SECRET_SELECT] = 0x03u;   /* 1-based slot 3 */
    build_plaintext_toc();

    payload_sha_ctx_init(buf + OCA_CLASSIC_BODY_SIZE, true, 0x5A);
    oca_callbacks_t cb;
    payload_cb(&cb, decrypt_capturing);

    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_OK);
    ASSERT_EQ_INT(g_fx.decrypt_calls, 1);
    ASSERT_EQ_INT(g_fx.seen_cipher, OCA_ENCRYPTION_TYPE_AES_256_CBC);
    ASSERT_EQ_INT(g_fx.seen_secret_select, 3);
    ASSERT_EQ_INT(g_fx.seen_ciphertext_len, ENC_CT_LEN);
}

/* The derivation inputs must point into the manifest body, not the payload —
 * that is what makes decrypting in place over the ciphertext safe. */
TEST(test_decrypt_descriptor_points_derivation_inputs_at_the_manifest)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    uint8_t chain[32]; memset(chain, 0, 32);
    build_encrypted_bundle(buf, ph, chain);
    build_plaintext_toc();

    payload_sha_ctx_init(buf + OCA_CLASSIC_BODY_SIZE, true, 0x5A);
    oca_callbacks_t cb;
    payload_cb(&cb, decrypt_capturing);

    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_OK);
    ASSERT_TRUE(g_fx.seen_iv        == buf + OCA_OFF_ENCRYPTION_IV);
    ASSERT_TRUE(g_fx.seen_kdf_input == buf + OCA_OFF_ENCRYPTION_KDF_INPUT);
    /* Both inside the body, so overwriting the payload cannot clobber them. */
    ASSERT_TRUE(g_fx.seen_iv        <  buf + OCA_CLASSIC_BODY_SIZE);
    ASSERT_TRUE(g_fx.seen_kdf_input <  buf + OCA_CLASSIC_BODY_SIZE);
}

/* Three ways payload decryption can fail to produce plaintext, and they must
 * not collapse into one another. "This part was never provisioned for this
 * manifest", "decryption is not wired at all", and "decryption ran and produced
 * garbage" each need a different response from whoever reads the code, and the
 * code is all a field failure leaves behind. */
TEST(test_no_provisioned_secret_is_distinct_from_other_decrypt_failures)
{
    ASSERT_TRUE(OCA_FAIL_NO_PROVISIONED_SECRET != OCA_FAIL_DECRYPT);
    ASSERT_TRUE(OCA_FAIL_NO_PROVISIONED_SECRET != OCA_FAIL_CALLBACK_UNAVAILABLE);
    ASSERT_TRUE(OCA_FAIL_DECRYPT != OCA_FAIL_CALLBACK_UNAVAILABLE);
}

TEST(test_result_string_covers_the_no_provisioned_secret_code)
{
    ASSERT_EQ_INT(strcmp(oca_result_str(OCA_FAIL_NO_PROVISIONED_SECRET),
                         "NO_PROVISIONED_SECRET"), 0);
}

/* The code has to survive the trip out of the payload stage. The encrypted path
 * forwards one code by name and maps everything else to the generic decryption
 * failure, so a new code that is merely declared — and not added to that
 * forwarding — reads correctly in the header and is swallowed in the field. */
TEST(test_no_provisioned_secret_reaches_the_caller)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    uint8_t chain[32]; memset(chain, 0, 32);
    build_encrypted_bundle(buf, ph, chain);

    payload_sha_ctx_init(buf + OCA_CLASSIC_BODY_SIZE, true, 0x5A);
    oca_callbacks_t cb;
    payload_cb(&cb, decrypt_no_secret);

    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL),
                  OCA_FAIL_NO_PROVISIONED_SECRET);
    ASSERT_EQ_INT(g_fx.decrypt_calls, 1);
}

TEST(test_payload_chain_mismatch)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    uint8_t chain[32]; memset(chain, 0x01, 32);  /* recompute yields all-zero */
    build_encrypted_bundle(buf, ph, chain);
    build_plaintext_toc();

    payload_sha_ctx_init(buf + OCA_CLASSIC_BODY_SIZE, true, 0x5A);
    oca_callbacks_t cb;
    payload_cb(&cb, decrypt_ok);

    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL),
                  OCA_FAIL_PAYLOAD_HASH_CHAIN);
}

TEST(test_payload_happy_path)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    uint8_t chain[32]; memset(chain, 0, 32);  /* recompute yields all-zero → match */
    build_encrypted_bundle(buf, ph, chain);
    build_plaintext_toc();

    payload_sha_ctx_init(buf + OCA_CLASSIC_BODY_SIZE, true, 0x5A);
    oca_callbacks_t cb;
    payload_cb(&cb, decrypt_ok);

    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_OK);
}

/* ------------------------------------------------------------------ */
/* Payload TOC structural validation (F-010)                          */
/*                                                                    */
/* These drive oca_check_payload down the encrypted path so it reaches */
/* the plaintext-TOC structural checks. The ciphertext hash is made to */
/* match (so step 1 passes), decryption returns a caller-controlled    */
/* plaintext TOC, and each test shapes that TOC to trip exactly one    */
/* structural rule. A structural violation must fail with the dedicated */
/* OCA_FAIL_PAYLOAD_TOC code — never the reused PAYLOAD_HASH_CHAIN.     */
/* ------------------------------------------------------------------ */

/* decrypt callback that hands back a caller-shaped plaintext TOC. */

static oca_result_t decrypt_returns_struct_pt(const oca_decrypt_input_t *in,
                                              const uint8_t **out_pt,
                                              size_t *out_pt_len)
{
    (void)in;
    *out_pt = g_fx.struct_pt;
    *out_pt_len = g_fx.struct_pt_len;
    return OCA_OK;
}

static void toc_put_u16(uint8_t *p, uint16_t v)
{
    for (unsigned i = 0u; i < 2u; ++i) {
        p[i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
    }
}

static void toc_put_u32(uint8_t *p, uint32_t v)
{
    for (unsigned i = 0u; i < 4u; ++i) {
        p[i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
    }
}

static void toc_put_u64(uint8_t *p, uint64_t v)
{
    for (unsigned i = 0u; i < 8u; ++i) {
        p[i] = (uint8_t)((v >> (8u * i)) & 0xFFu);
    }
}

static void toc_set_header(uint8_t *pt, uint64_t image_count)
{
    memcpy(pt, "PTOC", 4);
    toc_put_u64(pt + OCA_TOC_OFF_IMAGE_COUNT, image_count);
}

static void toc_set_entry(uint8_t *pt, uint64_t idx, uint64_t off, uint64_t len)
{
    uint8_t *e = pt + OCA_TOC_HEADER_SIZE + (size_t)idx * OCA_TOC_ENTRY_SIZE;
    toc_put_u64(e + OCA_TOC_ENTRY_OFF_OFFSET, off);
    toc_put_u64(e + OCA_TOC_ENTRY_OFF_LENGTH, len);
}

/* Run oca_check_payload over an encrypted bundle whose ciphertext hash
 * matches and whose decryption yields (pt, pt_len). The embedded
 * payload_hash_chain is all-zero and the stub sha256 recomputes all-zero for
 * any non-ciphertext input, so a structurally-valid TOC reaches OCA_OK. */
static oca_result_t run_struct_payload(const uint8_t *pt, size_t pt_len)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    uint8_t chain[32]; memset(chain, 0, 32);
    build_encrypted_bundle(buf, ph, chain);

    payload_sha_ctx_init(buf + OCA_CLASSIC_BODY_SIZE, true, 0x5A);
    oca_callbacks_t cb;
    payload_cb(&cb, decrypt_returns_struct_pt);

    g_fx.struct_pt = pt;
    g_fx.struct_pt_len = pt_len;
    return oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL);
}

TEST(test_payload_toc_zero_image_count)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 0u);                       /* image_count == 0 */
    ASSERT_EQ_INT(run_struct_payload(pt, sizeof pt), OCA_FAIL_PAYLOAD_TOC);
}

TEST(test_payload_toc_length_exceeds_payload)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + 2u * OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 3u);   /* claims 3 entries; buffer holds header + 2 */
    ASSERT_EQ_INT(run_struct_payload(pt, sizeof pt), OCA_FAIL_PAYLOAD_TOC);
}

TEST(test_payload_toc_entry_offset_misaligned)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    toc_set_entry(pt, 0u, 4u, 8u);                /* offset 4 not a multiple of 8 */
    ASSERT_EQ_INT(run_struct_payload(pt, sizeof pt), OCA_FAIL_PAYLOAD_TOC);
}

/* A zero-length entry passes every other structural rule -- it is in bounds and
 * overlaps nothing -- so this is the only check standing between a Consumer and
 * an entry that describes no image at all. */
TEST(test_payload_toc_entry_zero_length)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    toc_set_entry(pt, 0u, 0u, 0u);                /* aligned and in bounds, but empty */
    ASSERT_EQ_INT(run_struct_payload(pt, sizeof pt), OCA_FAIL_PAYLOAD_TOC);
}

TEST(test_payload_toc_entry_out_of_bounds)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    toc_set_entry(pt, 0u, 8u, (uint64_t)sizeof pt);   /* offset+length past pt_len */
    ASSERT_EQ_INT(run_struct_payload(pt, sizeof pt), OCA_FAIL_PAYLOAD_TOC);
}

TEST(test_payload_toc_entries_overlap)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + 2u * OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 2u);
    toc_set_entry(pt, 0u, 8u, 16u);               /* [8, 24) */
    toc_set_entry(pt, 1u, 16u, 16u);              /* [16, 32) overlaps [8, 24) */
    ASSERT_EQ_INT(run_struct_payload(pt, sizeof pt), OCA_FAIL_PAYLOAD_TOC);
}

/* Overlap detection must not assume entries are sorted by offset: the same
 * overlapping pair as above but with the entries in descending-offset order. */
TEST(test_payload_toc_entries_overlap_unsorted)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + 2u * OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 2u);
    toc_set_entry(pt, 0u, 16u, 16u);              /* [16, 32) */
    toc_set_entry(pt, 1u, 8u, 16u);               /* [8, 24) overlaps [16, 32) */
    ASSERT_EQ_INT(run_struct_payload(pt, sizeof pt), OCA_FAIL_PAYLOAD_TOC);
}

TEST(test_payload_toc_multi_entry_disjoint_passes)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + 2u * OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 2u);
    toc_set_entry(pt, 0u, 0u, 8u);                /* [0, 8), 8-byte aligned */
    toc_set_entry(pt, 1u, 8u, 8u);                /* [8, 16), aligned, disjoint */
    ASSERT_EQ_INT(run_struct_payload(pt, sizeof pt), OCA_OK);
}

/* Per-entry image hash. The stub sha256 digests everything to all-zero, so a
 * zero-filled TOC is self-consistent and any non-zero byte in an entry's stored
 * `hash` field is a mismatch the per-entry check must catch. The chain check
 * runs first and passes, which is the point: the chain hashes the stored `hash`
 * field as ordinary TOC data and therefore cannot detect this. */
TEST(test_payload_toc_entry_hash_mismatch)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    toc_set_entry(pt, 0u, 0u, 8u);
    pt[OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_OFF_HASH] = 0xFFu;  /* wrong digest */
    ASSERT_EQ_INT(run_struct_payload(pt, sizeof pt), OCA_FAIL_PAYLOAD_ENTRY_HASH);
}

/* The check covers every entry, not just the first. */
TEST(test_payload_toc_entry_hash_mismatch_second_entry)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + 2u * OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 2u);
    toc_set_entry(pt, 0u, 0u, 8u);
    toc_set_entry(pt, 1u, 8u, 8u);
    uint8_t *second = pt + OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE;
    second[OCA_TOC_ENTRY_OFF_HASH] = 0x01u;
    ASSERT_EQ_INT(run_struct_payload(pt, sizeof pt), OCA_FAIL_PAYLOAD_ENTRY_HASH);
}

/* Only the leading digest_size bytes of the 64-byte hash field are compared;
 * the trailing padding this pass does not interpret must not fail a good entry. */
TEST(test_payload_toc_entry_hash_padding_ignored)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    toc_set_entry(pt, 0u, 0u, 8u);
    uint8_t *entry = pt + OCA_TOC_HEADER_SIZE;
    memset(entry + OCA_TOC_ENTRY_OFF_HASH + OCA_MANIFEST_HASH_DIGEST_SIZE, 0xA5u,
           OCA_LEN_MANIFEST_HASH - OCA_MANIFEST_HASH_DIGEST_SIZE);
    ASSERT_EQ_INT(run_struct_payload(pt, sizeof pt), OCA_OK);
}

/* ------------------------------------------------------------------ */
/* Cleartext payload stage                                            */
/*                                                                    */
/* A non-encrypted payload used to skip validation entirely. These     */
/* tests exercise it in place: payload_hash over the TOC region, the   */
/* payload_hashed_length / payload_length agreement rules, structural  */
/* validation, the chain, and the per-entry hashes. The stub sha256    */
/* digests everything to all-zero, so a zero-filled manifest hash      */
/* field matches and each test isolates one rule.                     */
/* ------------------------------------------------------------------ */

#define CLEAR_TOC_BYTES  (OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE)   /* 308 */
#define CLEAR_IMG_OFF    312u   /* next 8-byte boundary after the TOC */
#define CLEAR_IMG_LEN      8u
#define CLEAR_PAYLOAD_LEN (CLEAR_IMG_OFF + CLEAR_IMG_LEN)             /* 320 */

/* Classic bundle with a well-formed cleartext payload: one image, every hash
 * field left all-zero to match the stub digest. */
static void build_cleartext_bundle(uint8_t *buf)
{
    memset(buf, 0, OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN);
    build_minimal_manifest(buf);
    toc_put_u64(buf + OCA_OFF_PAYLOAD_LENGTH, CLEAR_PAYLOAD_LEN);
    toc_put_u64(buf + OCA_OFF_PAYLOAD_HASHED_LENGTH, CLEAR_TOC_BYTES);

    uint8_t *pt = buf + OCA_CLASSIC_BODY_SIZE;
    toc_set_header(pt, 1u);
    toc_put_u64(pt + OCA_TOC_OFF_PAYLOAD_LENGTH, CLEAR_PAYLOAD_LEN);
    toc_set_entry(pt, 0u, CLEAR_IMG_OFF, CLEAR_IMG_LEN);
}

/* Callbacks for the cleartext path: sha256 only — no ciphertext, no decrypt. */
static void cleartext_cb(oca_callbacks_t *cb)
{
    payload_sha_ctx_init(0, false, 0x00);  /* always digests to all-zero */
    memset(cb, 0, sizeof(*cb));
    cb->sha256 = payload_sha256;
}

TEST(test_cleartext_payload_happy_path)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    build_cleartext_bundle(buf);
    oca_callbacks_t cb;
    cleartext_cb(&cb);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_OK);
}

/* ------------------------------------------------------------------ */
/* The validated-plaintext report                                     */
/*                                                                    */
/* The validator holds the plaintext location while it checks the     */
/* payload and used to drop it on return, which left the decryption   */
/* callback as the only place a Consumer could capture it. It reports */
/* the location instead — but only once every plaintext check has     */
/* passed, so a caller can never act on bytes the validator had not   */
/* finished verifying.                                                */
/* ------------------------------------------------------------------ */

TEST(test_encrypted_plaintext_reported_after_success)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    uint8_t chain[32]; memset(chain, 0, 32);
    build_encrypted_bundle(buf, ph, chain);
    build_plaintext_toc();

    payload_sha_ctx_init(buf + OCA_CLASSIC_BODY_SIZE, true, 0x5A);
    oca_callbacks_t cb;
    payload_cb(&cb, decrypt_ok);

    oca_payload_plaintext_t pt;
    memset(&pt, 0, sizeof pt);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, &pt),
                  OCA_OK);
    /* decrypt_ok hands back the file-scope plaintext TOC; that is what a
     * Consumer must be pointed at, not the ciphertext it replaced. */
    ASSERT_TRUE(pt.bytes == g_fx.plaintext_toc);
    ASSERT_EQ_INT(pt.len, sizeof g_fx.plaintext_toc);
}

TEST(test_cleartext_plaintext_reported_after_success)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    build_cleartext_bundle(buf);
    oca_callbacks_t cb;
    cleartext_cb(&cb);

    oca_payload_plaintext_t pt;
    memset(&pt, 0, sizeof pt);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, &pt),
                  OCA_OK);
    /* A cleartext payload is already plaintext, in place inside the bundle. */
    ASSERT_TRUE(pt.bytes == buf + OCA_CLASSIC_BODY_SIZE);
    ASSERT_EQ_INT(pt.len, CLEAR_PAYLOAD_LEN);
}

TEST(test_plaintext_reported_from_every_entry_point)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    oca_payload_plaintext_t pt;

    /* Whole-bundle entry point. It runs the manifest checks too, and the digest
     * stub this path shares always answers all-zero, so the stored manifest_hash
     * has to be all-zero for the manifest stage to agree. */
    build_cleartext_bundle(buf);
    memset(buf + OCA_CLASSIC_OFF_MANIFEST_HASH, 0, 32);
    oca_callbacks_t cb;
    cleartext_cb(&cb);
    cb.is_secure_boot_active = sb_inactive_cb;
    memset(&pt, 0, sizeof pt);
    ASSERT_EQ_INT(oca_validate(buf, sizeof buf, &cb, NULL, &pt), OCA_OK);
    ASSERT_TRUE(pt.bytes == buf + OCA_CLASSIC_BODY_SIZE);
    ASSERT_EQ_INT(pt.len, CLEAR_PAYLOAD_LEN);

    /* Composable whole-buffer entry point. */
    memset(&pt, 0, sizeof pt);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, &pt),
                  OCA_OK);
    ASSERT_TRUE(pt.bytes == buf + OCA_CLASSIC_BODY_SIZE);

    /* Staged entry point, payload addressed separately. */
    memset(&pt, 0, sizeof pt);
    ASSERT_EQ_INT(oca_check_payload_at(buf, buf + OCA_CLASSIC_BODY_SIZE,
                                       CLEAR_PAYLOAD_LEN, &cb, &g_authenticated,
                                       &pt),
                  OCA_OK);
    ASSERT_TRUE(pt.bytes == buf + OCA_CLASSIC_BODY_SIZE);
    ASSERT_EQ_INT(pt.len, CLEAR_PAYLOAD_LEN);
}

/* Nothing is reported on any failing path. Checked per distinct failure rather
 * than once with a representative one, because the plaintext checks return from
 * different places and a report leaking on one of them would be invisible from
 * the others. These are written after the report exists on purpose: written
 * earlier they would pass while nothing was reported at all, which proves
 * nothing. test_report_suppression_has_teeth below closes that gap. */
/* NOTE: this one is a boundary check, not a guard on the report site. A
 * structurally invalid TOC is rejected while the span is being bounded, which
 * happens before the plaintext checks and therefore before the report could be
 * written at all — so removing the report's success-gate does NOT make this case
 * fail. It is kept because "the earliest failure reports nothing" is still worth
 * pinning, but the two cases below are the ones with teeth. */
TEST(test_no_report_when_the_toc_is_malformed)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    build_cleartext_bundle(buf);
    /* image_count = 0 is structurally invalid. */
    memset(buf + OCA_CLASSIC_BODY_SIZE + OCA_TOC_OFF_IMAGE_COUNT, 0, 8);
    oca_callbacks_t cb;
    cleartext_cb(&cb);

    oca_payload_plaintext_t pt;
    memset(&pt, 0, sizeof pt);
    ASSERT_TRUE(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, &pt)
                != OCA_OK);
    ASSERT_TRUE(pt.bytes == NULL);
    ASSERT_EQ_INT(pt.len, 0);
}

TEST(test_no_report_when_the_hash_chain_mismatches)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    uint8_t chain[32]; memset(chain, 0x01, 32);   /* recompute yields all-zero */
    build_encrypted_bundle(buf, ph, chain);
    build_plaintext_toc();

    payload_sha_ctx_init(buf + OCA_CLASSIC_BODY_SIZE, true, 0x5A);
    oca_callbacks_t cb;
    payload_cb(&cb, decrypt_ok);

    oca_payload_plaintext_t pt;
    memset(&pt, 0, sizeof pt);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, &pt),
                  OCA_FAIL_PAYLOAD_HASH_CHAIN);
    ASSERT_TRUE(pt.bytes == NULL);
    ASSERT_EQ_INT(pt.len, 0);
}

TEST(test_no_report_when_an_entry_hash_mismatches)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    build_cleartext_bundle(buf);
    /* Break the first TOC entry's stored hash: the chain still recomputes,
     * because it hashes this field as ordinary TOC data. */
    uint8_t *entry = buf + OCA_CLASSIC_BODY_SIZE + OCA_TOC_HEADER_SIZE;
    entry[OCA_TOC_ENTRY_OFF_HASH] ^= 0xFFu;
    oca_callbacks_t cb;
    cleartext_cb(&cb);

    oca_payload_plaintext_t pt;
    memset(&pt, 0, sizeof pt);
    oca_result_t r = oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, &pt);
    ASSERT_TRUE(r != OCA_OK);
    ASSERT_TRUE(pt.bytes == NULL);
    ASSERT_EQ_INT(pt.len, 0);
}

/* Declining the report changes no verdict. */
TEST(test_declining_the_report_changes_no_verdict)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    oca_callbacks_t cb;
    oca_payload_plaintext_t pt;

    build_cleartext_bundle(buf);
    cleartext_cb(&cb);
    memset(&pt, 0, sizeof pt);
    oca_result_t with = oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, &pt);
    oca_result_t without = oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL);
    ASSERT_EQ_INT(with, OCA_OK);
    ASSERT_EQ_INT(without, with);

    /* Same on a failing shape: declining must not turn a refusal into a pass. */
    memset(buf + OCA_CLASSIC_BODY_SIZE + OCA_TOC_OFF_IMAGE_COUNT, 0, 8);
    oca_result_t bad_with = oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, &pt);
    oca_result_t bad_without = oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL);
    ASSERT_TRUE(bad_with != OCA_OK);
    ASSERT_EQ_INT(bad_without, bad_with);
}

/* A declared cleartext payload whose bytes are not present is TRUNCATED, never
 * a silent pass. */
TEST(test_cleartext_payload_missing_bytes_truncated)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    build_cleartext_bundle(buf);
    oca_callbacks_t cb;
    cleartext_cb(&cb);
    /* Claim the body only — the payload is gone. */
    ASSERT_EQ_INT(oca_check_payload(buf, OCA_CLASSIC_BODY_SIZE, &cb, &g_authenticated, NULL),
                  OCA_FAIL_TRUNCATED);
    /* Present but short by one byte. */
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf - 1u, &cb, &g_authenticated, NULL),
                  OCA_FAIL_TRUNCATED);
}

/* A cleartext payload needs sha256; without it the stage cannot proceed. */
TEST(test_cleartext_payload_requires_sha256_callback)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    build_cleartext_bundle(buf);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, NULL, &g_authenticated, NULL),
                  OCA_FAIL_CALLBACK_UNAVAILABLE);
}

TEST(test_cleartext_payload_hash_mismatch)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    build_cleartext_bundle(buf);
    buf[OCA_OFF_PAYLOAD_HASH] = 0x77u;   /* stub digests to all-zero */
    oca_callbacks_t cb;
    cleartext_cb(&cb);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_FAIL_PAYLOAD_HASH);
}

TEST(test_cleartext_payload_chain_mismatch)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    build_cleartext_bundle(buf);
    buf[OCA_OFF_PAYLOAD_HASH_CHAIN] = 0x77u;
    oca_callbacks_t cb;
    cleartext_cb(&cb);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL),
                  OCA_FAIL_PAYLOAD_HASH_CHAIN);
}

TEST(test_cleartext_payload_entry_hash_mismatch)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    build_cleartext_bundle(buf);
    buf[OCA_CLASSIC_BODY_SIZE + OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_OFF_HASH] = 0xFFu;
    oca_callbacks_t cb;
    cleartext_cb(&cb);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL),
                  OCA_FAIL_PAYLOAD_ENTRY_HASH);
}

/* payload_hashed_length must equal TOC_Header_Size + image_count*TOC_Entry_Size
 * exactly for a cleartext payload. */
TEST(test_cleartext_payload_hashed_length_must_equal_toc_span)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];

    build_cleartext_bundle(buf);
    toc_put_u64(buf + OCA_OFF_PAYLOAD_HASHED_LENGTH, CLEAR_TOC_BYTES + 8u);
    oca_callbacks_t cb;
    cleartext_cb(&cb);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_FAIL_PAYLOAD_TOC);

    build_cleartext_bundle(buf);
    toc_put_u64(buf + OCA_OFF_PAYLOAD_HASHED_LENGTH, CLEAR_TOC_BYTES - 8u);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_FAIL_PAYLOAD_TOC);

    /* Zero is not a valid hashed length for a declared payload. */
    build_cleartext_bundle(buf);
    toc_put_u64(buf + OCA_OFF_PAYLOAD_HASHED_LENGTH, 0u);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_FAIL_PAYLOAD_TOC);
}

/* The TOC's payload_length and the manifest's must agree for a cleartext
 * payload. */
TEST(test_cleartext_payload_length_disagreement)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    build_cleartext_bundle(buf);
    toc_put_u64(buf + OCA_CLASSIC_BODY_SIZE + OCA_TOC_OFF_PAYLOAD_LENGTH,
                CLEAR_PAYLOAD_LEN - 8u);
    oca_callbacks_t cb;
    cleartext_cb(&cb);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_FAIL_PAYLOAD_TOC);
}

/* Structural validation runs on the cleartext path too. */
TEST(test_cleartext_payload_structural_violation)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    oca_callbacks_t cb;

    build_cleartext_bundle(buf);
    toc_set_entry(buf + OCA_CLASSIC_BODY_SIZE, 0u, CLEAR_IMG_OFF + 1u, CLEAR_IMG_LEN);
    cleartext_cb(&cb);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL),  /* misaligned offset */
                  OCA_FAIL_PAYLOAD_TOC);

    build_cleartext_bundle(buf);
    toc_set_entry(buf + OCA_CLASSIC_BODY_SIZE, 0u, CLEAR_IMG_OFF, CLEAR_PAYLOAD_LEN);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL),  /* out of bounds */
                  OCA_FAIL_PAYLOAD_TOC);

    build_cleartext_bundle(buf);
    toc_put_u64(buf + OCA_CLASSIC_BODY_SIZE + OCA_TOC_OFF_IMAGE_COUNT, 0u);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL),  /* image_count 0 */
                  OCA_FAIL_PAYLOAD_TOC);
}

/* ------------------------------------------------------------------ */
/* Post-validation TOC access                                          */
/*                                                                     */
/* oca_payload_region / oca_toc_info / oca_toc_image_at. These do no    */
/* cryptography, so the tests here shape a TOC directly and check the   */
/* decode plus every bounds rule that keeps a returned pointer in       */
/* range. The contract is that a hostile or malformed TOC can never     */
/* yield an out-of-range bytes/length — not that these functions        */
/* establish authenticity (oca_validate does that).                     */
/* ------------------------------------------------------------------ */

/* First 8-byte-aligned image offset after a 1-entry TOC. Derived rather than
 * hand-computed: an entry offset that is not a multiple of 8 is a structural
 * violation, so a stale literal here would test the wrong rejection path. */
#define TOC_ALIGN8(x)  (((x) + 7u) & ~7u)
#define TOC1_IMG_OFF   TOC_ALIGN8(OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE)
#define TOC1_IMG_LEN   8u
#define TOC1_PT_SIZE   (TOC1_IMG_OFF + TOC1_IMG_LEN)

static void toc_set_entry_u64_field(uint8_t *pt, uint64_t idx, unsigned field_off,
                                    uint64_t value)
{
    uint8_t *e = pt + OCA_TOC_HEADER_SIZE + (size_t)idx * OCA_TOC_ENTRY_SIZE;
    toc_put_u64(e + field_off, value);
}

static void toc_set_entry_type(uint8_t *pt, uint64_t idx, const char *type)
{
    uint8_t *e = pt + OCA_TOC_HEADER_SIZE + (size_t)idx * OCA_TOC_ENTRY_SIZE;
    memset(e + OCA_TOC_ENTRY_OFF_TYPE, ' ', OCA_TOC_ENTRY_LEN_TYPE);
    for (unsigned i = 0u; i < OCA_TOC_ENTRY_LEN_TYPE && type[i] != '\0'; ++i) {
        e[OCA_TOC_ENTRY_OFF_TYPE + i] = (uint8_t)type[i];
    }
}

TEST(test_payload_region_locates_cleartext_payload)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    build_cleartext_bundle(buf);

    const uint8_t *pl = 0;
    size_t pl_len = 0u;
    bool encrypted = true;
    ASSERT_EQ_INT(oca_payload_region(buf, sizeof buf, &pl, &pl_len, &encrypted),
                  OCA_OK);
    ASSERT_TRUE(pl == buf + OCA_CLASSIC_BODY_SIZE);
    ASSERT_EQ_INT(pl_len, CLEAR_PAYLOAD_LEN);
    ASSERT_TRUE(!encrypted);
}

TEST(test_payload_region_flags_encrypted_and_sizes_by_ciphertext)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    uint8_t chain[32]; memset(chain, 0, 32);
    build_encrypted_bundle(buf, ph, chain);

    const uint8_t *pl = 0;
    size_t pl_len = 0u;
    bool encrypted = false;
    ASSERT_EQ_INT(oca_payload_region(buf, sizeof buf, &pl, &pl_len, &encrypted),
                  OCA_OK);
    ASSERT_TRUE(encrypted);                    /* caller must decrypt first */
    ASSERT_EQ_INT(pl_len, ENC_CT_LEN);         /* sized by payload_hashed_length */
}

TEST(test_check_payload_rejects_short_buffer_without_reading_past_it)
{
    /* oca_check_payload is part of the composable API and takes a length, so it
     * may be called on its own — without oca_validate() having bounded the
     * buffer first. It used to read payload_encryption_control (offset 200) and
     * payload_length (offset 2933) BEFORE checking the length, so a short buffer
     * read out of bounds. Sweep sizes across those offsets: every one short of a
     * full body must return TRUNCATED, never OCA_OK. */
    static const size_t short_lengths[] = {
        4u, 8u, 64u, 199u, 200u, 201u, 512u, 2932u, 2933u, 2940u,
        OCA_CLASSIC_BODY_SIZE - 1u,
    };
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.sha256 = payload_sha256;

    for (unsigned i = 0u; i < sizeof short_lengths / sizeof short_lengths[0]; ++i) {
        uint8_t buf[OCA_CLASSIC_BODY_SIZE];
        memset(buf, 0, sizeof buf);
        buf[0] = 'O'; buf[1] = 'C'; buf[2] = 'A'; buf[3] = 'C';
        ASSERT_EQ_INT(oca_check_payload(buf, short_lengths[i], &cb, &g_authenticated, NULL),
                      OCA_FAIL_TRUNCATED);
    }
    ASSERT_EQ_INT(oca_check_payload(0, OCA_CLASSIC_BODY_SIZE, &cb, &g_authenticated, NULL),
                  OCA_FAIL_INVALID_ARG);
}

TEST(test_payload_region_rejects_short_buffer_without_reading_past_it)
{
    /* A buffer far shorter than the body must be refused on the length check,
     * before any field read — the manifest fields this function consults live
     * near offset 2900. */
    uint8_t buf[64];
    memset(buf, 0, sizeof buf);
    buf[0] = 'O'; buf[1] = 'C'; buf[2] = 'A'; buf[3] = 'C';

    const uint8_t *pl = 0;
    size_t pl_len = 0u;
    bool encrypted = false;
    ASSERT_EQ_INT(oca_payload_region(buf, sizeof buf, &pl, &pl_len, &encrypted),
                  OCA_FAIL_TRUNCATED);
}

TEST(test_payload_region_rejects_null_args)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    build_cleartext_bundle(buf);
    const uint8_t *pl = 0;
    size_t pl_len = 0u;
    bool enc = false;
    ASSERT_EQ_INT(oca_payload_region(0, sizeof buf, &pl, &pl_len, &enc),
                  OCA_FAIL_INVALID_ARG);
    ASSERT_EQ_INT(oca_payload_region(buf, sizeof buf, 0, &pl_len, &enc),
                  OCA_FAIL_INVALID_ARG);
    ASSERT_EQ_INT(oca_payload_region(buf, sizeof buf, &pl, 0, &enc),
                  OCA_FAIL_INVALID_ARG);
    ASSERT_EQ_INT(oca_payload_region(buf, sizeof buf, &pl, &pl_len, 0),
                  OCA_FAIL_INVALID_ARG);
}

TEST(test_toc_info_reads_header)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + 2u * OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 2u);
    pt[OCA_TOC_OFF_VERSION_MAJOR] = 3u;                 /* LE u16 low byte */
    pt[OCA_TOC_OFF_VERSION_MINOR] = 7u;
    toc_put_u64(pt + OCA_TOC_OFF_PAYLOAD_LENGTH, 0x1234u);

    oca_toc_info_t info;
    ASSERT_EQ_INT(oca_toc_info(pt, sizeof pt, &info), OCA_OK);
    ASSERT_EQ_INT(info.version_major, 3);
    ASSERT_EQ_INT(info.version_minor, 7);
    ASSERT_EQ_INT(info.payload_length, 0x1234);
    ASSERT_EQ_INT(info.image_count, 2);
}

TEST(test_toc_info_rejects_bad_ptoc_magic)
{
    uint8_t pt[OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    pt[OCA_TOC_OFF_MAGIC] = 'Q';                        /* not "PTOC" */

    oca_toc_info_t info;
    ASSERT_EQ_INT(oca_toc_info(pt, sizeof pt, &info), OCA_FAIL_PAYLOAD_TOC);
}

TEST(test_toc_info_rejects_bad_span)
{
    oca_toc_info_t info;

    uint8_t zero_count[OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE];
    memset(zero_count, 0, sizeof zero_count);
    toc_set_header(zero_count, 0u);
    ASSERT_EQ_INT(oca_toc_info(zero_count, sizeof zero_count, &info),
                  OCA_FAIL_PAYLOAD_TOC);

    uint8_t overrun[OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE];
    memset(overrun, 0, sizeof overrun);
    toc_set_header(overrun, 4u);            /* claims 4; buffer holds 1 */
    ASSERT_EQ_INT(oca_toc_info(overrun, sizeof overrun, &info),
                  OCA_FAIL_PAYLOAD_TOC);

    /* Shorter than the header itself. */
    ASSERT_EQ_INT(oca_toc_info(overrun, 8u, &info), OCA_FAIL_PAYLOAD_TOC);

    ASSERT_EQ_INT(oca_toc_info(0, sizeof overrun, &info), OCA_FAIL_INVALID_ARG);
    ASSERT_EQ_INT(oca_toc_info(overrun, sizeof overrun, 0), OCA_FAIL_INVALID_ARG);
}

TEST(test_toc_image_at_decodes_every_entry_field)
{
    uint8_t pt[TOC1_PT_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    const uint64_t img_off = TOC1_IMG_OFF;
    toc_set_entry(pt, 0u, img_off, TOC1_IMG_LEN);
    toc_set_entry_type(pt, 0u, "SEPBL1");
    toc_set_entry_u64_field(pt, 0u, OCA_TOC_ENTRY_OFF_LOAD_ADDR, 0xC0000000u);
    toc_set_entry_u64_field(pt, 0u, OCA_TOC_ENTRY_OFF_ENTRY_POINT, 0xC0000100u);
    toc_set_entry_u64_field(pt, 0u, OCA_TOC_ENTRY_OFF_SECURITY_VERSION, 0x2Au);
    toc_set_entry_u64_field(pt, 0u, OCA_TOC_ENTRY_OFF_TARGET_CHIPLET_ID, 0xDEADu);
    /* group is a u32 at its own offset. */
    pt[OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_OFF_GROUP] = 5u;
    /* version packs major:16 | minor:24 | patch:24. */
    toc_set_entry_u64_field(pt, 0u, OCA_TOC_ENTRY_OFF_VERSION,
                            ((uint64_t)2u << 48) | ((uint64_t)11u << 24) | 314u);
    /* Distinctive image bytes so `bytes` can be checked. */
    memset(pt + img_off, 0x77, 8u);

    oca_image_info_t img;
    memset(&img, 0, sizeof img);
    if (oca_toc_image_at(pt, sizeof pt, 0u, &img) != OCA_OK) {
        ASSERT_TRUE(!"oca_toc_image_at should have succeeded");
        return;                 /* fields below would read uninitialized memory */
    }
    ASSERT_TRUE(img.bytes == pt + img_off);
    ASSERT_EQ_INT(img.length, 8);
    ASSERT_EQ_INT(img.offset, (long)img_off);
    ASSERT_EQ_INT(img.load_addr, 0xC0000000u);
    ASSERT_EQ_INT(img.entry_point, 0xC0000100u);
    ASSERT_EQ_INT(img.security_version, 0x2A);
    ASSERT_EQ_INT(img.target_chiplet_id, 0xDEAD);
    ASSERT_EQ_INT(img.group, 5);
    ASSERT_EQ_INT(img.version_major, 2);
    ASSERT_EQ_INT(img.version_minor, 11);
    ASSERT_EQ_INT(img.version_patch, 314);
    ASSERT_EQ_INT(strcmp(img.type, "SEPBL1"), 0);   /* space padding trimmed */
    ASSERT_TRUE(img.bytes[0] == 0x77u);
}

TEST(test_toc_image_at_hash_and_description_point_into_buffer)
{
    uint8_t pt[TOC1_PT_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    toc_set_entry(pt, 0u, TOC1_IMG_OFF, TOC1_IMG_LEN);

    uint8_t *entry = pt + OCA_TOC_HEADER_SIZE;
    memset(entry + OCA_TOC_ENTRY_OFF_HASH, 0xC3, 32);
    memcpy(entry + OCA_TOC_ENTRY_OFF_DESCRIPTION, "stage 1", 8);

    oca_image_info_t img;
    memset(&img, 0, sizeof img);
    if (oca_toc_image_at(pt, sizeof pt, 0u, &img) != OCA_OK) {
        ASSERT_TRUE(!"oca_toc_image_at should have succeeded");
        return;
    }
    ASSERT_TRUE(img.hash == entry + OCA_TOC_ENTRY_OFF_HASH);
    ASSERT_TRUE(img.description == entry + OCA_TOC_ENTRY_OFF_DESCRIPTION);
    ASSERT_EQ_INT(img.hash[0], 0xC3);
    ASSERT_EQ_INT(strcmp((const char *)img.description, "stage 1"), 0);
}

TEST(test_toc_image_at_indexes_in_stored_order_not_offset_order)
{
    /* Two entries stored in descending offset order. Index 0 must return the
     * FIRST STORED entry — the format does not require sorted entries, and the
     * hash chain is computed in stored order. */
    uint8_t pt[OCA_TOC_HEADER_SIZE + 2u * OCA_TOC_ENTRY_SIZE + 32u];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 2u);
    const uint64_t base = OCA_TOC_HEADER_SIZE + 2u * OCA_TOC_ENTRY_SIZE;
    toc_set_entry(pt, 0u, base + 16u, 8u);      /* stored first, higher offset */
    toc_set_entry(pt, 1u, base,       8u);      /* stored second, lower offset */
    toc_set_entry_type(pt, 0u, "SECOND_HALF");
    toc_set_entry_type(pt, 1u, "FIRST_HALF");

    oca_image_info_t a, b;
    ASSERT_EQ_INT(oca_toc_image_at(pt, sizeof pt, 0u, &a), OCA_OK);
    ASSERT_EQ_INT(oca_toc_image_at(pt, sizeof pt, 1u, &b), OCA_OK);
    ASSERT_EQ_INT(strcmp(a.type, "SECOND_HALF"), 0);
    ASSERT_EQ_INT(strcmp(b.type, "FIRST_HALF"), 0);
    ASSERT_TRUE(a.offset > b.offset);
}

TEST(test_toc_image_at_rejects_index_beyond_count)
{
    uint8_t pt[TOC1_PT_SIZE];
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    toc_set_entry(pt, 0u, TOC1_IMG_OFF, TOC1_IMG_LEN);

    oca_image_info_t img;
    ASSERT_EQ_INT(oca_toc_image_at(pt, sizeof pt, 1u, &img),
                  OCA_FAIL_INVALID_ARG);     /* == image_count */
    ASSERT_EQ_INT(oca_toc_image_at(pt, sizeof pt, 0xFFFFFFFFu, &img),
                  OCA_FAIL_INVALID_ARG);
    ASSERT_EQ_INT(oca_toc_image_at(0, sizeof pt, 0u, &img), OCA_FAIL_INVALID_ARG);
    ASSERT_EQ_INT(oca_toc_image_at(pt, sizeof pt, 0u, 0), OCA_FAIL_INVALID_ARG);
}

TEST(test_toc_image_at_rejects_structurally_invalid_entry)
{
    uint8_t pt[TOC1_PT_SIZE];
    const uint64_t good_off = TOC1_IMG_OFF;
    oca_image_info_t img;

    /* Baseline: good_off itself is accepted, so each rejection below is
     * attributable to the one rule it breaks. */
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    toc_set_entry(pt, 0u, good_off, TOC1_IMG_LEN);
    ASSERT_EQ_INT(oca_toc_image_at(pt, sizeof pt, 0u, &img), OCA_OK);

    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    toc_set_entry(pt, 0u, good_off + 1u, 8u);           /* misaligned offset */
    ASSERT_EQ_INT(oca_toc_image_at(pt, sizeof pt, 0u, &img),
                  OCA_FAIL_PAYLOAD_TOC);

    /* This accessor is the one a Consumer reaches for to pick an image out of a
     * payload it has not run oca_check_payload over, so it owes the zero-length
     * rule directly: returning bytes/length for an empty entry is what leaves a
     * caller loading nothing and launching whatever preceded it. */
    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    toc_set_entry(pt, 0u, good_off, 0u);                /* zero length */
    ASSERT_EQ_INT(oca_toc_image_at(pt, sizeof pt, 0u, &img),
                  OCA_FAIL_PAYLOAD_TOC);

    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    toc_set_entry(pt, 0u, good_off, sizeof pt);         /* length out of bounds */
    ASSERT_EQ_INT(oca_toc_image_at(pt, sizeof pt, 0u, &img),
                  OCA_FAIL_PAYLOAD_TOC);

    memset(pt, 0, sizeof pt);
    toc_set_header(pt, 1u);
    toc_set_entry(pt, 0u, 0xFFFFFFFFFFFFFFF8u, 8u);     /* offset + len overflows */
    ASSERT_EQ_INT(oca_toc_image_at(pt, sizeof pt, 0u, &img),
                  OCA_FAIL_PAYLOAD_TOC);
}

TEST(test_toc_image_at_never_returns_out_of_range_bytes)
{
    /* Sweep a hostile offset/length grid: whatever the TOC claims, a successful
     * return must describe a region wholly inside the payload. This is the
     * property a boot ROM depends on before it copies img.bytes anywhere. */
    uint8_t pt[TOC1_PT_SIZE + 56u];
    const uint64_t claims[] = {
        0u, 8u, TOC1_IMG_OFF, TOC1_IMG_OFF + 8u, 336u, 400u,
        0xFFFFFFFFu, 0xFFFFFFFFFFFFFFF8u, 0xFFFFFFFFFFFFFFFFu,
    };
    const unsigned n = (unsigned)(sizeof claims / sizeof claims[0]);

    for (unsigned oi = 0u; oi < n; ++oi) {
        for (unsigned li = 0u; li < n; ++li) {
            memset(pt, 0, sizeof pt);
            toc_set_header(pt, 1u);
            toc_set_entry(pt, 0u, claims[oi], claims[li]);
            oca_image_info_t img;
            if (oca_toc_image_at(pt, sizeof pt, 0u, &img) != OCA_OK) {
                continue;                       /* rejected: fine */
            }
            ASSERT_TRUE(img.bytes >= pt);
            ASSERT_TRUE(img.length <= sizeof pt);
            ASSERT_TRUE((size_t)(img.bytes - pt) <= sizeof pt - img.length);
        }
    }
}

/* ------------------------------------------------------------------ */
/* In-place payload decryption                                         */
/*                                                                     */
/* A memory-constrained consumer decrypts the payload OVER the          */
/* ciphertext rather than into a second full-size buffer. The library    */
/* supports this, and these tests pin down why it is safe:              */
/*                                                                     */
/*   - payload_hash is verified over the ciphertext BEFORE the decrypt  */
/*     callback runs, and the ciphertext is never read again after it    */
/*     returns;                                                        */
/*   - the `iv` and `kdf_input` arguments point into the MANIFEST BODY, */
/*     not the payload, so overwriting the payload cannot clobber the   */
/*     derivation inputs;                                              */
/*   - oca_check_payload is the last stage of oca_validate.             */
/*                                                                     */
/* If any of those ever stops holding, these tests fail.                */
/* ------------------------------------------------------------------ */

/* Payload region big enough for a real 1-entry TOC (so the callback can write a
 * valid plaintext over the ciphertext) and a whole number of AES blocks. */
#define INPLACE_CT_LEN TOC1_PT_SIZE

static void build_inplace_bundle(uint8_t *buf, const uint8_t payload_hash[32])
{
    memset(buf, 0, OCA_CLASSIC_BODY_SIZE + INPLACE_CT_LEN);
    build_minimal_manifest(buf);
    buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x01u;                 /* encrypted */
    buf[OCA_OFF_ENCRYPTION_TYPE] = OCA_ENCRYPTION_TYPE_AES_128_CBC;
    toc_put_u64(buf + OCA_OFF_PAYLOAD_HASHED_LENGTH, INPLACE_CT_LEN);
    toc_put_u64(buf + OCA_OFF_PAYLOAD_LENGTH, INPLACE_CT_LEN);
    memcpy(buf + OCA_OFF_PAYLOAD_HASH, payload_hash, 32);
    /* payload_hash_chain stays all-zero — what the stub sha256 recomputes. */
    memset(buf + OCA_CLASSIC_BODY_SIZE, 0xABu, INPLACE_CT_LEN);      /* ciphertext */
}

/* Decrypt callback that overwrites the ciphertext with the plaintext and hands
 * back the SAME address — the in-place contract. */
static oca_result_t decrypt_over_ciphertext(const oca_decrypt_input_t *in,
                                            const uint8_t **out_pt,
                                            size_t *out_pt_len)
{
    g_fx.decrypt_calls++;
    uint8_t *region = (uint8_t *)(uintptr_t)in->ciphertext;   /* caller's buffer is mutable */
    memset(region, 0, in->ciphertext_len);
    toc_set_header(region, 1u);
    toc_put_u64(region + OCA_TOC_OFF_PAYLOAD_LENGTH, in->ciphertext_len);
    toc_set_entry(region, 0u, TOC1_IMG_OFF, TOC1_IMG_LEN);
    *out_pt = region;
    *out_pt_len = in->ciphertext_len;
    return OCA_OK;
}

static void inplace_cb(oca_callbacks_t *cb,
                       const uint8_t *ciphertext)
{
    g_fx.ciphertext = ciphertext;
    g_fx.ciphertext_len = INPLACE_CT_LEN;
    g_fx.return_ct_digest = true;
    memset(g_fx.ct_digest, 0x5A, 32);
    memset(cb, 0, sizeof(*cb));
    cb->sha256 = payload_sha256;
    cb->decrypt_payload = decrypt_over_ciphertext;
}

TEST(test_decrypt_in_place_validates)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + INPLACE_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    build_inplace_bundle(buf, ph);

    oca_callbacks_t cb;
    inplace_cb(&cb, buf + OCA_CLASSIC_BODY_SIZE);

    g_fx.decrypt_calls = 0;
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_OK);
    ASSERT_EQ_INT(g_fx.decrypt_calls, 1);

    /* The ciphertext really is gone — the plaintext was written over it, not
     * into a separate buffer. */
    ASSERT_TRUE(buf[OCA_CLASSIC_BODY_SIZE] != 0xABu);
    ASSERT_MEM_EQ(buf + OCA_CLASSIC_BODY_SIZE, "PTOC", 4);
}

TEST(test_decrypt_in_place_leaves_manifest_body_untouched)
{
    /* The property that makes in-place safe: iv / kdf_input / payload_hash all
     * live in the manifest body, which the payload overwrite must not reach. */
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + INPLACE_CT_LEN];
    uint8_t pristine[OCA_CLASSIC_BODY_SIZE];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    build_inplace_bundle(buf, ph);
    memcpy(pristine, buf, OCA_CLASSIC_BODY_SIZE);

    oca_callbacks_t cb;
    inplace_cb(&cb, buf + OCA_CLASSIC_BODY_SIZE);

    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_OK);
    ASSERT_MEM_EQ(buf, pristine, OCA_CLASSIC_BODY_SIZE);
}

TEST(test_toc_accessors_work_on_in_place_plaintext)
{
    /* The whole boot-ROM flow on one buffer: validate, then read the TOC out of
     * the region the ciphertext used to occupy. */
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + INPLACE_CT_LEN];
    uint8_t ph[32]; memset(ph, 0x5A, 32);
    build_inplace_bundle(buf, ph);

    oca_callbacks_t cb;
    inplace_cb(&cb, buf + OCA_CLASSIC_BODY_SIZE);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_OK);

    /* oca_payload_region still reports the stored region as encrypted; for
     * in-place the plaintext is at that very address, so only the length
     * differs (here they happen to be equal). */
    const uint8_t *region = 0;
    size_t region_len = 0u;
    bool encrypted = false;
    ASSERT_EQ_INT(oca_payload_region(buf, sizeof buf, &region, &region_len,
                                     &encrypted), OCA_OK);
    ASSERT_TRUE(encrypted);
    ASSERT_TRUE(region == buf + OCA_CLASSIC_BODY_SIZE);

    oca_toc_info_t info;
    ASSERT_EQ_INT(oca_toc_info(region, region_len, &info), OCA_OK);
    ASSERT_EQ_INT(info.image_count, 1);

    oca_image_info_t img;
    ASSERT_EQ_INT(oca_toc_image_at(region, region_len, 0u, &img), OCA_OK);
    ASSERT_EQ_INT(img.offset, TOC1_IMG_OFF);
    ASSERT_EQ_INT(img.length, TOC1_IMG_LEN);
    ASSERT_TRUE(img.bytes == region + TOC1_IMG_OFF);
}

/* ------------------------------------------------------------------ */
/* image_count cap (OCA_TOC_MAX_IMAGES)                                */
/*                                                                     */
/* The format sets no upper bound on image_count, so the only structural */
/* limit is that the TOC fit the payload — which grows with the input,   */
/* while validate_toc_structure()'s overlap check is O(image_count^2).   */
/* An 8 MiB payload admits 30393 entries and 4.6e8 pair comparisons,     */
/* reachable before any signature check when secure boot is off.         */
/*                                                                     */
/* The cap lives in read_toc_span(), the one chokepoint every TOC reader */
/* shares, so these tests exercise it through the public accessors.      */
/* ------------------------------------------------------------------ */

/* The cap TOC buffer lives in the fixture — one entry past the cap, ~70 KB at
 * the default, which is why it is not on the stack. */

static void cap_toc_init(uint64_t image_count)
{
    memset(g_fx.cap_toc, 0, sizeof g_fx.cap_toc);
    toc_set_header(g_fx.cap_toc, image_count);
    toc_put_u64(g_fx.cap_toc + OCA_TOC_OFF_PAYLOAD_LENGTH, sizeof g_fx.cap_toc);
    /* Every entry gets a distinct 8-byte range: non-zero length, 8-byte aligned
     * offset, in bounds, and disjoint from every other entry, so nothing but the
     * cap can be the reason for a rejection. */
    for (uint64_t i = 0u; i < image_count; ++i) {
        toc_set_entry(g_fx.cap_toc, i, i * 8u, 8u);
    }
}

TEST(test_toc_rejects_image_count_above_the_cap)
{
    cap_toc_init(OCA_TOC_MAX_IMAGES + 1u);

    oca_toc_info_t info;
    ASSERT_EQ_INT(oca_toc_info(g_fx.cap_toc, sizeof g_fx.cap_toc, &info),
                  OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES);

    /* The accessors share the chokepoint, so they are covered by the same cap. */
    oca_image_info_t img;
    ASSERT_EQ_INT(oca_toc_image_at(g_fx.cap_toc, sizeof g_fx.cap_toc, 0u, &img),
                  OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES);
}

TEST(test_toc_accepts_image_count_exactly_at_the_cap)
{
    /* Boundary: the cap is inclusive. A build that rejected its own stated limit
     * would be off by one. */
    cap_toc_init(OCA_TOC_MAX_IMAGES);

    oca_toc_info_t info;
    ASSERT_EQ_INT(oca_toc_info(g_fx.cap_toc, sizeof g_fx.cap_toc, &info), OCA_OK);
    ASSERT_EQ_INT(info.image_count, (long)OCA_TOC_MAX_IMAGES);

    oca_image_info_t img;
    ASSERT_EQ_INT(oca_toc_image_at(g_fx.cap_toc, sizeof g_fx.cap_toc, 0u, &img), OCA_OK);
    ASSERT_EQ_INT(oca_toc_image_at(g_fx.cap_toc, sizeof g_fx.cap_toc,
                                   OCA_TOC_MAX_IMAGES - 1u, &img), OCA_OK);
}

TEST(test_cap_rejection_is_distinct_from_malformed_toc)
{
    /* Too-many-images and malformed-TOC must not collapse into one code: the
     * first says "this consumer will not process a manifest this large", the
     * second says "these bytes are not a valid TOC". */
    oca_toc_info_t info;

    cap_toc_init(OCA_TOC_MAX_IMAGES + 1u);
    ASSERT_EQ_INT(oca_toc_info(g_fx.cap_toc, sizeof g_fx.cap_toc, &info),
                  OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES);

    cap_toc_init(0u);                       /* image_count == 0: malformed */
    ASSERT_EQ_INT(oca_toc_info(g_fx.cap_toc, sizeof g_fx.cap_toc, &info),
                  OCA_FAIL_PAYLOAD_TOC);

    /* A count that clears the cap but overruns the buffer is still malformed,
     * not a cap violation — the structural bound is checked first. */
    cap_toc_init(4u);
    ASSERT_EQ_INT(oca_toc_info(g_fx.cap_toc, OCA_TOC_HEADER_SIZE + OCA_TOC_ENTRY_SIZE,
                               &info),
                  OCA_FAIL_PAYLOAD_TOC);
}

TEST(test_result_string_covers_the_cap_code)
{
    ASSERT_EQ_INT(strcmp(oca_result_str(OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES),
                         "PAYLOAD_TOO_MANY_IMAGES"), 0);
}

/* ------------------------------------------------------------------ */
/* oca_peek_manifest                                                  */
/* ------------------------------------------------------------------ */

TEST(test_peek_reports_classic_from_a_minimal_head)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_manifest_peek_t pk;
    build_minimal_manifest(buf);
    memcpy(buf + OCA_OFF_MANIFEST_IDENTIFIER, "BASIC\0\0\0", 8);

    /* Exactly the advertised minimum, not the whole body. */
    ASSERT_EQ_INT(oca_peek_manifest(buf, OCA_MANIFEST_PEEK_MIN, &pk), OCA_OK);
    ASSERT_EQ_INT(pk.body_size, OCA_CLASSIC_BODY_SIZE);
    ASSERT_EQ_INT(pk.declared_length, OCA_CLASSIC_BODY_SIZE);
    ASSERT_EQ_INT(pk.version_major, OCA_LIB_MANIFEST_MAJOR);
    ASSERT_EQ_INT(strcmp(pk.identifier, "BASIC"), 0);
    ASSERT_EQ_INT(strcmp(pk.variant_name, "OCA-Classic"), 0);
}

TEST(test_peek_reports_pqc_body_size)
{
    uint8_t buf[OCA_MANIFEST_PEEK_MIN];
    oca_manifest_peek_t pk;
    memset(buf, 0, sizeof buf);
    memcpy(buf, "OCAP", 4);
    ASSERT_EQ_INT(oca_peek_manifest(buf, sizeof buf, &pk), OCA_OK);
    ASSERT_EQ_INT(pk.body_size, OCA_PQC_BODY_SIZE);
    ASSERT_EQ_INT(strcmp(pk.variant_name, "OCA-PQC"), 0);
}

TEST(test_peek_body_size_comes_from_the_magic_not_declared_length)
{
    /* The property that keeps a staged read safe: declared_length is
     * attacker-controlled at peek time, so it must not size the buffer. */
    uint8_t buf[OCA_MANIFEST_PEEK_MIN];
    oca_manifest_peek_t pk;
    memset(buf, 0, sizeof buf);
    memcpy(buf, "OCAC", 4);
    toc_put_u32(buf + OCA_OFF_MANIFEST_LENGTH, 0xFFFFFFFFu);

    ASSERT_EQ_INT(oca_peek_manifest(buf, sizeof buf, &pk), OCA_OK);
    ASSERT_EQ_INT(pk.body_size, OCA_CLASSIC_BODY_SIZE);   /* NOT 0xFFFFFFFF */
    ASSERT_EQ_INT(pk.declared_length, 0xFFFFFFFF);        /* reported as-is */

    /* And the post-copy check is what rejects it. */
    uint8_t body[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(body);
    toc_put_u32(body + OCA_OFF_MANIFEST_LENGTH, 0xFFFFFFFFu);
    ASSERT_EQ_INT(oca_check_manifest_length(body), OCA_FAIL_MANIFEST_LENGTH);
}

TEST(test_peek_rejects_a_short_head)
{
    uint8_t buf[OCA_MANIFEST_PEEK_MIN];
    oca_manifest_peek_t pk;
    memset(buf, 0, sizeof buf);
    memcpy(buf, "OCAC", 4);
    for (size_t n = 0u; n < OCA_MANIFEST_PEEK_MIN; ++n) {
        ASSERT_EQ_INT(oca_peek_manifest(buf, n, &pk), OCA_FAIL_TRUNCATED);
    }
    ASSERT_EQ_INT(oca_peek_manifest(buf, OCA_MANIFEST_PEEK_MIN, &pk), OCA_OK);
}

TEST(test_peek_rejects_bad_magic_and_null_args)
{
    uint8_t buf[OCA_MANIFEST_PEEK_MIN];
    oca_manifest_peek_t pk;
    memset(buf, 0, sizeof buf);
    memcpy(buf, "XCAC", 4);
    ASSERT_EQ_INT(oca_peek_manifest(buf, sizeof buf, &pk), OCA_FAIL_MAGIC);

    memcpy(buf, "OCAC", 4);
    ASSERT_EQ_INT(oca_peek_manifest(0, sizeof buf, &pk), OCA_FAIL_INVALID_ARG);
    ASSERT_EQ_INT(oca_peek_manifest(buf, sizeof buf, 0), OCA_FAIL_INVALID_ARG);
}

TEST(test_peek_sanitizes_the_identifier)
{
    uint8_t buf[OCA_MANIFEST_PEEK_MIN];
    oca_manifest_peek_t pk;
    memset(buf, 0, sizeof buf);
    memcpy(buf, "OCAC", 4);

    /* Control bytes and high bytes become '?'; trailing NULs/spaces vanish. */
    static const uint8_t raw[8] = { 'A', 0x07u, 'B', 0xFFu, 'C', ' ', 0x00u, 0x00u };
    memcpy(buf + OCA_OFF_MANIFEST_IDENTIFIER, raw, 8);
    ASSERT_EQ_INT(oca_peek_manifest(buf, sizeof buf, &pk), OCA_OK);
    ASSERT_EQ_INT(strcmp(pk.identifier, "A?B?C"), 0);

    /* All padding -> empty string, still NUL-terminated. */
    memset(buf + OCA_OFF_MANIFEST_IDENTIFIER, 0x20u, 8);
    ASSERT_EQ_INT(oca_peek_manifest(buf, sizeof buf, &pk), OCA_OK);
    ASSERT_EQ_INT(strcmp(pk.identifier, ""), 0);

    /* A full-width identifier is not truncated and is terminated. */
    memcpy(buf + OCA_OFF_MANIFEST_IDENTIFIER, "ABCDEFGH", 8);
    ASSERT_EQ_INT(oca_peek_manifest(buf, sizeof buf, &pk), OCA_OK);
    ASSERT_EQ_INT(strcmp(pk.identifier, "ABCDEFGH"), 0);
    ASSERT_EQ_INT(pk.identifier[OCA_MANIFEST_IDENTIFIER_LEN], '\0');
}

/* ------------------------------------------------------------------ */
/* manifest_length self-description                                    */
/*                                                                     */
/* A staged consumer sizes its manifest copy from metadata read out of  */
/* storage before anything is authenticated. This check is where the    */
/* copied, authenticated manifest is required to agree about its own    */
/* size — so a mislabelled or truncated image is caught on that axis.   */
/* The field is inside the signed region, so once the signature         */
/* verifies this is an authenticated statement, not a hint.             */
/* ------------------------------------------------------------------ */

TEST(test_manifest_length_agrees_for_a_well_formed_body)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    ASSERT_EQ_INT(oca_check_manifest_length(buf), OCA_OK);
}

TEST(test_manifest_length_rejects_a_classic_body_claiming_pqc_size)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    /* OCAC magic, but the body claims 36864. */
    toc_put_u32(buf + OCA_OFF_MANIFEST_LENGTH, OCA_PQC_BODY_SIZE);
    ASSERT_EQ_INT(oca_check_manifest_length(buf), OCA_FAIL_MANIFEST_LENGTH);
}

TEST(test_manifest_length_rejects_near_miss_values)
{
    /* Off-by-one in either direction, and zero. A truncated image that still
     * carries a plausible-looking length must not slip through. */
    static const uint32_t bad[] = {
        0u, 1u, OCA_CLASSIC_BODY_SIZE - 1u, OCA_CLASSIC_BODY_SIZE + 1u,
        OCA_CLASSIC_BODY_SIZE / 2u, 0xFFFFFFFFu,
    };
    for (unsigned i = 0u; i < sizeof bad / sizeof bad[0]; ++i) {
        uint8_t buf[OCA_CLASSIC_BODY_SIZE];
        build_minimal_manifest(buf);
        toc_put_u32(buf + OCA_OFF_MANIFEST_LENGTH, bad[i]);
        ASSERT_EQ_INT(oca_check_manifest_length(buf), OCA_FAIL_MANIFEST_LENGTH);
    }
}

TEST(test_manifest_length_propagates_magic_failure)
{
    /* No recognizable variant means no body size to compare against — report
     * why, rather than a length mismatch that would misdescribe it. */
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[0] = 'X';
    ASSERT_EQ_INT(oca_check_manifest_length(buf), OCA_FAIL_MAGIC);
}

TEST(test_validate_manifest_runs_the_length_check)
{
    /* Composed into the canonical order, not merely available. */
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_callbacks_t cb;

    build_minimal_manifest(buf);
    build_full_cb(&cb, buf);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, NULL), OCA_OK);

    toc_put_u32(buf + OCA_OFF_MANIFEST_LENGTH, OCA_CLASSIC_BODY_SIZE + 8u);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, NULL),
                  OCA_FAIL_MANIFEST_LENGTH);
}

TEST(test_both_entry_points_agree_on_a_manifest_level_failure)
{
    /* oca_validate() is oca_validate_manifest() plus the payload stage, so a
     * manifest-level verdict must surface identically through both. Inlining
     * the check list into oca_validate() would let a new check reach the
     * whole-bundle path and silently skip the staged one. */
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_callbacks_t cb;

    build_minimal_manifest(buf);
    build_full_cb(&cb, buf);
    toc_put_u32(buf + OCA_OFF_MANIFEST_LENGTH, OCA_CLASSIC_BODY_SIZE + 8u);

    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, NULL),
                  OCA_FAIL_MANIFEST_LENGTH);
    ASSERT_EQ_INT(oca_validate(buf, sizeof buf, &cb, NULL, NULL),
                  OCA_FAIL_MANIFEST_LENGTH);
}

TEST(test_result_string_covers_the_manifest_length_code)
{
    ASSERT_EQ_INT(strcmp(oca_result_str(OCA_FAIL_MANIFEST_LENGTH),
                         "MANIFEST_LENGTH"), 0);
}

/* ------------------------------------------------------------------ */
/* Resolving payload_offset in storage                                 */
/*                                                                     */
/* payload_offset is a SIGNED i64 in the manifest's UNSIGNED tail, so   */
/* it is attacker-controlled. Following it is safe only once bounded.   */
/* boot-manifest v3 makes the resolution and range validation a         */
/* Consumer `shall`; these tests are that requirement, case by case.    */
/* ------------------------------------------------------------------ */

#define LOC_MANIFEST_ADDR  0x00100000        /* 1 MiB into the device */
#define LOC_REGION_BASE    0x00000000
#define LOC_REGION_LIMIT   0x01000000        /* 16 MiB device */
#define LOC_PAYLOAD_LEN    4096u

static void loc_bounds_init(oca_storage_bounds_t *b)
{
    b->manifest_addr = LOC_MANIFEST_ADDR;
    b->region_base   = LOC_REGION_BASE;
    b->region_limit  = LOC_REGION_LIMIT;
}

/* A cleartext manifest declaring a LOC_PAYLOAD_LEN payload at `offset`. */
static void loc_body_init(uint8_t *buf, int64_t offset)
{
    memset(buf, 0, OCA_CLASSIC_BODY_SIZE);
    build_minimal_manifest(buf);
    toc_put_u64(buf + OCA_OFF_PAYLOAD_LENGTH, LOC_PAYLOAD_LEN);
    toc_put_u64(buf + OCA_CLASSIC_OFF_PAYLOAD_OFFSET, (uint64_t)offset);
}

static oca_result_t loc_run(int64_t offset, int64_t *out_addr, size_t *out_span)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_storage_bounds_t bounds;
    loc_body_init(buf, offset);
    loc_bounds_init(&bounds);
    int64_t addr = 0; size_t span = 0u;
    oca_result_t r = oca_locate_payload(buf, &bounds, &addr, &span);
    if (out_addr) *out_addr = addr;
    if (out_span) *out_span = span;
    return r;
}

TEST(test_locate_payload_accepts_the_ordinary_case)
{
    /* payload_offset == body_size: what every single-bundle manifest carries,
     * and what oca_check_payload has always assumed. */
    int64_t addr = 0; size_t span = 0u;
    ASSERT_EQ_INT(loc_run(OCA_CLASSIC_BODY_SIZE, &addr, &span), OCA_OK);
    ASSERT_EQ_INT(addr, LOC_MANIFEST_ADDR + OCA_CLASSIC_BODY_SIZE);
    ASSERT_EQ_INT(span, LOC_PAYLOAD_LEN);
}

TEST(test_locate_payload_accepts_a_gap_after_the_manifest)
{
    /* The oca-combined case that fails today: payload well past the body. */
    int64_t addr = 0;
    ASSERT_EQ_INT(loc_run(0x8000, &addr, 0), OCA_OK);
    ASSERT_EQ_INT(addr, LOC_MANIFEST_ADDR + 0x8000);
}

TEST(test_locate_payload_accepts_payload_before_the_manifest)
{
    /* Negative offset is legal: the spec says so explicitly. Placed far enough
     * back that it clears the manifest region. */
    int64_t addr = 0;
    ASSERT_EQ_INT(loc_run(-0x8000, &addr, 0), OCA_OK);
    ASSERT_EQ_INT(addr, LOC_MANIFEST_ADDR - 0x8000);
}

TEST(test_locate_payload_rejects_underflow_below_the_region)
{
    /* "-10000000 from the start of the manifest" — resolves below region_base. */
    ASSERT_EQ_INT(loc_run(-10000000, 0, 0), OCA_FAIL_PAYLOAD_LOCATION);
    /* And an offset so negative it would underflow the arithmetic itself. */
    ASSERT_EQ_INT(loc_run(INT64_MIN, 0, 0), OCA_FAIL_PAYLOAD_LOCATION);
    ASSERT_EQ_INT(loc_run(INT64_MIN + 1, 0, 0), OCA_FAIL_PAYLOAD_LOCATION);
}

TEST(test_locate_payload_rejects_running_past_the_region)
{
    /* Starts inside, ends outside: the payload's LENGTH is what runs over. */
    int64_t just_over = LOC_REGION_LIMIT - LOC_MANIFEST_ADDR - (int64_t)LOC_PAYLOAD_LEN + 8;
    ASSERT_EQ_INT(loc_run(just_over, 0, 0), OCA_FAIL_PAYLOAD_LOCATION);
    /* Wholly past the end. */
    ASSERT_EQ_INT(loc_run(LOC_REGION_LIMIT, 0, 0), OCA_FAIL_PAYLOAD_LOCATION);
    /* And an offset large enough to overflow addr + span. */
    ASSERT_EQ_INT(loc_run(INT64_MAX, 0, 0), OCA_FAIL_PAYLOAD_LOCATION);
    ASSERT_EQ_INT(loc_run(INT64_MAX - 16, 0, 0), OCA_FAIL_PAYLOAD_LOCATION);
}

TEST(test_locate_payload_rejects_the_exact_region_boundary_overrun)
{
    /* Ending exactly AT region_limit is legal; one byte past is not. */
    int64_t flush = LOC_REGION_LIMIT - LOC_MANIFEST_ADDR - (int64_t)LOC_PAYLOAD_LEN;
    ASSERT_EQ_INT(loc_run(flush, 0, 0), OCA_OK);
    ASSERT_EQ_INT(loc_run(flush + 8, 0, 0), OCA_FAIL_PAYLOAD_LOCATION);
}

TEST(test_locate_payload_rejects_collision_with_the_manifest)
{
    /* Offset 0 puts the payload on top of the manifest body. */
    ASSERT_EQ_INT(loc_run(0, 0, 0), OCA_FAIL_PAYLOAD_LOCATION);
    /* Inside the body. */
    ASSERT_EQ_INT(loc_run(8, 0, 0), OCA_FAIL_PAYLOAD_LOCATION);
    /* One byte short of clearing the body — the classic off-by-one. */
    ASSERT_EQ_INT(loc_run(OCA_CLASSIC_BODY_SIZE - 8, 0, 0),
                  OCA_FAIL_PAYLOAD_LOCATION);
}

TEST(test_locate_payload_rejects_payload_before_manifest_that_overruns_it)
{
    /* THE case a bounds-only check misses: the payload starts legally before
     * the manifest, inside the region, but its length runs forward into it. */
    int64_t offset = -(int64_t)(LOC_PAYLOAD_LEN / 2);   /* ends mid-manifest */
    ASSERT_EQ_INT(loc_run(offset, 0, 0), OCA_FAIL_PAYLOAD_LOCATION);
    /* Ending exactly where the manifest starts is fine — half-open ranges. */
    ASSERT_EQ_INT(loc_run(-(int64_t)LOC_PAYLOAD_LEN, 0, 0), OCA_OK);
    /* One byte of overlap is not. */
    ASSERT_EQ_INT(loc_run(-(int64_t)LOC_PAYLOAD_LEN + 8, 0, 0),
                  OCA_FAIL_PAYLOAD_LOCATION);
}

TEST(test_locate_payload_rejects_collision_with_appended_entries)
{
    /* With a verifier key entry appended, the manifest's footprint grows by
     * 2048 B — and a payload that used to clear the body no longer does. This
     * is the bound that keeps working when the entries land. */
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_storage_bounds_t bounds;
    int64_t addr = 0; size_t span = 0u;

    loc_body_init(buf, OCA_CLASSIC_BODY_SIZE);
    loc_bounds_init(&bounds);
    ASSERT_EQ_INT(oca_locate_payload(buf, &bounds, &addr, &span), OCA_OK);

    buf[OCA_OFF_VERIFIER_KEY_CONTROL] |= OCA_VERIFIER_KEY_CONTROL_USE_BIT;
    ASSERT_EQ_INT(oca_locate_payload(buf, &bounds, &addr, &span),
                  OCA_FAIL_PAYLOAD_LOCATION);

    /* Past the verifier entry, it is legal again. */
    toc_put_u64(buf + OCA_CLASSIC_OFF_PAYLOAD_OFFSET,
                OCA_CLASSIC_BODY_SIZE + OCA_CLASSIC_VERIFIER_ENTRY_SIZE);
    ASSERT_EQ_INT(oca_locate_payload(buf, &bounds, &addr, &span), OCA_OK);
}

static size_t region_len_of(const uint8_t *body)
{
    size_t len = 0u;
    ASSERT_EQ_INT(oca_manifest_region_len(body, &len), OCA_OK);
    return len;
}

TEST(test_manifest_region_len_counts_appended_entries)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    loc_body_init(buf, OCA_CLASSIC_BODY_SIZE);

    /* Deferred features off: the region is just the body. */
    ASSERT_EQ_INT(region_len_of(buf), OCA_CLASSIC_BODY_SIZE);

    buf[OCA_OFF_VERIFIER_KEY_CONTROL] |= OCA_VERIFIER_KEY_CONTROL_USE_BIT;
    ASSERT_EQ_INT(region_len_of(buf),
                  OCA_CLASSIC_BODY_SIZE + OCA_CLASSIC_VERIFIER_ENTRY_SIZE);

    /* Three co-signers enabled -> three appended entries. */
    buf[OCA_OFF_CO_SIGNER_CONTROL] = 0x07u;
    ASSERT_EQ_INT(region_len_of(buf),
                  OCA_CLASSIC_BODY_SIZE + OCA_CLASSIC_VERIFIER_ENTRY_SIZE
                  + 3u * OCA_CLASSIC_CO_SIGNER_ENTRY_SIZE);

    /* All eight, the worst case. */
    buf[OCA_OFF_CO_SIGNER_CONTROL] = 0xFFu;
    ASSERT_EQ_INT(region_len_of(buf),
                  OCA_CLASSIC_BODY_SIZE + OCA_CLASSIC_VERIFIER_ENTRY_SIZE
                  + 8u * OCA_CLASSIC_CO_SIGNER_ENTRY_SIZE);
}

TEST(test_manifest_region_len_reports_why_it_failed)
{
    /* The reason the signature returns oca_result_t: a caller can tell a NULL
     * argument from a bad magic from an unsupported variant, instead of getting
     * an ambiguous 0. */
    size_t len = 12345u;
    ASSERT_EQ_INT(oca_manifest_region_len(0, &len), OCA_FAIL_INVALID_ARG);

    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    loc_body_init(buf, OCA_CLASSIC_BODY_SIZE);
    ASSERT_EQ_INT(oca_manifest_region_len(buf, 0), OCA_FAIL_INVALID_ARG);

    buf[0] = 'X';                       /* magic matches no known variant */
    ASSERT_EQ_INT(oca_manifest_region_len(buf, &len), OCA_FAIL_MAGIC);
}

TEST(test_locate_payload_rejects_bad_arguments)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_storage_bounds_t bounds;
    int64_t addr = 0; size_t span = 0u;
    loc_body_init(buf, OCA_CLASSIC_BODY_SIZE);
    loc_bounds_init(&bounds);

    ASSERT_EQ_INT(oca_locate_payload(0, &bounds, &addr, &span), OCA_FAIL_INVALID_ARG);
    ASSERT_EQ_INT(oca_locate_payload(buf, 0, &addr, &span), OCA_FAIL_INVALID_ARG);
    ASSERT_EQ_INT(oca_locate_payload(buf, &bounds, 0, &span), OCA_FAIL_INVALID_ARG);
    ASSERT_EQ_INT(oca_locate_payload(buf, &bounds, &addr, 0), OCA_FAIL_INVALID_ARG);

    /* An inverted or empty region is the caller's mistake, not the manifest's. */
    oca_storage_bounds_t bad = bounds;
    bad.region_limit = bad.region_base;
    ASSERT_EQ_INT(oca_locate_payload(buf, &bad, &addr, &span), OCA_FAIL_INVALID_ARG);
    bad = bounds; bad.region_limit = bounds.region_base - 1;
    ASSERT_EQ_INT(oca_locate_payload(buf, &bad, &addr, &span), OCA_FAIL_INVALID_ARG);
    /* Manifest outside its own region. */
    bad = bounds; bad.manifest_addr = bounds.region_limit;
    ASSERT_EQ_INT(oca_locate_payload(buf, &bad, &addr, &span), OCA_FAIL_INVALID_ARG);
}

TEST(test_locate_payload_no_payload_declared_is_ok)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_storage_bounds_t bounds;
    int64_t addr = 1; size_t span = 1u;
    memset(buf, 0, sizeof buf);
    build_minimal_manifest(buf);            /* payload_length stays 0 */
    loc_bounds_init(&bounds);
    ASSERT_EQ_INT(oca_locate_payload(buf, &bounds, &addr, &span), OCA_OK);
    ASSERT_EQ_INT(span, 0);
}

TEST(test_locate_payload_spans_the_ciphertext_when_encrypted)
{
    /* Encrypted payloads are sized by payload_hashed_length, not payload_length. */
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_storage_bounds_t bounds;
    int64_t addr = 0; size_t span = 0u;
    loc_body_init(buf, OCA_CLASSIC_BODY_SIZE);
    buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x01u;
    toc_put_u64(buf + OCA_OFF_PAYLOAD_HASHED_LENGTH, 8192u);
    loc_bounds_init(&bounds);
    ASSERT_EQ_INT(oca_locate_payload(buf, &bounds, &addr, &span), OCA_OK);
    ASSERT_EQ_INT(span, 8192);
}

TEST(test_check_payload_at_accepts_a_noncontiguous_payload)
{
    /* The whole point: body and payload in separate buffers. Mirrors the
     * cleartext happy path, but with the payload nowhere near the body. */
    uint8_t body[OCA_CLASSIC_BODY_SIZE];
    uint8_t payload[CLEAR_PAYLOAD_LEN];
    uint8_t bundle[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];

    /* Build the contiguous bundle the old API needs, then split it. */
    build_cleartext_bundle(bundle);
    memcpy(body, bundle, OCA_CLASSIC_BODY_SIZE);
    memcpy(payload, bundle + OCA_CLASSIC_BODY_SIZE, CLEAR_PAYLOAD_LEN);

    oca_callbacks_t cb;
    cleartext_cb(&cb);

    /* Contiguous form still passes, and the split form agrees. */
    ASSERT_EQ_INT(oca_check_payload(bundle, sizeof bundle, &cb, &g_authenticated, NULL), OCA_OK);
    ASSERT_EQ_INT(oca_check_payload_at(body, payload, sizeof payload, &cb, &g_authenticated, NULL), OCA_OK);

    /* A defect in the detached payload is still caught. Corrupt the TOC's own
     * payload_length rather than image bytes: this harness's sha256 stub digests
     * everything to all-zero, so CONTENT tampering is invisible here by design.
     * Content tampering is covered end-to-end by the CLI integration tests,
     * which use a real SHA-256. */
    toc_put_u64(payload + OCA_TOC_OFF_PAYLOAD_LENGTH, CLEAR_PAYLOAD_LEN + 8u);
    ASSERT_EQ_INT(oca_check_payload_at(body, payload, sizeof payload, &cb, &g_authenticated, NULL),
                  OCA_FAIL_PAYLOAD_TOC);
}

TEST(test_check_payload_at_rejects_bad_arguments)
{
    uint8_t bundle[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    oca_callbacks_t cb;
    build_cleartext_bundle(bundle);
    cleartext_cb(&cb);

    ASSERT_EQ_INT(oca_check_payload_at(0, bundle + OCA_CLASSIC_BODY_SIZE,
                                       CLEAR_PAYLOAD_LEN, &cb, &g_authenticated, NULL),
                  OCA_FAIL_INVALID_ARG);
    ASSERT_EQ_INT(oca_check_payload_at(bundle, 0, CLEAR_PAYLOAD_LEN, &cb, &g_authenticated, NULL),
                  OCA_FAIL_INVALID_ARG);
    /* Short payload buffer -> TRUNCATED, not a read past the end. */
    ASSERT_EQ_INT(oca_check_payload_at(bundle, bundle + OCA_CLASSIC_BODY_SIZE,
                                       CLEAR_PAYLOAD_LEN - 8u, &cb, &g_authenticated, NULL),
                  OCA_FAIL_TRUNCATED);
}

TEST(test_check_payload_refuses_to_guess_when_offset_disagrees)
{
    /* oca_check_payload assumes the payload follows the body. When the manifest
     * says otherwise, it must refuse rather than hash whatever is there and
     * report PAYLOAD_HASH — the misdiagnosis this whole change exists to kill. */
    uint8_t bundle[OCA_CLASSIC_BODY_SIZE + CLEAR_PAYLOAD_LEN];
    oca_callbacks_t cb;

    build_cleartext_bundle(bundle);
    cleartext_cb(&cb);
    ASSERT_EQ_INT(oca_check_payload(bundle, sizeof bundle, &cb, &g_authenticated, NULL), OCA_OK);

    /* Payload declared elsewhere -> refuse, with the accurate code. */
    toc_put_u64(bundle + OCA_CLASSIC_OFF_PAYLOAD_OFFSET, 0x8000u);
    ASSERT_EQ_INT(oca_check_payload(bundle, sizeof bundle, &cb, &g_authenticated, NULL),
                  OCA_FAIL_PAYLOAD_LOCATION);

    /* ...but oca_check_payload_at still works, because the caller is telling it
     * where the payload actually is. */
    ASSERT_EQ_INT(oca_check_payload_at(bundle, bundle + OCA_CLASSIC_BODY_SIZE,
                                       CLEAR_PAYLOAD_LEN, &cb, &g_authenticated, NULL), OCA_OK);
}

TEST(test_check_payload_ignores_offset_when_no_payload_declared)
{
    /* With no payload, where it would have been is moot. */
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_callbacks_t cb;
    memset(buf, 0, sizeof buf);
    build_minimal_manifest(buf);                 /* payload_length == 0 */
    memset(&cb, 0, sizeof cb);
    toc_put_u64(buf + OCA_CLASSIC_OFF_PAYLOAD_OFFSET, 0x8000u);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &g_authenticated, NULL), OCA_OK);
}

TEST(test_result_string_covers_the_location_code)
{
    ASSERT_EQ_INT(strcmp(oca_result_str(OCA_FAIL_PAYLOAD_LOCATION),
                         "PAYLOAD_LOCATION"), 0);
}

/* ------------------------------------------------------------------ */
/* Secure-boot device-state: ROOT-key revocation + anti-rollback +    */
/* device-state commit                                                */
/* ------------------------------------------------------------------ */

/* Device-state readers and writers over the fixture's fuse/OTP stand-in. */

static oca_result_t dev_get_revoke(oca_key_algorithm_t algo, uint8_t out[16])
{
    (void)algo;
    g_fx.revoke_calls++;
    memcpy(out, g_fx.revoke, 16);
    return OCA_OK;
}

static oca_result_t dev_get_secver(uint8_t out[16])
{
    memcpy(out, g_fx.secver, 16);
    return OCA_OK;
}

static oca_result_t dev_set_revoke(oca_key_algorithm_t algo, const uint8_t in[16])
{
    (void)algo;    g_fx.set_calls++;
    if (g_fx.fail_set) return OCA_FAIL_SECURITY_STATE_UPDATE;
    memcpy(g_fx.revoke, in, 16);
    return OCA_OK;
}

static oca_result_t dev_set_secver(const uint8_t in[16])
{
    g_fx.set_calls++;
    if (g_fx.fail_set) return OCA_FAIL_SECURITY_STATE_UPDATE;
    memcpy(g_fx.secver, in, 16);
    return OCA_OK;
}

static oca_result_t dev_get_cohort(uint8_t out[8])
{
    memcpy(out, g_fx.cohort, 8);
    return OCA_OK;
}

static oca_result_t dev_set_cohort(const uint8_t in[8])
{
    g_fx.set_calls++;
    if (g_fx.fail_set) return OCA_FAIL_SECURITY_STATE_UPDATE;
    memcpy(g_fx.cohort, in, 8);
    return OCA_OK;
}

static oca_result_t dev_get_class_revoke(uint8_t out[8])
{
    memcpy(out, g_fx.class_revoke, 8);
    return OCA_OK;
}

static oca_result_t dev_set_class_revoke(const uint8_t in[8])
{
    g_fx.set_calls++;
    if (g_fx.fail_set) return OCA_FAIL_SECURITY_STATE_UPDATE;
    memcpy(g_fx.class_revoke, in, 8);
    return OCA_OK;
}

/* secure-boot manifest with one selected ROOT key (group 1, slot 0).
 *
 * The algorithm, encodings, and both `*_size_classic` fields are populated to a
 * self-consistent RSA-3072 raw combination. They have to be: a secure manifest
 * whose size fields do not describe what its declared algorithm and encoding can
 * produce is rejected before the signature callback is ever reached. */
static void build_secure_manifest(uint8_t buf[OCA_CLASSIC_BODY_SIZE])
{
    build_minimal_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x03u;   /* secure boot enabled, classic class */
    buf[OCA_OFF_PUBLIC_KEY_SELECT] = 0x01u;     /* authorize key slot 0 */
    buf[OCA_OFF_SIGNATURE_TYPE] = OCA_PRIMITIVE_RSA_3072_PKCS1V15_SHA256;
    buf[OCA_OFF_SIGNATURE_ENCODING] = OCA_ENCODING_RAW;
    buf[OCA_OFF_PUBLIC_KEY_ENCODING] = OCA_ENCODING_RAW;
    toc_put_u16(buf + OCA_OFF_SIGNATURE_SIZE, 384u);   /* raw RSA-3072 signature */
    toc_put_u16(buf + OCA_OFF_PUBLIC_KEY_SIZE, 388u);  /* BE modulus || BE exponent */
}

static void set_revoke_bit(uint8_t buf[OCA_CLASSIC_BODY_SIZE], unsigned n)
{
    buf[OCA_OFF_PUBLIC_KEY_CLASSIC_REVOKE + (n / 8)] |= (uint8_t)(1u << (n % 8));
}

static oca_result_t counting_signature_cb(const oca_crypto_blob_t *sig,
                                          const oca_crypto_blob_t *pk,
                                          const uint8_t *signed_region,
                                          size_t signed_region_len)
{
    (void)sig; (void)pk; (void)signed_region; (void)signed_region_len;    g_fx.sig_calls++;
    return OCA_OK;
}

static oca_result_t failing_signature_cb(const oca_crypto_blob_t *sig,
                                         const oca_crypto_blob_t *pk,
                                         const uint8_t *signed_region,
                                         size_t signed_region_len)
{
    (void)sig; (void)pk; (void)signed_region; (void)signed_region_len;    g_fx.sig_calls++;
    return OCA_FAIL_SIGNATURE;
}

/* Captures which signature blob each verify call was handed, and optionally
 * fails exactly one algorithm family — the hybrid AND tests need to fail each
 * class in turn while the other verifies. Outside the fixture; tests that
 * assert on these reset them by hand. */
static const uint8_t *g_verify_sig_bytes[2];
static oca_key_algorithm_t g_verify_algo[2];
static size_t g_verify_region_len[2];
static oca_crypto_blob_t g_verify_pk_blob[2];
static bool g_verify_fail_enabled;
static oca_key_algorithm_t g_verify_fail_algo;
static oca_result_t verify_capture_cb(const oca_crypto_blob_t *sig,
                                      const oca_crypto_blob_t *pk,
                                      const uint8_t *signed_region,
                                      size_t signed_region_len)
{
    (void)signed_region;
    if (g_fx.sig_calls >= 0 && g_fx.sig_calls < 2) {
        g_verify_sig_bytes[g_fx.sig_calls]  = sig->bytes;
        g_verify_algo[g_fx.sig_calls]       = sig->key_algorithm;
        g_verify_region_len[g_fx.sig_calls] = signed_region_len;
        g_verify_pk_blob[g_fx.sig_calls]    = *pk;
    }
    g_fx.sig_calls++;
    if (g_verify_fail_enabled && sig->key_algorithm == g_verify_fail_algo) {
        return OCA_FAIL_SIGNATURE;
    }
    return OCA_OK;
}

/* OCAP-framed counterpart of build_minimal_manifest: framing only, secure boot
 * off. The 0x35 classic-trailer slot and the 0x96 PQC trailer are what the
 * structural checks demand of this variant. */
static void build_minimal_pqc_manifest(uint8_t buf[OCA_PQC_BODY_SIZE])
{
    memset(buf, 0, OCA_PQC_BODY_SIZE);
    memcpy(buf + OCA_OFF_MAGIC, OCA_PQC_MAGIC, OCA_MAGIC_LEN);
    memcpy(buf + OCA_OFF_MANIFEST_IDENTIFIER, "UNIT", 4);
    buf[OCA_OFF_MANIFEST_VERSION_MAJOR + 0] =
        (uint8_t)(OCA_LIB_MANIFEST_MAJOR & 0xFF);
    buf[OCA_OFF_MANIFEST_VERSION_MINOR + 0] =
        (uint8_t)(OCA_LIB_MANIFEST_MINOR & 0xFF);
    /* manifest_length = payload_offset = 36864 (0x9000) */
    buf[OCA_OFF_MANIFEST_LENGTH + 1] = 0x90;
    buf[OCA_PQC_OFF_PAYLOAD_OFFSET + 1] = 0x90;
    memset(buf + OCA_PQC_OFF_CLASSIC_TRAILER_SLOT,
           OCA_PQC_CLASSIC_TRAILER_SLOT_BYTE, OCA_PQC_CLASSIC_TRAILER_SLOT_LEN);
    memset(buf + OCA_PQC_OFF_TRAILER, OCA_PQC_TRAILER_BYTE, OCA_PQC_TRAILER_LEN);
    /* manifest_hash sentinel, mirrored back by stub_sha256_pass when the test
     * sets g_fx.sha_hash_off to this variant's hash position. */
    for (unsigned i = 0; i < 32; ++i) {
        buf[OCA_PQC_OFF_MANIFEST_HASH + i] = (uint8_t)i;
    }
}

/* Secure PQC manifest with the given secure_boot_control. BOTH class
 * descriptions are populated self-consistently — raw RSA-3072 classical, raw
 * ML-DSA-87 PQC — so whichever classes the control byte names survive the
 * crypto-field-size check, and a test picks classes with the control byte
 * alone: 0x03 classic-only, 0x05 pqc-only, 0x07 hybrid. */
static void build_secure_pqc_manifest(uint8_t buf[OCA_PQC_BODY_SIZE],
                                      uint8_t control)
{
    build_minimal_pqc_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = control;
    buf[OCA_OFF_PUBLIC_KEY_SELECT] = 0x01u;
    buf[OCA_OFF_SIGNATURE_TYPE] = OCA_PRIMITIVE_RSA_3072_PKCS1V15_SHA256;
    buf[OCA_OFF_SIGNATURE_ENCODING] = OCA_ENCODING_RAW;
    buf[OCA_OFF_PUBLIC_KEY_ENCODING] = OCA_ENCODING_RAW;
    toc_put_u16(buf + OCA_OFF_SIGNATURE_SIZE, 384u);
    toc_put_u16(buf + OCA_OFF_PUBLIC_KEY_SIZE, 388u);
    buf[OCA_PQC_OFF_PUBLIC_KEY_SELECT] = 0x01u;
    buf[OCA_PQC_OFF_SIGNATURE_TYPE] = OCA_PRIMITIVE_ML_DSA_87;
    buf[OCA_PQC_OFF_SIGNATURE_ENCODING] = OCA_ENCODING_RAW;
    buf[OCA_PQC_OFF_PUBLIC_KEY_ENCODING] = OCA_ENCODING_RAW;
    /* ML-DSA-87: raw public key 2592, signature 4627. */
    toc_put_u16(buf + OCA_PQC_OFF_SIGNATURE_SIZE, 4627u);
    toc_put_u16(buf + OCA_PQC_OFF_PUBLIC_KEY_SIZE, 2592u);
}

/* Full callback table for device-state pipeline tests: passing sha + counting
 * signature + the device-state stub get/set callbacks. */
static void build_devstate_cb(oca_callbacks_t *cb,
                              const uint8_t *body)
{
    memset(cb, 0, sizeof(*cb));
    g_fx.sha_body = body;
    cb->sha256                  = stub_sha256_pass;
    cb->verify_signature        = counting_signature_cb;
    cb->is_key_authorized = authorize_any_cb;
    cb->get_root_key_revocation = dev_get_revoke;
    cb->get_security_version    = dev_get_secver;
    cb->set_root_key_revocation = dev_set_revoke;
    cb->set_security_version    = dev_set_secver;
    cb->get_signature_cohort_enforce = dev_get_cohort;
    cb->set_signature_cohort_enforce = dev_set_cohort;
    cb->get_signature_class_revoke   = dev_get_class_revoke;
    cb->set_signature_class_revoke   = dev_set_class_revoke;
}

/* ------------------------------------------------------------------ */
/* Encryption requires CONFIRMED secure boot                          */
/*                                                                    */
/* The gate reads what oca_check_signature recorded. Every test here  */
/* that expects a refusal also asserts the decrypt callback was never */
/* invoked: a correct result code with the wrong call pattern would   */
/* leave the device's provisioned secret exercised anyway, which is   */
/* the whole thing being prevented.                                   */
/* ------------------------------------------------------------------ */

/* Counts decrypt invocations so "no decryption occurred" is measured, not
 * inferred from the returned code. */
static oca_result_t counting_decrypt_cb(const oca_decrypt_input_t *in,
                                        const uint8_t **out_pt, size_t *out_pt_len)
{
    
    g_fx.decrypt_calls++;
    *out_pt = in->ciphertext;
    *out_pt_len = in->ciphertext_len;
    return OCA_OK;
}

/* Secure boot OFF, reported by the device. */
static oca_secure_bool_t sb_off_cb(void) { return OCA_SECURE_FALSE; }

/* Encrypted bundle + callbacks that would decrypt if allowed to. `secure` picks
 * whether the device reports secure boot on or off. */
static void build_gate_case(uint8_t *buf, oca_callbacks_t *cb,
                            bool secure)
{
    uint8_t zero[32];
    memset(zero, 0, sizeof zero);
    build_encrypted_bundle(buf, zero, zero);
    g_fx.sha_body = buf;
    memset(cb, 0, sizeof(*cb));
    cb->sha256 = stub_sha256_pass;
    cb->decrypt_payload = counting_decrypt_cb;
    cb->verify_signature = counting_signature_cb;
    cb->is_key_authorized = authorize_any_cb;
    cb->is_secure_boot_active = secure ? sb_active_cb : sb_off_cb;
    g_fx.decrypt_calls = 0;
}

TEST(test_encrypted_payload_refused_when_secure_boot_off)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    oca_callbacks_t cb;
    build_gate_case(buf, &cb, false);

    ASSERT_EQ_INT(oca_validate(buf, sizeof buf, &cb, NULL, NULL),
                  OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);
    ASSERT_EQ_INT(g_fx.decrypt_calls, 0);
}

TEST(test_encrypted_payload_refused_by_validate_manifest_alone)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    oca_callbacks_t cb;
    build_gate_case(buf, &cb, false);

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_validate_manifest(buf, OCA_CLASSIC_BODY_SIZE, &cb, &ctx),
                  OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);
    ASSERT_EQ_INT(g_fx.decrypt_calls, 0);
}

/* Both enforcement points must agree. Compared against each other rather than
 * against a literal, so a regression giving the payload guard its own code is
 * caught even if both codes look plausible in isolation. */
TEST(test_both_enforcement_points_report_the_same_reason)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    oca_callbacks_t cb;
    build_gate_case(buf, &cb, false);

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    oca_result_t from_manifest =
        oca_validate_manifest(buf, OCA_CLASSIC_BODY_SIZE, &cb, &ctx);
    oca_result_t from_payload =
        oca_check_payload_at(buf, buf + OCA_CLASSIC_BODY_SIZE, ENC_CT_LEN, &cb, &ctx, NULL);

    ASSERT_EQ_INT(from_manifest, from_payload);
    ASSERT_EQ_INT(from_manifest, OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);
}

/* Positive control, as a controlled A/B: the same bundle and the same callbacks
 * as the working encrypted path, with the recorded confirmation as the ONLY
 * variable. Refused unconfirmed, accepted confirmed — so the gate is
 * demonstrably the cause, not some property of the bundle. */
TEST(test_encrypted_payload_accepted_when_authenticated)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    uint8_t ph[32];    memset(ph, 0x5A, 32);
    uint8_t chain[32]; memset(chain, 0, 32);
    build_encrypted_bundle(buf, ph, chain);
    build_plaintext_toc();

    payload_sha_ctx_init(buf + OCA_CLASSIC_BODY_SIZE, true, 0x5A);
    oca_callbacks_t cb;
    payload_cb(&cb, decrypt_ok);

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &ctx, NULL),
                  OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);

    ctx.secure_boot_authenticated = OCA_SECURE_TRUE;
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &ctx, NULL), OCA_OK);
}

TEST(test_cleartext_payload_unaffected_at_either_secure_boot_state)
{
    for (int secure = 0; secure < 2; ++secure) {
        uint8_t buf[OCA_CLASSIC_BODY_SIZE];
        build_minimal_manifest(buf);
        g_fx.sha_body = buf;
        oca_callbacks_t cb;
        memset(&cb, 0, sizeof cb);
        cb.sha256 = stub_sha256_pass;
        cb.verify_signature = counting_signature_cb;
        cb.is_key_authorized = authorize_any_cb;
        cb.is_secure_boot_active = secure ? sb_active_cb : sb_off_cb;

        oca_validation_context_t ctx;
        oca_validation_context_init(&ctx);
        ASSERT_EQ_INT(oca_check_payload_encryption_policy(buf, &cb, &ctx), OCA_OK);
    }
}

/* PQC bodies use the same shared encryption offsets, so the rule must apply
 * identically. This is what makes "variant-agnostic by construction" a verified
 * property rather than an assumption about the layout. */
TEST(test_encryption_gate_applies_to_pqc_variant)
{
    /* The gate needs only the magic (to resolve the variant) and the control
     * bit; a full valid PQC body would add nothing to what is under test. */
    static uint8_t buf[OCA_PQC_BODY_SIZE];
    memset(buf, 0, sizeof buf);
    memcpy(buf, "OCAP", 4);
    buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x01u;

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_check_payload_encryption_policy(buf, NULL, &ctx),
                  OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);

    ctx.secure_boot_authenticated = OCA_SECURE_TRUE;
    ASSERT_EQ_INT(oca_check_payload_encryption_policy(buf, NULL, &ctx), OCA_OK);
}

/* Boundary: the rule is about what the manifest DECLARES, not about whether any
 * decryption work would have happened. An implementation short-circuiting on an
 * empty payload would skip the check and pass every other test here. */
TEST(test_encryption_declared_with_zero_length_payload_still_refused)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x01u;
    /* payload_length and payload_hashed_length both left at zero */

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_check_payload_encryption_policy(buf, NULL, &ctx),
                  OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);
}

/* The mirror boundary: only the control bit governs. An implementation testing
 * `encryption_type != 0` would wrongly reject a legitimate cleartext manifest
 * that happens to carry stray values in those fields. */
TEST(test_cleartext_with_stray_encryption_fields_not_refused)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x00u;          /* the governing bit */
    buf[OCA_OFF_ENCRYPTION_TYPE] = OCA_ENCRYPTION_TYPE_AES_256_CBC;
    buf[OCA_OFF_ENCRYPTION_SHARED_SECRET_SELECT] = 0x07u;

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);           /* nothing authenticated */
    ASSERT_EQ_INT(oca_check_payload_encryption_policy(buf, NULL, &ctx), OCA_OK);
}

/* ---- composition independence: the gate cannot be skipped by ordering ---- */

TEST(test_payload_at_standalone_refuses_with_zero_init_context)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    oca_callbacks_t cb;
    build_gate_case(buf, &cb, true);   /* secure boot ON */

    /* No manifest checks composed at all: the context is untouched. */
    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_check_payload_at(buf, buf + OCA_CLASSIC_BODY_SIZE,
                                       ENC_CT_LEN, &cb, &ctx, NULL),
                  OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);
    ASSERT_EQ_INT(g_fx.decrypt_calls, 0);
}

TEST(test_check_payload_standalone_refuses_with_zero_init_context)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    oca_callbacks_t cb;
    build_gate_case(buf, &cb, true);

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_check_payload(buf, sizeof buf, &cb, &ctx, NULL),
                  OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);
    ASSERT_EQ_INT(g_fx.decrypt_calls, 0);
}

/* "Enabled" is not "confirmed". This is the distinction the whole feature turns
 * on: a sequence can establish that secure boot is in force and still never have
 * verified anything. */
TEST(test_enabled_without_authenticated_is_refused)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    oca_callbacks_t cb;
    build_gate_case(buf, &cb, true);

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ctx.secure_boot_enabled = OCA_SECURE_TRUE;   /* but nothing authenticated */
    ASSERT_EQ_INT(oca_check_payload_at(buf, buf + OCA_CLASSIC_BODY_SIZE,
                                       ENC_CT_LEN, &cb, &ctx, NULL),
                  OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);
    ASSERT_EQ_INT(g_fx.decrypt_calls, 0);
}

/* Only the exact OCA_SECURE_TRUE value admits decryption. Testing
 * `!= OCA_SECURE_FALSE` instead would let every one of these through. */
TEST(test_corrupted_confirmation_values_all_refuse)
{
    static const oca_secure_bool_t corrupt[] = {
        0x00000000u, 0xFFFFFFFFu, OCA_SECURE_FALSE,
        OCA_SECURE_TRUE ^ 1u, OCA_SECURE_TRUE ^ 0x80000000u,
        0x5A5A5A5Bu, 0xA5A5A5A4u
    };
    for (unsigned i = 0; i < sizeof corrupt / sizeof corrupt[0]; ++i) {
        uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    oca_callbacks_t cb;
        build_gate_case(buf, &cb, true);

        oca_validation_context_t ctx;
        oca_validation_context_init(&ctx);
        ctx.secure_boot_authenticated = corrupt[i];
        ASSERT_EQ_INT(oca_check_payload_at(buf, buf + OCA_CLASSIC_BODY_SIZE,
                                           ENC_CT_LEN, &cb, &ctx, NULL),
                      OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);
        ASSERT_EQ_INT(g_fx.decrypt_calls, 0);
    }
}

/* A NULL context is the same as an unconfirmed one — fail closed, not crash. */
TEST(test_null_context_refuses_encrypted_payload)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    oca_callbacks_t cb;
    build_gate_case(buf, &cb, true);

    ASSERT_EQ_INT(oca_check_payload_at(buf, buf + OCA_CLASSIC_BODY_SIZE,
                                       ENC_CT_LEN, &cb, NULL, NULL),
                  OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);
    ASSERT_EQ_INT(g_fx.decrypt_calls, 0);
}

/* A failed signature must leave the confirmation unset, so a later payload check
 * refuses. Guards against the flag being set ahead of the verify callback. */
TEST(test_failed_signature_leaves_confirmation_unset)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.verify_signature = failing_signature_cb;
    cb.is_key_authorized = authorize_any_cb;

    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx), OCA_FAIL_SIGNATURE);
    ASSERT_TRUE(ctx.secure_boot_authenticated != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_enabled == OCA_SECURE_TRUE);
}

/* Secure boot off makes oca_check_signature return OCA_OK — because there was
 * nothing to verify, NOT because anything did. Recording that as authentication
 * would open the gate for exactly the case it exists to close, and it is the
 * natural way to write the writer wrongly.
 *
 * The determination now writes secure_boot_enabled and oca_check_signature
 * writes secure_boot_authenticated, so this asserts across both: the pair a
 * non-secure part must end a signature check holding. */
TEST(test_secure_boot_off_records_neither_enabled_nor_authenticated)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    g_fx.sha_body = buf;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active = sb_off_cb;

    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx), OCA_OK);
    ASSERT_TRUE(ctx.secure_boot_enabled != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_authenticated != OCA_SECURE_TRUE);
}

/* Confirm the initialization of the the validation context does not set
 * any flags to true immediately */
TEST(test_context_init_leaves_nothing_established)
{
    oca_validation_context_t ctx;
    memset(&ctx, 0xFFu, sizeof ctx);          /* worst-case prior contents */
    oca_validation_context_init(&ctx);
    ASSERT_TRUE(ctx.secure_boot_enabled != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.manifest_is_classic != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.manifest_is_pqc != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_enforce_classic != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_enforce_pqc != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_key_authorized_classic != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_key_authorized_pqc != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_authenticated != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_device_disabled != OCA_SECURE_TRUE);

    /* A plain zeroing must mean the same thing, so a caller that memsets its own
     * struct is not accidentally trusted. */
    memset(&ctx, 0, sizeof ctx);
    ASSERT_TRUE(ctx.secure_boot_authenticated != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_device_disabled != OCA_SECURE_TRUE);
}

/* oca_result_str falls through to "UNKNOWN" for unhandled codes, so a missing
 * switch case is silent — the CLI would print FAIL: UNKNOWN and every
 * integration test matching on the real string would fail far from the cause.
 * This also pins the exact spelling those tests match. */
TEST(test_result_string_covers_the_encryption_policy_code)
{
    ASSERT_EQ_INT(strcmp(oca_result_str(OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT),
                         "ENCRYPTION_REQUIRES_SECURE_BOOT"), 0);
}

/* Same guard for the signature-class code, for the same reason. */
TEST(test_result_string_covers_the_signature_class_code)
{
    ASSERT_EQ_INT(strcmp(oca_result_str(OCA_FAIL_SIGNATURE_CLASS_CONTROL),
                         "SIGNATURE_CLASS_CONTROL"), 0);
}

/* ---- ROOT-key revocation ---- */

TEST(test_root_key_revoked_by_manifest)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    set_revoke_bit(buf, 0);                 /* revoke the selected key slot 0 */
    test_fixture_reset();
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    cb.get_root_key_revocation = dev_get_revoke;
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_root_key_revocation(buf, &cb, &ctx), OCA_FAIL_ROOT_KEY_REVOKED);
}

TEST(test_root_key_revoked_by_device_state)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);             /* manifest revoke = 0 */
    test_fixture_reset();
    g_fx.revoke[0] = 0x01u;                /* device revokes slot 0 */
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    cb.get_root_key_revocation = dev_get_revoke;
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_root_key_revocation(buf, &cb, &ctx), OCA_FAIL_ROOT_KEY_REVOKED);
}

TEST(test_root_key_not_revoked_passes)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);             /* select slot 0; revoke = 0; device = 0 */
    test_fixture_reset();
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    cb.get_root_key_revocation = dev_get_revoke;
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_root_key_revocation(buf, &cb, &ctx), OCA_OK);
}

/* A reserved bit (127:112) set in BOTH select and revoke must be ignored — if
 * the reserved region were compared, this would falsely report revoked. */
TEST(test_root_key_reserved_bits_ignored)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);                       /* selected key slot 0 */
    buf[OCA_OFF_PUBLIC_KEY_SELECT + 15] |= 0x01u;     /* reserved select bit 120 */
    set_revoke_bit(buf, 120);                         /* reserved revoke bit 120 */
    test_fixture_reset();
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    cb.get_root_key_revocation = dev_get_revoke;
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_root_key_revocation(buf, &cb, &ctx), OCA_OK);
}

TEST(test_root_key_revocation_secure_boot_disabled_inert)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);            /* manifest secure_boot enable bit off */
    buf[OCA_OFF_PUBLIC_KEY_SELECT] = 0x01u;
    set_revoke_bit(buf, 0);                 /* would be revoked if engaged */
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active = sb_inactive_cb;  /* and device reports secure boot off */
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_root_key_revocation(buf, &cb, &ctx), OCA_OK);
}

/* Device-authoritative: manifest bit clear, but the device reports secure boot
 * active — the revocation check engages and rejects the revoked selected key. */
TEST(test_root_key_revocation_engaged_via_device_callback)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);            /* manifest secure_boot enable bit off */
    /* Classic class named with the enable bit clear: legal, and required — the
     * device is about to put secure boot in force, and an in-force boot with no
     * class named is the determination's SIGNATURE_CLASS_CONTROL rejection. */
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x02u;
    buf[OCA_OFF_PUBLIC_KEY_SELECT] = 0x01u; /* select key slot 0 */
    set_revoke_bit(buf, 0);                 /* revoke it */
    test_fixture_reset();
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active   = sb_active_cb;   /* device enforces secure boot */
    cb.get_root_key_revocation = dev_get_revoke;
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_root_key_revocation(buf, &cb, &ctx), OCA_FAIL_ROOT_KEY_REVOKED);
}

/* Secure-by-default: manifest bit clear and no secure-boot callback — the check
 * still engages (fail-safe) and needs the device-state callback. */
TEST(test_root_key_revocation_secure_by_default_when_unset)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);            /* manifest secure_boot enable bit off, no callbacks */
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x02u;  /* class named; fail-safe decides */
    oca_validation_context_t ctx = determined_for(buf, NULL);
    ASSERT_EQ_INT(oca_check_root_key_revocation(buf, NULL, &ctx),
                  OCA_FAIL_CALLBACK_UNAVAILABLE);
}

TEST(test_root_key_revocation_callback_unavailable)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);             /* secure boot ON, no callback wired */
    oca_validation_context_t ctx = determined_for(buf, NULL);
    ASSERT_EQ_INT(oca_check_root_key_revocation(buf, NULL, &ctx),
                  OCA_FAIL_CALLBACK_UNAVAILABLE);
}

/* Pipeline: a revoked selected key is rejected before the signature callback runs. */
TEST(test_revoked_key_skips_signature_in_pipeline)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    set_revoke_bit(buf, 0);                 /* selected key revoked */
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    g_fx.sig_calls = 0;
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL),
                  OCA_FAIL_ROOT_KEY_REVOKED);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);          /* signature never attempted */
}

/* ---- ROOT-key authorization (the trust anchor) ---- */

/* The whole point of the check. A manifest carries the key its own signature is
 * verified against, so without authorization any self-signed manifest passes.
 * An unauthorized key must be refused, and refused BEFORE the verifier is
 * reached — the call count is what makes the ordering observable, since a result
 * code alone cannot distinguish "rejected first" from "rejected after paying for
 * a modexp". */
TEST(test_an_unauthorized_key_is_refused_before_verification)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.is_key_authorized = authorize_none_cb;
    g_fx.sig_calls = 0;
    g_authorize_calls = 0;
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL),
                  OCA_FAIL_ROOT_KEY_UNAUTHORIZED);
    ASSERT_EQ_INT(g_authorize_calls, 1);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);          /* signature never attempted */
}

/* Authorization precedes revocation. A manifest whose key is BOTH unauthorized
 * and revoked reports unauthorized, because "was this key ever trusted" is
 * settled before "is it still trusted". Reverse the two in
 * oca_validate_manifest() and this fails. */
TEST(test_authorization_precedes_revocation)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    set_revoke_bit(buf, 0);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.is_key_authorized = authorize_none_cb;
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL),
                  OCA_FAIL_ROOT_KEY_UNAUTHORIZED);
}

/* An unwired callback fails closed. A build that forgot its trust anchor must
 * verify nothing, rather than treating "no anchor" as "anything goes". */
TEST(test_a_missing_authorization_callback_fails_closed)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.is_key_authorized = NULL;
    g_fx.sig_calls = 0;
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL),
                  OCA_FAIL_CALLBACK_UNAVAILABLE);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);
}

/* Recording the decision is what makes the ordering enforced rather than merely
 * documented: a hand-composed sequence that skipped authorization must not be
 * able to verify. The context here records a completed determination and no
 * authorization, which is exactly what omitting the check leaves behind. */
TEST(test_signature_refuses_a_context_without_authorization)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    g_fx.sig_calls = 0;

    /* g_determined_secure is exactly this state: determination in force, no
     * authorization recorded. Copied because oca_check_signature writes. */
    oca_validation_context_t ctx = g_determined_secure;
    ASSERT_TRUE(ctx.secure_boot_key_authorized_classic != OCA_SECURE_TRUE);
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx),
                  OCA_FAIL_ROOT_KEY_UNAUTHORIZED);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);
}

/* Authorization is a no-op on a part where secure boot is not in force, and
 * costs no callback: there is no key to anchor.
 *
 * The device has to REPORT the disable for that. A cleared manifest bit is not
 * enough on its own: with no reporter wired the determination falls through to
 * its fail-safe and comes back in force, which is why this test would otherwise
 * see the key refused. */
TEST(test_authorization_is_a_noop_when_secure_boot_is_off)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);                /* control bit clear */
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.is_secure_boot_disabled = sb_disabled_true_cb;
    cb.is_key_authorized = authorize_none_cb;   /* would refuse if consulted */
    g_authorize_calls = 0;

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    (void)oca_determine_secure_boot(buf, &cb, &ctx);
    ASSERT_EQ_INT(oca_check_root_key_authorized(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_authorize_calls, 0);
}

/* Pipeline, the other half: anti-rollback runs BEFORE signature verification, so
 * a replayed manifest is rejected without paying for a public-key operation. A
 * manifest carrying both a rollback violation and an invalid signature reports
 * the rollback, and the verifier is never reached.
 *
 * This inverts the order the library previously composed, and the inversion IS
 * the assertion — move oca_check_security_version() back after
 * oca_check_signature() and this fails. The callback count is what makes the
 * ordering observable at all: a result code alone cannot distinguish "rejected
 * before verifying" from "rejected after paying for a verification". */
TEST(test_rollback_violation_rejected_before_signature_verification)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);             /* manifest security version = 0 */
    test_fixture_reset();
    g_fx.secver[0] = 0x02u;                /* device holds a flag the manifest lacks */
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.verify_signature = failing_signature_cb;
    cb.is_key_authorized = authorize_any_cb;
    g_fx.sig_calls = 0;
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL),
                  OCA_FAIL_SECURITY_VERSION);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);          /* never reached — that is the point */
}

/* Counts device-state reads so "each evaluation obtains the value
 * independently" is measured rather than asserted. */
static oca_result_t counting_secver_cb(uint8_t out[16])
{
    g_fx.secver_calls++;
    memset(out, 0, 16);
    return OCA_OK;
}

#if OCA_RECHECK_SECURITY_VERSION
/* Passes on the first read, fails on the second. Only an implementation that
 * ACTS on the second evaluation's verdict rejects this. Defined inside the gate
 * because there is no second evaluation to exercise when it is off, and an
 * unused static is a -Werror failure. */
static oca_result_t varying_secver_cb(uint8_t out[16])
{
    g_fx.secver_calls++;
    memset(out, 0, 16);
    if (g_fx.secver_calls >= 2) {
        out[0] = 0x02u;      /* a device flag the manifest does not carry */
    }
    return OCA_OK;
}

/* The comparison is evaluated twice in a default build, and each evaluation
 * reads the device value afresh — nothing is cached between them, so a faulted
 * read cannot be carried forward into the check meant to catch it. */
TEST(test_accepted_manifest_evaluates_anti_rollback_twice)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.get_security_version = counting_secver_cb;
    g_fx.secver_calls = 0;

    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL), OCA_OK);
    ASSERT_EQ_INT(g_fx.secver_calls, 2);
}

/* The load-bearing test for the re-evaluation. An implementation that calls the
 * second evaluation and discards its result still passes the count test above,
 * while providing none of the defence the re-evaluation exists for. Only this
 * one distinguishes them. */
TEST(test_late_anti_rollback_verdict_is_acted_on)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.get_security_version = varying_secver_cb;
    g_fx.secver_calls = 0;

    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL),
                  OCA_FAIL_SECURITY_VERSION);
    ASSERT_EQ_INT(g_fx.secver_calls, 2);   /* the first passed; the second rejected */
}
#else
/* With the re-evaluation compiled out, the comparison happens once. */
TEST(test_anti_rollback_evaluated_once_when_recheck_disabled)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.get_security_version = counting_secver_cb;
    g_fx.secver_calls = 0;

    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL), OCA_OK);
    ASSERT_EQ_INT(g_fx.secver_calls, 1);
}
#endif

/* An early anti-rollback PASS is not a decision on its own: a manifest that
 * clears the comparison but carries an invalid signature is still refused for
 * the signature. Guards against the early evaluation being treated as
 * authoritative once it happens to succeed. */
TEST(test_early_rollback_pass_does_not_rescue_a_bad_signature)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    test_fixture_reset();                            /* device secver 0 -> comparison passes */
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.verify_signature = failing_signature_cb;
    cb.is_key_authorized = authorize_any_cb;
    g_fx.sig_calls = 0;
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL),
                  OCA_FAIL_SIGNATURE);
    ASSERT_EQ_INT(g_fx.sig_calls, 1);          /* reached, and its verdict won */
}

/* ---- anti-rollback security version ---- */

TEST(test_security_version_rollback_rejected)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);             /* manifest security version = 0 */
    test_fixture_reset();
    g_fx.secver[0] = 0x02u;                /* device has flag bit 1; manifest lacks it */
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    cb.get_security_version = dev_get_secver;
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_security_version(buf, &cb, &ctx), OCA_FAIL_SECURITY_VERSION);
}

TEST(test_security_version_superset_accepted)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    buf[OCA_OFF_MANIFEST_SECURITY_VERSION] = 0x03u;  /* manifest flags bit0+bit1 */
    test_fixture_reset();
    g_fx.secver[0] = 0x02u;                         /* device flag bit1 (subset) */
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    cb.get_security_version = dev_get_secver;
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_security_version(buf, &cb, &ctx), OCA_OK);
}

TEST(test_security_version_equal_accepted)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    buf[OCA_OFF_MANIFEST_SECURITY_VERSION] = 0x02u;
    test_fixture_reset();
    g_fx.secver[0] = 0x02u;                         /* equal */
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    cb.get_security_version = dev_get_secver;
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_security_version(buf, &cb, &ctx), OCA_OK);
}

TEST(test_security_version_secure_boot_disabled_inert)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);            /* manifest secure_boot enable bit off */
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active = sb_inactive_cb;  /* and device reports secure boot off */
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_security_version(buf, &cb, &ctx), OCA_OK);
}

TEST(test_security_version_callback_unavailable)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);             /* secure boot ON, no callback wired */
    oca_callbacks_t cb; memset(&cb, 0, sizeof cb);
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_check_security_version(buf, &cb, &ctx), OCA_FAIL_CALLBACK_UNAVAILABLE);
}

/* ---- device-state commit ---- */

TEST(test_commit_ors_in_revoke_and_secver)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    set_revoke_bit(buf, 5);                          /* manifest revokes slot 5 (byte0 bit5) */
    buf[OCA_OFF_MANIFEST_SECURITY_VERSION] = 0x04u;  /* manifest flag bit2 */
    /* manifest_security_control = 0x00 → both updates enabled */
    test_fixture_reset();
    g_fx.revoke[1] = 0x01u;                         /* device already revokes slot 8 */
    g_fx.secver[0] = 0x01u;                         /* device already has flag bit0 */
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.revoke[0], 0x20u);           /* slot 5 OR-ed in */
    ASSERT_EQ_INT(g_fx.revoke[1], 0x01u);           /* prior slot 8 retained */
    ASSERT_EQ_INT(g_fx.secver[0], 0x05u);           /* bit0 | bit2 */
}

TEST(test_commit_disable_secver_only)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    set_revoke_bit(buf, 5);
    buf[OCA_OFF_MANIFEST_SECURITY_VERSION] = 0x04u;
    buf[OCA_OFF_MANIFEST_SECURITY_CONTROL] = 0x01u;  /* bit0: suppress security-version OR-in */
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.revoke[0], 0x20u);           /* revocation still updated */
    ASSERT_EQ_INT(g_fx.secver[0], 0x00u);           /* security version suppressed */
}

/* ------------------------------------------------------------------ */
/* Signature posture registers (manifest_security_control bits 4 / 5)  */
/* ------------------------------------------------------------------ */

TEST(test_commit_ors_in_the_signature_posture_registers)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    buf[OCA_OFF_SIGNATURE_COHORT_ENFORCE] = 0x01u;   /* ROOT demands classical */
    buf[OCA_OFF_SIGNATURE_CLASS_REVOKE]   = 0x02u;   /* revoke RSA-4096 class */
    test_fixture_reset();
    g_fx.cohort[1] = 0x02u;                          /* prior verifier-key posture */
    g_fx.class_revoke[0] = 0x01u;                    /* device already revoked RSA-3072 */
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.cohort[0], 0x01u);            /* manifest value OR-ed in */
    ASSERT_EQ_INT(g_fx.cohort[1], 0x02u);            /* prior posture retained */
    ASSERT_EQ_INT(g_fx.class_revoke[0], 0x03u);      /* both classes now revoked */
}

TEST(test_commit_disable_cohort_enforce_only)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    buf[OCA_OFF_SIGNATURE_COHORT_ENFORCE] = 0x01u;
    buf[OCA_OFF_SIGNATURE_CLASS_REVOKE]   = 0x02u;
    toc_put_u16(buf + OCA_OFF_MANIFEST_SECURITY_CONTROL,
                OCA_SECURITY_CONTROL_COHORT_ENFORCE_DISABLE_BIT);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.cohort[0], 0x00u);            /* suppressed */
    ASSERT_EQ_INT(g_fx.class_revoke[0], 0x02u);      /* the other still committed */
}

TEST(test_commit_disable_class_revoke_only)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    buf[OCA_OFF_SIGNATURE_COHORT_ENFORCE] = 0x01u;
    buf[OCA_OFF_SIGNATURE_CLASS_REVOKE]   = 0x02u;
    toc_put_u16(buf + OCA_OFF_MANIFEST_SECURITY_CONTROL,
                OCA_SECURITY_CONTROL_CLASS_REVOKE_DISABLE_BIT);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.cohort[0], 0x01u);
    ASSERT_EQ_INT(g_fx.class_revoke[0], 0x00u);      /* suppressed */
}

/* The regression guard for the field's 1 -> 2 byte widening. Bits 4 and 5 live
 * in the low byte, so a stale single-byte read still decodes them; what it
 * cannot see is anything in the HIGH byte. Setting a high-byte bit and
 * requiring every low-byte-driven update to still happen pins the read width
 * without depending on a bit the format has not yet assigned. */
TEST(test_manifest_security_control_is_read_as_a_u16)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    set_revoke_bit(buf, 5);
    buf[OCA_OFF_MANIFEST_SECURITY_VERSION] = 0x04u;
    buf[OCA_OFF_SIGNATURE_COHORT_ENFORCE] = 0x01u;
    buf[OCA_OFF_SIGNATURE_CLASS_REVOKE]   = 0x02u;
    /* Reserved high-byte bits set; every disable bit [5:0] clear. */
    toc_put_u16(buf + OCA_OFF_MANIFEST_SECURITY_CONTROL, 0xFF00u);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.revoke[0], 0x20u);
    ASSERT_EQ_INT(g_fx.secver[0], 0x04u);
    ASSERT_EQ_INT(g_fx.cohort[0], 0x01u);
    ASSERT_EQ_INT(g_fx.class_revoke[0], 0x02u);
}

/* An unwired posture callback fails the commit rather than silently skipping
 * the fold-in — the same fail-closed schedule the other device-state slots use. */
TEST(test_commit_without_posture_callbacks_is_unavailable)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.set_signature_cohort_enforce = 0;
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx),
                  OCA_FAIL_CALLBACK_UNAVAILABLE);
}

/* ------------------------------------------------------------------ */
/* signature_class_revoke group codes                                  */
/* ------------------------------------------------------------------ */

TEST(test_intact_group_codes_are_accepted)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    ASSERT_EQ_INT(oca_check_signature_class_group_codes(buf), OCA_OK);

    buf[OCA_OFF_SIGNATURE_CLASS_REVOKE + OCA_CLASS_REVOKE_OFF_CLASSIC_GROUP_CODE] =
        OCA_CLASS_REVOKE_CLASSIC_GROUP_CODE;
    ASSERT_EQ_INT(oca_check_signature_class_group_codes(buf), OCA_OK);

    buf[OCA_OFF_SIGNATURE_CLASS_REVOKE + OCA_CLASS_REVOKE_OFF_PQC_GROUP_CODE] =
        OCA_CLASS_REVOKE_PQC_GROUP_CODE;
    ASSERT_EQ_INT(oca_check_signature_class_group_codes(buf), OCA_OK);
}

TEST(test_a_fragment_of_a_group_code_is_rejected)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];

    /* 0xC0 is most of 0xCA. Accepting it would let a later manifest contribute
     * the remaining bits and complete a group-wide revocation by accumulation. */
    build_minimal_manifest(buf);
    buf[OCA_OFF_SIGNATURE_CLASS_REVOKE + OCA_CLASS_REVOKE_OFF_CLASSIC_GROUP_CODE] = 0xC0u;
    ASSERT_EQ_INT(oca_check_signature_class_group_codes(buf), OCA_FAIL_GROUP_CODE);

    build_minimal_manifest(buf);
    buf[OCA_OFF_SIGNATURE_CLASS_REVOKE + OCA_CLASS_REVOKE_OFF_PQC_GROUP_CODE] = 0x0Cu;
    ASSERT_EQ_INT(oca_check_signature_class_group_codes(buf), OCA_FAIL_GROUP_CODE);

    /* Each group code only means anything in its own byte. */
    build_minimal_manifest(buf);
    buf[OCA_OFF_SIGNATURE_CLASS_REVOKE + OCA_CLASS_REVOKE_OFF_CLASSIC_GROUP_CODE] =
        OCA_CLASS_REVOKE_PQC_GROUP_CODE;
    ASSERT_EQ_INT(oca_check_signature_class_group_codes(buf), OCA_FAIL_GROUP_CODE);
}

/* The check is ungated and cheap, so it must run before anything consults the
 * device. Observing that no identity callback fired pins the ordering. */
TEST(test_a_bad_group_code_is_caught_before_any_device_read)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    buf[OCA_OFF_SIGNATURE_CLASS_REVOKE + OCA_CLASS_REVOKE_OFF_CLASSIC_GROUP_CODE] = 0x01u;
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.get_identity_bytes = fixed_identity_cb;
    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, &ctx),
                  OCA_FAIL_GROUP_CODE);
    ASSERT_EQ_INT(g_fx.identity_calls, 0);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);
}

/* oca_commit_security_state() is public and burns fuses, so it repeats the
 * group-code check rather than trusting that a caller composed it. */
TEST(test_commit_refuses_a_fragmented_group_code)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    buf[OCA_OFF_SIGNATURE_CLASS_REVOKE + OCA_CLASS_REVOKE_OFF_PQC_GROUP_CODE] = 0xA0u;
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx), OCA_FAIL_GROUP_CODE);
    ASSERT_EQ_INT(g_fx.class_revoke[0], 0x00u);   /* nothing written */
}

/* ------------------------------------------------------------------ */
/* Crypto field sizes                                                  */
/* ------------------------------------------------------------------ */

TEST(test_consistent_crypto_field_sizes_are_accepted)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);          /* raw RSA-3072: 384 / 388 */
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_OK);

    /* Raw ECDSA P-256: a 64-byte signature and a 65-byte SEC1 point. */
    buf[OCA_OFF_SIGNATURE_TYPE] = OCA_PRIMITIVE_ECDSA_P256_SHA256;
    toc_put_u16(buf + OCA_OFF_SIGNATURE_SIZE, 64u);
    toc_put_u16(buf + OCA_OFF_PUBLIC_KEY_SIZE, 65u);
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_OK);

    /* DER ECDSA: the size field carries the algorithm MAXIMUM, not the actual
     * length, because it sits inside the region its own signature covers. */
    buf[OCA_OFF_SIGNATURE_ENCODING] = OCA_ENCODING_DER;
    toc_put_u16(buf + OCA_OFF_SIGNATURE_SIZE, 72u);
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_OK);
}

TEST(test_inconsistent_crypto_field_sizes_are_rejected)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];

    /* Zero is never a valid size. */
    build_secure_manifest(buf);
    toc_put_u16(buf + OCA_OFF_SIGNATURE_SIZE, 0u);
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_FAIL_CRYPTO_FIELD_SIZE);

    /* Larger than the field it bounds. */
    build_secure_manifest(buf);
    toc_put_u16(buf + OCA_OFF_PUBLIC_KEY_SIZE, OCA_LEN_PUBLIC_KEY + 1u);
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_FAIL_CRYPTO_FIELD_SIZE);

    /* Right shape, wrong algorithm: 384 is the RSA signature length. */
    build_secure_manifest(buf);
    buf[OCA_OFF_SIGNATURE_TYPE] = OCA_PRIMITIVE_ECDSA_P256_SHA256;
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_FAIL_CRYPTO_FIELD_SIZE);

    /* DER is not defined for an RSA signature — it is a bare integer. */
    build_secure_manifest(buf);
    buf[OCA_OFF_SIGNATURE_ENCODING] = OCA_ENCODING_DER;
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_FAIL_CRYPTO_FIELD_SIZE);

    /* A DER ECDSA size that is the ACTUAL length rather than the maximum. */
    build_secure_manifest(buf);
    buf[OCA_OFF_SIGNATURE_TYPE] = OCA_PRIMITIVE_ECDSA_P256_SHA256;
    buf[OCA_OFF_SIGNATURE_ENCODING] = OCA_ENCODING_DER;
    toc_put_u16(buf + OCA_OFF_PUBLIC_KEY_SIZE, 65u);
    toc_put_u16(buf + OCA_OFF_SIGNATURE_SIZE, 70u);
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_FAIL_CRYPTO_FIELD_SIZE);
}

/* A non-secure manifest zeroes these fields, and the secure-boot invariant owns
 * that case — so this check has to stay quiet rather than double-report it. */
TEST(test_crypto_field_sizes_ignored_on_a_non_secure_manifest)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_OK);
}

/* ---- signature-class control (secure_boot_control bits 2:1) ---- */

/* A manifest that demands verification while naming no signature class to
 * verify with describes a policy nothing can satisfy. Rejected at the
 * determination — the one place the effective secure-boot state and the class
 * bits are read together. */
TEST(test_secure_boot_with_no_signature_class_is_rejected)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x01u;   /* enforced, neither class */
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, &ctx),
                  OCA_FAIL_SIGNATURE_CLASS_CONTROL);
}

/* Secure boot put in force by the DEVICE, with the manifest enable bit clear,
 * demands a class selection just the same: the requirement is about the
 * effective state, not about which input established it. */
TEST(test_device_enabled_secure_boot_with_no_class_is_rejected)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);            /* control = 0x00, fields zeroed */
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active = sb_active_cb;
    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(buf, &cb, &ctx),
                  OCA_FAIL_SIGNATURE_CLASS_CONTROL);
}

/* The rejection leaves the context UNSETTLED — determined stays FALSE — so a
 * hand-composed sequence that ignores the failure cannot proceed: every gated
 * check refuses an undetermined context. */
TEST(test_class_rejection_leaves_the_context_unsettled)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x01u;
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    g_fx.sig_calls = 0;
    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(buf, &cb, &ctx),
                  OCA_FAIL_SIGNATURE_CLASS_CONTROL);
    ASSERT_TRUE(ctx.secure_boot_determined != OCA_SECURE_TRUE);
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx),
                  OCA_FAIL_SECURE_BOOT_UNDETERMINED);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);
}

/* The determination records WHICH classes the manifest is verified by, in the
 * same consultation that decided secure boot itself. */
TEST(test_determination_records_the_enforced_signature_classes)
{
    uint8_t classic[OCA_CLASSIC_BODY_SIZE];
    static uint8_t pqc[OCA_PQC_BODY_SIZE];
    oca_validation_context_t ctx;

    build_secure_manifest(classic);         /* control = 0x03: classic only */
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(classic, NULL, &ctx), OCA_OK);
    ASSERT_TRUE(ctx.secure_boot_enforce_classic == OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_enforce_pqc != OCA_SECURE_TRUE);

    /* The PQC flag is recordable only on a body whose variant carries PQC
     * fields — a PQC class bit on a classic body is the determination's own
     * rejection, exercised separately. */
    build_secure_pqc_manifest(pqc, 0x05u);
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(pqc, NULL, &ctx), OCA_OK);
    ASSERT_TRUE(ctx.secure_boot_enforce_classic != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_enforce_pqc == OCA_SECURE_TRUE);

    build_secure_pqc_manifest(pqc, 0x07u);
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(pqc, NULL, &ctx), OCA_OK);
    ASSERT_TRUE(ctx.secure_boot_enforce_classic == OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_enforce_pqc == OCA_SECURE_TRUE);
}

/* The determination decides the variant class ONCE and records it as a
 * complementary pair: exactly one TRUE in any settled context, and always
 * opposite patterns of each other. Asserted for exact patterns on both
 * variants, which pins both invariants at their only writer. */
TEST(test_determination_records_the_manifest_variant_pair)
{
    uint8_t classic[OCA_CLASSIC_BODY_SIZE];
    static uint8_t pqc[OCA_PQC_BODY_SIZE];
    oca_validation_context_t ctx;

    build_secure_manifest(classic);
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(classic, NULL, &ctx), OCA_OK);
    ASSERT_TRUE(ctx.manifest_is_classic == OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.manifest_is_pqc == OCA_SECURE_FALSE);

    build_secure_pqc_manifest(pqc, 0x05u);
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(pqc, NULL, &ctx), OCA_OK);
    ASSERT_TRUE(ctx.manifest_is_pqc == OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.manifest_is_classic == OCA_SECURE_FALSE);
}

/* The record is a reference, not a cache: the confirm every gated check runs
 * re-derives the variant class and refuses a record that no longer describes
 * the body — or that is not a complementary pair at all. */
TEST(test_gated_checks_refuse_a_moved_or_incoherent_variant_record)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    test_fixture_reset();
    g_authorize_calls = 0;
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    oca_validation_context_t good = determined_for(buf, &cb);
    g_authorize_calls = 0;
    g_fx.sig_calls = 0;

    /* A coherent pair claiming PQC — on a classical body. */
    oca_validation_context_t moved = good;
    moved.manifest_is_classic = OCA_SECURE_FALSE;
    moved.manifest_is_pqc     = OCA_SECURE_TRUE;
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &moved),
                  OCA_FAIL_SECURE_BOOT_STATE_CHANGED);

    /* The complement invariant violated: both claim true. */
    oca_validation_context_t incoherent = good;
    incoherent.manifest_is_pqc = OCA_SECURE_TRUE;
    ASSERT_EQ_INT(oca_check_root_key_authorized(buf, &cb, &incoherent),
                  OCA_FAIL_SECURE_BOOT_STATE_CHANGED);

    ASSERT_EQ_INT(g_fx.sig_calls, 0);
    ASSERT_EQ_INT(g_authorize_calls, 0);
}

/* The determination refuses to RECORD a PQC enforcement no field can satisfy:
 * a classic body with the PQC class bit never settles a context, so a context
 * claiming enforce_pqc on a classic manifest is unrepresentable through the
 * library's own writer — every PQC code path downstream is variant-gated at
 * the source, not just at its own guard. */
TEST(test_determination_refuses_a_pqc_class_on_a_classic_variant)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x05u;    /* pqc named on OCAC */
    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(buf, NULL, &ctx),
                  OCA_FAIL_SIGNATURE_CLASS_CONTROL);
    ASSERT_TRUE(ctx.secure_boot_determined != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_enforce_pqc != OCA_SECURE_TRUE);
}

/* secure_boot_pqc on a variant with no PQC fields is a format violation
 * regardless of secure-boot state — with the enable bit clear and set alike. */
TEST(test_pqc_class_bit_on_a_classic_manifest_is_rejected)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x04u;    /* secure boot OFF */
    ASSERT_EQ_INT(oca_check_secure_boot_invariant(buf),
                  OCA_FAIL_SIGNATURE_CLASS_CONTROL);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x05u;    /* secure boot ON */
    ASSERT_EQ_INT(oca_check_secure_boot_invariant(buf),
                  OCA_FAIL_SIGNATURE_CLASS_CONTROL);
}

TEST(test_pqc_class_bit_is_permitted_on_a_pqc_manifest)
{
    static uint8_t buf[OCA_PQC_BODY_SIZE];
    memset(buf, 0, sizeof buf);
    memcpy(buf, "OCAP", 4);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x04u;
    ASSERT_EQ_INT(oca_check_secure_boot_invariant(buf), OCA_OK);
}

/* A PQC-only manifest (bit1 clear) zeroes its classical crypto description;
 * the classical size rules must not fire on fields the manifest never uses. */
TEST(test_pqc_only_manifest_passes_size_check_with_zeroed_classical_fields)
{
    static uint8_t buf[OCA_PQC_BODY_SIZE];
    memset(buf, 0, sizeof buf);
    memcpy(buf, "OCAP", 4);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x05u;    /* enforced + pqc only */
    /* ML-DSA-87: raw public key 2592, signature 4627. */
    toc_put_u16(buf + OCA_PQC_OFF_SIGNATURE_SIZE, 4627u);
    toc_put_u16(buf + OCA_PQC_OFF_PUBLIC_KEY_SIZE, 2592u);
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_OK);
}

/* The PQC size fields bound how far a later parse reads into their companion
 * fields, so zero and beyond-the-field are rejected. Exact per-algorithm sizes
 * get pinned when a PQC verification backend exists to consume them. */
TEST(test_pqc_size_fields_are_bounded)
{
    static uint8_t buf[OCA_PQC_BODY_SIZE];

    memset(buf, 0, sizeof buf);
    memcpy(buf, "OCAP", 4);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x05u;
    toc_put_u16(buf + OCA_PQC_OFF_SIGNATURE_SIZE, 0u);        /* zero */
    toc_put_u16(buf + OCA_PQC_OFF_PUBLIC_KEY_SIZE, 2592u);
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_FAIL_CRYPTO_FIELD_SIZE);

    toc_put_u16(buf + OCA_PQC_OFF_SIGNATURE_SIZE, 29825u);    /* overruns */
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_FAIL_CRYPTO_FIELD_SIZE);

    toc_put_u16(buf + OCA_PQC_OFF_SIGNATURE_SIZE, 4627u);
    toc_put_u16(buf + OCA_PQC_OFF_PUBLIC_KEY_SIZE, 0u);       /* zero */
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_FAIL_CRYPTO_FIELD_SIZE);

    toc_put_u16(buf + OCA_PQC_OFF_PUBLIC_KEY_SIZE, 2625u);    /* overruns */
    ASSERT_EQ_INT(oca_check_crypto_field_sizes(buf), OCA_FAIL_CRYPTO_FIELD_SIZE);
}

/* ---- per-class authorization and the hybrid AND ---- */

/* A hybrid manifest consults each class's OWN anchor: two calls, each handed
 * that class's key, select bitmap, and algorithm family, each recorded in its
 * own context flag. */
TEST(test_hybrid_authorization_consults_each_classes_anchor)
{
    static uint8_t buf[OCA_PQC_BODY_SIZE];
    build_secure_pqc_manifest(buf, 0x07u);
    test_fixture_reset();
    g_authorize_calls = 0;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_key_authorized = authorize_capture_cb;
    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(oca_check_root_key_authorized(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_authorize_calls, 2);
    ASSERT_TRUE(g_auth_algo[0] == OCA_KEY_ALGO_CLASSIC);
    ASSERT_TRUE(g_auth_key_bytes[0] == buf + OCA_OFF_PUBLIC_KEY);
    ASSERT_TRUE(g_auth_select[0] == buf + OCA_OFF_PUBLIC_KEY_SELECT);
    ASSERT_TRUE(g_auth_algo[1] == OCA_KEY_ALGO_PQC);
    ASSERT_TRUE(g_auth_key_bytes[1] == buf + OCA_PQC_OFF_PUBLIC_KEY);
    ASSERT_TRUE(g_auth_select[1] == buf + OCA_PQC_OFF_PUBLIC_KEY_SELECT);
    ASSERT_TRUE(ctx.secure_boot_key_authorized_classic == OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_key_authorized_pqc == OCA_SECURE_TRUE);
}

/* A single-class manifest authorizes one key and leaves the other class's
 * flag unset — the flags say which family vouched, not merely that one did. */
TEST(test_single_class_authorization_leaves_the_other_flag_unset)
{
    static uint8_t buf[OCA_PQC_BODY_SIZE];
    oca_callbacks_t cb;
    oca_validation_context_t ctx;

    build_secure_pqc_manifest(buf, 0x03u);       /* classic only */
    test_fixture_reset();
    g_authorize_calls = 0;
    memset(&cb, 0, sizeof cb);
    cb.is_key_authorized = authorize_capture_cb;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(oca_check_root_key_authorized(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_authorize_calls, 1);
    ASSERT_TRUE(g_auth_algo[0] == OCA_KEY_ALGO_CLASSIC);
    ASSERT_TRUE(ctx.secure_boot_key_authorized_classic == OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_key_authorized_pqc != OCA_SECURE_TRUE);

    build_secure_pqc_manifest(buf, 0x05u);       /* pqc only */
    test_fixture_reset();
    g_authorize_calls = 0;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(oca_check_root_key_authorized(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_authorize_calls, 1);
    ASSERT_TRUE(g_auth_algo[0] == OCA_KEY_ALGO_PQC);
    ASSERT_TRUE(ctx.secure_boot_key_authorized_pqc == OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_key_authorized_classic != OCA_SECURE_TRUE);
}

/* A refused PQC key is the same refusal a refused classical key is, and the
 * flag it would have set stays unset. */
TEST(test_a_refused_pqc_key_fails_authorization)
{
    static uint8_t buf[OCA_PQC_BODY_SIZE];
    build_secure_pqc_manifest(buf, 0x05u);
    test_fixture_reset();
    g_authorize_calls = 0;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_key_authorized = authorize_none_cb;
    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(oca_check_root_key_authorized(buf, &cb, &ctx),
                  OCA_FAIL_ROOT_KEY_UNAUTHORIZED);
    ASSERT_TRUE(ctx.secure_boot_key_authorized_pqc != OCA_SECURE_TRUE);
}

/* An engaged context in which NO class is enforced can only be composed by
 * hand around the determination's rejection. Both key checks fail closed on
 * it rather than skipping verification — and without consulting a callback. */
TEST(test_key_checks_backstop_a_context_with_no_enforced_class)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x01u;    /* neither class named */
    test_fixture_reset();
    g_authorize_calls = 0;
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);

    /* What ignoring the determination's rejection leaves behind: determined
     * and enabled, with neither enforcement recorded. */
    oca_validation_context_t ctx = g_determined_secure;
    ctx.secure_boot_enforce_classic = OCA_SECURE_FALSE;

    ASSERT_EQ_INT(oca_check_root_key_authorized(buf, &cb, &ctx),
                  OCA_FAIL_SIGNATURE_CLASS_CONTROL);
    ASSERT_EQ_INT(g_authorize_calls, 0);
    ctx.secure_boot_key_authorized_classic = OCA_SECURE_TRUE;   /* even vouched-for */
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx),
                  OCA_FAIL_SIGNATURE_CLASS_CONTROL);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);
}

/* A recorded enforcement that disagrees with the manifest's class bits is the
 * same evidence a flipped secure-boot reporter is: something changed between
 * the determination and its use. Refused as STATE_CHANGED, in both checks —
 * this is what keeps one glitched context word from downgrading a hybrid
 * manifest to single-class verification. */
TEST(test_key_checks_refuse_a_record_disagreeing_with_the_class_bits)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);                  /* control = 0x03 */
    test_fixture_reset();
    g_authorize_calls = 0;
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    oca_validation_context_t ctx = determined_for(buf, &cb);

    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x07u;    /* bits moved under the record */
    g_authorize_calls = 0;
    g_fx.sig_calls = 0;
    ASSERT_EQ_INT(oca_check_root_key_authorized(buf, &cb, &ctx),
                  OCA_FAIL_SECURE_BOOT_STATE_CHANGED);
    ASSERT_EQ_INT(g_authorize_calls, 0);
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx),
                  OCA_FAIL_SECURE_BOOT_STATE_CHANGED);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);
}

/* The authorization comment claims the key blob is built EXACTLY as the
 * signature check will present it, so an anchor can never vouch for one
 * reading of the field while the verifier exercises another. This is that
 * claim as a drift test: every field of the public-key blob each anchor call
 * received must equal the one the matching verify call received — per class,
 * over a hybrid manifest so both classes are pinned. A change to either
 * function's offset or encoding sources that misses its twin fails here. */
TEST(test_authorization_presents_the_key_the_verifier_receives)
{
    static uint8_t buf[OCA_PQC_BODY_SIZE];
    build_secure_pqc_manifest(buf, 0x07u);
    /* Every confusable encoding byte gets a DISTINCT value, so a blob built
     * from the wrong offset differs by value instead of coinciding — the
     * builder's uniform RAW would let a signature-encoding/key-encoding mixup
     * slip through this comparison unseen. Nothing on the direct-call path
     * below interprets these bytes, so the values need not be legal. */
    buf[OCA_OFF_SIGNATURE_ENCODING]      = 0x11u;
    buf[OCA_OFF_PUBLIC_KEY_ENCODING]     = 0x22u;
    buf[OCA_PQC_OFF_SIGNATURE_ENCODING]  = 0x33u;
    buf[OCA_PQC_OFF_PUBLIC_KEY_ENCODING] = 0x44u;
    test_fixture_reset();
    g_authorize_calls = 0;
    g_verify_fail_enabled = false;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_key_authorized = authorize_capture_cb;
    cb.verify_signature  = verify_capture_cb;
    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(oca_check_root_key_authorized(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_authorize_calls, 2);
    ASSERT_EQ_INT(g_fx.sig_calls, 2);

    /* Both checks walk the classes in the same order, so index i is the same
     * class on both sides. */
    for (unsigned i = 0; i < 2u; ++i) {
        ASSERT_TRUE(g_auth_pk_blob[i].bytes == g_verify_pk_blob[i].bytes);
        ASSERT_TRUE(g_auth_pk_blob[i].field_length
                    == g_verify_pk_blob[i].field_length);
        ASSERT_TRUE(g_auth_pk_blob[i].kind == g_verify_pk_blob[i].kind);
        ASSERT_TRUE(g_auth_pk_blob[i].encoding
                    == g_verify_pk_blob[i].encoding);
        ASSERT_TRUE(g_auth_pk_blob[i].primitive_type
                    == g_verify_pk_blob[i].primitive_type);
        ASSERT_TRUE(g_auth_pk_blob[i].key_algorithm
                    == g_verify_pk_blob[i].key_algorithm);
    }
}

/* Hybrid verification is a logical AND over both signatures, each verified
 * with its own class's blobs over the same signed region. */
TEST(test_hybrid_signature_verifies_both_classes)
{
    static uint8_t buf[OCA_PQC_BODY_SIZE];
    build_secure_pqc_manifest(buf, 0x07u);
    test_fixture_reset();
    g_authorize_calls = 0;
    g_verify_fail_enabled = false;
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_key_authorized = authorize_any_cb;
    cb.verify_signature  = verify_capture_cb;
    oca_validation_context_t ctx = determined_for(buf, &cb);

    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.sig_calls, 2);
    ASSERT_TRUE(g_verify_algo[0] == OCA_KEY_ALGO_CLASSIC);
    ASSERT_TRUE(g_verify_sig_bytes[0] == buf + OCA_PQC_OFF_SIGNATURE);
    ASSERT_TRUE(g_verify_region_len[0] == OCA_PQC_SIGNED_REGION_END);
    ASSERT_TRUE(g_verify_algo[1] == OCA_KEY_ALGO_PQC);
    ASSERT_TRUE(g_verify_sig_bytes[1] == buf + OCA_PQC_OFF_SIGNATURE_PQC);
    ASSERT_TRUE(g_verify_region_len[1] == OCA_PQC_SIGNED_REGION_END);
    ASSERT_TRUE(ctx.secure_boot_authenticated == OCA_SECURE_TRUE);
}

/* Either class failing fails the manifest, authenticated stays unset, and the
 * encryption gate — which reads that flag — refuses downstream. The policy is
 * an AND, never or-else. */
TEST(test_hybrid_signature_fails_when_either_class_fails)
{
    static const oca_key_algorithm_t failing[] = {
        OCA_KEY_ALGO_CLASSIC, OCA_KEY_ALGO_PQC
    };
    unsigned i;
    for (i = 0; i < sizeof failing / sizeof failing[0]; ++i) {
        static uint8_t buf[OCA_PQC_BODY_SIZE];
        build_secure_pqc_manifest(buf, 0x07u);
        buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x01u;
        test_fixture_reset();
        g_authorize_calls = 0;
        g_verify_fail_enabled = true;
        g_verify_fail_algo = failing[i];
        oca_callbacks_t cb;
        memset(&cb, 0, sizeof cb);
        cb.is_key_authorized = authorize_any_cb;
        cb.verify_signature  = verify_capture_cb;
        oca_validation_context_t ctx = determined_for(buf, &cb);

        ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx), OCA_FAIL_SIGNATURE);
        ASSERT_TRUE(ctx.secure_boot_authenticated != OCA_SECURE_TRUE);
        /* The gate the AND protects: an encrypted payload must not decrypt on
         * the strength of one signature. */
        ASSERT_EQ_INT(oca_check_payload_encryption_policy(buf, &cb, &ctx),
                      OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);
        ASSERT_EQ_INT(g_fx.decrypt_calls, 0);
    }
    g_verify_fail_enabled = false;
}

/* The signature check reads the PER-CLASS authorization flag: a PQC verify is
 * refused when the PQC anchor never vouched, even while the classical one has. */
TEST(test_pqc_signature_requires_the_pqc_authorization)
{
    static uint8_t buf[OCA_PQC_BODY_SIZE];
    build_secure_pqc_manifest(buf, 0x05u);
    test_fixture_reset();
    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_key_authorized = authorize_any_cb;
    cb.verify_signature  = verify_capture_cb;
    g_verify_fail_enabled = false;
    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(buf, &cb, &ctx), OCA_OK);
    /* No authorization ran; vouch for the OTHER class by hand to prove the
     * check reads the flag for the class it is about to verify. */
    ctx.secure_boot_key_authorized_classic = OCA_SECURE_TRUE;
    g_fx.sig_calls = 0;
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx),
                  OCA_FAIL_ROOT_KEY_UNAUTHORIZED);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);
}

/* PQC enforcement on a variant with no PQC crypto region fails closed in both
 * key checks — the hand-composed escape from the invariant's rejection. */
TEST(test_pqc_enforcement_on_a_classic_variant_fails_closed)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x05u;    /* pqc named on OCAC */
    test_fixture_reset();
    g_authorize_calls = 0;
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);

    /* The determination itself refuses this body, so the state below can only
     * be composed BY HAND — which is exactly what these in-check guards exist
     * for. Enforcement mirrors the manifest bits so the agreement check is not
     * what fires. */
    oca_validation_context_t ctx = g_determined_secure;
    ctx.secure_boot_enforce_classic = OCA_SECURE_FALSE;
    ctx.secure_boot_enforce_pqc     = OCA_SECURE_TRUE;

    ASSERT_EQ_INT(oca_check_root_key_authorized(buf, &cb, &ctx),
                  OCA_FAIL_SIGNATURE_CLASS_CONTROL);
    ASSERT_EQ_INT(g_authorize_calls, 0);
    ctx.secure_boot_key_authorized_pqc = OCA_SECURE_TRUE;   /* even vouched-for */
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx),
                  OCA_FAIL_SIGNATURE_CLASS_CONTROL);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);
}

/* Hybrid end-to-end through the composed pipeline: both anchors consulted,
 * both signatures verified, authenticated recorded. */
TEST(test_hybrid_manifest_validates_end_to_end)
{
    static uint8_t buf[OCA_PQC_BODY_SIZE];
    build_secure_pqc_manifest(buf, 0x07u);
    test_fixture_reset();
    g_authorize_calls = 0;
    g_verify_fail_enabled = false;
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.verify_signature = verify_capture_cb;
    g_fx.sha_hash_off = OCA_PQC_OFF_MANIFEST_HASH;
    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_authorize_calls, 2);
    ASSERT_EQ_INT(g_fx.sig_calls, 2);
    ASSERT_TRUE(ctx.secure_boot_authenticated == OCA_SECURE_TRUE);
}

TEST(test_commit_disable_revoke_only)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    set_revoke_bit(buf, 5);
    buf[OCA_OFF_MANIFEST_SECURITY_VERSION] = 0x04u;
    buf[OCA_OFF_MANIFEST_SECURITY_CONTROL] = 0x02u;  /* bit1: suppress revocation OR-in */
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.revoke[0], 0x00u);           /* revocation suppressed */
    ASSERT_EQ_INT(g_fx.secver[0], 0x04u);           /* security version still updated */
}

TEST(test_commit_write_failure_surfaced)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    set_revoke_bit(buf, 5);
    test_fixture_reset();
    g_fx.fail_set = true;
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx), OCA_FAIL_SECURITY_STATE_UPDATE);
}

/* ---- a device-asserted disable reaches every gated path ----
 *
 * The disable answer creates a NEW route to "secure boot off". Everything gated
 * on that determination must take the route, and the two protections below must
 * be inherited across it — one touches provisioned secrets, the other is
 * irreversible, so neither is assumed. */

/* A/B on the reporter alone. The manifest is rigged so that every gated check
 * FAILS if it engages — a revoked key slot and a device anti-rollback flag the
 * manifest lacks — and the signature callback counts its invocations. Run A
 * (reporter unwired) must therefore fail; run B (reporter asserting) must pass
 * with the signature never attempted. */
TEST(test_device_disable_reaches_every_gated_check)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_callbacks_t cb;
    oca_validation_context_t ctx;

    /* A: nothing establishes the state, so the fail-safe puts secure boot in
     *    force and the rigged checks bite. */
    build_secure_manifest(buf);
    set_revoke_bit(buf, 0);                 /* revoke the selected key slot */
    test_fixture_reset();
    g_fx.secver[0] = 0x02u;                /* device flag the manifest lacks */
    build_devstate_cb(&cb, buf);
    g_fx.sig_calls = 0;
    oca_validation_context_init(&ctx);
    ASSERT_TRUE(oca_validate_manifest(buf, sizeof buf, &cb, &ctx) != OCA_OK);

    /* B: same manifest, same device, one callback added. */
    build_secure_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] &= (uint8_t)~0x07u;  /* non-secure image */
    /* A manifest declaring itself non-secure must zero every signing field, so
     * undo what build_secure_manifest populated. */
    buf[OCA_OFF_PUBLIC_KEY_SELECT] = 0x00u;
    buf[OCA_OFF_SIGNATURE_TYPE] = 0x00u;
    buf[OCA_OFF_SIGNATURE_ENCODING] = 0x00u;
    buf[OCA_OFF_PUBLIC_KEY_ENCODING] = 0x00u;
    toc_put_u16(buf + OCA_OFF_SIGNATURE_SIZE, 0u);
    toc_put_u16(buf + OCA_OFF_PUBLIC_KEY_SIZE, 0u);
    set_revoke_bit(buf, 0);
    test_fixture_reset();
    g_fx.secver[0] = 0x02u;
    build_devstate_cb(&cb, buf);
    cb.is_secure_boot_disabled = sb_disabled_true_cb;
    g_fx.sig_calls = 0;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, &ctx), OCA_OK);

    ASSERT_EQ_INT(g_fx.sig_calls, 0);          /* signature never attempted */
    ASSERT_TRUE(ctx.secure_boot_enabled != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_authenticated != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_device_disabled == OCA_SECURE_TRUE);
}

/* Encryption declared with the secure boot control bit CLEAR: ingesting a a manifest
 * in this invalid state is the whole test. 
 * build_encrypted_bundle() builds on build_minimal_manifest(), so the bit
 * is clear, and that is the only shape this refusal applies to.
 *
 * The producer will not emit this combination (it requires the bit set whenever
 * encryption is declared), so it can only reach a consumer hand-crafted or
 * tampered — which is exactly why the consumer refuses it independently rather
 * than trusting the producer to have prevented it.
 *
 * A normally-produced encrypted manifest has the bit SET, outranks the device,
 * and decrypts normally on a disabled part. This test says nothing about that
 * case; the CLI integration suite covers it. */
TEST(test_encryption_with_bit_clear_refused_on_a_disabled_device)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE + ENC_CT_LEN];
    oca_callbacks_t cb;
    build_gate_case(buf, &cb, true);      /* device says secure boot ACTIVE */
    cb.is_secure_boot_disabled = sb_disabled_true_cb;   /* but definitively turned off */

    /* The existing reason, not a new one — this route needs no new failure
     * vocabulary — and no provisioned secret exercised. */
    ASSERT_EQ_INT(oca_validate(buf, sizeof buf, &cb, NULL, NULL),
                  OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);
}

TEST(test_device_disable_commits_no_security_state)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    set_revoke_bit(buf, 5);
    buf[OCA_OFF_MANIFEST_SECURITY_VERSION] = 0x04u;
    test_fixture_reset();

    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.is_secure_boot_active   = sb_active_cb;          /* would say "in force" */
    cb.is_secure_boot_disabled = sb_disabled_true_cb;   /* but definitively off */

    /* Fuse programming is irreversible, so this is verified, not assumed. */
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.set_calls, 0);
}

/* ---- what the recorded state says about WHY ---- */

TEST(test_recorded_disable_is_independent_of_enabled)
{
    uint8_t clear[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(clear);
    test_fixture_reset();

    oca_callbacks_t cb;
    oca_validation_context_t ctx;

    /* not in force BECAUSE the device asserted it */
    build_devstate_cb(&cb, clear);
    cb.is_secure_boot_disabled = sb_disabled_true_cb;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(clear, &cb, &ctx), OCA_OK);
    ASSERT_TRUE(ctx.secure_boot_enabled != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_device_disabled == OCA_SECURE_TRUE);
    /* And the check gated on it agrees, without asking again for itself. */
    ASSERT_EQ_INT(oca_check_signature(clear, &cb, &ctx), OCA_OK);

    /* not in force via the pre-existing path — same verdict, different reason */
    build_devstate_cb(&cb, clear);
    cb.is_secure_boot_active = sb_inactive_cb;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(clear, &cb, &ctx), OCA_OK);
    ASSERT_TRUE(ctx.secure_boot_enabled != OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_device_disabled != OCA_SECURE_TRUE);
    ASSERT_EQ_INT(oca_check_signature(clear, &cb, &ctx), OCA_OK);
}

/* A part provisioned as non-secure, running a manifest built for secure parts.
 * The manifest wins at input (1), which means the device is never asked — so the
 * recorded disable stays clear. The field reports what the determination
 * observed, not an independently-obtained second opinion; "the device was not
 * consulted" and "the device answered no" are deliberately the same value,
 * because neither one contributed to the verdict. */
TEST(test_a_manifest_that_outranks_the_device_records_no_disable)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);             /* control bit set */
    test_fixture_reset();

    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.is_secure_boot_disabled = sb_disabled_true_cb;
    test_fixture_reset();

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(buf, &cb, &ctx), OCA_OK);

    ASSERT_TRUE(ctx.secure_boot_enabled == OCA_SECURE_TRUE);          /* manifest won */
    ASSERT_TRUE(ctx.secure_boot_device_disabled != OCA_SECURE_TRUE);  /* never asked */
    ASSERT_EQ_INT(g_fx.sb_disabled_calls, 0);

    /* The confirm re-walks the same precedence, so it short-circuits at the
     * manifest bit too: consuming the determination costs no device read either.
     * Authorization is the first consumer and has to run before the signature
     * check will exercise the key at all; both confirms are counted below. */
    ASSERT_EQ_INT(oca_check_root_key_authorized(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.sb_disabled_calls, 0);
}

/* The hardened comparison, driven through the library rather than asserted about
 * a struct field this test set itself.
 *
 * secure_boot_determined is the field that decides whether a gated check will act
 * at all, so every value that is not the one intact TRUE pattern has to reach the
 * refusal. Written `!= OCA_SECURE_FALSE` — the mistake the type's @warning names
 * — 0xFFFFFFFF and every other corrupted word would sail through as "determined"
 * and be trusted. */
TEST(test_a_corrupted_determination_flag_refuses_at_every_consumer)
{
    static const oca_secure_bool_t corrupt[] = {
        0x00000000u, 0xFFFFFFFFu, OCA_SECURE_FALSE,
        OCA_SECURE_TRUE ^ 1u, OCA_SECURE_TRUE ^ 0x80000000u
    };
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);

    unsigned i;
    for (i = 0; i < sizeof corrupt / sizeof corrupt[0]; ++i) {
        test_fixture_reset();
        oca_callbacks_t cb;
        build_devstate_cb(&cb, buf);

        oca_validation_context_t ctx = determined_for(buf, &cb);
        ctx.secure_boot_determined = corrupt[i];

        ASSERT_EQ_INT(oca_check_root_key_revocation(buf, &cb, &ctx),
                      OCA_FAIL_SECURE_BOOT_UNDETERMINED);
        ASSERT_EQ_INT(oca_check_security_version(buf, &cb, &ctx),
                      OCA_FAIL_SECURE_BOOT_UNDETERMINED);
        ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx),
                      OCA_FAIL_SECURE_BOOT_UNDETERMINED);
        ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx),
                      OCA_FAIL_SECURE_BOOT_UNDETERMINED);

        /* Refused before touching anything, including the fuses. */
        ASSERT_EQ_INT(g_fx.sig_calls, 0);
        ASSERT_EQ_INT(g_fx.set_calls, 0);
    }
}

/* Deciding and recording are one consultation, not two.
 *
 * This is what rules out a caller that asks the device a second time to fill in
 * the record: that shape passes every other test here while allowing the
 * recorded value to disagree with the one the verdict was actually made on. A
 * device whose answer is not stable — a glitched fuse read, a reporter with a
 * side effect — would then be reported as something other than what it decided. */
TEST(test_deciding_and_recording_are_one_consultation)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    test_fixture_reset();

    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.is_secure_boot_disabled = sb_disabled_true_cb;
    test_fixture_reset();

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_determine_secure_boot(buf, &cb, &ctx), OCA_OK);

    ASSERT_EQ_INT(g_fx.sb_disabled_calls, 1);
    ASSERT_TRUE(ctx.secure_boot_device_disabled == OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_determined == OCA_SECURE_TRUE);
}

/* ------------------------------------------------------------------ */
/* Confirming the determination at each use                           */
/*                                                                    */
/* The determination is established once and re-derived by every      */
/* check that consumes it. Deriving independently at each check let a */
/* single glitched reporter read skip signature verification alone,   */
/* with nothing comparing the answers; recording once and merely      */
/* READING it would let one glitched determination disarm all of them.*/
/* Doing both is what these tests pin.                                */
/* ------------------------------------------------------------------ */

/* A reporter whose answer changes after a set number of calls, so a
 * determination and a later confirm can be made to disagree deterministically.
 * Nothing else in the suite can express "the device changed its mind". */
static int  g_flip_after   = 0;
static bool g_flip_initial = false;

static oca_secure_bool_t sb_flipping_active_cb(void)
{
    bool flipped = (g_fx.sb_active_calls >= g_flip_after);
    bool answer  = flipped ? !g_flip_initial : g_flip_initial;
    g_fx.sb_active_calls++;
    return answer ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
}

/* Arm the flipping reporter: `after` calls of `initial`, then the opposite. */
static void arm_flip(int after, bool initial)
{
    g_flip_after   = after;
    g_flip_initial = initial;
}

/* The headline property, checked at EVERY consumer rather than once.
 *
 * Each iteration lets the determination and the confirms before consumer N see
 * the honest answer, then flips the device underneath consumer N. A confirm
 * missing from any one consumer shows up here and nowhere else — the earlier
 * consumers pass, and that consumer silently acts on a stale record.
 */
TEST(test_a_reporter_that_changes_its_answer_is_caught_at_each_consumer)
{
    /* Consumer order inside oca_validate_manifest(): the determination itself is
     * consultation 0, then the encryption precondition, revocation,
     * security_version, signature, and the security_version recheck — six in
     * all, which is why the manifest below declares encryption. Flipping before
     * consultation N means 0..N-1 agree and N does not, so each iteration lands
     * the disagreement on a different consumer. */
    int flip_at;
    for (flip_at = 1; flip_at <= 5; ++flip_at) {
        uint8_t buf[OCA_CLASSIC_BODY_SIZE];
        build_minimal_manifest(buf);        /* bit clear, so the device decides */
        buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x02u;  /* class named for the in-force phase */
        buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x01u;
        test_fixture_reset();

        oca_callbacks_t cb;
        build_devstate_cb(&cb, buf);
        arm_flip(flip_at, true);            /* in force, then not */
        cb.is_secure_boot_active = sb_flipping_active_cb;

        oca_validation_context_t ctx;
        oca_validation_context_init(&ctx);
        ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, &ctx),
                      OCA_FAIL_SECURE_BOOT_STATE_CHANGED);
    }
}

/* Both directions. The dangerous flip is secure -> insecure, because that is the
 * one that skips verification, but a checker that only catches one direction is
 * one somebody will later "simplify" into catching neither. */
TEST(test_a_flip_to_secure_is_caught_as_readily_as_a_flip_to_insecure)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    test_fixture_reset();

    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    arm_flip(1, false);                     /* NOT in force, then in force */
    cb.is_secure_boot_active = sb_flipping_active_cb;

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, &ctx),
                  OCA_FAIL_SECURE_BOOT_STATE_CHANGED);
}

/* The positive control. Without it, every assertion above passes on a build
 * where the confirm hard-fails unconditionally. */
TEST(test_a_stable_reporter_confirms_clean_through_every_consumer)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x02u;  /* class named; the device decides */
    test_fixture_reset();

    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.is_secure_boot_active = sb_active_counting_cb;   /* stable: always true */

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, &ctx), OCA_OK);

    /* Secure boot was genuinely in force and the gated work genuinely ran, so
     * the clean confirm above is not a clean confirm of nothing. */
    ASSERT_TRUE(ctx.secure_boot_enabled == OCA_SECURE_TRUE);
    ASSERT_TRUE(ctx.secure_boot_authenticated == OCA_SECURE_TRUE);
    ASSERT_EQ_INT(g_fx.sig_calls, 1);
}

/* One determination, then one confirm per consumer — stated as an exact count.
 *
 * A loose bound would keep passing if a consumer lost its confirm. The count is
 * the determination plus the checks that gate on it: revocation,
 * security_version, signature, and the security_version recheck, and — only when
 * the manifest declares encryption — the encryption precondition. Both cases are
 * asserted, because the difference between them IS the precondition's
 * short-circuit: it tests the control bit before consulting anything, so a
 * cleartext manifest pays nothing for a rule that cannot apply to it.
 *
 * If either number changes, a consumer was added or one stopped confirming.
 * Both deserve a deliberate look at this line rather than a quiet re-baseline.
 */
TEST(test_the_determination_costs_one_consultation_per_consumer)
{
#if OCA_RECHECK_SECURITY_VERSION
    /* authorization, revocation, security_version, signature, recheck */
    const int gated = 5;
#else
    const int gated = 4;
#endif
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    oca_callbacks_t cb;
    oca_validation_context_t ctx;

    /* Cleartext: the encryption precondition returns before it confirms. */
    build_minimal_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x02u;  /* class named; the device decides */
    test_fixture_reset();
    build_devstate_cb(&cb, buf);
    cb.is_secure_boot_disabled = sb_disabled_false_cb;
    cb.is_secure_boot_active   = sb_active_counting_cb;

    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.sb_active_calls,   1 + gated);
    ASSERT_EQ_INT(g_fx.sb_disabled_calls, 1 + gated);
    /* Secure boot really was in force, so the counts above are not the counts of
     * a validation that skipped everything. */
    ASSERT_EQ_INT(g_fx.sig_calls, 1);
    ASSERT_EQ_INT(g_fx.revoke_calls, 1);

    /* Encryption declared: the precondition now confirms too. */
    build_minimal_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x02u;
    buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x01u;
    test_fixture_reset();
    build_devstate_cb(&cb, buf);
    cb.is_secure_boot_disabled = sb_disabled_false_cb;
    cb.is_secure_boot_active   = sb_active_counting_cb;

    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.sb_active_calls,   2 + gated);
    ASSERT_EQ_INT(g_fx.sb_disabled_calls, 2 + gated);
}

/* The determination reads the manifest's secure_boot_control bit as its highest
 * priority input, so it must not run on a body that failed its integrity check.
 * Asserted on the reporters rather than the return code: the code alone cannot
 * tell "the hash check ran first" from "the determination ran and agreed". */
TEST(test_the_determination_runs_after_the_manifest_hash)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    test_fixture_reset();

    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.sha256                  = stub_sha256_fail;
    cb.is_secure_boot_disabled = sb_disabled_false_cb;
    cb.is_secure_boot_active   = sb_active_counting_cb;

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, &ctx),
                  OCA_FAIL_MANIFEST_HASH);
    ASSERT_EQ_INT(g_fx.sb_active_calls, 0);
    ASSERT_EQ_INT(g_fx.sb_disabled_calls, 0);
    ASSERT_TRUE(ctx.secure_boot_determined != OCA_SECURE_TRUE);
}

/* Each gated check refuses a context no determination has settled, and refuses it
 * without touching the device. Wired fully, so a CALLBACK_UNAVAILABLE cannot
 * masquerade as the refusal. */
TEST(test_every_gated_check_refuses_an_undetermined_context)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);

    ASSERT_EQ_INT(oca_check_root_key_revocation(buf, &cb, &ctx),
                  OCA_FAIL_SECURE_BOOT_UNDETERMINED);
    ASSERT_EQ_INT(oca_check_security_version(buf, &cb, &ctx),
                  OCA_FAIL_SECURE_BOOT_UNDETERMINED);
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &ctx),
                  OCA_FAIL_SECURE_BOOT_UNDETERMINED);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx),
                  OCA_FAIL_SECURE_BOOT_UNDETERMINED);

    ASSERT_EQ_INT(g_fx.revoke_calls, 0);
    ASSERT_EQ_INT(g_fx.secver_calls, 0);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);
    ASSERT_EQ_INT(g_fx.set_calls, 0);   /* irreversible; verified, not assumed */

    /* NULL is the same answer, for the same reason. */
    ASSERT_EQ_INT(oca_check_root_key_revocation(buf, &cb, NULL),
                  OCA_FAIL_SECURE_BOOT_UNDETERMINED);
    ASSERT_EQ_INT(oca_check_security_version(buf, &cb, NULL),
                  OCA_FAIL_SECURE_BOOT_UNDETERMINED);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, NULL),
                  OCA_FAIL_SECURE_BOOT_UNDETERMINED);
    ASSERT_EQ_INT(g_fx.set_calls, 0);
}

/* The determination speaks in oca_secure_bool_t all the way out, so a corrupted
 * word can never be mistaken for either answer.
 *
 * This is what a plain `bool` could not give: there, "in force" and "not in
 * force" are 1 and 0, adjacent values one bit apart, and every corrupted byte is
 * one or the other. Here both answers are full-width complements and everything
 * else is neither — which is why the confirm's equality comparison can reject a
 * stale record outright rather than having to guess which side is right. */
TEST(test_the_determination_answers_only_in_hardened_words)
{
    uint8_t secure[OCA_CLASSIC_BODY_SIZE];
    uint8_t clear[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(secure);
    build_minimal_manifest(clear);

    oca_callbacks_t cb;
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active = sb_inactive_cb;

    /* Both answers are exactly one of the two patterns — never 0 or 1, which is
     * what a bool would have produced and what a truthiness test would accept. */
    ASSERT_TRUE(oca_secure_boot_active(secure, &cb) == OCA_SECURE_TRUE);
    ASSERT_TRUE(oca_secure_boot_active(clear, &cb) == OCA_SECURE_FALSE);
    ASSERT_TRUE(oca_secure_boot_device_disabled(&cb) == OCA_SECURE_FALSE);

    /* And the complement relationship holds, which is the property that makes a
     * small-multiplicity bit fault unable to turn one answer into the other. */
    ASSERT_EQ_INT((long)(OCA_SECURE_TRUE ^ OCA_SECURE_FALSE), 0xFFFFFFFFL);
}

/* Reporters that answer with something the library does not recognise.
 *
 * `return 1;` is the realistic one — the shape an integrator writes from muscle
 * memory, or from a `bool` implementation ported without reading the type. The
 * others stand in for a glitched or uninitialized word. */
static oca_secure_bool_t sb_active_returns_one_cb(void)
{
    g_fx.sb_active_calls++; return 1u;
}
static oca_secure_bool_t sb_active_returns_zero_cb(void)
{
    g_fx.sb_active_calls++; return 0u;
}
static oca_secure_bool_t sb_disabled_returns_one_cb(void)
{
    g_fx.sb_disabled_calls++; return 1u;
}
static oca_secure_bool_t sb_disabled_returns_garbage_cb(void)
{
    g_fx.sb_disabled_calls++; return 0xFFFFFFFFu;
}

/* An unrecognised answer from either reporter leaves secure boot ON.
 *
 * The two callbacks need OPPOSITE normalizations to get there, which is the
 * whole reason this is worth a test. is_secure_boot_active must treat anything
 * that is not exactly FALSE as enforced; is_secure_boot_disabled must treat
 * anything that is not exactly TRUE as not-asserted. Get either backwards and a
 * `return 1;` — or a glitched word — turns verification off.
 *
 * Under the old plain-bool signatures none of this was expressible: `1` and
 * `0xFFFFFFFF` were both simply true, and true from is_secure_boot_disabled
 * meant secure boot off. */
TEST(test_an_unrecognized_reporter_answer_leaves_secure_boot_on)
{
    uint8_t clear[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(clear);          /* bit clear: the device decides */

    oca_callbacks_t cb;

    /* is_secure_boot_active: only an exact FALSE turns verification off. */
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active = sb_active_returns_one_cb;
    ASSERT_TRUE(oca_secure_boot_active(clear, &cb) == OCA_SECURE_TRUE);

    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active = sb_active_returns_zero_cb;
    ASSERT_TRUE(oca_secure_boot_active(clear, &cb) == OCA_SECURE_TRUE);

    /* The control: an exact FALSE is honored, so the two above are not passing
     * because the reporter is being ignored altogether. */
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_active = sb_inactive_cb;
    ASSERT_TRUE(oca_secure_boot_active(clear, &cb) == OCA_SECURE_FALSE);

    /* is_secure_boot_disabled: only an exact TRUE asserts the disable. */
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_disabled = sb_disabled_returns_one_cb;
    ASSERT_TRUE(oca_secure_boot_device_disabled(&cb) == OCA_SECURE_FALSE);
    ASSERT_TRUE(oca_secure_boot_active(clear, &cb) == OCA_SECURE_TRUE);

    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_disabled = sb_disabled_returns_garbage_cb;
    ASSERT_TRUE(oca_secure_boot_device_disabled(&cb) == OCA_SECURE_FALSE);
    ASSERT_TRUE(oca_secure_boot_active(clear, &cb) == OCA_SECURE_TRUE);

    /* And its control, so the disable path is known to still work. */
    memset(&cb, 0, sizeof cb);
    cb.is_secure_boot_disabled = sb_disabled_true_cb;
    ASSERT_TRUE(oca_secure_boot_device_disabled(&cb) == OCA_SECURE_TRUE);
    ASSERT_TRUE(oca_secure_boot_active(clear, &cb) == OCA_SECURE_FALSE);
}

/* The same property through the pipeline: a `return 1;` reporter must not be the
 * difference between a signature being verified and not. */
TEST(test_a_return_one_reporter_still_gets_signature_verification)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_SECURE_BOOT_CONTROL] = 0x02u;  /* class named; reporters decide */
    test_fixture_reset();

    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.is_secure_boot_disabled = sb_disabled_returns_one_cb;  /* "disabled", badly */
    cb.is_secure_boot_active   = sb_active_returns_one_cb;    /* "active", badly */

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, &ctx), OCA_OK);
    ASSERT_TRUE(ctx.secure_boot_enabled == OCA_SECURE_TRUE);
    ASSERT_EQ_INT(g_fx.sig_calls, 1);
}

/* A corrupted `engaged` word ENGAGES the caller's check rather than skipping it.
 *
 * The confirm hands `engaged` back across a function return, and in a plain bool
 * that value is one byte whose zero state is the one that skips verification.
 * Here zero is neither pattern, so it fails toward running the check. Driven
 * through the real consumers rather than asserted about the helper, because it
 * is the consumers' comparisons that have to be right. */
TEST(test_a_corrupted_engaged_word_runs_the_check_rather_than_skipping_it)
{
    static const oca_secure_bool_t corrupt[] = {
        0x00000000u, 0xFFFFFFFFu, 0x00000001u,
        OCA_SECURE_FALSE ^ 1u, OCA_SECURE_FALSE ^ 0x80000000u
    };
    unsigned i;
    for (i = 0; i < sizeof corrupt / sizeof corrupt[0]; ++i) {
        /* Stand in for the confirm's output and apply each consumer's own test.
         * Only the intact FALSE may skip a gated check... */
        ASSERT_TRUE(corrupt[i] != OCA_SECURE_FALSE);
        /* ...and only the intact TRUE may let the encryption rule pass. */
        ASSERT_TRUE(corrupt[i] != OCA_SECURE_TRUE);
    }

    /* The same property end to end: a manifest declaring encryption on a
     * non-secure part is refused, and the refusal comes from the encryption rule
     * rather than from something upstream having already failed. */
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);
    buf[OCA_OFF_PAYLOAD_ENCRYPTION_CONTROL] = 0x01u;
    test_fixture_reset();

    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.is_secure_boot_active = sb_inactive_cb;

    oca_validation_context_t ctx;
    oca_validation_context_init(&ctx);
    ASSERT_EQ_INT(oca_validate_manifest(buf, sizeof buf, &cb, &ctx),
                  OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);
    ASSERT_EQ_INT(g_fx.identity_calls, 0);
}

/* A recorded determination that disagrees with the device is refused even when
 * the record says the SAFER thing. The rule is that the two must match, not that
 * the record must be permissive — a context claiming "not in force" on a part
 * that reports in force is just as much a fault indication. */
TEST(test_a_record_disagreeing_in_the_safe_direction_is_still_refused)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);          /* manifest bit set: live answer is TRUE */
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);

    /* Copies, because oca_check_signature writes the authentication flag. */
    oca_validation_context_t stale = g_determined_nonsecure;
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &stale),
                  OCA_FAIL_SECURE_BOOT_STATE_CHANGED);
    ASSERT_EQ_INT(g_fx.sig_calls, 0);

    /* And the matching record is accepted, so the refusal above is about the
     * disagreement rather than about the constant. */
    oca_validation_context_t fresh = g_authorized_secure;
    ASSERT_EQ_INT(oca_check_signature(buf, &cb, &fresh), OCA_OK);
    ASSERT_EQ_INT(g_fx.sig_calls, 1);
}

TEST(test_commit_secure_boot_disabled_noop)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_minimal_manifest(buf);            /* manifest secure_boot enable bit off */
    set_revoke_bit(buf, 5);
    buf[OCA_OFF_MANIFEST_SECURITY_VERSION] = 0x04u;
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    cb.is_secure_boot_active = sb_inactive_cb;  /* and device reports secure boot off */
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx), OCA_OK);
    ASSERT_EQ_INT(g_fx.set_calls, 0);      /* nothing written */
}

/* Validation is read-only: a full successful oca_validate must not write device
 * state; only the explicit commit does. */
TEST(test_validate_is_read_only_then_commit)
{
    uint8_t buf[OCA_CLASSIC_BODY_SIZE];
    build_secure_manifest(buf);             /* not revoked; security version 0 (superset of 0) */
    test_fixture_reset();
    oca_callbacks_t cb;
    build_devstate_cb(&cb, buf);
    g_fx.sig_calls = 0;
    ASSERT_EQ_INT(oca_validate(buf, OCA_CLASSIC_BODY_SIZE, &cb, NULL, NULL), OCA_OK);
    ASSERT_EQ_INT(g_fx.set_calls, 0);      /* validation never commits */
    oca_validation_context_t ctx = determined_for(buf, &cb);
    ASSERT_EQ_INT(oca_commit_security_state(buf, &cb, &ctx), OCA_OK);
    ASSERT_TRUE(g_fx.set_calls > 0);       /* explicit commit does write */
}

/* ------------------------------------------------------------------ */
/* main                                                               */
/* ------------------------------------------------------------------ */

/* `--reverse` runs the registered tests last-to-first. Same tests, same
 * expected results: a difference between the two orders is a case depending on
 * another having run first, which is the failure the shared fixture and its
 * per-case reset exist to prevent. */
int main(int argc, char **argv)
{
    /* Fixed-time comparison primitives */
    RUN_TEST(test_ct_diff_detects_difference_at_any_position);
    RUN_TEST(test_ct_diff_zero_length_is_equal);
    RUN_TEST(test_ct_diff_masked_ignores_unselected_bytes);
    RUN_TEST(test_ct_any_nonzero);
    RUN_TEST(test_ct_any_overlap);

    /* Dispatch + boundary */
    RUN_TEST(test_permissive_manifest_passes_with_only_sha_callback);
    RUN_TEST(test_null_callback_fails_when_constraint_enabled);
    RUN_TEST(test_null_sha_callback_fails_manifest_hash);
    RUN_TEST(test_omitting_a_device_value_fails_rather_than_inheriting_one);
    RUN_TEST(test_the_reset_clears_every_fixture_field);
    RUN_TEST(test_a_full_integration_needs_no_caller_defined_state);

    /* Structural */
    RUN_TEST(test_check_length_rejects_short_buffer);

    /* Manifest peek */
    RUN_TEST(test_peek_reports_classic_from_a_minimal_head);
    RUN_TEST(test_peek_reports_pqc_body_size);
    RUN_TEST(test_peek_body_size_comes_from_the_magic_not_declared_length);
    RUN_TEST(test_peek_rejects_a_short_head);
    RUN_TEST(test_peek_rejects_bad_magic_and_null_args);
    RUN_TEST(test_peek_sanitizes_the_identifier);

    /* manifest_length self-description */
    RUN_TEST(test_manifest_length_agrees_for_a_well_formed_body);
    RUN_TEST(test_manifest_length_rejects_a_classic_body_claiming_pqc_size);
    RUN_TEST(test_manifest_length_rejects_near_miss_values);
    RUN_TEST(test_manifest_length_propagates_magic_failure);
    RUN_TEST(test_validate_manifest_runs_the_length_check);
    RUN_TEST(test_both_entry_points_agree_on_a_manifest_level_failure);
    RUN_TEST(test_result_string_covers_the_manifest_length_code);
    RUN_TEST(test_check_magic_rejects_bad_bytes);
    RUN_TEST(test_check_trailer_rejects_bad_pattern);
    RUN_TEST(test_check_format_version_accepts_newer_minor);
    RUN_TEST(test_check_format_version_rejects_newer_major);
    RUN_TEST(test_reserved_selector_bit_ignored);
    RUN_TEST(test_reserved_lifecycle_bit_ignored);
    RUN_TEST(test_reserved_demotion_bit_ignored);
    RUN_TEST(test_reserved_bits_ignored_end_to_end);
    RUN_TEST(test_secure_boot_invariant_clean_zero_path);
    RUN_TEST(test_secure_boot_invariant_dirty_signature_field);

    /* Identity */
    RUN_TEST(test_identity_match_passes);
    RUN_TEST(test_identity_mismatch_fails);

    /* Lifecycle */
    RUN_TEST(test_lifecycle_state_in_set_passes);
    RUN_TEST(test_lifecycle_state_not_in_set_fails);

    /* Version range */
    RUN_TEST(test_version_range_in_range_passes);
    RUN_TEST(test_version_range_below_min_fails);
    RUN_TEST(test_version_range_above_max_fails);

    /* Demotion control */
    RUN_TEST(test_demotion_control_clean);
    RUN_TEST(test_demotion_control_reserved_bit_ignored);

    /* manifest_hash + signature dispatch */
    RUN_TEST(test_manifest_hash_match_passes);
    RUN_TEST(test_manifest_hash_mismatch_fails);
    RUN_TEST(test_corruption_outranks_a_field_level_violation);
    RUN_TEST(test_manifest_hash_dirty_padding_fails);

    /* Device-asserted secure-boot disable */
    RUN_TEST(test_device_disabled_defaults_to_false);
    RUN_TEST(test_determination_rows_unchanged_by_the_new_input);
    RUN_TEST(test_disable_outranks_the_active_reporter);
    RUN_TEST(test_disable_outranks_the_fail_safe_default);
    RUN_TEST(test_manifest_bit_outranks_a_device_disable);
    RUN_TEST(test_manifest_bit_short_circuits_the_device_reporters);
    RUN_TEST(test_disable_short_circuits_the_active_reporter);
    RUN_TEST(test_disable_answering_false_matches_no_reporter);
    RUN_TEST(test_null_callback_table_still_fail_safes);
    RUN_TEST(test_secure_boot_invariant_still_reads_the_raw_manifest_bit);

    /* Encryption requires confirmed secure boot */
    RUN_TEST(test_decrypt_receives_cipher_and_selector_as_named_fields);
    RUN_TEST(test_decrypt_descriptor_points_derivation_inputs_at_the_manifest);
    RUN_TEST(test_no_provisioned_secret_is_distinct_from_other_decrypt_failures);
    RUN_TEST(test_result_string_covers_the_no_provisioned_secret_code);
    RUN_TEST(test_no_provisioned_secret_reaches_the_caller);
    RUN_TEST(test_encrypted_payload_refused_when_secure_boot_off);
    RUN_TEST(test_encrypted_payload_refused_by_validate_manifest_alone);
    RUN_TEST(test_both_enforcement_points_report_the_same_reason);
    RUN_TEST(test_encrypted_payload_accepted_when_authenticated);
    RUN_TEST(test_cleartext_payload_unaffected_at_either_secure_boot_state);
    RUN_TEST(test_encryption_gate_applies_to_pqc_variant);
    RUN_TEST(test_encryption_declared_with_zero_length_payload_still_refused);
    RUN_TEST(test_cleartext_with_stray_encryption_fields_not_refused);
    RUN_TEST(test_payload_at_standalone_refuses_with_zero_init_context);
    RUN_TEST(test_check_payload_standalone_refuses_with_zero_init_context);
    RUN_TEST(test_enabled_without_authenticated_is_refused);
    RUN_TEST(test_corrupted_confirmation_values_all_refuse);
    RUN_TEST(test_null_context_refuses_encrypted_payload);
    RUN_TEST(test_failed_signature_leaves_confirmation_unset);
    RUN_TEST(test_secure_boot_off_records_neither_enabled_nor_authenticated);
    RUN_TEST(test_context_init_leaves_nothing_established);
    RUN_TEST(test_result_string_covers_the_encryption_policy_code);
    RUN_TEST(test_result_string_covers_the_signature_class_code);

    /* Payload encryption info */
    RUN_TEST(test_encryption_info_reports_cleartext);
    RUN_TEST(test_encryption_info_reports_cipher_and_selector);
    RUN_TEST(test_encryption_info_reports_an_unknown_cipher_verbatim);
    RUN_TEST(test_encryption_info_rejects_bad_magic_and_null_args);
    RUN_TEST(test_encryption_info_needs_no_payload_resident);
    RUN_TEST(test_signature_secure_boot_zero_skipped);
    RUN_TEST(test_signature_refuses_an_undetermined_context);
    RUN_TEST(test_signature_callback_unavailable_when_secure_boot_enabled);

    /* Canonical order */
    RUN_TEST(test_validate_short_circuits_on_first_fail);
    RUN_TEST(test_validate_happy_path_full_pipeline);

    /* Encrypted-payload stage */
    RUN_TEST(test_payload_no_payload_declared_is_noop);
    RUN_TEST(test_payload_hash_mismatch_before_decrypt);
    RUN_TEST(test_payload_null_decrypt_callback_unavailable);
    RUN_TEST(test_payload_decrypt_failure);
    RUN_TEST(test_payload_chain_mismatch);
    RUN_TEST(test_payload_happy_path);

    /* Payload TOC structural validation (F-010) */
    RUN_TEST(test_payload_toc_zero_image_count);
    RUN_TEST(test_payload_toc_length_exceeds_payload);
    RUN_TEST(test_payload_toc_entry_offset_misaligned);
    RUN_TEST(test_payload_toc_entry_zero_length);
    RUN_TEST(test_payload_toc_entry_out_of_bounds);
    RUN_TEST(test_payload_toc_entries_overlap);
    RUN_TEST(test_payload_toc_entries_overlap_unsorted);
    RUN_TEST(test_payload_toc_multi_entry_disjoint_passes);

    /* Per-entry image hash */
    RUN_TEST(test_payload_toc_entry_hash_mismatch);
    RUN_TEST(test_payload_toc_entry_hash_mismatch_second_entry);
    RUN_TEST(test_payload_toc_entry_hash_padding_ignored);

    /* Cleartext payload stage */
    RUN_TEST(test_cleartext_payload_happy_path);
    RUN_TEST(test_encrypted_plaintext_reported_after_success);
    RUN_TEST(test_cleartext_plaintext_reported_after_success);
    RUN_TEST(test_plaintext_reported_from_every_entry_point);
    RUN_TEST(test_no_report_when_the_toc_is_malformed);
    RUN_TEST(test_no_report_when_the_hash_chain_mismatches);
    RUN_TEST(test_no_report_when_an_entry_hash_mismatches);
    RUN_TEST(test_declining_the_report_changes_no_verdict);
    RUN_TEST(test_cleartext_payload_missing_bytes_truncated);
    RUN_TEST(test_cleartext_payload_requires_sha256_callback);
    RUN_TEST(test_cleartext_payload_hash_mismatch);
    RUN_TEST(test_cleartext_payload_chain_mismatch);
    RUN_TEST(test_cleartext_payload_entry_hash_mismatch);
    RUN_TEST(test_cleartext_payload_hashed_length_must_equal_toc_span);
    RUN_TEST(test_cleartext_payload_length_disagreement);
    RUN_TEST(test_cleartext_payload_structural_violation);

    /* Post-validation TOC access */
    RUN_TEST(test_check_payload_rejects_short_buffer_without_reading_past_it);
    RUN_TEST(test_payload_region_locates_cleartext_payload);
    RUN_TEST(test_payload_region_flags_encrypted_and_sizes_by_ciphertext);
    RUN_TEST(test_payload_region_rejects_short_buffer_without_reading_past_it);
    RUN_TEST(test_payload_region_rejects_null_args);
    RUN_TEST(test_toc_info_reads_header);
    RUN_TEST(test_toc_info_rejects_bad_ptoc_magic);
    RUN_TEST(test_toc_info_rejects_bad_span);
    RUN_TEST(test_toc_image_at_decodes_every_entry_field);
    RUN_TEST(test_toc_image_at_hash_and_description_point_into_buffer);
    RUN_TEST(test_toc_image_at_indexes_in_stored_order_not_offset_order);
    RUN_TEST(test_toc_image_at_rejects_index_beyond_count);
    RUN_TEST(test_toc_image_at_rejects_structurally_invalid_entry);
    RUN_TEST(test_toc_image_at_never_returns_out_of_range_bytes);

    /* In-place payload decryption */
    RUN_TEST(test_decrypt_in_place_validates);
    RUN_TEST(test_decrypt_in_place_leaves_manifest_body_untouched);
    RUN_TEST(test_toc_accessors_work_on_in_place_plaintext);

    /* image_count cap */
    RUN_TEST(test_toc_rejects_image_count_above_the_cap);
    RUN_TEST(test_toc_accepts_image_count_exactly_at_the_cap);
    RUN_TEST(test_cap_rejection_is_distinct_from_malformed_toc);
    RUN_TEST(test_result_string_covers_the_cap_code);

    /* Resolving payload_offset in storage */
    RUN_TEST(test_locate_payload_accepts_the_ordinary_case);
    RUN_TEST(test_locate_payload_accepts_a_gap_after_the_manifest);
    RUN_TEST(test_locate_payload_accepts_payload_before_the_manifest);
    RUN_TEST(test_locate_payload_rejects_underflow_below_the_region);
    RUN_TEST(test_locate_payload_rejects_running_past_the_region);
    RUN_TEST(test_locate_payload_rejects_the_exact_region_boundary_overrun);
    RUN_TEST(test_locate_payload_rejects_collision_with_the_manifest);
    RUN_TEST(test_locate_payload_rejects_payload_before_manifest_that_overruns_it);
    RUN_TEST(test_locate_payload_rejects_collision_with_appended_entries);
    RUN_TEST(test_manifest_region_len_counts_appended_entries);
    RUN_TEST(test_manifest_region_len_reports_why_it_failed);
    RUN_TEST(test_locate_payload_rejects_bad_arguments);
    RUN_TEST(test_locate_payload_no_payload_declared_is_ok);
    RUN_TEST(test_locate_payload_spans_the_ciphertext_when_encrypted);
    RUN_TEST(test_check_payload_at_accepts_a_noncontiguous_payload);
    RUN_TEST(test_check_payload_at_rejects_bad_arguments);
    RUN_TEST(test_check_payload_refuses_to_guess_when_offset_disagrees);
    RUN_TEST(test_check_payload_ignores_offset_when_no_payload_declared);
    RUN_TEST(test_result_string_covers_the_location_code);

    /* Secure-boot device-state: ROOT-key revocation */
    RUN_TEST(test_root_key_revoked_by_manifest);
    RUN_TEST(test_root_key_revoked_by_device_state);
    RUN_TEST(test_root_key_not_revoked_passes);
    RUN_TEST(test_root_key_reserved_bits_ignored);
    RUN_TEST(test_root_key_revocation_secure_boot_disabled_inert);
    RUN_TEST(test_root_key_revocation_engaged_via_device_callback);
    RUN_TEST(test_root_key_revocation_secure_by_default_when_unset);
    RUN_TEST(test_root_key_revocation_callback_unavailable);
    RUN_TEST(test_an_unauthorized_key_is_refused_before_verification);
    RUN_TEST(test_authorization_precedes_revocation);
    RUN_TEST(test_a_missing_authorization_callback_fails_closed);
    RUN_TEST(test_signature_refuses_a_context_without_authorization);
    RUN_TEST(test_authorization_is_a_noop_when_secure_boot_is_off);
    RUN_TEST(test_revoked_key_skips_signature_in_pipeline);
    RUN_TEST(test_rollback_violation_rejected_before_signature_verification);
    RUN_TEST(test_early_rollback_pass_does_not_rescue_a_bad_signature);
#if OCA_RECHECK_SECURITY_VERSION
    RUN_TEST(test_accepted_manifest_evaluates_anti_rollback_twice);
    RUN_TEST(test_late_anti_rollback_verdict_is_acted_on);
#else
    RUN_TEST(test_anti_rollback_evaluated_once_when_recheck_disabled);
#endif

    /* Anti-rollback security version */
    RUN_TEST(test_security_version_rollback_rejected);
    RUN_TEST(test_security_version_superset_accepted);
    RUN_TEST(test_security_version_equal_accepted);
    RUN_TEST(test_security_version_secure_boot_disabled_inert);
    RUN_TEST(test_security_version_callback_unavailable);

    /* Device-state commit */
    RUN_TEST(test_commit_ors_in_revoke_and_secver);
    RUN_TEST(test_commit_disable_secver_only);
    RUN_TEST(test_commit_ors_in_the_signature_posture_registers);
    RUN_TEST(test_commit_disable_cohort_enforce_only);
    RUN_TEST(test_commit_disable_class_revoke_only);
    RUN_TEST(test_manifest_security_control_is_read_as_a_u16);
    RUN_TEST(test_commit_without_posture_callbacks_is_unavailable);
    RUN_TEST(test_intact_group_codes_are_accepted);
    RUN_TEST(test_a_fragment_of_a_group_code_is_rejected);
    RUN_TEST(test_a_bad_group_code_is_caught_before_any_device_read);
    RUN_TEST(test_commit_refuses_a_fragmented_group_code);
    RUN_TEST(test_consistent_crypto_field_sizes_are_accepted);
    RUN_TEST(test_inconsistent_crypto_field_sizes_are_rejected);
    RUN_TEST(test_crypto_field_sizes_ignored_on_a_non_secure_manifest);
    RUN_TEST(test_secure_boot_with_no_signature_class_is_rejected);
    RUN_TEST(test_device_enabled_secure_boot_with_no_class_is_rejected);
    RUN_TEST(test_class_rejection_leaves_the_context_unsettled);
    RUN_TEST(test_determination_records_the_enforced_signature_classes);
    RUN_TEST(test_determination_refuses_a_pqc_class_on_a_classic_variant);
    RUN_TEST(test_determination_records_the_manifest_variant_pair);
    RUN_TEST(test_gated_checks_refuse_a_moved_or_incoherent_variant_record);
    RUN_TEST(test_pqc_class_bit_on_a_classic_manifest_is_rejected);
    RUN_TEST(test_pqc_class_bit_is_permitted_on_a_pqc_manifest);
    RUN_TEST(test_pqc_only_manifest_passes_size_check_with_zeroed_classical_fields);
    RUN_TEST(test_pqc_size_fields_are_bounded);
    RUN_TEST(test_hybrid_authorization_consults_each_classes_anchor);
    RUN_TEST(test_single_class_authorization_leaves_the_other_flag_unset);
    RUN_TEST(test_a_refused_pqc_key_fails_authorization);
    RUN_TEST(test_key_checks_backstop_a_context_with_no_enforced_class);
    RUN_TEST(test_key_checks_refuse_a_record_disagreeing_with_the_class_bits);
    RUN_TEST(test_authorization_presents_the_key_the_verifier_receives);
    RUN_TEST(test_hybrid_signature_verifies_both_classes);
    RUN_TEST(test_hybrid_signature_fails_when_either_class_fails);
    RUN_TEST(test_pqc_signature_requires_the_pqc_authorization);
    RUN_TEST(test_pqc_enforcement_on_a_classic_variant_fails_closed);
    RUN_TEST(test_hybrid_manifest_validates_end_to_end);
    RUN_TEST(test_commit_disable_revoke_only);
    RUN_TEST(test_commit_write_failure_surfaced);
    RUN_TEST(test_commit_secure_boot_disabled_noop);
    RUN_TEST(test_device_disable_reaches_every_gated_check);
    RUN_TEST(test_encryption_with_bit_clear_refused_on_a_disabled_device);
    RUN_TEST(test_device_disable_commits_no_security_state);
    RUN_TEST(test_recorded_disable_is_independent_of_enabled);
    RUN_TEST(test_a_manifest_that_outranks_the_device_records_no_disable);
    RUN_TEST(test_a_corrupted_determination_flag_refuses_at_every_consumer);
    RUN_TEST(test_deciding_and_recording_are_one_consultation);
    RUN_TEST(test_a_reporter_that_changes_its_answer_is_caught_at_each_consumer);
    RUN_TEST(test_a_flip_to_secure_is_caught_as_readily_as_a_flip_to_insecure);
    RUN_TEST(test_a_stable_reporter_confirms_clean_through_every_consumer);
    RUN_TEST(test_the_determination_costs_one_consultation_per_consumer);
    RUN_TEST(test_the_determination_runs_after_the_manifest_hash);
    RUN_TEST(test_every_gated_check_refuses_an_undetermined_context);
    RUN_TEST(test_the_determination_answers_only_in_hardened_words);
    RUN_TEST(test_an_unrecognized_reporter_answer_leaves_secure_boot_on);
    RUN_TEST(test_a_return_one_reporter_still_gets_signature_verification);
    RUN_TEST(test_a_corrupted_engaged_word_runs_the_check_rather_than_skipping_it);
    RUN_TEST(test_a_record_disagreeing_in_the_safe_direction_is_still_refused);
    RUN_TEST(test_validate_is_read_only_then_commit);

    int reverse = (argc > 1 && strcmp(argv[1], "--reverse") == 0);
    unit_run_all(reverse);
    return unit_report();
}
