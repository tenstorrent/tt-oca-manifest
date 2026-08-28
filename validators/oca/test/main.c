/*
 * main.c — The oca-validate command-line driver.
 *
 * Reads a manifest file, wires the validator callbacks (OpenSSL for
 * crypto, CLI flags for hardware identity), invokes oca_validate(), and
 * prints a single-line verdict per the cli_surface contract.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cli_args.h"
#include "cli_hwid.h"
#include "oca_layout.h"
#include "oca_layout_pqc.h"
#include "oca_validator.h"
#include "openssl_crypto.h"

/* Read the entire file at `path` (manifest body + any payload) into a freshly
 * malloc'd buffer. Returns the buffer (caller frees) and sets *out_len, or NULL
 * on open/read failure. The whole bundle is needed so the encrypted-payload
 * stage can see the payload that follows the manifest body. */
static uint8_t *read_file(const char *path, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "usage: cannot open --manifest %s: %s\n",
                path, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0L, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        return NULL;
    }
    rewind(f);
    uint8_t *buf = malloc((size_t)size + 1u);  /* +1 avoids a 0-size malloc */
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    size_t n = fread(buf, 1u, (size_t)size, f);
    fclose(f);
    *out_len = n;
    return buf;
}

/* Parsed command-line options, for the callbacks that stand in for device
 * state. A real implementation reads fuses or registers directly; this is the
 * host equivalent of reaching them, and it is why the callbacks below need
 * nothing handed to them. Bound once in main(). */
static const cli_options_t *g_cli_opt;


/* Map an oca_result_t to a one-line human reason. */
static const char *reason_for(oca_result_t r)
{
    switch (r) {
        case OCA_FAIL_TRUNCATED:
            return "manifest file is shorter than its declared body size";
        case OCA_FAIL_MAGIC:
            return "file does not start with a recognized OCA manifest magic";
        case OCA_FAIL_TRAILER:
            return "signed-region trailer bytes do not match the expected fill";
        case OCA_FAIL_UNSUPPORTED_VARIANT:
            return "manifest variant is not supported by this build";
        case OCA_FAIL_PAYLOAD_HASH:
            return "payload hash over the stored payload does not match";
        case OCA_FAIL_DECRYPT:
            return "payload decryption failed (key derivation, cipher, or padding)";
        case OCA_FAIL_NO_PROVISIONED_SECRET:
            return "no secret is provisioned for the slot the manifest selected "
                   "(supply --payload-secret for that slot)";
        case OCA_FAIL_PAYLOAD_HASH_CHAIN:
            return "recovered plaintext payload does not match payload_hash_chain";
        case OCA_FAIL_PAYLOAD_TOC:
            return "payload TOC structure is invalid (image_count, entry bounds, "
                   "8-byte offset alignment, overlapping image ranges, or a "
                   "payload_length / payload_hashed_length disagreement)";
        case OCA_FAIL_PAYLOAD_ENTRY_HASH:
            return "a TOC entry's hash does not match the image bytes it describes";
        case OCA_FAIL_PAYLOAD_TOO_MANY_IMAGES:
            return "payload TOC declares more images than this build accepts "
                   "(see OCA_TOC_MAX_IMAGES)";
        case OCA_FAIL_PAYLOAD_LOCATION:
            return "payload_offset does not resolve to a usable storage location "
                   "(out of range, overflows, or collides with the manifest)";
        case OCA_FAIL_MANIFEST_LENGTH:
            return "manifest_length disagrees with the body size its magic implies "
                   "(mislabelled or truncated manifest)";
        case OCA_FAIL_ROOT_KEY_REVOKED:
            return "selected ROOT key is revoked (manifest or device-stored state)";
        case OCA_FAIL_ROOT_KEY_UNAUTHORIZED:
            return "ROOT key is not authorized by this device "
                   "(pass --root-key-digest or --trust-any-root-key)";
        case OCA_FAIL_SIGNATURE_CLASS_CONTROL:
            return "secure_boot_control class bits name a signature policy this "
                   "manifest cannot satisfy (neither class selected under secure "
                   "boot, or secure_boot_pqc on a variant with no PQC fields)";
        case OCA_FAIL_SECURITY_VERSION:
            return "manifest security version is a rollback (not a superset of the device value)";
        case OCA_FAIL_SECURITY_STATE_UPDATE:
            return "device-state commit (revocation / security-version write-back) failed";
        case OCA_FAIL_FORMAT_VERSION_MISMATCH:
            return "manifest format major is newer than this build";
        case OCA_FAIL_RESERVED_BITS:
            return "manifest has a reserved bit set";
        case OCA_FAIL_SECURE_BOOT_INVARIANT:
            return "secure_boot=0 bundle has dirty signing fields";
        case OCA_FAIL_CHIPLET_ID:
            return "chiplet_id constraint not satisfied by --chiplet-id";
        case OCA_FAIL_PACKAGE_ID:
            return "package_id constraint not satisfied by --package-id";
        case OCA_FAIL_SYSTEM_ID:
            return "system_id constraint not satisfied by --system-id";
        case OCA_FAIL_LIFECYCLE:
            return "lifecycle state not in the manifest's permitted set";
        case OCA_FAIL_VERSION_RANGE:
            return "current version outside the manifest-declared range";
        case OCA_FAIL_DEMOTION_CONTROL:
            return "demotion_control has a reserved bit set";
        case OCA_FAIL_MANIFEST_HASH:
            return "recomputed SHA-256 does not match the embedded hash";
        case OCA_FAIL_SIGNATURE:
            return "signature verification failed";
        case OCA_FAIL_CALLBACK_UNAVAILABLE:
            return "required hardware/crypto value not supplied on CLI";
        case OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT:
            return "encrypted payload declared, but secure boot is not in force "
                   "for this manifest";
        case OCA_FAIL_SECURE_BOOT_STATE_CHANGED:
            return "secure-boot state stopped matching the determination made "
                   "for this validation";
        case OCA_FAIL_SECURE_BOOT_UNDETERMINED:
            return "internal: a gated check ran before the secure-boot "
                   "determination";
        case OCA_FAIL_INVALID_ARG:
            return "internal: invalid argument";
        case OCA_OK:
        default:
            return "ok";
    }
}

/* Extract a NUL-padded ASCII manifest_identifier from offset 4..12. */
static void copy_manifest_id(const uint8_t *body, char out[9])
{
    memcpy(out, body + OCA_OFF_MANIFEST_IDENTIFIER, 8);
    out[8] = '\0';
    /* Trim trailing NULs and non-printables for clean output. */
    for (int i = 7; i >= 0; --i) {
        if (out[i] == '\0' || out[i] == ' ') {
            out[i] = '\0';
        } else {
            break;
        }
    }
}

/* manifest_content_version is a single LE u64 at offset 2941 packed as
 * `(major << 48) | (minor << 24) | patch` — 16 bits for major, 24 bits
 * each for minor and patch. */
static void read_content_version(const uint8_t *body,
                                 uint32_t *major,
                                 uint32_t *minor,
                                 uint32_t *patch)
{
    const uint8_t *p = body + OCA_OFF_MANIFEST_CONTENT_VERSION;
    uint64_t v = 0;
    for (unsigned i = 0; i < 8u; ++i) {
        v |= ((uint64_t)p[i]) << (8u * i);
    }
    *patch = (uint32_t)(v & 0xFFFFFFu);
    *minor = (uint32_t)((v >> 24) & 0xFFFFFFu);
    *major = (uint32_t)((v >> 48) & 0xFFFFu);
}

/* Host validation defaults for device-anchored secure-boot state. This CLI is a
 * host tool, not a device: it reports no revoked ROOT keys and enforces no
 * security-version floor. A real device would report its fuse/OTP state here.
 *
 * --secure-boot-active. Off by default, so the manifest's own
 * secure_boot_control bit drives the secure path and a plain invocation behaves
 * as a host tool should. Setting it is the only way to reach input (3) of the
 * determination from the command line — without it the device-enforced route,
 * and therefore the confirm that guards it, has no end-to-end expression at
 * all. */
static oca_secure_bool_t cli_is_secure_boot_active(void)
{
    return (g_cli_opt != NULL && g_cli_opt->secure_boot_active)
         ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
}

/* --secure-boot-disabled. A device would answer this from its life-cycle state
 * or a discrete disable fuse; here it is a flag, so the path has an end-to-end
 * expression. Answering true relaxes only the requirement the device imposes —
 * the manifest's own control bit still outranks it. */
static oca_secure_bool_t cli_is_secure_boot_disabled(void)
{
    return (g_cli_opt != NULL && g_cli_opt->secure_boot_disabled)
         ? OCA_SECURE_TRUE : OCA_SECURE_FALSE;
}

static oca_result_t cli_get_root_key_revocation(oca_key_algorithm_t algo,
                                                uint8_t out[16])
{
    (void)algo;
    memset(out, 0, 16);
    return OCA_OK;
}

static oca_result_t cli_get_security_version(uint8_t out[16])
{
    memset(out, 0, 16);
    return OCA_OK;
}

/* Reference post-validation walk of the payload TOC — the shape a Consumer uses
 * to decide where to stage each image and where to enter it.
 *
 * Called ONLY after oca_validate() returned OCA_OK: the accessors do no
 * cryptography, so they establish nothing about authenticity on their own.
 *
 * The plaintext region differs by bundle. A cleartext payload is located inside
 * the bundle with oca_payload_region(). An encrypted payload's plaintext is
 * whatever the decrypt_payload callback produced, which the validator reports
 * back through its plaintext out-parameter.
 */
/* Print the TOC and every image, given an explicit payload pointer. Split out so
 * storage-image mode can reuse it with a payload that is nowhere near the body —
 * the same decoupling oca_check_payload_at() provides in the library. */
static void list_toc(const uint8_t *payload, size_t payload_len)
{
    if (payload_len == 0u) {
        printf("images: none (manifest declares no payload)\n");
        return;
    }
    oca_toc_info_t toc;
    oca_result_t r = oca_toc_info(payload, payload_len, &toc);
    if (r != OCA_OK) {
        fprintf(stderr, "list-images: bad payload TOC: %s\n", oca_result_str(r));
        return;
    }
    printf("toc: v%u.%u payload_length=%llu images=%llu\n",
           (unsigned)toc.version_major, (unsigned)toc.version_minor,
           (unsigned long long)toc.payload_length,
           (unsigned long long)toc.image_count);

    for (uint64_t i = 0u; i < toc.image_count; ++i) {
        oca_image_info_t img;
        r = oca_toc_image_at(payload, payload_len, i, &img);
        if (r != OCA_OK) {
            fprintf(stderr, "list-images: entry %llu: %s\n",
                    (unsigned long long)i, oca_result_str(r));
            return;
        }
        printf("image[%llu]: type=%-16s offset=%#llx length=%llu "
               "load_addr=%#llx entry_point=%#llx v%u.%u.%u "
               "security_version=%llu group=%u\n",
               (unsigned long long)i, img.type,
               (unsigned long long)img.offset,
               (unsigned long long)img.length,
               (unsigned long long)img.load_addr,
               (unsigned long long)img.entry_point,
               (unsigned)img.version_major, (unsigned)img.version_minor,
               (unsigned)img.version_patch,
               (unsigned long long)img.security_version,
               (unsigned)img.group);
    }
}

static void list_payload_images(const uint8_t *bundle, size_t bundle_len,
                                const oca_payload_plaintext_t *plaintext)
{
    const uint8_t *payload = NULL;
    size_t payload_len = 0u;
    bool encrypted = false;

    oca_result_t r = oca_payload_region(bundle, bundle_len, &payload,
                                        &payload_len, &encrypted);
    if (r != OCA_OK) {
        fprintf(stderr, "list-images: cannot locate payload: %s\n",
                oca_result_str(r));
        return;
    }
    if (encrypted) {
        /* The region oca_payload_region returned is CIPHERTEXT. Substitute the
         * plaintext the decrypt callback recovered during validation. */
        if (plaintext == NULL || plaintext->bytes == NULL) {
            fprintf(stderr, "list-images: payload is encrypted and no plaintext "
                            "was recovered (supply --payload-secret)\n");
            return;
        }
        payload = plaintext->bytes;
        payload_len = plaintext->len;
    }
    list_toc(payload, payload_len);
}

/* Storage-image mode: the staged flow a boot ROM actually runs.
 *
 *   0. peek the head in place to learn the variant and body size;
 *   1. copy exactly that body out and authenticate the copy;
 *   2. resolve payload_offset against the permitted region;
 *   3. copy the payload from the resolved address into secured memory;
 *   4. verify it there.
 *
 * Steps 1 and 4 are separate library calls precisely because the payload need
 * not follow the manifest. `image` stands in for the storage device; the two
 * malloc'd buffers stand in for secured internal memory, and the copies are the
 * ToCToU boundary — nothing is verified in place in the "device".
 */
static oca_result_t validate_from_storage(const uint8_t *image, size_t image_len,
                                         cli_options_t *opt,
                                         const oca_callbacks_t *cb,
                                         oca_payload_plaintext_t *out_plaintext)
{
    if (opt->manifest_addr < 0 || (size_t)opt->manifest_addr >= image_len) {
        fprintf(stderr, "usage: --manifest-addr %lld is outside the image\n",
                (long long)opt->manifest_addr);
        return OCA_FAIL_INVALID_ARG;
    }

    /* Step 0: peek the head in place. The one read allowed straight from the
     * mapped image, because it makes no trust decision. */
    const uint8_t *head = image + (size_t)opt->manifest_addr;
    size_t avail = image_len - (size_t)opt->manifest_addr;

    oca_manifest_peek_t pk;
    oca_result_t r = oca_peek_manifest(head, avail, &pk);
    if (r != OCA_OK) {
        return r;
    }
    if (pk.body_size > avail) {
        return OCA_FAIL_TRUNCATED;
    }
    if (opt->list_images) {
        printf("peek: %s v%u.%u body_size=%zu declared=%u id=\"%s\"\n",
               pk.variant_name, (unsigned)pk.version_major,
               (unsigned)pk.version_minor, pk.body_size,
               (unsigned)pk.declared_length, pk.identifier);
    }

    /* Step 1: copy exactly the body out of storage, then authenticate the COPY.
     * peek sized this; oca_check_manifest_length() inside oca_validate_manifest()
     * confirms the manifest agrees, now that it is authenticated. */
    uint8_t *body = malloc(pk.body_size);
    if (body == NULL) {
        return OCA_FAIL_INVALID_ARG;
    }
    memcpy(body, head, pk.body_size);

    /* One context spans the whole staged sequence. This is why the staged entry
     * point takes a caller-owned one: authentication happens here, decryption
     * happens in a separate call further down, and the second needs to know what
     * the first established. */
    oca_validation_context_t vctx;
    oca_validation_context_init(&vctx);

    r = oca_validate_manifest(body, pk.body_size, cb, &vctx);
    if (r != OCA_OK) {
        free(body);
        return r;
    }

    /* Hand the ingestor the body it just authenticated. The manifest here does
     * NOT start at image[0], so this is also the only pointer from which its
     * encryption fields can be read correctly. */

    /* Step 2: resolve payload_offset. Untrusted, so it is bounds-checked against
     * the region the caller permits — not against the whole device by default,
     * because a bank should not be able to name another bank's payload. */
    oca_storage_bounds_t bounds;
    bounds.manifest_addr = opt->manifest_addr;
    bounds.region_base   = opt->region_base_present ? opt->region_base : 0;
    bounds.region_limit  = opt->region_limit_present ? opt->region_limit
                                                     : (int64_t)image_len;

    int64_t payload_addr = 0;
    size_t  payload_span = 0u;
    r = oca_locate_payload(body, &bounds, &payload_addr, &payload_span);
    if (r != OCA_OK) {
        free(body);
        return r;
    }
    if (payload_span == 0u) {
        free(body);
        return OCA_OK;                      /* no payload declared */
    }

    /* Step 3: copy the payload out of storage. oca_locate_payload has already
     * proved the range lies inside the permitted region, so this read is in
     * bounds by construction — but assert the image actually holds it, since
     * region_limit is caller policy and may exceed the file. */
    if (payload_addr < 0 || (uint64_t)payload_addr + payload_span > image_len) {
        fprintf(stderr, "usage: payload at %#llx+%#zx is outside the image\n",
                (unsigned long long)payload_addr, payload_span);
        free(body);
        return OCA_FAIL_INVALID_ARG;
    }
    uint8_t *payload = malloc(payload_span);
    if (payload == NULL) {
        free(body);
        return OCA_FAIL_INVALID_ARG;
    }
    memcpy(payload, image + (size_t)payload_addr, payload_span);

    /* Step 4: verify the payload copy against the authenticated manifest copy. */
    r = oca_check_payload_at(body, payload, payload_span, cb, &vctx,
                             out_plaintext);

    if (r == OCA_OK && opt->list_images) {
        printf("located: payload at %#llx span %#zx\n",
               (unsigned long long)payload_addr, payload_span);
        list_toc(payload, payload_span);
    }
    free(payload);
    free(body);
    return r;
}

int main(int argc, char **argv)
{
    cli_options_t opt;
    int rc = cli_parse_args(argc, argv, &opt);
    if (rc != 0) {
        return 2;
    }

    size_t bundle_len = 0u;
    uint8_t *buf = read_file(opt.manifest_path, &bundle_len);
    if (buf == NULL) {
        return 2;
    }
    /* Whole-bundle mode validates the file where it sits, so the manifest is at
     * buf[0]. Storage mode overwrites this with its authenticated copy — the
     * manifest there is at --manifest-addr, not at the start of the image. No
     * secret is resolved yet: the ingestor does that from inside the decrypt
     * callback, once the signature has verified. */

    /* Point the readback callbacks at the parsed flags. On a real part these
     * values come from fuses the implementation reaches directly; a host tool
     * substituting flags for silicon binds them once, here. */
    cli_hwid_bind(&opt);
    openssl_decrypt_bind(&opt);
    g_cli_opt = &opt;

    oca_callbacks_t cb;
    memset(&cb, 0, sizeof(cb));
    cb.sha256              = openssl_sha256;
    cb.verify_signature    = openssl_verify_signature;
    cb.decrypt_payload     = openssl_decrypt_payload;
    cb.is_key_authorized   = cli_is_key_authorized;
    cb.get_identity_bytes  = cli_get_identity_bytes;
    cb.get_lifecycle_state = cli_get_lifecycle_state;
    cb.get_version         = cli_get_version;
    cb.is_secure_boot_active   = cli_is_secure_boot_active;
    cb.is_secure_boot_disabled = cli_is_secure_boot_disabled;
    cb.get_root_key_revocation = cli_get_root_key_revocation;
    cb.get_security_version    = cli_get_security_version;

    /* Storage-image mode runs the staged flow (manifest, locate, copy, verify);
     * the default treats the file as a contiguous bundle. */
    /* The validator reports where the validated plaintext is, so nothing has to
     * be captured inside the decrypt callback to find it afterwards. Written only
     * when validation succeeded. */
    oca_payload_plaintext_t plaintext;
    memset(&plaintext, 0, sizeof plaintext);

    /* Held across the call so the determination this validation made would be
     * available to oca_commit_security_state(). This CLI never commits — it is a
     * host tool and burns no fuses — but passing NULL here is the shape that
     * makes a real consumer have to determine a second time. */
    oca_validation_context_t vctx;
    oca_validation_context_init(&vctx);

    oca_result_t r = opt.storage_mode
        ? validate_from_storage(buf, bundle_len, &opt, &cb, &plaintext)
        : oca_validate(buf, bundle_len, &cb, &vctx, &plaintext);

    int exit_code;
    if (r == OCA_OK) {
        if (!opt.quiet) {
            char id[9];
            uint32_t cv_major = 0, cv_minor = 0, cv_patch = 0;
            /* In storage-image mode the manifest is at --manifest-addr, not at
             * the start of the image. Reading buf[0] there prints garbage. */
            const uint8_t *manifest = opt.storage_mode
                ? buf + (size_t)opt.manifest_addr : buf;
            copy_manifest_id(manifest, id);
            read_content_version(manifest, &cv_major, &cv_minor, &cv_patch);
            printf("PASS: %s v%u.%u.%u\n", id, cv_major, cv_minor, cv_patch);
        }
        exit_code = 0;
        /* Post-validation TOC walk. Only reachable on OCA_OK, which is the
         * contract the accessors document. */
        if (opt.list_images && !opt.storage_mode) {
            list_payload_images(buf, bundle_len, &plaintext);
        }
        /* Emit the recovered plaintext when the payload was decrypted and an
         * output path was requested. Plaintext goes only to that file — never
         * to stdout/stderr/logs (Principle V). */
        if (opt.payload_out_path != NULL && plaintext.bytes != NULL) {
            FILE *out = fopen(opt.payload_out_path, "wb");
            if (out == NULL) {
                fprintf(stderr, "usage: cannot open --payload-out %s: %s\n",
                        opt.payload_out_path, strerror(errno));
                exit_code = 2;
            } else {
                size_t w = fwrite(plaintext.bytes, 1u, plaintext.len, out);
                fclose(out);
                if (w != plaintext.len) {
                    exit_code = 2;
                }
            }
        }
    } else {
        fprintf(stderr, "FAIL: %s: %s\n", oca_result_str(r), reason_for(r));
        /* Distinguish "this build doesn't support that variant" (exit 3) from a
         * generic validation failure (exit 1); usage/IO errors return 2 above. */
        exit_code = (r == OCA_FAIL_UNSUPPORTED_VARIANT) ? 3 : 1;
    }

    /* The decrypt stub owns whatever it allocated; with --decrypt-in-place the
     * plaintext aliases the interior of `buf` and it owns nothing. Either way,
     * releasing is its call to make, not ours. */
    openssl_decrypt_release();
    free(buf);
    return exit_code;
}
