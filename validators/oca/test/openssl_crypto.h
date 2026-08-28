/*
 * openssl_crypto.h — Host-side crypto callbacks backed by OpenSSL 3.
 * Provides the sha256 and verify_signature callbacks the OCA validator
 * library expects when running on a developer laptop.
 */

#ifndef OCA_OPENSSL_CRYPTO_H
#define OCA_OPENSSL_CRYPTO_H

#include "cli_args.h"
#include "oca_validator.h"

oca_result_t openssl_sha256(const uint8_t *msg, size_t msg_len,
                            uint8_t out_digest[32]);

oca_result_t openssl_verify_signature(
    const oca_crypto_blob_t *signature,
    const oca_crypto_blob_t *public_key,
    const uint8_t *signed_region, size_t signed_region_len);

/* Bind the provisioned secrets and the in-place preference this callback needs.
 *
 * A real part reads its key store directly; this is the host equivalent of
 * having one. Call once before validating. NULL unbinds, after which the
 * callback reports that no secret is provisioned. */
void openssl_decrypt_bind(const cli_options_t *opt);

/* Resolve in->secret_select against the bound secrets, derive the AES key from
 * that secret via SP 800-108r1 Counter Mode (HMAC-SHA-256) over the 192-byte
 * expanded input block, then AES-CBC-decrypt the payload (PKCS#7 unpadded). The
 * cipher and key length follow in->cipher.
 *
 * The selector is an index, not a secret: no key material crosses the library
 * boundary in either direction. A slot with no provisioned secret is reported as
 * OCA_FAIL_NO_PROVISIONED_SECRET, distinct from a decryption that ran and
 * failed. */
oca_result_t openssl_decrypt_payload(
    const oca_decrypt_input_t *in,
    const uint8_t **out_plaintext, size_t *out_plaintext_len);

/* Free the plaintext buffer the callback allocated, if it allocated one. A no-op
 * when it decrypted in place over the caller's buffer. Idempotent. */
void openssl_decrypt_release(void);

#endif /* OCA_OPENSSL_CRYPTO_H */
