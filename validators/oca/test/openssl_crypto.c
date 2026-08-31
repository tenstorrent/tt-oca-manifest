// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/*
 * openssl_crypto.c — SHA-256 + signature verification via OpenSSL 3 EVP.
 *
 * The verify callback handles both supported primitive types:
 *   RSA-3072 PKCS#1 v1.5 + SHA-256  (signature_type = 0x01)
 *   ECDSA P-256 + SHA-256           (signature_type = 0x05)
 *
 * in both encodings the format defines. The library hands us the full field
 * width as an upper bound and the blob's `encoding` / `primitive_type`, which
 * together determine how to read the bytes:
 *
 *   Public key, raw (0x02)  RSA: big-endian modulus || 4-byte big-endian
 *                                exponent (388 bytes)
 *                           EC:  SEC1 uncompressed point (65 bytes)
 *   Public key, DER (0x01)  PKCS#1 RSAPublicKey. NOT SubjectPublicKeyInfo —
 *                           the format's DER encoding is the structure for the
 *                           value itself, with no AlgorithmIdentifier wrapper.
 *   Signature,  raw (0x02)  RSA: the 384-byte big-endian integer
 *                           EC:  r || s, each 32 bytes big-endian
 *   Signature,  DER (0x01)  EC only: an RFC 3279 ECDSA-Sig-Value
 *
 * OpenSSL wants an ECDSA signature as DER, so the raw form is re-encoded here.
 */

#include "openssl_crypto.h"
#include "oca_layout.h"
#include "cli_args.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

oca_result_t openssl_sha256(const uint8_t *msg, size_t msg_len,
                            uint8_t out_digest[32])
{
    unsigned out_len = 32u;
    if (EVP_Digest(msg, msg_len, out_digest, &out_len,
                   EVP_sha256(), NULL) != 1) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    if (out_len != 32u) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    return OCA_OK;
}

/* RSA-3072 PKCS#1 v1.5 writes a fixed-width signature: the modulus size. */
#define RSA_3072_SIGNATURE_BYTES 384u

/* Total encoded length of the DER SEQUENCE at `p` — tag + length octets +
 * contents — or 0 if those bytes are not a well-formed SEQUENCE header whose
 * contents fit inside `avail`.
 *
 * The signature field is a fixed-width slot that the packer right-pads with
 * 0x00, so the real length has to come from the DER framing. It must NOT come
 * from trimming trailing zeros: a DER INTEGER may legitimately end in 0x00
 * (roughly 1 ECDSA-P256 signature in 256, since it happens whenever the low
 * byte of `s` is zero), and trimming that byte corrupts an otherwise valid
 * signature into a spurious verification failure.
 */
static size_t der_sequence_total_len(const uint8_t *p, size_t avail)
{
    if (avail < 2u || p[0] != 0x30u) {
        return 0u;                          /* not a SEQUENCE */
    }
    uint8_t len_octet = p[1];
    size_t header;
    size_t content;
    if ((len_octet & 0x80u) == 0u) {
        header  = 2u;                       /* short form: length is the octet */
        content = len_octet;
    } else {
        unsigned n = (unsigned)(len_octet & 0x7Fu);  /* long form: n length octets */
        /* n == 0 is BER indefinite length, which DER forbids. A signature field
         * is far below 64 KiB, so more than two length octets is malformed. */
        if (n == 0u || n > 2u || avail < 2u + n) {
            return 0u;
        }
        header  = 2u + n;
        content = 0u;
        for (unsigned i = 0u; i < n; ++i) {
            content = (content << 8) | p[2u + i];
        }
    }
    if (content == 0u || content > avail - header) {
        return 0u;                          /* empty, or runs past the field */
    }
    return header + content;
}

/* Raw public-key component widths, per the spec's encoded-length table. */
#define RSA_3072_MODULUS_BYTES      384u
#define RSA_PUBLIC_EXPONENT_BYTES     4u
#define RAW_RSA_PUBLIC_KEY_BYTES    (RSA_3072_MODULUS_BYTES + RSA_PUBLIC_EXPONENT_BYTES)
#define EC_P256_COORD_BYTES          32u
#define RAW_EC_PUBLIC_KEY_BYTES     (1u + (2u * EC_P256_COORD_BYTES))
#define RAW_EC_SIGNATURE_BYTES      (2u * EC_P256_COORD_BYTES)

/**
 * @brief Build an EVP_PKEY from a raw RSA public key.
 *
 * The raw form is a fixed-width big-endian modulus followed by a 4-byte
 * big-endian public exponent, so the exponent is read from the blob rather than
 * assumed: a key using the legacy exponent 3 and one using F4 (65537) have the
 * same raw length and differ only in those trailing four bytes.
 *
 * @param[in] raw  RAW_RSA_PUBLIC_KEY_BYTES of key material.
 * @return A caller-owned EVP_PKEY, or NULL if any OpenSSL step failed.
 */
static EVP_PKEY *rsa_key_from_raw(const uint8_t *raw)
{
    BIGNUM *n = BN_bin2bn(raw, (int)RSA_3072_MODULUS_BYTES, NULL);
    BIGNUM *e = BN_bin2bn(raw + RSA_3072_MODULUS_BYTES,
                          (int)RSA_PUBLIC_EXPONENT_BYTES, NULL);
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (n == NULL || e == NULL || bld == NULL) {
        goto done;
    }
    if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) != 1
        || OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e) != 1) {
        goto done;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
    if (params == NULL || ctx == NULL || EVP_PKEY_fromdata_init(ctx) != 1) {
        goto done;
    }
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        pkey = NULL;
    }

done:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    BN_free(e);
    BN_free(n);
    return pkey;
}

/**
 * @brief Build an EVP_PKEY from a SEC1 uncompressed P-256 point.
 *
 * The point is 0x04 || X || Y with both coordinates big-endian, which is what
 * the raw EC public-key encoding carries.
 *
 * @param[in] raw  RAW_EC_PUBLIC_KEY_BYTES of point material.
 * @return A caller-owned EVP_PKEY, or NULL if any OpenSSL step failed.
 */
static EVP_PKEY *ec_key_from_raw(const uint8_t *raw)
{
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (bld == NULL) {
        goto done;
    }
    if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
                                        "prime256v1", 0) != 1
        || OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                            raw, RAW_EC_PUBLIC_KEY_BYTES) != 1) {
        goto done;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (params == NULL || ctx == NULL || EVP_PKEY_fromdata_init(ctx) != 1) {
        goto done;
    }
    if (EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) != 1) {
        pkey = NULL;
    }

done:
    EVP_PKEY_CTX_free(ctx);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(bld);
    return pkey;
}

/**
 * @brief Decode a public key blob according to its declared encoding.
 *
 * Dispatches on the blob's encoding and primitive: DER means a PKCS#1
 * RSAPublicKey (defined for RSA only), raw means the algorithm's own byte
 * layout. The DER length is not known in advance — it varies with the public
 * exponent — so d2i_PublicKey is handed the whole field as an upper bound and
 * consumes only what the structure declares, leaving the zero padding alone.
 *
 * @param[in] public_key  The key blob, with its encoding and primitive type.
 * @return A caller-owned EVP_PKEY, or NULL if the encoding is undefined for the
 *         declared primitive, the field is too small, or parsing failed.
 */
static EVP_PKEY *decode_public_key(const oca_crypto_blob_t *public_key)
{
    if (public_key->encoding == OCA_ENCODING_DER) {
        /* PKCS#1 RSAPublicKey. d2i_PublicKey consumes only what the DER
         * structure asks for and leaves the trailing 0x00 padding alone. DER is
         * defined for RSA keys only. */
        if (public_key->primitive_type != OCA_PRIMITIVE_RSA_3072_PKCS1V15_SHA256) {
            return NULL;
        }
        const unsigned char *p = public_key->bytes;
        return d2i_PublicKey(EVP_PKEY_RSA, NULL, &p,
                             (long)public_key->field_length);
    }
    if (public_key->encoding != OCA_ENCODING_RAW) {
        return NULL;
    }
    if (public_key->primitive_type == OCA_PRIMITIVE_RSA_3072_PKCS1V15_SHA256) {
        if (public_key->field_length < RAW_RSA_PUBLIC_KEY_BYTES) {
            return NULL;
        }
        return rsa_key_from_raw(public_key->bytes);
    }
    if (public_key->primitive_type == OCA_PRIMITIVE_ECDSA_P256_SHA256) {
        if (public_key->field_length < RAW_EC_PUBLIC_KEY_BYTES) {
            return NULL;
        }
        return ec_key_from_raw(public_key->bytes);
    }
    return NULL;
}

/**
 * @brief Re-encode a raw r || s ECDSA signature as DER.
 *
 * OpenSSL's verify path takes an ECDSA-Sig-Value, so the fixed-width raw form
 * has to be converted before use.
 *
 * @param[in]  raw      RAW_EC_SIGNATURE_BYTES of signature material.
 * @param[out] out      Receives an OpenSSL-allocated DER buffer, which the
 *                      caller frees with OPENSSL_free(). Untouched on failure.
 * @param[out] out_len  Receives the DER length. Untouched on failure.
 * @return 1 on success, 0 if any allocation or encoding step failed.
 */
static int ecdsa_raw_to_der(const uint8_t *raw, unsigned char **out, size_t *out_len)
{
    ECDSA_SIG *sig = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(raw, (int)EC_P256_COORD_BYTES, NULL);
    BIGNUM *s = BN_bin2bn(raw + EC_P256_COORD_BYTES, (int)EC_P256_COORD_BYTES, NULL);
    int ok = 0;

    if (sig == NULL || r == NULL || s == NULL) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return 0;
    }
    /* Ownership of r and s transfers to sig on success. */
    if (ECDSA_SIG_set0(sig, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        ECDSA_SIG_free(sig);
        return 0;
    }

    unsigned char *der = NULL;
    int len = i2d_ECDSA_SIG(sig, &der);
    if (len > 0) {
        *out = der;
        *out_len = (size_t)len;
        ok = 1;
    }
    ECDSA_SIG_free(sig);
    return ok;
}

oca_result_t openssl_verify_signature(
    const oca_crypto_blob_t *signature,
    const oca_crypto_blob_t *public_key,
    const uint8_t *signed_region, size_t signed_region_len)
{

    if (signature == NULL || public_key == NULL || signed_region == NULL) {
        return OCA_FAIL_INVALID_ARG;
    }
    if (signature->primitive_type != public_key->primitive_type) {
        return OCA_FAIL_INVALID_ARG;
    }

    EVP_PKEY *pkey = decode_public_key(public_key);
    if (pkey == NULL) {
        return OCA_FAIL_SIGNATURE;
    }

    /* Resolve the signature bytes within the fixed-width field. Three shapes:
     * a fixed-width RSA integer; a variable-length ECDSA DER value whose length
     * comes from its own SEQUENCE framing (never from trimming padding — see
     * der_sequence_total_len); or a fixed-width raw r || s that has to be
     * re-encoded as DER for OpenSSL. */
    const unsigned char *sig_bytes = signature->bytes;
    size_t sig_len = 0u;
    unsigned char *sig_der = NULL;      /* owned here only for the raw-EC path */

    if (signature->primitive_type == OCA_PRIMITIVE_RSA_3072_PKCS1V15_SHA256) {
        if (signature->encoding != OCA_ENCODING_RAW
            || signature->field_length < RSA_3072_SIGNATURE_BYTES) {
            EVP_PKEY_free(pkey);
            return OCA_FAIL_SIGNATURE;
        }
        sig_len = RSA_3072_SIGNATURE_BYTES;
    } else if (signature->primitive_type == OCA_PRIMITIVE_ECDSA_P256_SHA256) {
        if (signature->encoding == OCA_ENCODING_DER) {
            sig_len = der_sequence_total_len(signature->bytes,
                                             signature->field_length);
            if (sig_len == 0u) {
                EVP_PKEY_free(pkey);
                return OCA_FAIL_SIGNATURE;
            }
        } else if (signature->encoding == OCA_ENCODING_RAW) {
            if (signature->field_length < RAW_EC_SIGNATURE_BYTES
                || !ecdsa_raw_to_der(signature->bytes, &sig_der, &sig_len)) {
                EVP_PKEY_free(pkey);
                return OCA_FAIL_SIGNATURE;
            }
            sig_bytes = sig_der;
        } else {
            EVP_PKEY_free(pkey);
            return OCA_FAIL_SIGNATURE;
        }
    } else {
        EVP_PKEY_free(pkey);
        return OCA_FAIL_INVALID_ARG;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL) {
        OPENSSL_free(sig_der);
        EVP_PKEY_free(pkey);
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    oca_result_t result = OCA_OK;
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
        result = OCA_FAIL_SIGNATURE;
    } else {
        int rc = EVP_DigestVerify(md_ctx,
                                  sig_bytes, sig_len,
                                  signed_region, signed_region_len);
        if (rc != 1) {
            result = OCA_FAIL_SIGNATURE;
        }
    }

    EVP_MD_CTX_free(md_ctx);
    OPENSSL_free(sig_der);
    EVP_PKEY_free(pkey);
    return result;
}

/* Build the 192-byte expanded KDF input block and derive the AES key via
 * SP 800-108r1 Counter Mode (HMAC-SHA-256), reproducing the OCAH Key Manager
 * PREPARE_BL_DECRYPT_KEY flow:
 *   block = header(32) || "KM_CLASS_BL"(32) || kdf_input(64) || zero-entropy(64)
 *   key   = ( HMAC-SHA256(secret, be16(i) || block || be16(L)) )[0 : L/8]
 * for i = 1,2,... with L = key_bits (128 for AES-128-CBC, 256 for AES-256-CBC).
 * Only the block's out_bits header field and the length suffix vary by cipher;
 * everything else is fixed. `out_key` must hold key_bits/8 bytes. */
static int derive_payload_key(const uint8_t secret[32],
                              const uint8_t kdf_input[64],
                              unsigned key_bits,
                              uint8_t *out_key)
{
    uint8_t block[192];
    memset(block, 0, sizeof block);
    /* 32-byte header (little-endian km_kdf_input_t fields) */
    block[0]  = 0x01; block[1] = 0x00;      /* version = 0x0001                */
    block[2]  = 0x01;                        /* out_class = SYMMETRIC           */
    block[3]  = 0x00;                        /* out_type  = SYM_RAW             */
    block[4]  = 0x00;                        /* out_owner = NONE                */
    block[5]  = 0x01;                        /* out_domain = SW                 */
    block[6]  = 0x18; block[7] = 0x00;      /* flags = ROM_CREATED|ROM_LINEAGE */
    block[8]  = 0x00; block[9] = 0x00;      /* purpose = 0                     */
    block[10] = (uint8_t)(key_bits & 0xFFu);          /* out_bits (LE)         */
    block[11] = (uint8_t)((key_bits >> 8) & 0xFFu);
    block[12] = 0x01; block[13] = 0x00; block[14] = 0x00; block[15] = 0x00;  /* caps = SYM_AES */
    /* device_state (16..19) and rsvd (20..31) stay zero */
    memcpy(block + 32, "KM_CLASS_BL", 11);   /* label (remaining bytes zero)   */
    memcpy(block + 64, kdf_input, 64);        /* context                        */
    /* entropy (128..191) stays zero */

    const size_t out_len = key_bits / 8u;
    uint8_t msg[2u + 192u + 2u];
    memcpy(msg + 2, block, 192);
    msg[2 + 192]     = (uint8_t)((key_bits >> 8) & 0xFFu);  /* L (BE) high      */
    msg[2 + 192 + 1] = (uint8_t)(key_bits & 0xFFu);         /* L (BE) low       */

    size_t done = 0u;
    for (uint16_t i = 1u; done < out_len; ++i) {
        msg[0] = (uint8_t)(i >> 8);          /* counter (BE)                    */
        msg[1] = (uint8_t)(i & 0xFFu);
        uint8_t mac[EVP_MAX_MD_SIZE];
        unsigned mac_len = 0u;
        if (HMAC(EVP_sha256(), secret, 32, msg, sizeof msg, mac, &mac_len) == NULL
            || mac_len < 32u) {
            return -1;
        }
        size_t take = (out_len - done > 32u) ? 32u : (out_len - done);
        memcpy(out_key + done, mac, take);
        done += take;
    }
    return 0;
}

/* Bound provisioned secrets — this host's stand-in for a key store. */
static const cli_options_t *g_secrets;

/* The plaintext buffer this stub allocated, or NULL when it decrypted in place
 * over the caller's own buffer and so owns nothing. */
static uint8_t *g_owned_plaintext;

void openssl_decrypt_release(void)
{
    free(g_owned_plaintext);
    g_owned_plaintext = NULL;
}

void openssl_decrypt_bind(const cli_options_t *opt)
{
    g_secrets = opt;
}

/* Resolve a 1-based provisioned-secret index against the bound secrets.
 * Returns NULL when this part holds no secret for that slot. */
static const uint8_t *secret_for_slot(uint16_t slot)
{
    if (g_secrets == NULL) {
        return NULL;
    }
    for (size_t i = 0u; i < g_secrets->payload_secret_count; ++i) {
        if (g_secrets->payload_secret_slot[i] == slot) {
            return g_secrets->payload_secret[i];
        }
    }
    return NULL;
}

oca_result_t openssl_decrypt_payload(
    const oca_decrypt_input_t *in,
    const uint8_t **out_plaintext, size_t *out_plaintext_len)
{
    /* Resolving the selector is this callback's job. The library hands over an
     * index and never sees the secret it names. */
    const uint8_t *secret = secret_for_slot(in->secret_select);
    if (secret == NULL) {
        return OCA_FAIL_NO_PROVISIONED_SECRET;
    }
    /* The validator guarantees a non-zero, 16-byte-block-aligned ciphertext
     * before invoking this callback, and rejects any cipher outside the two
     * below before getting here — so the else branch is a belt-and-braces
     * refusal, not a reachable path. */
    unsigned key_bits;
    const EVP_CIPHER *cipher;
    if (in->cipher == OCA_ENCRYPTION_TYPE_AES_128_CBC) {
        key_bits = 128u; cipher = EVP_aes_128_cbc();
    } else if (in->cipher == OCA_ENCRYPTION_TYPE_AES_256_CBC) {
        key_bits = 256u; cipher = EVP_aes_256_cbc();
    } else {
        return OCA_FAIL_DECRYPT;   /* unsupported cipher */
    }

    uint8_t key[32];
    if (derive_payload_key(secret, in->kdf_input, key_bits, key) != 0) {
        return OCA_FAIL_DECRYPT;
    }

    /* Destination buffer. In-place decryption writes over the ciphertext,
     * halving peak memory — what a boot ROM with limited SRAM wants.
     *
     * Safe because the library never touches the ciphertext again once this
     * callback returns: payload_hash was already verified over it (step 1 of
     * oca_check_payload), the `iv` and `kdf_input` arguments point into the
     * MANIFEST BODY rather than the payload, and oca_check_payload is the last
     * stage of oca_validate. Casting away const is legal here because the
     * underlying object is the caller's own mutable bundle buffer.
     *
     * The cost is that the bundle no longer holds the ciphertext, so the same
     * buffer cannot be validated a second time — payload_hash covers ciphertext
     * that is gone. A single-shot boot flow does not care; a retry loop must
     * re-read from flash. */
    uint8_t *plaintext;
    bool owned;
    if (g_secrets->decrypt_in_place) {
        plaintext = (uint8_t *)(uintptr_t)in->ciphertext;
        owned = false;
    } else {
        plaintext = malloc(in->ciphertext_len);       /* plaintext <= ciphertext */
        owned = true;
        if (plaintext == NULL) {
            return OCA_FAIL_DECRYPT;
        }
    }
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        if (owned) {
            free(plaintext);
        }
        return OCA_FAIL_DECRYPT;
    }

    int ok = (EVP_DecryptInit_ex(ctx, cipher, NULL, key, in->iv) == 1);
    int outl = 0;
    size_t total = 0u;
    if (ok && EVP_DecryptUpdate(ctx, plaintext, &outl,
                                in->ciphertext, (int)in->ciphertext_len) == 1) {
        total += (size_t)outl;
    } else {
        ok = 0;
    }
    if (ok && EVP_DecryptFinal_ex(ctx, plaintext + total, &outl) == 1) {
        total += (size_t)outl;  /* PKCS#7 unpadding happens here */
    } else {
        ok = 0;
    }
    EVP_CIPHER_CTX_free(ctx);

    if (!ok) {
        if (owned) {
            free(plaintext);
        }
        return OCA_FAIL_DECRYPT;
    }

    /* Ownership stays with whoever allocated. The validator reports WHERE the
     * plaintext is; only this stub knows whether the buffer is its own malloc or
     * the caller's bundle decrypted in place, so releasing it is its job too. */
    openssl_decrypt_release();          /* defensive; validation calls this once */
    g_owned_plaintext = owned ? plaintext : NULL;
    *out_plaintext = plaintext;
    *out_plaintext_len = total;
    return OCA_OK;
}
