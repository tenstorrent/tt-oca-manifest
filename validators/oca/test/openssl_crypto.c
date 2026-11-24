// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
/*
 * openssl_crypto.c — SHA-256 + signature verification via OpenSSL 3.5+ EVP.
 *
 * The verify callback handles every supported primitive type:
 *   RSA-3072 PKCS#1 v1.5 + SHA-256  (signature_type = 0x01)
 *   ECDSA P-256 + SHA-256           (signature_type = 0x05)
 *   ML-DSA-87                       (signature_type_pqc = 0x33)
 *
 * ML-DSA-87 is pure FIPS 204 ML-DSA.Verify over the signed region itself with
 * the empty context: no pre-hash and no HashML-DSA. Its key and signature are
 * raw only — pkEncode (2592 bytes) and sigEncode (4627 bytes) — and are read to
 * the lengths the blobs carry, which the library has already held to those
 * values. Each PQC algorithm is one row of the table in verify_pqc().
 *
 * A raw or DER RSA key's public exponent must be odd and at least 3. That is a
 * sanity bound, not the trust decision: the anchor in cli_hwid.c binds the
 * whole key, exponent included.
 *
 * The classical types come in both encodings the format defines. Each blob
 * carries its field width, its declared `length`, and its `encoding` /
 * `primitive_type`, which together determine how to read the bytes. A DER
 * value is parsed within `length` and never past it:
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
#include <openssl/opensslv.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#if OPENSSL_VERSION_NUMBER < 0x30500000L
#error "oca-validate needs OpenSSL 3.5 or later, the first release with ML-DSA"
#endif

oca_result_t openssl_hash(oca_hash_type_t type,
                          const uint8_t *msg, size_t msg_len,
                          uint8_t *out_digest, size_t digest_len)
{
    if (type != OCA_HASH_TYPE_SHA2_256 || digest_len != 32u) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    return openssl_sha256(msg, msg_len, out_digest);
}

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

/* Whether all `len` bytes at `p` are zero. */
static int all_zero(const uint8_t *p, size_t len)
{
    uint8_t acc = 0u;
    for (size_t i = 0u; i < len; ++i) {
        acc |= p[i];
    }
    return acc == 0u;
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
 * layout. A DER key's length varies with the public exponent, which is why the
 * manifest declares it: the structure is parsed within that length and must
 * consume all of it, so a public_key_size that misdescribes the key is refused.
 *
 * @param[in] public_key  The key blob, with its encoding and primitive type.
 * @return A caller-owned EVP_PKEY, or NULL if the encoding is undefined for the
 *         declared primitive, the field is too small, parsing failed, or a DER
 *         key does not occupy exactly its declared length.
 */
static EVP_PKEY *decode_public_key(const oca_crypto_blob_t *public_key)
{
    if (public_key->encoding == OCA_ENCODING_DER) {
        if (public_key->primitive_type != OCA_PRIMITIVE_RSA_3072_PKCS1V15_SHA256
            || public_key->length == 0u
            || public_key->length > public_key->field_length) {
            return NULL;
        }
        const unsigned char *p = public_key->bytes;
        EVP_PKEY *pkey = d2i_PublicKey(EVP_PKEY_RSA, NULL, &p,
                                       (long)public_key->length);
        if (pkey != NULL && (size_t)(p - public_key->bytes) != public_key->length) {
            EVP_PKEY_free(pkey);
            return NULL;
        }
        return pkey;
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

/**
 * @brief Build an EVP_PKEY from a raw PQC public key.
 *
 * The raw form is the algorithm's own encoding (FIPS 204 pkEncode for
 * ML-DSA), which OpenSSL imports as the key's public octet string.
 *
 * @param[in] name  OpenSSL's name for the key type.
 * @param[in] raw   Key material.
 * @param[in] len   Bytes of @p raw.
 * @return A caller-owned EVP_PKEY, or NULL if any OpenSSL step failed.
 */
static EVP_PKEY *pqc_key_from_raw(const char *name, const uint8_t *raw, size_t len)
{
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (bld == NULL
        || OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, raw, len) != 1) {
        goto done;
    }
    params = OSSL_PARAM_BLD_to_param(bld);
    ctx = EVP_PKEY_CTX_new_from_name(NULL, name, NULL);
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

/* PQC primitives this backend verifies, by the name OpenSSL knows each as.
 * Adding an algorithm the library accepts is one row here. */
static const struct {
    oca_primitive_type_t primitive;
    const char          *openssl_name;
} PQC_ALGORITHMS[] = {
    { OCA_PRIMITIVE_ML_DSA_87, "ML-DSA-87" },
};

/**
 * @brief Verify a PQC-family signature with the algorithm its primitive names.
 *
 * Message encoding 1 is pure ML-DSA, M' = 0 || len(ctx) || ctx || M; the
 * context string is set explicitly empty and external-mu off, so a change in
 * OpenSSL's defaults cannot change the construction. The message is the signed
 * region as given, and the key and signature are read to the lengths the blobs
 * carry.
 *
 * @param[in] signature          Signature blob.
 * @param[in] public_key         Public-key blob.
 * @param[in] signed_region      Bytes the signature covers.
 * @param[in] signed_region_len  Length of @p signed_region.
 * @retval OCA_OK                        Signature verified.
 * @retval OCA_FAIL_SIGNATURE            Verification mismatch, or a blob this
 *                                       backend cannot read as its algorithm.
 * @retval OCA_FAIL_CALLBACK_UNAVAILABLE A primitive this backend does not
 *                                       implement, an OpenSSL without it, or
 *                                       an OpenSSL allocation failure.
 */
static oca_result_t verify_pqc(const oca_crypto_blob_t *signature,
                               const oca_crypto_blob_t *public_key,
                               const uint8_t *signed_region, size_t signed_region_len)
{
    const char *name = NULL;
    for (size_t i = 0u; i < sizeof PQC_ALGORITHMS / sizeof PQC_ALGORITHMS[0]; ++i) {
        if (PQC_ALGORITHMS[i].primitive == signature->primitive_type) {
            name = PQC_ALGORITHMS[i].openssl_name;
        }
    }
    if (name == NULL) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    if (signature->encoding != OCA_ENCODING_RAW || public_key->encoding != OCA_ENCODING_RAW
        || signature->length == 0u || signature->length > signature->field_length
        || public_key->length == 0u || public_key->length > public_key->field_length) {
        return OCA_FAIL_SIGNATURE;
    }

    EVP_SIGNATURE *algorithm = EVP_SIGNATURE_fetch(NULL, name, NULL);
    if (algorithm == NULL) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    EVP_PKEY *pkey = pqc_key_from_raw(name, public_key->bytes, public_key->length);
    if (pkey == NULL) {
        EVP_SIGNATURE_free(algorithm);
        return OCA_FAIL_SIGNATURE;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (ctx == NULL) {
        EVP_PKEY_free(pkey);
        EVP_SIGNATURE_free(algorithm);
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }

    int message_encoding = 1;
    unsigned char empty_context = 0u;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &message_encoding),
        OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING,
                                          &empty_context, 0u),
#ifdef OSSL_SIGNATURE_PARAM_MU
        OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MU, &(int){0}),
#endif
        OSSL_PARAM_construct_end(),
    };
    oca_result_t result = OCA_FAIL_SIGNATURE;
    if (EVP_PKEY_verify_message_init(ctx, algorithm, params) == 1
        && EVP_PKEY_verify(ctx, signature->bytes, signature->length,
                           signed_region, signed_region_len) == 1) {
        result = OCA_OK;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    EVP_SIGNATURE_free(algorithm);
    return result;
}

/* Whether an RSA key's public exponent is odd and at least 3. A sanity bound
 * on what this backend will verify with; the anchor binds the key itself. */
static int rsa_exponent_acceptable(const EVP_PKEY *pkey)
{
    BIGNUM *e = NULL;
    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) != 1) {
        return 0;
    }
    int ok = BN_is_odd(e) && BN_num_bits(e) >= 2;
    BN_free(e);
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
    if (signature->primitive_type != public_key->primitive_type
        || signature->key_algorithm != public_key->key_algorithm) {
        return OCA_FAIL_INVALID_ARG;
    }
    if (signature->key_algorithm == OCA_KEY_ALGO_PQC) {
        return verify_pqc(signature, public_key, signed_region, signed_region_len);
    }

    EVP_PKEY *pkey = decode_public_key(public_key);
    if (pkey == NULL) {
        return OCA_FAIL_SIGNATURE;
    }
    if (public_key->primitive_type == OCA_PRIMITIVE_RSA_3072_PKCS1V15_SHA256
        && !rsa_exponent_acceptable(pkey)) {
        EVP_PKEY_free(pkey);
        return OCA_FAIL_SIGNATURE;
    }

    /* Resolve the signature bytes within the fixed-width field. Three shapes:
     * a fixed-width RSA integer; a variable-length ECDSA DER value whose length
     * comes from its own SEQUENCE framing (never from trimming padding — see
     * der_sequence_total_len), bounded by the declared maximum and followed by
     * nothing but zeros up to it; or a fixed-width raw r || s that has to be
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
            if (signature->length <= signature->field_length) {
                sig_len = der_sequence_total_len(signature->bytes,
                                                 signature->length);
            }
            if (sig_len == 0u
                || !all_zero(signature->bytes + sig_len, signature->length - sig_len)) {
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
 * SP 800-108r1 Counter Mode (HMAC-SHA-256), per the payload-key derivation
 * contract in validators/oca/README.md:
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
    /* This backend derives one way, from one source. The library passes only
     * what its build enables; anything else is a combination this backend has
     * no implementation for. */
    if (in->kdf != OCA_KDF_SP800_108_HMAC_SHA256
        || in->key_source != OCA_KEY_SOURCE_PRESHARED) {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
    }
    /* Resolving the selector is this callback's job. The library hands over an
     * index and never sees the secret it names. */
    const uint8_t *secret = secret_for_slot(in->secret_select);
    if (secret == NULL) {
        return OCA_FAIL_NO_PROVISIONED_SECRET;
    }
    /* The validator guarantees a non-zero, block-aligned ciphertext before
     * invoking this callback, and passes only a cipher its build enables; the
     * else branch is for a build enabling one this backend does not implement. */
    unsigned key_bits;
    const EVP_CIPHER *cipher;
    if (in->cipher == OCA_ENCRYPTION_TYPE_AES_128_CBC) {
        key_bits = 128u; cipher = EVP_aes_128_cbc();
    } else if (in->cipher == OCA_ENCRYPTION_TYPE_AES_256_CBC) {
        key_bits = 256u; cipher = EVP_aes_256_cbc();
    } else {
        return OCA_FAIL_CALLBACK_UNAVAILABLE;
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
