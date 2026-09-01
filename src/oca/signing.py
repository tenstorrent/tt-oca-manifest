# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""OCA signing glue.

Wraps the existing `manifest_signing.SigningKey` factory so OCA producers
reuse the shared `local` / `aws` signing authorities. Translates between
OCA's on-disk `signature_type_classic` values (0x01 / 0x05) and the
internal `ManifestSignatureType` enum (1 / 2).

The OCA spec permits two on-disk encodings, but not symmetrically:

* **Raw bytes (0x02)** is available for every algorithm and means the value as
  its own standard defines it, in the byte order that standard requires — which
  is big-endian for both RSA and ECDSA.
* **ASN.1 DER (0x01)** is available only where a bare ASN.1 structure is defined
  for the value itself: RSA public keys (PKCS#1 `RSAPublicKey`) and ECDSA
  signatures (RFC 3279 `ECDSA-Sig-Value`). Every other DER combination is
  undefined and rejected.

Each encoded value is accompanied by a `*_size_classic` field giving its byte
count, so a consumer can bound its parse instead of guessing from zero padding.
Vendor-defined encoding (0x03) is deferred to a future feature pass.
"""

from __future__ import annotations

from collections import namedtuple

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, utils as _ec_utils

from .. import manifest_signing as _ms
from ..pack_images_constants import ManifestSignatureType
from . import constants as oca_consts
from .validators import OcaConfigError


# OCA `signature_type_classic` → internal `ManifestSignatureType` enum value.
# The OCA RSA value (0x01) coincidentally equals the internal value (1). The
# OCA ECC value (0x05) does NOT equal the internal value (2) — the table makes
# that explicit.
_OCA_TO_INTERNAL_SIG_TYPE = {
    oca_consts.OcaClassicSignatureType.RSA_3072_PKCS1V15_SHA256.value:
        ManifestSignatureType.RSA_3072.value,
    oca_consts.OcaClassicSignatureType.ECDSA_P256_SHA256.value:
        ManifestSignatureType.ECC_P_256.value,
}

# Sentinel value for the legacy `manifest_identifier` field used in the adapter
# dict passed to `prepare_signing_key`. Any value other than 0x314c4254 ("TBL1")
# avoids the factory's BL1-must-use-RSA restriction.
_NON_BL1_MANIFEST_IDENTIFIER = 0

ENCODING_DER = oca_consts.OcaClassicPublicKeyEncoding.ASN1_DER.value        # 0x01
ENCODING_RAW = oca_consts.OcaClassicPublicKeyEncoding.RAW_BYTES.value       # 0x02

_RSA_3072_MODULUS_BYTES = oca_consts.RSA_3072_MODULUS_BYTES
_RSA_PUBLIC_EXPONENT_BYTES = oca_consts.RSA_PUBLIC_EXPONENT_BYTES
_EC_P256_COORD_BYTES = oca_consts.EC_P256_COORD_BYTES

# An encoded value plus the byte count that its `*_size_classic` field carries.
# The count is returned rather than recomputed by the caller so that exactly one
# place decides what the size field means — which matters because the two fields
# do not follow the same rule (see `signature_field()`).
EncodedField = namedtuple("EncodedField", ["field", "size"])


def build_signing_key(config: dict):
    """Construct a `manifest_signing.SigningKey` from an OCA-classic config.

    Bridges the OCA YAML shape to the adapter dict shape the existing
    factory expects. Caller must have set `secure_boot == 1` (this function is
    only invoked on the secure-boot path).
    """
    sig_type_oca = int(config["signature_type"])
    if sig_type_oca not in _OCA_TO_INTERNAL_SIG_TYPE:
        # Should be unreachable — reject_deferred_features catches this earlier.
        raise OcaConfigError(
            f"signature_type {sig_type_oca:#x} cannot be mapped to a supported signing key type",
            field_name="signature_type",
        )

    adapter = {
        "signing_key_name": config.get("signing_key_name", "oca-key"),
        "signing_authority": config["signing_authority"],
        "signing_key_id": config.get("signing_key_id", ""),
        "signing_key_file": config.get("signing_key_file"),
        "signature_type": _OCA_TO_INTERNAL_SIG_TYPE[sig_type_oca],
        "manifest_identifier": _NON_BL1_MANIFEST_IDENTIFIER,
    }
    try:
        return _ms.prepare_signing_key(adapter, secure_boot=1)
    except FileNotFoundError as e:
        raise OcaConfigError(
            f"signing_key_file not found: {e}",
            field_name="signing_key_file",
        ) from e
    except KeyError as e:
        missing = str(e).strip("'\"")
        raise OcaConfigError(
            f"missing required signing field for oca-classic secure_boot=1: {missing}",
            field_name=missing,
        ) from e


# ---------------------------------------------------------------------------
# Public-key encoding
# ---------------------------------------------------------------------------


def encode_public_key(signing_key, encoding: int, signature_type: int) -> EncodedField:
    """Encode the public key into the `public_key_classic` field.

    Returns the full 532-byte field (right-padded with 0x00) together with the
    number of encoded bytes, which the caller writes to `public_key_size_classic`.
    The count is always exact for a public key: the key exists before the
    manifest is assembled, so nothing about its length is circular.

    `encoding` is 0x01 (ASN.1 DER, RSA only) or 0x02 (raw bytes, any algorithm).
    """
    pk = signing_key.public_key
    if pk is None:
        raise OcaConfigError(
            "signing key has no public key (signing_key_file may be missing or invalid)",
            field_name="signing_key_file",
        )

    if encoding == ENCODING_DER:
        if signature_type not in oca_consts.CLASSIC_DER_PUBLIC_KEY_TYPES:
            raise OcaConfigError(
                f"public_key_encoding 0x01 (DER) is not defined for signature_type "
                f"{signature_type:#04x}; ASN.1 DER public keys are limited to RSA "
                f"(PKCS#1 RSAPublicKey). Use 0x02 (raw bytes).",
                field_name="public_key_encoding",
            )
        # PKCS#1 RSAPublicKey — the bare SEQUENCE { modulus, publicExponent }.
        # NOT SubjectPublicKeyInfo, which wraps it in an AlgorithmIdentifier: the
        # spec's DER encoding is defined as the structure for the value itself,
        # and the sizes it quotes (398 bytes for RSA-3072 at e=65537) are PKCS#1.
        raw = pk.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.PKCS1,
        )
    elif encoding == ENCODING_RAW:
        raw = _public_key_raw(pk)
        expected = oca_consts.CLASSIC_RAW_PUBLIC_KEY_LENGTHS.get(signature_type)
        if expected is not None and len(raw) != expected:
            raise OcaConfigError(
                f"raw public key encoded to {len(raw)} bytes; the spec fixes the raw "
                f"length for signature_type {signature_type:#04x} at {expected}",
                field_name="public_key_encoding",
            )
    else:
        raise OcaConfigError(
            f"unsupported public_key_encoding: {encoding:#x}; "
            f"allowed: {oca_consts.OCA_SELECTABLE_ENCODINGS_TEXT}",
            field_name="public_key_encoding",
        )

    if len(raw) > oca_consts.PUBLIC_KEY_CLASSIC_SIZE:
        raise OcaConfigError(
            f"encoded public key is {len(raw)} bytes, exceeds OCA public_key_classic "
            f"field ({oca_consts.PUBLIC_KEY_CLASSIC_SIZE} bytes)",
            field_name="signature_type",
        )
    return EncodedField(raw.ljust(oca_consts.PUBLIC_KEY_CLASSIC_SIZE, b"\x00"), len(raw))


def _public_key_raw(pk) -> bytes:
    """Raw encoding of a public key per OCA `public_key_encoding_classic = 0x02`.

    "Raw" is the value as its own standard defines it, in that standard's byte
    order — big-endian in both cases below.

      * RSA-3072: 384-byte big-endian modulus || 4-byte big-endian public
        exponent (388 bytes). A raw RSA key has two components, so the spec
        gives it an explicit layout rather than leaving the exponent implicit.
      * ECDSA P-256: SEC1 uncompressed point, 0x04 || X || Y with each
        coordinate big-endian (65 bytes).
    """
    if isinstance(pk, rsa.RSAPublicKey):
        numbers = pk.public_numbers()
        return (numbers.n.to_bytes(_RSA_3072_MODULUS_BYTES, "big")
                + numbers.e.to_bytes(_RSA_PUBLIC_EXPONENT_BYTES, "big"))
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return pk.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
    raise OcaConfigError(
        f"raw encoding not supported for public key type {type(pk).__name__}",
        field_name="public_key_encoding",
    )


# ---------------------------------------------------------------------------
# Signature encoding
# ---------------------------------------------------------------------------


def declared_signature_size(signature_type: int, encoding: int) -> int:
    """Return the value to write into `signature_size_classic`.

    This has to be resolved BEFORE the signature exists. `signature_size_classic`
    sits at offset 2094, inside the signed region that ends at 3172, so it is one
    of the bytes the signature is computed over — a value chosen after signing
    could not be written back without invalidating the signature.

    That is trivially satisfiable for fixed-length encodings, where the length
    follows from the algorithm alone. For a DER ECDSA signature it is not: an
    RFC 3279 `ECDSA-Sig-Value` is 70-72 bytes for P-256 depending on the
    leading-zero and high-bit handling of r and s, and deterministic signing
    (RFC 6979) means re-signing yields the identical signature, so there is no
    sign-measure-re-sign loop that converges. The spec resolves this by making
    the field a MAXIMUM for that one case: it carries the algorithm's largest
    possible DER length, the DER length octets self-describe the actual size
    within it, and the gap is zero-filled.
    """
    if encoding == ENCODING_RAW:
        size = oca_consts.CLASSIC_RAW_SIGNATURE_LENGTHS.get(signature_type)
        if size is None:
            raise OcaConfigError(
                f"no raw signature length defined for signature_type {signature_type:#04x}",
                field_name="signature_type",
            )
        return size

    if encoding == ENCODING_DER:
        size = oca_consts.CLASSIC_DER_SIGNATURE_MAX_LENGTHS.get(signature_type)
        if size is None:
            raise OcaConfigError(
                f"signature_encoding 0x01 (DER) is not defined for signature_type "
                f"{signature_type:#04x}; ASN.1 DER signatures are limited to ECDSA "
                f"(RFC 3279 ECDSA-Sig-Value). Use 0x02 (raw bytes).",
                field_name="signature_encoding",
            )
        return size

    raise OcaConfigError(
        f"unsupported signature_encoding: {encoding:#x}; "
        f"allowed: {oca_consts.OCA_SELECTABLE_ENCODINGS_TEXT}",
        field_name="signature_encoding",
    )


def sign_signed_region(signed_region: bytes, signing_key, encoding: int,
                       declared_size: int) -> bytes:
    """Sign the OCA signed-region bytes and return the 512-byte
    `signature_classic` field, right-padded with 0x00.

    `declared_size` is the value already written into `signature_size_classic`
    by `build_signed_region`. It is checked against what signing actually
    produced, so a future algorithm or encoding change fails here rather than
    emitting a manifest whose size field misdescribes its own signature.

    Uses `SigningKey.generate_verified_signature()` so the sign+verify
    round-trip catches any defect at generation time.
    """
    signing_key.generate_verified_signature(signed_region)
    der_or_rsa = signing_key.signature  # RSA: big-endian integer; ECDSA: DER
    if der_or_rsa is None or len(der_or_rsa) == 0:
        raise OcaConfigError(
            "signing produced an empty signature",
            field_name="signing_authority",
        )

    if encoding == ENCODING_DER:
        # Only reachable for ECDSA — declared_signature_size() rejects DER for
        # every other type. The library already returns an ECDSA-Sig-Value.
        raw = der_or_rsa
        if len(raw) > declared_size:
            raise OcaConfigError(
                f"DER signature is {len(raw)} bytes, exceeds the declared maximum "
                f"signature_size_classic of {declared_size}",
                field_name="signature_encoding",
            )
    elif encoding == ENCODING_RAW:
        raw = _signature_raw(signing_key, der_or_rsa)
        if len(raw) != declared_size:
            raise OcaConfigError(
                f"raw signature is {len(raw)} bytes but signature_size_classic "
                f"declares {declared_size}",
                field_name="signature_encoding",
            )
    else:
        raise OcaConfigError(
            f"unsupported signature_encoding: {encoding:#x}; "
            f"allowed: {oca_consts.OCA_SELECTABLE_ENCODINGS_TEXT}",
            field_name="signature_encoding",
        )

    if len(raw) > oca_consts.SIGNATURE_CLASSIC_SIZE:
        raise OcaConfigError(
            f"signature is {len(raw)} bytes, exceeds OCA signature_classic field "
            f"({oca_consts.SIGNATURE_CLASSIC_SIZE} bytes)",
            field_name="signature_type",
        )
    return raw.ljust(oca_consts.SIGNATURE_CLASSIC_SIZE, b"\x00")


def _signature_raw(signing_key, der_or_rsa_bytes: bytes) -> bytes:
    """Raw encoding of a signature per OCA `signature_encoding_classic = 0x02`.

    As with public keys, "raw" is the algorithm's own byte order — big-endian.

      * RSA-3072: the 384-byte big-endian signature integer, used as produced.
      * ECDSA P-256: 32-byte r || 32-byte s, each big-endian (64 bytes total).
        The library outputs DER, so decode and re-emit.
    """
    pk = signing_key.public_key
    if isinstance(pk, rsa.RSAPublicKey):
        if len(der_or_rsa_bytes) != _RSA_3072_MODULUS_BYTES:
            raise OcaConfigError(
                f"unexpected RSA signature length {len(der_or_rsa_bytes)}; "
                f"expected {_RSA_3072_MODULUS_BYTES}",
                field_name="signature_type",
            )
        return der_or_rsa_bytes
    if isinstance(pk, ec.EllipticCurvePublicKey):
        r, s = _ec_utils.decode_dss_signature(der_or_rsa_bytes)
        return (r.to_bytes(_EC_P256_COORD_BYTES, "big")
                + s.to_bytes(_EC_P256_COORD_BYTES, "big"))
    raise OcaConfigError(
        f"raw encoding not supported for signature type {type(pk).__name__}",
        field_name="signature_encoding",
    )
