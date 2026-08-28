"""Read the crypto fields back out of a packed OCA-classic manifest.

Shared by the tests that independently verify a manifest's signature without
going through the C validator. Everything here slices by the manifest's
`*_size_classic` fields rather than stripping trailing 0x00, which is the whole
reason those fields exist: the key and signature fields are sized for the
largest supported value, and a DER INTEGER or a raw coordinate may legitimately
end in a zero byte.
"""

from __future__ import annotations

import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from tt_boot_manifest.oca import constants as oca_consts

DER_ENCODING = oca_consts.OcaClassicPublicKeyEncoding.ASN1_DER.value
RAW_ENCODING = oca_consts.OcaClassicPublicKeyEncoding.RAW_BYTES.value

RSA_3072 = oca_consts.OcaClassicSignatureType.RSA_3072_PKCS1V15_SHA256.value
ECDSA_P256 = oca_consts.OcaClassicSignatureType.ECDSA_P256_SHA256.value

_RSA_SPKI_ALGORITHM_ID = bytes.fromhex("300d06092a864886f70d0101010500")


def der_tlv(tag: int, value: bytes) -> bytes:
    """Emit a DER tag-length-value triple wrapping `value`."""
    length = len(value)
    if length < 0x80:
        header = bytes([tag, length])
    else:
        encoded_len = length.to_bytes((length.bit_length() + 7) // 8, "big")
        header = bytes([tag, 0x80 | len(encoded_len)]) + encoded_len
    return header + value


def spki_wrap(pkcs1_der: bytes) -> bytes:
    """Wrap a PKCS#1 RSAPublicKey in a SubjectPublicKeyInfo.

    The manifest carries the bare PKCS#1 structure, but `cryptography` only
    loads SPKI, so the AlgorithmIdentifier has to be put back to parse it.
    """
    bitstring = der_tlv(0x03, b"\x00" + pkcs1_der)
    return der_tlv(0x30, _RSA_SPKI_ALGORITHM_ID + bitstring)


def public_key_bytes(body: bytes) -> bytes:
    """Return the encoded public key, sliced to public_key_size_classic."""
    size = struct.unpack_from("<H", body, oca_consts.OFF_PUBLIC_KEY_SIZE_CLASSIC)[0]
    field = body[oca_consts.OFF_PUBLIC_KEY_CLASSIC:
                 oca_consts.OFF_PUBLIC_KEY_CLASSIC + oca_consts.PUBLIC_KEY_CLASSIC_SIZE]
    assert field[size:] == b"\x00" * (len(field) - size), \
        "bytes beyond public_key_size_classic must be 0x00"
    return field[:size]


def load_public_key(body: bytes):
    """Recover the embedded public key as a `cryptography` key object."""
    encoded = public_key_bytes(body)
    sig_type = body[oca_consts.OFF_SIGNATURE_TYPE_CLASSIC]
    encoding = body[oca_consts.OFF_PUBLIC_KEY_ENCODING_CLASSIC]

    if encoding == DER_ENCODING:
        return serialization.load_der_public_key(spki_wrap(encoded))
    if sig_type == RSA_3072:
        # Raw RSA: big-endian modulus followed by a 4-byte big-endian exponent.
        modulus = int.from_bytes(encoded[:oca_consts.RSA_3072_MODULUS_BYTES], "big")
        exponent = int.from_bytes(encoded[oca_consts.RSA_3072_MODULUS_BYTES:], "big")
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()
    if sig_type == ECDSA_P256:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), encoded)
    raise AssertionError(f"unexpected classic signature_type {sig_type:#x}")


def signature_bytes(body: bytes) -> bytes:
    """Return the signature as produced, resolved within its fixed-width field.

    For every encoding but one this is an exact slice at signature_size_classic.
    A DER ECDSA signature is the exception: its size field carries the
    algorithm's MAXIMUM DER length, so the real length comes from the DER length
    octets and the gap up to the declared size is zero-filled.
    """
    declared = struct.unpack_from("<H", body, oca_consts.OFF_SIGNATURE_SIZE_CLASSIC)[0]
    field = body[oca_consts.OFF_SIGNATURE_CLASSIC:
                 oca_consts.OFF_SIGNATURE_CLASSIC + oca_consts.SIGNATURE_CLASSIC_SIZE]
    sig_type = body[oca_consts.OFF_SIGNATURE_TYPE_CLASSIC]
    encoding = body[oca_consts.OFF_SIGNATURE_ENCODING_CLASSIC]

    if encoding == DER_ENCODING:
        assert declared == oca_consts.CLASSIC_DER_SIGNATURE_MAX_LENGTHS[sig_type], \
            "a DER ECDSA size field carries the algorithm maximum"
        actual = 2 + field[1]           # SEQUENCE tag + short-form length octet
        assert actual <= declared
        assert field[actual:declared] == b"\x00" * (declared - actual), \
            "gap between the DER encoding and signature_size_classic must be 0x00"
        return field[:actual]

    assert declared == oca_consts.CLASSIC_RAW_SIGNATURE_LENGTHS[sig_type], \
        "a raw size field carries the algorithm's exact length"
    assert field[declared:] == b"\x00" * (len(field) - declared), \
        "bytes beyond signature_size_classic must be 0x00"
    return field[:declared]


def verify_classic_signature(body: bytes, signed_region: bytes) -> None:
    """Verify the embedded signature over `signed_region`. Raises on failure."""
    sig_type = body[oca_consts.OFF_SIGNATURE_TYPE_CLASSIC]
    encoding = body[oca_consts.OFF_SIGNATURE_ENCODING_CLASSIC]
    public_key = load_public_key(body)
    raw = signature_bytes(body)

    if sig_type == RSA_3072:
        public_key.verify(raw, signed_region, padding.PKCS1v15(), hashes.SHA256())
        return
    if sig_type != ECDSA_P256:
        raise AssertionError(f"unexpected classic signature_type {sig_type:#x}")

    if encoding == RAW_ENCODING:
        # r || s big-endian; `cryptography` wants DER.
        half = len(raw) // 2
        raw = encode_dss_signature(int.from_bytes(raw[:half], "big"),
                                   int.from_bytes(raw[half:], "big"))
    public_key.verify(raw, signed_region, ec.ECDSA(hashes.SHA256()))
