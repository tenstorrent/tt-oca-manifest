# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Sign OCA manifests through the existing signing-authority abstraction.

For each algorithm + authority we:
  1. Generate a bundle with secure_boot=1 and a configured signing key.
  2. Recover the embedded public_key_classic, slicing it by
     public_key_size_classic and decoding it per public_key_encoding_classic.
  3. Independently verify signature_classic against the recovered public key +
     signed region using `cryptography.hazmat.primitives.asymmetric`.

Code-path independence: tests read on-disk bytes directly and call
`public_key.verify()` — the reader in oca_fixtures shares no code with the
tool's signing path.
"""

from __future__ import annotations

import struct

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from tt_boot_manifest.oca import constants as oca_consts
from tt_boot_manifest.oca.entry import pack_oca_bundle
from tt_boot_manifest.oca.validators import OcaConfigError
from oca_fixtures import (
    ECC_P256_KEY_PATH,
    RSA_3072_KEY_PATH,
    RSA_EXPONENT_KEYS,
)
from oca_fixtures.manifest_reader import (
    load_public_key,
    public_key_bytes,
    signature_bytes,
    verify_classic_signature,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_image(tmp_path):
    p = tmp_path / "img.bin"
    p.write_bytes(b"\xDE\xAD\xBE\xEF\x90\x90\x90\x90")
    return str(p)


def _secure_config(tmp_path, sig_type_oca, key_file):
    return {
        "manifest_format": "oca-classic",
        "manifest_identifier": "SIGNED1",
        "description": "secure-boot OCA-classic test",
        "secure_boot": 1,
        "timestamp": 1764633600,
        "signature_type": sig_type_oca,
        "signing_authority": "local",
        "signing_key_name": "test_dev_key_0",
        "signing_key_id": "unused-for-local",
        "signing_key_file": key_file,
        "public_key_select_classic": 0x1,    # group 1, key 0
        "payload_images": [{"type": "SIGNED1_BLSTAGE1", "path": _make_image(tmp_path)}],
    }


def _parse_bundle(bundle_bytes):
    """Return (manifest_body, signed_region, signature_bytes, sig_type_byte)."""
    manifest = bundle_bytes[: oca_consts.OCA_CLASSIC_BODY_SIZE]
    signed_region = manifest[: oca_consts.OCA_CLASSIC_SIGNED_REGION_END]
    sig_type = manifest[oca_consts.OFF_SIGNATURE_TYPE_CLASSIC]
    return manifest, signed_region, signature_bytes(manifest), sig_type


def test_rsa_3072_signature_verifies_independently(tmp_path):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    bundle = pack_oca_bundle(cfg)
    manifest, signed_region, signature, sig_type = _parse_bundle(bundle)
    assert sig_type == 0x01

    public_key = load_public_key(manifest)
    assert isinstance(public_key, rsa.RSAPublicKey)
    # RSA-3072 produces a 384-byte signature; the field is 512 with the rest NUL.
    assert len(signature) == 384
    public_key.verify(signature, signed_region, padding.PKCS1v15(), hashes.SHA256())


def test_ecc_p256_signature_verifies_independently(tmp_path):
    cfg = _secure_config(tmp_path, sig_type_oca=0x05, key_file=ECC_P256_KEY_PATH)
    bundle = pack_oca_bundle(cfg)
    manifest, signed_region, signature, sig_type = _parse_bundle(bundle)
    assert sig_type == 0x05

    public_key = load_public_key(manifest)
    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    # Raw ECDSA is a fixed 64 bytes: r || s, each 32 big-endian.
    assert len(signature) == 64
    verify_classic_signature(manifest, signed_region)


def test_signed_region_tamper_detection(tmp_path):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    bundle = pack_oca_bundle(cfg)
    manifest, signed_region, signature, _ = _parse_bundle(bundle)

    # Flip one bit deep in the signed region.
    tampered = bytearray(signed_region)
    tampered[1000] ^= 0xFF
    tampered = bytes(tampered)

    public_key = load_public_key(manifest)
    with pytest.raises(InvalidSignature):
        public_key.verify(signature, tampered, padding.PKCS1v15(), hashes.SHA256())


# Redundant with the manifest-body test that also covers this — the signing
# tests reassert it at the signing contract boundary.
def test_signature_field_all_zero_when_secure_boot_disabled(tmp_path):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    cfg["secure_boot"] = 0
    bundle = pack_oca_bundle(cfg)
    manifest = bundle[: oca_consts.OCA_CLASSIC_BODY_SIZE]
    sig = manifest[oca_consts.OFF_SIGNATURE_CLASSIC : oca_consts.OFF_SIGNATURE_CLASSIC + oca_consts.SIGNATURE_CLASSIC_SIZE]
    pk = manifest[oca_consts.OFF_PUBLIC_KEY_CLASSIC : oca_consts.OFF_PUBLIC_KEY_CLASSIC + oca_consts.PUBLIC_KEY_CLASSIC_SIZE]
    assert sig == b"\x00" * oca_consts.SIGNATURE_CLASSIC_SIZE
    assert pk == b"\x00" * oca_consts.PUBLIC_KEY_CLASSIC_SIZE
    assert manifest[oca_consts.OFF_SIGNATURE_TYPE_CLASSIC] == 0
    assert manifest[oca_consts.OFF_SIGNATURE_ENCODING_CLASSIC] == 0
    assert manifest[oca_consts.OFF_PUBLIC_KEY_ENCODING_CLASSIC] == 0
    assert manifest[oca_consts.OFF_PUBLIC_KEY_SELECT_CLASSIC : oca_consts.OFF_PUBLIC_KEY_SELECT_CLASSIC + 16] == b"\x00" * 16


def test_secure_boot_fields_populated_when_enabled(tmp_path):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    bundle = pack_oca_bundle(cfg)
    manifest = bundle[: oca_consts.OCA_CLASSIC_BODY_SIZE]
    assert manifest[oca_consts.OFF_SIGNATURE_TYPE_CLASSIC] == 0x01
    assert manifest[oca_consts.OFF_SIGNATURE_ENCODING_CLASSIC] == 0x02     # raw
    assert manifest[oca_consts.OFF_PUBLIC_KEY_ENCODING_CLASSIC] == 0x02    # raw
    # Both size fields describe what raw RSA-3072 actually produces.
    assert struct.unpack_from(
        "<H", manifest, oca_consts.OFF_SIGNATURE_SIZE_CLASSIC)[0] == 384
    assert struct.unpack_from(
        "<H", manifest, oca_consts.OFF_PUBLIC_KEY_SIZE_CLASSIC)[0] == 388
    pkscl = manifest[oca_consts.OFF_PUBLIC_KEY_SELECT_CLASSIC : oca_consts.OFF_PUBLIC_KEY_SELECT_CLASSIC + 16]
    assert pkscl != b"\x00" * 16, "public_key_select_classic must be non-zero when secure boot is enabled"
    pk = manifest[oca_consts.OFF_PUBLIC_KEY_CLASSIC : oca_consts.OFF_PUBLIC_KEY_CLASSIC + oca_consts.PUBLIC_KEY_CLASSIC_SIZE]
    assert pk != b"\x00" * oca_consts.PUBLIC_KEY_CLASSIC_SIZE
    sig = manifest[oca_consts.OFF_SIGNATURE_CLASSIC : oca_consts.OFF_SIGNATURE_CLASSIC + oca_consts.SIGNATURE_CLASSIC_SIZE]
    assert sig != b"\x00" * oca_consts.SIGNATURE_CLASSIC_SIZE
    # secure_boot_control: bit 0 (enforced) and bit 1 (classic) both set.
    assert manifest[oca_consts.OFF_SECURE_BOOT_CONTROL] & 0x03 == 0x03


# ---------------------------------------------------------------------------
# public_key_classic content, bounded by public_key_size_classic.
# ---------------------------------------------------------------------------


def test_public_key_classic_is_a_sec1_point_for_ecdsa(tmp_path):
    """A raw ECDSA key is a SEC1 uncompressed point, and the bytes past
    public_key_size_classic are zero."""
    cfg = _secure_config(tmp_path, sig_type_oca=0x05, key_file=ECC_P256_KEY_PATH)
    bundle = pack_oca_bundle(cfg)
    manifest = bundle[: oca_consts.OCA_CLASSIC_BODY_SIZE]

    encoded = public_key_bytes(manifest)     # asserts the zero tail itself
    assert len(encoded) == 65
    assert encoded[0] == 0x04, "SEC1 uncompressed point prefix"
    assert isinstance(load_public_key(manifest), ec.EllipticCurvePublicKey)


@pytest.mark.parametrize("label,key_file,der_len", RSA_EXPONENT_KEYS)
def test_public_key_classic_is_pkcs1_when_der_is_selected(
    tmp_path, label, key_file, der_len
):
    """DER is defined for RSA public keys only, and means PKCS#1 RSAPublicKey —
    not SubjectPublicKeyInfo, which wraps it in an AlgorithmIdentifier.

    Run against both public exponents because this is the one classic encoding
    whose length the algorithm does not fix: the DER INTEGER holding e is 3 bytes
    for F4 and 1 for e=3, so the same 3072-bit modulus yields 398 or 396 bytes.
    """
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=key_file)
    cfg["public_key_encoding"] = 0x01
    bundle = pack_oca_bundle(cfg)
    manifest = bundle[: oca_consts.OCA_CLASSIC_BODY_SIZE]

    encoded = public_key_bytes(manifest)
    assert len(encoded) == der_len
    assert struct.unpack_from(
        "<H", manifest, oca_consts.OFF_PUBLIC_KEY_SIZE_CLASSIC)[0] == len(encoded)

    recovered = load_public_key(manifest)
    assert isinstance(recovered, rsa.RSAPublicKey)
    assert recovered.public_numbers().e == (65537 if label == "f4" else 3)
    # Byte-for-byte the PKCS#1 form, and NOT the SubjectPublicKeyInfo form that
    # earlier revisions of this packer emitted.
    assert encoded == recovered.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.PKCS1)
    assert encoded != recovered.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def test_der_public_key_size_field_actually_differs_between_exponents(tmp_path):
    """The premise of the parametrization above, asserted directly.

    If both exponents ever produced the same DER length, the pair of cases would
    silently stop testing anything about variable-length key encodings.
    """
    sizes = {}
    for label, key_file, _der_len in RSA_EXPONENT_KEYS:
        cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=key_file)
        cfg["public_key_encoding"] = 0x01
        manifest = pack_oca_bundle(cfg)[: oca_consts.OCA_CLASSIC_BODY_SIZE]
        sizes[label] = struct.unpack_from(
            "<H", manifest, oca_consts.OFF_PUBLIC_KEY_SIZE_CLASSIC)[0]
    assert sizes["f4"] != sizes["e3"], (
        f"both exponents encoded to {sizes['f4']} bytes — the DER key length is "
        f"no longer exponent-dependent and these tests cover nothing"
    )


@pytest.mark.parametrize("label,key_file,_der_len", RSA_EXPONENT_KEYS)
def test_raw_public_key_carries_the_exponent_verbatim(
    tmp_path, label, key_file, _der_len
):
    """A raw RSA key is a big-endian modulus followed by a 4-byte big-endian
    exponent, so unlike DER its length is 388 for every exponent — but the
    trailing four bytes must actually differ."""
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=key_file)
    cfg["public_key_encoding"] = 0x02
    manifest = pack_oca_bundle(cfg)[: oca_consts.OCA_CLASSIC_BODY_SIZE]

    encoded = public_key_bytes(manifest)
    assert len(encoded) == 388
    exponent = encoded[oca_consts.RSA_3072_MODULUS_BYTES:]
    assert exponent == (b"\x00\x01\x00\x01" if label == "f4" else b"\x00\x00\x00\x03")
    assert int.from_bytes(exponent, "big") == (65537 if label == "f4" else 3)


@pytest.mark.parametrize("label,key_file,_der_len", RSA_EXPONENT_KEYS)
@pytest.mark.parametrize("key_encoding", [0x01, 0x02])
def test_signature_verifies_for_both_exponents(
    tmp_path, label, key_file, _der_len, key_encoding
):
    """The end-to-end producer check: sign with each exponent under each key
    encoding, then verify against the key recovered from the manifest."""
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=key_file)
    cfg["public_key_encoding"] = key_encoding
    manifest = pack_oca_bundle(cfg)[: oca_consts.OCA_CLASSIC_BODY_SIZE]
    signed_region = manifest[: oca_consts.OCA_CLASSIC_SIGNED_REGION_END]

    # Signature length is fixed by the modulus, not the exponent.
    assert struct.unpack_from(
        "<H", manifest, oca_consts.OFF_SIGNATURE_SIZE_CLASSIC)[0] == 384
    verify_classic_signature(manifest, signed_region)


def test_der_public_key_rejected_for_ecdsa(tmp_path):
    """ASN.1 DER has no defined structure for a bare EC public key."""
    cfg = _secure_config(tmp_path, sig_type_oca=0x05, key_file=ECC_P256_KEY_PATH)
    cfg["public_key_encoding"] = 0x01
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == "public_key_encoding"


def test_der_signature_rejected_for_rsa(tmp_path):
    """ASN.1 DER is not defined for an RSA signature — it is a bare integer."""
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    cfg["signature_encoding"] = 0x01
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == "signature_encoding"


def test_der_ecdsa_signature_size_field_carries_the_maximum(tmp_path):
    """The one place a size field is a maximum rather than an exact count.

    signature_size_classic lies inside the region its own signature covers, so
    it must be fixed before signing — and a DER ECDSA length is value-dependent.
    The field therefore carries the algorithm maximum, the DER length octets give
    the real length, and the gap between them is zero-filled.
    """
    cfg = _secure_config(tmp_path, sig_type_oca=0x05, key_file=ECC_P256_KEY_PATH)
    cfg["signature_encoding"] = 0x01
    bundle = pack_oca_bundle(cfg)
    manifest = bundle[: oca_consts.OCA_CLASSIC_BODY_SIZE]
    signed_region = manifest[: oca_consts.OCA_CLASSIC_SIGNED_REGION_END]

    declared = struct.unpack_from(
        "<H", manifest, oca_consts.OFF_SIGNATURE_SIZE_CLASSIC)[0]
    assert declared == 72, "P-256 maximum DER ECDSA-Sig-Value"

    actual = signature_bytes(manifest)       # asserts the zero gap itself
    assert 70 <= len(actual) <= 72
    verify_classic_signature(manifest, signed_region)


# ---------------------------------------------------------------------------
# Negative: secure_boot=1 without public_key_select_classic is rejected.
# ---------------------------------------------------------------------------


def test_missing_public_key_select_classic_rejected(tmp_path):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    del cfg["public_key_select_classic"]
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == "public_key_select_classic"


# ---------------------------------------------------------------------------
# Secure-boot device-state fields: manifest_security_control,
# manifest_security_version (128-bit flags), public_key_classic_revoke.
# ---------------------------------------------------------------------------


def test_security_device_state_fields_round_trip(tmp_path):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    cfg["manifest_security_control"] = 0x3F              # suppress all six auto-updates
    cfg["manifest_security_version"] = (1 << 0) | (1 << 2)   # posture flags bit0 + bit2
    cfg["public_key_classic_revoke"] = 1 << 5           # revoke key slot 5
    bundle = pack_oca_bundle(cfg)
    manifest = bundle[: oca_consts.OCA_CLASSIC_BODY_SIZE]

    assert struct.unpack_from(
        "<H", manifest, oca_consts.OFF_MANIFEST_SECURITY_CONTROL)[0] == 0x3F
    msv = manifest[oca_consts.OFF_MANIFEST_SECURITY_VERSION : oca_consts.OFF_MANIFEST_SECURITY_VERSION + 16]
    assert int.from_bytes(msv, "little") == (1 << 0) | (1 << 2)
    rev = manifest[oca_consts.OFF_PUBLIC_KEY_CLASSIC_REVOKE : oca_consts.OFF_PUBLIC_KEY_CLASSIC_REVOKE + 16]
    assert int.from_bytes(rev, "little") == 1 << 5


def test_manifest_security_control_out_of_range_rejected(tmp_path):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    cfg["manifest_security_control"] = 0x40   # only bits [5:0] are defined
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == "manifest_security_control"


def test_security_control_and_revoke_zeroed_when_secure_boot_disabled(tmp_path):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    cfg["secure_boot"] = 0
    cfg["manifest_security_control"] = 0x3F
    cfg["public_key_classic_revoke"] = 1 << 5
    bundle = pack_oca_bundle(cfg)
    manifest = bundle[: oca_consts.OCA_CLASSIC_BODY_SIZE]
    assert struct.unpack_from(
        "<H", manifest, oca_consts.OFF_MANIFEST_SECURITY_CONTROL)[0] == 0x00
    rev = manifest[oca_consts.OFF_PUBLIC_KEY_CLASSIC_REVOKE : oca_consts.OFF_PUBLIC_KEY_CLASSIC_REVOKE + 16]
    assert rev == b"\x00" * 16


def test_manifest_security_control_is_two_bytes(tmp_path):
    """The field is a u16, and the byte after it belongs to the next reserved
    region. A single-byte write here would shift the whole manifest by one and
    still produce a body that passes its own length check."""
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    cfg["manifest_security_control"] = 0x3F
    manifest = pack_oca_bundle(cfg)[: oca_consts.OCA_CLASSIC_BODY_SIZE]

    off = oca_consts.OFF_MANIFEST_SECURITY_CONTROL
    assert struct.unpack_from("<H", manifest, off)[0] == 0x3F
    assert manifest[off:off + 2] == b"\x3F\x00"
    assert oca_consts.OFF_RESERVED_4 == off + 2
    assert manifest[oca_consts.OFF_RESERVED_4] == 0x00


# ---------------------------------------------------------------------------
# signature_cohort_enforce / signature_class_revoke — the two device control
# registers OR'd into vendor storage after a fully verified boot.
# ---------------------------------------------------------------------------


def _u64(manifest, off):
    return struct.unpack_from("<Q", manifest, off)[0]


def test_signature_posture_registers_round_trip(tmp_path):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    # ROOT nibble demands a classical signature; co-signer 1 demands both.
    cfg["signature_cohort_enforce"] = 0x01 | (0x3 << 8)
    # Revoke RSA-3072 (b0) and ML-DSA-44 (b24), no group codes.
    cfg["signature_class_revoke"] = (1 << 0) | (1 << 24)
    manifest = pack_oca_bundle(cfg)[: oca_consts.OCA_CLASSIC_BODY_SIZE]

    assert _u64(manifest, oca_consts.OFF_SIGNATURE_COHORT_ENFORCE) == 0x01 | (0x3 << 8)
    assert _u64(manifest, oca_consts.OFF_SIGNATURE_CLASS_REVOKE) == (1 << 0) | (1 << 24)


def test_signature_posture_registers_zeroed_when_secure_boot_disabled(tmp_path):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    cfg["secure_boot"] = 0
    cfg["signature_cohort_enforce"] = 0x01
    cfg["signature_class_revoke"] = 1 << 0
    manifest = pack_oca_bundle(cfg)[: oca_consts.OCA_CLASSIC_BODY_SIZE]

    assert _u64(manifest, oca_consts.OFF_SIGNATURE_COHORT_ENFORCE) == 0
    assert _u64(manifest, oca_consts.OFF_SIGNATURE_CLASS_REVOKE) == 0


@pytest.mark.parametrize("value", [
    0x00,                                   # neither group disabled
    0xCA << 8,                              # classical group disabled
    0xAC << 32,                             # PQC group disabled
    (0xCA << 8) | (0xAC << 32),             # both — legal, and bricks the device
    (1 << 0) | (0xCA << 8),                 # per-class bit alongside its group code
])
def test_signature_class_revoke_accepts_intact_group_codes(tmp_path, value):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    cfg["signature_class_revoke"] = value
    manifest = pack_oca_bundle(cfg)[: oca_consts.OCA_CLASSIC_BODY_SIZE]
    assert _u64(manifest, oca_consts.OFF_SIGNATURE_CLASS_REVOKE) == value


@pytest.mark.parametrize("value,group", [
    (0x01 << 8,  "classical"),      # a fragment of 0xCA
    (0xC0 << 8,  "classical"),      # most of 0xCA, but not 0xCA
    (0xFF << 8,  "classical"),
    (0xAC << 8,  "classical"),      # the PQC code in the classical byte
    (0x01 << 32, "PQC"),
    (0xA0 << 32, "PQC"),
    (0xCA << 32, "PQC"),            # the classical code in the PQC byte
])
def test_signature_class_revoke_rejects_partial_group_codes(tmp_path, value, group):
    """A group code is a constant, not a bitmask. Fragments are rejected because
    the device-side register accumulates by OR: fragments from separate
    manifests would otherwise add up to an intact code that no single manifest
    ever declared."""
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    cfg["signature_class_revoke"] = value
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == "signature_class_revoke"
    assert group in str(exc.value)


@pytest.mark.parametrize("value", [
    1 << 2,     # bit[3:2] of the ROOT entity nibble is reserved
    1 << 3,
    1 << 40,    # only b[39:0] carry entity nibbles
    1 << 63,
])
def test_signature_cohort_enforce_rejects_reserved_bits(tmp_path, value):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    cfg["signature_cohort_enforce"] = value
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == "signature_cohort_enforce"


@pytest.mark.parametrize("value", [1 << 16, 1 << 23, 1 << 40, 1 << 63])
def test_signature_class_revoke_rejects_reserved_bits(tmp_path, value):
    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=RSA_3072_KEY_PATH)
    cfg["signature_class_revoke"] = value
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == "signature_class_revoke"


# ---------------------------------------------------------------------------
# Raw encoding: the algorithm's own byte order, which is big-endian.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sig_type_oca,key_file",
    [(0x01, RSA_3072_KEY_PATH), (0x05, ECC_P256_KEY_PATH)],
)
def test_raw_public_key_encoding_round_trip(tmp_path, sig_type_oca, key_file):
    """A raw public key is the value as its own standard defines it: for RSA a
    big-endian modulus followed by a 4-byte big-endian exponent, for ECDSA a SEC1
    uncompressed point. Rebuilding that form from the signing PEM must reproduce
    the on-disk bytes exactly."""
    cfg = _secure_config(tmp_path, sig_type_oca, key_file=key_file)
    cfg["public_key_encoding"] = 0x02
    bundle = pack_oca_bundle(cfg)
    manifest = bundle[: oca_consts.OCA_CLASSIC_BODY_SIZE]
    assert manifest[oca_consts.OFF_PUBLIC_KEY_ENCODING_CLASSIC] == 0x02

    with open(key_file, "rb") as fh:
        priv = serialization.load_pem_private_key(fh.read(), password=None)
    pub = priv.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        numbers = pub.public_numbers()
        expected = (numbers.n.to_bytes(384, "big") + numbers.e.to_bytes(4, "big"))
    else:
        expected = pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint,
        )

    # public_key_bytes() slices by the size field and asserts the zero tail.
    assert public_key_bytes(manifest) == expected
    assert struct.unpack_from(
        "<H", manifest, oca_consts.OFF_PUBLIC_KEY_SIZE_CLASSIC)[0] == len(expected)


@pytest.mark.parametrize(
    "sig_type_oca,key_file,expected_len",
    [(0x01, RSA_3072_KEY_PATH, 384), (0x05, ECC_P256_KEY_PATH, 64)],
)
def test_raw_signature_encoding_verifies(tmp_path, sig_type_oca, key_file, expected_len):
    """A raw signature is big-endian too: the RSA signature integer as produced,
    or ECDSA r || s. Both are fixed-length, so signature_size_classic is exact."""
    cfg = _secure_config(tmp_path, sig_type_oca, key_file=key_file)
    cfg["signature_encoding"] = 0x02
    bundle = pack_oca_bundle(cfg)
    manifest = bundle[: oca_consts.OCA_CLASSIC_BODY_SIZE]
    signed_region = manifest[: oca_consts.OCA_CLASSIC_SIGNED_REGION_END]

    assert manifest[oca_consts.OFF_SIGNATURE_ENCODING_CLASSIC] == 0x02
    assert struct.unpack_from(
        "<H", manifest, oca_consts.OFF_SIGNATURE_SIZE_CLASSIC)[0] == expected_len
    assert len(signature_bytes(manifest)) == expected_len
    verify_classic_signature(manifest, signed_region)


# ---------------------------------------------------------------------------
# AWS KMS signing (aws-marked; opts out without credentials).
# ---------------------------------------------------------------------------


@pytest.mark.aws
def test_aws_kms_signed_bundle_verifies(tmp_path):
    """Generate an OCA bundle with signing_authority='aws' and verify with the
    embedded public key. Requires AWS credentials and a configured KMS key id
    via the AWS_KMS_TEST_KEY_ID environment variable."""
    import os

    key_id = os.environ.get("AWS_KMS_TEST_KEY_ID")
    if not key_id:
        pytest.skip("AWS_KMS_TEST_KEY_ID not set; skipping AWS KMS test")

    cfg = _secure_config(tmp_path, sig_type_oca=0x01, key_file=None)
    cfg["signing_authority"] = "aws"
    cfg["signing_key_id"] = key_id
    cfg["signing_key_file"] = None
    bundle = pack_oca_bundle(cfg)
    signed_region, sig_field, pk_der, _ = _parse_bundle(bundle)
    public_key = serialization.load_der_public_key(pk_der)
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(sig_field[:384], signed_region, padding.PKCS1v15(), hashes.SHA256())
    else:
        sig = sig_field.rstrip(b"\x00")
        public_key.verify(sig, signed_region, ec.ECDSA(hashes.SHA256()))
