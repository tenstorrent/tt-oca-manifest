# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""ML-DSA-87 signing of OCA-PQC manifests: PQC-only and hybrid.

A PQC manifest may carry a classical signature, an ML-DSA-87 signature, or both,
selected by secure_boot_classic / secure_boot_pqc. Both cover the same signed
region, [0, 5903), and the ML-DSA-87 signature is pure FIPS 204 over those bytes
with the empty context. Every signature here is checked independently of the
packer, through the bool helpers in oca_fixtures.manifest_reader, and the same
helpers are what the negative cases fail.
"""

from __future__ import annotations

import hashlib
import struct

import pytest
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from oca_fixtures import ECC_P256_KEY_PATH, ML_DSA_87_KEY_PATH, RSA_3072_KEY_PATH
from oca_fixtures import manifest_reader
from tt_boot_manifest.key_hygiene import ALLOW_CONFIG_FIELD, ALLOW_ENV_VAR, KeyHygieneError
from tt_boot_manifest.oca import constants as oca_consts
from tt_boot_manifest.oca import signing as oca_signing
from tt_boot_manifest.oca.entry import pack_oca_bundle
from tt_boot_manifest.oca.manifest import build_signed_region, build_unsigned_tail
from tt_boot_manifest.oca.validators import (OcaConfigError, OcaLayoutError,
                                             validate_and_normalize_oca_classic)

ML_DSA_87 = oca_consts.OcaPqcSignatureType.ML_DSA_87.value
RSA_3072 = oca_consts.OcaClassicSignatureType.RSA_3072_PKCS1V15_SHA256.value
ECDSA_P256 = oca_consts.OcaClassicSignatureType.ECDSA_P256_SHA256.value

CLASSIC_SIGNING_FIELDS = (
    "signature_type", "signing_authority", "signing_key_file", "signing_key_id",
    "public_key_select_classic", "signature_encoding", "public_key_encoding",
)
PQC_SIGNING_FIELDS = (
    "signature_type_pqc", "signing_authority_pqc", "signing_key_file_pqc",
    "signing_key_id_pqc", "public_key_select_pqc", "signature_encoding_pqc",
    "public_key_encoding_pqc",
)


def _base_config(tmp_path, manifest_format="oca-pqc", **overrides):
    img = tmp_path / "img.bin"
    img.write_bytes(b"\xDE\xAD\xBE\xEF" * 4)
    cfg = {
        "manifest_format": manifest_format,
        "manifest_identifier": "PQCSIGN",
        "description": "ML-DSA-87 signing test bundle",
        "secure_boot": 1,
        "timestamp": 1764633600,
        "manifest_content_version": {"major": 1, "minor": 0, "patch": 0},
        "payload_images": [{"type": "PQCSIGNXBLSTAGE1", "path": str(img)}],
    }
    cfg.update(overrides)
    return cfg


def _pqc_fields(**overrides):
    fields = {
        "secure_boot_pqc": 1,
        "signature_type_pqc": ML_DSA_87,
        "signing_authority_pqc": "local",
        "signing_key_file_pqc": ML_DSA_87_KEY_PATH,
        "public_key_select_pqc": 0x01,
    }
    fields.update(overrides)
    return fields


def _classic_fields(key_path=RSA_3072_KEY_PATH, signature_type=RSA_3072):
    return {
        "signature_type": signature_type,
        "signing_authority": "local",
        "signing_key_file": key_path,
        "public_key_select_classic": 0x01,
    }


def _pqc_only_config(tmp_path, **overrides):
    cfg = _base_config(tmp_path, secure_boot_classic=0, **_pqc_fields())
    cfg.update(overrides)
    return cfg


def _hybrid_config(tmp_path, key_path=RSA_3072_KEY_PATH, signature_type=RSA_3072,
                   **overrides):
    cfg = _base_config(tmp_path, **_classic_fields(key_path, signature_type), **_pqc_fields())
    cfg.update(overrides)
    return cfg


def _classic_only_ocap_config(tmp_path, **overrides):
    cfg = _base_config(tmp_path, **_classic_fields())
    cfg.update(overrides)
    return cfg


def _body(bundle: bytes) -> bytes:
    return bundle[:oca_consts.OCA_PQC_BODY_SIZE]


def _u128(body: bytes, offset: int) -> int:
    return int.from_bytes(body[offset:offset + 16], "little")


def _ml_dsa_key_raw() -> bytes:
    with open(ML_DSA_87_KEY_PATH, "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    return key.public_key().public_bytes_raw()


def _config_error(cfg) -> OcaConfigError:
    with pytest.raises(OcaConfigError) as excinfo:
        pack_oca_bundle(cfg)
    return excinfo.value


# ---------------------------------------------------------------------------
# What a signed bundle carries
# ---------------------------------------------------------------------------


def test_pqc_only_bundle_carries_an_ml_dsa_87_signature(tmp_path):
    body = _body(pack_oca_bundle(_pqc_only_config(tmp_path)))

    assert body[oca_consts.OFF_SECURE_BOOT_CONTROL] == 0x05

    # The classical class is unused: its description and signature are zero.
    assert body[oca_consts.OFF_SIGNATURE_TYPE_CLASSIC:
                oca_consts.OFF_SIGNATURE_SIZE_CLASSIC + 2] == b"\x00" * 4
    assert _u128(body, oca_consts.OFF_PUBLIC_KEY_SELECT_CLASSIC) == 0
    assert not any(body[oca_consts.OFF_PUBLIC_KEY_CLASSIC:
                        oca_consts.OFF_PUBLIC_KEY_CLASSIC + oca_consts.PUBLIC_KEY_CLASSIC_SIZE])
    assert not any(body[oca_consts.OFF_PQC_SIGNATURE_CLASSIC:
                        oca_consts.OFF_PQC_SIGNATURE_CLASSIC + oca_consts.SIGNATURE_CLASSIC_SIZE])

    # The PQC description names the algorithm, raw encodings, and exact sizes.
    assert body[oca_consts.OFF_SIGNATURE_TYPE_PQC] == ML_DSA_87
    assert body[oca_consts.OFF_SIGNATURE_ENCODING_PQC] == 0x02
    assert body[oca_consts.OFF_PUBLIC_KEY_ENCODING_PQC] == 0x02
    assert struct.unpack_from("<H", body, oca_consts.OFF_SIGNATURE_SIZE_PQC)[0] == \
        oca_consts.ML_DSA_87_SIGNATURE_BYTES
    assert struct.unpack_from("<H", body, oca_consts.OFF_PUBLIC_KEY_SIZE_PQC)[0] == \
        oca_consts.ML_DSA_87_PUBLIC_KEY_BYTES
    assert _u128(body, oca_consts.OFF_PUBLIC_KEY_SELECT_PQC) == 0x01
    assert manifest_reader.pqc_public_key_bytes(body) == _ml_dsa_key_raw()

    assert manifest_reader.pqc_signature_valid(body)


@pytest.mark.parametrize("key_path,signature_type", [
    (RSA_3072_KEY_PATH, RSA_3072),
    (ECC_P256_KEY_PATH, ECDSA_P256),
])
def test_hybrid_bundle_carries_both_signatures(tmp_path, key_path, signature_type):
    body = _body(pack_oca_bundle(_hybrid_config(tmp_path, key_path, signature_type)))

    assert body[oca_consts.OFF_SECURE_BOOT_CONTROL] == 0x07
    assert body[oca_consts.OFF_SIGNATURE_TYPE_CLASSIC] == signature_type
    assert manifest_reader.classic_signature_valid(body)
    assert manifest_reader.pqc_signature_valid(body)


def test_classic_only_ocap_bundle_leaves_the_pqc_class_zero(tmp_path):
    body = _body(pack_oca_bundle(_classic_only_ocap_config(tmp_path)))

    assert body[oca_consts.OFF_SECURE_BOOT_CONTROL] == 0x03
    assert not any(body[oca_consts.OFF_SIGNATURE_TYPE_PQC:oca_consts.OFF_PUBLIC_KEY_PQC_REVOKE])
    assert not any(body[oca_consts.OFF_SIGNATURE_PQC:
                        oca_consts.OFF_SIGNATURE_PQC + oca_consts.LEN_SIGNATURE_PQC])
    assert manifest_reader.classic_signature_valid(body)


# ---------------------------------------------------------------------------
# The signatures bind exactly the signed region, exactly as specified
# ---------------------------------------------------------------------------


def test_a_tampered_signed_byte_breaks_both_signatures(tmp_path):
    body = bytearray(_body(pack_oca_bundle(_hybrid_config(tmp_path))))
    body[oca_consts.OFF_MANIFEST_IDENTIFIER] ^= 0x01

    assert not manifest_reader.classic_signature_valid(bytes(body))
    assert not manifest_reader.pqc_signature_valid(bytes(body))


def test_a_tampered_pqc_signature_breaks_only_the_pqc_signature(tmp_path):
    body = bytearray(_body(pack_oca_bundle(_hybrid_config(tmp_path))))
    body[oca_consts.OFF_SIGNATURE_PQC + 10] ^= 0x01

    assert manifest_reader.classic_signature_valid(bytes(body))
    assert not manifest_reader.pqc_signature_valid(bytes(body))


def test_the_pqc_signature_fails_any_other_key_message_or_construction(tmp_path):
    """Another key, the Classic-length region, and a SHA-512 pre-hash of the
    right region all fail, which pins the positive case to pure ML-DSA-87 over
    the full PQC signed region."""
    body = _body(pack_oca_bundle(_pqc_only_config(tmp_path)))
    region = manifest_reader.signed_region(body)
    other_key = mldsa.MLDSA87PrivateKey.generate().public_key().public_bytes_raw()

    assert manifest_reader.pqc_signature_valid(body, region=region)
    assert not manifest_reader.pqc_signature_valid(body, public_key_raw=other_key)
    assert not manifest_reader.pqc_signature_valid(
        body, region=region[:oca_consts.OCA_CLASSIC_SIGNED_REGION_END])
    assert not manifest_reader.pqc_signature_valid(
        body, region=hashlib.sha512(region).digest())


# ---------------------------------------------------------------------------
# Revocation bitmaps travel with any signed PQC manifest
# ---------------------------------------------------------------------------


def test_a_classic_only_ocap_manifest_can_carry_pqc_revocations(tmp_path):
    body = _body(pack_oca_bundle(_classic_only_ocap_config(
        tmp_path, public_key_pqc_revoke=0x06)))
    assert _u128(body, oca_consts.OFF_PUBLIC_KEY_PQC_REVOKE) == 0x06


def test_a_pqc_only_manifest_can_carry_classic_revocations(tmp_path):
    body = _body(pack_oca_bundle(_pqc_only_config(tmp_path, public_key_classic_revoke=0x06)))
    assert _u128(body, oca_consts.OFF_PUBLIC_KEY_CLASSIC_REVOKE) == 0x06


def test_a_non_secure_manifest_zeroes_the_pqc_revocations(tmp_path):
    body = _body(pack_oca_bundle(_base_config(tmp_path, secure_boot=0,
                                              public_key_pqc_revoke=0x06)))
    assert _u128(body, oca_consts.OFF_PUBLIC_KEY_PQC_REVOKE) == 0


def test_pqc_revocations_are_refused_on_a_classic_manifest(tmp_path):
    cfg = _base_config(tmp_path, manifest_format="oca-classic",
                       public_key_pqc_revoke=0x06, **_classic_fields())
    assert _config_error(cfg).field_name == "public_key_pqc_revoke"


# ---------------------------------------------------------------------------
# Signature classes
# ---------------------------------------------------------------------------


def test_secure_boot_needs_at_least_one_class(tmp_path):
    cfg = _base_config(tmp_path, secure_boot_classic=0)
    assert _config_error(cfg).field_name == "secure_boot"


def test_the_pqc_class_is_refused_on_a_classic_manifest(tmp_path):
    cfg = _base_config(tmp_path, manifest_format="oca-classic",
                       **_classic_fields(), **_pqc_fields())
    assert _config_error(cfg).field_name == "secure_boot_pqc"


@pytest.mark.parametrize("field", ["secure_boot_classic", "secure_boot_pqc"])
def test_a_class_needs_secure_boot(tmp_path, field):
    cfg = _base_config(tmp_path, secure_boot=0, **{field: 1})
    assert _config_error(cfg).field_name == field


@pytest.mark.parametrize("field,value", [
    ("secure_boot_classic", 2),
    ("secure_boot_pqc", 2),
])
def test_a_class_bit_is_zero_or_one(tmp_path, field, value):
    cfg = _hybrid_config(tmp_path, **{field: value})
    assert _config_error(cfg).field_name == field


@pytest.mark.parametrize("field", PQC_SIGNING_FIELDS)
def test_pqc_signing_fields_need_the_pqc_class(tmp_path, field):
    value = {"signing_authority_pqc": "local", "signing_key_file_pqc": ML_DSA_87_KEY_PATH,
             "signing_key_id_pqc": "key"}.get(field, 0x02 if "encoding" in field else 0x33)
    cfg = _classic_only_ocap_config(tmp_path, **{field: value})
    error = _config_error(cfg)
    assert error.field_name == field
    assert "secure_boot_pqc" in error.reason


@pytest.mark.parametrize("field", CLASSIC_SIGNING_FIELDS)
def test_classic_signing_fields_need_the_classic_class(tmp_path, field):
    value = {"signing_authority": "local", "signing_key_file": RSA_3072_KEY_PATH,
             "signing_key_id": "key"}.get(field, 0x02 if "encoding" in field else 0x01)
    cfg = _pqc_only_config(tmp_path, **{field: value})
    error = _config_error(cfg)
    assert error.field_name == field
    assert "secure_boot_classic" in error.reason


_SIGNING_FIELD_VALUES = {
    "signing_authority": "local", "signing_key_file": RSA_3072_KEY_PATH,
    "signing_key_id": "key", "signing_authority_pqc": "local",
    "signing_key_file_pqc": ML_DSA_87_KEY_PATH, "signing_key_id_pqc": "key",
    "signature_type_pqc": ML_DSA_87,
}


def _signing_field_value(field):
    """A plausible value for one signing field, so the field is present and set."""
    if field in _SIGNING_FIELD_VALUES:
        return _SIGNING_FIELD_VALUES[field]
    return 0x02 if "encoding" in field else 0x01


# Every signing field each format can name: a Classic manifest has no PQC class.
_SIGNING_FIELDS_BY_FORMAT = (
    [("oca-classic", field) for field in CLASSIC_SIGNING_FIELDS]
    + [("oca-pqc", field) for field in CLASSIC_SIGNING_FIELDS + PQC_SIGNING_FIELDS]
)


@pytest.mark.parametrize("manifest_format,field", _SIGNING_FIELDS_BY_FORMAT)
def test_signing_fields_need_secure_boot(tmp_path, manifest_format, field):
    """With secure boot off no class is enforced, so a signing field of either
    class describes a signature the manifest will not carry, and is refused by
    name rather than zeroed."""
    cfg = _base_config(tmp_path, manifest_format=manifest_format, secure_boot=0,
                       **{field: _signing_field_value(field)})
    error = _config_error(cfg)
    assert error.field_name == field
    assert "secure_boot: 1" in error.reason


@pytest.mark.parametrize("field", ["signature_type", "signing_authority"])
def test_the_classic_class_names_its_missing_fields(tmp_path, field):
    cfg = _classic_only_ocap_config(tmp_path)
    del cfg[field]
    assert _config_error(cfg).field_name == field


# ---------------------------------------------------------------------------
# The PQC signing description
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["signature_type_pqc", "signing_authority_pqc",
                                   "signing_key_file_pqc", "public_key_select_pqc"])
def test_the_pqc_class_names_its_missing_fields(tmp_path, field):
    cfg = _pqc_only_config(tmp_path)
    del cfg[field]
    assert _config_error(cfg).field_name == field


@pytest.mark.parametrize("value", [0x31, 0x32, 0x41, 0x51, 0x56, 0xF0])
def test_pqc_signature_types_other_than_ml_dsa_87_are_deferred(tmp_path, value):
    error = _config_error(_pqc_only_config(tmp_path, signature_type_pqc=value))
    assert error.field_name == "signature_type_pqc"
    assert error.deferred_feature == "Unsupported signature algorithm"


@pytest.mark.parametrize("authority,deferred", [
    ("aws", "AWS signing authority for ML-DSA"),
    ("hsm", "HSM signing authority"),
    ("bogus", None),
])
def test_the_pqc_key_signs_through_local_only(tmp_path, authority, deferred):
    error = _config_error(_pqc_only_config(tmp_path, signing_authority_pqc=authority))
    assert error.field_name == "signing_authority_pqc"
    assert error.deferred_feature == deferred


@pytest.mark.parametrize("field", ["signature_encoding_pqc", "public_key_encoding_pqc"])
@pytest.mark.parametrize("value,deferred", [
    (0x01, None),                                # DER: reserved for PQC
    (0x03, None),                                # reserved
    (0xEF, None),                                # reserved
    (0xF0, "integrator-defined encoding"),
    (0xFF, "integrator-defined encoding"),
])
def test_pqc_encodings_are_raw_only(tmp_path, field, value, deferred):
    error = _config_error(_pqc_only_config(tmp_path, **{field: value}))
    assert error.field_name == field
    assert error.deferred_feature == deferred


@pytest.mark.parametrize("value", [0, 1 << 128])
def test_public_key_select_pqc_is_a_non_zero_128_bit_mask(tmp_path, value):
    error = _config_error(_pqc_only_config(tmp_path, public_key_select_pqc=value))
    assert error.field_name == "public_key_select_pqc"


@pytest.mark.parametrize("value", [-1, 1 << 128])
def test_public_key_pqc_revoke_is_a_128_bit_mask(tmp_path, value):
    error = _config_error(_pqc_only_config(tmp_path, public_key_pqc_revoke=value))
    assert error.field_name == "public_key_pqc_revoke"


@pytest.mark.parametrize("field", ["public_key_pqc", "signature_pqc"])
def test_pqc_key_and_signature_are_outputs_not_inputs(tmp_path, field):
    error = _config_error(_pqc_only_config(tmp_path, **{field: "00" * 4}))
    assert error.field_name == field


def test_a_pqc_key_file_holding_another_algorithm_is_refused(tmp_path):
    error = _config_error(_pqc_only_config(tmp_path, signing_key_file_pqc=RSA_3072_KEY_PATH))
    assert error.field_name == "signing_key_file_pqc"
    assert "ML-DSA-87" in error.reason


def test_a_missing_pqc_key_file_is_named(tmp_path):
    missing = tmp_path / "absent.pem"
    error = _config_error(_pqc_only_config(tmp_path, signing_key_file_pqc=str(missing)))
    assert error.field_name == "signing_key_file_pqc"


def _raise_unsupported(*args, **kwargs):
    raise UnsupportedAlgorithm("not supported by this backend.")


def test_an_unloadable_pqc_key_is_reported_as_the_key_files_problem(tmp_path, monkeypatch):
    """With ML-DSA available, an UnsupportedAlgorithm from loading the key file
    means the file is the problem, and nothing points at OpenSSL."""
    import tt_boot_manifest.manifest_signing as manifest_signing_module

    monkeypatch.setattr(manifest_signing_module.serialization, "load_pem_private_key",
                        _raise_unsupported)
    error = _config_error(_pqc_only_config(tmp_path))
    assert error.field_name == "signing_key_file_pqc"
    assert "OpenSSL" not in error.reason


def test_a_build_without_ml_dsa_is_reported_as_such(tmp_path, monkeypatch):
    """Only when this cryptography build cannot do ML-DSA at all does the error
    name the OpenSSL requirement."""
    import tt_boot_manifest.manifest_signing as manifest_signing_module

    monkeypatch.setattr(manifest_signing_module.serialization, "load_pem_private_key",
                        _raise_unsupported)
    monkeypatch.setattr(mldsa.MLDSA87PrivateKey, "generate", _raise_unsupported)
    error = _config_error(_pqc_only_config(tmp_path))
    assert error.field_name == "signing_key_file_pqc"
    assert "OpenSSL 3.5" in error.reason


# ---------------------------------------------------------------------------
# The committed development key
# ---------------------------------------------------------------------------


def test_the_committed_ml_dsa_87_key_is_refused_without_opt_in(tmp_path, monkeypatch):
    monkeypatch.delenv(ALLOW_ENV_VAR, raising=False)
    with pytest.raises(KeyHygieneError, match="mldsa87_private_key.pem"):
        pack_oca_bundle(_pqc_only_config(tmp_path))


def test_the_committed_ml_dsa_87_key_signs_when_declared(tmp_path, monkeypatch):
    monkeypatch.delenv(ALLOW_ENV_VAR, raising=False)
    body = _body(pack_oca_bundle(_pqc_only_config(tmp_path, **{ALLOW_CONFIG_FIELD: True})))
    assert manifest_reader.pqc_signature_valid(body)


# ---------------------------------------------------------------------------
# Composition and reproducibility
# ---------------------------------------------------------------------------


def test_a_pqc_only_bundle_can_encrypt_its_payload(tmp_path):
    cfg = _pqc_only_config(
        tmp_path,
        encrypted_payload=1,
        encryption_type=oca_consts.OcaEncryptionType.AES_256_CBC.value,
        encryption_secret="00" * 32,
        encryption_iv="10" * 16,
        encryption_kdf_input="a5" * 64,
    )
    body = _body(pack_oca_bundle(cfg))
    assert body[oca_consts.OFF_PAYLOAD_ENCRYPTION_CONTROL] & 0x01
    assert manifest_reader.pqc_signature_valid(body)


@pytest.mark.parametrize("make_config", [_pqc_only_config, _hybrid_config])
def test_two_packs_differ_only_in_the_ml_dsa_signature(tmp_path, make_config):
    """ML-DSA signing is hedged, so the signature value is the one span that may
    differ between packs; masked, the bundles are identical, and both verify."""
    first = pack_oca_bundle(make_config(tmp_path))
    second = pack_oca_bundle(make_config(tmp_path))

    assert manifest_reader.mask_pqc_signature(first) == \
        manifest_reader.mask_pqc_signature(second)
    assert manifest_reader.pqc_signature_valid(_body(first))
    assert manifest_reader.pqc_signature_valid(_body(second))


# ---------------------------------------------------------------------------
# The PQC builders refuse what does not fit the layout
#
# Each guard sits behind an earlier check that keeps a real config from
# reaching it, so these drive the builders directly.
# ---------------------------------------------------------------------------


class _StubPqcKey:
    """A signing key that reports whatever public key and signature it is given."""

    def __init__(self, public_key_bytes=b"", signature_bytes=b""):
        self.public_key_bytes = public_key_bytes
        self.signature_bytes = signature_bytes

    def generate_verified_signature(self, data):
        return self.signature_bytes


@pytest.mark.parametrize("length,accepted", [
    (oca_consts.ML_DSA_87_PUBLIC_KEY_BYTES, True),
    (oca_consts.ML_DSA_87_PUBLIC_KEY_BYTES - 1, False),
    (oca_consts.ML_DSA_87_PUBLIC_KEY_BYTES + 1, False),
])
def test_the_pqc_public_key_must_have_its_algorithms_length(length, accepted):
    key = _StubPqcKey(public_key_bytes=b"\x01" * length)
    if accepted:
        encoded = oca_signing.encode_public_key_pqc(key, ML_DSA_87)
        assert encoded.size == length
        assert len(encoded.field) == oca_consts.LEN_PUBLIC_KEY_PQC
        return
    with pytest.raises(OcaConfigError) as excinfo:
        oca_signing.encode_public_key_pqc(key, ML_DSA_87)
    assert excinfo.value.field_name == "signing_key_file_pqc"


@pytest.mark.parametrize("length,accepted", [
    (oca_consts.ML_DSA_87_SIGNATURE_BYTES, True),
    (oca_consts.ML_DSA_87_SIGNATURE_BYTES - 1, False),
])
def test_the_pqc_signature_must_have_the_declared_size(length, accepted):
    key = _StubPqcKey(signature_bytes=b"\x01" * length)
    declared = oca_consts.ML_DSA_87_SIGNATURE_BYTES
    if accepted:
        field = oca_signing.sign_signed_region_pqc(b"region", key, declared)
        assert len(field) == oca_consts.LEN_SIGNATURE_PQC
        return
    with pytest.raises(OcaConfigError) as excinfo:
        oca_signing.sign_signed_region_pqc(b"region", key, declared)
    assert excinfo.value.field_name == "signature_type_pqc"


def test_an_unmapped_pqc_signature_type_is_named():
    with pytest.raises(OcaConfigError) as excinfo:
        oca_signing.build_pqc_signing_key({"signature_type_pqc": 0x32})
    assert excinfo.value.field_name == "signature_type_pqc"


def _pqc_signed_region(tmp_path, public_key_pqc_field):
    """The signed region of a PQC-only manifest, built with this key field."""
    normalized = validate_and_normalize_oca_classic(_pqc_only_config(tmp_path))
    hash_field = b"\x00" * oca_consts.HASH_FIELD_SIZE
    return build_signed_region(
        normalized, hash_field, hash_field, 0, 0,
        variant=oca_consts.PQC_VARIANT,
        public_key_pqc_field=public_key_pqc_field,
        public_key_size_pqc=oca_consts.ML_DSA_87_PUBLIC_KEY_BYTES,
        signature_size_pqc=oca_consts.ML_DSA_87_SIGNATURE_BYTES)


def test_the_signed_region_needs_the_pqc_public_key(tmp_path):
    region = _pqc_signed_region(tmp_path, b"\x00" * oca_consts.LEN_PUBLIC_KEY_PQC)
    assert len(region) == oca_consts.PQC_SIGNED_REGION_END
    with pytest.raises(ValueError):
        _pqc_signed_region(tmp_path, None)
    with pytest.raises(OcaLayoutError):
        _pqc_signed_region(tmp_path, b"\x00" * (oca_consts.LEN_PUBLIC_KEY_PQC - 1))


@pytest.mark.parametrize("length,accepted", [
    (oca_consts.LEN_SIGNATURE_PQC, True),
    (oca_consts.LEN_SIGNATURE_PQC - 1, False),
])
def test_the_unsigned_tail_needs_a_whole_signature_pqc_field(tmp_path, length, accepted):
    region = _pqc_signed_region(tmp_path, b"\x00" * oca_consts.LEN_PUBLIC_KEY_PQC)
    hash_field = b"\x00" * oca_consts.HASH_FIELD_SIZE
    args = (region, hash_field, oca_consts.OCA_PQC_BODY_SIZE)
    kwargs = {"variant": oca_consts.PQC_VARIANT, "signature_pqc_field": b"\x00" * length}
    if accepted:
        tail = build_unsigned_tail(*args, **kwargs)
        assert len(tail) == oca_consts.OCA_PQC_BODY_SIZE - oca_consts.PQC_SIGNED_REGION_END
        return
    with pytest.raises(OcaLayoutError):
        build_unsigned_tail(*args, **kwargs)
