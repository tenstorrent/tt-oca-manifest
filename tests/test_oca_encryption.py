"""Tests for OCA payload encryption (AES-128-CBC and AES-256-CBC).

The whole payload (TOC + images) is AES-CBC encrypted under a key derived from a
pre-shared secret via NIST SP 800-108r1 Counter Mode (HMAC-SHA-256) over the
192-byte expanded input block (see test_oca_kdf_kat.py for the KDF known-answer
vectors). BOTH ciphers are supported: encryption_type 0x01 (AES-128-CBC, 16-byte
key) and 0x02 (AES-256-CBC, 32-byte key); they share the derivation and differ
only in key length. `payload_hash` covers the ciphertext; `payload_hash_chain`
covers the plaintext. Encryption applies identically to both manifest variants.
"""

from __future__ import annotations

import hashlib
import json
import os

import pytest

from tt_boot_manifest.oca import constants as oca_consts
from tt_boot_manifest.oca import encryption as enc
from tt_boot_manifest.oca.entry import pack_oca_bundle
from tt_boot_manifest.oca.validators import OcaConfigError

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RSA_KEY = os.path.join(PROJECT_ROOT, "tests", "signing_keys", "rsa_private_key.dev0.pem")

_SECRET_HEX = "00" * 32
_IV_HEX = "10" * 16
_KDF_INPUT_HEX = "a5" * 64                 # full 64-byte KDF context

# Both supported ciphers, exercised across both manifest variants.
_CIPHERS = [oca_consts.OcaEncryptionType.AES_128_CBC.value,
            oca_consts.OcaEncryptionType.AES_256_CBC.value]
_KEY_BYTES = {0x01: 16, 0x02: 32}

_BODY_SIZE = {"oca-classic": oca_consts.OCA_CLASSIC_BODY_SIZE, "oca-pqc": oca_consts.OCA_PQC_BODY_SIZE}

# Encryption keys stripped to produce the equivalent cleartext bundle.
_ENC_KEYS = (
    "encrypted_payload", "encryption_type", "encryption_key_derivation_function",
    "encryption_secret", "encryption_secret_file", "encryption_iv",
    "encryption_kdf_input", "encryption_authority", "encryption_shared_secret_select",
)


def _enc_config(tmp_path, manifest_format="oca-classic", encryption_type=0x01, **overrides):
    img = tmp_path / "img.bin"
    img.write_bytes(bytes(range(256)) * 2)  # 512 fixed bytes
    cfg = {
        "manifest_format": manifest_format,
        "manifest_identifier": "ENCT",
        "description": "encryption test bundle",
        "secure_boot": 1,
        "signature_type": 0x01,
        "signing_authority": "local",
        "signing_key_file": RSA_KEY,
        "public_key_select_classic": 0x01,
        "encrypted_payload": 1,
        "encryption_type": encryption_type,
        "encryption_key_derivation_function": 0x0001,
        "encryption_secret": _SECRET_HEX,
        "encryption_iv": _IV_HEX,
        "encryption_kdf_input": _KDF_INPUT_HEX,
        "timestamp": 1764633600,
        "manifest_content_version": {"major": 1, "minor": 0, "patch": 0},
        "payload_images": [{"type": "ENCTXXXXBLSTAGE1", "path": str(img)}],
    }
    cfg.update(overrides)
    return cfg


def _cleartext_payload_and_body(cfg, body_size):
    """Pack a non-encrypted twin of `cfg` and return (body, cleartext payload)."""
    clear = {k: v for k, v in cfg.items() if k not in _ENC_KEYS}
    bundle = pack_oca_bundle(clear)
    return bundle[:body_size], bundle[body_size:]


# ---------------------------------------------------------------------------
# Producer structure, round-trip, determinism/side-car — both ciphers, both
# manifest variants.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fmt", ["oca-classic", "oca-pqc"])
@pytest.mark.parametrize("etype", _CIPHERS)
def test_encrypted_structure(tmp_path, fmt, etype):
    body_size = _BODY_SIZE[fmt]
    body = pack_oca_bundle(_enc_config(tmp_path, manifest_format=fmt, encryption_type=etype))[:body_size]

    control = int.from_bytes(body[oca_consts.OFF_PAYLOAD_ENCRYPTION_CONTROL:
                                  oca_consts.OFF_PAYLOAD_ENCRYPTION_CONTROL + 2], "little")
    assert control & oca_consts.ENCRYPTION_CONTROL_ENCRYPTED_PAYLOAD_BIT
    assert (control >> oca_consts.ENCRYPTION_INPUT_KEY_SOURCE_SHIFT) & 0b111 \
        == oca_consts.ENCRYPTION_INPUT_KEY_SOURCE_PRESHARED
    assert body[oca_consts.OFF_ENCRYPTION_TYPE] == etype
    assert int.from_bytes(body[oca_consts.OFF_ENCRYPTION_KDF:
                               oca_consts.OFF_ENCRYPTION_KDF + 2], "little") == 0x0001

    iv_off = oca_consts.OFF_ENCRYPTION_IV
    assert body[iv_off:iv_off + oca_consts.ENCRYPTION_IV_SIZE] == bytes.fromhex(_IV_HEX)
    assert body[iv_off + oca_consts.ENCRYPTION_IV_SIZE:
                iv_off + oca_consts.ENCRYPTION_IV_FIELD_SIZE] == b"\x00" * 16
    # The full 64-byte field is the KDF context.
    kdf_off = oca_consts.OFF_ENCRYPTION_KDF_INPUT
    assert body[kdf_off:kdf_off + oca_consts.ENCRYPTION_KDF_INPUT_SIZE] == bytes.fromhex(_KDF_INPUT_HEX)


@pytest.mark.parametrize("fmt", ["oca-classic", "oca-pqc"])
@pytest.mark.parametrize("etype", _CIPHERS)
def test_encrypted_roundtrip_and_hashes(tmp_path, fmt, etype):
    body_size = _BODY_SIZE[fmt]
    cfg = _enc_config(tmp_path, manifest_format=fmt, encryption_type=etype)
    bundle = pack_oca_bundle(cfg)
    body, payload = bundle[:body_size], bundle[body_size:]
    clear_body, clear_payload = _cleartext_payload_and_body(cfg, body_size)

    # Confidentiality: stored payload is not the cleartext.
    assert payload != clear_payload

    # Round-trip: derive key + decrypt recovers the exact cleartext payload.
    key = enc.derive_payload_key(bytes.fromhex(_SECRET_HEX), bytes.fromhex(_KDF_INPUT_HEX), etype)
    assert len(key) == _KEY_BYTES[etype]
    assert enc._aes_cbc_decrypt(key, bytes.fromhex(_IV_HEX), payload) == clear_payload

    # payload_hash covers the ciphertext; hashed_length == payload_length == len(ciphertext).
    ph = body[oca_consts.OFF_PAYLOAD_HASH:oca_consts.OFF_PAYLOAD_HASH + oca_consts.MANIFEST_HASH_DIGEST_SIZE]
    assert ph == hashlib.sha256(payload).digest()
    hashed_len = int.from_bytes(body[oca_consts.OFF_PAYLOAD_HASHED_LENGTH:
                                     oca_consts.OFF_PAYLOAD_HASHED_LENGTH + 8], "little")
    payload_length = int.from_bytes(body[oca_consts.OFF_PAYLOAD_LENGTH:
                                        oca_consts.OFF_PAYLOAD_LENGTH + 8], "little")
    assert hashed_len == len(payload) == payload_length

    # payload_hash_chain covers the plaintext — identical to the cleartext twin's chain.
    chain_lo = oca_consts.OFF_PAYLOAD_HASH_CHAIN
    chain_hi = chain_lo + oca_consts.HASH_FIELD_SIZE
    assert body[chain_lo:chain_hi] == clear_body[chain_lo:chain_hi]


def test_aes128_and_aes256_produce_different_ciphertext(tmp_path):
    """AES-128 and AES-256 with identical inputs yield different derived keys and
    thus different ciphertext — confirming AES-128 still works and is distinct."""
    b128 = pack_oca_bundle(_enc_config(tmp_path, encryption_type=0x01))
    b256 = pack_oca_bundle(_enc_config(tmp_path, encryption_type=0x02))
    body = _BODY_SIZE["oca-classic"]
    assert b128[body:] != b256[body:]


def test_encrypted_determinism_when_supplied(tmp_path):
    for etype in _CIPHERS:
        cfg = _enc_config(tmp_path, encryption_type=etype)
        assert pack_oca_bundle(dict(cfg)) == pack_oca_bundle(dict(cfg))


def test_encrypted_generates_and_records_sidecar(tmp_path):
    cfg = _enc_config(tmp_path, encryption_type=0x02)
    cfg.pop("encryption_iv")
    cfg.pop("encryption_kdf_input")
    out = tmp_path / "enc.bin"
    pack_oca_bundle(cfg, output_path=str(out))

    sidecars = list(tmp_path.glob("encrypt_inputs_*.json"))
    assert len(sidecars) == 1, f"expected one side-car, got {sidecars}"
    data = json.loads(sidecars[0].read_text())
    assert "encryption_iv" in data and "encryption_kdf_input" in data
    # Generated KDF input is the full 64-byte context.
    assert len(bytes.fromhex(data["encryption_kdf_input"])) == oca_consts.ENCRYPTION_KDF_INPUT_SIZE
    # The pre-shared secret is NEVER recorded.
    assert _SECRET_HEX not in json.dumps(data)

    # Feeding the recorded inputs back reproduces the exact bundle.
    cfg2 = _enc_config(tmp_path, encryption_type=0x02, encryption_iv=data["encryption_iv"],
                       encryption_kdf_input=data["encryption_kdf_input"])
    out2 = tmp_path / "enc2.bin"
    pack_oca_bundle(cfg2, output_path=str(out2))
    assert out.read_bytes() == out2.read_bytes()


# ---------------------------------------------------------------------------
# Rejection of unsupported / mis-configured encryption (fast, no output).
# ---------------------------------------------------------------------------


def _pack_expect_error(cfg, tmp_path) -> OcaConfigError:
    out = tmp_path / "should_not_exist.bin"
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg, output_path=str(out))
    assert not out.exists(), "no output must be written on rejection"
    return exc.value


def test_reject_encryption_without_secure_boot(tmp_path):
    cfg = _enc_config(tmp_path)
    cfg["secure_boot"] = 0
    assert _pack_expect_error(cfg, tmp_path).field_name == "encrypted_payload"


def test_reject_unsupported_cipher(tmp_path):
    cfg = _enc_config(tmp_path)
    cfg["encryption_type"] = 0x03  # AES-128-CBC-HMAC-SHA256 (composite, not implemented)
    assert _pack_expect_error(cfg, tmp_path).deferred_feature == "Unsupported encryption algorithm"


def test_reject_unsupported_kdf(tmp_path):
    cfg = _enc_config(tmp_path)
    cfg["encryption_key_derivation_function"] = 0x0005  # CMAC-AES-128
    assert _pack_expect_error(cfg, tmp_path).deferred_feature == "Unsupported key-derivation function"


def test_reject_kem_wrapping(tmp_path):
    cfg = _enc_config(tmp_path)
    cfg["encryption_kem_dek"] = "aa" * 16
    assert _pack_expect_error(cfg, tmp_path).deferred_feature == "KEM key wrapping"


@pytest.mark.parametrize("authority", ["aws", "hsm"])
def test_reject_remote_encryption_authority(tmp_path, authority):
    cfg = _enc_config(tmp_path)
    cfg["encryption_authority"] = authority
    err = _pack_expect_error(cfg, tmp_path)
    assert err.deferred_feature == f"{authority.upper()} encryption authority"


def test_reject_bad_secret_size(tmp_path):
    cfg = _enc_config(tmp_path)
    cfg["encryption_secret"] = "00" * 16  # 16 bytes; need 32
    assert _pack_expect_error(cfg, tmp_path).field_name == "encryption_secret"


def test_reject_bad_iv_size(tmp_path):
    cfg = _enc_config(tmp_path)
    cfg["encryption_iv"] = "10" * 8  # 8 bytes; need 16
    assert _pack_expect_error(cfg, tmp_path).field_name == "encryption_iv"


def test_reject_bad_kdf_input_size(tmp_path):
    """A KDF input that is not exactly the 64-byte context is rejected, never
    truncated (truncation would alias distinct inputs to one key)."""
    cfg = _enc_config(tmp_path)
    cfg["encryption_kdf_input"] = "a5" * 32  # 32 bytes; need 64
    assert _pack_expect_error(cfg, tmp_path).field_name == "encryption_kdf_input"


def test_reject_shared_secret_select_zero(tmp_path):
    cfg = _enc_config(tmp_path)
    cfg["encryption_shared_secret_select"] = 0  # indices start at 1
    assert _pack_expect_error(cfg, tmp_path).field_name == "encryption_shared_secret_select"


# ---------------------------------------------------------------------------
# Key hygiene: the secret and derived key are never logged.
# ---------------------------------------------------------------------------


def test_secret_and_derived_key_never_logged(tmp_path, caplog):
    import logging

    cfg = _enc_config(tmp_path, encryption_type=0x02)
    out = tmp_path / "enc.bin"
    with caplog.at_level(logging.DEBUG):
        pack_oca_bundle(cfg, output_path=str(out))
    logs = caplog.text

    derived = enc.derive_payload_key(bytes.fromhex(_SECRET_HEX), bytes.fromhex(_KDF_INPUT_HEX), 0x02)
    assert _SECRET_HEX not in logs, "pre-shared secret must never be logged"
    assert derived.hex() not in logs, "derived key must never be logged"
