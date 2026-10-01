# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Tests for OCA Post-Quantum (PQC) manifest assembly.

This pass produces the PQC manifest structure (OCAP magic, 36864-byte body, shared
classic fields at their offsets, PQC-only regions present) on the non-secure path.
PQC-native cryptography (ML-DSA / SLH-DSA / ML-KEM) is deferred and rejected fast.

PQC layout anchors (verified against boot-manifest.adoc):
    classic_manifest_trailer slot @ 3168  -> 0x35 x4 in a PQC manifest
    pqc_manifest_trailer        @ 5899  -> 0x96 x4
    signed region ends          @ 5903
    payload_offset (tail)       @ 6479  -> equals the 36864-byte body size
"""

from __future__ import annotations

import os
import struct

import pytest

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from tt_boot_manifest.oca import constants as oca_consts
from tt_boot_manifest.oca.entry import pack_oca_bundle
from tt_boot_manifest.oca.validators import OcaConfigError

OCAP_MAGIC = b"OCAP"
PTOC_MAGIC = b"PTOC"
OFF_PAYLOAD_OFFSET_PQC = 6479  # payload_offset field within the PQC unsigned tail
OFF_SIGNATURE_PQC = 6495       # signature_pqc field within the PQC unsigned tail

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RSA_KEY_FILE = os.path.join(PROJECT_ROOT, "tests", "signing_keys", "rsa_private_key.f4.pem")
_RSA_3072_SIG_BYTES = 384  # raw PKCS#1 v1.5 signature length; field is padded to 512


def _pqc_config(tmp_path, ident="PQCDEMO1", secure_boot=0, img_byte=0xAB):
    img = tmp_path / "img.bin"
    img.write_bytes(bytes([img_byte]) * 16)
    return {
        "manifest_format": "oca-pqc",
        "manifest_identifier": ident,
        "description": "OCA-PQC test bundle",
        "secure_boot": secure_boot,
        "timestamp": 1764633600,
        "manifest_content_version": {"major": 1, "minor": 0, "patch": 0},
        "payload_images": [{"type": "PQCDEMO1BLSTAGE1", "path": str(img)}],
    }


def _pqc_secure_rsa_config(tmp_path, ident="PQCSEC"):
    """A PQC config signed with a classic RSA-3072 key (secure boot)."""
    cfg = _pqc_config(tmp_path, ident=ident, secure_boot=1)
    cfg.update({
        "signature_type": 0x01,             # RSA-3072 PKCS#1 v1.5 / SHA-256
        "signing_authority": "local",
        "signing_key_name": "test_dev_rom_key_0",
        "signing_key_id": "1234567890",
        "signing_key_file": "tests/signing_keys/rsa_private_key.f4.pem",
        "public_key_select_classic": 0x01,
    })
    return cfg


# ---------------------------------------------------------------------------
# Structure
# ---------------------------------------------------------------------------


def test_pqc_manifest_structure(tmp_path):
    bundle = pack_oca_bundle(_pqc_config(tmp_path))
    body = bundle[: oca_consts.OCA_PQC_BODY_SIZE]

    # Magic + body size.
    assert body[0:4] == OCAP_MAGIC
    assert len(body) == 36864

    # manifest_length field carries the PQC body size.
    assert struct.unpack_from("<I", body, oca_consts.OFF_MANIFEST_LENGTH)[0] == 36864

    # A shared field keeps its Classic offset.
    assert body[oca_consts.OFF_MANIFEST_IDENTIFIER:oca_consts.OFF_MANIFEST_IDENTIFIER + 8].rstrip(b"\x00") == b"PQCDEMO1"

    # PQC-specific markers: 0x35 classic-trailer slot, 0x96 PQC trailer.
    assert body[oca_consts.OFF_CLASSIC_MANIFEST_TRAILER:oca_consts.OFF_CLASSIC_MANIFEST_TRAILER + 4] == oca_consts.PQC_CLASSIC_TRAILER_FILL
    trailer_at = oca_consts.PQC_SIGNED_REGION_END - 4
    assert body[trailer_at:oca_consts.PQC_SIGNED_REGION_END] == oca_consts.PQC_TRAILER

    # payload_offset (PQC tail) points just past the manifest body.
    assert struct.unpack_from("<q", body, OFF_PAYLOAD_OFFSET_PQC)[0] == 36864

    # Payload immediately follows the body and begins with the TOC magic.
    assert bundle[36864:36868] == PTOC_MAGIC


def test_pqc_classic_fields_match_classic_offsets(tmp_path):
    """The shared region before the PQC insertion point is byte-identical to a
    Classic manifest built from the same shared inputs."""
    pqc_cfg = _pqc_config(tmp_path)
    classic_cfg = dict(pqc_cfg)
    classic_cfg["manifest_format"] = "oca-classic"

    pqc_body = pack_oca_bundle(pqc_cfg)[: oca_consts.OCA_PQC_BODY_SIZE]
    classic_body = pack_oca_bundle(classic_cfg)[: oca_consts.OCA_CLASSIC_BODY_SIZE]

    # Shared fields are byte-identical at the same offsets EXCEPT the magic
    # (OCAC vs OCAP) and manifest_length (4096 vs 36864). Compare the two shared
    # spans that bracket manifest_length.
    assert (pqc_body[oca_consts.OFF_MANIFEST_IDENTIFIER:oca_consts.OFF_MANIFEST_LENGTH]
            == classic_body[oca_consts.OFF_MANIFEST_IDENTIFIER:oca_consts.OFF_MANIFEST_LENGTH])
    assert (pqc_body[oca_consts.OFF_SELECTOR_BITS:oca_consts.OFF_CLASSIC_MANIFEST_TRAILER]
            == classic_body[oca_consts.OFF_SELECTOR_BITS:oca_consts.OFF_CLASSIC_MANIFEST_TRAILER])


def test_pqc_determinism(tmp_path):
    cfg = _pqc_config(tmp_path)
    assert pack_oca_bundle(cfg) == pack_oca_bundle(cfg)


# ---------------------------------------------------------------------------
# Classic-signed PQC: a PQC manifest may carry a classic RSA-3072 / ECC-P256
# signature over the PQC signed region (PQC-native signing is still deferred).
# ---------------------------------------------------------------------------


def _classic_signature_valid_over_pqc_region(body: bytes) -> bool:
    """Return True iff the embedded classic RSA-3072 signature verifies over
    the PQC signed region [0, PQC_SIGNED_REGION_END) using the dev key.

    The region extent is the point of the check: a True result proves the
    producer signed the PQC extent (5903), not the Classic extent (3172). The
    verify is wrapped so callers assert on the boolean — the positive test
    expects True, the negative (tampered) test expects False."""
    signed_region = body[: oca_consts.PQC_SIGNED_REGION_END]
    sig_off = oca_consts.PQC_SIGNED_REGION_END  # signature_classic starts here in PQC
    sig_field = body[sig_off: sig_off + oca_consts.SIGNATURE_CLASSIC_SIZE]
    # Raw is the algorithm's own byte order, which for RSA is big-endian, so the
    # signature integer is used exactly as stored.
    rsa_sig = sig_field[:_RSA_3072_SIG_BYTES]

    with open(RSA_KEY_FILE, "rb") as fh:
        public_key = serialization.load_pem_private_key(fh.read(), password=None).public_key()
    try:
        public_key.verify(rsa_sig, signed_region, padding.PKCS1v15(), hashes.SHA256())
        return True
    except InvalidSignature:
        return False


def test_pqc_classic_signed_structure(tmp_path):
    """A secure-boot PQC manifest populates the classic signing fields (at their
    shared offsets / PQC signature offset) and leaves the PQC-native signature
    region zero."""
    body = pack_oca_bundle(_pqc_secure_rsa_config(tmp_path))[: oca_consts.OCA_PQC_BODY_SIZE]

    # secure_boot_enforced bit set.
    assert body[oca_consts.OFF_SECURE_BOOT_CONTROL] & 0x01
    # signature_type_classic written at its shared offset.
    assert body[oca_consts.OFF_SIGNATURE_TYPE_CLASSIC] == 0x01
    # public_key_classic populated at its shared offset.
    pk_off = oca_consts.OFF_PUBLIC_KEY_CLASSIC
    assert any(body[pk_off: pk_off + oca_consts.PUBLIC_KEY_CLASSIC_SIZE])
    # signature_classic populated at the PQC signature offset.
    sig_off = oca_consts.PQC_SIGNED_REGION_END
    assert any(body[sig_off: sig_off + oca_consts.SIGNATURE_CLASSIC_SIZE])
    # signature_pqc (PQC-native) stays all-zero — deferred.
    assert body[OFF_SIGNATURE_PQC: OFF_SIGNATURE_PQC + oca_consts.PQC_SIGNATURE_SIZE] \
        == b"\x00" * oca_consts.PQC_SIGNATURE_SIZE


def test_pqc_classic_signature_covers_pqc_signed_region(tmp_path):
    """The embedded RSA-3072 signature verifies over the full PQC signed
    region — proving the shared signing path signed the PQC extent (5872)."""
    body = pack_oca_bundle(_pqc_secure_rsa_config(tmp_path))[: oca_consts.OCA_PQC_BODY_SIZE]
    assert _classic_signature_valid_over_pqc_region(body)


def test_pqc_classic_signature_rejects_tampered_signed_region(tmp_path):
    """Flipping a byte inside the PQC signed region breaks verification —
    confirming the signature actually binds the region, not a rubber stamp."""
    body = bytearray(
        pack_oca_bundle(_pqc_secure_rsa_config(tmp_path))[: oca_consts.OCA_PQC_BODY_SIZE]
    )
    body[100] ^= 0xFF  # a shared-region byte, well inside [0, 5872)
    assert not _classic_signature_valid_over_pqc_region(bytes(body))


def test_pqc_classic_signed_determinism(tmp_path):
    cfg = _pqc_secure_rsa_config(tmp_path)
    assert pack_oca_bundle(cfg) == pack_oca_bundle(cfg)


# ---------------------------------------------------------------------------
# Deferred PQC-native crypto is rejected fast
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("sig_type_pqc", [0x31, 0x36, 0x37, 0x3E, 0xF0])
def test_pqc_native_signature_rejected(tmp_path, sig_type_pqc):
    """Any PQC-native signature_type_pqc value (ML-DSA / FN-DSA / SLH-DSA /
    integrator) is rejected as a deferred feature, across the full range."""
    cfg = _pqc_config(tmp_path)
    cfg["signature_type_pqc"] = sig_type_pqc
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.deferred_feature == "PQC signature fields"


def test_pqc_secure_boot_pqc_rejected(tmp_path):
    cfg = _pqc_config(tmp_path)
    cfg["secure_boot_pqc"] = 1
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.deferred_feature == "PQC signature fields"
