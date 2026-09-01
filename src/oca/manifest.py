# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""OCA manifest body builder (Classic and PQC variants).

This module turns a normalized config dict (output of
`validators.validate_and_normalize_oca_classic`) plus the precomputed payload
hashes into the manifest body for the selected variant — 4096 bytes for
Classic, 36864 for PQC. Every variant-dependent offset is taken from the
`OcaVariant` descriptor passed in; the shared field layout is identical.

Build sequence (offsets parameterized by the variant descriptor):
  1. build_signed_region(normalized_cfg, payload_hash, payload_hash_chain,
                         payload_length, variant=...)
     → bytes [0, variant.signed_region_end) (the signed region, ending in the
       variant trailer).
  2. compute_manifest_hash(signed_region, variant=...) → 64-byte field
     (digest + zero pad; SHA-256 this pass, per manifest_hash_type).
  3. build_unsigned_tail(signed_region, manifest_hash, payload_offset, variant=...)
     → bytes [variant.signed_region_end, variant.body_size).
  4. Concatenate → variant.body_size body, asserted at assembly time.

When `secure_boot = 0` the signature_classic / public_key_classic fields stay
zero. When `secure_boot = 1` the caller supplies `public_key_classic_field`
and signs the assembled bytes; the signed-region layout is identical either
way.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Any, Dict

from . import constants as oca_consts
from .validators import OcaLayoutError


# ---------------------------------------------------------------------------
# Layout guards
#
# These replace the bare `assert`s this module used to carry. `python -O`
# strips asserts, which would leave the byte-layout of a *signed* manifest
# unchecked at exactly the moment it matters. See OcaLayoutError.
# ---------------------------------------------------------------------------


def _expect_offset(out: bytearray, expected: int, field: str) -> None:
    """The builder must stand at exactly `expected` bytes before writing `field`."""
    if len(out) != expected:
        raise OcaLayoutError(
            f"manifest layout: builder at offset {len(out)} before {field}, "
            f"expected {expected}"
        )


def _expect_field_size(value: bytes, expected: int, field: str) -> None:
    """`field` must be exactly `expected` bytes wide."""
    if len(value) != expected:
        raise OcaLayoutError(
            f"manifest layout: {field} is {len(value)} bytes, expected {expected}"
        )


def _expect_field_fits(value: bytes, limit: int, field: str) -> None:
    """`field`'s content must fit inside its `limit`-byte manifest field."""
    if len(value) > limit:
        raise OcaLayoutError(
            f"manifest layout: {field} is {len(value)} bytes, exceeds its "
            f"{limit}-byte field"
        )


# ---------------------------------------------------------------------------
# Signed region (bytes [0, variant.signed_region_end))
# ---------------------------------------------------------------------------


def build_signed_region(
    normalized: Dict[str, Any],
    payload_hash_field: bytes,
    payload_hash_chain_field: bytes,
    payload_length: int,
    payload_hashed_length: int,
    public_key_classic_field: bytes = None,
    public_key_size_classic: int = 0,
    signature_size_classic: int = 0,
    encryption: dict = None,
    variant: "oca_consts.OcaVariant" = oca_consts.CLASSIC_VARIANT,
) -> bytes:
    """Build the signed region (bytes [0, variant.signed_region_end)) in field-table order.

    `public_key_classic_field`, when provided, is the 532-byte encoding-padded
    public-key bytes (secure-boot path) — the on-disk encoding (DER or raw) is
    chosen by the producer via `public_key_encoding`. When None, the secure-boot
    key fields are all-zero (non-secure path).

    `public_key_size_classic` and `signature_size_classic` are the companion
    byte counts. Both are emitted here, inside the signed region, so the
    signature size has to be decided before signing — see
    `signing.declared_signature_size()`.

    Asserts the final length equals `variant.signed_region_end` (3172 for
    Classic, 5903 for PQC).
    """
    out = bytearray()

    # --- 0:4 boot_manifest_magic ---
    out += variant.magic
    _expect_offset(out, oca_consts.OFF_MANIFEST_IDENTIFIER, "manifest_identifier")

    # --- 4:12 manifest_identifier ---
    out += normalized["manifest_identifier_bytes"]
    _expect_offset(out, oca_consts.OFF_MANIFEST_VERSION_MAJOR, "manifest_version_major")

    # --- 12:14 / 14:16 / 16:20 / 20:24 ---
    out += struct.pack("<H", oca_consts.OCA_MANIFEST_VERSION_MAJOR)
    out += struct.pack("<H", oca_consts.OCA_MANIFEST_VERSION_MINOR)
    out += struct.pack("<I", variant.body_size)
    out += b"\x00" * oca_consts.LEN_RESERVED_1
    _expect_offset(out, oca_consts.OFF_SELECTOR_BITS, "selector_bits")

    # --- 24:40 selector_bits (128-bit, little-endian) ---
    out += normalized["selector_bits"].to_bytes(16, "little")
    _expect_offset(out, oca_consts.OFF_CHIPLET_ID, "chiplet_id")

    # --- 40:72 chiplet_id, 72:104 package_id, 104:136 system_id ---
    out += normalized["chiplet_id_bytes"]
    out += normalized["package_id_bytes"]
    out += normalized["system_id_bytes"]
    _expect_offset(out, oca_consts.OFF_LIFECYCLE_CHIPLET_STATES, "lifecycle_chiplet_states")

    # --- 136:140 / 140:144 / 144:148 lifecycle_*_states ---
    # Pre-resolved by usage_constraints.decode().
    out += struct.pack("<I", int(normalized["lifecycle_chiplet_states"]))
    out += struct.pack("<I", int(normalized["lifecycle_package_states"]))
    out += struct.pack("<I", int(normalized["lifecycle_system_states"]))
    _expect_offset(out, oca_consts.OFF_VERSION_RANGE_CHIPLET, "version_range_chiplet")

    # --- 148:156 / 156:164 / 164:172 version_range_* ---
    # Pre-packed by usage_constraints.decode().
    out += normalized["version_range_chiplet_bytes"]
    out += normalized["version_range_package_bytes"]
    out += normalized["version_range_system_bytes"]
    _expect_offset(out, oca_consts.OFF_DEMOTION_CONTROL, "demotion_control")

    # --- 172:174 demotion_control / 174:182 reserved ---
    out += struct.pack("<H", int(normalized["demotion_control"]))
    out += b"\x00" * oca_consts.LEN_RESERVED_2
    _expect_offset(out, oca_consts.OFF_SECURE_BOOT_CONTROL, "secure_boot_control")

    # --- 182:183 secure_boot_control ---
    secure_boot = normalized["secure_boot"]
    secure_boot_byte = 0
    if secure_boot:
        secure_boot_byte |= 0x01            # bit 0: secure_boot_enforced
        secure_boot_byte |= 0x02            # bit 1: secure_boot_classic
    out += struct.pack("B", secure_boot_byte)
    out += b"\x00" * oca_consts.LEN_RESERVED_3
    _expect_offset(out, oca_consts.OFF_MANIFEST_SECURITY_CONTROL, "manifest_security_control")

    # --- 191:193 manifest_security_control / 193:201 reserved ---
    out += struct.pack("<H", int(normalized.get("manifest_security_control", 0)))
    out += b"\x00" * oca_consts.LEN_RESERVED_4
    _expect_offset(out, oca_consts.OFF_PAYLOAD_ENCRYPTION_CONTROL, "payload_encryption_control")

    # --- Encryption fields ---
    # Populated on the encrypted path; all-zero otherwise, so a non-encrypted
    # bundle is byte-identical to the pre-encryption layout. KEM fields stay
    # zero (KEM key-wrapping is deferred).
    enc = encryption or {}
    iv_raw = enc.get("iv", b"")
    kdf_input_raw = enc.get("kdf_input", b"")
    _expect_field_fits(iv_raw, oca_consts.ENCRYPTION_IV_FIELD_SIZE, "encryption_iv")
    _expect_field_fits(kdf_input_raw, oca_consts.ENCRYPTION_KDF_INPUT_SIZE, "encryption_kdf_input")
    out += struct.pack("<H", enc.get("control", 0))              # payload_encryption_control
    out += struct.pack("<H", enc.get("kdf", 0))                  # encryption_key_derivation_function
    out += struct.pack("<H", enc.get("shared_secret_select", 0)) # encryption_shared_secret_select
    out += b"\x00" * oca_consts.LEN_RESERVED_5
    out += struct.pack("<H", 0)                     # encryption_kem_unwrap_key_select
    out += struct.pack("<H", 0)                     # encryption_key_encapsulation_function
    out += b"\x00" * oca_consts.LEN_RESERVED_6
    # The builder owns the field widths: pad each component up to its field size.
    out += iv_raw.ljust(oca_consts.ENCRYPTION_IV_FIELD_SIZE, b"\x00")               # encryption_iv (32B; low 16 = IV)
    out += b"\x00" * oca_consts.LEN_RESERVED_7
    out += kdf_input_raw.ljust(oca_consts.ENCRYPTION_KDF_INPUT_SIZE, b"\x00") # encryption_kdf_input (64B; full field = KDF context)
    out += b"\x00" * oca_consts.LEN_RESERVED_8
    out += b"\x00" * 1600                           # encryption_kem_dek
    out += b"\x00" * oca_consts.LEN_RESERVED_9
    _expect_offset(out, oca_consts.OFF_VERIFIER_KEY_CONTROL, "verifier_key_control")

    # --- 2010:2011 verifier_key_control (deferred) / reserved / co_signer (deferred) ---
    out += b"\x00"
    out += b"\x00" * oca_consts.LEN_RESERVED_10
    out += struct.pack("<H", 0)                     # co_signer_control
    out += b"\x00" * oca_consts.LEN_RESERVED_11
    _expect_offset(out, oca_consts.OFF_FEATURE_CONTROL, "feature_control")

    # --- 2025:2033 feature_control / reserved / 2041 manifest_security_version ---
    out += struct.pack("<Q", int(normalized["_source"].get("feature_control", 0)))
    out += b"\x00" * oca_consts.LEN_RESERVED_12
    msv = int(normalized["_source"].get("manifest_security_version", 0))
    if not (0 <= msv < (1 << 128)):
        raise ValueError("manifest_security_version must fit in 128 bits")
    out += msv.to_bytes(16, "little")
    _expect_offset(out, oca_consts.OFF_ENCRYPTION_TYPE, "encryption_type")

    # --- 2058:2059 encryption_type / 2059:2067 reserved / 2067:2068 manifest_hash_type ---
    out += struct.pack("B", enc.get("type", 0))     # encryption_type (0x01=AES-128-CBC, 0x02=AES-256-CBC)
    out += b"\x00" * oca_consts.LEN_RESERVED_13
    out += struct.pack("B", oca_consts.OcaClassicHashType.SHA2_256.value)
    out += b"\x00" * oca_consts.LEN_RESERVED_14
    _expect_offset(out, oca_consts.OFF_SIGNATURE_COHORT_ENFORCE, "signature_cohort_enforce")

    # --- 2076:2084 signature_cohort_enforce / 2084:2092 signature_class_revoke ---
    # Device control registers the Consumer ORs into vendor storage after a fully
    # verified boot; they govern how signatures are treated on SUBSEQUENT boots
    # and take no part in verifying the manifest carrying them. The validator
    # already zeroed both when secure boot is off, exactly as it does for
    # manifest_security_control above.
    out += struct.pack("<Q", int(normalized.get("signature_cohort_enforce", 0)))
    out += struct.pack("<Q", int(normalized.get("signature_class_revoke", 0)))
    _expect_offset(out, oca_consts.OFF_SIGNATURE_TYPE_CLASSIC, "signature_type_classic")

    # --- 2092:2093 signature_type_classic / 2093:2094 signature_encoding_classic /
    #     2094:2096 signature_size_classic ---
    if secure_boot:
        out += struct.pack("B", int(normalized["_source"]["signature_type"]))
        out += struct.pack("B", int(normalized["signature_encoding"]))
        out += struct.pack("<H", int(signature_size_classic))
    else:
        out += b"\x00" * 4      # signature_type + encoding + size
    out += b"\x00" * oca_consts.LEN_RESERVED_15
    _expect_offset(out, oca_consts.OFF_PUBLIC_KEY_SELECT_CLASSIC, "public_key_select_classic")

    # --- 2104:2120 public_key_select_classic (16 B) / 2120:2652 public_key_classic (532 B) /
    #     2652:2653 public_key_encoding_classic / 2653:2655 public_key_size_classic /
    #     2655:2671 public_key_classic_revoke / 2671:2687 reserved ---
    # When secure_boot == 0 these fields are zeroed in the output even if the
    # config supplies values — config values must not leak into a non-secure
    # bundle.
    if secure_boot:
        out += int(normalized["public_key_select_classic"]).to_bytes(16, "little")
        if public_key_classic_field is None:
            raise ValueError(
                "secure_boot=1 build_signed_region called without public_key_classic_field"
            )
        if len(public_key_classic_field) != oca_consts.PUBLIC_KEY_CLASSIC_SIZE:
            raise ValueError(
                f"public_key_classic_field must be {oca_consts.PUBLIC_KEY_CLASSIC_SIZE} bytes; "
                f"got {len(public_key_classic_field)}"
            )
        out += public_key_classic_field
        out += struct.pack("B", int(normalized["public_key_encoding"]))
        out += struct.pack("<H", int(public_key_size_classic))
        out += int(normalized["public_key_classic_revoke"]).to_bytes(16, "little")
    else:
        out += b"\x00" * 16
        out += b"\x00" * oca_consts.PUBLIC_KEY_CLASSIC_SIZE
        out += b"\x00"
        out += b"\x00" * 2      # public_key_size_classic
        out += b"\x00" * 16
    out += b"\x00" * oca_consts.LEN_RESERVED_16
    _expect_offset(out, oca_consts.OFF_VERIFIER_KEY_ID_REVOKE, "verifier_key_id_revoke")

    # --- 2687:2751 verifier_key_id_revoke (deferred → 0) ---
    out += b"\x00" * 64
    # --- 2751:2759 verifier_security_version (deferred → 0) ---
    out += b"\x00" * 8
    out += b"\x00" * oca_consts.LEN_RESERVED_17
    _expect_offset(out, oca_consts.OFF_PAYLOAD_HASH, "payload_hash")

    # --- 2775:2839 payload_hash (64 B) / 2839:2847 reserved / 2847:2911 payload_hash_chain (64 B) ---
    _expect_field_size(payload_hash_field, oca_consts.HASH_FIELD_SIZE, "payload_hash")
    _expect_field_size(payload_hash_chain_field, oca_consts.HASH_FIELD_SIZE, "payload_hash_chain")
    out += payload_hash_field
    out += b"\x00" * oca_consts.LEN_RESERVED_18
    out += payload_hash_chain_field
    _expect_offset(out, oca_consts.OFF_PAYLOAD_HASHED_LENGTH, "payload_hashed_length")

    # --- 2911:2919 payload_hashed_length / 2919:2920 payload_hash_type / 2920:2952 reserved ---
    out += struct.pack("<Q", payload_hashed_length) # TOC byte count (cleartext) / full ciphertext length (encrypted)
    out += struct.pack("B", oca_consts.OcaClassicHashType.SHA2_256.value)
    out += b"\x00" * oca_consts.LEN_RESERVED_19
    _expect_offset(out, oca_consts.OFF_TIMESTAMP, "timestamp")

    # --- 2952:2960 timestamp (signed int64) / 2960:2968 payload_length ---
    out += struct.pack("<q", int(normalized["timestamp"]))
    out += struct.pack("<Q", int(payload_length))
    _expect_offset(out, oca_consts.OFF_MANIFEST_CONTENT_VERSION, "manifest_content_version")

    # --- 2968:2976 manifest_content_version (packed 16/24/24) ---
    major, minor, patch = normalized["manifest_content_version"]
    if not (0 <= major < (1 << 16)):
        raise ValueError("manifest_content_version.major must fit in 16 bits")
    if not (0 <= minor < (1 << 24)):
        raise ValueError("manifest_content_version.minor must fit in 24 bits")
    if not (0 <= patch < (1 << 24)):
        raise ValueError("manifest_content_version.patch must fit in 24 bits")
    packed_mcv = (major << 48) | (minor << 24) | patch
    out += struct.pack("<Q", packed_mcv)
    _expect_offset(out, oca_consts.OFF_MANIFEST_DESCRIPTION, "manifest_description")

    # --- 2976:3104 manifest_description (128 B, NUL-terminated at byte 127) ---
    out += normalized["description_bytes"]
    _expect_offset(out, oca_consts.OFF_RESERVED_20, "reserved_20")

    # --- 3104:3168 reserved / 3168:3172 classic_manifest_trailer ---
    out += b"\x00" * oca_consts.LEN_RESERVED_20
    if variant.format_name == "oca-pqc":
        # The classic_manifest_trailer slot is 0x35-filled in a PQC manifest,
        # followed by the PQC-only signed fields (all 0x00 here — PQC-native
        # crypto is deferred), closed by the 0x96 pqc_manifest_trailer.
        out += oca_consts.PQC_CLASSIC_TRAILER_FILL
        out += b"\x00" * oca_consts.PQC_SIGNED_CRYPTO_BLOCK_SIZE
        out += oca_consts.PQC_TRAILER
    else:
        out += variant.trailer
    _expect_offset(out, variant.signed_region_end, "the signed-region trailer")

    return bytes(out)


# ---------------------------------------------------------------------------
# Unsigned tail (bytes [variant.signed_region_end, variant.body_size))
# ---------------------------------------------------------------------------


def build_unsigned_tail(
    signed_region: bytes,
    manifest_hash_field: bytes,
    payload_offset: int,
    signature_classic_field: bytes = None,
    variant: "oca_consts.OcaVariant" = oca_consts.CLASSIC_VARIANT,
) -> bytes:
    """Build the unsigned tail bytes `[signed_region_end, body_size)` and return them.

    Asserts the final length equals `body_size - signed_region_end`.
    """
    _expect_field_size(signed_region, variant.signed_region_end, "signed_region")
    _expect_field_size(manifest_hash_field, oca_consts.HASH_FIELD_SIZE, "manifest_hash")

    if signature_classic_field is None:
        signature_classic_field = b"\x00" * oca_consts.SIGNATURE_CLASSIC_SIZE
    _expect_field_size(signature_classic_field, oca_consts.SIGNATURE_CLASSIC_SIZE, "signature_classic")

    out = bytearray()
    # signature_classic (512 B) — zero in non-secure-boot path. Begins at
    # variant.signed_region_end (3172 Classic / 5903 PQC).
    out += signature_classic_field
    # manifest_hash (64 B)
    out += manifest_hash_field
    # payload_offset (signed int64)
    out += struct.pack("<q", int(payload_offset))
    # unauthenticated_flags (= 0 in this pass)
    out += struct.pack("<Q", 0)
    if variant.format_name == "oca-pqc":
        # signature_pqc (0x00 — PQC-native signing deferred), then reserved
        # 4 + 8 + alignment pad to the 36864-byte PQC body.
        out += b"\x00" * oca_consts.PQC_SIGNATURE_SIZE
        out += b"\x00" * oca_consts.LEN_RESERVED_21
        out += b"\x00" * oca_consts.LEN_RESERVED_22
        out += b"\x00" * oca_consts.PQC_TAIL_ALIGN_SIZE
    else:
        # reserved 4 + 8 + alignment pad to the 4096-byte Classic body.
        out += b"\x00" * oca_consts.LEN_RESERVED_21
        out += b"\x00" * oca_consts.LEN_RESERVED_22
        out += b"\x00" * oca_consts.LEN_RESERVED_23

    tail = bytes(out)
    _expect_field_size(tail, variant.body_size - variant.signed_region_end, "the unsigned tail")
    return tail


# ---------------------------------------------------------------------------
# Hashes
# ---------------------------------------------------------------------------


def compute_manifest_hash(
    signed_region: bytes,
    variant: "oca_consts.OcaVariant" = oca_consts.CLASSIC_VARIANT,
) -> bytes:
    """Return the 64-byte manifest_hash field: the signed-region digest at
    offset 0, zero-padded to 64 bytes. This pass emits a SHA-256 digest
    (manifest_hash_type = 0x01); the field width accommodates other digest
    types the format permits."""
    if len(signed_region) != variant.signed_region_end:
        raise ValueError(
            f"signed_region must be exactly {variant.signed_region_end} bytes; got {len(signed_region)}"
        )
    digest = hashlib.sha256(signed_region).digest()
    return digest.ljust(oca_consts.HASH_FIELD_SIZE, b"\x00")


