# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Byte offsets, sizes, enums, and magic values for the OCA-classic manifest format.

Source of truth: `boot-manifest.adoc` (the OCA AsciiDoc spec). Field offsets and
sizes are defined there.

This module is import-only; it contains no logic.

Heads up for future field additions
-----------------------------------

The C-side validator at `validators/oca/lib/oca_layout.h` mirrors a
subset of these constants byte-for-byte. Adding a new `OFF_*` / `LEN_*` /
`SELECTOR_BIT_*` here automatically triggers
`tests/test_oca_c_validator_layout_sync.py` until you either (a) map the
new symbol in `validators/oca/lib/scripts/sync_layout.py` and add
the C-side mirror, or (b) place the new symbol on the
`NOT_REQUIRED_PREFIXES` / `NOT_REQUIRED_EXACT` allowlist with rationale.
Field-level decoders under `validators/oca/lib/` may also need
updates if the field is constraint-bearing.
"""

from collections import namedtuple
from enum import Enum


# ---------------------------------------------------------------------------
# Magic byte strings (raw ASCII, NOT integer-packed)
# ---------------------------------------------------------------------------

OCAC_MAGIC = b"OCAC"  # Open Chiplet Atlas, Classic Signature
OCAP_MAGIC = b"OCAP"  # Open Chiplet Atlas, Post-Quantum Signature
PTOC_MAGIC = b"PTOC"  # Payload Table of Contents

# Classic-manifest trailer: four 0xCA bytes marking the end of the signed region.
CLASSIC_TRAILER = b"\xCA\xCA\xCA\xCA"

# Byte value used to populate selector-unused identity bytes in the manifest.
MANIFEST_UNUSED_BYTE = 0xA5


# ---------------------------------------------------------------------------
# Top-level sizes
# ---------------------------------------------------------------------------

OCA_CLASSIC_BODY_SIZE = 4096        # exact total body length
OCA_CLASSIC_SIGNED_REGION_END = 3172   # bytes [0, 3172) are covered by manifest_hash / signature_classic

TOC_HEADER_SIZE = 32                # PTOC header
TOC_ENTRY_SIZE = 276                # one TOC entry

# Payload TOC byte layout — "Payload TOC" / "Payload TOC entry" tables in the
# OCA spec. Both the packer (src/oca/toc.py) and the C validator
# (validators/oca/lib/oca_layout.h) address every field through these
# offsets; sync_layout.py diff-checks the two sides on every CI run.
OFF_TOC_MAGIC = 0                   # 4 bytes, "PTOC"
OFF_TOC_VERSION_MAJOR = 4           # u16 LE
OFF_TOC_VERSION_MINOR = 6           # u16 LE
OFF_TOC_PAYLOAD_LENGTH = 8          # u64 LE
OFF_TOC_IMAGE_COUNT = 16            # u64 LE
# 24..32 reserved

OFF_TOC_ENTRY_TYPE = 0              # 16 ASCII bytes
OFF_TOC_ENTRY_GROUP = 16            # u32 LE
OFF_TOC_ENTRY_OFFSET = 20           # u64 LE
OFF_TOC_ENTRY_LENGTH = 28           # u64 LE
OFF_TOC_ENTRY_VERSION = 36          # u64 LE, packed major/minor/patch
OFF_TOC_ENTRY_SECURITY_VERSION = 44  # u64 LE
OFF_TOC_ENTRY_LOAD_ADDR = 52        # u64 LE
OFF_TOC_ENTRY_ENTRY_POINT = 60      # u64 LE
OFF_TOC_ENTRY_TARGET_CHIPLET_ID = 68  # u64 LE
# 76..80 reserved
OFF_TOC_ENTRY_HASH = 80             # 64-byte field; digest at offset 0, rest 0x00
OFF_TOC_ENTRY_DESCRIPTION = 144     # 128 bytes, NUL-terminated ASCII
# 272..276 reserved

LEN_TOC_ENTRY_TYPE = 16
LEN_TOC_ENTRY_DESCRIPTION = 128
TOC_ENTRY_DESCRIPTION_MAX_TEXT = 127  # byte 127 shall be NUL

# Identity field sizes
CHIPLET_ID_SIZE = 32
PACKAGE_ID_SIZE = 32
SYSTEM_ID_SIZE = 32

# Description field
MANIFEST_DESCRIPTION_SIZE = 128
MANIFEST_DESCRIPTION_MAX_TEXT = 127  # byte 127 must be NUL

# manifest_identifier
MANIFEST_IDENTIFIER_SIZE = 8
MANIFEST_IDENTIFIER_MAX_TEXT = 8

# Public-key and signature field sizes (per OCA classic spec). The key field is
# sized for the largest supported value: an RSA-4096 PKCS#1 RSAPublicKey DER
# structure at 523 bytes plus the public exponent length. The number of valid
# bytes in each field is carried by its companion `*_size_classic` field.
PUBLIC_KEY_CLASSIC_SIZE = 532
SIGNATURE_CLASSIC_SIZE = 512

# Hash field size: 64 bytes total. The configured manifest_hash_type's digest
# occupies the leading bytes (32 for SHA-256, the type this pass emits); the
# remainder is 0x00 padding.
HASH_FIELD_SIZE = 64
MANIFEST_HASH_DIGEST_SIZE = 32

# Payload encryption. Supported modes: AES-128-CBC (encryption_type 0x01) and
# AES-256-CBC (0x02). For BOTH modes the key is derived via NIST SP 800-108r1
# Counter Mode (HMAC-SHA-256) over the SAME 192-byte expanded input block (see
# KDF_BLOCK_* below), reproducing the OCAH Key Manager PREPARE_BL_DECRYPT_KEY
# flow; only the derived-key length and the block's out_bits field / PRF length
# suffix track the cipher (128 vs 256 bits). The manifest's encryption_kdf_input
# field is the 64-byte KDF context.
ENCRYPTION_SECRET_SIZE = 32          # pre-shared secret (the PRF/HMAC key)
ENCRYPTION_IV_SIZE = 16              # AES-CBC IV (low bytes of the 32-byte field)
ENCRYPTION_KDF_INPUT_SIZE = 64       # encryption_kdf_input field == full KDF context
ENCRYPTION_IV_FIELD_SIZE = 32        # encryption_iv manifest field
AES_BLOCK_SIZE = 16                  # PKCS#7 padding boundary (AES block, key-size-independent)

# Expanded SP 800-108r1 counter-mode KDF input block (192 bytes) — the fixed
# "input data" the PRF consumes. Layout: 32-byte header || 32-byte label ||
# 64-byte context || 64-byte entropy. The label and entropy, and all header
# fields EXCEPT out_bits, are fixed constants from the reference
# PREPARE_BL_DECRYPT_KEY flow; out_bits (u16 LE at header offset 10) is the
# derived-key bit length (128 or 256) and is set per cipher by the block builder.
# The manifest's encryption_kdf_input field supplies the 64-byte context. PRF
# stream: HMAC-SHA-256(key, be16(i) || block || be16(L))[:L/8] with i from 1 and
# L = the derived-key bit length.
KDF_BLOCK_HEADER_SIZE = 32
KDF_BLOCK_LABEL_SIZE = 32
KDF_BLOCK_CONTEXT_SIZE = 64
KDF_BLOCK_ENTROPY_SIZE = 64
KDF_BLOCK_SIZE = 192
KDF_LABEL = b"KM_CLASS_BL"           # domain-separation label (null-padded to 32)
# Fixed header scalar fields (little-endian) per the reference km_kdf_input_t;
# out_bits is supplied per-cipher by the builder, everything else is fixed.
KDF_HDR_VERSION = 0x0001             # ABI version
KDF_HDR_OUT_CLASS = 0x01             # SYMMETRIC
KDF_HDR_OUT_TYPE = 0x00              # SYM_RAW
KDF_HDR_OUT_OWNER = 0x00             # NONE (ownerless)
KDF_HDR_OUT_DOMAIN = 0x01            # SW
KDF_HDR_FLAGS = 0x0018               # ROM_CREATED | ROM_LINEAGE
KDF_HDR_PURPOSE = 0x0000
KDF_HDR_CAPS = 0x00000001            # SYM_AES
KDF_HDR_DEVICE_STATE = 0x00000000    # no device-state binding (reproducible in every LC state)

# payload_encryption_control bit layout (2-byte LE field):
#   bit[0]    encrypted_payload
#   bit[5:3]  input_key_source (b001 = pre-shared secret)
ENCRYPTION_CONTROL_ENCRYPTED_PAYLOAD_BIT = 0x0001
ENCRYPTION_INPUT_KEY_SOURCE_SHIFT = 3
ENCRYPTION_INPUT_KEY_SOURCE_PRESHARED = 0b001


# ---------------------------------------------------------------------------
# Field offsets within the OCA-classic manifest body (in field-table order)
# ---------------------------------------------------------------------------

OFF_BOOT_MANIFEST_MAGIC = 0
OFF_MANIFEST_IDENTIFIER = 4
OFF_MANIFEST_VERSION_MAJOR = 12
OFF_MANIFEST_VERSION_MINOR = 14
OFF_MANIFEST_LENGTH = 16
OFF_RESERVED_1 = 20             # 4 bytes
OFF_SELECTOR_BITS = 24          # 16 bytes
OFF_CHIPLET_ID = 40
OFF_PACKAGE_ID = 72
OFF_SYSTEM_ID = 104
OFF_LIFECYCLE_CHIPLET_STATES = 136
OFF_LIFECYCLE_PACKAGE_STATES = 140
OFF_LIFECYCLE_SYSTEM_STATES = 144
OFF_VERSION_RANGE_CHIPLET = 148   # 8 bytes
OFF_VERSION_RANGE_PACKAGE = 156
OFF_VERSION_RANGE_SYSTEM = 164
OFF_DEMOTION_CONTROL = 172        # 2 bytes
OFF_RESERVED_2 = 174              # 8 bytes
OFF_SECURE_BOOT_CONTROL = 182     # 1 byte
OFF_RESERVED_3 = 183              # 8 bytes
OFF_MANIFEST_SECURITY_CONTROL = 191  # 2 bytes
OFF_RESERVED_4 = 193              # 8 bytes
OFF_PAYLOAD_ENCRYPTION_CONTROL = 201  # 2 bytes
OFF_ENCRYPTION_KDF = 203          # 2 bytes
OFF_ENCRYPTION_SHARED_SECRET_SELECT = 205
OFF_RESERVED_5 = 207              # 16 bytes
OFF_ENCRYPTION_KEM_UNWRAP_KEY_SELECT = 223
OFF_ENCRYPTION_KEM_FUNC = 225
OFF_RESERVED_6 = 227              # 8 bytes
OFF_ENCRYPTION_IV = 235           # 32 bytes
OFF_RESERVED_7 = 267              # 8 bytes
OFF_ENCRYPTION_KDF_INPUT = 275    # 64 bytes
OFF_RESERVED_8 = 339              # 8 bytes
OFF_ENCRYPTION_KEM_DEK = 347      # 1600 bytes
OFF_RESERVED_9 = 1947             # 64 bytes
OFF_VERIFIER_KEY_CONTROL = 2011   # 1 byte
OFF_RESERVED_10 = 2012            # 8 bytes
OFF_CO_SIGNER_CONTROL = 2020      # 2 bytes
OFF_RESERVED_11 = 2022            # 4 bytes
OFF_FEATURE_CONTROL = 2026        # 8 bytes
OFF_RESERVED_12 = 2034            # 8 bytes
OFF_MANIFEST_SECURITY_VERSION = 2042  # 16 bytes
OFF_ENCRYPTION_TYPE = 2058        # 1 byte
OFF_RESERVED_13 = 2059            # 8 bytes
OFF_MANIFEST_HASH_TYPE = 2067     # 1 byte
OFF_RESERVED_14 = 2068            # 8 bytes
OFF_SIGNATURE_COHORT_ENFORCE = 2076     # 8 bytes
OFF_SIGNATURE_CLASS_REVOKE = 2084       # 8 bytes
OFF_SIGNATURE_TYPE_CLASSIC = 2092       # 1 byte
OFF_SIGNATURE_ENCODING_CLASSIC = 2093   # 1 byte
OFF_SIGNATURE_SIZE_CLASSIC = 2094       # u16 LE
OFF_RESERVED_15 = 2096            # 8 bytes
OFF_PUBLIC_KEY_SELECT_CLASSIC = 2104    # 16 bytes
OFF_PUBLIC_KEY_CLASSIC = 2120           # 532 bytes
OFF_PUBLIC_KEY_ENCODING_CLASSIC = 2652  # 1 byte
OFF_PUBLIC_KEY_SIZE_CLASSIC = 2653      # u16 LE
OFF_PUBLIC_KEY_CLASSIC_REVOKE = 2655    # 16 bytes
OFF_RESERVED_16 = 2671            # 16 bytes
OFF_VERIFIER_KEY_ID_REVOKE = 2687 # 64 bytes
OFF_VERIFIER_SECURITY_VERSION = 2751  # 8 bytes
OFF_RESERVED_17 = 2759            # 16 bytes
OFF_PAYLOAD_HASH = 2775           # 64 bytes
OFF_RESERVED_18 = 2839            # 8 bytes
OFF_PAYLOAD_HASH_CHAIN = 2847     # 64 bytes
OFF_PAYLOAD_HASHED_LENGTH = 2911  # 8 bytes
OFF_PAYLOAD_HASH_TYPE = 2919      # 1 byte
OFF_RESERVED_19 = 2920            # 32 bytes
OFF_TIMESTAMP = 2952              # 8 bytes (signed)
OFF_PAYLOAD_LENGTH = 2960         # 8 bytes
OFF_MANIFEST_CONTENT_VERSION = 2968  # 8 bytes
OFF_MANIFEST_DESCRIPTION = 2976   # 128 bytes
OFF_RESERVED_20 = 3104            # 64 bytes
OFF_CLASSIC_MANIFEST_TRAILER = 3168  # 4 bytes

# Unsigned tail
OFF_SIGNATURE_CLASSIC = 3172       # 512 bytes
OFF_MANIFEST_HASH = 3684           # 64 bytes
OFF_PAYLOAD_OFFSET = 3748          # 8 bytes
OFF_UNAUTHENTICATED_FLAGS = 3756   # 8 bytes
OFF_RESERVED_21 = 3764             # 4 bytes
OFF_RESERVED_22 = 3768             # 8 bytes
OFF_RESERVED_23 = 3776             # 320 bytes (alignment pad to 4096)


# ---------------------------------------------------------------------------
# Multi-byte control-field widths (mirrored by the C validator, which reads
# these fields as little-endian scalars rather than single bytes)
# ---------------------------------------------------------------------------

LEN_MANIFEST_SECURITY_CONTROL = 2   # u16 LE — six update-disable bits [5:0]
LEN_SIGNATURE_COHORT_ENFORCE = 8    # u64 LE — 4-bit cohort nibble per signed entity
LEN_SIGNATURE_CLASS_REVOKE = 8      # u64 LE — per-class bits + two group-code bytes


# ---------------------------------------------------------------------------
# Field lengths for reserved regions (kept here so the manifest builder can
# emit b"\x00" * N without hardcoding sizes inline)
# ---------------------------------------------------------------------------

LEN_RESERVED_1 = 4
LEN_RESERVED_2 = 8
LEN_RESERVED_3 = 8
LEN_RESERVED_4 = 8
LEN_RESERVED_5 = 16
LEN_RESERVED_6 = 8
LEN_RESERVED_7 = 8
LEN_RESERVED_8 = 8
LEN_RESERVED_9 = 64
LEN_RESERVED_10 = 8
LEN_RESERVED_11 = 4
LEN_RESERVED_12 = 8
LEN_RESERVED_13 = 8
LEN_RESERVED_14 = 8
LEN_RESERVED_15 = 8
LEN_RESERVED_16 = 16
LEN_RESERVED_17 = 16
LEN_RESERVED_18 = 8
LEN_RESERVED_19 = 32
LEN_RESERVED_20 = 64
LEN_RESERVED_21 = 4
LEN_RESERVED_22 = 8
LEN_RESERVED_23 = 320


# ---------------------------------------------------------------------------
# Algorithm enums (this feature pass: minimum supported set)
# ---------------------------------------------------------------------------

class OcaClassicSignatureType(Enum):
    """OCA-classic `signature_type_classic` byte values, restricted to the
    algorithms supported by this packer. The spec defines more values;
    unsupported values are rejected at config-load time."""
    RSA_3072_PKCS1V15_SHA256 = 0x01
    ECDSA_P256_SHA256 = 0x05


class OcaClassicHashType(Enum):
    """OCA `*_hash_type` byte values; this feature pass supports SHA2-256 only."""
    SHA2_256 = 0x01


class OcaClassicSignatureEncoding(Enum):
    """OCA `signature_encoding_classic` byte values.

    UNSET (0x00) is what a `secure_boot = 0` bundle carries — the signing fields
    are zeroed — and is distinct from any real encoding. Vendor-defined (0x03) is
    deferred.

    RAW_BYTES is the value as its own standard defines it, in the byte order that
    standard requires — big-endian for both RSA and ECDSA. It is not a
    little-endian encoding despite what earlier revisions of this packer emitted.

    These values are mirrored by `oca_encoding_t` in the C validator's
    `oca_validator.h`, which casts the manifest byte straight to that type.
    `tests/test_oca_encoding_enum_sync.py` fails if the two drift apart.
    """
    UNSET = 0x00
    ASN1_DER = 0x01
    RAW_BYTES = 0x02


class OcaClassicPublicKeyEncoding(Enum):
    """OCA `public_key_encoding_classic` byte values.

    Same value set and the same C-side mirror as
    `OcaClassicSignatureEncoding` — see that docstring.
    """
    UNSET = 0x00
    ASN1_DER = 0x01
    RAW_BYTES = 0x02


# The encodings a producer may actually select for a signed bundle. UNSET is
# excluded: it is what the builder writes when secure_boot = 0, not something a
# config chooses.
OCA_SELECTABLE_ENCODINGS = (
    OcaClassicSignatureEncoding.ASN1_DER.value,
    OcaClassicSignatureEncoding.RAW_BYTES.value,
)

# Human-readable rendering of the above, for error messages. Derived so that
# adding an encoding updates every message that lists the allowed values.
_ENCODING_LABELS = {
    OcaClassicSignatureEncoding.ASN1_DER.value: "DER",
    OcaClassicSignatureEncoding.RAW_BYTES.value: "raw bytes",
}
OCA_SELECTABLE_ENCODINGS_TEXT = ", ".join(
    f"{value:#04x} ({_ENCODING_LABELS[value]})" for value in OCA_SELECTABLE_ENCODINGS
)


# ---------------------------------------------------------------------------
# Encoded public-key and signature lengths
# ---------------------------------------------------------------------------
# Every key and signature field is sized for the largest value any supported
# algorithm can produce, so each carries a companion `*_size_classic` field
# giving the number of valid bytes. Bytes beyond that count are 0x00.
#
# ASN.1 DER (0x01) is available only where a bare ASN.1 structure is defined for
# the value itself: RSA public keys (PKCS#1 RSAPublicKey) and ECDSA signatures
# (RFC 3279 ECDSA-Sig-Value). Every other DER combination is undefined and
# rejected.
CLASSIC_DER_PUBLIC_KEY_TYPES = frozenset({
    OcaClassicSignatureType.RSA_3072_PKCS1V15_SHA256.value,
})
CLASSIC_DER_SIGNATURE_TYPES = frozenset({
    OcaClassicSignatureType.ECDSA_P256_SHA256.value,
})

# Raw (0x02) lengths are fixed by the algorithm, and the size field carries them
# exactly. A raw RSA public key is a fixed-width big-endian modulus followed by a
# 4-byte big-endian public exponent; a raw ECDSA public key is a SEC1
# uncompressed point (0x04 || X || Y, big-endian).
RSA_3072_MODULUS_BYTES = 384
RSA_PUBLIC_EXPONENT_BYTES = 4
EC_P256_COORD_BYTES = 32
SEC1_UNCOMPRESSED_PREFIX = 0x04

CLASSIC_RAW_PUBLIC_KEY_LENGTHS = {
    OcaClassicSignatureType.RSA_3072_PKCS1V15_SHA256.value:
        RSA_3072_MODULUS_BYTES + RSA_PUBLIC_EXPONENT_BYTES,      # 388
    OcaClassicSignatureType.ECDSA_P256_SHA256.value:
        1 + (2 * EC_P256_COORD_BYTES),                           # 65
}
CLASSIC_RAW_SIGNATURE_LENGTHS = {
    OcaClassicSignatureType.RSA_3072_PKCS1V15_SHA256.value:
        RSA_3072_MODULUS_BYTES,                                  # 384
    OcaClassicSignatureType.ECDSA_P256_SHA256.value:
        2 * EC_P256_COORD_BYTES,                                 # 64
}

# DER ECDSA signatures are the one place the size field is a MAXIMUM rather than
# an exact count. Every `*_size_*` field lies inside the region its companion
# signature covers, so its value has to be fixed before the signature exists —
# yet a DER ECDSA-Sig-Value is 70-72 bytes depending on the leading-zero and
# high-bit handling of r and s, and deterministic signing (RFC 6979) offers no
# sign-measure-re-sign loop that converges. The field therefore carries the
# algorithm's maximum DER length, the DER length octets self-describe the actual
# size within it, and the bytes between the two are 0x00.
CLASSIC_DER_SIGNATURE_MAX_LENGTHS = {
    OcaClassicSignatureType.ECDSA_P256_SHA256.value: 72,
}


class OcaEncryptionType(Enum):
    """OCA `encryption_type` byte values. Both AES-128-CBC (0x01) and
    AES-256-CBC (0x02) are supported; both derive the key from the expanded KDF
    input block (differing only in key length)."""
    AES_128_CBC = 0x01
    AES_256_CBC = 0x02


# Derived-key bit length per encryption_type. Sets the AES key size, the KDF
# block's out_bits header field, and the PRF length suffix.
ENCRYPTION_KEY_BITS = {
    OcaEncryptionType.AES_128_CBC.value: 128,
    OcaEncryptionType.AES_256_CBC.value: 256,
}
# encryption_type values this pass supports (plain AES-CBC; CBC-HMAC/AEAD deferred).
ENCRYPTION_TYPES_SUPPORTED = frozenset(ENCRYPTION_KEY_BITS)


class OcaEncryptionKdf(Enum):
    """OCA `encryption_key_derivation_function` values; this feature pass supports
    NIST SP 800-108r1 Counter Mode (HMAC-SHA-256) only."""
    SP800_108_CTR_HMAC_SHA256 = 0x0001


# ---------------------------------------------------------------------------
# Deferred-feature names (used by validator error messages)
# ---------------------------------------------------------------------------

DEFERRED_FEATURE_NAMES = frozenset({
    "PQC manifest variant",
    "PQC signature fields",
    "Payload encryption",
    "Verifier-key entry",
    "Co-signer entries",
    "Unsupported signature algorithm",
    "Hash algorithms beyond SHA-256",
    "HSM signing authority",
    "KEM key wrapping",
    "Unsupported encryption algorithm",
    "Unsupported key-derivation function",
    "AWS encryption authority",
    "HSM encryption authority",
})


# ---------------------------------------------------------------------------
# Version policy for this feature pass
# ---------------------------------------------------------------------------

OCA_MANIFEST_VERSION_MAJOR = 1
OCA_MANIFEST_VERSION_MINOR = 0

TOC_VERSION_MAJOR = 1
TOC_VERSION_MINOR = 0

# Image alignment within the payload (per OCA spec)
PAYLOAD_IMAGE_ALIGNMENT = 8


# ---------------------------------------------------------------------------
# Manifest variant descriptors
# ---------------------------------------------------------------------------
# A variant descriptor carries the per-variant anchors the manifest builder
# parameterizes over (magic, body size, signed-region end, trailer) so both
# manifest variants flow through one assembly path. Crypto-family field
# offsets/sizes (the `*_CLASSIC` constants) are shared across variants and are
# NOT part of the descriptor. The PQC variant descriptor is added in the PQC
# support pass.

OcaVariant = namedtuple(
    "OcaVariant",
    ["format_name", "magic", "body_size", "signed_region_end", "trailer",
     "payload_offset_field"],
)

CLASSIC_VARIANT = OcaVariant(
    format_name="oca-classic",
    magic=OCAC_MAGIC,
    body_size=OCA_CLASSIC_BODY_SIZE,
    signed_region_end=OCA_CLASSIC_SIGNED_REGION_END,
    trailer=CLASSIC_TRAILER,
    payload_offset_field=OFF_PAYLOAD_OFFSET,
)

# PQC variant (OCAP, 36864-byte body). Layout verified against
# `boot-manifest.adoc`: the PQC-only signed block is inserted at the Classic
# manifest-trailer position, shifting the unsigned tail down by its size, and a
# `signature_pqc` field is added to the tail. Per-field PQC offsets and the
# C-side layout mirror are added with the validator's PQC support; this pass
# emits the PQC-only crypto regions as zero (PQC-native crypto is deferred)
# bounded by the spec-mandated trailer/fill markers. (Sizes use non-OFF_/LEN_
# names so the layout-sync gate stays green until the C mirror lands.)
OCA_PQC_BODY_SIZE = 36864             # exact total PQC body length
PQC_SIGNED_REGION_END = 5903          # bytes [0, 5903) covered by manifest_hash / signatures
PQC_TRAILER = b"\x96\x96\x96\x96"     # pqc_manifest_trailer marker (offset 5899)
PQC_CLASSIC_TRAILER_FILL = b"\x35\x35\x35\x35"  # classic_manifest_trailer slot in a PQC manifest
# Signed PQC-only fields between the 0x35 slot and the 0x96 trailer:
# signature_type_pqc, signature_encoding_pqc, signature_size_pqc,
# public_key_select_pqc, public_key_pqc, public_key_encoding_pqc,
# public_key_size_pqc, public_key_pqc_revoke, and a 64-byte reserved region.
PQC_SIGNED_CRYPTO_BLOCK_SIZE = 2727
PQC_SIGNATURE_SIZE = 29824            # signature_pqc field (unsigned tail)
PQC_TAIL_ALIGN_SIZE = 533             # final alignment pad in the PQC unsigned tail
PQC_PAYLOAD_OFFSET_FIELD = 6479       # payload_offset field offset in the PQC unsigned tail

PQC_VARIANT = OcaVariant(
    format_name="oca-pqc",
    magic=OCAP_MAGIC,
    body_size=OCA_PQC_BODY_SIZE,
    signed_region_end=PQC_SIGNED_REGION_END,
    trailer=PQC_TRAILER,
    payload_offset_field=PQC_PAYLOAD_OFFSET_FIELD,
)


# ---------------------------------------------------------------------------
# Usage-constraints control plane
# ---------------------------------------------------------------------------

# Lifecycle-state name → bit position (bits 0..4 preserve the historical
# lifecycle bit positions; OCA-classic extends with PROD_DBG_1/2 at bits 5..6).
# The two extra OCA debug states occupy the next free bits above the base set.
LIFECYCLE_STATE_NAMES = {
    "TEST_DEV":    0,
    "PROD":        1,
    "PROD_END":    2,
    "RMA_SIP":     3,    # Bit 3, previously spelled RMA_SoP; OCA renames to RMA_SIP.
    "RMA_CHIPLET": 4,
    "PROD_DBG_1":  5,
    "PROD_DBG_2":  6,
}

LIFECYCLE_STATES_VALID_MASK = (1 << 7) - 1                       # bits 0..6
LIFECYCLE_STATES_RESERVED_MASK = (~LIFECYCLE_STATES_VALID_MASK) & 0xFFFFFFFF

# selector_bits region for the lifecycle and version-range enable bits.
SELECTOR_BIT_LIFECYCLE_CHIPLET = 96
SELECTOR_BIT_LIFECYCLE_PACKAGE = 97
SELECTOR_BIT_LIFECYCLE_SYSTEM  = 98
SELECTOR_BIT_VERSION_CHIPLET_MIN = 99
SELECTOR_BIT_VERSION_CHIPLET_MAX = 100
SELECTOR_BIT_VERSION_PACKAGE_MIN = 101
SELECTOR_BIT_VERSION_PACKAGE_MAX = 102
SELECTOR_BIT_VERSION_SYSTEM_MIN  = 103
SELECTOR_BIT_VERSION_SYSTEM_MAX  = 104

# Bits 0..104 of selector_bits are used in this feature pass; bits 105..127
# are reserved and rejected.
SELECTOR_BITS_USED_LIMIT = 105
SELECTOR_BITS_RESERVED_MASK = ((1 << 128) - 1) ^ ((1 << SELECTOR_BITS_USED_LIMIT) - 1)

# Demotion-control 16-bit field. Vendor-defined bit layout (bits 4..15 unused):
#   bit 0 BL1_DEMOTION_VALID
#   bit 1 BL1_DEMOTION_ENABLE
#   bit 2 BL2_DEMOTION_VALID
#   bit 3 BL2_DEMOTION_ENABLE
DEMOTION_CONTROL_FLAG_NAMES = {
    "BL1_DEMOTION_VALID":  0,
    "BL1_DEMOTION_ENABLE": 1,
    "BL2_DEMOTION_VALID":  2,
    "BL2_DEMOTION_ENABLE": 3,
}
DEMOTION_CONTROL_VALID_MASK = (1 << 4) - 1                           # bits 0..3
DEMOTION_CONTROL_RESERVED_MASK = (~DEMOTION_CONTROL_VALID_MASK) & 0xFFFF


# ---------------------------------------------------------------------------
# Device-side security-state controls
# ---------------------------------------------------------------------------
# manifest_security_control (u16 LE) holds six opt-OUT update-disable bits. The
# default behavior of a Consumer that has verified the manifest is to advance
# the corresponding device-side state; each bit suppresses one of those updates.
# Only respected when secure boot is enabled.
MANIFEST_SECURITY_CONTROL_FLAG_NAMES = {
    "manifest_security_version_update_disable": 0,
    "manifest_revoke_keys_disable":             1,
    "verifier_security_update_disable":         2,
    "verifier_revoke_keys_disable":             3,
    "signature_cohort_enforce_update_disable":  4,
    "signature_class_revoke_update_disable":    5,
}
MANIFEST_SECURITY_CONTROL_VALID_MASK = (1 << 6) - 1                  # bits 0..5
MANIFEST_SECURITY_CONTROL_RESERVED_MASK = (
    (~MANIFEST_SECURITY_CONTROL_VALID_MASK) & 0xFFFF
)

# signature_cohort_enforce (u64 LE): a 4-bit nibble per signed entity, ten
# entities in all — b[3:0] the ROOT key, b[7:4] the verifier key, then
# b[11:8]..b[39:36] for co-signers 1..8. Within a nibble bit0 demands a
# classical signature and bit1 a post-quantum one; bits[3:2] are reserved.
SIGNATURE_COHORT_ENFORCE_ENTITY_COUNT = 10
SIGNATURE_COHORT_ENFORCE_CLASSICAL_BIT = 0
SIGNATURE_COHORT_ENFORCE_PQC_BIT = 1
SIGNATURE_COHORT_ENFORCE_VALID_MASK = sum(
    0x3 << (4 * entity) for entity in range(SIGNATURE_COHORT_ENFORCE_ENTITY_COUNT)
)
SIGNATURE_COHORT_ENFORCE_RESERVED_MASK = (
    (~SIGNATURE_COHORT_ENFORCE_VALID_MASK) & ((1 << 64) - 1)
)

# signature_class_revoke (u64 LE): per-algorithm-class disable bits in b[7:0]
# (classical) and b[31:24] (PQC), each group followed by a GROUP CODE byte —
# b[15:8] for classical, b[39:32] for PQC.
#
# A group code is a single constant, not a bitmask: only its exact value carries
# meaning, and an intact code disables the whole group. That is what makes a
# group-wide disable an explicit act rather than something a device can
# accumulate its way into via the OR-in update. The spec REQs that a Producer
# write exactly 0x00 or exactly the constant, so no manifest ever carries a
# fragment that could accumulate into an intact code across several updates.
SIGNATURE_CLASS_REVOKE_CLASSIC_MASK = 0x00000000000000FF   # b[7:0]
SIGNATURE_CLASS_REVOKE_CLASSIC_GROUP_SHIFT = 8             # b[15:8]
SIGNATURE_CLASS_REVOKE_CLASSIC_GROUP_CODE = 0xCA
SIGNATURE_CLASS_REVOKE_PQC_MASK = 0x000000FF000000         # b[31:24]
SIGNATURE_CLASS_REVOKE_PQC_GROUP_SHIFT = 32                # b[39:32]
SIGNATURE_CLASS_REVOKE_PQC_GROUP_CODE = 0xAC
SIGNATURE_CLASS_REVOKE_VALID_MASK = (
    SIGNATURE_CLASS_REVOKE_CLASSIC_MASK
    | (0xFF << SIGNATURE_CLASS_REVOKE_CLASSIC_GROUP_SHIFT)
    | SIGNATURE_CLASS_REVOKE_PQC_MASK
    | (0xFF << SIGNATURE_CLASS_REVOKE_PQC_GROUP_SHIFT)
)
SIGNATURE_CLASS_REVOKE_RESERVED_MASK = (
    (~SIGNATURE_CLASS_REVOKE_VALID_MASK) & ((1 << 64) - 1)
)
