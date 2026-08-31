# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""OCA payload encryption: AES-128-CBC or AES-256-CBC with a KDF-derived key.

The cipher key is DERIVED from a pre-shared secret via NIST SP 800-108r1 Counter
Mode (HMAC-SHA-256). Both supported ciphers (``encryption_type`` 0x01 = AES-128-CBC,
0x02 = AES-256-CBC) derive the key from the SAME 192-byte expanded input block —
reproducing the OCAH Key Manager ``PREPARE_BL_DECRYPT_KEY`` flow byte-for-byte —
differing only in the derived-key length (128 vs 256 bits), which also sets the
block's ``out_bits`` header field and the PRF length suffix. The manifest's
64-byte ``encryption_kdf_input`` field supplies the KDF context. The pre-shared
secret, the derived key, and the plaintext are never logged.

The initialization vector and KDF input may be supplied (for a reproducible
build) or generated; generated values are recorded to a side-car JSON so the
build can be reproduced — the side-car never contains the secret.

Where the key material comes from is abstracted behind an *encryption
authority* (``encryption_authority`` in {``local``, ``aws``, ``hsm``}), mirroring
``manifest_signing``'s ``signing_authority``. Only ``local`` (a supplied
pre-shared secret, KDF-derived locally) is implemented today; ``aws`` and
``hsm`` are reserved provider slots that fail with a clear deferred-feature
error rather than ship a partial implementation.
"""

from __future__ import annotations

import json
import os
import struct
from typing import Tuple

from cryptography.hazmat.primitives import hashes, hmac

from . import constants as oca_consts
from .constants import OcaEncryptionType
from .validators import OcaConfigError, OcaLayoutError
from .. import aes128cbc as _aes128
from .. import aes256cbc as _aes256


# ---------------------------------------------------------------------------
# SP 800-108r1 counter-mode KDF over the expanded input block
# ---------------------------------------------------------------------------


def _hmac_sha256(key: bytes, msg: bytes) -> bytes:
    """HMAC-SHA-256(key, msg) via the vetted ``cryptography`` primitive."""
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    return h.finalize()


def build_kdf_input_block(context: bytes, key_bits: int) -> bytes:
    """Assemble the 192-byte KDF input block: header || label || context ||
    entropy. All header fields are fixed per the reference except ``out_bits``,
    which is ``key_bits`` (128 or 256). ``context`` must be the full 64 bytes."""
    if len(context) != oca_consts.KDF_BLOCK_CONTEXT_SIZE:
        raise OcaConfigError(
            f"KDF context must be {oca_consts.KDF_BLOCK_CONTEXT_SIZE} bytes; got {len(context)}",
            field_name="encryption_kdf_input",
        )
    header = struct.pack(
        "<HBBBBHHHII",
        oca_consts.KDF_HDR_VERSION,
        oca_consts.KDF_HDR_OUT_CLASS,
        oca_consts.KDF_HDR_OUT_TYPE,
        oca_consts.KDF_HDR_OUT_OWNER,
        oca_consts.KDF_HDR_OUT_DOMAIN,
        oca_consts.KDF_HDR_FLAGS,
        oca_consts.KDF_HDR_PURPOSE,
        key_bits,                       # out_bits — the only per-cipher header field
        oca_consts.KDF_HDR_CAPS,
        oca_consts.KDF_HDR_DEVICE_STATE,
    ) + b"\x00" * 12                    # rsvd[12]
    if len(header) != oca_consts.KDF_BLOCK_HEADER_SIZE:
        raise OcaLayoutError(
            f"KDF input block header is {len(header)} bytes, expected "
            f"{oca_consts.KDF_BLOCK_HEADER_SIZE}"
        )
    label = oca_consts.KDF_LABEL.ljust(oca_consts.KDF_BLOCK_LABEL_SIZE, b"\x00")
    entropy = b"\x00" * oca_consts.KDF_BLOCK_ENTROPY_SIZE
    block = header + label + context + entropy
    if len(block) != oca_consts.KDF_BLOCK_SIZE:
        # A wrong-sized block derives a different key, so producer and consumer
        # would silently stop interoperating. Never an elidable assert.
        raise OcaLayoutError(
            f"KDF input block is {len(block)} bytes, expected "
            f"{oca_consts.KDF_BLOCK_SIZE}"
        )
    return block


def _kdf_counter_mode(secret: bytes, block: bytes, out_bits: int) -> bytes:
    """SP 800-108r1 counter mode: concat K(i)=HMAC-SHA-256(secret, be16(i) ||
    block || be16(out_bits)) for i=1,2,... truncated to out_bits/8 bytes."""
    out_len = (out_bits + 7) // 8
    suffix = struct.pack(">H", out_bits)
    result = b""
    i = 1
    while len(result) < out_len:
        result += _hmac_sha256(secret, struct.pack(">H", i) + block + suffix)
        i += 1
    return result[:out_len]


def derive_payload_key(secret: bytes, kdf_input: bytes, encryption_type: int) -> bytes:
    """Return the derived AES key (16 bytes for AES-128-CBC, 32 for AES-256-CBC)
    from the 32-byte pre-shared ``secret`` and the 64-byte ``kdf_input`` (the KDF
    context), via SP 800-108r1 Counter Mode over the expanded input block. The
    producer and consumer derive the key identically."""
    if len(secret) != oca_consts.ENCRYPTION_SECRET_SIZE:
        raise OcaConfigError(
            f"encryption pre-shared secret must be {oca_consts.ENCRYPTION_SECRET_SIZE} "
            f"bytes; got {len(secret)}",
            field_name="encryption_secret",
        )
    if len(kdf_input) != oca_consts.ENCRYPTION_KDF_INPUT_SIZE:
        raise OcaConfigError(
            f"encryption_kdf_input must be {oca_consts.ENCRYPTION_KDF_INPUT_SIZE} "
            f"bytes; got {len(kdf_input)}",
            field_name="encryption_kdf_input",
        )
    key_bits = oca_consts.ENCRYPTION_KEY_BITS.get(int(encryption_type))
    if key_bits is None:
        raise OcaConfigError(
            f"unsupported encryption_type {encryption_type:#04x}; "
            f"supported: {sorted(oca_consts.ENCRYPTION_TYPES_SUPPORTED)}",
            field_name="encryption_type",
        )
    block = build_kdf_input_block(kdf_input, key_bits)
    return _kdf_counter_mode(secret, block, key_bits)


# ---------------------------------------------------------------------------
# Cipher (key length selects AES-128 vs AES-256)
# ---------------------------------------------------------------------------


def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(key) == oca_consts.KDF_BLOCK_HEADER_SIZE:  # 32 -> AES-256
        return _aes256.aes256cbc_encrypt(key, iv, plaintext)
    return _aes128.aes128cbc_encrypt(key, iv, plaintext)


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    if len(key) == oca_consts.KDF_BLOCK_HEADER_SIZE:  # 32 -> AES-256
        return _aes256.aes256cbc_decrypt(key, iv, ciphertext)
    return _aes128.aes128cbc_decrypt(key, iv, ciphertext)


def encrypt_payload(plaintext: bytes, secret: bytes, kdf_input: bytes, iv: bytes,
                    encryption_type: int) -> bytes:
    """Derive the key for ``encryption_type`` and AES-CBC-encrypt ``plaintext``
    (PKCS#7 padded)."""
    if len(iv) != oca_consts.ENCRYPTION_IV_SIZE:
        raise OcaConfigError(
            f"encryption_iv must be {oca_consts.ENCRYPTION_IV_SIZE} bytes; got {len(iv)}",
            field_name="encryption_iv",
        )
    key = derive_payload_key(secret, kdf_input, encryption_type)
    return _aes_cbc_encrypt(key, iv, plaintext)


# ---------------------------------------------------------------------------
# Encryption authority providers (local implemented; aws / hsm reserved)
# ---------------------------------------------------------------------------
#
# Mirrors manifest_signing's signing_authority abstraction. A provider turns the
# manifest's KDF input into the AES cipher key and encrypts the payload. The key
# derivation + cipher run wherever the authority dictates (locally today; inside
# KMS/HSM in a future pass). The provider carries the encryption_type so it
# derives a key of the correct length and selects the matching cipher.

ENCRYPTION_AUTHORITIES = ("local", "aws", "hsm")


class EncryptionProvider:
    """Base interface: derive the AES payload key for a manifest's KDF input and
    AES-CBC-encrypt the payload with it."""

    authority = None            # set by subclasses
    encryption_type = None      # set by subclasses / build_encryption_provider

    def derive_key(self, kdf_input: bytes) -> bytes:
        raise NotImplementedError

    def encrypt(self, plaintext: bytes, kdf_input: bytes, iv: bytes) -> bytes:
        if len(iv) != oca_consts.ENCRYPTION_IV_SIZE:
            raise OcaConfigError(
                f"encryption_iv must be {oca_consts.ENCRYPTION_IV_SIZE} bytes; got {len(iv)}",
                field_name="encryption_iv",
            )
        return _aes_cbc_encrypt(self.derive_key(kdf_input), iv, plaintext)


class LocalEncryptionProvider(EncryptionProvider):
    """Derive the key locally via the KDF from a supplied pre-shared secret."""

    authority = "local"

    def __init__(self, secret: bytes, encryption_type: int) -> None:
        self._secret = secret
        self.encryption_type = int(encryption_type)

    def derive_key(self, kdf_input: bytes) -> bytes:
        return derive_payload_key(self._secret, kdf_input, self.encryption_type)


class _ReservedEncryptionProvider(EncryptionProvider):
    """Reserved slot for a remote authority (aws / hsm) not yet implemented.
    Fails fast with a deferred-feature error — a partial remote implementation
    must not ship."""

    def __init__(self, authority: str) -> None:
        self.authority = authority

    def derive_key(self, kdf_input: bytes) -> bytes:
        label = f"{self.authority.upper()} encryption authority"
        raise OcaConfigError(
            f"OCA feature deferred to future pass: {label} (field encryption_authority)",
            field_name="encryption_authority",
            deferred_feature=label,
        )


def build_encryption_provider(config: dict) -> EncryptionProvider:
    """Construct the encryption provider for the config's ``encryption_authority``
    (default ``local``). ``aws`` / ``hsm`` return a reserved stub that errors when
    used; an unknown authority is rejected immediately."""
    authority = config.get("encryption_authority", "local")
    # Defaults to AES-256-CBC when unspecified (configs should set it explicitly).
    encryption_type = int(
        config.get("encryption_type", OcaEncryptionType.AES_256_CBC.value)
    )
    if authority == "local":
        return LocalEncryptionProvider(resolve_secret(config), encryption_type)
    if authority in ("aws", "hsm"):
        return _ReservedEncryptionProvider(authority)
    raise OcaConfigError(
        f"unknown encryption_authority {authority!r}; expected one of "
        f"{', '.join(ENCRYPTION_AUTHORITIES)}",
        field_name="encryption_authority",
    )


# ---------------------------------------------------------------------------
# Input resolution (supplied or generated)
# ---------------------------------------------------------------------------


def _read_key_material(path: str, size: int, field: str) -> bytes:
    """Read ``size`` bytes of key material from ``path`` — accepting either a
    raw binary file or a hex-text file."""
    with open(path, "rb") as fh:
        raw = fh.read()
    if len(raw) == size:
        return raw
    try:
        decoded = bytes.fromhex(raw.decode("ascii").strip())
    except (ValueError, UnicodeDecodeError):
        decoded = b""
    if len(decoded) == size:
        return decoded
    raise OcaConfigError(
        f"{field} file {path!r} must contain {size} raw bytes or {2 * size} hex chars",
        field_name=field,
    )


def resolve_secret(config: dict) -> bytes:
    """Resolve the 32-byte pre-shared secret from an inline hex value
    (``encryption_secret``) or a key file (``encryption_secret_file``)."""
    hex_val = config.get("encryption_secret")
    path = config.get("encryption_secret_file")
    if hex_val is not None and path is not None:
        raise OcaConfigError(
            "specify only one of encryption_secret / encryption_secret_file",
            field_name="encryption_secret",
        )
    if hex_val is None and path is None:
        raise OcaConfigError(
            "encrypted_payload=1 requires encryption_secret or encryption_secret_file",
            field_name="encryption_secret",
        )
    if path is not None:
        secret = _read_key_material(path, oca_consts.ENCRYPTION_SECRET_SIZE, "encryption_secret_file")
    else:
        secret = bytes.fromhex(hex_val)
    if len(secret) != oca_consts.ENCRYPTION_SECRET_SIZE:
        raise OcaConfigError(
            f"encryption pre-shared secret must be {oca_consts.ENCRYPTION_SECRET_SIZE} "
            f"bytes; got {len(secret)}",
            field_name="encryption_secret",
        )
    return secret


def resolve_iv(config: dict) -> Tuple[bytes, bool]:
    """Return ``(iv, generated)`` — the 16-byte IV supplied via ``encryption_iv``
    or a freshly generated random value."""
    hex_val = config.get("encryption_iv")
    if hex_val is None:
        return os.urandom(oca_consts.ENCRYPTION_IV_SIZE), True
    iv = bytes.fromhex(hex_val)
    if len(iv) != oca_consts.ENCRYPTION_IV_SIZE:
        raise OcaConfigError(
            f"encryption_iv must be {oca_consts.ENCRYPTION_IV_SIZE} bytes; got {len(iv)}",
            field_name="encryption_iv",
        )
    return iv, False


def resolve_kdf_input(config: dict) -> Tuple[bytes, bool]:
    """Return ``(kdf_input, generated)`` — the 64-byte KDF input (the full KDF
    context) supplied via ``encryption_kdf_input`` or a freshly generated random
    value."""
    hex_val = config.get("encryption_kdf_input")
    if hex_val is None:
        return os.urandom(oca_consts.ENCRYPTION_KDF_INPUT_SIZE), True
    kdf_input = bytes.fromhex(hex_val)
    if len(kdf_input) != oca_consts.ENCRYPTION_KDF_INPUT_SIZE:
        raise OcaConfigError(
            f"encryption_kdf_input must be {oca_consts.ENCRYPTION_KDF_INPUT_SIZE} "
            f"bytes; got {len(kdf_input)}",
            field_name="encryption_kdf_input",
        )
    return kdf_input, False


# ---------------------------------------------------------------------------
# Reproducibility side-car
# ---------------------------------------------------------------------------


def encrypt_inputs_filename(manifest_hash: bytes) -> str:
    """The side-car filename derived from the manifest hash."""
    return f"encrypt_inputs_{manifest_hash.hex()[-8:]}.json"


def write_encrypt_inputs_sidecar(
    output_path: str,
    manifest_hash: bytes,
    iv: bytes,
    kdf_input: bytes,
    iv_generated: bool,
    kdf_generated: bool,
) -> str:
    """Write the generated encryption inputs to ``encrypt_inputs_<hash>.json``
    next to ``output_path`` so the build can be reproduced. Records only the
    public IV / KDF input that were generated — never the pre-shared secret.
    Returns the side-car path, or None when nothing was generated."""
    if not (iv_generated or kdf_generated):
        return None
    data = {}
    if iv_generated:
        data["encryption_iv"] = iv.hex()
    if kdf_generated:
        data["encryption_kdf_input"] = kdf_input.hex()
    out_dir = os.path.dirname(os.path.abspath(output_path)) if output_path else os.getcwd()
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, encrypt_inputs_filename(manifest_hash))
    with open(path, "w") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path
