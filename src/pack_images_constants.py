# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Signing and encryption constants shared by the manifest tooling."""

from enum import Enum

class ManifestSignatureType(Enum):
    NO_SIGNATURE = 0
    RSA_3072 = 1
    ECC_P_256 = 2

RSA_3072_KEY_SZ_BITS = 3072
RSA_3072_KEY_SZ_BYTES = RSA_3072_KEY_SZ_BITS // 8
EC_256_KEY_SZ_BYTES = 32
SHA256_DIGEST_SIZE_BYTES = 32
AES_ENC_IV_SIZE_BYTES = 16
AES_ENC_SALT_SIZE_BYTES = 32
AES_ENC_KEY_SIZE_BYTES = 16
SIGNATURE_FIELD_SIZE = 384
PUBLIC_KEY_FIELD_SIZE = 384

PUBLIC_EXPONENT = 65537 # Fixed exponent value 0x010001
