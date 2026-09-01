# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""AES-256-CBC encrypt/decrypt with PKCS#7 padding.

Mirrors :mod:`aes128cbc` for the 32-byte-key cipher. The underlying
``cryptography`` AES primitive selects AES-128/192/256 by key length, so these
helpers require a 32-byte key and a 16-byte IV (the AES block size is 16 bytes
regardless of key length). Used by the OCA payload-encryption path for
``encryption_type = 0x02``.
"""

import logging

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__.strip("_"))

AES_BLOCK_SIZE_BYTES = 16
AES256_KEY_SIZE_BYTES = 32


def aes256cbc_encrypt(key, iv, plaintext):
    """AES-256-CBC-encrypt ``plaintext`` (PKCS#7 padded) with a 32-byte ``key``
    and 16-byte ``iv``."""
    assert len(key) == AES256_KEY_SIZE_BYTES, \
        f"AES-256 key must be {AES256_KEY_SIZE_BYTES} bytes; got {len(key)}"
    assert len(iv) == AES_BLOCK_SIZE_BYTES, \
        f"IV must be {AES_BLOCK_SIZE_BYTES} bytes; got {len(iv)}"
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()
    return encryptor.update(padded_plaintext) + encryptor.finalize()


def aes256cbc_decrypt(key, iv, ciphertext):
    """AES-256-CBC-decrypt ``ciphertext`` and strip PKCS#7 padding."""
    assert len(key) == AES256_KEY_SIZE_BYTES, \
        f"AES-256 key must be {AES256_KEY_SIZE_BYTES} bytes; got {len(key)}"
    assert len(iv) == AES_BLOCK_SIZE_BYTES, \
        f"IV must be {AES_BLOCK_SIZE_BYTES} bytes; got {len(iv)}"
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return unpadder.update(padded_plaintext) + unpadder.finalize()
