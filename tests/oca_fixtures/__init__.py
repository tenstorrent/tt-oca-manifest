# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Shared fixture helpers for OCA tests.

Exposes path constants for the existing test signing keys so OCA tests don't
hard-code paths. The keys themselves are NOT duplicated — these constants point
at the shared `tests/signing_keys/` files (key-hygiene rule: no production keys;
test keys live under tests/signing_keys/ only).
"""

from __future__ import annotations

import os

# Resolve project root one directory above tests/
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir, os.pardir))


def _key_path(rel: str) -> str:
    return os.path.join(_PROJECT_ROOT, rel)


RSA_3072_KEY_PATH = _key_path("tests/signing_keys/rsa_private_key.f4.pem")
ECC_P256_KEY_PATH = _key_path("tests/signing_keys/ec_private_key.pem")

# A second RSA-3072 key differing only in its public exponent: 3 rather than the
# modern F4 (65537). It exists to exercise the one classic encoding whose length
# is not fixed by the algorithm — a PKCS#1 RSAPublicKey is 396 bytes at e=3 and
# 398 at F4, so a consumer that assumed a constant DER key length, or ignored
# public_key_size_classic, passes with one key and fails with the other.
RSA_3072_E3_KEY_PATH = _key_path("tests/signing_keys/rsa_private_key.e3.pem")

# (label, key path, PKCS#1 DER length) for parametrizing over both exponents.
RSA_EXPONENT_KEYS = [
    ("f4", RSA_3072_KEY_PATH, 398),
    ("e3", RSA_3072_E3_KEY_PATH, 396),
]
