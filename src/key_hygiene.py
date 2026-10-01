"""Refuse to sign a manifest with the development keys committed to this repo.

Scope first, because it is easy to read this module as broader than it is:
signing a production manifest from a local PEM file is poor practice regardless
of which key it holds. A private key in a file is exposed to every process on
the host, to backups, and to whatever the build system logs. Production signing
belongs behind `signing_authority: aws` (KMS) or `hsm`, where the key material
never leaves the boundary and the signing operation is auditable. How that is
set up — key custody, rotation, who may invoke a sign — is a design question for
your organization's security engineering team, not a field to pick in a config
file.

What follows is a guard-rail for the narrower case where local signing is
genuinely required for a well-understood and permitted reason. It makes one
specific accident impossible. It does not make local signing a good idea.

The keys under `tests/signing_keys/` exist so the test suite can exercise the
signing paths without external key material. Nothing about them is secret, which
is exactly why a manifest signed with one must never be mistaken for a real one.
This script is intended to make production signing with a test key a build failure.

The check is on the *key material* — SHA-256 over the public key's
SubjectPublicKeyInfo DER — not on `signing_key_file`. Fingerprinting the key
rather than the path means copying `rsa_private_key.f4.pem` to
`~/keys/production_key.pem` does not launder it, which is the mistake most
likely to happen by accident.

Two ways to opt in, deliberately different in depending one what needs to be done:

* `allow_test_signing_key: true` in the config is the supported opt-in. It
  travels with the file, so a copied config still shows what it is doing.
* `TT_BOOT_MANIFEST_ALLOW_TEST_KEY=1` exists for this repo's own test harness,
  which builds several hundred manifests from inline config dicts. It is set
  once in `tests/conftest.py`.

Note the fingerprint here is NOT the boot-ROM trust anchor digest. That one is
SHA-256 over the raw 384-byte RSA modulus (see `validators/oca/test/cli_hwid.c`),
is RSA-only, and answers a different question; whether silicon trusts a particular 
public key. This one only answers whether a key came out of this repository.
"""

from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives import serialization

# SHA-256 over each key's SubjectPublicKeyInfo DER, mapped to the path it lives
# at so the error message can name the offending file.
#
# Pinned as a literal rather than scanned from `tests/signing_keys/` at runtime:
# `tests/` is not shipped in the wheel, so a scan would find nothing and the
# guard would silently pass for exactly the installed users it protects.
# `tests/test_key_hygiene.py` recomputes this from the keys on disk and fails if
# the two disagree, so a newly added test key cannot slip past unpinned.
COMMITTED_TEST_KEY_FINGERPRINTS = {
    "be6d01b596cf6be468cc5143e1e95e01dbfa944e7072552966223319a0d776c3":
        "tests/signing_keys/ec_private_key.pem",
    "d8ffccad54e348416be4c81d338c618afa74cf0ac0d177cae9d5c62ca6974e9e":
        "tests/signing_keys/rsa_private_key.f4.pem",
    "5bd317a0701fc47922f9d1647f4811feb5442b7e337389795607386866484844":
        "tests/signing_keys/rsa_private_key.e3.pem",
}

# Config field: the supported opt-in, visible in any copy of the config.
ALLOW_CONFIG_FIELD = "allow_test_signing_key"

# Environment override: for this repo's test harness only. Documented as such
# so it does not become a way to turn the guard off in a real build.
ALLOW_ENV_VAR = "TT_BOOT_MANIFEST_ALLOW_TEST_KEY"

KEY_DIR = "tests/signing_keys"


class KeyHygieneError(Exception):
    """Raised when a build would sign with a key committed to this repository."""


def public_key_fingerprint(public_key) -> str:
    """Return the SHA-256 hex digest of a public key's SubjectPublicKeyInfo DER.

    SPKI is used because it is defined for every algorithm, so RSA and ECDSA
    keys are covered by one rule and a future key type needs no new code here.
    """
    der = public_key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def committed_key_declared(manifest) -> bool:
    """Whether this build has declared that signing with a test key is intended."""
    if manifest is not None and manifest.get(ALLOW_CONFIG_FIELD):
        return True
    return os.environ.get(ALLOW_ENV_VAR) == "1"


def reject_committed_test_key(public_key, manifest) -> None:
    """Raise unless signing with `public_key` is either safe or declared.

    Deliberately a bare `raise` rather than `utils.check()`: `check()` degrades
    to a logged warning when checks are disabled, and a guard that evaporates
    under `python -O` is not a guard.
    """
    fingerprint = public_key_fingerprint(public_key)
    key_path = COMMITTED_TEST_KEY_FINGERPRINTS.get(fingerprint)
    if key_path is None or committed_key_declared(manifest):
        return

    raise KeyHygieneError(
        f"refusing to sign: this key is a development key committed to this "
        f"repository ({key_path}). A manifest signed with it is not "
        f"distinguishable from a real one, and the key is public.\n"
        f"  For a real build, point signing_key_file at a key from your signing "
        f"authority, or use signing_authority: aws.\n"
        f"  For a development build, declare it: add "
        f"`{ALLOW_CONFIG_FIELD}: true` to the config."
    )
