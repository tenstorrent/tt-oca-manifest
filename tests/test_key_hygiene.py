"""The guard that refuses to sign a manifest with a key committed to this repo.

Two things are covered here, and the second matters as much as the first:

1. The pinned fingerprint table in `tt_boot_manifest.key_hygiene` still matches
   the keys actually on disk under `tests/signing_keys/`. A key added without a
   matching pin would otherwise sign real manifests unnoticed, which is the
   whole failure mode the guard exists to prevent.

2. The guard fires, and fires for the right reason. A check that had silently
   stopped working — or one that refused every key — would leave the suite green
   either way, so both the positive and the negative control are asserted.

Note `conftest.py` sets TT_BOOT_MANIFEST_ALLOW_TEST_KEY for the whole session so
the rest of the suite can sign freely. Every refusal test here must delete it
first or it passes for the wrong reason.
"""

from __future__ import annotations

import glob
import os
import shutil

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from tt_boot_manifest.key_hygiene import (
    ALLOW_CONFIG_FIELD,
    ALLOW_ENV_VAR,
    COMMITTED_TEST_KEY_FINGERPRINTS,
    KEY_DIR,
    KeyHygieneError,
    public_key_fingerprint,
)
from tt_boot_manifest.oca.entry import pack_oca_bundle

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_CONFIG = os.path.join(PROJECT_ROOT, "configs", "oca_production_template.yaml")


def _committed_key_fingerprints():
    """Fingerprint every key on disk under `tests/signing_keys/`."""
    found = {}
    pattern = os.path.join(PROJECT_ROOT, KEY_DIR, "*.pem")
    for path in sorted(glob.glob(pattern)):
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        rel = os.path.relpath(path, PROJECT_ROOT)
        found[public_key_fingerprint(key.public_key())] = rel
    return found


def _secure_config(tmp_path, key_file):
    """A minimal secure-boot OCA config signing with `key_file`."""
    img = tmp_path / "img.bin"
    img.write_bytes(b"\xDE\xAD\xBE\xEF\x90\x90\x90\x90")
    return {
        "manifest_format": "oca-classic",
        "manifest_identifier": "HYGIENE1",
        "description": "key-hygiene guard test",
        "secure_boot": 1,
        "timestamp": 1764633600,
        "signature_type": 0x01,
        "signing_authority": "local",
        "signing_key_file": str(key_file),
        "public_key_select_classic": 0x01,
        "manifest_content_version": {"major": 1, "minor": 0, "patch": 0},
        "payload_images": [{"type": "HYGIENEXBLSTAGE1", "path": str(img)}],
    }


def _write_rsa_3072_key(path):
    """Generate a fresh RSA-3072 key that is not committed to this repository."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    return path


# ---------------------------------------------------------------------------
# The pinned table tracks the keys on disk
# ---------------------------------------------------------------------------


def test_pinned_fingerprints_match_committed_keys():
    """Every key under tests/signing_keys/ is pinned, and nothing else is.

    The table is a literal rather than a runtime scan because `tests/` is not
    shipped in the wheel. That trade buys correctness for installed users at the
    cost of needing this test to keep the two in step.
    """
    found = _committed_key_fingerprints()
    assert found, f"no keys found under {KEY_DIR}/ — has the directory moved?"

    if found != COMMITTED_TEST_KEY_FINGERPRINTS:
        pinned = "\n".join(
            f'    "{fp}":\n        "{path}",'
            for fp, path in sorted(found.items(), key=lambda kv: kv[1])
        )
        missing = set(found) - set(COMMITTED_TEST_KEY_FINGERPRINTS)
        stale = set(COMMITTED_TEST_KEY_FINGERPRINTS) - set(found)
        pytest.fail(
            "COMMITTED_TEST_KEY_FINGERPRINTS has drifted from the keys on disk.\n"
            f"  unpinned keys (would sign real manifests): "
            f"{sorted(found[fp] for fp in missing) or 'none'}\n"
            f"  pins with no key on disk: "
            f"{sorted(COMMITTED_TEST_KEY_FINGERPRINTS[fp] for fp in stale) or 'none'}\n"
            "Replace COMMITTED_TEST_KEY_FINGERPRINTS in src/key_hygiene.py with:\n"
            "COMMITTED_TEST_KEY_FINGERPRINTS = {\n" + pinned + "\n}"
        )


# ---------------------------------------------------------------------------
# The guard refuses
# ---------------------------------------------------------------------------


def test_signing_with_committed_key_is_refused(tmp_path, monkeypatch):
    """With no opt-in, a committed development key cannot sign a manifest."""
    monkeypatch.delenv(ALLOW_ENV_VAR, raising=False)
    cfg = _secure_config(tmp_path, os.path.join(
        PROJECT_ROOT, KEY_DIR, "rsa_private_key.dev0.pem"))

    with pytest.raises(KeyHygieneError) as excinfo:
        pack_oca_bundle(cfg)
    # The message has to name the file, or the user cannot act on it.
    assert "rsa_private_key.dev0.pem" in str(excinfo.value)
    assert ALLOW_CONFIG_FIELD in str(excinfo.value)


def test_guard_fires_on_a_renamed_copy(tmp_path, monkeypatch):
    """Copying a committed key to a production-looking path does not launder it.

    This is why the guard fingerprints key material instead of matching on
    `signing_key_file` — the rename is the mistake most likely to happen.
    """
    monkeypatch.delenv(ALLOW_ENV_VAR, raising=False)
    disguised = tmp_path / "production_key.pem"
    shutil.copyfile(
        os.path.join(PROJECT_ROOT, KEY_DIR, "rsa_private_key.dev0.pem"), disguised)

    with pytest.raises(KeyHygieneError) as excinfo:
        pack_oca_bundle(_secure_config(tmp_path, disguised))
    # It still reports the repository path, not the disguised one.
    assert "rsa_private_key.dev0.pem" in str(excinfo.value)


def test_every_committed_key_is_refused(tmp_path, monkeypatch):
    """The refusal covers all committed keys, not just the RSA one used above."""
    monkeypatch.delenv(ALLOW_ENV_VAR, raising=False)
    for fingerprint, rel_path in COMMITTED_TEST_KEY_FINGERPRINTS.items():
        path = os.path.join(PROJECT_ROOT, rel_path)
        with open(path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
        assert public_key_fingerprint(key.public_key()) == fingerprint, rel_path


# ---------------------------------------------------------------------------
# The guard permits what it should
# ---------------------------------------------------------------------------


def test_config_field_permits_committed_key(tmp_path, monkeypatch):
    """`allow_test_signing_key: true` is the supported opt-in for a config."""
    monkeypatch.delenv(ALLOW_ENV_VAR, raising=False)
    cfg = _secure_config(tmp_path, os.path.join(
        PROJECT_ROOT, KEY_DIR, "rsa_private_key.dev0.pem"))
    cfg[ALLOW_CONFIG_FIELD] = True

    assert pack_oca_bundle(cfg), "declared development build should still pack"


def test_env_var_permits_committed_key(tmp_path, monkeypatch):
    """The harness override works without touching the config."""
    monkeypatch.setenv(ALLOW_ENV_VAR, "1")
    cfg = _secure_config(tmp_path, os.path.join(
        PROJECT_ROOT, KEY_DIR, "rsa_private_key.dev0.pem"))

    assert pack_oca_bundle(cfg), "env-var opt-in should still pack"


def test_uncommitted_key_signs_without_opt_in(tmp_path, monkeypatch):
    """A real key needs no opt-in — the guard is not just refusing everything."""
    monkeypatch.delenv(ALLOW_ENV_VAR, raising=False)
    key_file = _write_rsa_3072_key(tmp_path / "my_signing_key.pem")

    assert pack_oca_bundle(_secure_config(tmp_path, key_file)), \
        "a key not committed to this repo must sign with no declaration"


# ---------------------------------------------------------------------------
# The template stays clean
# ---------------------------------------------------------------------------


def test_production_template_carries_no_committed_key():
    """The template a user copies must not reference repository key material.

    It is the one config in `configs/` explicitly meant as a starting point for
    a real build, so an `allow_test_signing_key` line landing in it would
    reintroduce exactly the copy-paste trap the rename removed. Commented-out
    lines count: they are the ones a user uncomments.
    """
    with open(TEMPLATE_CONFIG, "r", encoding="utf-8") as f:
        text = f.read()

    assert KEY_DIR not in text, \
        f"template must not mention {KEY_DIR} anywhere, including in comments"
    assert not any(
        line.strip().lstrip("#").strip().startswith(f"{ALLOW_CONFIG_FIELD}:")
        for line in text.splitlines()), \
        f"template must not declare {ALLOW_CONFIG_FIELD}"


def test_production_template_defaults_to_a_managed_key_store():
    """The template signs through KMS, not a PEM on the build host.

    Local signing exposes the private key to every process, backup, and build
    log on the machine. It is a development affordance; a config explicitly
    labelled as the production starting point should not model it as the default
    even with a placeholder path.
    """
    with open(TEMPLATE_CONFIG, "r", encoding="utf-8") as f:
        active = [line for line in f.read().splitlines()
                  if line.strip() and not line.lstrip().startswith("#")]

    authority = next(
        line for line in active if line.startswith("signing_authority:"))
    assert "aws" in authority or "hsm" in authority, \
        f"production template should default to a managed key store; got: {authority}"
    assert not any(line.startswith("signing_key_file:") for line in active), \
        "production template should not set signing_key_file as an active field"
