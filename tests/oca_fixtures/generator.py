# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The build configuration generator, loaded for the tests of the generated
configuration, and the helpers those tests share.

`gen_config.py` is a standalone script, not on any package path, so it is
loaded here by path, once for every test module that uses it.
"""

from __future__ import annotations

import importlib.util
import os
import shlex
import shutil
import subprocess
import sys

import pytest

from oca_fixtures import build_config
from oca_fixtures.toolchain import C_COMPILER

VALIDATOR_DIR = build_config.VALIDATOR_DIR
LIB_DIR = os.path.join(VALIDATOR_DIR, "lib")
GENERATOR = os.path.join(LIB_DIR, "scripts", "gen_config.py")
CHECK_HEADER = os.path.join(LIB_DIR, "oca_config_check.h")
DEFAULT_CONFIG = build_config.DEFAULT_CONFIG
BUILD_CONFIG_DIR = os.path.join(VALIDATOR_DIR, "test", "build_configs")

REQUIRE_VALIDATOR_ENV = "TT_BOOT_MANIFEST_REQUIRE_VALIDATOR"


def _load(path, name):
    """Import a standalone script by path; it is not on any package path.

    Registered in sys.modules before it runs, because a dataclass looks its own
    module up there while it is being defined.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gen_config = _load(GENERATOR, "oca_gen_config")
REQUIRED = [setting for setting in gen_config.SETTINGS if setting.required]
IMPLEMENTED = [setting for setting in gen_config.SETTINGS if setting.implemented]
SWITCHES = [setting for setting in IMPLEMENTED if setting.kind == "bool"]
NOT_IMPLEMENTED = [setting for setting in gen_config.SETTINGS if not setting.implemented]

# Each implemented setting's default, as the README's Settings table documents
# it. A setting the table leaves out has none, which the default's own test
# reports.
DOCUMENTED = build_config.documented_defaults()
DEFAULT_VALUES = {s.macro: DOCUMENTED[s.name] for s in IMPLEMENTED if s.name in DOCUMENTED}

# Settings that declare a kind of build, and are refused in a configuration
# that is not one.
DECLARATIONS = {"OCA_CFG_SECURE_BOOT_DISABLED"}

# The settings these tests change most, by the short names their calls use.
SHORT_NAMES = {
    "classic": "variants.classic",
    "pqc": "variants.pqc",
    "toc_max_images": "limits.toc_max_images",
    "recheck_security_version": "hardening.recheck_security_version",
    "secure_boot_disabled": "secure_boot.disabled",
    "sha2_256": "hash.sha2_256",
    "rsa": "signature_classic.rsa_3072_pkcs1v15_sha256",
    "ecdsa": "signature_classic.ecdsa_p256_sha256",
    "ml_dsa_87": "signature_pqc.ml_dsa_87",
    "der_rsa": "der.rsa_public_key",
    "der_ecdsa": "der.ecdsa_signature",
    "aes_128": "encryption_cipher.aes_128_cbc",
    "aes_256": "encryption_cipher.aes_256_cbc",
    "kdf": "encryption_kdf.sp800_108_hmac_sha256",
    "preshared": "encryption_key_source.preshared",
}

# Verifies nothing: every signature algorithm, DER encoding and payload
# encryption setting off, as the declaration requires.
NO_SECURE_BOOT = {"rsa": "false", "ecdsa": "false", "ml_dsa_87": "false",
                  "der_rsa": "false", "der_ecdsa": "false", "aes_128": "false",
                  "aes_256": "false", "kdf": "false", "preshared": "false"}

# Between them, these turn off each variant, each signature algorithm, each DER
# encoding while its algorithm stays on, each cipher, payload encryption as a
# whole, the recheck, and everything but a hash. Each also names the unit tests
# beyond the configuration's own that must pass under it.
UNIT_TEST_CONFIGURATIONS = [
    pytest.param({}, (), id="default"),
    pytest.param({"toc_max_images": "16", "recheck_security_version": "false"},
                 ("test_anti_rollback_evaluated_once_when_recheck_disabled",),
                 id="small-toc-no-recheck"),
    pytest.param({"pqc": "false", "ml_dsa_87": "false"}, (), id="classic-only"),
    pytest.param({"classic": "false"}, (), id="pqc-only"),
    pytest.param({"ecdsa": "false", "der_ecdsa": "false", "ml_dsa_87": "false",
                  "der_rsa": "false", "aes_128": "false"}, (),
                 id="rsa-raw-keys-aes-256"),
    pytest.param({"rsa": "false", "der_rsa": "false", "der_ecdsa": "false",
                  "aes_128": "false", "aes_256": "false", "kdf": "false",
                  "preshared": "false"}, (),
                 id="ecdsa-raw-signatures-ml-dsa-no-encryption"),
    pytest.param({"rsa": "false", "ecdsa": "false", "der_rsa": "false",
                  "der_ecdsa": "false", "aes_256": "false"}, (),
                 id="ml-dsa-aes-128"),
    pytest.param({**NO_SECURE_BOOT, "secure_boot_disabled": "true"}, (),
                 id="hash-only"),
    # The largest cap the generator allows, where cap + 1 wraps a 32-bit count.
    pytest.param({"toc_max_images": "4294967295"}, (), id="largest-toc"),
]


def config_text(extra="", **changes):
    """A complete configuration: the shipped default, with each change named by
    its short name and given as its TOML text."""
    return build_config.config_text(
        {SHORT_NAMES[name]: value for name, value in changes.items()}, extra)


def write_config(directory, text, name="board.toml"):
    path = directory / name
    path.write_text(text)
    return str(path)


def problems_for(text):
    """The generator's complaints about a configuration, or [] when it accepts it."""
    try:
        gen_config.resolve_settings(gen_config.tomllib.loads(text))
    except gen_config.ConfigError as exc:
        return exc.problems
    return []


def default_header():
    return gen_config.header_for_config(DEFAULT_CONFIG)


def require_tools(*tools):
    """Skip when a tool is missing, or fail under the validator-required setting."""
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        reason = f"needs {', '.join(missing)}"
        if os.environ.get(REQUIRE_VALIDATOR_ENV):
            pytest.fail(f"{reason} ({REQUIRE_VALIDATOR_ENV} is set)")
        pytest.skip(reason)


def run_make(build_dir, *args, environment=None):
    """Run the validator's Makefile with the tests' C compiler, unless args
    name another."""
    require_tools("make", C_COMPILER[0])
    return subprocess.run(
        ["make", "-C", VALIDATOR_DIR, f"BUILD={build_dir}", *args],
        capture_output=True, text=True,
        env={**os.environ, "PYTHON": sys.executable, "CC": shlex.join(C_COMPILER),
             **(environment or {})})
