# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The library under every build configuration.

The C unit tests must pass under any configuration, not only the default, and
a build that declares [secure_boot] disabled must compile its secure-boot
checks out.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys

import pytest

from oca_fixtures.generator import (LIB_DIR, BUILD_CONFIG_DIR, gen_config,
                                    UNIT_TEST_CONFIGURATIONS, config_text, write_config,
                                    default_header, require_tools, run_make)
from oca_fixtures.toolchain import C_COMPILER


# The tests of each setting's off branch, and the sweeps that hold the
# algorithm tables to the configuration. They run under every configuration.
TESTS_OF_THE_CONFIGURATION = (
    "test_a_variant_the_build_leaves_off_is_unsupported",
    "test_a_signature_algorithm_the_build_leaves_off_is_refused",
    "test_a_der_encoding_the_build_leaves_off_is_refused",
    "test_a_cipher_the_build_leaves_off_is_refused_before_hashing",
    "test_every_payload_algorithm_resolves_against_the_format_and_the_build",
    "test_a_build_without_secure_boot_refuses_every_check_it_left_out",
)

# The sweeps of the signature-algorithm table, which a build that declares
# [secure_boot] disabled compiles out with the lookups they call: they run
# wherever secure boot is built, and are listed as not run where it is not.
TESTS_OF_THE_SIGNATURE_TABLE = (
    "test_every_signature_type_resolves_against_the_format_and_the_build",
    "test_signature_rows_carry_the_format_encoded_lengths",
)


@pytest.mark.parametrize("changes, also_passing", UNIT_TEST_CONFIGURATIONS)
def test_the_unit_tests_pass_under_every_build_configuration(tmp_path, changes,
                                                             also_passing):
    """A unit test whose fixtures need something a configuration turns off is
    registered with what it needs, and is listed as not run where the build
    lacks it; every test that runs must pass. Under the default every test
    runs, so a test gated wrongly is caught there."""
    config = write_config(tmp_path, config_text(**changes))
    result = run_make(tmp_path / "build", f"CONFIG={config}", "unit_test")
    # The driver reports on stderr.
    assert result.returncode == 0, result.stdout + result.stderr
    summary = re.search(r"^(\d+)/(\d+) passed$", result.stderr, re.M)
    assert summary and summary.group(1) == summary.group(2), result.stderr
    for name in (*TESTS_OF_THE_CONFIGURATION, *also_passing):
        assert f"PASS: {name}\n" in result.stderr, name
    secure_boot_built = changes.get("secure_boot_disabled") != "true"
    for name in TESTS_OF_THE_SIGNATURE_TABLE:
        line = f"PASS: {name}\n" if secure_boot_built else f"NOT RUN: {name} ("
        assert line in result.stderr, name
    if not changes:
        assert "NOT RUN:" not in result.stderr


# The functions only a build with secure boot contains: the checks a build that
# declares [secure_boot] disabled compiles out, and the helpers and lookups
# only they call.
SECURE_BOOT_ONLY = {
    "authorize_key_by_class", "check_revocation_by_class", "verify_signature_by_class",
    "check_class_algorithm", "check_cohort", "classical_revoke_bit", "pqc_revoke_bit",
    "commit_revocation_for_family", "padding_is_dirty", "required_size", "empty_blob",
    "check_class_description", "oca_check_class_description", "oca_signature_algorithm",
    "oca_encoding_status", "classical_signature_defined", "pqc_signature_defined",
    "oca_secure_boot_confirm_classes", "check_encrypted_payload",
}

# The entry points of those checks, which every build defines: a build without
# secure boot defines each as a stub.
SECURE_BOOT_ENTRY_POINTS = {
    "oca_check_signing_description", "oca_check_signature_posture",
    "oca_check_root_key_authorized", "oca_check_root_key_revocation",
    "oca_check_security_version", "oca_check_signature", "oca_commit_security_state",
}


def defined_functions(directory, header_text):
    """Every function the library defines when compiled against header_text.

    Compiled without optimization, so a static function keeps its symbol
    rather than being inlined away, and its absence means its source was not
    compiled.
    """
    require_tools(C_COMPILER[0], "nm")
    gen = directory / "gen"
    gen.mkdir(parents=True)
    (gen / "oca_config.h").write_text(header_text)
    names = set()
    for source in sorted(os.listdir(LIB_DIR)):
        if not source.endswith(".c"):
            continue
        obj = directory / (source[:-2] + ".o")
        subprocess.run([*C_COMPILER, "-std=c99", "-O0", "-c", "-I", LIB_DIR, "-I", str(gen),
                        os.path.join(LIB_DIR, source), "-o", str(obj)], check=True)
        listed = subprocess.run(["nm", str(obj)], capture_output=True, text=True,
                                check=True)
        for line in listed.stdout.splitlines():
            words = line.split()
            if len(words) == 3 and words[1] in ("t", "T"):
                names.add(words[2][1:] if sys.platform == "darwin" else words[2])
    return names


def test_a_build_without_secure_boot_compiles_its_checks_out(tmp_path):
    full = defined_functions(tmp_path / "full", default_header())
    hash_only = defined_functions(
        tmp_path / "hash-only",
        gen_config.header_for_config(os.path.join(BUILD_CONFIG_DIR, "hash_only.toml")))
    assert SECURE_BOOT_ONLY <= full, SECURE_BOOT_ONLY - full
    assert SECURE_BOOT_ONLY & hash_only == set()
    assert SECURE_BOOT_ENTRY_POINTS <= hash_only
    assert hash_only - full == {"oca_secure_boot_not_built"}
