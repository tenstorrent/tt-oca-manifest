# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The Makefile's handling of the build configuration.

The Makefile regenerates the header on every build, rebuilds when it or the
compiler changes, and stops before compiling anything when the configuration
is invalid.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import time

import pytest

from oca_fixtures.generator import (VALIDATOR_DIR, GENERATOR, config_text, write_config,
                                    default_header, require_tools, run_make)
from oca_fixtures.toolchain import C_COMPILER


def test_a_config_variable_in_the_environment_does_not_choose_the_configuration(
        tmp_path):
    """CONFIG is a common name for an unrelated environment variable, so only the
    make command line names the build configuration."""
    build = tmp_path / "build"
    stray = write_config(tmp_path, config_text(pqc="false", ml_dsa_87="false"))
    result = run_make(build, str(build / "gen" / "oca_config.h"),
                      environment={"CONFIG": stray})
    assert result.returncode == 0, result.stdout + result.stderr
    assert (build / "gen" / "oca_config.h").read_text() == default_header()


def test_an_invalid_configuration_stops_the_build_before_any_compile(tmp_path):
    config = write_config(tmp_path, config_text(toc_max_images="0"))
    result = run_make(tmp_path / "build", f"CONFIG={config}", "lib")
    assert result.returncode != 0
    assert "limits.toc_max_images must be between 1" in result.stderr
    assert not list((tmp_path / "build").rglob("*.o"))


def test_the_build_runs_the_generator_isolated_from_pythonpath(tmp_path):
    """Without -I, a module on PYTHONPATH with the same name as one the
    generator imports would run inside the build."""
    shadow = tmp_path / "shadow"
    shadow.mkdir()
    (shadow / "tomllib.py").write_text('raise SystemExit("a shadowing tomllib ran")\n')
    build = tmp_path / "build"
    result = run_make(build, str(build / "gen" / "oca_config.h"),
                      environment={"PYTHONPATH": str(shadow)})
    assert result.returncode == 0, result.stdout + result.stderr
    assert (build / "gen" / "oca_config.h").read_text() == default_header()


# Every place that tells someone how to run the generator, and the Makefile
# that runs it.
GENERATOR_RUNNERS = [os.path.join(VALIDATOR_DIR, "Makefile"),
                     os.path.join(VALIDATOR_DIR, "README.md"),
                     os.path.join(VALIDATOR_DIR, "INTEGRATION.md"),
                     GENERATOR]
INTERPRETER = r"(?:python3|\$\{Python3_EXECUTABLE\}|\$\(CONFIG_PYTHON\))"


def runs_without_isolation(text):
    """Every line of text that runs gen_config.py with an interpreter but
    without -I."""
    return [line for line in text.splitlines()
            if re.search(rf"{INTERPRETER}\s.*gen_config\.py", line)
            and not re.search(rf"{INTERPRETER} -I \S*gen_config\.py", line)]


@pytest.mark.parametrize("path", GENERATOR_RUNNERS, ids=os.path.basename)
def test_every_documented_run_of_the_generator_is_isolated(path):
    with open(path) as handle:
        text = handle.read()
    assert "gen_config.py" in text
    assert runs_without_isolation(text) == []


def test_a_run_without_isolation_is_found():
    """The check above is only worth having if it notices a missing -I."""
    assert runs_without_isolation(
        "python3 lib/scripts/gen_config.py --config a.toml\n"
        "  COMMAND ${Python3_EXECUTABLE} ${OCA_LIB}/scripts/gen_config.py\n"
        "\t@$(CONFIG_PYTHON) lib/scripts/gen_config.py --out $@\n"
        "python3 -I lib/scripts/gen_config.py --config a.toml\n") == [
        "python3 lib/scripts/gen_config.py --config a.toml",
        "  COMMAND ${Python3_EXECUTABLE} ${OCA_LIB}/scripts/gen_config.py",
        "\t@$(CONFIG_PYTHON) lib/scripts/gen_config.py --out $@"]


def test_a_changed_configuration_rebuilds_and_an_unchanged_one_does_not(tmp_path):
    build = tmp_path / "build"
    config = write_config(tmp_path, config_text())
    assert run_make(build, f"CONFIG={config}", "lib").returncode == 0
    variant_object = build / "lib" / "oca_variant.o"
    first = variant_object.stat().st_mtime_ns

    unchanged = run_make(build, f"CONFIG={config}", "lib")
    assert unchanged.returncode == 0
    assert variant_object.stat().st_mtime_ns == first, unchanged.stdout

    # make 3.81 compares timestamps to the whole second, so a header rewritten
    # in the same second as the objects would not look newer than them.
    time.sleep(1.1)
    write_config(tmp_path, config_text(pqc="false", ml_dsa_87="false"))
    changed = run_make(build, f"CONFIG={config}", "lib")
    assert changed.returncode == 0
    assert variant_object.stat().st_mtime_ns != first, changed.stdout
    assert "#define OCA_CFG_VARIANT_PQC 0" in (build / "gen" / "oca_config.h").read_text()


def write_compiler(path, version, machine):
    """Write a compiler that compiles with the tests' C compiler but reports
    the given --version line and -dumpmachine target. Returns the path."""
    path.write_text("#!/bin/sh\n"
                    "case \"$1\" in\n"
                    f"  --version) echo \"{version}\"; exit 0 ;;\n"
                    f"  -dumpmachine) echo \"{machine}\"; exit 0 ;;\n"
                    "esac\n"
                    f"exec {shlex.join(C_COMPILER)} \"$@\"\n")
    path.chmod(0o755)
    return str(path)


# One object from each stamp: the library's, and the test driver's.
STAMPED_OBJECTS = [os.path.join("lib", "oca_variant.o"), os.path.join("test", "unit_test.o")]


def object_built_by(tmp_path, compiler, stamped_object):
    """Build one object with the given compiler and return its mtime."""
    build = tmp_path / "build"
    result = run_make(build, f"CC={compiler}", str(build / stamped_object))
    assert result.returncode == 0, result.stdout + result.stderr
    return (build / stamped_object).stat().st_mtime_ns


@pytest.mark.parametrize("stamped_object", STAMPED_OBJECTS)
def test_the_same_compiler_does_not_rebuild(tmp_path, stamped_object):
    compiler = write_compiler(tmp_path / "cc-a", "cc-a 1.0", "host")
    first = object_built_by(tmp_path, compiler, stamped_object)
    time.sleep(1.1)
    assert object_built_by(tmp_path, compiler, stamped_object) == first


@pytest.mark.parametrize("stamped_object", STAMPED_OBJECTS)
def test_another_compiler_command_rebuilds(tmp_path, stamped_object):
    first = object_built_by(tmp_path, write_compiler(tmp_path / "cc-a", "cc 1.0", "host"),
                            stamped_object)
    # make 3.81 compares timestamps to the whole second, so a stamp rewritten
    # in the same second as the objects would not look newer than them.
    time.sleep(1.1)
    second = object_built_by(tmp_path, write_compiler(tmp_path / "cc-b", "cc 1.0", "host"),
                             stamped_object)
    assert second != first


@pytest.mark.parametrize("stamped_object", STAMPED_OBJECTS)
@pytest.mark.parametrize("version,machine", [("cc 2.0", "host"), ("cc 1.0", "riscv64-elf")],
                         ids=["version", "target"])
def test_the_same_command_naming_another_compiler_rebuilds(tmp_path, stamped_object,
                                                           version, machine):
    """CC=cc can name a different compiler after a PATH or toolchain change.
    A new version, or a new target, must rebuild even though CC reads the same."""
    compiler = write_compiler(tmp_path / "cc", "cc 1.0", "host")
    first = object_built_by(tmp_path, compiler, stamped_object)
    time.sleep(1.1)
    write_compiler(tmp_path / "cc", version, machine)
    assert object_built_by(tmp_path, compiler, stamped_object) != first


def write_archiver(path, record):
    """Write an archiver that notes it ran in record, then runs the host's ar."""
    path.write_text("#!/bin/sh\n"
                    f"echo ran > {shlex.quote(str(record))}\n"
                    f"exec {shutil.which('ar')} \"$@\"\n")
    path.chmod(0o755)
    return str(path)


def test_the_library_is_archived_with_the_named_archiver(tmp_path):
    """make archives with the AR it is given, so a cross build can name its
    target's archiver."""
    require_tools("ar")
    record = tmp_path / "archiver-ran"
    build = tmp_path / "build"
    result = run_make(build, f"AR={write_archiver(tmp_path / 'cross-ar', record)}", "lib")
    assert result.returncode == 0, result.stdout + result.stderr
    assert record.read_text() == "ran\n"
    assert (build / "lib" / "liboca_validator.a").stat().st_size > 0


def test_a_quote_in_the_compiler_version_does_not_break_the_build(tmp_path):
    compiler = write_compiler(tmp_path / "cc", "vendor's cc 1.0", "host")
    object_built_by(tmp_path, compiler, STAMPED_OBJECTS[0])
    assert "vendors cc 1.0" in (tmp_path / "build" / "lib" / ".cflags").read_text()


@pytest.mark.parametrize("target", ["lib", "unit_test"])
def test_a_setting_read_by_a_name_nothing_defines_stops_the_build(tmp_path, target):
    """An undefined macro in #if reads as 0. Without -Wundef, a misspelled
    setting, or code still testing a setting's former name, would silently
    compile its feature out."""
    stale = tmp_path / "stale.h"
    stale.write_text("#if OCA_SUPPORT_PQC\n#endif\n")
    result = run_make(tmp_path / "build", f"EXTRA_CFLAGS=-include {stale}", target)
    assert result.returncode != 0
    assert "OCA_SUPPORT_PQC" in result.stderr
