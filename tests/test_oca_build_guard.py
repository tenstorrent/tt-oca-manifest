# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Code compiled against another oca_config.h does not link with the library.

The library defines a guard symbol whose name spells every setting of the
header it was compiled against, and every file that includes oca_validator.h
refers to the guard its own header names. An application whose header states
any setting differently from the library's refers to a guard nothing defines,
and the link fails naming it. These tests compile a library and an application
against different headers and require exactly that, with unused sections
collected as firmware links them.

A header that is missing altogether stops the compile instead, naming the
generator.
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys

import pytest

from oca_fixtures import build_config
from oca_fixtures.build_config import config_text
from oca_fixtures.toolchain import C_COMPILER, CXX_COMPILER

LIB_DIR = os.path.join(build_config.VALIDATOR_DIR, "lib")
BUILD_CONFIG_DIR = os.path.join(build_config.VALIDATOR_DIR, "test", "build_configs")
REQUIRE_VALIDATOR_ENV = "TT_BOOT_MANIFEST_REQUIRE_VALIDATOR"

WARNINGS = ["-Wall", "-Wextra", "-Werror", "-pedantic", "-Wundef"]
SECTIONS = ["-ffunction-sections", "-fdata-sections"]
COLLECT_UNUSED = ["-Wl,-dead_strip"] if sys.platform == "darwin" else ["-Wl,--gc-sections"]

APPLICATION = """\
#include "oca_validator.h"

int main(void)
{
    return oca_result_str(OCA_OK) == 0;
}
"""

SECOND_FILE = """\
#include "oca_validator.h"

int application_helper(void)
{
    return (int)OCA_TOC_MAX_IMAGES;
}
"""

# A host tool that uses the header's types and links no library.
TYPES_ONLY = """\
#include "oca_validator.h"

int main(void)
{
    return sizeof(oca_crypto_blob_t) == 0u;
}
"""

LANGUAGES = {"c": (C_COMPILER, "app.c", ["-std=c99"]),
             "c++": (CXX_COMPILER, "app.cpp", ["-std=c++17"])}



def shipped_config(name) -> str:
    """The text of a configuration under test/build_configs."""
    with open(os.path.join(BUILD_CONFIG_DIR, name)) as handle:
        return handle.read()


# Between them, these take every setting but the one hash both ways.
CONFIGURATIONS = {
    "default": config_text(),
    "classic-only": shipped_config("classic_only.toml"),
    "pqc-only": shipped_config("pqc_only.toml"),
    "hash-only": shipped_config("hash_only.toml"),
    "small-toc-no-recheck": config_text({"limits.toc_max_images": 16,
                                         "hardening.recheck_security_version": False}),
}


def _load(path, name):
    """Import a standalone script by path; it is not on any package path."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gen_config = _load(os.path.join(LIB_DIR, "scripts", "gen_config.py"),
                   "oca_gen_config_for_build_guard")
IMPLEMENTED = [setting for setting in gen_config.SETTINGS if setting.implemented]


def require_tools(*tools):
    """Skip when a tool is missing, or fail under the validator-required setting."""
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        reason = f"needs {', '.join(missing)}"
        if os.environ.get(REQUIRE_VALIDATOR_ENV):
            pytest.fail(f"{reason} ({REQUIRE_VALIDATOR_ENV} is set)")
        pytest.skip(reason)


def settings_of(directory, text) -> dict[str, int]:
    """Each implemented setting's value in a configuration, by macro."""
    path = directory / "board.toml"
    path.write_text(text)
    return gen_config.resolve_settings(gen_config.load_config(str(path)))


def header_of(directory, text) -> str:
    """The oca_config.h a configuration generates."""
    path = directory / "board.toml"
    path.write_text(text)
    return gen_config.header_for_config(str(path))


def guard_name(values: dict[str, int], prefix="oca_build_guard") -> str:
    """The guard a header names: each setting's macro without OCA_CFG_,
    lowercased, then its value as the header spells it, in generator order."""
    parts = [prefix]
    for setting in IMPLEMENTED:
        value = values[setting.macro]
        spelled = f"{value}u" if setting.kind == "count" else str(value)
        parts.append(f"{setting.macro.removeprefix('OCA_CFG_').lower()}_{spelled}")
    return "_".join(parts)


def symbols(path) -> list[tuple[str, str]]:
    """(type, name) for every symbol nm lists, without the platform's prefix."""
    listed = subprocess.run(["nm", str(path)], capture_output=True, text=True, check=True)
    found = []
    for line in listed.stdout.splitlines():
        words = line.split()
        if len(words) >= 2:
            name = words[-1]
            if sys.platform == "darwin" and name.startswith("_"):
                name = name[1:]
            found.append((words[-2], name))
    return found


def guard_refs(obj) -> list[str]:
    """The guard symbols an object defines or refers to."""
    return [name for _, name in symbols(obj) if name.startswith("oca_build_guard")]


def include_dir(directory, header_text) -> str:
    """A directory holding header_text as oca_config.h."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "oca_config.h").write_text(header_text)
    return str(directory)


def compile_source(compiler, flags, source, obj, header_dir, check=True):
    """Compile one file against the library headers and header_dir."""
    return subprocess.run([*compiler, *flags, *WARNINGS, *SECTIONS, "-Os", "-I", LIB_DIR,
                           "-I", header_dir, "-c", str(source), "-o", str(obj)],
                          capture_output=True, text=True, check=check)


def library_archive(directory, header_text) -> str:
    """The library compiled against header_text, archived as firmware links it."""
    require_tools(C_COMPILER[0], "ar")
    header_dir = include_dir(directory / "gen", header_text)
    objects = []
    for source in sorted(os.listdir(LIB_DIR)):
        if source.endswith(".c"):
            obj = directory / (source[:-2] + ".o")
            compile_source(C_COMPILER, ["-std=c99", "-ffreestanding", "-fno-builtin"],
                           os.path.join(LIB_DIR, source), obj, header_dir)
            objects.append(str(obj))
    archive = directory / "liboca_validator.a"
    subprocess.run(["ar", "rcs", str(archive), *objects], check=True)
    return str(archive)


def application_object(directory, header_text, language="c", text=APPLICATION,
                       name="app", extra_flags=()) -> str:
    """One application file compiled against header_text."""
    compiler, source_name, flags = LANGUAGES[language]
    require_tools(compiler[0])
    directory.mkdir(parents=True, exist_ok=True)
    source = directory / f"{name}{os.path.splitext(source_name)[1]}"
    source.write_text(text)
    obj = directory / f"{name}.o"
    compile_source(compiler, [*flags, *extra_flags], source, obj,
                   include_dir(directory / f"{name}_gen", header_text))
    return str(obj)


def link(directory, objects, archive=None, language="c") -> subprocess.CompletedProcess:
    """Link the application, with the library unless archive is None,
    collecting unused sections."""
    compiler = LANGUAGES[language][0]
    libraries = [archive] if archive else []
    return subprocess.run([*compiler, *objects, *libraries, *COLLECT_UNUSED,
                           "-o", str(directory / "program")],
                          capture_output=True, text=True)


# ---------------------------------------------------------------------------
# The guard's name
# ---------------------------------------------------------------------------

def test_the_configurations_take_every_setting_both_ways(tmp_path):
    """The name test below proves a setting is in the name only if some
    configuration it runs on holds it at each value."""
    seen = {setting.macro: set() for setting in IMPLEMENTED}
    for index, text in enumerate(CONFIGURATIONS.values()):
        directory = tmp_path / str(index)
        directory.mkdir()
        for macro, value in settings_of(directory, text).items():
            if macro in seen:
                seen[macro].add(value)
    single = {macro for macro, values in seen.items() if len(values) < 2}
    assert single == {"OCA_CFG_HASH_SHA2_256"}, single


@pytest.mark.parametrize("configuration", sorted(CONFIGURATIONS))
def test_the_library_defines_the_guard_its_settings_name(tmp_path, configuration):
    text = CONFIGURATIONS[configuration]
    values = settings_of(tmp_path, text)
    archive = library_archive(tmp_path / "lib", header_of(tmp_path, text))
    defined = [name for kind, name in symbols(archive)
               if kind not in ("U", "w", "v") and name.startswith("oca_build_guard_")
               and not name.startswith("oca_build_guard_ref_")]
    assert set(defined) == {guard_name(values)}


def test_every_file_refers_to_the_guard_its_header_names(tmp_path):
    values = settings_of(tmp_path, config_text())
    obj = application_object(tmp_path / "app", header_of(tmp_path, config_text()))
    listed = symbols(obj)
    assert ("U", guard_name(values)) in listed
    assert guard_name(values, "oca_build_guard_ref") in {name for _, name in listed}


# ---------------------------------------------------------------------------
# The link
# ---------------------------------------------------------------------------

def stale_header(tmp_path) -> str:
    """A header generated from a configuration that has since changed."""
    return header_of(tmp_path, config_text({"limits.toc_max_images": 16}))


def portfolio_header(tmp_path) -> str:
    """A header generated from another board's configuration."""
    return header_of(tmp_path, CONFIGURATIONS["classic-only"])


MISMATCHES = {"stale": stale_header, "another-portfolio": portfolio_header}


@pytest.mark.parametrize("language", sorted(LANGUAGES))
def test_an_application_compiled_against_the_library_header_links(tmp_path, language):
    header = header_of(tmp_path, config_text())
    archive = library_archive(tmp_path / "lib", header)
    obj = application_object(tmp_path / "app", header, language)
    result = link(tmp_path, [obj], archive, language)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("language", sorted(LANGUAGES))
@pytest.mark.parametrize("mismatch", sorted(MISMATCHES))
def test_an_application_compiled_against_another_header_does_not_link(
        tmp_path, mismatch, language):
    archive = library_archive(tmp_path / "lib", header_of(tmp_path, config_text()))
    obj = application_object(tmp_path / "app", MISMATCHES[mismatch](tmp_path), language)
    result = link(tmp_path, [obj], archive, language)
    assert result.returncode != 0
    assert "oca_build_guard_variant_classic_" in result.stderr, result.stderr


def test_one_stale_file_stops_the_link(tmp_path):
    header = header_of(tmp_path, config_text())
    archive = library_archive(tmp_path / "lib", header)
    current = application_object(tmp_path / "app", header)
    stale = application_object(tmp_path / "app", stale_header(tmp_path), text=SECOND_FILE,
                               name="helper")
    result = link(tmp_path, [current, stale], archive)
    assert result.returncode != 0
    assert "toc_max_images_16u" in result.stderr, result.stderr


def test_a_compiler_without_retain_compiles_without_the_guard(tmp_path):
    """Without __has_attribute the header cannot ask for retain, so it leaves
    the reference out rather than make one the link may discard. Such a
    compiler gets no guard and builds as before. Undefining the builtin warns,
    so this compile does not treat warnings as errors."""
    require_tools(C_COMPILER[0])
    header_dir = include_dir(tmp_path / "gen", stale_header(tmp_path))
    source = tmp_path / "app.c"
    source.write_text(APPLICATION)
    obj = tmp_path / "app.o"
    subprocess.run([*C_COMPILER, "-std=c99", "-U__has_attribute", "-I", LIB_DIR,
                    "-I", header_dir, "-c", str(source), "-o", str(obj)],
                   capture_output=True, text=True, check=True)
    assert not guard_refs(obj)
    archive = library_archive(tmp_path / "lib", header_of(tmp_path, config_text()))
    result = link(tmp_path, [str(obj)], archive)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("omitted", [True, False])
def test_only_a_file_that_omits_the_guard_links_without_the_library(tmp_path, omitted):
    text = "#define OCA_BUILD_GUARD_OMIT\n" + TYPES_ONLY if omitted else TYPES_ONLY
    obj = application_object(tmp_path / "app", header_of(tmp_path, config_text()), text=text)
    assert bool(guard_refs(obj)) is not omitted
    result = link(tmp_path, [obj])
    assert (result.returncode == 0) is omitted, result.stderr


# ---------------------------------------------------------------------------
# A missing header
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("language", sorted(LANGUAGES))
def test_a_missing_configuration_header_names_the_generator(tmp_path, language):
    compiler, source_name, flags = LANGUAGES[language]
    require_tools(compiler[0])
    source = tmp_path / source_name
    source.write_text(APPLICATION)
    result = subprocess.run([*compiler, *flags, *WARNINGS, "-I", LIB_DIR, "-c", str(source),
                             "-o", str(tmp_path / "app.o")], capture_output=True, text=True)
    assert result.returncode != 0
    assert "gen_config.py" in result.stderr, result.stderr
    assert "INTEGRATION.md" in result.stderr, result.stderr
