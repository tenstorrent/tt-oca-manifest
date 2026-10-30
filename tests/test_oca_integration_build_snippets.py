# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""INTEGRATION.md's build snippets, built as an adopter would build them.

The "Configuring the build" section gives integrators CMake, Make and shell
snippets to copy. Every test here reads its snippet from the guide itself,
places it in a project in tmp_path that vendors lib/ as the guide says, and
builds it, so a snippet that no longer builds, rebuilds more or less than it
should, or quietly reads a misspelled setting as off fails here.

The scaffolding around each snippet is what any project has and the guide
leaves to the reader: a program that links the library and prints the
portfolio digest it was built with, and the rules that compile and link it.
"""

from __future__ import annotations

import importlib.util
import os
import re
import shutil
import subprocess
import sys
import time

import pytest

from oca_fixtures import build_config

GUIDE = os.path.join(build_config.VALIDATOR_DIR, "INTEGRATION.md")
SECTION_HEADING = "## Configuring the build"
LIB_DIR = os.path.join(build_config.VALIDATOR_DIR, "lib")
CLASSIC_ONLY_CONFIG = os.path.join(build_config.VALIDATOR_DIR, "test", "build_configs",
                                   "classic_only.toml")
VENDORED_LIB = "third_party/oca_validator"
GENERATED_HEADER = "oca_config.h"

REQUIRE_VALIDATOR_ENV = "TT_BOOT_MANIFEST_REQUIRE_VALIDATOR"

MAIN_SOURCE = """\
#include <stdio.h>
#include "oca_validator.h"

int main(void)
{
    const uint8_t *digest = oca_build_portfolio_digest();
    for (unsigned i = 0u; i < OCA_PORTFOLIO_DIGEST_SIZE; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\\n");
    return 0;
}
"""

# The callback the --print snippet compiles only when ML-DSA-87 is on.
ML_DSA_SOURCE = "src/crypto/ml_dsa_87_verify.c"
ML_DSA_OBJECT = "src/crypto/ml_dsa_87_verify.o"

MAKE_PREFIX = """\
.DEFAULT_GOAL := all
CFLAGS    := -std=c99 -Wall -Wextra -Wundef -Werror -MMD -MP
SRCS      := src/main.c
OBJS       = $(patsubst %.c,$(BUILD_DIR)/%.o,$(OCA_SOURCES) $(SRCS))
"""

MAKE_SUFFIX = """\
all: $(BUILD_DIR)/app

$(BUILD_DIR)/app: $(OBJS)
\t$(CC) $(CFLAGS) $(OBJS) -o $@

$(BUILD_DIR)/%.o: %.c
\t@mkdir -p $(dir $@)
\t$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

-include $(OBJS:.o=.d)
"""

CMAKE_PREFIX = """\
cmake_minimum_required(VERSION 3.20)
project(adopter C)
set(CMAKE_C_STANDARD 99)
"""

CMAKE_SUFFIX = """\
add_executable(app src/main.c)
target_link_libraries(app PRIVATE oca_validator)
"""

# The generators an adopter is likely to use. Ninja re-stats an output a
# command left alone, and Unix Makefiles does not, so a snippet can be right
# under one and wrong under the other.
CMAKE_GENERATORS = pytest.mark.parametrize("generator", ["Ninja", "Unix Makefiles"])

# A source a library upgrade adds to lib/.
ADDED_SOURCE = "oca_added_by_upgrade.c"


def _load(path, name):
    """Import a standalone script by path; it is not on any package path."""
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


gen_config = _load(os.path.join(LIB_DIR, "scripts", "gen_config.py"),
                   "oca_gen_config_for_snippets")


def require_tools(*tools):
    """Skip when a tool is missing, or fail under the validator-required setting."""
    missing = [tool for tool in tools if shutil.which(tool) is None]
    if missing:
        reason = f"needs {', '.join(missing)}"
        if os.environ.get(REQUIRE_VALIDATOR_ENV):
            pytest.fail(f"{reason} ({REQUIRE_VALIDATOR_ENV} is set)")
        pytest.skip(reason)


def make_tool() -> str:
    """GNU Make 4 where it is installed beside an older make, else make."""
    return shutil.which("gmake") or "make"


# ---------------------------------------------------------------------------
# Reading the guide
# ---------------------------------------------------------------------------

def guide_section() -> str:
    """The guide's "Configuring the build" section, up to the next heading."""
    with open(GUIDE, encoding="utf-8") as handle:
        text = handle.read()
    assert SECTION_HEADING in text, f"INTEGRATION.md lost its {SECTION_HEADING!r} section"
    return re.split(r"^## ", text.split(SECTION_HEADING, 1)[1], maxsplit=1, flags=re.M)[0]


def snippet(language: str, containing: str) -> str:
    """The one code block of language in the section whose text contains
    containing."""
    blocks = re.findall(rf"^```{language}\n(.*?)^```", guide_section(), re.M | re.S)
    found = [block for block in blocks if containing in block]
    assert len(found) == 1, f"expected one {language} block containing {containing!r}"
    return found[0]


def make_snippet() -> str:
    return snippet("make", ".PHONY: oca-config\n")


def without_line(text: str, start: str) -> str:
    """text without its one line beginning with start."""
    lines = text.splitlines(keepends=True)
    kept = [line for line in lines if not line.startswith(start)]
    assert len(kept) == len(lines) - 1, f"expected one line starting {start!r}"
    return "".join(kept)


# ---------------------------------------------------------------------------
# The adopter's project
# ---------------------------------------------------------------------------

def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        handle.write(text)


def adopter_project(root) -> str:
    """A project that vendors lib/ as the guide says, with a configuration
    copied from the default and a program that links the library."""
    root = str(root)
    shutil.copytree(LIB_DIR, os.path.join(root, VENDORED_LIB),
                    ignore=shutil.ignore_patterns("__pycache__"))
    os.makedirs(os.path.join(root, "board"))
    shutil.copy(build_config.DEFAULT_CONFIG, os.path.join(root, "board", "oca_config.toml"))
    write(os.path.join(root, "src", "main.c"), MAIN_SOURCE)
    write(os.path.join(root, ML_DSA_SOURCE), "int ml_dsa_87_verify_linked(void) { return 1; }\n")
    return root


def tool_path(tmp_path) -> dict[str, str]:
    """An environment whose python3 is the interpreter running the tests, which
    is 3.11 or later, whatever python3 the host has."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    shim = bin_dir / "python3"
    if not shim.exists():
        shim.symlink_to(sys.executable)
    return {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"}


def run(command, cwd, environment, check=True) -> subprocess.CompletedProcess:
    result = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, text=True)
    if check:
        assert result.returncode == 0, f"{command}\n{result.stdout}\n{result.stderr}"
    return result


def digest_of(config) -> str:
    """The portfolio digest the generator gives config, as hex."""
    document = gen_config.load_config(str(config))
    return gen_config.portfolio_digest(gen_config.resolve_settings(document)).hex()


def older_config(root, name, **changes) -> str:
    """A configuration differing from the default by changes, its file dated
    well before anything the build writes."""
    path = os.path.join(root, "board", name)
    write(path, build_config.config_text(changes))
    past = time.time() - 3600
    os.utime(path, (past, past))
    return path


def age(directory, seconds=10):
    """Date every file under directory seconds earlier, so a file the next build
    writes is newer than all of them whatever the file system's timestamp
    resolution or the make's."""
    for parent, _, names in os.walk(directory):
        for name in names:
            path = os.path.join(parent, name)
            stat = os.stat(path)
            os.utime(path, (stat.st_atime - seconds, stat.st_mtime - seconds))


def compiled(output: str) -> list[str]:
    """The compiler invocations a make printed."""
    return [line for line in output.splitlines() if " -c " in line]


def built_objects(output: str) -> list[str]:
    """The objects a CMake build reports building."""
    return [line for line in output.splitlines() if "Building C object" in line]


def ran_custom_command(output: str) -> bool:
    """Whether a CMake build ran a custom command, which in these projects is
    only ever the generator."""
    return any("Generating " in line for line in output.splitlines())


# ---------------------------------------------------------------------------
# The shell snippet
# ---------------------------------------------------------------------------

def test_the_generator_command_writes_the_header(tmp_path):
    root = adopter_project(tmp_path / "project")
    run(["sh", "-c", snippet("sh", "--out build/oca_gen/oca_config.h")], root,
        tool_path(tmp_path))
    header = os.path.join(root, "build", "oca_gen", GENERATED_HEADER)
    with open(header) as handle:
        assert "#define OCA_CONFIG_H" in handle.read()


# ---------------------------------------------------------------------------
# GNU Make
# ---------------------------------------------------------------------------

def add_library_source(root):
    """Add a source to the vendored lib/, as an upgrade that adds one does."""
    write(os.path.join(root, VENDORED_LIB, ADDED_SOURCE),
          "int oca_added_by_upgrade(void);\nint oca_added_by_upgrade(void) { return 1; }\n")


def make_project(tmp_path, *middle, build_dir="BUILD_DIR := build\n") -> str:
    """An adopter project whose Makefile is the scaffolding around middle."""
    require_tools("cc")
    root = adopter_project(tmp_path / "project")
    write(os.path.join(root, "Makefile"),
          build_dir + MAKE_PREFIX + "\n".join(middle) + "\n" + MAKE_SUFFIX)
    return root


def make(root, environment, *args, check=True) -> subprocess.CompletedProcess:
    return run([make_tool(), *args], root, environment, check=check)


def app_digest(root, build_dir="build") -> str:
    return run([os.path.join(root, build_dir, "app")], root, os.environ).stdout.strip()


def test_the_make_snippet_builds_against_its_configuration(tmp_path):
    root = make_project(tmp_path, make_snippet())
    environment = tool_path(tmp_path)
    assert compiled(make(root, environment).stdout)
    assert app_digest(root) == digest_of(os.path.join(root, "board", "oca_config.toml"))


def test_the_make_snippet_rebuilds_nothing_when_nothing_changed(tmp_path):
    root = make_project(tmp_path, make_snippet())
    environment = tool_path(tmp_path)
    make(root, environment)
    header = os.path.join(root, "build", "oca_gen", GENERATED_HEADER)
    written = os.stat(header).st_mtime_ns
    assert compiled(make(root, environment).stdout) == []
    assert os.stat(header).st_mtime_ns == written


def test_the_make_snippet_recompiles_nothing_for_a_comment_edit(tmp_path):
    root = make_project(tmp_path, make_snippet())
    environment = tool_path(tmp_path)
    make(root, environment)
    config = os.path.join(root, "board", "oca_config.toml")
    with open(config, "a") as handle:
        handle.write("# Reviewed.\n")
    assert compiled(make(root, environment).stdout) == []


def test_the_make_snippet_follows_a_switch_to_an_older_file(tmp_path):
    """The reason the generator runs on every build: a file older than the
    header would not trigger a rule that depends on the file alone."""
    root = make_project(tmp_path, make_snippet())
    environment = tool_path(tmp_path)
    make(root, environment)
    older = older_config(root, "older.toml",
                         **{"variants.pqc": False, "signature_pqc.ml_dsa_87": False})
    age(os.path.join(root, "build"))
    output = make(root, environment, "OCA_CONFIG=board/older.toml").stdout
    assert any(VENDORED_LIB in line for line in compiled(output))
    assert app_digest(root) == digest_of(older)


def test_the_make_snippet_compiles_a_source_an_upgrade_adds(tmp_path):
    root = make_project(tmp_path, make_snippet())
    environment = tool_path(tmp_path)
    make(root, environment)
    add_library_source(root)
    make(root, environment)
    assert os.path.exists(os.path.join(root, "build", VENDORED_LIB,
                                       ADDED_SOURCE.replace(".c", ".o")))


def several_builds_project(tmp_path) -> str:
    """The several-builds snippet ahead of the main one, in place of its
    OCA_CONFIG, as the guide says."""
    root = make_project(tmp_path, snippet("make", "OCA_BUILD  :="),
                        without_line(make_snippet(), "OCA_CONFIG "), build_dir="")
    shutil.copy(build_config.DEFAULT_CONFIG, os.path.join(root, "board", "oca_default.toml"))
    shutil.copy(CLASSIC_ONLY_CONFIG, os.path.join(root, "board", "oca_classic_only.toml"))
    return root


def test_each_build_has_its_own_configuration_and_directory(tmp_path):
    root = several_builds_project(tmp_path)
    environment = tool_path(tmp_path)
    make(root, environment)
    make(root, environment, "OCA_BUILD=classic_only")
    assert app_digest(root, "build/default") \
        == digest_of(os.path.join(root, "board", "oca_default.toml"))
    assert app_digest(root, "build/classic_only") \
        == digest_of(os.path.join(root, "board", "oca_classic_only.toml"))
    assert app_digest(root, "build/default") != app_digest(root, "build/classic_only")


def test_a_build_variable_in_the_environment_does_not_choose_the_build(tmp_path):
    root = several_builds_project(tmp_path)
    make(root, {**tool_path(tmp_path), "OCA_BUILD": "classic_only"})
    assert os.path.exists(os.path.join(root, "build", "default", "app"))
    assert not os.path.exists(os.path.join(root, "build", "classic_only"))


def print_project(tmp_path, print_snippet=None) -> str:
    """The main snippet followed by the --print snippet."""
    return make_project(tmp_path, make_snippet(),
                        print_snippet or snippet("make", "--print signature_pqc.ml_dsa_87"))


def test_print_compiles_a_callback_only_when_its_algorithm_is_on(tmp_path):
    root = print_project(tmp_path)
    environment = tool_path(tmp_path)
    make(root, environment)
    assert os.path.exists(os.path.join(root, "build", ML_DSA_OBJECT))

    shutil.rmtree(os.path.join(root, "build"))
    older_config(root, "oca_config.toml",
                 **{"variants.pqc": False, "signature_pqc.ml_dsa_87": False})
    make(root, environment)
    assert os.path.exists(os.path.join(root, "build", "app"))
    assert not os.path.exists(os.path.join(root, "build", ML_DSA_OBJECT))


def test_print_stops_the_build_on_a_misspelled_setting(tmp_path):
    """$(shell) discards the generator's exit status, so without the snippet's
    check a misspelled name would read as off."""
    misspelled = snippet("make", "--print signature_pqc.ml_dsa_87").replace(
        "signature_pqc.ml_dsa_87", "signature_pqc.ml_dsa_78")
    root = print_project(tmp_path, misspelled)
    result = make(root, tool_path(tmp_path), check=False)
    assert result.returncode != 0
    assert "cannot read signature_pqc.ml_dsa_78" in result.stderr
    assert not os.path.exists(os.path.join(root, "build", "app"))


# ---------------------------------------------------------------------------
# Committed headers
# ---------------------------------------------------------------------------

def committed_headers_project(tmp_path) -> str:
    root = adopter_project(tmp_path / "project")
    shutil.copy(build_config.DEFAULT_CONFIG, os.path.join(root, "board", "oca_default.toml"))
    shutil.copy(CLASSIC_ONLY_CONFIG, os.path.join(root, "board", "oca_classic_only.toml"))
    write(os.path.join(root, "Makefile"),
          f"OCA_LIB   := {VENDORED_LIB}\nOCA_BUILD := default\n"
          + snippet("make", "oca-config-regen:"))
    return root


def check_headers(root, environment) -> int:
    return run(["sh", "-c", snippet("sh", "--check")], root, environment,
               check=False).returncode


def test_regenerated_headers_pass_the_check(tmp_path):
    root = committed_headers_project(tmp_path)
    environment = tool_path(tmp_path)
    make(root, environment, "oca-config-regen")
    for build in ("default", "classic_only"):
        with open(os.path.join(root, "board", "oca_gen", build, GENERATED_HEADER)) as handle:
            header = handle.read()
        assert header == gen_config.header_for_config(
            os.path.join(root, "board", f"oca_{build}.toml"))
    assert check_headers(root, environment) == 0


def test_the_check_passes_a_comment_edit_and_fails_a_setting_edit(tmp_path):
    root = committed_headers_project(tmp_path)
    environment = tool_path(tmp_path)
    make(root, environment, "oca-config-regen")
    config = os.path.join(root, "board", "oca_classic_only.toml")
    with open(config, "a") as handle:
        handle.write("# Reviewed.\n")
    assert check_headers(root, environment) == 0
    with open(config) as handle:
        text = handle.read()
    with open(config, "w") as handle:
        handle.write(text.replace("toc_max_images = 256", "toc_max_images = 32"))
    assert check_headers(root, environment) == 1


# ---------------------------------------------------------------------------
# CMake
# ---------------------------------------------------------------------------

def cmake_project(tmp_path, generator) -> tuple[str, dict[str, str]]:
    """An adopter project built by the CMake snippet, configured for generator."""
    require_tools("cc", "cmake", *({"Ninja": ("ninja",)}.get(generator, ())))
    root = adopter_project(tmp_path / "project")
    write(os.path.join(root, "CMakeLists.txt"),
          CMAKE_PREFIX + snippet("cmake", "add_library(oca_validator") + CMAKE_SUFFIX)
    environment = tool_path(tmp_path)
    run(["cmake", "-S", root, "-B", os.path.join(root, "build"), "-G", generator],
        root, environment)
    return root, environment


def cmake_build(root, environment) -> str:
    return run(["cmake", "--build", os.path.join(root, "build")], root, environment).stdout


@CMAKE_GENERATORS
def test_the_cmake_snippet_builds_against_its_configuration(tmp_path, generator):
    root, environment = cmake_project(tmp_path, generator)
    assert built_objects(cmake_build(root, environment))
    assert app_digest(root) == digest_of(os.path.join(root, "board", "oca_config.toml"))


@CMAKE_GENERATORS
def test_the_cmake_snippet_rebuilds_nothing_when_nothing_changed(tmp_path, generator):
    root, environment = cmake_project(tmp_path, generator)
    cmake_build(root, environment)
    output = cmake_build(root, environment)
    assert built_objects(output) == []
    assert not ran_custom_command(output)


@CMAKE_GENERATORS
def test_the_cmake_snippet_recompiles_nothing_for_a_comment_edit(tmp_path, generator):
    root, environment = cmake_project(tmp_path, generator)
    cmake_build(root, environment)
    """The generator runs once for the edit and leaves the header alone, and the
    build after that has nothing to do."""
    with open(os.path.join(root, "board", "oca_config.toml"), "a") as handle:
        handle.write("# Reviewed.\n")
    output = cmake_build(root, environment)
    assert ran_custom_command(output)
    assert built_objects(output) == []
    output = cmake_build(root, environment)
    assert built_objects(output) == []
    assert not ran_custom_command(output)


@CMAKE_GENERATORS
def test_the_cmake_snippet_follows_a_switch_to_an_older_file(tmp_path, generator):
    root, environment = cmake_project(tmp_path, generator)
    cmake_build(root, environment)
    older = older_config(root, "older.toml",
                         **{"variants.pqc": False, "signature_pqc.ml_dsa_87": False})
    lists = os.path.join(root, "CMakeLists.txt")
    with open(lists) as handle:
        text = handle.read()
    assert text.count("/board/oca_config.toml") == 1
    with open(lists, "w") as handle:
        handle.write(text.replace("/board/oca_config.toml", "/board/older.toml"))
    age(os.path.join(root, "build"))
    assert built_objects(cmake_build(root, environment))
    assert app_digest(root) == digest_of(older)


@CMAKE_GENERATORS
def test_the_cmake_snippet_compiles_a_source_an_upgrade_adds(tmp_path, generator):
    """Without reconfiguring by hand: an existing build directory would
    otherwise fail to link once a function moves into a new file."""
    require_tools("ar")
    root, environment = cmake_project(tmp_path, generator)
    cmake_build(root, environment)
    add_library_source(root)
    cmake_build(root, environment)
    members = run(["ar", "t", os.path.join(root, "build", "liboca_validator.a")], root,
                  environment).stdout.split()
    assert ADDED_SOURCE + ".o" in members, members
