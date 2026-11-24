# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The tests compile with the compiler CC and CXX name, as make does.

CI runs the compiler tests once under gcc and once under clang by setting CC
and CXX, so a helper that ignored them would test one compiler twice.
"""

from __future__ import annotations

import os

import pytest
from ruamel.yaml import YAML

from oca_fixtures.build_config import PROJECT_ROOT
from oca_fixtures.toolchain import compiler_from_environment

TESTS_DIR = os.path.join(PROJECT_ROOT, "tests")
WORKFLOW = os.path.join(PROJECT_ROOT, ".github", "workflows", "ci.yml")
TOOLCHAIN_IMPORT = "from oca_fixtures.toolchain import"


def compiler_tests_in_ci() -> list[str]:
    """The test files CI runs under each compiler."""
    with open(WORKFLOW) as handle:
        return YAML(typ="safe").load(handle)["env"]["COMPILER_TESTS"].split()


def files_that_compile(directory=TESTS_DIR) -> list[str]:
    """Every test file in directory that compiles with the shared toolchain,
    as a path from the project root, apart from this one."""
    found = []
    for name in sorted(os.listdir(directory)):
        path = os.path.join(directory, name)
        if not name.startswith("test_") or not name.endswith(".py") or path == __file__:
            continue
        with open(path) as handle:
            if TOOLCHAIN_IMPORT in handle.read():
                found.append(os.path.relpath(path, PROJECT_ROOT))
    return found


def test_an_unset_variable_gives_the_default(monkeypatch):
    monkeypatch.delenv("CC", raising=False)
    assert compiler_from_environment("CC", "cc") == ["cc"]


def test_an_empty_variable_gives_the_default(monkeypatch):
    monkeypatch.setenv("CC", "")
    assert compiler_from_environment("CC", "cc") == ["cc"]


@pytest.mark.parametrize("value,command", [
    ("clang", ["clang"]),
    ("ccache gcc", ["ccache", "gcc"]),
    ("'/opt/my tools/gcc' -m32", ["/opt/my tools/gcc", "-m32"]),
])
def test_a_set_variable_names_the_command(monkeypatch, value, command):
    monkeypatch.setenv("CXX", value)
    assert compiler_from_environment("CXX", "c++") == command


def test_every_test_file_that_compiles_runs_under_each_compiler():
    """A test file that compiles but is missing from COMPILER_TESTS runs under
    gcc only. One listed but gone fails the CI step that names it."""
    assert sorted(compiler_tests_in_ci()) == files_that_compile()


def test_a_new_test_file_that_compiles_is_found(tmp_path):
    """Only a test file that imports the toolchain is found."""
    (tmp_path / "test_new.py").write_text(f"{TOOLCHAIN_IMPORT} C_COMPILER\n")
    (tmp_path / "test_other.py").write_text("import os\n")
    (tmp_path / "helper.py").write_text(f"{TOOLCHAIN_IMPORT} C_COMPILER\n")
    assert files_that_compile(str(tmp_path)) == [
        os.path.relpath(tmp_path / "test_new.py", PROJECT_ROOT)]
