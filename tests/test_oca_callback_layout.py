# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The layout of the structs the library hands its callbacks.

A compiler chooses an enum's size, and -fshort-enums, or an ABI that makes it
the default, shrinks every enum to a byte. A struct with an enum member then
lays out differently in a library and a callback built with different
settings, and the callback reads its fields at the wrong offsets. The crypto
types the descriptors and callbacks carry are uint16_t, with an enum listing
their values, so the layout cannot depend on it; these tests compile the
public header both ways and require the same layout.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys

import pytest

from oca_fixtures import build_config

LIB_DIR = os.path.join(build_config.VALIDATOR_DIR, "lib")
GENERATOR = os.path.join(LIB_DIR, "scripts", "gen_config.py")

REQUIRE_VALIDATOR_ENV = "TT_BOOT_MANIFEST_REQUIRE_VALIDATOR"

# The crypto types, each a uint16_t whatever the compiler's enum size.
CRYPTO_TYPES = ["oca_key_algorithm_t", "oca_blob_kind_t", "oca_encoding_t",
                "oca_primitive_type_t", "oca_hash_type_t", "oca_encryption_type_t",
                "oca_kdf_t", "oca_key_source_t"]

# The members of the structs a callback receives that hold one of them, or the
# secret selector beside them.
FIXED_WIDTH_MEMBERS = {
    "oca_crypto_blob_t": ["kind", "encoding", "primitive_type", "key_algorithm"],
    "oca_decrypt_input_t": ["cipher", "kdf", "key_source", "secret_select"],
}
STRUCT_MEMBERS = {
    "oca_crypto_blob_t": ["bytes", "field_length", "length",
                          *FIXED_WIDTH_MEMBERS["oca_crypto_blob_t"]],
    "oca_decrypt_input_t": ["ciphertext", "ciphertext_len", "iv", "kdf_input",
                            *FIXED_WIDTH_MEMBERS["oca_decrypt_input_t"]],
}


def layout_probe() -> str:
    """C that prints every crypto type's size, every struct's size, and every
    member's offset and size."""
    lines = ['#include <stddef.h>', '#include <stdio.h>', '#include "oca_validator.h"',
             "int main(void)", "{"]
    for crypto_type in CRYPTO_TYPES:
        lines.append(f'    printf("{crypto_type} %zu\\n", sizeof({crypto_type}));')
    for struct, members in STRUCT_MEMBERS.items():
        lines.append(f'    printf("{struct} %zu\\n", sizeof({struct}));')
        for member in members:
            lines.append(f'    printf("{struct}.{member} %zu %zu\\n", '
                         f'offsetof({struct}, {member}), '
                         f'sizeof(((const {struct} *)0)->{member}));')
    lines += ["    return 0;", "}"]
    return "\n".join(lines) + "\n"


def require_cc():
    """Skip without a C compiler, or fail under the validator-required setting."""
    if shutil.which("cc") is None:
        if os.environ.get(REQUIRE_VALIDATOR_ENV):
            pytest.fail(f"needs cc ({REQUIRE_VALIDATOR_ENV} is set)")
        pytest.skip("needs cc")


def layout(tmp_path, lib_dir, *flags) -> dict[str, tuple[int, ...]]:
    """Compile the probe against lib_dir's header with flags, and run it."""
    gen = tmp_path / "gen"
    gen.mkdir(exist_ok=True)
    subprocess.run([sys.executable, GENERATOR, "--config", build_config.DEFAULT_CONFIG,
                    "--out", str(gen / "oca_config.h")], check=True)
    probe = tmp_path / "layout.c"
    probe.write_text(layout_probe())
    binary = tmp_path / ("layout" + "".join(flags).replace("-", "_"))
    built = subprocess.run(["cc", "-std=c99", "-Wall", "-Werror", *flags, "-I", str(lib_dir),
                            "-I", str(gen), str(probe), "-o", str(binary)],
                           capture_output=True, text=True)
    assert built.returncode == 0, built.stderr
    printed = subprocess.run([str(binary)], capture_output=True, text=True, check=True)
    return {words[0]: tuple(int(word) for word in words[1:])
            for words in (line.split() for line in printed.stdout.splitlines())}


def layout_differences(tmp_path, lib_dir=LIB_DIR) -> list[str]:
    """Every size or offset that moves under -fshort-enums."""
    default = layout(tmp_path, lib_dir)
    short = layout(tmp_path, lib_dir, "-fshort-enums")
    return [f"{name}: {default[name]} by default, {short[name]} with -fshort-enums"
            for name in default if default[name] != short[name]]


def test_the_callback_structs_lay_out_the_same_whatever_the_enum_size(tmp_path):
    require_cc()
    assert layout_differences(tmp_path) == []


def test_every_descriptor_field_is_two_bytes(tmp_path):
    require_cc()
    printed = layout(tmp_path, LIB_DIR, "-fshort-enums")
    for struct, members in FIXED_WIDTH_MEMBERS.items():
        for member in members:
            assert printed[f"{struct}.{member}"][1] == 2, f"{struct}.{member}"


def test_every_crypto_type_is_two_bytes(tmp_path):
    require_cc()
    printed = layout(tmp_path, LIB_DIR, "-fshort-enums")
    for crypto_type in CRYPTO_TYPES:
        assert printed[crypto_type] == (2,), crypto_type


def test_an_enum_member_is_reported(tmp_path):
    """The comparison is only worth having if it notices a member whose size
    follows the enum's, so one is planted in a copy of the header."""
    require_cc()
    lib = tmp_path / "lib"
    shutil.copytree(LIB_DIR, lib, ignore=shutil.ignore_patterns("scripts"))
    header = lib / "oca_validator.h"
    text = header.read_text()
    member = "    oca_kdf_t              kdf;\n"
    assert text.count(member) == 1
    header.write_text(text.replace(member, "    enum oca_kdf           kdf;\n"))
    differences = layout_differences(tmp_path, lib)
    assert any(difference.startswith("oca_decrypt_input_t.kdf:")
               for difference in differences), differences
