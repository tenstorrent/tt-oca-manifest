# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The README's secure-boot signing configuration, packed as written.

README.md's "OCA manifest variants" section documents signing with a table of
the signature-class combinations, a classical YAML snippet, a hybrid YAML
snippet, and a recipe that turns the hybrid snippet into an ML-DSA-87-only one.
Every test here reads that section from the README itself, so a packer change
that falsifies the documentation, or a documentation edit the packer does not
honour, fails here.

The snippets name their keys by placeholder. The tests fill those with the
committed development keys, declared with `allow_test_signing_key` in place of
the conftest override, and add the fields every config needs that the snippets
leave out. The class bits, signing fields and manifest format are the README's.
"""

from __future__ import annotations

import os
import re
from typing import NamedTuple, Tuple

import pytest
from oca_fixtures import ML_DSA_87_KEY_PATH, RSA_3072_KEY_PATH, manifest_reader
from tt_boot_manifest.key_hygiene import ALLOW_CONFIG_FIELD, ALLOW_ENV_VAR
from tt_boot_manifest.oca import constants as oca_consts
from tt_boot_manifest.oca.entry import pack_oca_bundle
from tt_boot_manifest.oca.validators import OcaConfigError
from tt_boot_manifest.utils import load_config

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
README_PATH = os.path.join(PROJECT_ROOT, "README.md")
SECTION_HEADING = "### OCA manifest variants"
TABLE_MARKER = "`secure_boot_control`"

MAGIC_BY_FORMAT = {"oca-classic": oca_consts.OCAC_MAGIC, "oca-pqc": oca_consts.OCAP_MAGIC}

PLACEHOLDER_KEYS = {
    "<path to classical private key>": RSA_3072_KEY_PATH,
    "<path to ML-DSA-87 private key>": ML_DSA_87_KEY_PATH,
}

# Fields every config needs that the snippets leave out.
CONFIG_SCAFFOLD = {
    "manifest_identifier": "README1",
    "description": "README signing snippet",
    "timestamp": 1764633600,
    ALLOW_CONFIG_FIELD: True,
}

# What the classical snippet sets that is not a signing field of its class.
CLASSICAL_SNIPPET_NON_SIGNING = {"manifest_format", "secure_boot"}

CLASSICAL_DESCRIPTION = slice(oca_consts.OFF_SIGNATURE_TYPE_CLASSIC,
                              oca_consts.OFF_PUBLIC_KEY_CLASSIC_REVOKE)
PQC_DESCRIPTION = slice(oca_consts.OFF_SIGNATURE_TYPE_PQC, oca_consts.OFF_PUBLIC_KEY_PQC_REVOKE)
SIGNATURE_PQC = slice(oca_consts.OFF_SIGNATURE_PQC,
                      oca_consts.OFF_SIGNATURE_PQC + oca_consts.LEN_SIGNATURE_PQC)

ROW_NAMES = {(1, 0): "classical", (1, 1): "hybrid", (0, 1): "pqc-only"}


class SigningRow(NamedTuple):
    """One row of the README's signature-class table."""
    formats: Tuple[str, ...]
    classic: int
    pqc: int
    control: int
    classic_is_default: bool
    pqc_is_default: bool


def _section() -> str:
    """The README's "OCA manifest variants" section, up to the next heading."""
    with open(README_PATH, encoding="utf-8") as f:
        readme = f.read()
    assert SECTION_HEADING in readme, f"README.md lost its {SECTION_HEADING!r} section"
    return re.split(r"^#{2,3} ", readme.split(SECTION_HEADING, 1)[1], maxsplit=1, flags=re.M)[0]


def _sets_field(snippet: str, field: str) -> bool:
    return re.search(rf"^{field}:", snippet, re.M) is not None


def _snippet_fields(snippet: str) -> set:
    return set(re.findall(r"^([a-z_]+):", snippet, re.M))


def _snippets(section: str) -> dict:
    """The section's classical and hybrid YAML snippets, told apart by whether
    they set secure_boot_pqc."""
    blocks = re.findall(r"^```yaml\n(.*?)^```", section, re.S | re.M)
    classical = [b for b in blocks if not _sets_field(b, "secure_boot_pqc")]
    hybrid = [b for b in blocks if _sets_field(b, "secure_boot_pqc")]
    assert len(classical) == 1 and len(hybrid) == 1, (
        f"{SECTION_HEADING!r} should hold one classical and one hybrid YAML snippet; "
        f"found {len(classical)} and {len(hybrid)}")
    return {"classical": classical[0], "hybrid": hybrid[0]}


def _class_cell(cell: str) -> Tuple[int, bool]:
    return int(re.match(r"\d+", cell).group()), "(the default)" in cell


def _signing_table(section: str) -> list:
    """The rows of the signature-class table, keyed by its header names."""
    lines = section.splitlines()
    start = next((i for i, line in enumerate(lines)
                  if line.startswith("|") and TABLE_MARKER in line), None)
    assert start is not None, f"{SECTION_HEADING!r} lost its signature-class table"
    header = [cell.strip() for cell in lines[start].strip("|").split("|")]
    rows = []
    for line in lines[start + 2:]:
        if not line.startswith("|"):
            break
        cells = dict(zip(header, (cell.strip() for cell in line.strip("|").split("|"))))
        classic, classic_is_default = _class_cell(cells["`secure_boot_classic`"])
        pqc, pqc_is_default = _class_cell(cells["`secure_boot_pqc`"])
        rows.append(SigningRow(
            formats=tuple(re.findall(r"`(oca-[a-z]+)`", cells["Variant"])),
            classic=classic,
            pqc=pqc,
            control=int(cells[TABLE_MARKER].strip("`"), 16),
            classic_is_default=classic_is_default,
            pqc_is_default=pqc_is_default,
        ))
    return rows


SECTION = _section()
SNIPPETS = _snippets(SECTION)
ROWS = _signing_table(SECTION)
CLASSICAL_SIGNING_FIELDS = sorted(
    _snippet_fields(SNIPPETS["classical"]) - CLASSICAL_SNIPPET_NON_SIGNING)


def _row_id(row: SigningRow) -> str:
    return ROW_NAMES.get((row.classic, row.pqc), f"classic{row.classic}-pqc{row.pqc}")


def _row(classic: int, pqc: int) -> SigningRow:
    matches = [row for row in ROWS if (row.classic, row.pqc) == (classic, pqc)]
    assert len(matches) == 1, (
        f"the signature-class table has no single {ROW_NAMES[(classic, pqc)]} row")
    return matches[0]


def _config(snippet: str, tmp_path, **overrides) -> dict:
    """The snippet with its placeholders filled and the scaffold added."""
    for placeholder, key_path in PLACEHOLDER_KEYS.items():
        snippet = snippet.replace(placeholder, key_path)
    assert "<" not in snippet, f"unfilled placeholder in README snippet:\n{snippet}"
    config_path = tmp_path / "config.yaml"
    config_path.write_text(snippet, encoding="utf-8")
    cfg = load_config(str(config_path))
    assert cfg is not None, f"README snippet does not parse:\n{snippet}"

    image = tmp_path / "img.bin"
    image.write_bytes(b"\xDE\xAD\xBE\xEF\x90\x90\x90\x90")
    cfg.update(CONFIG_SCAFFOLD)
    cfg["payload_images"] = [{"type": "README1_BLSTAGE1", "path": str(image)}]
    cfg.update(overrides)
    return cfg


def _apply_pqc_only_recipe(cfg: dict, keep: Tuple[str, ...] = ()) -> dict:
    """The README's ML-DSA-87-only recipe: secure_boot_classic: 0 and the
    classical fields removed, except any named in `keep`."""
    cfg["secure_boot_classic"] = 0
    for field in CLASSICAL_SIGNING_FIELDS:
        if field not in keep:
            del cfg[field]
    return cfg


def _row_config(row: SigningRow, manifest_format: str, tmp_path) -> dict:
    """The README's configuration for a table row: the classical snippet, the
    hybrid snippet, or the hybrid snippet through the ML-DSA-87-only recipe."""
    if not row.pqc:
        return _config(SNIPPETS["classical"], tmp_path, manifest_format=manifest_format)
    cfg = _config(SNIPPETS["hybrid"], tmp_path, manifest_format=manifest_format)
    if not row.classic:
        _apply_pqc_only_recipe(cfg)
    return cfg


def _signature_classic(body: bytes) -> bytes:
    offset = (oca_consts.OFF_PQC_SIGNATURE_CLASSIC if body[:4] == oca_consts.OCAP_MAGIC
              else oca_consts.OFF_SIGNATURE_CLASSIC)
    return body[offset:offset + oca_consts.SIGNATURE_CLASSIC_SIZE]


@pytest.fixture(autouse=True)
def _no_test_key_override(monkeypatch):
    monkeypatch.delenv(ALLOW_ENV_VAR, raising=False)


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------


def test_the_table_lists_each_signature_class_combination_once():
    assert sorted((row.classic, row.pqc) for row in ROWS) == sorted(ROW_NAMES)


@pytest.mark.parametrize(
    "row,manifest_format",
    [(row, fmt) for row in ROWS for fmt in row.formats],
    ids=[f"{_row_id(row)}-{fmt}" for row in ROWS for fmt in row.formats],
)
def test_each_row_packs_to_its_control_byte_with_only_its_signatures(row, manifest_format,
                                                                     tmp_path):
    body = pack_oca_bundle(_row_config(row, manifest_format, tmp_path))
    assert body[:4] == MAGIC_BY_FORMAT[manifest_format]
    assert body[oca_consts.OFF_SECURE_BOOT_CONTROL] == row.control

    if row.classic:
        assert manifest_reader.classic_signature_valid(body)
    else:
        assert not any(body[CLASSICAL_DESCRIPTION])
        assert not any(_signature_classic(body))

    if row.pqc:
        assert manifest_reader.pqc_signature_valid(body)
    elif manifest_format == "oca-pqc":
        assert not any(body[PQC_DESCRIPTION])
        assert not any(body[SIGNATURE_PQC])


@pytest.mark.parametrize(
    "row,manifest_format",
    [(row, fmt) for row in ROWS for fmt in MAGIC_BY_FORMAT if fmt not in row.formats],
    ids=[f"{_row_id(row)}-{fmt}" for row in ROWS for fmt in MAGIC_BY_FORMAT
         if fmt not in row.formats],
)
def test_each_row_is_refused_on_a_variant_it_does_not_list(row, manifest_format, tmp_path):
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(_row_config(row, manifest_format, tmp_path))
    assert exc.value.field_name == "secure_boot_pqc"


def test_the_classical_snippet_leaves_out_the_class_bits_the_table_calls_defaults():
    row = _row(classic=1, pqc=0)
    assert row.classic_is_default and row.pqc_is_default
    assert not _sets_field(SNIPPETS["classical"], "secure_boot_classic")
    assert not _sets_field(SNIPPETS["classical"], "secure_boot_pqc")


def test_the_hybrid_snippet_sets_the_class_bits_its_row_gives(tmp_path):
    row = _row(classic=1, pqc=1)
    cfg = _config(SNIPPETS["hybrid"], tmp_path)
    assert (cfg["secure_boot_classic"], cfg["secure_boot_pqc"]) == (row.classic, row.pqc)
    assert cfg["manifest_format"] in row.formats


# ---------------------------------------------------------------------------
# The snippets and the recipe
# ---------------------------------------------------------------------------


def test_the_classical_snippet_names_its_variant_and_signing_fields():
    assert _sets_field(SNIPPETS["classical"], "manifest_format")
    assert {"signature_type", "signing_key_file"} <= set(CLASSICAL_SIGNING_FIELDS)


def test_the_classical_fields_describe_the_same_signature_on_either_variant(tmp_path):
    bodies = [pack_oca_bundle(_config(SNIPPETS["classical"], tmp_path, manifest_format=fmt))
              for fmt in MAGIC_BY_FORMAT]
    assert bodies[0][CLASSICAL_DESCRIPTION] == bodies[1][CLASSICAL_DESCRIPTION]


def test_the_hybrid_snippet_keeps_the_classical_fields(tmp_path):
    classical = _config(SNIPPETS["classical"], tmp_path)
    hybrid = _config(SNIPPETS["hybrid"], tmp_path)
    for field in CLASSICAL_SIGNING_FIELDS:
        assert hybrid.get(field) == classical[field], field


@pytest.mark.parametrize("field", CLASSICAL_SIGNING_FIELDS)
def test_the_pqc_only_recipe_refuses_a_leftover_classical_field(field, tmp_path):
    cfg = _apply_pqc_only_recipe(_config(SNIPPETS["hybrid"], tmp_path), keep=(field,))
    with pytest.raises(OcaConfigError) as exc:
        pack_oca_bundle(cfg)
    assert exc.value.field_name == field
