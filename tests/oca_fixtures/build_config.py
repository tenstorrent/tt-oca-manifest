# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Validator build configurations for tests, written from the shipped default.

A test states only the settings it changes; every other setting takes the
value `lib/oca_config.toml` states. Adding a setting to the generator and the
shipped default therefore changes no test's configuration.
"""

from __future__ import annotations

import os
import re
import tomllib

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VALIDATOR_DIR = os.path.join(PROJECT_ROOT, "validators", "oca")
DEFAULT_CONFIG = os.path.join(VALIDATOR_DIR, "lib", "oca_config.toml")
VALIDATOR_README = os.path.join(VALIDATOR_DIR, "README.md")

# A row of the README's Settings table: `[section] key` and its `default`.
_SETTINGS_ROW = re.compile(r"^\| `\[(\w+)\] (\w+)` \| `([^`]+)` \|", re.M)


def toml_text(value) -> str:
    """A value as TOML text. A string is taken as TOML text already, so a test
    can state a value the generator refuses."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    return value


def config_text(changes: dict | None = None, extra: str = "") -> str:
    """The shipped default with each `section.key` in changes set to its value.

    A value is a bool, an int, or a string of TOML text; None leaves the key
    out. A key the default does not state is added to its section, and a
    section it does not have is added at the end. extra is appended as given.
    """
    with open(DEFAULT_CONFIG, "rb") as handle:
        document = tomllib.load(handle)
    sections = {section: {key: toml_text(value) for key, value in table.items()}
                for section, table in document.items()}
    for name, value in (changes or {}).items():
        section, key = name.split(".")
        table = sections.setdefault(section, {})
        if value is None:
            table.pop(key, None)
        else:
            table[key] = toml_text(value)
    blocks = [f"[{section}]\n" + "".join(f"{key} = {value}\n" for key, value in table.items())
              for section, table in sections.items()]
    return "\n".join(blocks) + extra


def documented_defaults() -> dict[str, int]:
    """Each setting's default as the validator README's Settings table states
    it, by `section.key` name; true and false are 1 and 0."""
    with open(VALIDATOR_README) as handle:
        text = handle.read()
    return {f"{section}.{key}": {"true": 1, "false": 0}.get(value) if value in ("true", "false")
            else int(value)
            for section, key, value in _SETTINGS_ROW.findall(text)}
