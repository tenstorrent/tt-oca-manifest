# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""OCA boot manifest format support.

This subpackage implements producer-side generation of OCA boot manifests plus the
associated `PTOC` payload table of contents. Both on-disk variants flow through one
assembly path, selected by the config's `manifest_format`:

    oca-classic   `OCAC` magic, 4096-byte body
    oca-pqc       `OCAP` magic, 36864-byte body (a superset of the Classic layout)

It is structurally self-contained: modules outside this subpackage are only used
for shared signing, encryption, and config-loading utilities.

Public entry point:
    pack_oca_bundle(config, output_path=None, verbose=False) -> bytes

The full OCA boot manifest specification is published at
https://www.openchipletatlas.org/specifications/oca/latest.
"""

from .entry import pack_oca_bundle

__all__ = ["pack_oca_bundle"]
