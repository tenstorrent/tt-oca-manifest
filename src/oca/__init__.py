# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""OCA-classic boot manifest format support.

This subpackage implements producer-side generation of OCA-classic boot manifests
(`OCAC` magic, 4096-byte body) plus the associated payload TOC. It is structurally
self-contained: modules outside this subpackage are only used for shared signing,
encryption, and config-loading utilities.

Public entry point:
    pack_oca_bundle(config, output_path, verbose=False)

The full OCA AsciiDoc spec lives at `specifications/oca/boot-manifest.adoc`.
"""

from .entry import pack_oca_bundle

__all__ = ["pack_oca_bundle"]
