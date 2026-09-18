#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""
Pytest configuration: anchor the test session at the repo root, and declare the
development-key opt-in for the whole suite.

OCA tests and example configs use repo-relative paths and $ROOT expansion
(e.g. $ROOT/tests/signing_keys/...), so resolve both once per session.
"""

import os
from pathlib import Path

project_root = Path(__file__).parent.parent
os.chdir(project_root)
os.environ['ROOT'] = str(project_root)

# The suite signs hundreds of manifests with the committed development keys,
# most of them from config dicts built inline in the test bodies. Declaring the
# opt-in once here covers all of them and keeps a newly added test from failing
# on a guard it has no reason to know about. Committed *config files* use the
# `allow_test_signing_key` field instead — see tt_boot_manifest.key_hygiene.
os.environ['TT_BOOT_MANIFEST_ALLOW_TEST_KEY'] = '1'
