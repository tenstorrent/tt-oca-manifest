#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""
Pytest configuration: anchor the test session at the repo root.

OCA tests and example configs use repo-relative paths and $ROOT expansion
(e.g. $ROOT/tests/signing_keys/...), so resolve both once per session.
"""

import os
from pathlib import Path

project_root = Path(__file__).parent.parent
os.chdir(project_root)
os.environ['ROOT'] = str(project_root)
