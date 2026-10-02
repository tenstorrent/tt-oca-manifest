#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""The suite runs without the `aws` extra installed.

boto3 is an optional dependency: only `signing_authority: aws` needs it, and
`src/manifest_signing.py` imports it inside the functions that use it. A test
module that imports boto3 or botocore at module scope breaks that for the whole
suite, not only for the AWS tests, because collection errors out and pytest runs
nothing. These tests run pytest in a subprocess with both modules unimportable,
so the property is checked whether or not the extra is installed here.
"""

import os
import subprocess
import sys
import textwrap

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# A None entry in sys.modules makes importing that module raise
# ModuleNotFoundError, the same error an uninstalled package produces.
_PYTEST_WITHOUT_BOTO3 = """
    import sys
    sys.modules["boto3"] = None
    sys.modules["botocore"] = None
    import pytest
    sys.exit(pytest.main(sys.argv[1:]))
"""

# Every variable an aws-marked test checks before skipping for missing key ids.
AWS_KEY_ID_ENV_VARS = ("AWS_KMS_TEST_ECC_0", "AWS_KMS_TEST_RSA_0", "AWS_KMS_TEST_KEY_ID")


def _run_pytest_without_boto3(args, env=None):
    """Run pytest over the suite in a subprocess where boto3 cannot be imported."""
    argv = [sys.executable, "-c", textwrap.dedent(_PYTEST_WITHOUT_BOTO3),
            "-p", "no:cacheprovider", *args]
    return subprocess.run(argv, capture_output=True, text=True, cwd=PROJECT_ROOT, env=env)


def _tail(result):
    """The end of a subprocess's output, enough to show a collection error."""
    return result.stdout[-4000:] + result.stderr[-2000:]


def test_suite_collects_without_boto3():
    """Every test module imports cleanly with boto3 and botocore absent."""
    result = _run_pytest_without_boto3(["--collect-only", "-q"])
    assert result.returncode == 0, (
        "collection fails without the aws extra; does a test module import boto3 "
        "or botocore at module scope?\n" + _tail(result))


def test_aws_tests_skip_without_boto3():
    """aws-marked tests skip and name the missing extra; they do not error.

    The KMS key-id variables get dummy values so the tests' own skip for unset
    key ids cannot stand in for this one. Without the boto3 skip these tests
    reach the signing code and fail there.
    """
    env = dict(os.environ, **{var: "unused-key-id" for var in AWS_KEY_ID_ENV_VARS})
    result = _run_pytest_without_boto3(["-m", "aws", "-rs"], env=env)
    assert result.returncode == 0, _tail(result)

    summary = result.stdout.strip().splitlines()[-1]
    assert "skipped" in summary, summary
    for outcome in ("passed", "failed", "error"):
        assert outcome not in summary, summary
    assert "aws extra" in result.stdout, _tail(result)
