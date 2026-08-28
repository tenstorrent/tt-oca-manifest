#!/usr/bin/env python3

import pytest
import unittest.mock
import os
import subprocess
import sys
import textwrap

from botocore.exceptions import ClientError
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec, padding

from tt_boot_manifest.utils import load_config, convert_to_int
from tt_boot_manifest.manifest_signing import *
from tt_boot_manifest.pack_images_constants import *

# Repo root, so the -O subprocesses below resolve the installed package the same
# way the test session does.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def load_default_config() -> dict:
    """Minimal signing config (inlined; previously loaded from a packing YAML)."""
    return {
        'primary': {
            'manifest': {
                # "TBL1" — a BL1 manifest, exercising the BL1-must-use-RSA restriction.
                'manifest_identifier': 0x314c4254,
                'boot_arguments': {'secure_boot': 1},
                'signature_type': 1,  # 1: RSA, 2: ECDSA
                'signing_authority': 'local',
                'signing_key_name': 'test_dev_rom_key_0',
                'signing_key_id': '1234567890',
                'signing_key_file': '$ROOT/tests/signing_keys/rsa_private_key.dev0.pem',
            }
        }
    }


dummy_message_to_sign = b'Hello Tenstorrent. This is is a test message we will sign \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# Testing Only Keys - Loaded from Environment Variables
# Set these in your environment before running AWS tests:
#   export AWS_KMS_TEST_ECC_0="your-ecc-key-id"
#   export AWS_KMS_TEST_RSA_0="your-rsa-key-id"
AWS_KMS_TEST_ECC_0 = os.environ.get("AWS_KMS_TEST_ECC_0", "")
AWS_KMS_TEST_RSA_0 = os.environ.get("AWS_KMS_TEST_RSA_0", "")



@pytest.fixture(autouse=True)
def validate_aws_env_vars(request):
    """Validate that required AWS KMS environment variables are set for AWS tests."""
    # Only run this validation for tests marked with 'aws'
    if 'aws' in [mark.name for mark in request.node.iter_markers()]:
        missing_vars = []

        if not AWS_KMS_TEST_ECC_0:
            missing_vars.append("AWS_KMS_TEST_ECC_0")
        if not AWS_KMS_TEST_RSA_0:
            missing_vars.append("AWS_KMS_TEST_RSA_0")

        if missing_vars:
            pytest.skip(
                f"Missing required environment variables: {', '.join(missing_vars)}\n"
                f"These are required for AWS KMS signing tests.\n"
                f"Please set them before running tests with '-m aws':\n"
                + "\n".join(f"  export {var}=<your-key-id>" for var in missing_vars)
            )


### General Tests ###

def test_prepare_signing_key_unknown_authority():
      test_config = load_default_config()
      test_manifest = test_config['primary']['manifest']
      test_manifest['signing_authority'] = 'unknown'
      secure_boot = 1
      with pytest.raises(ValueError, match="Unknown object type"):
          prepare_signing_key(test_manifest, secure_boot)

def test_signature_size_validation():
      test_config = load_default_config()
      test_manifest = test_config['primary']['manifest']
      signing_key = prepare_signing_key(test_manifest, 1)

      # Test oversized signature
      signing_key.signature_bytes = b'x' * (SIGNATURE_FIELD_SIZE + 1)
      with pytest.raises(ValueError, match="Invalid signature length"):
          signing_key.validate_signature_size()

def test_check_rsa_private_key_invalid():
      # Test with wrong key type
      ec_key = ec.generate_private_key(ec.SECP256R1())

      with pytest.raises(AssertionError):
          check_rsa_private_key(ec_key)

def test_check_ec_private_key_invalid():
    # Test with wrong key type
    rsa_key = rsa.generate_private_key(65537, 2048)

    with pytest.raises(AssertionError):
        check_ec_private_key(rsa_key)

def test_check_ec_private_key_wrong_curve():
    # Test with wrong curve
    wrong_curve_key = ec.generate_private_key(ec.SECP384R1())

    with pytest.raises(AssertionError):
        check_ec_private_key(wrong_curve_key)

### Local Signing Tests #####

def test_no_signing_key_operations():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    secure_boot = 0
    no_key = prepare_signing_key(test_manifest, secure_boot)

    assert isinstance(no_key, NoSigningKey)
    assert no_key.sign_data(dummy_message_to_sign) == bytearray()
    assert no_key.verify_signature(dummy_message_to_sign) == True

def test_prepare_signing_key_local_rsa():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    secure_boot = convert_to_int(test_manifest['boot_arguments']['secure_boot'])
    local_signing_key = prepare_signing_key(test_manifest, secure_boot)
    assert isinstance(local_signing_key, LocalKey)
    assert local_signing_key.name == 'test_dev_rom_key_0'
    assert local_signing_key.signature_type == 1
    assert local_signing_key.signing_authority == 'local'
    assert local_signing_key.signature_digest == b''
    assert local_signing_key.public_key_bytes == \
    (b'\xa3\xdf\xd9\xa80\x1d\xfa\xbaDkI\x04t_\x0b\xb3\xa9\xc0\x8fcm\xc9\xb5\xf2'
    +  b'\x02bv\xab\xf4|R\x1aW\xdd\x80\xc1#\x98\xcb\xb0\xe7\xf4\x1b>\x14HW;8\xd9\xacF'
    +  b'\xcb\x8c\xbb\x1eXl<\xd2\xc66\x97\x04\x1aC\xc8\x93\n\xffG\x0eQDi\x94M\x993N'
    +  b'\x9dnL\x97<\x7f\xd1\xfdc\x0c\x0c\xb4_\x15\xa9\xb7\xb2\xc9\xab\xa4'
    +  b'\x9c\x81\xecW0\xb8\x99\xb8\xc5\xd8\x81\xc7\x95\xf8\x98_\xeaB\x197'
    +  b'\x88\x1e\xe8\x81\xf2\xeaVE\x86\xea\xceg\x97\xa0\xd4h\xfb;M\xa5lg-x'
    +  b'D\xac\xef\xa1CSa\xf3k7z_\x1bRjt.L{\xfbR\xecfU(\x1a\x04\xfd\xd3\xda>\xf0'
    +  b"\x86%\xae\x1f\xcc'\x85F-\xfe\xfd\xd3\xea\x05_\xad\xd2\xfcx\x01\x95\xce\n\x83"
    +  b'm\xd0\xab7^L\x98\xbe\x1e\x95\x9d\xb8\x1b\xe5\xba\xad\xeb\x90\xf4<'
    +  b'\xb5\xe2;\xca\xa15\xa0\xb5A\xdb4\x0b\xb0y=\xbe\xd5\x8a\xd6\x97'
    +  b'\xc0\xb1\x0b\xe9\xcc:\xfc4$\xa0|\xc9\x82O \x1de\xb2\x16?D\x98\x18\x0c'
    +  b'M-\x8d\xa2Ct*O_\xbe\x9f\xdb\x8f`\x96<a\xab\xc5\x11k\xc1|\x0f\x9f\xedX\x02'
    +  b'\x87\xec\xceL\xe8h\xfe\x137\xeb\xea\x00\xef\xa0\x04\x03\x84\x19+\x03'
    +  b'\x18\xc0Cutq\xba.}\x10\xcf\xd9i.2wBFyWOP\x16\\v\x80a9\xe3K#\x1e'
    +  b'\x8f\xbd\x18\x97\x97hM\xec\xcduI\x8c\xd5\xca\x01L\xe6\xcf\x05y'
    +  b'\x90\xc5\x9b\xa7y\xac\xd5\xa2\xaf\xf598a\x88}\xf0\x1e\xb9|\x19')


def test_prepare_signing_key_local_ecc():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    # override defaults for ECC key and signature type
    test_manifest['signing_key_file'] = "$ROOT/tests/signing_keys/ec_private_key.pem"
    test_manifest['signature_type'] = ManifestSignatureType.ECC_P_256.value
    test_manifest['signing_key_name'] = "ecdsa_test_key"
    # Mark the manifest as being for BL2 to get around ECC signing restrictions
    test_manifest['manifest_identifier'] = 0x324c4254
    secure_boot = convert_to_int(test_manifest['boot_arguments']['secure_boot'])
    local_signing_key = prepare_signing_key(test_manifest, secure_boot)
    assert local_signing_key.name == 'ecdsa_test_key'
    assert local_signing_key.signature_type == ManifestSignatureType.ECC_P_256.value
    assert local_signing_key.signing_authority == 'local'
    assert local_signing_key.signature_digest == b''
    assert local_signing_key.public_key_bytes == \
    (b'\xb0\x76\x05\xe4\x3a\xf7\x50\xb3\xde\x79\xe3\x17\xad\xb8\xde\x07\x76\xda'
    + b'\x58\x8b\xe3\x45\xfe\x63\x08\x17\x46\xdc\xb1\xc1\x8f\xf0\x42\x8f\x38\x32'
    + b'\xf9\x87\x87\x65\x33\xdf\xb8\x08\xa0\x8e\x24\x12\xe4\xd4\xbc\xaa\xfe\xb1'
    + b'\x24\xad\x81\x23\x2f\x42\x0b\x0a\x22\x61')



def test_generate_verified_signature_local_rsa():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    secure_boot = convert_to_int(test_manifest['boot_arguments']['secure_boot'])
    local_signing_key = prepare_signing_key(test_manifest, secure_boot)
    signature = local_signing_key.generate_verified_signature(dummy_message_to_sign)
    assert len(signature) == 384


def test_generate_verified_signature_local_ecc():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    # override defaults for ECC key and signature type
    test_manifest['signing_key_file'] = "$ROOT/tests/signing_keys/ec_private_key.pem"
    test_manifest['signature_type'] = ManifestSignatureType.ECC_P_256.value
    test_manifest['signing_key_name'] = "ecdsa_test_key"
    # Mark the manifest as being for BL2 to get around ECC signing restrictions
    test_manifest['manifest_identifier'] = 0x324c4254
    secure_boot = convert_to_int(test_manifest['boot_arguments']['secure_boot'])
    local_signing_key = prepare_signing_key(test_manifest, secure_boot)
    signature = local_signing_key.generate_verified_signature(dummy_message_to_sign)
    assert len(signature) == 64


def test_verify_signature_without_signing():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    signing_key = prepare_signing_key(test_manifest, 1)

    # Try to verify without having a signature
    with pytest.raises(TypeError):
        signing_key.verify_signature(dummy_message_to_sign)

def test_digest_message():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    signing_key = prepare_signing_key(test_manifest, 1)

    signing_key.digest_message(dummy_message_to_sign)
    assert len(signing_key.signature_digest) == 32  # SHA256 digest size
    assert signing_key.signature_digest != b''

### AWS KMS Signing Tests #####

@pytest.mark.aws
def test_aws_credential_probe():
    aws_credentials_verify()

@pytest.mark.aws
def test_aws_credentials_verify_invalid():
    # Mock invalid credentials scenario

    with unittest.mock.patch('boto3.client') as mock_client:
        mock_sts = unittest.mock.Mock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {'Error': {'Code': 'InvalidUserID.NotFound'}},
            'GetCallerIdentity'
        )
        mock_client.return_value = mock_sts
        with pytest.raises(SigningError, match="credentials are invalid"):
            aws_credentials_verify()

@pytest.mark.aws
def test_aws_invalid_key_id():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    test_manifest['signing_key_id'] = 'invalid-key-id'
    test_manifest['signing_authority'] = 'aws'

    with pytest.raises(SigningError, match="unable to read public key"):
        prepare_signing_key(test_manifest, 1)


@pytest.mark.aws
def test_prepare_signing_key_kms_rsa():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    # overrides for test KMS RSA Key
    test_manifest['signing_key_file'] = ""
    test_manifest['signature_type'] = 1
    test_manifest['signing_authority'] = 'aws'
    test_manifest['signing_key_name'] = "kms_sep_test_rsa_0"
    test_manifest['signing_key_id'] = AWS_KMS_TEST_RSA_0
    # Setup KMS RSA Key from updated manifest config
    secure_boot = convert_to_int(test_manifest['boot_arguments']['secure_boot'])
    kms_signing_key = prepare_signing_key(test_manifest, secure_boot)
    assert isinstance(kms_signing_key, AWSKey)
    assert kms_signing_key.name == 'kms_sep_test_rsa_0'
    assert kms_signing_key.signature_type == 1
    assert kms_signing_key.signing_authority == 'aws'
    assert kms_signing_key.keyID == AWS_KMS_TEST_RSA_0
    assert kms_signing_key.signature_digest == b''
    assert len(kms_signing_key.public_key_bytes) == 384


@pytest.mark.aws
def test_generate_verified_signature_kms_rsa():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    # overrides for test KMS RSA Key
    test_manifest['signing_key_file'] = ""
    test_manifest['signature_type'] = 1
    test_manifest['signing_authority'] = 'aws'
    test_manifest['signing_key_name'] = "kms_sep_test_rsa_0"
    test_manifest['signing_key_id'] = AWS_KMS_TEST_RSA_0
    # Setup KMS RSA Key from updated manifest config
    secure_boot = convert_to_int(test_manifest['boot_arguments']['secure_boot'])
    kms_signing_key = prepare_signing_key(test_manifest, secure_boot)
    signature = kms_signing_key.generate_verified_signature(dummy_message_to_sign)
    assert len(signature) == 384

@pytest.mark.aws
def test_generate_verified_signature_kms_dev_rsa_0():
    """Test signing with AWS_KMS_TEST_RSA_0 and verifying with release public key"""
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    # overrides for dev KMS RSA Key
    test_manifest['signing_key_file'] = ""
    test_manifest['signature_type'] = 1
    test_manifest['signing_authority'] = 'aws'
    test_manifest['signing_key_name'] = "kms_rom_rsa_0"
    test_manifest['signing_key_id'] = AWS_KMS_TEST_RSA_0
    # Setup KMS RSA Key from updated manifest config
    secure_boot = convert_to_int(test_manifest['boot_arguments']['secure_boot'])
    kms_signing_key = prepare_signing_key(test_manifest, secure_boot)

    # Sign the dummy message using AWS KMS
    kms_signing_key.sign_data(dummy_message_to_sign)
    assert len(kms_signing_key.signature_bytes) == 384

    # Load the corresponding public key from the AWS key object
    # public_key_bytes contains raw modulus bytes, not ASN.1 encoded
    modulus = int.from_bytes(kms_signing_key.public_key_bytes, byteorder='big')
    public_numbers = rsa.RSAPublicNumbers(PUBLIC_EXPONENT, modulus)
    public_key = public_numbers.public_key()

    # Verify the signature using the loaded public key
    try:
        public_key.verify(
            kms_signing_key.signature,
            dummy_message_to_sign,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_valid = True
    except Exception as e:
        signature_valid = False
        pytest.fail(f"Signature verification failed: {e}")

    assert signature_valid, "Signature verification should succeed"

@pytest.mark.aws
def test_prepare_signing_key_kms_ecc():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    # overrides for test KMS RSA Key
    test_manifest['signing_key_file'] = ""
    test_manifest['signature_type'] = ManifestSignatureType.ECC_P_256.value
    test_manifest['signing_authority'] = 'aws'
    test_manifest['signing_key_name'] = "kms_sep_test_ecc_0"
    test_manifest['signing_key_id'] = AWS_KMS_TEST_ECC_0
    # Mark the manifest as being for BL2 to get around ECC signing restrictions
    test_manifest['manifest_identifier'] = 0x324c4254
    # Setup KMS RSA Key from updated manifest config
    secure_boot = convert_to_int(test_manifest['boot_arguments']['secure_boot'])
    kms_signing_key = prepare_signing_key(test_manifest, secure_boot)
    assert kms_signing_key.name == 'kms_sep_test_ecc_0'
    assert kms_signing_key.signature_type == ManifestSignatureType.ECC_P_256.value
    assert kms_signing_key.signing_authority == 'aws'
    assert kms_signing_key.keyID == AWS_KMS_TEST_ECC_0
    assert kms_signing_key.signature_digest == b''
    assert len(kms_signing_key.public_key_bytes) ==  64


@pytest.mark.aws
def test_generate_verified_signature_kms_ecc():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    # overrides for test KMS RSA Key
    test_manifest['signing_key_file'] = ""
    test_manifest['signature_type'] = ManifestSignatureType.ECC_P_256.value
    test_manifest['signing_authority'] = 'aws'
    test_manifest['signing_key_name'] = "kms_sep_test_ECC_0"
    test_manifest['signing_key_id'] = AWS_KMS_TEST_ECC_0
    # Mark the manifest as being for BL2 to get around ECC signing restrictions
    test_manifest['manifest_identifier'] = 0x324c4254
    # Setup KMS RSA Key from updated manifest config
    secure_boot = convert_to_int(test_manifest['boot_arguments']['secure_boot'])
    kms_signing_key = prepare_signing_key(test_manifest, secure_boot)
    signature = kms_signing_key.generate_verified_signature(dummy_message_to_sign)
    assert len(signature) == 64


### HSM Signing Tests ###

@pytest.mark.hsm
def test_hsm_key_not_implemented():
    test_config = load_default_config()
    test_manifest = test_config['primary']['manifest']
    test_manifest['signing_authority'] = 'hsm'
    hsm_key = prepare_signing_key(test_manifest, 1)

    with pytest.raises(SigningError, match="HSM Signing Not Yet Supported"):
        hsm_key.sign_data(dummy_message_to_sign)

    with pytest.raises(SigningError, match="HSM Signing Not Yet Supported"):
        hsm_key.verify_signature(dummy_message_to_sign)


# ---------------------------------------------------------------------------
# Validation must not depend on an interpreter flag
#
# `python -O` (PYTHONOPTIMIZE=1) strips every `assert` statement. When check()
# and the OCA layout guards were bare asserts, running the packer under -O
# silently disabled the RSA key-size, EC curve, and signature-algorithm checks
# and every manifest byte-layout invariant — a build could sign with a
# wrong-sized key and report success. These tests run the guards in a real -O
# subprocess so a regression to `assert` fails here rather than in a release.
# ---------------------------------------------------------------------------

def _run_guard_snippet(body: str, optimize: bool) -> subprocess.CompletedProcess:
    """Run `body` in a subprocess, with or without -O.

    A subprocess is the only honest way to test this: -O is decided when the
    interpreter starts, so it cannot be toggled from inside a running test.
    """
    argv = [sys.executable]
    if optimize:
        argv.append("-O")
    argv += ["-c", textwrap.dedent(body)]
    return subprocess.run(argv, capture_output=True, text=True, cwd=PROJECT_ROOT)


_WRONG_KEY_TYPE_SNIPPET = """
    from cryptography.hazmat.primitives.asymmetric import ec
    from tt_boot_manifest.manifest_signing import check_rsa_private_key
    try:
        check_rsa_private_key(ec.generate_private_key(ec.SECP256R1()))
    except Exception as exc:
        print(f"RAISED:{type(exc).__name__}")
    else:
        print("NOT_RAISED")
"""

_BAD_LAYOUT_SNIPPET = """
    from tt_boot_manifest.oca import manifest as oca_manifest
    try:
        # A signed region one byte short must never be accepted: the
        # manifest_hash would cover the wrong span.
        oca_manifest.build_unsigned_tail(
            signed_region=b"\\x00" * 3144,      # 3145 is correct for Classic
            manifest_hash_field=b"\\x00" * 64,
            payload_offset=4096,
        )
    except Exception as exc:
        print(f"RAISED:{type(exc).__name__}")
    else:
        print("NOT_RAISED")
"""


@pytest.mark.parametrize("optimize", [False, True], ids=["no-O", "with-O"])
def test_key_type_check_survives_optimize_flag(optimize):
    """check()-based key validation fires with and without -O."""
    result = _run_guard_snippet(_WRONG_KEY_TYPE_SNIPPET, optimize)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("RAISED:"), (
        f"an EC key passed to the RSA validator was accepted under "
        f"{'-O' if optimize else 'default'} — check() must not be a bare assert; "
        f"stdout={result.stdout!r}"
    )


@pytest.mark.parametrize("optimize", [False, True], ids=["no-O", "with-O"])
def test_oca_layout_guard_survives_optimize_flag(optimize):
    """OCA manifest byte-layout guards fire with and without -O."""
    result = _run_guard_snippet(_BAD_LAYOUT_SNIPPET, optimize)
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("RAISED:"), (
        f"a short signed region was accepted under "
        f"{'-O' if optimize else 'default'} — the layout guards must not be bare "
        f"asserts; stdout={result.stdout!r}"
    )


def test_check_error_is_still_an_assertion_error():
    """CheckError subclasses AssertionError on purpose, so the many existing
    `pytest.raises(AssertionError)` expectations and any external caller that
    catches AssertionError keep working. Changing the base class is a breaking
    change for them; this test makes that explicit rather than incidental."""
    from tt_boot_manifest.utils import CheckError

    assert issubclass(CheckError, AssertionError)
    with pytest.raises(AssertionError):
        check(False, "boom")
