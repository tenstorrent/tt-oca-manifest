#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.

import logging
import os
from abc import ABC, abstractmethod
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, utils
from cryptography.hazmat.backends import default_backend
from .pack_images_constants import *
from .utils import int_to_bytes_be, check

logger = logging.getLogger(__name__)

class SigningError(Exception):
    """A signing or verification operation failed."""

class SigningKey(ABC):
    """One signing authority, built from a manifest config.

    Holds the key and signature parameters the manifest declares, and the
    signature bytes in the fixed-width form the manifest carries. Subclasses
    supply sign_data() and verify_signature() for local keys, AWS KMS, or an HSM.
    """

    def __init__(self, manifest, secure_boot):
        """Read the signing parameters out of `manifest`.

        With secure boot off the key is forced to NO_SIGNATURE, so a
        non-secure bundle can never carry signature bytes. With secure boot on
        and an unsupported signature type, `check()` raises — unless checks are
        globally disabled, in which case it returns True and the key degrades to
        an unsigned one, which is how deliberately malformed test bundles are
        built.
        """
        self.name = manifest['signing_key_name']
        self.signature_type = manifest['signature_type']
        self.signing_authority = manifest['signing_authority']
        self.keyID = manifest['signing_key_id']
        self.public_key = None  # each subclass will populate this with either an EllipticCurvePublicKey or RSAPublicKey
        self.public_key_bytes = b''
        self.signature_digest = b''
        self.signature = None
        self.signature_bytes = b''
        self.signature_verified = False
        self.hash_func = hashes.SHA256  # every supported signature type digests with SHA-256
        self.min_pub_key_size = 0
        self.min_signature_size = 0
        self.secure_boot = secure_boot
        self.no_signature = False  # support generation of manifests with broken/bad signature related values for testing
        if self.secure_boot == 1:
            if self.signature_type == ManifestSignatureType.RSA_3072.value:
                self.min_pub_key_size = RSA_3072_KEY_SZ_BYTES
                self.min_signature_size = RSA_3072_KEY_SZ_BYTES
            elif self.signature_type == ManifestSignatureType.ECC_P_256.value:
                self.min_pub_key_size = EC_256_KEY_SZ_BYTES*2
                self.min_signature_size = EC_256_KEY_SZ_BYTES*2
            else:
                self.no_signature = check(self.signature_type in [ManifestSignatureType.ECC_P_256.value, ManifestSignatureType.RSA_3072.value],
                                          f'invalid signature type {self.signature_type} for secure boot being enabled')
        else:
            self.signature_type = ManifestSignatureType.NO_SIGNATURE.value
            self.no_signature = True

    def validate_signature_size(self):
        """Raise unless the signature fits the manifest's fixed signature field
        and is at least the size the configured algorithm produces."""
        # the signature bytes to be written into a manifest can never be larger than the designated size of the signature manifest field
        max_sz = SIGNATURE_FIELD_SIZE
        if len(self.signature_bytes) > max_sz or len(self.signature_bytes) < self.min_signature_size:
            raise ValueError(f"Invalid signature length: {len(self.signature_bytes)}. \
                            Max size for type {self.signature_type} is {max_sz}, min size is {self.min_signature_size}.")

    def validate_public_key_size(self):
        """Raise unless the public key fits the manifest's fixed key field and is
        at least the size the configured algorithm requires."""
        max_sz = PUBLIC_KEY_FIELD_SIZE
        if len(self.public_key_bytes) > max_sz or len(self.public_key_bytes) < self.min_pub_key_size:
            raise ValueError(f"Invalid public key length: {len(self.public_key_bytes)}. \
                            Max size for type {self.signature_type} is {max_sz}, min size is {self.min_pub_key_size}.")

    def generate_verified_signature(self, data) -> bytes:
        """Sign `data`, then verify the result before returning it.

        A signature that will not verify against its own public key is a
        SigningError here rather than a manifest the boot ROM rejects in the
        field. Returns empty bytes for a key configured not to sign.
        """
        # For test cases where secure boot is enabled but signature verification is disable; use this path
        if self.no_signature:
            self.signature_bytes = b''
            self.signature_verified = True
            return self.signature_bytes
        try:
            self.sign_data(data)
            if not self.verify_signature(data):
                raise SigningError(f'failed to verify generated signature with public key material')
            return self.signature_bytes
        except Exception as e:
            raise SigningError(f'failed to generate signature for data using {self.name} private key via {self.signing_authority}: {e}')

    def digest_message(self, data):
        """Hash `data` and cache it, for authorities that sign a digest rather
        than the message itself."""
        hasher = hashes.Hash(self.hash_func())
        hasher.update(data)
        self.signature_digest = hasher.finalize()

    def add_signature(self, signature_value):
        """Record a raw signature and re-encode it the way the manifest carries
        it: RSA zero-padded to the field width, ECDSA decoded from DER to a
        fixed-width r || s."""
        self.signature = signature_value
        if self.signature_type == ManifestSignatureType.RSA_3072.value:
            # Pad out the provided signature value to the maximum size of 384 bytes for insertion into manifests)
            self.signature_bytes = self.signature.rjust(SIGNATURE_FIELD_SIZE, b'\x00')
        elif self.signature_type == ManifestSignatureType.ECC_P_256.value:
            # Manifests carry r||s fixed-width; the library returns RFC 3279 DER.
            r, s = utils.decode_dss_signature(self.signature)
            r_bytes = r.to_bytes(EC_256_KEY_SZ_BYTES, byteorder='big')
            s_bytes = s.to_bytes(EC_256_KEY_SZ_BYTES, byteorder='big')
            self.signature_bytes = r_bytes + s_bytes
        self.signature_verified = False

    @abstractmethod
    def sign_data(self, data: bytes):
        """Generate a cryptographic signature for the provided data.

        This method must be implemented by subclasses to provide signing functionality
        specific to their signing authority (local keys, AWS KMS, HSM, etc.).

        Args:
            data: The data to be signed

        Returns:
            The signature bytes
        """
        pass

    @abstractmethod
    def verify_signature(self, data: bytes) -> bool:
        """Verify a signature against the provided data.

        This method must be implemented by subclasses to provide verification functionality
        specific to their signing authority (local keys, AWS KMS, HSM, etc.).

        Args:
            data: The data that was signed

        Returns:
            True if signature is valid, False otherwise
        """
        pass

#######################################################################
################ Non-secure boot empty key object #####################
#######################################################################
class NoSigningKey(SigningKey):
    """The authority used when secure boot is off: signs nothing, and reports
    verification as passed so the unsigned path runs to completion."""

    def __init__(self, manifest, secure_boot):
        super().__init__(manifest, secure_boot)

    def sign_data(self, data: bytes):
        """Return an empty signature."""
        logger.debug(f'passing through signing method and returning empty signature')
        return bytearray()

    def verify_signature(self, data: bytes):
        """Report success without checking anything."""
        logger.debug(f'passing through verification method and signature check was successful')
        self.signature_verified = True
        return self.signature_verified


#######################################################################
################ Local Key File Management and Signing ################
#######################################################################
class LocalKey(SigningKey):
    """Signing backed by a PEM private key file on the build host.

    A development affordance: the key is readable by every process on the host
    and by whatever the build system logs, so production manifests are expected
    to sign through `aws` or `hsm`.
    """

    def __init__(self, manifest, secure_boot):
        """Load the PEM key named by `signing_key_file` and derive the manifest's
        public-key bytes, rejecting a key that does not match the configured
        signature type."""
        super().__init__(manifest, secure_boot)

        if self.signature_type == ManifestSignatureType.NO_SIGNATURE.value:
            return

        with open(os.path.expandvars(manifest['signing_key_file']), "rb") as key_file:
            self.private_key = serialization.load_pem_private_key(key_file.read(), password=None)

        self.public_key = self.private_key.public_key()
        if self.signature_type == ManifestSignatureType.RSA_3072.value:
            check_rsa_private_key(self.private_key)
            self.public_key_bytes = get_rsa_public_key_bytes(self.private_key)
        elif self.signature_type == ManifestSignatureType.ECC_P_256.value:
            check_ec_private_key(self.private_key)
            self.public_key_bytes = get_ec_public_key_bytes(self.private_key)


    def sign_data(self, data):
        """Sign `data` with the loaded private key using the configured primitive."""
        logger.debug(f'sig generation for data len {len(data)} with key {self.name}')
        if self.signature_type == ManifestSignatureType.ECC_P_256.value and\
            isinstance(self.private_key, ec.EllipticCurvePrivateKey):
            ecdsa_signature = self.private_key.sign(
                data,
                ec.ECDSA(self.hash_func(), deterministic_signing=True)
            )
            self.add_signature(ecdsa_signature)
            return self.signature_bytes

        if self.signature_type == ManifestSignatureType.RSA_3072.value and\
                isinstance(self.private_key, rsa.RSAPrivateKey):
            signature_result = self.private_key.sign(
                data,
                padding.PKCS1v15(),
                self.hash_func()
            )
            self.add_signature(signature_result)
            return self.signature_bytes

        if self.signature_type == ManifestSignatureType.NO_SIGNATURE.value:
            return bytearray()

        raise ValueError(f"Unsupported signature type {self.signature_type} private key {self.private_key.__class__}")

    def verify_signature(self, data):
        """Verify the stored signature against `data` with the matching public key."""
        logger.debug(f'sig verification for data len {len(data)} with key {self.name}')
        if self.signature_type == ManifestSignatureType.ECC_P_256.value and\
            isinstance(self.public_key, ec.EllipticCurvePublicKey):
            # ECDSA signature
            self.public_key.verify(
                self.signature,
                data,
                ec.ECDSA(self.hash_func(), deterministic_signing=True)
            )
            self.signature_verified = True
            return self.signature_verified

        if self.signature_type == ManifestSignatureType.RSA_3072.value and\
                isinstance(self.public_key, rsa.RSAPublicKey):
            # RSA signature
            self.public_key.verify(
                self.signature,
                data,
                padding.PKCS1v15(),
                self.hash_func()
            )
            self.signature_verified = True
            return self.signature_verified

        if self.signature_type == ManifestSignatureType.NO_SIGNATURE.value:
            return self.signature_verified

        raise ValueError(f"Unsupported signature type {self.signature_type} public key {self.public_key.__class__}")

#######################################################################
################# AWS KMS Management and Signing #####################
#######################################################################
def aws_credentials_verify():
    """
    This function attempts to confirm valid AWS credentials are present in a path
    the boto3 AWS API package can use to reach out to AWS
    **NOTE** This function does not verify the available credentials provide access to signing key
    material that may be requested later. Each key has it's own permission where a user may have access to
    the public, signing using the private key, or neither/both of those.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        raise SigningError("boto3 is required for AWS KMS signing. Install it with: pip install tt-oca-manifest[aws]")

    try:
        sts = boto3.client('sts')
        response = sts.get_caller_identity()
        logger.debug(f"Credentials are valid. Account ID: {response['Account']}")
    except ClientError as e:
        raise SigningError(f"credentials are invalid. Error: {e}")


class AWSKey(SigningKey):
    """Signing delegated to AWS KMS: the private key never reaches this host.

    Only the public key is fetched; signing and verification are KMS calls over
    the message digest. Requires the `aws` extra and valid credentials.
    """

    def __init__(self, manifest, secure_boot):
        '''Init function for AWS KMS signing key key object'''
        super().__init__(manifest, secure_boot)
        try:
            import boto3
        except ImportError:
            raise SigningError("boto3 is required for AWS KMS signing. Install it with: pip install tt-oca-manifest[aws]")

        # Credentials are checked before any key material is read, so an expired
        # session fails here rather than inside a signing call. Refresh with the
        # `aws-sso` console script.
        client = boto3.client('kms')
        aws_credentials_verify()

        try:
            response = client.get_public_key(
                KeyId=self.keyID
            )
        except Exception as e:
            raise SigningError(f'unable to read public key for {self.name}({self.keyID}) - check credentials or key permission: {e}')

        self.public_key = serialization.load_der_public_key(response['PublicKey'], backend=default_backend)
        if self.signature_type == ManifestSignatureType.RSA_3072.value:
            check_rsa_public_key(self.public_key)
            rsa_modulus = self.public_key.public_numbers().n
            self.public_key_bytes = int_to_bytes_be(rsa_modulus, RSA_3072_KEY_SZ_BYTES)
        elif self.signature_type == ManifestSignatureType.ECC_P_256.value:
            check_ec_public_key(self.public_key)
            ec_x = self.public_key.public_numbers().x
            ec_y = self.public_key.public_numbers().y
            ec_x_bytes = int_to_bytes_be(ec_x, EC_256_KEY_SZ_BYTES)
            ec_y_bytes = int_to_bytes_be(ec_y, EC_256_KEY_SZ_BYTES)
            logger.debug(f"ECDSA Public Key:\n\
                X: {ec_x}\n{ec_x_bytes.hex()} {len(ec_x_bytes)} bytes\n\
                Y: {ec_y}\n{ec_y_bytes.hex()} {len(ec_y_bytes)} bytes")
            self.public_key_bytes =  ec_x_bytes + ec_y_bytes

        self.validate_public_key_size()
        self.get_signing_algorithm()


    def get_signing_algorithm(self):
        ''' Set the AWS KMS specific names for each signing primitive'''
        if self.signature_type == ManifestSignatureType.ECC_P_256.value:
            self.signing_algorithm = 'ECDSA_SHA_256'
            return
        if self.signature_type == ManifestSignatureType.RSA_3072.value:
            self.signing_algorithm = 'RSASSA_PKCS1_V1_5_SHA_256'
            return
        raise ValueError(f"Unsupported signing type {self.signature_type} for AWS KMS signing")


    def sign_data(self, data):
        '''Generate a cryptographic signature for the provided data given the key/signing type
        specified in this signing key object'''

        try:
            import boto3
            from botocore.exceptions import ClientError
        except ImportError:
            raise SigningError("boto3 is required for AWS KMS signing. Install it with: pip install tt-oca-manifest[aws]")


        logger.debug(f'AWS KMS sig generation for data len {len(data)} with key {self.name}')
        if self.signature_digest == b'':
            self.digest_message(data)
        logger.debug(f'digest of message to be signed: {self.signature_digest}')

        client = boto3.client('kms')
        response = client.sign(
            KeyId=self.keyID,
            Message=self.signature_digest,
            MessageType='DIGEST',
            SigningAlgorithm=self.signing_algorithm,
        )
        logger.debug(f'signing request for key {response["KeyId"]} returned {response["ResponseMetadata"]}')
        if response["ResponseMetadata"]['HTTPStatusCode'] != 200:
            raise SigningError(f'signing request for key {response["KeyId"]} has invalid return code {response["ResponseMetadata"]["HTTPStatusCode"]}')

        self.add_signature(response['Signature'])
        self.validate_signature_size()
        self.signature_verified = False
        return self.signature_bytes


    def verify_signature(self, data):
        """Ask KMS to verify the stored signature over the cached digest."""
        if self.signature_digest == b'':
            # if no digest of the message has already been generated, calculate it now
            self.digest_message(data)
        logger.debug(f'digest of message to be signed: {self.signature_digest}')

        try:
            import boto3
            from botocore.exceptions import ClientError
        except ImportError:
            raise SigningError("boto3 is required for AWS KMS signing. Install it with: pip install tt-oca-manifest[aws]")

        client = boto3.client('kms')
        response = client.verify(
            KeyId=self.keyID,
            Message=self.signature_digest,
            MessageType='DIGEST',
            Signature=self.signature,
            SigningAlgorithm=self.signing_algorithm,
            DryRun=False
        )
        logger.debug(f'signature verify request for key {response["KeyId"]} returned {response["ResponseMetadata"]}')
        if response["ResponseMetadata"]['HTTPStatusCode'] != 200:
            raise SigningError(f'signature verify request for key {response["KeyId"]} has invalid return code {response["ResponseMetadata"]["HTTPStatusCode"]}')

        self.signature_verified = response['SignatureValid']
        return self.signature_verified

#######################################################################
################## Internal HSM Management and Signing ################
#######################################################################
class HSMKey(SigningKey):
    """Reserved slot for HSM-backed signing. Every operation refuses: a partial
    implementation must not ship."""

    def __init__(self, manifest, secure_boot):
        super().__init__(manifest, secure_boot)

    def sign_data(self, data):
        """Always raises: HSM signing is not implemented."""
        raise SigningError("HSM Signing Not Yet Supported")

    def verify_signature(self, data):
        """Always raises: HSM verification is not implemented."""
        raise SigningError("HSM Signing Not Yet Supported")



def prepare_signing_key(manifest: dict, secure_boot: int) -> SigningKey:
    """Build the signing key named by the manifest's `signing_authority`.

    Returns a NoSigningKey when secure boot is off. Otherwise rejects a
    signature type this packer does not support, and refuses anything but
    RSA-3072 for a 'TBL1' manifest, before constructing the authority's key.
    """

    if secure_boot != 1:
        return NoSigningKey(manifest, secure_boot)

    key_authority_mapping = {
        "local": LocalKey,
        "aws": AWSKey,
        "hsm": HSMKey,
    }

    sig_type = manifest['signature_type']
    manifest_identifier = manifest['manifest_identifier']
    check(sig_type in [ManifestSignatureType.ECC_P_256.value, ManifestSignatureType.RSA_3072.value],
        f'invalid signature type {sig_type} for secure boot being enabled')
    # BL0 only support RSA signatures for secure boot authentication
    # Reject any request to sign BL1 manifests with other signature algos (ECC for example)
    if manifest_identifier == 0x314c4254:
        check(sig_type == ManifestSignatureType.RSA_3072.value,
            f'BL1 manifest signing is only allowed to use RSA-3072 signatures - signature type requested: {sig_type}')

    signing_authority = manifest["signing_authority"]
    signing_class = key_authority_mapping.get(signing_authority)

    if signing_class:
        return signing_class(manifest, secure_boot)
    else:
        raise ValueError(f"Unknown object type: '{signing_authority}'. Valid types are 'local', 'aws', 'hsm'.")


def check_rsa_private_key(key, expected_size=RSA_3072_KEY_SZ_BITS):
    """Raise unless `key` is an RSA private key of `expected_size` bits."""
    check(isinstance(key, rsa.RSAPrivateKey), f"Key {key} is not an RSA private key")
    check(key.key_size == expected_size, f"RSA key size {key.key_size} is not {expected_size} bits")

def check_ec_private_key(key, expected_curve=ec.SECP256R1):
    """Raise unless `key` is an EC private key on `expected_curve`."""
    check(isinstance(key, ec.EllipticCurvePrivateKey), f"Key {key.__class__} is not an EC private key")
    check(isinstance(key.curve, expected_curve), f"EC key {key.curve} is not using the {expected_curve.name}")

def check_rsa_public_key(key, expected_size=RSA_3072_KEY_SZ_BITS):
    """Raise unless `key` is an RSA public key of `expected_size` bits."""
    check(isinstance(key, rsa.RSAPublicKey), f"Key {key} is not an RSA public key")
    check(key.key_size == expected_size, f"RSA key size {key.key_size} is not {expected_size} bits")

def check_ec_public_key(key, expected_curve=ec.SECP256R1):
    """Raise unless `key` is an EC public key on `expected_curve`."""
    check(isinstance(key, ec.EllipticCurvePublicKey), f"Key {key.__class__} is not an EC public key")
    check(isinstance(key.curve, expected_curve), f"EC key {key.curve} is not using the {expected_curve.name}")

def get_ec_public_key_bytes(ec_private_key):
    """Return the manifest encoding of an EC public key: X || Y, each big-endian
    and padded to the curve's field width."""
    check_ec_private_key(ec_private_key)
    ec_public_key = ec_private_key.public_key()
    ec_x = ec_public_key.public_numbers().x
    ec_y = ec_public_key.public_numbers().y
    ec_x_bytes = int_to_bytes_be(ec_x, EC_256_KEY_SZ_BYTES)
    ec_y_bytes = int_to_bytes_be(ec_y, EC_256_KEY_SZ_BYTES)
    logger.debug(f"ECDSA Public Key:\n\
          X: {ec_x}\n{ec_x_bytes.hex()} {len(ec_x_bytes)} bytes\n\
          Y: {ec_y}\n{ec_y_bytes.hex()} {len(ec_y_bytes)} bytes")
    return ec_x_bytes + ec_y_bytes

def get_rsa_public_key_bytes(rsa_private_key):
    """Return the manifest encoding of an RSA public key: the modulus,
    big-endian and padded to the key width."""
    check_rsa_private_key(rsa_private_key)
    rsa_public_key = rsa_private_key.public_key()
    rsa_modulus = rsa_public_key.public_numbers().n
    rsa_modulus_bytes = int_to_bytes_be(rsa_modulus, RSA_3072_KEY_SZ_BYTES)
    logger.debug(f"RSA Public Key:\n\
          Modulus: {rsa_modulus}\n{rsa_modulus_bytes.hex()} {len(rsa_modulus_bytes)} bytes")
    return rsa_modulus_bytes
