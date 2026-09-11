# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
import logging
import re
from ruamel.yaml import YAML
from cryptography.hazmat.primitives import hashes
from .pack_images_constants import *

disable_checks = False

logger = logging.getLogger(__name__)

def int_to_bytes_le(value, length):
    # Pads on the right, which is where a little-endian value's high-order
    # zero bytes belong.
    byte_array = value.to_bytes((value.bit_length() + 7) // 8, 'little')
    return byte_array.ljust(length, b'\x00')

def int_to_bytes_be(value, length):
    return value.to_bytes(length, byteorder='big', signed=False)

def convert_to_int(value):
    if isinstance(value, int):
        return value

    if isinstance(value, float):
        return int(value)

    if isinstance(value, str):
        # Strings are always base 16, with or without the prefix: a bare '10'
        # from a config is 16, not ten.
        if re.match(r'^0x[0-9a-fA-F]+$', value) or re.match(r'^[0-9a-fA-F]+$', value):
            return int(value, 16)
        else:
            raise ValueError(f"Invalid hexadecimal string: {value}")

    raise TypeError(f"Unsupported type for conversion: {type(value)}")

def generate_sha256_hash(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    hash_value = digest.finalize()
    assert SHA256_DIGEST_SIZE_BYTES == len(hash_value), \
        f"Invalid digest length {len(hash_value)} should be equal to {SHA256_DIGEST_SIZE_BYTES}"
    return hash_value

def enable_checking():
    global disable_checks
    disable_checks = False
    logger.debug("checks are enabled during this packing process")

def disable_checking():
    global disable_checks
    disable_checks = True
    logger.warning("checks are disabled during this packing process")

class CheckError(AssertionError):
    """A `check()` invariant failed.

    Subclasses AssertionError because that is what the bare `assert` this
    replaced used to raise, so existing callers and tests that catch
    AssertionError keep working unchanged.

    The reason it is a `raise` and not an `assert`: `python -O` (equivalently
    PYTHONOPTIMIZE=1) strips assert statements entirely. Every guard routed
    through `check()` would then silently vanish — including the RSA key-size,
    EC curve, and signature-algorithm checks in `manifest_signing`, which is
    how a build could sign with a wrong-sized key and report success. A build
    tool must not have a validation posture that depends on an interpreter flag.
    """


def check(condition, message) -> bool:
    if disable_checks:
        if not condition:
            logger.warning(message)
        return True

    if not condition:
        raise CheckError(message)
    return False

def checking_disabled():
    return disable_checks

def load_config(config_path):
    yaml = YAML()
    yaml.preserve_quotes = True
    try:
        with open(config_path, "r", encoding='utf-8') as yaml_data:
            try:
                config_data = yaml.load(yaml_data)
                return config_data
            except Exception as exc:
                logger.error(f"Failed to parse YAML in '{config_path}': {exc}")
                return None
    except FileNotFoundError:
        logger.error(f"Configuration file not found: '{config_path}'")
        return None
    except PermissionError:
        logger.error(f"Permission denied reading configuration file: '{config_path}'")
        return None
    except IsADirectoryError:
        logger.error(f"Expected a file but found a directory: '{config_path}'")
        return None
    except IOError as exc:
        logger.error(f"Failed to read configuration file '{config_path}': {exc}")
        return None