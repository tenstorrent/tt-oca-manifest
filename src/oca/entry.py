# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Top-level OCA bundle generation entry point (oca-classic and oca-pqc).

Wired into `src/pack_images.py` via deferred import when
`config['manifest_format']` is `'oca-classic'` or `'oca-pqc'`.

Pipeline:
  0. reject_deferred_features(config)
  1. validate_and_normalize_oca_classic(config)
  2. Build signing key (secure_boot=1 only)
  3. Assemble payload (TOC + image bytes)
  4. Compute payload_hash + payload_hash_chain
  5. Build signed region (with public_key_classic embedded when signing)
  6. Compute manifest_hash over signed region
  7. Sign the signed region (secure_boot=1 only) → 512-byte signature_classic field
  8. Build unsigned tail with manifest_hash + signature_classic
  9. Concatenate manifest_body + payload → bundle bytes
  10. Write to disk if output_path is given
"""

from __future__ import annotations

import logging
import os
from typing import Optional

from . import constants as oca_consts
from . import encryption
from .manifest import build_signed_region, build_unsigned_tail, compute_manifest_hash
from .payload import assemble_multi_image_payload, compute_payload_hashes
from .signing import (
    build_signing_key,
    declared_signature_size,
    encode_public_key,
    sign_signed_region,
)
from .validators import (
    OcaConfigError,
    OcaLayoutError,
    reject_deferred_features,
    validate_and_normalize_oca_classic,
)

logger = logging.getLogger(__name__)


def pack_oca_bundle(
    config: dict,
    output_path: Optional[str] = None,
    verbose: bool = False,
) -> bytes:
    """Generate an OCA bundle (manifest body + payload) for the configured variant.

    Dispatches on `manifest_format`: `oca-classic` builds the Classic variant,
    `oca-pqc` the PQC variant (a superset layout). Returns the bundle bytes; if
    `output_path` is given, also writes them to disk.
    """
    # Variant selection.
    manifest_format = config.get("manifest_format", "oca-classic")
    variant = (
        oca_consts.PQC_VARIANT if manifest_format == "oca-pqc"
        else oca_consts.CLASSIC_VARIANT
    )

    # 0. Reject deferred features FIRST.
    reject_deferred_features(config)

    # 1. Validate + normalize.
    normalized = validate_and_normalize_oca_classic(config)

    logger.info("%s: manifest_identifier=%s timestamp: %d",
                variant.format_name,
                normalized["manifest_identifier_bytes"].rstrip(b"\x00").decode("ascii"),
                normalized["timestamp"])

    # 2. Signing key (only on the secure-boot path).
    #
    # Both `*_size_classic` values are resolved here, before the signed region is
    # built, because both fields live inside that region. The key's size is its
    # real encoded length; the signature's is what the algorithm and encoding
    # will produce, which cannot be measured yet — see declared_signature_size().
    signing_key = None
    public_key_classic_field = None
    public_key_size_classic = 0
    signature_size_classic = 0
    if normalized["secure_boot"] == 1:
        signature_type = int(config["signature_type"])
        signing_key = build_signing_key(config)
        encoded_key = encode_public_key(
            signing_key,
            encoding=normalized["public_key_encoding"],
            signature_type=signature_type,
        )
        public_key_classic_field = encoded_key.field
        public_key_size_classic = encoded_key.size
        signature_size_classic = declared_signature_size(
            signature_type, normalized["signature_encoding"]
        )

    # 3. Assemble the cleartext payload (TOC + images).
    images = normalized["payload_images"]
    payload_bytes, toc_byte_count, entry_ranges = assemble_multi_image_payload(images)

    # 4. Optional payload encryption (AES-256-CBC or AES-128-CBC per encryption_type;
    #    key derived from the pre-shared secret via SP 800-108r1 CTR-HMAC-SHA-256 over
    #    the 192-byte expanded input block). The whole payload is encrypted; the IV and
    #    KDF input are supplied for a reproducible build or generated and recorded.
    encryption_fields = None
    stored_payload = payload_bytes
    payload_hashed_length = toc_byte_count
    ciphertext = None
    resolved_iv = resolved_kdf_input = None
    iv_generated = kdf_generated = False
    if normalized["encrypted_payload"]:
        provider = encryption.build_encryption_provider(config)
        resolved_iv, iv_generated = encryption.resolve_iv(config)
        resolved_kdf_input, kdf_generated = encryption.resolve_kdf_input(config)
        ciphertext = provider.encrypt(payload_bytes, resolved_kdf_input, resolved_iv)
        stored_payload = ciphertext
        payload_hashed_length = len(ciphertext)
        control = (
            oca_consts.ENCRYPTION_CONTROL_ENCRYPTED_PAYLOAD_BIT
            | (oca_consts.ENCRYPTION_INPUT_KEY_SOURCE_PRESHARED
               << oca_consts.ENCRYPTION_INPUT_KEY_SOURCE_SHIFT)
        )
        encryption_fields = {
            "control": control,
            "kdf": normalized["encryption_kdf"],
            "shared_secret_select": normalized["encryption_shared_secret_select"],
            "type": normalized["encryption_type"],
            "iv": resolved_iv,
            "kdf_input": resolved_kdf_input,
        }

    # 5. Payload-level hashes: chain over the plaintext; payload_hash over the
    #    stored bytes (ciphertext when encrypted, else the cleartext TOC).
    payload_hash_field, payload_hash_chain_field = compute_payload_hashes(
        payload_bytes, toc_byte_count, entry_ranges, ciphertext=ciphertext
    )

    # 6. Signed region. Includes public_key_classic when signing and the
    #    encryption parameters when encrypting.
    signed_region = build_signed_region(
        normalized,
        payload_hash_field=payload_hash_field,
        payload_hash_chain_field=payload_hash_chain_field,
        payload_length=len(stored_payload),
        payload_hashed_length=payload_hashed_length,
        public_key_classic_field=public_key_classic_field,
        public_key_size_classic=public_key_size_classic,
        signature_size_classic=signature_size_classic,
        encryption=encryption_fields,
        variant=variant,
    )

    # 7. Manifest hash over the signed region.
    manifest_hash_field = compute_manifest_hash(signed_region, variant=variant)

    # 8. Signature over the signed region (secure_boot=1 only).
    signature_field = None
    if signing_key is not None:
        signature_field = sign_signed_region(
            signed_region, signing_key,
            encoding=normalized["signature_encoding"],
            declared_size=signature_size_classic,
        )

    # 9. Unsigned tail.
    payload_offset = variant.body_size  # no verifier/co-signer entries in this pass
    unsigned_tail = build_unsigned_tail(
        signed_region,
        manifest_hash_field=manifest_hash_field,
        payload_offset=payload_offset,
        signature_classic_field=signature_field,
        variant=variant,
    )

    # 10. Concatenate manifest body + stored payload.
    manifest_body = signed_region + unsigned_tail
    if len(manifest_body) != variant.body_size:
        # The last line of defense before a bundle is written: a raise, not an
        # assert, so `python -O` cannot let a wrong-sized signed body through.
        raise OcaLayoutError(
            f"OCA {variant.format_name} manifest body must be {variant.body_size} "
            f"bytes, got {len(manifest_body)}"
        )
    bundle = manifest_body + stored_payload

    # 11. Optional disk write + reproducibility side-car for generated inputs.
    if output_path is not None:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "wb") as fh:
            fh.write(bundle)
        logger.info("%s: wrote %d bytes to %s", variant.format_name, len(bundle), output_path)
        if encryption_fields is not None and (iv_generated or kdf_generated):
            sidecar = encryption.write_encrypt_inputs_sidecar(
                output_path,
                manifest_hash_field[:oca_consts.MANIFEST_HASH_DIGEST_SIZE],
                resolved_iv,
                resolved_kdf_input,
                iv_generated,
                kdf_generated,
            )
            if sidecar is not None:
                logger.info("%s: recorded generated encryption inputs to %s",
                            variant.format_name, sidecar)

    return bundle
