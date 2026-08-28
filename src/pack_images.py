#!/usr/bin/env python3
"""CLI entry point and format dispatch for OCA boot-manifest packing.

Selects the packer from the config's `manifest_format` and renders
OcaConfigError rejections as single-line `error:` messages on stderr.
"""

import argparse
import logging
import sys

from .oca import combined as oca_combined
from .oca import entry as oca_entry
from .oca.validators import OcaConfigError
from .utils import load_config

logger = logging.getLogger(__name__.strip('_'))

ALLOWED_FORMATS = ('oca-classic', 'oca-pqc', 'oca-combined')


def setup_logging(verbose):
    """ Setup logger, at INFO level by default, or DEBUG if verbose is true."""
    level = logging.INFO
    if verbose:
        level = logging.DEBUG
    logging.basicConfig(level=level, format='pack_images: %(levelname)s: %(message)s')


def _format_error_reason(manifest_format) -> str:
    allowed = ", ".join(repr(fmt) for fmt in ALLOWED_FORMATS)
    if manifest_format is None:
        return f"missing; allowed: {allowed}"
    return f"unknown value {manifest_format!r}; allowed: {allowed}"


def _print_oca_config_error(e) -> None:
    # CLI-side error rendering (single-line, fail-fast, no output bytes).
    if e.deferred_feature:
        print(
            f"error: OCA feature deferred to future pass: "
            f"{e.deferred_feature} (field {e.field_name})",
            file=sys.stderr,
        )
    else:
        print(f"error: {e.field_name}: {e.reason}", file=sys.stderr)


def generate_images(config_data) -> list:
    logger.debug(f"Input config data:\n{config_data}")

    manifest_format = config_data.get('manifest_format')
    if manifest_format in ('oca-classic', 'oca-pqc'):
        bundle_bytes = oca_entry.pack_oca_bundle(config_data)
        return [bundle_bytes]
    if manifest_format == 'oca-combined':
        image_bytes = oca_combined.pack_combined_image(config_data)
        return [image_bytes]
    raise ValueError(f"manifest_format: {_format_error_reason(manifest_format)}")


def pack_images(config_path: str, output_path: str, verbose: bool) -> bool:
    setup_logging(verbose)
    config_data = load_config(config_path)
    if config_data is None:
        return False

    manifest_format = config_data.get('manifest_format')
    if manifest_format not in ALLOWED_FORMATS:
        print(
            f"error: manifest_format: {_format_error_reason(manifest_format)}",
            file=sys.stderr,
        )
        return False

    try:
        if manifest_format == 'oca-combined':
            blob = oca_combined.pack_combined_image(
                config_data, output_path=output_path, verbose=verbose
            )
        else:
            blob = oca_entry.pack_oca_bundle(
                config_data, output_path=output_path, verbose=verbose
            )
    except OcaConfigError as e:
        _print_oca_config_error(e)
        return False
    return blob is not None and len(blob) > 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, required=True)
    parser.add_argument("--out", type=str, required=True)
    parser.add_argument("-v", "--verbose", action='store_true')

    args = parser.parse_args()

    ok = pack_images(args.config, args.out, args.verbose)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
