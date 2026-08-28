"""
Tenstorrent OCA Boot Manifest - Firmware packaging and signing tools

This package provides tools for constructing, signing, and encrypting
Open Chiplet Atlas (OCA) boot manifest bundles.

Note: Modules use absolute imports and are intended to be run as scripts.
To use individual modules, import them by name after ensuring dependencies are available.
"""

__version__ = "0.5.0"

__all__ = [
    "pack_images",
    "manifest_signing",
    "utils",
    "aes128cbc",
    "aes256cbc",
    "pack_images_constants",
    "oca",
]
