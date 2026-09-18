<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc. -->
# Test signing keys

**These are disposable keys generated solely to run this repository's test
suite. They are published deliberately, they are not secret, and they have
never signed a production artifact.**

Do not use any key in this directory for anything but running the tests.

| File | Key | Used by |
|---|---|---|
| `rsa_private_key.f4.pem` | RSA-3072, e=F4 (65537) | the default signing path in most producer tests |
| `rsa_private_key.e3.pem` | RSA-3072, e=3 | coverage of the small-public-exponent path |
| `ec_private_key.pem` | ECDSA P-256 | coverage of the ECC signing path |

The test suite needs real, parseable private keys — signing and verification are
what it is testing, so the keys cannot be stubs or fixtures. They are checked in
so that a clone can run `pytest` and `make -C validators/oca check` with no
setup and no credentials, and so that signature outputs stay reproducible across
machines and CI runs.

Release keys, key digests, and pre-signed manifests are **not** stored in this
repository. Obtain them from the signing authority for your program. See the
[Using the Lower-Level API](../../README.md#using-the-lower-level-api) section
of the top-level README.

Because these keys are public, any manifest signed with them proves nothing
about its origin. A consumer enforcing secure boot must authorize the signing
key against its own trust anchors — see the `is_key_authorized` callback
documented in [validators/oca/INTEGRATION.md](../../validators/oca/INTEGRATION.md).
