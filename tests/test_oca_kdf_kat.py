# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc.
"""Known-answer + domain-separation tests for the payload-decryption KDF.

The payload key is derived via NIST SP 800-108r1 Counter Mode (HMAC-SHA-256)
over a 192-byte expanded input block, reproducing the OCAH Key Manager
PREPARE_BL_DECRYPT_KEY flow. These tests anchor the derivation to the reference
design's known-answer vectors (so producer + consumer are correct against the
silicon, not merely self-consistent) and prove the structured block gives real
cryptographic domain separation.

Vectors are embedded verbatim from the reference `km_kat_vectors.jsonl`
(`pure` = raw PRF framing; `func`/`classkey` = the full CLASS_BL block flow).
"""

from __future__ import annotations

from tt_boot_manifest.oca import constants as oca_consts
from tt_boot_manifest.oca import encryption as enc
from tt_boot_manifest.oca.constants import OcaEncryptionType

# --- reference "pure" vectors: HMAC-SHA-256(key, be16(i)||input||be16(L))[:L/8] ---
_PURE_VECTORS = [
    # (L_bits, key_hex, input_hex, out_hex)
    (128, "dda7ec0f441777d2bd48b9f262254832",
     "182673d5e220370d5b539a11ae87c8b58c67b417dbb7a0341e556b47a2f19ee5"
     "6e8c35dae8b22dc14776d265bc32c5db60fbcf5bdce669e3dafe078a2f0028a4"
     "c5dd1f9b4aed9e889af30794edd47312c0177e58841bd961091c8d23a9e410b1"
     "345009119f8ae3db6b001396d7262ad2c5f19a056c0f4826c3e6d50ba953ac83"
     "d41fcb3380415231d3d6ce6212e1429486c2f95a2c770eab2096b839c6065692"
     "bd813ef985ca4502eaad0ef038bb13cf1dc275505c0e836737630ca699b56557",
     "88a7aa21d085dc430c36c7426bc79328"),
    (256, "dda7ec0f441777d2bd48b9f262254832",
     "49157b3d68f995f7f4c93a76988b5fe1bbd785a9d634ea427632729e1047546e"
     "886a85178071e476612b2a542a3d90a8fbbd3d8f6090760c5f84847f402c64e7"
     "1f7f31d7322f5239dbcb63c66d93e441be1fa47671aeebf6004f6a8f8bb2e38e"
     "64cb98b4572c75f8ba1ffd023786f5645c74d196df87e2b8b20b3d06cbd06b1a"
     "b1c7d2e5c55fe66c56a20f42620e59c92d34de278412f30ace31151cd77f9145"
     "5ceaf7a456c13c4b07cab2bcc622a82789d8e0613748b5a4ab39090988b6f0c6",
     "b03a8413463c9f6de42c8b8c56be7937d5148c599a85d3705713dd03177c7208"),
    (512, "dda7ec0f441777d2bd48b9f262254832",
     "7b0383a5edd2f2e18d3fdada818ef50ceb47563bd1b1344fcf0f79f57e9d0af6"
     "a348d55518319c2b7ae0834398485a75967fabc3e53a8335e30a01745158a029"
     "782144131b7205eb1ba3bff7ed535670bc27c9955d41fe8bf68247fb6e80b76a"
     "944628570ece0716083fe66f98e7bff6f3f6092852007d4aa231a502ee4d29b2"
     "8d6fd9980b7d79a6d86e5022b23b6ffdd4a6c2f5dcaed8697dcd72ffe9f7cdf8"
     "fb53af4e28b7349324e6568953893d80f6ee4c731282e7e11f0f066d76b67b34",
     "44381ecb0d261c443944dfa9edf8dcaff11d3efb6f13e51bce86fc800cd0a9c2"
     "070934cf4398edec94b07864a1b78b3f406e3900621ec2453aebbf6462b01bae"),
    # 32-byte key (matching the CLASS_KEY / pre-shared-secret size), across L sizes.
    (128, "0f95f477c9f0d5bc56be59574c28df5e595d696212724fb37c00a558567c6dcd",
     "6d6c985f0ee8c05b29821e81fde677baf5243afed8739172b5a7283b8c74c023"
     "bc6072f33089c48a491c6dc18a91e8ff06a7bb9b8a2384f48a48c852cc157b7b"
     "d6414f1519f7bdbfda52d4ede497c487ef342941ce7c19b95c20ec52256dced2"
     "d34706be5fe90371f35a2bfea1ae63cbc6025eea3c35a73643666c322d3210a1"
     "cbaa6fe59a17ee18ad6d4aec5a8f1e43a448318d6c0586e5565421eb7c1d995f"
     "d5a262826438d72d20c30aaea6f34c66a1407b23f5a60e3eae20e174ace7c185",
     "2b63db6586f42dbf05ae889f04fa446b"),
    (256, "0f95f477c9f0d5bc56be59574c28df5e595d696212724fb37c00a558567c6dcd",
     "9e5aa0c793c11d45c2f8bee6e6e90de524940b90d3efdb7f0d842f91f9c976ab"
     "d73ec230c8497b3f63d1c6b0f89cb3cca26929ce0fcd911d0ece4547dd41b7bd"
     "30e36151013a70701b2a301f645636b7ed3c4f5fbb0f2b4e5353c9be073ba2af"
     "03c29561168b958e4279146b020e2e5d5d85967cafad41c8328cd42d4fafce38"
     "a7527597e035825330398cccaabd35784bba165bc3a06b4505ef7ece8d96d412"
     "740c1a2d352fce753ddfae7a345ae1be0e56e635d0e0407b23f7ded79ae74cf4",
     "809978141723335553213ffc759a849fc38679d731c89ca6743eb1076739baeb"),
    (512, "0f95f477c9f0d5bc56be59574c28df5e595d696212724fb37c00a558567c6dcd",
     "d049a82e199a7b2f5b6f5e4ad0eda4115304dc22ce6c258c666136e8671f2c34"
     "f11d126e600932f57d861e9f66a77d993d2b960293769e479354c23cee6df3ff"
     "8a86748dea7d24215b028b50e415a7e6eb44747ea7a23ee34986a62aea09768b"
     "333d2404ce2d27ac9099fed8636ef9eff407ce0d2226dc5a22b13c29722c8dd0"
     "83fa7c4a2553158db204cdacfaea4badf22cfa281b3b50a4b38bdbb19f0e10c51"
     "375d3d70726c6bd5afc5146c2c176177b6b5246ab1a72b897cddb3b88e8d762",
     "31f20a4856565a48fd8a884e12d0c3fd8c00ca01b5316e34042a66c9d6ae2095"
     "c5a7c32256e84c3eca8ce7fc2a0ae2e3cc91000730fb5ccb011cde9d260cd74e"),
]

# --- reference CLASS_BL vector (op=classkey, scn 35): the full block flow.
# kdf_key = fused CLASS_KEY (32 B); context = BL1 nonce zero-padded to 64 B;
# kdf_out = the 256-bit AES key. This is exactly the AES-256-CBC producer flow.
_CLASS_SECRET = bytes.fromhex("434c4153532d4b45592d667573652d7368617265642d7365637265742d333200")
_CLASS_CONTEXT = bytes.fromhex(
    "424c312d696d6167652d6864722d6e6f6e63652d303030303030303030303031"
    "0000000000000000000000000000000000000000000000000000000000000000"
)
_CLASS_KEY_OUT = bytes.fromhex("d33452a510c514de47f985a63a6eb92051ee00fd4ea4058959e82a03e9d3b420")


def test_prf_framing_matches_reference_pure_vectors():
    """The raw SP 800-108r1 counter-mode framing (be16 counter, opaque block,
    be16 length) reproduces the reference vectors byte-for-byte across L sizes."""
    for l_bits, key_hex, input_hex, out_hex in _PURE_VECTORS:
        got = enc._kdf_counter_mode(bytes.fromhex(key_hex), bytes.fromhex(input_hex), l_bits)
        assert got == bytes.fromhex(out_hex), f"framing mismatch at L={l_bits}"


def test_classkey_frozen_vector_aes256():
    """The full AES-256 CLASS_BL derivation (fixed header/label/entropy + the
    64-byte context) reproduces the reference PREPARE_BL_DECRYPT_KEY output."""
    assert len(_CLASS_SECRET) == 32 and len(_CLASS_CONTEXT) == 64
    got = enc.derive_payload_key(_CLASS_SECRET, _CLASS_CONTEXT,
                                 OcaEncryptionType.AES_256_CBC.value)
    assert got == _CLASS_KEY_OUT


def test_block_assembly_matches_reference_layout():
    """The assembled 192-byte block places the fixed header, `KM_CLASS_BL`
    label, context, and zero entropy at the reference offsets."""
    block = enc.build_kdf_input_block(_CLASS_CONTEXT, 256)
    assert len(block) == 192
    assert block[0:2] == b"\x01\x00"                 # version = 0x0001
    assert block[10:12] == b"\x00\x01"               # out_bits = 256 (LE)
    assert block[32:43] == b"KM_CLASS_BL"            # label
    assert block[64:128] == _CLASS_CONTEXT           # context
    assert block[128:192] == b"\x00" * 64            # entropy
    # AES-128 differs only in out_bits (0x0080 LE).
    assert enc.build_kdf_input_block(_CLASS_CONTEXT, 128)[10:12] == b"\x80\x00"


def test_domain_separation_single_byte_changes_key():
    """Flipping any single byte of the block (header out_bits, label, or
    context) changes the derived key — the structured fields are real domain
    separation, not free metadata."""
    baseline = enc._kdf_counter_mode(_CLASS_SECRET, enc.build_kdf_input_block(_CLASS_CONTEXT, 256), 256)

    block = bytearray(enc.build_kdf_input_block(_CLASS_CONTEXT, 256))
    for pos, region in ((10, "header/out_bits"), (32, "label"), (64, "context"), (128, "entropy")):
        mutated = bytearray(block)
        mutated[pos] ^= 0x01
        got = enc._kdf_counter_mode(_CLASS_SECRET, bytes(mutated), 256)
        assert got != baseline, f"byte flip in {region} did not change the key"


def test_key_length_tracks_cipher():
    """AES-128 derives a 16-byte key, AES-256 a 32-byte key, and the two differ
    (the out_bits field + PRF length participate in the derivation)."""
    k128 = enc.derive_payload_key(_CLASS_SECRET, _CLASS_CONTEXT, OcaEncryptionType.AES_128_CBC.value)
    k256 = enc.derive_payload_key(_CLASS_SECRET, _CLASS_CONTEXT, OcaEncryptionType.AES_256_CBC.value)
    assert len(k128) == 16 and len(k256) == 32
    assert k128 != k256[:16]
