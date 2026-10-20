<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Tenstorrent USA, Inc. -->
# OCA validator — integration guide

How to build a consumer on top of `lib/`. The reference implementation is
`test/main.c`, compiled and run over every fixture by `make check` — read it
alongside this document; where the two disagree, the code is right.

Build, CLI usage, the supported algorithm portfolio, and the producer/consumer
drift gates live in [README.md](README.md).

Sections here are cited by anchor from `lib/oca_validator.h` — these headings
are an interface. Reword the prose freely; renaming a heading means updating
its citations.

---

## Vendoring

Copy `lib/` into your tree:

```
cp -r validators/oca/lib your-project/third_party/oca_validator
```

`oca_validator.h` is the only header your code includes. Provide
implementations of the callbacks declared at the top of that header
(SHA-256, signature verify, hardware-identity readers), populate an
`oca_callbacks_t`, and call one of the two entry points below. The library
reads the magic bytes itself and routes to the appropriate format handler; the
integrator never picks a variant.

One exception, for convenience rather than necessity: the two secure-boot
reporters answer in `oca_secure_bool_t`, and a translation unit that implements
only those — a fuse-read shim, a life-cycle accessor, a board file — can include
`oca_secure_bool.h` on its own instead of the whole validator API.

## Callbacks you must provide

`lib/` is freestanding: it contains no cryptography, no hardware access, no
libc, and no state that survives a call. Everything it cannot do itself is a
function pointer on `oca_callbacks_t`, for one of two reasons:

- **the resource is unreachable from a library** — a crypto engine, a fuse bank,
  an OTP block, a provisioned secret that must never cross into general-purpose
  code; or
- **the answer is policy the integrator owns** — whether secure boot is enforced
  on this device, what a field should be called in a log.

Populate the struct with `memset(&cb, 0, sizeof cb)` first, then assign what you
implement. A NULL pointer is a valid state, not a stub to fill in: checks that do
not need a callback never touch it, and a check that *does* need one fails with
`OCA_FAIL_CALLBACK_UNAVAILABLE` rather than passing.

| Field | What it is | Prototype | Purpose, and why it is a callback | System resources it reaches for you |
|---|---|---|---|---|
| `sha256` | Message digest | `oca_result_t (*)(const uint8_t *msg, size_t msg_len, uint8_t out_digest[32])` | Every integrity check in the library is built on this one primitive — `manifest_hash`, `payload_hash`, `payload_hash_chain`, per-image entry hashes. The library ships no hash implementation, so the target can use its accelerator instead of paying for a software SHA-256 in ROM. **Required on every path**; `manifest_hash` runs unconditionally and early, so a NULL here fails immediately. | SHA-256 engine or accelerator; whatever DMA/clock/power gating it needs. Software SHA-256 if there is no engine. |
| `verify_signature` | Signature verification | `oca_result_t (*)(const oca_crypto_blob_t *signature, const oca_crypto_blob_t *public_key, const uint8_t *signed_region, size_t signed_region_len)` | The library's only authenticity primitive — it establishes trust in the signed region, and transitively in every digest that region carries. Invoked once per signature class the manifest enforces: a hybrid manifest produces one classical call and one PQC call, and both must verify. This library composes and enforces the AND result of the two signatures. Algorithm and encoding vary (classical: RSA-3072 PKCS#1 v1.5 or ECDSA P-256, DER or raw; PQC: ML-DSA-87 today, raw only) so the `oca_crypto_blob_t` descriptors tell you which, and `key_algorithm` names the family. Each blob's `length` is its validated size. For ML-DSA-87 the contract is pure FIPS 204 ML-DSA.Verify over `signed_region` exactly as given, with the empty context: no pre-hash and no HashML-DSA (an engine that takes μ computes it as [Enabling PQC secure boot](#enabling-pqc-secure-boot) shows). The key is the raw 2592-byte FIPS 204 public-key encoding and the signature the raw 4627-byte signature encoding. The library performs none of this cryptography. A backend without a PQC implementation returns `OCA_FAIL_CALLBACK_UNAVAILABLE` for `OCA_KEY_ALGO_PQC` and the manifest fails closed. Required under secure boot. | Public-key accelerator or bignum unit; constant-time modular arithmetic; any key-format parsing (DER) you need; a PQC signature engine or software implementation (ML-DSA today) for the PQC class. |
| `decrypt_payload` | Payload key derivation + decryption | `oca_result_t (*)(const oca_decrypt_input_t *in, const uint8_t **out_plaintext, size_t *out_plaintext_len)` | Resolves `in->secret_select` against your key store, runs the SP 800-108r1 CTR-HMAC-SHA-256 KDF over `in->kdf_input`, and AES-CBC-decrypts with the result, stripping PKCS#7. It is a callback because **the provisioned secret is**: the library must never hold key material. Everything the operation reads is a named field on `in` — including the cipher and the secret index — so it never re-reads the manifest. The selector is an INDEX, never a secret: no key material crosses this boundary in either direction. Invoked only after the ciphertext's `payload_hash` verifies. Required only for encrypted payloads. | AES engine (CBC, 128/256-bit); HMAC-SHA-256 for the KDF; the **key store** holding the pre-shared secret — fuses, OTP, a key vault, or a derived-key slot the CPU cannot read. |
| `get_identity_bytes` | Silicon identity readback | `oca_hw_result_t (*)(oca_id_kind_t field, uint8_t out[32])` | Supplies the chiplet / package / system ID the manifest is checked against, per `selector_bits`. The library holds no device state, so these can only come from silicon. Returning `OCA_HW_UNAVAILABLE` is a hard failure, never a silent pass. Required when the matching selector bit is set. | Identity fuses, OTP, ID ROM, or an ID register block. |
| `get_lifecycle_state` | Lifecycle readback | `oca_hw_result_t (*)(oca_lifecycle_level_t level, oca_lifecycle_token_t *out_state)` | Reports the device's current lifecycle state so the manifest's permitted-state mask can be enforced. Same reasoning as identity: device state the library cannot see. Required when the lifecycle selector bit is set. | Lifecycle-state fuses or the lifecycle controller. |
| `get_version` | Version readback | `oca_hw_result_t (*)(oca_version_level_t level, uint16_t *out_major, uint16_t *out_minor)` | Reports the hardware version per level for the manifest's min/max range check. Required when the version selector bit is set. | Version fuses or revision-ID registers. |
| `is_secure_boot_active` | Secure-boot policy | `oca_secure_bool_t (*)(void)` | Secure boot is a **device-global state**, not something a manifest gets to assert about itself; it may be enforced by lifecycle, fuses, straps, or debug state. The manifest's `secure_boot_control` bit is one input, not the authority — so the integrator reports the truth here. **Optional**: NULL falls back to the manifest bit, and an undetermined state is treated as *active*, so a half-wired integration gets the secure path. Answers in `oca_secure_bool_t` — return `OCA_SECURE_FALSE` to say "not enforced" and nothing else; every other value, including a plain `1`, reads as enforced. | Secure-boot enforcement fuses, lifecycle state, boot straps, debug-disable state. |
| `is_secure_boot_disabled` | Secure-boot definitively off | `oca_secure_bool_t (*)(void)` | Some parts are settled as non-secure — a life-cycle state, or a discrete disable fuse. Without a way to say so they are held to secure boot by `is_secure_boot_active` or by the fail-safe default, and cannot boot for a reason unrelated to the image. This is the only input that turns secure boot **off**, and it is outranked by the manifest's own bit, so it relaxes what the *device* requires and never what the *image* requires. **Optional**: NULL means "not asserted", and so does every value except an exact `OCA_SECURE_TRUE`. This is the one input that can turn secure boot off, so only the intact pattern asserts it is `OCA_SECURE_TRUE`. Returning `OCA_SECURE_TRUE` withdraws the device's requirement that boots be verified. Manifests asserting secure boot are unaffected and still get signature verification and payload decryption, but a manifest with the bit clear now boots unverified where the device would previously have refused. | Life-cycle / life-cycle-state registers, a discrete secure-boot-disable OTP fuse. |
| `is_key_authorized` | ROOT-key trust anchor | `oca_result_t (*)(const oca_crypto_blob_t *public_key, const uint8_t select[16])` | Allow a consumer to verify public key material against its internal trust anchors. A manifest carries the public key its own signature is checked against, so verification alone proves that *some* private key signed it and nothing about whose. A trust anchor check is required to authorize keys, otherwise any self-signed manifest passes. Invoked once per signature class the manifest enforces; the classical key, the PQC key, or both for a hybrid manifest. The blob's `key_algorithm` naming which anchor family to consult; a device with no PQC anchor returns `OCA_FAIL_ROOT_KEY_UNAUTHORIZED` for `OCA_KEY_ALGO_PQC` and the manifest fails closed. Consulted before revocation and before any public-key operation, so an unknown key is never used and costs no computation. The library holds no opinion on how the answer is reached because the anchor is not something the format can describe. Required under secure boot; NULL fails closed. | Keys or key digests in mask ROM, OTP or a fuse bank; an on-die key table; constant-time comparison (see `lib/oca_compare.h`). |
| `get_root_key_revocation` | Revocation state read | `oca_result_t (*)(oca_key_algorithm_t algo, uint8_t out[16])` | Supplies the device-stored ROOT-key revocation bitmap so a revoked key is rejected *before* it is used to verify anything. The library is stateless by design and cannot read non-volatile storage. Required under secure boot. | Non-volatile revocation store — fuse bank, OTP, or a monotonic region. Classic and PQC state are kept separately. |
| `get_security_version` | Anti-rollback state read | `oca_result_t (*)(uint8_t out[16])` | Supplies the device-stored 128-bit security-version flags for the bit-superset anti-rollback test. Same reasoning. Required under secure boot. | Non-volatile anti-rollback store — OTP, fuses, or a monotonic counter. |
| `set_root_key_revocation` | Revocation state write | `oca_result_t (*)(oca_key_algorithm_t algo, const uint8_t in[16])` | Persists the OR-ed revocation bitmap. Separate from the read so that **validation stays read-only**: only `oca_commit_security_state()` calls the setters, and only after a manifest has passed. Required only if you commit device state. | Fuse programming / OTP burn path, with whatever voltage, timing, or unlock sequence that needs. Irreversible. |
| `set_security_version` | Anti-rollback state write | `oca_result_t (*)(const uint8_t in[16])` | Persists the OR-ed security-version flags. Same contract; bits are only ever set, never cleared. Required only if you commit device state. | Same NV write path. Irreversible. |
| `get_signature_cohort_enforce` | Signature posture read | `oca_result_t (*)(uint8_t out[8])` | Supplies the device's signature cohort enforcement — the cohorts it demands of each entity's signatures. Read at every secure boot by `oca_check_signature_posture()`, which refuses a manifest that does not enforce a cohort demanded of the ROOT key, and by the commit, which ORs the manifest's value into it. Report the whole posture: the stored register, plus anything lifecycle or another fuse imposes. All zeros if the device demands nothing. Eight bytes, not sixteen — it mirrors a u64 manifest field. Required under secure boot; NULL, or a non-`OCA_OK` return, fails closed. | Non-volatile posture store — fuse bank or OTP; lifecycle state, where it widens the posture. |
| `set_signature_cohort_enforce` | Signature posture write | `oca_result_t (*)(const uint8_t in[8])` | Persists the OR-ed cohort enforcement register. Bits are only ever set. Required only if you commit device state. | Same NV write path. Irreversible. |
| `get_signature_class_revoke` | Class revocation read | `oca_result_t (*)(uint8_t out[8])` | Supplies the device's signature class revocation — the algorithm classes it has disabled. Read at every secure boot by `oca_check_signature_posture()`, which refuses a manifest verified by a disabled algorithm, and by the commit. Report the whole posture, as for cohort enforcement; all zeros if nothing is disabled. Not keyed by algorithm family: the classical and PQC halves live in one 8-byte word, and splitting them across two calls would let a group code be written in fragments. Required under secure boot; NULL, or a non-`OCA_OK` return, fails closed. | Non-volatile revocation store — fuse bank or OTP; lifecycle state, where it widens the posture. |
| `set_signature_class_revoke` | Class revocation write | `oca_result_t (*)(const uint8_t in[8])` | Persists the OR-ed class revocation register. The library ORs the **whole** field, reserved bytes included, so a group code can never be assembled from fragments contributed by separate manifests. Required only if you commit device state. | Same NV write path. Irreversible. |
| `describe_field` | Diagnostic naming | `const char *(*)(oca_id_kind_t field)` | Turns a field enum into a human-readable name for error messages. A callback because the library is freestanding and carries **no string tables**; it returns your pointer or NULL, and never formats anything itself. **Optional**, diagnostics only. | None. A string table in your own image. |

### What "required" means at runtime

Nothing here is discovered by inspection — every unmet requirement is a distinct
result code, and none of them is a pass:

- a needed callback is NULL → `OCA_FAIL_CALLBACK_UNAVAILABLE`. Checked in the
  function that makes the call, not only at the entry point. NULL is the only
  thing the library can test a function pointer for: a corrupted non-NULL
  entry is called. Keep the table in read-only memory, so nothing at run time
  can overwrite an entry;
- a hardware reader returns `OCA_HW_UNAVAILABLE` → the check hard-fails rather
  than skipping;
- secure boot cannot be determined from the reporters → treated as **active**, so
  an incomplete integration gets the strict path rather than a bypass;
- the device's secure-boot answer stops matching the one this validation recorded
  → `OCA_FAIL_SECURE_BOOT_STATE_CHANGED`. Note this is the *opposite* failure
  direction to the bullet above, and deliberately so: an un-answered question
  fails toward strictness, an answer that changed mid-validation fails closed;
- a check that consumes the determination is handed a context no determination
  has settled → `OCA_FAIL_SECURE_BOOT_UNDETERMINED`. Reachable only when
  composing checks by hand;
- a device-state write fails → `OCA_FAIL_SECURITY_STATE_UPDATE`, which does not
  retroactively invalidate an already-valid manifest.

### Minimum viable table

A non-secure bundle with a cleartext payload and no `selector_bits` set needs
exactly one entry:

```c
oca_callbacks_t cb;
memset(&cb, 0, sizeof cb);
cb.sha256 = my_sha256;
cb.is_secure_boot_active = my_secure_boot_state;  /* else secure-by-default */
```

That is the whole integration — no structure of your own to declare, and nothing
to hand the library beyond the functions themselves.

Add `verify_signature`, `is_key_authorized`, `get_root_key_revocation`,
`get_security_version`, `get_signature_cohort_enforce` and
`get_signature_class_revoke` for secure boot; `decrypt_payload` for encrypted
payloads; the `get_*` identity, lifecycle and version readers for whichever
`selector_bits` your manifests set. If you commit device state, add the four
`set_*` writers. PQC secure boot uses the same callbacks, called once per
signature family; see [Enabling PQC secure boot](#enabling-pqc-secure-boot) for
what each must do for the PQC family.
`test/main.c` wires all of them against OpenSSL and CLI flags, and is the
reference for the shapes.

### Where your own state lives

No callback takes a caller-supplied context pointer, and that is deliberate
rather than an omission.

A callback that needs state of its own — a hash-engine handle, a key-store
session, a driver context — reaches it the way any other code in your image
would:

```c
/* In your image. The library neither holds nor forwards this. */
static my_engine_t *g_sha_engine;

oca_result_t my_sha256(const uint8_t *msg, size_t len, uint8_t out[32])
{
    return my_engine_digest(g_sha_engine, msg, len, out) ? OCA_OK
                                                        : OCA_FAIL_CALLBACK_UNAVAILABLE;
}
```

The library used to forward one `void *` to every callback, and the shape had two
problems worth knowing about if you are porting older code. It was untyped, so
each callback recovered its object by cast with nothing checking the cast was the
right one. And it belonged to the table rather than to a callback, so the pointer
reaching the digest callback was the same pointer reaching payload decryption —
meaning a single structure holding your provisioned secret was reachable from
twelve callbacks with no business touching it.

Each callback now receives exactly what its operation reads. Nothing else was
lost: the pointer only ever moved something you already had from one place in
your image to another.

## Choosing an entry point

There are two general ways to utilize the library functions. Both run the same 
checks in the same order. The choice is about where the bytes you need to check
live, not how much checking you get.

**Whole-bundle**: one call over one buffer that already holds the manifest body
followed by its payload.

```c
oca_validate(bundle, bundle_len, &cb, NULL, &plaintext);
```

**Staged**: four calls, with the manifest and then the payload copied out of
storage *between* them. The library never touches storage itself. Your code
performs copy operations and the library verifies what you copied.

```c
oca_peek_manifest(head, head_len, &pk);                 /* how big is the body? */
oca_validate_manifest(body, pk.body_size, &cb, &vctx);  /* authenticate the copy */
oca_locate_payload(body, &bounds, &addr, &span);        /* where is the payload? */
oca_check_payload_at(body, payload, span, &cb, &vctx,   /* verify the copy, and */
                     &plaintext);                       /*   learn where it is  */
```

| | whole-bundle | staged |
|---|---|---|
| Bundle lives in | trusted memory already | external storage |
| Buffer shape | body + payload contiguous | body and payload separate |
| `payload_offset` | must equal the body size | resolved and bounds-checked |
| Peak RAM | body + whole payload | body, then payload |
| Built for | host tooling, tests, an image a prior loader staged | a boot ROM |

If you are writing a boot ROM you want the staged flow, spelled out below.
`oca_validate()` is the better-named and more discoverable function, which is
why this section exists: reaching for it on a device that reads from flash
silently inherits a contiguity assumption `oca-combined` bundles already
violate.

## The staged flow

The governing rule is **Time-of-Check/Time-of-Use**: each region is copied out
of storage into internal memory *before* it is verified, and verified in the
buffer you will actually use. Re-copying afterwards reopens the window you just
closed.

```c
/* 1. Peek — the only read taken straight from mapped storage, because it makes
 *    no trust decision. It says how many bytes to copy, nothing more. */
oca_manifest_peek_t pk;
if (oca_peek_manifest(flash + manifest_addr, avail, &pk) != OCA_OK) return REFUSE;

/* 2. Copy the body into your staging memory and authenticate the COPY.
 *    body_size is determined from the magic;
 *    oca_check_manifest_length(), inside oca_validate_manifest(), confirms the
 *    manifest's own declared length agrees once it is authenticated.
 *
 *    The validation context records what this step ESTABLISHED — the secure-boot
 *    determination, and whether a signature check actually ran and passed. It is
 *    caller-owned because steps 5 and 6 happen in separate calls and both need
 *    to know: step 5 to release plaintext, step 6 to confirm the commit against
 *    the same determination this step decided on. */
oca_validation_context_t vctx;
oca_validation_context_init(&vctx);

memcpy(body, flash + manifest_addr, pk.body_size);
if (oca_validate_manifest(body, pk.body_size, &cb, &vctx) != OCA_OK) return REFUSE;

/* 3. The manifest is authenticated, so its encryption fields can now be
 *    believed. If the payload is encrypted, wire the callback that step 5 will
 *    invoke. Nothing else to set up: the callback receives the cipher and the
 *    secret selector as descriptor fields when it is called. */
oca_payload_encryption_t enc;
if (oca_payload_encryption_info(body, &enc) != OCA_OK) return REFUSE;
if (enc.encrypted) {
    cb.decrypt_payload = my_decrypt_payload;
}

/* 4. Resolve payload_offset against the region this boot may read. Runs AFTER
 *    authentication: it sizes the payload from payload_length /
 *    payload_hashed_length, trustworthy only once the manifest is. */
oca_storage_bounds_t bounds;
bounds.manifest_addr = manifest_addr;
bounds.region_base   = BANK_BASE;      /* the bank being booted, not the device */
bounds.region_limit  = BANK_LIMIT;

int64_t payload_addr; size_t payload_span;
if (oca_locate_payload(body, &bounds, &payload_addr, &payload_span) != OCA_OK)
    return REFUSE;

/* 5. Copy the payload inward and verify it. The context from step 2 comes back
 *    in here: an encrypted payload is refused unless it records that a signature
 *    check ran and passed. THIS is where decryption happens —
 *    you never call your decrypt routine yourself. oca_check_payload_at()
 *    drives the whole sequence:
 *
 *      a. verify payload_hash over the CIPHERTEXT as copied;
 *      b. call cb.decrypt_payload — your code, wired in step 3;
 *      c. verify payload_hash_chain and every TOC entry hash over the
 *         recovered PLAINTEXT.
 *
 *    Authenticate-then-decrypt: (a) precedes (b), so your cipher is never
 *    pointed at bytes that failed their hash. A cleartext payload skips (a)
 *    and (b) entirely. */
memcpy(payload, flash + payload_addr, payload_span);
if (oca_check_payload_at(body, payload, payload_span, &cb, &vctx,
                         &plaintext) != OCA_OK)
    return REFUSE;

/* 6. The plaintext is wherever your callback put it — the library does not
 *    retain that pointer. Walk the TOC there, stage the images, then commit.
 *    A failed commit leaves the image valid but the device state un-advanced:
 *    report it rather than ignore it. */
if (oca_commit_security_state(body, &cb, &vctx) != OCA_OK)
    report_commit_failure();
```

### Encryption requires confirmed secure boot

An encrypted payload is refused unless a signature check **ran and passed** for
that manifest. Not "secure boot is enabled" — *confirmed*. The two differ
whenever a signature check was skipped, never composed, or did not complete, and
a boot ROM has to tell them apart.

The reason is what the manifest's encryption fields control. With no verified
signature, an attacker chooses which provisioned secret is used
(`encryption_shared_secret_select`), the derivation context
(`encryption_kdf_input`), the cipher, the ciphertext, and every digest that
subsequently "verifies" the result. That is a key-derivation oracle over the
device's own secrets, and the verification that follows is circular — the
plaintext is checked against digests the same attacker wrote, then staged and
executed.

Confidentiality without authenticity is a reasonable primitive in general. It is
not one on a path that executes what it decrypted.

In practice this costs you nothing: the packaging tool already refuses to build
a manifest that declares encryption without secure boot, so no bundle produced
by this toolchain changes verdict. What changes is that a manifest built by
something else, or altered afterwards, is now refused rather than decrypted.

Two things follow for your code:

- **Initialize the context.** `oca_validation_context_init()` before each
  validation. A zero-initialized context means "nothing established", which
  refuses — the safe default, and the reason a forgotten `init` fails closed
  rather than open.
- **Carry it to the payload step.** In the staged flow the same context must
  reach `oca_check_payload_at()`. Passing a fresh one there refuses, correctly:
  from that call's point of view nothing has been authenticated.

The refusal reports `OCA_FAIL_ENCRYPTION_REQUIRES_SECURE_BOOT`.

**Step 3 is the staged flow's advantage.** `oca_validate()` runs the manifest and
payload stages back to back with no seam between them, so a whole-bundle consumer
has to resolve the selector from inside its `decrypt_payload` callback to keep the
read post-authentication. Staged gives you an ordinary place in the sequence to do
it, on a manifest that has already verified.

Skipping step 3 on an encrypted payload fails step 5 with
`OCA_FAIL_CALLBACK_UNAVAILABLE` — the library will not proceed without a way to
decrypt. What `decrypt_payload` itself must do, including capturing the plaintext
so step 6 can find it, is
[reading the payload, step 1](#step-1--get-a-pointer-to-the-plaintext).

The CLI reference resolves the selector inside the callback rather than at step 3,
so one code path serves both entry points; either placement is correct as long as
it is not before `oca_validate_manifest()`.

### Performing the copies

**The library never reads storage.** There is no read, fetch, or DMA callback on
`oca_callbacks_t` — every function takes a pointer to memory you have already
filled. The two copies above are yours to perform by whatever means the platform
offers: `memcpy` from a memory-mapped window, a blocking SPI driver call, or a
DMA transfer you wait on. Nothing needs to be stubbed for this, and the library
constrains only the result:

- each region lands in **one contiguous buffer** — the body in one, the payload
  in another, with no required relationship between them;
- the **whole region is resident** before the call that reads it, since there is
  no incremental entry point yet.

Because the copy is outside the library, it is also outside the library's
guarantees: a DMA engine that can be retargeted mid-transfer, or a buffer another
master can write while validation runs, reintroduces exactly the ToCToU exposure
the copy exists to close. The destination needs to be memory only this boot path
can write until it has finished with it.

`oca_peek_manifest()` is the one exception. It is documented as safe to call
against a mapped flash window because it makes no trust decision — it reports a
size. Every call after it must run against your copy.

Constraints the signatures do not show:

- **`payload_offset` is never trusted.** It sits in the manifest's unsigned tail
  because the spec lets it be rewritten at flash-placement time. Bounding it is
  what makes following it safe; `payload_hash` / `payload_hash_chain` — which
  are inside the signed region — then decide whether what you landed on is the
  payload the manifest describes.
- **Narrow `region_base`/`region_limit` to the bank being booted.** Against
  whole-device bounds, bank A's manifest can name bank B's payload and the
  hashes will not object — bank B's payload is genuinely well-formed. Only the
  bounds reject a cross-bank locator.
- **`body` stays resident to the end.** Steps 3, 4 and 5 all read from it.
  Budget the manifest for the whole sequence, not just for authentication.
- **The whole payload must be resident at once.** There is no iterative
  verification yet, so a payload larger than your buffer has no staged path.

`test/main.c`'s `validate_from_storage()` runs exactly this sequence — a drift
test pins the two together — so `make check` exercises the documented flow
rather than a parallel description that can rot. `oca-validate
--storage-image` invokes it.

### How it lands in memory

`A` is `bounds.manifest_addr`; `off` is the bounded `payload_offset`. The flash
gap between the two regions is not reproduced in SRAM — `oca_check_payload_at()`
takes the buffers separately, so they need no fixed relationship:

```
        EXTERNAL FLASH                        SECURED SRAM
                                              (two independent buffers)

  A ──▶ ┌──────────────────────┐        ┌──────────────────────┐ ◀── body
        │ manifest body        │ ═copy═▶│ manifest body        │    resident
        │   4096 / 36864       │        │   4096 / 36864       │    through step 5
        │ [verifier key]       │        └──────────────────────┘
        │ [co-signer keys]     │
        └──────────────────────┘        ┌──────────────────────┐ ◀── payload
        ┌ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┐        │ PTOC header + entries│ ┐
          gap, arbitrary size  │        │ image[0]             │ │ payload_span
        └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─ ─┘        │ image[1] …           │ │ bytes, all
A+off ▶ ┌──────────────────────┐ ═copy═▶│ trailing slack       │ ┘ resident
        │ payload, payload_span│        └──────────────────────┘
        └──────────────────────┘
```

Images then land at their own payload-relative TOC offsets, inter-image gaps
included, because the chain hashes `payload + offset`.

## The whole-bundle flow

**Pass the whole bundle, not just the manifest body.** `oca_validate()` takes
the manifest body *followed by its payload*, contiguous in memory, and the
length of both together. Every manifest this packer emits carries a payload, so
passing the body size alone (4096 / 36864) fails with `OCA_FAIL_TRUNCATED`, and
a `payload_offset` that is not exactly the body size fails with
`OCA_FAIL_PAYLOAD_LOCATION`.

```c
oca_result_t r = oca_validate(bundle, bundle_len, &cb, NULL, &plaintext);  /* body + payload */
if (r != OCA_OK) { /* refuse to boot */ }
```

Pass an initialized `oca_validation_context_t` instead of `NULL` if you will
commit device state afterwards: the commit reads what the validation recorded
there.

## Reading the payload after validation

Validation decides PASS/FAIL. Acting on the payload takes two steps: get a
pointer to the **plaintext** payload region, then walk its table of contents.
The validator reports the first for you, the same way for a cleartext payload as
for an encrypted one and the same way from every entry point.

### Step 1 — get a pointer to the plaintext

The validator reports it. `oca_validate()`, `oca_check_payload()` and
`oca_check_payload_at()` each take a final out-parameter that receives the
validated plaintext location and its recovered length:

```c
oca_payload_plaintext_t plaintext;
memset(&plaintext, 0, sizeof plaintext);

if (oca_validate(bundle, bundle_len, &cb, NULL, &plaintext) != OCA_OK) {
    return REFUSE;                /* plaintext is untouched */
}
/* plaintext.bytes / plaintext.len — where the images are. */
```

Three properties worth relying on:

- **Written only on success.** On any failure the struct is untouched, so you can
  never act on a location the validator had not finished checking. It is written
  after the TOC structural pass, the payload hash chain, and every per-entry
  image hash have all passed.
- **Cleartext and encrypted alike.** You do not have to ask which kind of payload
  you had in order to find its images.
- **Declining is supported.** Pass `NULL` if you do not need it; the verdict is
  identical.

For an encrypted payload the reported address is whatever your `decrypt_payload`
callback returned — possibly the ciphertext's own address, if it decrypted in
place. The length is the recovered length, which is **shorter** than the stored
ciphertext because PKCS#7 padding was removed; the tail of the region is stale
ciphertext, so take both values from the report.

### Writing the decryption callback

Everything the operation reads arrives in one read-only descriptor, so the
callback needs nothing else:

```c
static oca_result_t my_decrypt_payload(
    const oca_decrypt_input_t *in,
    const uint8_t **out_pt, size_t *out_pt_len)
{
    /* The selector is a 1-based INDEX into your provisioned secrets, never a
     * secret. Resolving it is this callback's job, which is what keeps key
     * material out of the library entirely. */
    const uint8_t *secret = my_key_store_slot(in->secret_select);
    if (secret == NULL) {
        return OCA_FAIL_NO_PROVISIONED_SECRET;
    }

    unsigned key_bits = (in->cipher == OCA_ENCRYPTION_TYPE_AES_256_CBC) ? 256u : 128u;

    /* Variant A — decrypt IN PLACE, over the ciphertext buffer. */
    uint8_t *region = (uint8_t *)(uintptr_t)in->ciphertext;   /* your own buffer */
    size_t recovered = aes_cbc_decrypt_in_place(
        region, in->ciphertext_len, in->iv, in->kdf_input, secret, key_bits);
    if (recovered == 0) return OCA_FAIL_DECRYPT;
    *out_pt     = region;              /* same address as the ciphertext */
    *out_pt_len = recovered;           /* SHORTER — PKCS#7 stripped */

    /* Variant B — decrypt into a SEPARATE buffer:
     *   size_t recovered = aes_cbc_decrypt(my_pt_buf, sizeof my_pt_buf,
     *                                      in->ciphertext, in->ciphertext_len,
     *                                      in->iv, in->kdf_input, secret, key_bits);
     *   if (recovered == 0) return OCA_FAIL_DECRYPT;
     *   *out_pt     = my_pt_buf;
     *   *out_pt_len = recovered;
     */
    return OCA_OK;
}
```

Report a slot you hold no secret for as `OCA_FAIL_NO_PROVISIONED_SECRET`, not as
`OCA_FAIL_CALLBACK_UNAVAILABLE`. The three ways decryption can fail to produce
plaintext need three different responses, and the result code is all a field
failure leaves behind:

| Code | Means |
|---|---|
| `OCA_FAIL_CALLBACK_UNAVAILABLE` | no decryption callback is wired — an integration mistake |
| `OCA_FAIL_NO_PROVISIONED_SECRET` | this part was never provisioned for this manifest, which may be a perfectly valid manifest on a part that was |
| `OCA_FAIL_DECRYPT` | decryption ran and failed: key derivation, the cipher, or PKCS#7 unpadding |

### Deciding whether a bundle is encrypted at all

`oca_payload_encryption_info()` answers from the **manifest body alone**, so it
works in the staged flow where no payload is resident. Use it to decide something
*before* the payload stage — most usefully whether to wire `decrypt_payload`:

```c
oca_payload_encryption_t enc;
if (oca_payload_encryption_info(body, &enc) != OCA_OK) return REFUSE;

if (enc.encrypted) {
    cb.decrypt_payload = my_decrypt_payload;
}
```

**Call it on an authenticated manifest.** All three fields live inside the signed
region, so they mean nothing until `oca_check_signature()` has verified it.
There is no pressure to read early: the callback receives the cipher and the
selector as descriptor fields, so it never needs this function for itself.

`oca_payload_region()`'s `encrypted` out-parameter cannot substitute: it assumes
the payload sits immediately after the body, which a staged copy does not.

#### Choosing in place or a separate buffer

In-place decryption needs one buffer rather than two, which on a ROM staging a
multi-megabyte payload into SRAM halves peak memory. It is safe here because
`payload_hash` is verified over the ciphertext *before* the callback runs, the
library never reads the ciphertext again afterwards, and `iv` / `kdf_input` point
into the **manifest body** rather than the payload, so overwriting the payload
cannot clobber the derivation inputs.

The cost is that the buffer cannot be validated a second time — `payload_hash`
covers ciphertext that no longer exists. Single-shot boot does not care; a retry
loop must re-read the payload from storage.

`oca-validate --decrypt-in-place` exercises this path (see
`openssl_decrypt_payload` in `test/openssl_crypto.c`), and the suite asserts it
recovers byte-identical plaintext to the copy-out path.

### Step 2 — walk the TOC

With `payload` / `payload_len` established, the walk is the same in every case:

```c
oca_toc_info_t toc;
if (oca_toc_info(payload, payload_len, &toc) != OCA_OK) return REFUSE;

for (uint64_t i = 0; i < toc.image_count; ++i) {
    oca_image_info_t img;
    if (oca_toc_image_at(payload, payload_len, i, &img) != OCA_OK) break;
    /* img.bytes / img.length are bounds-checked against the payload. */
    copy_to(img.load_addr, img.bytes, img.length);
    if (img.entry_point != 0) enter_at(img.entry_point);
}
```

The accessors re-derive the TOC bounds, so a malformed or hostile TOC can never
yield an out-of-range `bytes`/`length`. Beyond that they verify nothing — they
decode structure, and well-formed structure is not a trust statement.

**Integrity comes from the payload check.** `oca_check_payload()` in the
whole-bundle flow, `oca_check_payload_at()` in the staged one: both verify
SHA-256 digests through your `sha256` callback — `payload_hash` over the
ciphertext when the payload is encrypted (before any decryption) or over the TOC
region when it is not, then `payload_hash_chain` across the TOC and every image,
then each TOC entry's own `hash` against the bytes it describes. That is
cryptography, and it proves the payload is exactly what the manifest describes.
It does not prove the manifest is genuine.

**Authenticity is transitive, and it comes from the signature.** `payload_hash`,
`payload_hash_chain`, `payload_length` and `payload_hashed_length` all sit inside
the manifest's *signed* region, so once `oca_check_signature()` has verified that
region those digests are trustworthy — and a payload matching them inherits that
trust. Under secure boot, running the manifest checks and then the payload check
does authenticate the payload; the payload check is the second half of that, not
the whole of it.

**With secure boot off you get integrity only.** The signature never runs, so the
digests are themselves unverified. The payload check will still catch a corrupt
flash read or a truncated image — it will not catch a substituted payload
accompanied by a rewritten manifest.

So calling the accessors on a payload that has not passed the payload check means
acting on unverified bytes. The library cannot enforce that ordering; it holds no
state across calls by design.

`test/main.c` is the working reference for both steps: `list_payload_images()`
does the whole-bundle resolution including the encrypted substitution, and
`list_toc()` does the walk. `oca-validate --list-images` prints what they read.

## Secure-boot device state

When secure boot is in force, five checks run ahead of signature verification:
`oca_check_crypto_field_sizes()`, `oca_check_signature_posture()`,
`oca_check_root_key_authorized()`, `oca_check_root_key_revocation()` and
`oca_check_security_version()`. All are composed into
`oca_validate_manifest()`, so both entry points run them, and all are callable
directly if you are composing checks by hand — but composing them by hand
requires the validation context `oca_determine_secure_boot()` produced. A fresh
one is refused, not treated as "not in force". See "Determined once, confirmed
at every use" below.

- **Signing description** (`oca_check_crypto_field_sizes()`) — each enforced
  class's signature type, encodings and size fields must describe a key and
  signature this library accepts (`CRYPTO_FIELD_SIZE` otherwise). These are
  Secure-Boot-only fields, so the check is keyed on the determination rather
  than on the manifest's `secure_boot_enforced` bit: a part that enforces secure
  boot itself validates them even on a manifest that leaves the bit clear, and
  while secure boot is not in force they are ignored, whatever they hold — a
  manifest that does not assert secure boot is not refused for carrying them.
- **Signature posture** (`oca_check_signature_posture()`) — the device's
  signature class revocation and cohort enforcement, as
  `get_signature_class_revoke` and `get_signature_cohort_enforce` report them,
  applied to this boot. Earlier manifests OR their `signature_class_revoke` and
  `signature_cohort_enforce` into that state when committed; the posture fields
  of the manifest being validated play no part until it is committed in turn.
  Two rules:

  - **Algorithm revocation.** Each enforced class's `signature_type` must not
    fall in an algorithm class the device has disabled, by that class's own bit
    or by its group's intact group code — `0xCA` disables every classical
    class, `0xAC` every PQC class. Refused as `SIGNATURE_ALGORITHM_REVOKED`. A
    partly set group-code byte disables nothing.
  - **Cohort enforcement.** Each cohort the device demands of the ROOT key's
    signatures — bits 0 (classical) and 1 (PQC) of the low nibble — must be one
    the manifest enforces. Refused as `SIGNATURE_COHORT_REQUIRED`. A demand for
    a cohort whose whole group is disabled is withdrawn, since no algorithm is
    left that could meet it. The verifier-key and co-signer nibbles are not
    consulted, because this library verifies neither.

  Both readers are required under secure boot and fail closed: a NULL reader,
  or one that does not return `OCA_OK`, is `CALLBACK_UNAVAILABLE`. A reader that
  returns `OCA_OK` without writing leaves the buffer as the library prefilled
  it — every class disabled, every cohort demanded — the strictest posture. The
  check runs before any key is authorized or used, and `oca_check_signature()`
  refuses a context it did not vouch for (`SIGNATURE_COHORT_REQUIRED`), so a
  hand-composed sequence that skipped it verifies nothing.
- **ROOT-key authorization** (`oca_check_root_key_authorized()`) — the trust
  anchor, and the first of the key checks. The manifest carries the key its own
  signature is verified against, so verification establishes only that some
  private key signed it; this is what establishes whose. Each signature class
  the manifest enforces (`secure_boot_classic` / `secure_boot_pqc`) is
  authorized separately, against its own anchor family, and recorded in its own
  per-class context flag; `oca_check_signature()` refuses a context whose flag
  for the class it is about to verify does not vouch
  (`ROOT_KEY_UNAUTHORIZED`) — so a hand-composed sequence that skipped
  authorization cannot verify against a key nothing vouched for, and a
  classical vouching never unlocks a PQC verify. That holds for a context
  initialized for this validation: a reused one still carries the flags an
  earlier validation set, which is why `oca_validation_context_init()` comes
  first every time. An enforced class whose select bitmap names no key is
  refused before the anchor is asked. The decision itself is
  `cb->is_key_authorized`'s: the anchor may be a key in mask ROM, a digest in
  OTP, or a store this library cannot describe, and it must bind both the
  whole key and the slot the manifest selects (see the callback table).

  Authorization and revocation are two different questions asked about key
  material: first "was this key ever trusted?", and then "is it still trusted?".
  A key can be unauthorized with no revocation bit set anywhere.
- **ROOT-key revocation** (`oca_check_root_key_revocation()`) — before a
  selected ROOT key is used to verify the manifest signature, the validator
  rejects the manifest (`ROOT_KEY_REVOKED`) if the key is revoked in its own
  family's manifest bitmap (`public_key_classic_revoke` or
  `public_key_pqc_revoke`) **or** in that family's device-stored state. Each
  enforced class's key is checked; a revoked key is never exercised.
- **Anti-rollback** (`oca_check_security_version()`) — the validator enforces
  that the 128-bit `manifest_security_version` flag field is a **bit-superset**
  of the device-stored value (`manifest & device == device`); a manifest missing
  a flag the device has already recorded is rejected (`SECURITY_VERSION`) as a
  downgrade. Evaluated twice: once *before* the signature, so a replayed manifest
  is rejected without paying for a public-key operation, and again after it by
  default (`OCA_RECHECK_SECURITY_VERSION`). The early pass is not a decision — it
  becomes one retroactively once the signature verifies over the region holding
  the compared value.

**When is secure boot "in force"?** It is a global state, not a single bit.
Three inputs are consulted in this order, and the first to settle the question
decides it:

1. **The manifest's `secure_boot_control` enable bit** — if set, secure boot is
   in force. Checked first, and nothing below can override it.
2. **`is_secure_boot_disabled()`** — a device reporting it is definitively *not*
   a secure-boot part via a life-cycle state or a discrete disable fuse. The only
   input that can turn secure boot **off**.
3. **`is_secure_boot_active()`** — the device's own view of whether secure boot
   is enforced. Also typically tied to life-cycle state and/or discrete
   programmable fuses

Both reporters answer in `oca_secure_bool_t`, and an answer the library does not
recognize leaves secure boot **on** in both cases — but reaching that takes
opposite rules, so it is worth knowing which is which. Only an exact
`OCA_SECURE_FALSE` from (3) says "not enforced"; only an exact `OCA_SECURE_TRUE`
from (2) asserts the disable. A `return 1;`, a glitched word, or an
uninitialized one is handled the same as a reporter that was never wired.

If neither device state reporter is wired, the validator defaults to 
**secure boot enabled**. That is a fail-safe such that an un-configured integration
gets the secure path, not a bypass.

The ordering is the whole safety argument. `is_secure_boot_disabled` relaxes only
the requirement the **device** imposes, never one the **image** imposes, so no
fault, mis-provisioned fuse, or defective reporter can cause a manifest built for
secure boot to run unverified.

> **Wiring `is_secure_boot_disabled` to return `OCA_SECURE_TRUE` removes a
> protection. Be clear about which one.**
>
> It does **not** restrict what the part can boot. A manifest asserting
> `secure_boot_control` is entirely unaffected: secure boot is in force, the
> signature is verified, and an encrypted payload decrypts normally. That is the
> only way to boot with secure boot and payload encryption, and it keeps working
> on a part reporting itself disabled.
>
> What it withdraws is the **device's** insistence that this part boot verified.
> Once that is gone, a manifest with `secure_boot_control` clear boots
> unverified, and nothing at the device level objects — where previously
> `is_secure_boot_active` or the fail-safe default would have refused it.
>
> So the exposure is: **anyone who can present a manifest with
> `secure_boot_control` clear gets an unverified boot.** Supplying a manifest
> with the bit set restores full verification for that boot, but nothing
> *requires* you to, which is exactly the requirement this reporter removes. Wire
> it only where the images the part can reach are controlled by other means.

**Device state is host-supplied.** The validator holds no fuse/OTP state; the
integrator provides it through callbacks on `oca_callbacks_t`:
`is_secure_boot_active`, `is_secure_boot_disabled`, `is_key_authorized`,
`get_root_key_revocation(algo, …)`, `get_security_version(…)`,
`get_signature_cohort_enforce(…)` and `get_signature_class_revoke(…)`. Classic
and PQC ROOT-key revocation state are kept separately (`oca_key_algorithm_t`):
the revocation check reads the state of each family whose signature class the
manifest enforces, and the commit writes the state of each family whose bitmap
the manifest carries, so an implementation that ignores `algo` applies one
family's revocations to the other's keys.

**Which input decided.** `oca_validate_manifest()` calls
`oca_determine_secure_boot()` once, early, and the determination records what it
observed into your `oca_validation_context_t`: `secure_boot_enabled` for the
verdict, and `secure_boot_device_disabled` when input (2) was reached and
affirmative. A manifest that settles the question at (1) never consults the
device, so `secure_boot_device_disabled` stays clear — the field reports what the
determination saw, not an independent second opinion.

### Secure Boot Determined once, confirmed at every use

The recorded secure boot verdict is a **reference, not a cache**. Every check that gates on secure boot re-derives the whole precedence immediately before acting and requires the live answer to match the record. A disagreement is
`SECURE_BOOT_STATE_CHANGED` and fails the validation.

This is a fault-injection defense. Deriving independently at each check means a single glitched reporter read *at the signature check* skips signature verification. Revocation and anti-rollback had already run on their own, separately obtained answers, and no code compared the various callback secure boot states.
Recording once and having every check simply *read* the record would be worse
still: one glitched determination would disarm all of them at once. Doing both
costs an attacker a consistent fault at the determination **and** at every
confirm.

Two consequences for your code:

- **A reporter must be stable for the duration of a validation.** One that
  answers differently across calls — a fuse still settling during early boot, a
  reporter with a side effect — now fails the validation rather than being
  silently tolerated. If you see `SECURE_BOOT_STATE_CHANGED` on a part you
  believe is healthy, the reporter is the first thing to look at.
- **Escalate it; do not retry.** A retry that succeeds has not established that
  the first answer was wrong.

The reporters are consulted once for the determination and once per gated
check — eight times per validation, nine when the manifest declares
encryption — which is the price of the above. They are fuse or OTP reads; if
that cost is material on your part, it is worth measuring rather than assuming.

**A context no determination has settled is refused.** `secure_boot_determined`
distinguishes "secure boot is not in force" from "nobody has asked yet", which
are otherwise the same zero value and have opposite safe answers. A gated check
handed a fresh, NULL, or corrupted context returns
`SECURE_BOOT_UNDETERMINED` rather than quietly passing by doing nothing. You will
only see it composing checks by hand; `oca_validate()` and
`oca_validate_manifest()` determine before anything that consumes it.

**Advancing device state is a separate, explicit step.** Validation is
read-only — it never writes device state. Once the manifest has passed, by
either entry point, the integrator calls
`oca_commit_security_state(body, &cb, &vctx)` — passing the context that
validation produced, so the commit confirms against the same determination the
decision was made on rather than taking a fresh one at a different moment. This
is why `oca_validate()` takes an optional context: a whole-bundle caller that
intends to commit needs one. It folds four values into device state, bitwise-ORing
each into the stored value (setting bits only, never clearing):

| Fold-in | Callbacks | Suppressed by |
|---|---|---|
| ROOT-key revocation — classic, and PQC on a PQC manifest | `get`/`set_root_key_revocation` | `manifest_security_control` bit 1 |
| Security-version flags | `get`/`set_security_version` | bit 0 |
| Signature cohort enforcement | `get`/`set_signature_cohort_enforce` | bit 4 |
| Signature class revocation | `get`/`set_signature_class_revoke` | bit 5 |

Which signature class authenticated the manifest does not limit what it
revokes: a PQC-only manifest commits its classic revocations and a classic-only
PQC manifest its PQC ones.

Bits 2 and 3 are defined by the format and govern verifier-key device state,
which this library does not implement — see "Not supported" in the README. They
are accepted and ignored.

Before folding in the class revocation the commit re-checks the
`signature_class_revoke` group-code bytes, even though `oca_validate_manifest()`
already did. This function is public and burns fuses, so it does not assume the
caller composed the check; a fragment of a group code reaching OTP is
irreversible. That re-check surfaces as `GROUP_CODE`.

The commit returns a distinct status; a write-back failure surfaces
as `SECURITY_STATE_UPDATE` and does not retroactively invalidate the manifest.

## Enabling PQC secure boot

An OCA-PQC manifest is verified by its classical signature, its PQC
signature, or both, as the manifest's `secure_boot_classic` and
`secure_boot_pqc` bits choose. The library already runs everything that
follows from that choice: per-class authorization, revocation and
verification, and the AND of a hybrid manifest. What a device adds is the
PQC half of each callback, plus a decision the library leaves to you.

**1. Keep PQC compiled in, and budget for its body.** `OCA_SUPPORT_PQC`
defaults to 1. An OCA-PQC body is 36864 bytes against Classic's 4096, and in
the staged flow it stays resident from authentication through the payload step.
The verify callback reads the signed region, key and signature straight out of
that buffer, so it needs no copy of its own.

**2. Verify the PQC signature in `verify_signature`.** Dispatch on the blobs'
`key_algorithm`, then on `primitive_type`: each PQC algorithm reaches the
callback as `OCA_KEY_ALGO_PQC` with its own primitive type, and a primitive
your backend does not implement returns `OCA_FAIL_CALLBACK_UNAVAILABLE`.
ML-DSA-87 (`OCA_PRIMITIVE_ML_DSA_87`) is the PQC algorithm the library accepts
today. Its contract:

- pure FIPS 204 ML-DSA.Verify, with the empty context, over `signed_region`
  exactly as passed — bytes `[0, 5903)` of the body. No pre-hash: a
  HashML-DSA signature, or one made over a digest of the region, must fail;
- read the key and the signature to their blobs' `length` — 2592 and 4627
  bytes for ML-DSA-87, both raw FIPS 204 encodings. The library has already
  refused any manifest whose PQC description is not raw ML-DSA-87 with exactly
  those sizes; the rest of each field is padding;
- an engine that takes the message representative μ rather than the message
  computes it as FIPS 204 does: `tr = SHAKE256(pk, 64)` and
  `μ = SHAKE256(tr ‖ 0x00 ‖ 0x00 ‖ signed_region, 64)`, where the two zero
  bytes are pure ML-DSA's domain separator and the empty context's length;
- return `OCA_FAIL_SIGNATURE` for a signature that does not verify, and
  `OCA_FAIL_CALLBACK_UNAVAILABLE` only when there is no backend for the
  primitive at all.

**3. Provision a PQC anchor in `is_key_authorized`.** A call with
`key_algorithm` `OCA_KEY_ALGO_PQC` carries the PQC key, with its
`primitive_type` and `length`, and the manifest's `public_key_select_pqc`.
Answer it from a PQC anchor only — a classical anchor must never authorize a
PQC key, nor the reverse — and a hybrid manifest needs both families' anchors
to accept. The anchor's shape is yours, but it must bind two things, for the
classical anchor as much as the PQC one:

- **the whole key** — compare or digest all `length` bytes. For a raw RSA key
  that is the exponent as well as the modulus;
- **the selected slot** — accept only a key matching the anchor of a slot whose
  bit is set in `select`. Revocation is decided from that bitmap, so an anchor
  that ignores it lets the holder of a revoked key select a different slot and
  boot. The library refuses a class that selects no key before asking.

The reference harness digests the whole raw key with SHA-256 and holds each
digest for one slot (`--root-key-digest-pqc [<slot>:]HEX64`); the comparison
should be constant time.

**4. Give the PQC family its own revocation state.** `get_root_key_revocation`
and `set_root_key_revocation` are called with `OCA_KEY_ALGO_PQC`. The check
reads that state whenever the manifest enforces the PQC class. The commit,
which runs only under secure boot, writes it for **every** OCA-PQC manifest
unless `manifest_security_control` bit 1 suppresses it — classic-only ones
included, because a manifest's revocations apply whichever class signed it. A
part that verifies PQC needs a PQC revocation store. A part that verifies no
PQC can report an all-zero bitmap and accept the write as a no-op: no PQC key
can be authorized there, so nothing it would revoke is usable anyway. Failing
the write instead is costly. The ROOT-key revocations are committed first, so
every OCA-PQC commit would stop at `SECURITY_STATE_UPDATE` before the
security-version flags and the posture registers are written, and the
device's anti-rollback state would never advance.

**5. Report the signature posture; it decides whether PQC is mandatory.** The
library verifies the classes the manifest enforces, and the device's signature
posture decides which classes a manifest must enforce. A manifest that
enforces only the classical class, Classic or PQC variant, passes on a part
whose posture demands nothing more and whose classical anchor accepts its key.
`oca_check_signature_posture()` applies the posture at every secure boot, from
what `get_signature_cohort_enforce` and `get_signature_class_revoke` report:

- **Require PQC.** Report the PQC bit (bit 1) of the ROOT nibble in cohort
  enforcement byte 0. A manifest that does not enforce the PQC class is then
  refused with `SIGNATURE_COHORT_REQUIRED`. Report both bits to require a
  hybrid manifest.
- **Retire the classical group.** Report the group code `0xCA` in class
  revocation byte 1. Every classical algorithm is then disabled: a manifest
  that enforces the classical class, hybrid included, is refused with
  `SIGNATURE_ALGORITHM_REVOKED`, and a demand for the classical cohort is
  withdrawn. To retire one algorithm rather than the group, report its class
  bit instead.
- **The posture accumulates.** Committing a verified manifest ORs its
  `signature_cohort_enforce` and `signature_class_revoke` into the stored
  registers, so a signed manifest can move a fielded part to PQC without
  provisioning it again. It takes effect from the next boot. Where lifecycle or
  another fuse imposes posture of its own, report the union.
- **Or by anchor.** Authorize no classical key: `is_key_authorized` returns
  `OCA_FAIL_ROOT_KEY_UNAUTHORIZED` for `OCA_KEY_ALGO_CLASSIC`. Only manifests
  that enforce the PQC class alone verify; a hybrid manifest is refused too,
  since it needs both anchors.
- **Compiling Classic out is not the same thing.** `OCA_SUPPORT_CLASSIC=0`
  refuses the Classic variant, but an OCA-PQC manifest signed only
  classically still verifies.

**Reading a PQC refusal.**

| Result | Meaning on the PQC path |
|---|---|
| `ROOT_KEY_UNAUTHORIZED` | No PQC anchor accepted the key, the PQC class selects no key, or, for a hybrid manifest, either family's anchor refused |
| `ROOT_KEY_REVOKED` | The selected PQC key is revoked in the manifest's or the device's PQC bitmap |
| `SIGNATURE` | The PQC signature did not verify, or either half of a hybrid manifest did not |
| `CALLBACK_UNAVAILABLE` | `verify_signature` has no backend for the manifest's PQC algorithm, the PQC revocation state could not be read, or a signature posture reader is missing or failed |
| `CRYPTO_FIELD_SIZE` | The PQC description names an algorithm, encoding or size this library does not accept — today, anything but raw ML-DSA-87 at its exact sizes |
| `SIGNATURE_CLASS_CONTROL` | `secure_boot_pqc` on a Classic manifest, or secure boot with no class selected |
| `SIGNATURE_ALGORITHM_REVOKED` | The device has disabled the PQC algorithm's class, or the whole PQC group (`0xAC`) — or, for a hybrid manifest, the classical one's |
| `SIGNATURE_COHORT_REQUIRED` | The device demands a cohort the manifest does not enforce: PQC of a classic-only manifest, or the classical cohort of a PQC-only one |
| `UNSUPPORTED_VARIANT` | This build compiled PQC out |

**Testing a PQC backend.** `configs/oca_pqc_signed_example.yaml` (PQC only)
and `configs/oca_pqc_hybrid_example.yaml` build ML-DSA-87 manifests signed with
the committed development key — test material, never for shipped images. The
fixtures `pqc_secure_mldsa`, `pqc_hybrid_rsa`, `pqc_hybrid_ecdsa` and
`encrypted_aes_pqc_mldsa` under `test/fixtures/configs/` cover each
combination. ML-DSA signing is hedged, so two builds of one config differ in
the 4627 signature bytes and nowhere else. `verify_pqc()` in
`test/openssl_crypto.c` and `key_matches_anchor()` in `test/cli_hwid.c` are the
reference shapes, and `oca-validate --root-key-digest-pqc`,
`--revoked-root-keys-pqc`, `--signature-cohort-enforce` and
`--signature-class-revoke` exercise the anchor, the revocation state and the
signature posture from the command line. Before trusting a new backend,
confirm that it refuses what `tests/test_oca_c_validator_integration.py` builds
to be refused: a signature made with a non-empty context, and one made over a
SHA-256 or SHA-512 digest of the region. A backend that accepts either is
verifying a different construction from the one the packer signs.

## Upgrading to 0.7

Changes an existing integration should check. Most show only at run time.

- **Revocation is called per family.** `get_root_key_revocation` and
  `set_root_key_revocation` are now called with `OCA_KEY_ALGO_PQC` as well as
  `OCA_KEY_ALGO_CLASSIC`, and the commit does so for every OCA-PQC manifest. An
  implementation that ignored `algo`, as the earlier reference harness did,
  would OR PQC revocations into its classical state, irreversibly. Honor
  `algo`; step 4 of [Enabling PQC secure boot](#enabling-pqc-secure-boot)
  covers a part with no PQC store.
- **The commit requires authentication.** `oca_commit_security_state()` returns
  `OCA_FAIL_SIGNATURE` and writes nothing unless a signature check ran and
  passed for the context it is given. Pass the context your validation produced.
- **An enforced class must select a key.** A manifest whose enforced class
  selects no key fails `ROOT_KEY_UNAUTHORIZED` before your anchor is asked.
- **The anchor contract is explicit.** `is_key_authorized` must bind the whole
  key and the selected slot (see the callback table). The earlier reference
  harness bound neither.
- **Blobs carry their length.** `oca_crypto_blob_t` gains `length`, the
  validated size of the value. Code that only reads blobs needs no change.
- **The signature posture is enforced at boot.** `get_signature_cohort_enforce`
  and `get_signature_class_revoke` are now read at every secure boot, not only
  by the commit, and are required there: a NULL reader fails every secure boot
  with `CALLBACK_UNAVAILABLE`. A part with no posture store reports all zeros.
  Because earlier commits have already ORed manifests' posture fields into the
  stored registers, a device can refuse at boot a manifest it accepted before
  upgrading — check what your fielded parts hold before shipping the update.
- **New check and result codes.** `oca_check_signature_posture()` runs inside
  `oca_validate_manifest()`; a hand-composed sequence must call it before
  `oca_check_signature()`, which refuses a context it did not vouch for. It
  returns `OCA_FAIL_SIGNATURE_COHORT_REQUIRED` and
  `OCA_FAIL_SIGNATURE_ALGORITHM_REVOKED`; a `switch` over `oca_result_t` with
  no `default` needs both cases.
- **The PQC description is pinned.** The PQC class accepts raw ML-DSA-87 at its
  exact sizes; anything else is `CRYPTO_FIELD_SIZE`.
- **Secure-Boot-only fields are ignored while secure boot is off.** A
  non-secure manifest with populated signing fields now validates, and a device
  that enforces secure boot checks a manifest's signing description even when
  the manifest leaves its own secure-boot bit clear.
- **Hand-composed sequences.** `oca_check_crypto_field_sizes()` now takes
  `(body, cb, ctx)`, and the internal layout constant
  `OCA_LEN_PUBLIC_KEY_CLASSIC_REVOKE` is now `OCA_LEN_ROOT_KEY_BITMAP`.
- **The reference CLI** needs OpenSSL 3.5 or later. The library itself has no
  OpenSSL dependency.
