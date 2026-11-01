# Additive ML-DSA-87 manifest endorsement

This directory is a new opt-in boundary. It changes no historical manifest,
decoder, fixture, document/native source identity, frame or receipt. The caller
must define and validate its new strict manifest-body schema and verify this
envelope **before opening frame payloads or invoking package dependencies**.

The closed envelope contains `schema`, `algorithm`, `domain`, `signing_mode`,
`manifest`, `public_key`, `revocation` and `signature`. Canonical encoding is
ASCII JSON, sorted keys, `ensure_ascii=True`, compact comma/colon separators,
then exactly one LF. Floats, duplicate keys, unknown envelope/revocation fields,
oversized and excessively nested JSON are refused. Signing covers the complete
canonical envelope with `signature` explicitly `null`; the actual signature
occupies that slot afterward. This avoids circular self-signing while retaining
every other field. The context is `SAST-MANIFEST-MLDSA87-v1`.

The embedded public key is not a human identity. Verification requires a
separately admitted public key, a separately held registry identity, and a
current revocation decision `NOT_REVOKED`. Embedded `seal_status` is one of
`ACTIVE`, `REVOKED`, `COMPROMISED`, `UNKNOWN` and is a signed declaration about
seal time only. Verification requires embedded `ACTIVE`; all other states
refuse, as do independent current `UNKNOWN`, `REVOKED` and `COMPROMISED`.
The calling profile owns current registry lookup, freshness, key admission,
identity and authorization. Endorsement does not prove semantic correctness,
reading coverage, or execution authority.

The sole provider is [pq-code-package/mldsa-native](https://github.com/pq-code-package/mldsa-native/tree/17ebc1aa493265515a92239c76507ae28777cd4a)
at commit `17ebc1aa493265515a92239c76507ae28777cd4a`, portable C backend,
parameter set 87. Sizes come from its public header: public key 2592 bytes,
signature 4627 bytes. The shim uses only randomized signing, Linux nonblocking
`getrandom`, a 821-attempt signing cap and bounded RNG retries. RNG failures
refuse; no zero-seed or deterministic fallback exists in the shim. Signatures
are checked before output. Runtime CPU/address/core limits and caller deadlines
bound the process. Kernel process teardown is relied on for interrupted process
memory; normal return explicitly wipes secret and message buffers. No private
key is logged or returned through stdout. Test key generation writes secret
material only to an explicit caller-owned memfd. Production signing reads an
explicit inherited key descriptor.

`NativeProvider` checks the binary pin before each invocation, copies bytes
into a sealed memfd, and executes that immutable descriptor through
`/proc/self/fd`, passing only `LC_ALL=C`. The reviewed provider has no child
creation calls; deadline cleanup kills and reaps its one owned process.
Input is a fixed-length public key/signature followed by a big-endian 4-byte
message length and exact message bytes, followed by EOF. Maximum message is
8388608 bytes. This is a full canonical-message signature, with no prehash
substitution. Output sizes are fixed by the reviewed binary. The provider
limits AS to 64 MiB, CPU to 10 seconds and disables core dumps. The Python
caller deadline is 15 seconds per protocol stage.

The signed document profile preserves the old 8388608-byte **total metadata**
ceiling: envelope plus all seven other metadata payloads. Public key/signature
and new declaration bytes consume that same budget. Some old metadata sets
already at the ceiling therefore cannot migrate and must refuse explicitly.
Original source, frame, derived-reading and segment limits are unchanged. The
new declaration pins the exact old `reading.json` bytes and carries the typed
unit count; it does not duplicate the complete record inside the envelope.
The original signed body already pins original source and derived-reading
identities. The recipient checks the pinned reading record after signature
verification and before frame payload reads.

The generic signature boundary admits 135249 JSON value nodes, derived from
the maximal closed new document shape: one object plus seven scalar nodes for
each of 16384 source and 512 derived-reading frame rows, plus 81 fixed-shape
nodes with both optional pins present. The 65536-segment record remains in
`reading.json` and is checked by the legacy reading validator; that list is
not duplicated into the signed envelope. Traversal uses an iterator stack,
with at most 33 frames for the legacy depth ceiling 32; it checks capacity
before adding a stack frame and never allocates a pending tuple per sibling.
This is engineering reasoning and tested structural accounting, not a formal
proof of the parser or Python runtime. Capacity qualification has a private
256 MiB AS / 30-second CPU / 16 MiB output ceiling; it does not alter the C
provider's 64 MiB AS / 10-second CPU limits or source/frame capacities.

`ephemeral_test_seal` is explicitly local-test-only: one fresh key lives in one
provider process, its public key is returned, and its secret key never crosses
the process boundary. `sign_manifest(manifest, public_key, secret_key,
registry_id, current_revocation, declared_status='ACTIVE')` implements the
production signing boundary with an explicit caller-provided key path or FD.
It accepts only a regular file owned by the effective user, mode 0600 or
stricter, with the header-defined ML-DSA-87 secret-key length. Paths are opened
without following a final symlink. Python never reads secret bytes. C checks
key validity and derived-public-key equality before randomized signing, checks
the resulting signature, and wipes secret buffers. Keys are never selected
from package content. No actual production key has been admitted or used.
Public-key and registry parameters must not be taken from the envelope
and relabeled as independent trust.

```python
from manifest_signing.manifest import NativeProvider, verify_envelope

provider = NativeProvider(binary_path, independently_pinned_binary_sha256)
body = verify_envelope(envelope_bytes, provider, independently_admitted_key,
                       independently_pinned_registry_sha256, current_status)
# Validate the new profile's closed body schema, then read its frame payloads.
```

Acquire only after resource admission using `fetch_sources.py --output SOURCE`;
build with `build_provider.py --source SOURCE --output NEW_BUILD`. Neither script
runs upstream build/install code. Acquisition checks Git blob identities from
the exact-commit official tree; build checks the acquisition inventory and
records source, compiler, configuration, command and binary identities. One
build is ML-DSA-87 only. Tests require `SAST_MLDSA87_BUILD=NEW_BUILD`; RNG fault
controls are separate test binaries built with `--rng-test-fail-after 0` and
`--rng-test-fail-after 1`, named `rng-fault-0` / `rng-fault-1` under the directory
specified by `SAST_MLDSA87_RNG_FAULT_ROOT`. These fault binaries must never be
admitted as normal providers.

Upstream proof statements are attribution, not local proof runs. The pinned
[README](https://github.com/pq-code-package/mldsa-native/blob/17ebc1aa493265515a92239c76507ae28777cd4a/README.md)
describes CBMC coverage of C memory/type safety and undefined behavior, with
documented exceptions. This local build uses portable C. Its
[SOUNDNESS](https://github.com/pq-code-package/mldsa-native/blob/17ebc1aa493265515a92239c76507ae28777cd4a/SOUNDNESS.md)
also explains separate assembly proof assumptions and rejection-pattern leakage.
No local CBMC/HOL Light/Isabelle run, whole-system proof, timing measurement,
fault-injection resistance, power/EM resistance or FIPS module validation is
claimed. The new shim, Python boundary, compiler and operating system remain
outside any claimed local proof chain.

[FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf), sections
3.4–3.6, distinguishes signing mode, key-management assurances and length checks.
The same verifier accepts hedged and deterministic ML-DSA signatures; signature
bytes alone cannot prove fresh signing randomness. Hedged-only is an enforced
provider creation policy and signed declaration, not verifier-derived RNG
evidence. `getrandom` usage here does not establish an approved FIPS RBG.
