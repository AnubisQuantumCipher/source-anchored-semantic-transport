# Declared change impact

When a supplied replacement or withdrawal targets a source version, this component
finds the claims that depend on it. It returns `NEEDS_REVALIDATION` with every
declared dependency path. A quotation can remain unchanged while its declared
context changes; that claim still requires review.

The internal Python interface is:

```python
check_declared_impact(body_raw, originals, held_update_pins)
```

`body_raw` is complete canonical Body bytes. `originals` is the exact tuple of
`(alias_id, SourceKey, immutable_bytes)` accepted by the source component.
`held_update_pins` is a separately supplied exact tuple of
`(event_id, sha256, byte_length)` for every complete canonical UpdateNotice.
Missing pins cannot be derived from the candidate. Matching them establishes
integrity against the supplied values; independent custody remains `UNKNOWN`.

Every call performs the existing input, source and claim gates first. It then
checks exact dependency targets, all graph components, update pins and fields,
provenance/evidence record pins, event predecessors and historical artifacts.
Parallel labeled edges and separate notices remain separate path evidence.
Conflicting notices remain visible without selecting a winner. Historical
`PRIOR_COMMITTED_UPDATE` records must carry exact canonical event bytes; those
events still contribute change impact. History classifications remain supplied
labels, and no notice or decoded statement grants execution permission.

The [contract](contract.json) fixes refusal order and caps. Enumeration uses a
bounded iterative stack, prunes unreachable branches and accounts for the whole
output before returning success. Too many paths, missing targets, cycles or
output overflow refuse the complete result; no truncated success is returned.

Reproduce from the repository root:

```sh
python3 -I -S -B -Werror install/test_quorum_impact.py
python3 -I -S -B -O -Werror install/test_quorum_impact.py
python3 -I -S -B -Werror examples/quorum-impact-v1/prepare_receipt.py --check
python3 -I -S -B -Werror install/test_quorum_claim.py
```

The suite retains complete manually specified outputs, independent controls,
hostile caller types, refusal precedence and separately labeled helper resource
probes. Identical checks serve the original-annotation and transport-projection
development arms. This is component parity, not measured transport advantage.
First preparation corrections and the owner test-harness failure remain in the
evidence. The source-derived receipt binds actual test outputs and source files.

This component is tested Python, not a new SPARK proof. The installed decoder
inventory remains unchanged. Full Task/Manifest/Reading/runtime and global
reference closure, full replay, external users, measured benefit and release
acceptance remain unfinished. `UNCHANGED_DECLARED_CLOSURE` cannot establish that
undeclared dependencies are absent or that an offline source is current.
