# Public integration evidence

This directory records preparation, not combined-main acceptance. All content in
`synthetic-source.txt` is an authored PUBLIC SYNTHETIC fixture. The derived
`receipt.json` checks its exact bytes and declared repository source identities;
it runs no semantic evaluator, model, native provider or decoder.

```sh
python3 -I -S -B -Werror tests/check_manifest_signing.py
python3 -I -S -B -Werror examples/sentinel-v1-integration/readback.py --check
python3 -I -S -B -O -Werror examples/sentinel-v1-integration/readback.py --check
```

`source-snapshot.json` is an allowlisted derivation from frozen local receipts.
Its provenance map pins the exact original receipt bytes. It retains failures
and distinguishes the historical full regression from the later adapter review.
`acceptance-matrix.json` carries the independent preparatory gate scopes and
acceptance evidence, all UNRUN for a final combined revision. Original receipts
were not changed or retargeted. `readback.py --check` validates deterministic
public derivation and source continuity; it does not authenticate the provenance
or reproduce unavailable private inputs. The custodian separately retains the
bounded metadata exporter and its original-byte comparison receipt.

Private corpus entries contain hashes, finite verdict IDs and statuses only.
Reproduction requires original licensed inputs and held assessment materials.
No copyrighted source text, raw model output, oracle answer, private path,
secret key or encrypted message is included. Finite book assessment remains
unadjudicated and cannot establish semantic completeness.

See [integration scope and required acceptance](../../docs/SAST_MAIN_INTEGRATION.md).
`ci_gate.py` is used by mandatory signing CI: it requires all three separately
built provider binaries before controls run and rejects every skipped test.
The signed document suite mocks provider/native execution; only the crypto
suite exercises the actual ML-DSA provider. A complete signed document/native
round trip remains separate and pending.

The later transferred SENTINEL source has its own full normal/optimized suite
receipt. Its scope excludes future combined-source acceptance. A later targeted
book generation also has a raw-final pin and structural-import receipt; semantic
assessment is still pending and whole-book completeness remains UNPROVEN. The
older pending admission, historical full-suite receipt and failed attempts remain
separate observations with unchanged original provenance.

All executable entrypoints preserve stricter inherited soft and hard resource
limits; their declared ceilings are maximum requests, without fallback.
