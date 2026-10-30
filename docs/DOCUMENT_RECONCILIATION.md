# Whole-document reconciliation

`sentinel_v1.document_analysis.reconcile_document` checks the complete source,
binding, index, paragraph blocks, job blocks and dependency closure once per call.
It then replays each job against that owned checked context. Each job still
checks its records, immutable registry snapshot, request, provenance and generation
admission. Direct public job, request and import entry points retain fresh checks.
There is no global cache or context shared between calls.

This changes repeated validation work, not the public signatures, schemas,
resource limits or interpretation status. Missing, stale or mismatched evidence
still refuses. A recorded generation import is not semantic qualification.

Run the public deterministic controls from the repository root:

```sh
python3 -I -S -B -Werror tests/check_sentinel_v1.py
python3 -I -S -B -Werror tests/test_sentinel_document_analysis_reuse.py
python3 -I -S -B -O -Werror tests/test_sentinel_document_analysis_reuse.py
python3 -I -S -B -Werror tests/test_sentinel_document_analysis_independent.py
```

CI runs the reuse suite in both modes alongside the existing controls. The new
controls check aggregate/per-job receipt equality, constant full-source validation
count, tampering and isolation across calls and documents. Independent held-out
refusal tests are separate from the builder's tests.

On the retained private 69-job input, the fresh original API replay completed
near its existing wall deadline after 72 complete document validations. The
earlier timeout remains a failure; it was not reproduced as a timeout in that
fresh run. The repaired API completed normal and optimized runs under the same
limits with one full validation. Every job receipt and the aggregate were
compared byte for byte with the retained originals. This is finite execution
evidence, not a universal latency bound. Reproducing that measurement requires
the licensed input; public synthetic controls contain no private book text.

The resulting book status remains `INCOMPLETE_GENERATION`: one recorded import
and 68 pending jobs. OCR accuracy, semantic completeness, QUORUM admission and
native semantic qualification are separate obligations. The optimization grants
no execution authority and no broader formal proof.
