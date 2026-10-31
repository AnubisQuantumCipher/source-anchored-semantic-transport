# Export-reader CI cache preparation

Both export-reader jobs at `98baa39` exhausted the existing five-minute job
limit. The normal and optimized control suites passed, but the complete jobs
did not. Their logs and failure receipt remain here; passing test subsets are
not recorded as successful jobs.

The workflow now prepares optimized standard-library bytecode in the ephemeral
CI interpreter before running the original commands. The preparation imports
only a fixed list of standard-library modules, with isolated mode and without
site loading. It imports no project code. Before/after cache observations and
import timings are emitted for hosted verification. The tests still run with
`-I -S -B -Werror`, in both modes, under all original child limits and the same
five-minute job limit.

`-B` prevents cache writes; it does not prevent reading a valid existing cache.
Repeated compilation of missing optimized library caches is the candidate cause.
Hosted observations and a complete successful job are required before claiming
this repair worked. This is CI setup accounting, not an application speedup or
a reduction in the codec's measured cost.

The original workflow, reader, tests, fixtures, receipt generator and receipt
remain preserved. `check_continuity.py` checks the original receipt and admits
only the exact cache-preparation insertion and corresponding continuity-command
replacement. All other source and evidence entries must still match. It does
not rewrite the old receipt or treat its old workflow pin as the new one.

Run the continuity checks with:

```sh
python3 -I -S -B -Werror examples/export-reader-ci-warmup/check_continuity.py
python3 -I -S -B -O -Werror examples/export-reader-ci-warmup/check_continuity.py
python3 -I -S -B -Werror examples/export-reader-ci-warmup/test_continuity.py
python3 -I -S -B -O -Werror examples/export-reader-ci-warmup/test_continuity.py
```

The continuity controls also run in a separate CI job; they do not consume or
extend the original export-reader job's five-minute budget.

The complete receiving and QUORUM repair evidence remains in
[the audit report](../../docs/AUDIT_REPAIR_20261029.md).
