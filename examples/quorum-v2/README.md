# QUORUM policy and replay verification

The version 2 CLI computes support thresholds from explicitly held run records.
The replay adapter recomputes source checks through the existing qualified
decoder and retains findings such as `NEEDS_REVALIDATION` alongside the threshold.

See [usage and interfaces](../../docs/QUORUM-V2.md). The additional
[model/family coherence contract](../../docs/quorum-v2-coherence-addendum.json)
requires each exact model ID to map to one family ID. Conflicting assignments
are refused. Repeated seats using the same model and family remain permitted,
but that family is counted once. Different aliases may still refer to the same
underlying model; this check does not authenticate models or establish independent
errors.

The first frozen review missed that coherence defect. Its source snapshot,
receipts and failures remain unchanged. The current
[independent review](coherence/independent-review.json) records the correction
and reruns: the original 87 policy cases, 43 replay-adapter controls, nine new
coherence cases, and a nine-seat synthetic companion using actual source replay,
in normal and optimized Python.

From the repository root:

```sh
python3 -I -S -B -Werror examples/quorum-v2/coherence/check_continuity.py
python3 -I -S -B -Werror install/test_quorum_v2_coherence.py
python3 -I -S -B -O -Werror install/test_quorum_v2_coherence.py
```

The original `SHA256SUMS` intentionally retains its historical schema pin.
Use the continuity checker for the current tree: it admits only the exact
reviewed schema correction and verifies the other original files, new contract,
test, historical source, and correction evidence. The old receipts are not
rewritten to make the correction disappear.

The packed independent policy oracle and reproduction commands are documented
in the usage guide. Synthetic nine-seat results establish tested policy behavior;
they are not nine actual independent model observations. Python policy checks do
not replace the native semantic evaluator or its separate proof obligations.
