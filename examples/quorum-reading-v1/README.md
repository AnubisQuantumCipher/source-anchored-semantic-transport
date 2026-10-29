# Reading records and retained disagreements

This component validates the links behind recorded readings before computing
stance counts. Duplicate records from one Seat do not add eligible support.
Unexpected or withdrawn readings remain in raw counts. Every disagreement,
abstention, challenge and withdrawal remains visible, including challenges that
no reading explicitly lists.

The internal interface is:

```python
check_reading_aggregation(body_raw, originals, held_update_pins, held_withdrawal_pins)
```

Inputs use the same canonical Body, exact source tuples and separately supplied
update pins as the context component. `held_withdrawal_pins` is a mandatory exact
tuple of `(event_id, sha256, byte_length)` for every complete canonical withdrawal
record. Missing pins cannot be filled from the candidate. Matching proves
integrity against supplied values, with independent custody still unknown.

All inherited gates run first, followed by complete provenance, run, reading,
challenge and withdrawal reference checks. The withdrawal predecessor graph is
checked separately within its existing bound. A manual illustrative withdrawal
can exclude a manual reading from illustrative eligible counts when its declared
author string matches. That equality is not authentication or revocation
authority. External run records remain unverified and ineligible, even when
they name a model, family or policy source.

The original claim-structure comparison travels through an owned internal
bundle. Agreement cannot turn an opaque, mismatched or insufficiently scoped
claim into a structurally qualified claim. OPPOSE and DISPUTE agreement remain
dissent; there is no majority or truth threshold.

The [contract](contract.json), [profile choices](design-addendum.json) and
[resource addendum](output-resource-addendum.json) specify exact behavior.
Each complete claim entry is charged before insertion into the result. Output
overflow refuses the whole result; required evidence is never trimmed.

Reproduce from the repository root:

```sh
python3 -I -S -B -Werror install/test_quorum_reading.py
python3 -I -S -B -O -Werror install/test_quorum_reading.py
python3 -I -S -B -Werror examples/quorum-reading-v1/prepare_receipt.py --check
python3 -I -S -B -Werror install/test_quorum_context.py
python3 -I -S -B -Werror install/test_quorum_impact.py
```

The first independent controls all failed at the earlier canonical-order gate:
their InputManifest rule pins used rule-ID order instead of complete canonical
Pin-object order. Those original candidates, expectations and failed outputs
remain under `focused/`. An independent review verified the additive
`focused/revision-02/` correction: only that ordering, matching manifest pins and
mechanical body pins changed. Manual expected counts, dispositions and deliberate
invalid pins stayed unchanged. The checker required no repair. These are
development fixtures, including synthetic external-run specimens, not actual
model provenance or held-out acceptance results.

The suite compares complete outputs for the original-annotation and transport
development arms with the same checker. Hostile argument and separately labeled
helper probes check explicit failure behavior with assertions disabled as well.
The receipt binds source files and independent observed results. Tested Python
does not extend the existing native SPARK proof. Installed decoder identity is
unchanged. Full replay still needs external request/runtime identities, generic
record pins, complete reference closure and its frozen global validation order.
External human validation and measured transport benefit remain pending.
