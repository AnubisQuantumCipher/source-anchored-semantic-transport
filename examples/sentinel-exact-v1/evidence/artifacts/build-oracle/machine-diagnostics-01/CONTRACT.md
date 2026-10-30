# Machine diagnostic gate, frozen before implementation

An additive conservative gate, not a change to GNAT truth semantics. The source04
run discharged its reported115 obligations but contains a warn_error record whose
active/potential meaning is unresolved. Preserve that fact; never assert an active
warning merely from the array name. The new gate refuses ANY nonempty warn_error
array, regardless of how_proved. No warning is suppressed or silently ignored.

Read exactly the fixed unit's .spark JSON, at most1048576 bytes, ASCII/depth32,
no duplicate keys/nonfinite constants. Floats may appear only as discarded timing
metadata; never use them in an acceptance count, comparison or decision. JSON
float tokens become an inert nonnumeric sentinel; integer count comparisons must
check exact int type. Require the closed currently declared top-level schema and
list/dict types. Require pragma_assume, skip_flow_proof and skip_proof empty.
Require all proof/flow rows severity info, no nonempty suppression, and how_proved
in {prover,trivial,flow}. Bound both arrays to4096. Their complete lengths must
equal the independently parsed text report's prover/flow totals. Keep the original
text categories, source roster, positive contracts and all clean/zero checks.
This supplements them; it is not a proof of the report generator or whole system.

Literal control oracle: synthetic proof3/flow2 and empty forbidden arrays passes;
nonempty warn_error with how_proved=trivial REFUSES; changing it to warning/error,
nonempty skip/pragmaAssume, proof/flow count mismatches, missing field, unknown
field, duplicate key, nonfinite/deep/truncated/oversized JSON, suppressed record,
non-info severity and unknown proof method REFUSE. Benign finite timing float
metadata may be ignored and cannot change any count or verdict. Existing35
summary controls, mixedannotation controls and source-pin checks remain unchanged.

Source05's sole parentheses delta is a separate reviewed source epoch. No actual
run is granted by this contract; root admission follows independent code/tests
review and newly derived source roster. The old raw record remains UNRESOLVED,
not retroactively accepted or labeled an emitted warning.
