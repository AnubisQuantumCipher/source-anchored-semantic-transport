# Evaluate a declared, source-bound obligation

The optional evaluator connects a predicate occurrence in a decoded meaning unit
to its own reports. It computes `SATISFIED`, `VIOLATED` or `UNKNOWN`, then can reject
a submitted verdict that disagrees. Two predicates no longer have to share one
observation. The original evaluator and its wire format remain unchanged.

This is a conditional calculation over an explicit reading and explicit reports.
A report saying something happened is still a report. Its quotation can be
checked without proving that it is true, authentic or correctly interpreted.

## Run the complete local demonstration

Use the GNAT toolchain and an existing installed decoder bundle. No service or
account installation is involved. Commands run from this repository:

```sh
gprbuild -q -P evaluation/transport_bound_eval.gpr
gprbuild -q -P evaluation/tests/bound_checks.gpr
evaluation/tests/bin/transport_bound_eval_checks
gnatprove -P evaluation/transport_bound_eval_proof.gpr -U --level=2 \
  --report=all --warnings=error --checks-as-errors=on --proof-warnings=on -j1
python3 -I -S -B -Werror install/test_bound_evaluation.py \
  --bundle /absolute/path/to/installed/decoder \
  --native "$PWD/evaluation/bin/transport_bound_eval_native" \
  --evidence /absolute/path/to/a/new/evidence-directory
```

The demonstration encodes separate requirement, report and history documents into
matched share text, meaning ZIP and readable lexicon. It checks exact recovered
source bytes, typed bindings, conditional outcomes and refusal controls. One case
uses two review completions; the other uses an ordered actor/item/recipient
predicate under a prohibition. Neither source text nor a candidate is executed.

For another prepared recipient, use the existing [handoff preparer](HANDOFF_CLIENT.md)
and pass its `manifest.json` to the evaluator:

```sh
python3 -I -S -B -Werror install/transport_bound_evaluate.py \
  --manifest /absolute/receiver/manifest.json --expect-manifest-sha256 MANIFEST_SHA256 \
  --contract /absolute/contract.json --expect-contract-sha256 CONTRACT_SHA256 \
  --observations /absolute/reports.json --expect-observations-sha256 REPORTS_SHA256 \
  --native /absolute/transport_bound_eval_native --expect-native-sha256 NATIVE_SHA256
```

Hold the digests independently of the received inputs. The CLI verifies the
copied helper files, decoder bundle, package pair and declared input identities.
It returns a deterministic `evaluation` object and separate process timing.
Adding `--candidate /absolute/conclusion.json` checks a conclusion after evaluation;
it does not save a handoff draft or authorize any further action.

## Contract and binding identities

`transport/bound-evaluation-contract/1` is a closed JSON object with these fields:

| Field | Meaning |
|---|---|
| `schema`, `profile` | Exact version and `transport/ground-obligation-evaluation/1`. |
| `package_identity` | Exact `STS1:` identity of the decoded meaning ZIP. |
| `unit_id`, `unit_sha256` | Selected unit and SHA-256 of its canonical decoded unit view. |
| `source_id`, `source_sha256` | Selected unit's exact source revision. |
| `native_sha256` | Exact evaluator executable supplied separately. |
| `terms` | Distinct `{node, sort}` declarations for ground term occurrences. Sorts are nominal identifiers. |
| `predicates` | `{id, name_node, argument_sorts}` declarations with ordered argument types. |
| `bindings` | `{node, predicate, arguments}` entries matching every predicate occurrence exactly. |

Node numbers refer to the decoded meaning tree, not an inferred sentence or a
matching word. The compiler checks the existing meaning grammar first, then the
nominal signature and exact ordered occurrences. Equal spelling does not create
an alias. A binding digest includes the contract digest, node, predicate
declaration and ordered typed arguments. The contract digest transitively binds
the package, source, unit, dictionaries and evaluator identity.

Unused declarations, missing predicate bindings, wrong sorts, changed actors,
changed revisions and unsupported versions are errors. A changed contract needs
new report bindings; a previous report cannot silently migrate to it.

## Reports and operator behavior

`transport/bound-observations/1` contains `schema`, `contract_sha256` and `records`.
Each record has `binding_sha256`, `truth`, `provenance` and nonempty `citations`.
Truth is `KNOWN_TRUE`, `KNOWN_FALSE` or `UNRESOLVED`. Provenance is one of
`attributed_report`, `test_result`, `contract_result`; these are declared classes,
not authentication results. Citations use the existing exact source ID, source
digest, half-open UTF-8 byte span and quotation contract.

| Supported operator | Evaluation profile |
|---|---|
| Ground `pred` | Receives only reports bound to that exact occurrence. |
| `not` | Negates a fact; unresolved stays unresolved. |
| Fact `and` | False if either input is false; true only if both are true; otherwise unresolved. |
| `must` | Maps the enclosed fact to violated, satisfied or unknown. This checks a declared obligation condition and grants no permission. |
| Obligation `and` | Violated if either obligation is violated; satisfied only if both are satisfied; otherwise unknown. |

Missing reports, conflicting true/false reports, and explicit unresolved reports
combined with a known report resolve to unresolved. Report order and timestamps
do not select a winner. The SPARK parser performs this resolution from a report
mask; Python only combines the declared mask bits.

Quantifiers, exceptions, conditions, attribution operators, uncertainty operators,
temporal operators, opaque atoms, variables, nested obligations and mixed
fact/obligation conjunctions are outside this profile and refuse. Their nodes
are never stripped to make an evaluation possible. Source ambiguity records also
refuse. Context links, related uncertainty records and unevaluated units remain
visible in the result. Evaluating one unit does not settle the surrounding source.

## Checked conclusions

The closed `transport/evaluation-conclusion/1` object has `schema`,
`evaluation_sha256`, `outcome` and `commentary`. Compute the evaluation digest over
the canonical `evaluation` object, excluding process timing. `outcome` must equal
the computed root result. `commentary` is a required string that may be empty;
its prose is not graded by this check. Correct quotations cannot excuse a wrong
`outcome`, but a matching outcome does not certify accompanying prose.

## Bounds and wire format

Contract, observation and candidate inputs are each bounded at 32768 bytes, with
the existing safe-JSON depth/value limits. There are at most 256 meaning nodes,
64 term declarations, 32 predicate declarations, 64 bindings, 64 report records
and 64 total report citations. Each predicate has at most six ground arguments.
Existing source, package, reader and decoder bounds remain unchanged.

`STV1` uses four magic bytes, a big-endian unsigned 16-bit node count, then six
bytes per node: operator byte, report-mask byte, left reference and right reference
as big-endian unsigned 16-bit values. References are one-based and backward;
zero means absent. Operators retain the original evaluator enumeration:
unbound fact, bound fact, negation, fact conjunction, obligation, norm conjunction.
The bridge emits bound facts. Only bound facts may carry a nonzero mask.
Mask bits are unresolved report=1, false report=2, true report=4. Only masks 2 and
4 resolve to known truth; all other admitted masks resolve to unresolved.
The maximum frame is 1542 bytes. Invalid counts, types, connectivity, masks,
versions, truncation and trailing bytes refuse.

The native file boundary accepts a bounded regular file and rejects a final
symlink, FIFO, directory or device. The caller's process timeout remains necessary
for operating-system IO. Native output is fully checked for node identity, sort,
count and allowed value before a result is exposed.

## Evidence boundary

The focused proof covers the named SPARK evaluator and parser contracts, including
per-node evaluation, default tails, typed connected parser success, consistent
observations and rejection reset. It does not prove byte-to-tree correspondence,
the C/OS IO boundary, Python lowering, compiler behavior or source interpretation.
Those boundaries require their own tests and retained counterexamples.

This addition uses the existing decoder as a dependency and does not change a
previously pinned bundle. Authentication, legal force, natural-language entailment,
semantic completeness and behavioral superiority remain separate claims.
