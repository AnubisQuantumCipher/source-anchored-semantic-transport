# Bind an obligation to a recomputed finite test

`install/transport_bound_check.py` connects a declared predicate occurrence to
an actual bounded test of a proposed function replacement. It checks the original
source revision, interprets the proposed replacement as data, visits every state
in the declared finite domain, and sends the resulting fact to the existing
SPARK obligation evaluator. It executes no supplied function or command.

A received test receipt is optional. When supplied, the tool recomputes the test
and requires the receipt to match exactly. Editing a reported outcome, reusing a
receipt for another candidate, or changing the expected table cannot silently
turn a failed test into a passing one under the original held identities.

## Run

Use a trusted checkout, the [prepared receiving directory](HANDOFF_CLIENT.md),
and the existing [bound evaluation contract](BOUND_EVALUATION.md):

```sh
python3 -I -S -B -Werror install/transport_bound_check.py \
  --manifest /absolute/receiver/manifest.json --expect-manifest-sha256 MANIFEST_SHA256 \
  --contract /absolute/contract.json --expect-contract-sha256 CONTRACT_SHA256 \
  --test /absolute/test.json --expect-test-sha256 TEST_SHA256 \
  --replacement /absolute/replacement.json --expect-replacement-sha256 REPLACEMENT_SHA256 \
  --native /absolute/transport_bound_eval_native --expect-native-sha256 NATIVE_SHA256
```

To check an existing receipt, also supply `--receipt /absolute/receipt.json` and
`--expect-receipt-sha256 RECEIPT_SHA256`. A mismatch refuses before a native
evaluation is exposed. Hold input identities independently of received data.
The invocation prints its receipt; it does not apply a patch or authorize an
action. Preserve that output separately if required.

## Finite test specification

`transport/finite-predicate-test/1` is a closed JSON object:

| Field | Contract |
| --- | --- |
| `schema` | Exact schema above. |
| `binding_sha256` | One exact predicate binding from the bound evaluation contract. |
| `checker_sha256` | SHA-256 of canonical `transport_finite_check.checker_identity()`. |
| `base_source_id`, `base_source_sha256` | Original function source in the decoded package. |
| `function_name` | Fixed ASCII identifier. |
| `parameters` | Ordered, distinct parameter names, matching the exact source signature. |
| `domains` | One domain per parameter: `{type: "boolean"}` or `{type: "integer", min: INTEGER, max: INTEGER}`. |
| `expected_bits` | A nonempty string containing one `0` or `1` for every declared state. |

The caller establishes this specification before candidate evaluation. State
order is the Cartesian product in parameter order, with the last parameter
changing fastest. Booleans use `False`, then `True`; integers use ascending order.
The empty parameter list has one state. Cardinality is checked before enumeration
and must not exceed 512. A supplied prefix or sample cannot masquerade as the
complete declared table.

The table is an explicit interpretation chosen by its author. Matching it proves
neither that it expresses the source correctly nor that its finite domain covers
every application input. Those are separate review obligations.

## Replacement data

`transport/function-replacement/1` has exactly `schema`, `source_id`,
`base_sha256`, `before` and `after`. The latter two are UTF-8 strings. The original
bytes must match the held source digest, and `before` must identify exactly one
replacement site. The function name, parameter order and signature bytes remain
unchanged.

The existing whitelist interpreter accepts one ordinary function with one Boolean
return expression. It supports declared names, Boolean constants, bounded integer
literals, Boolean operators and same-type comparisons. It refuses calls, imports,
attributes, arithmetic, statements, loops and other syntax. Booleans and integers
remain distinct types. The program is parsed and interpreted; it is never
imported, evaluated with Python `eval`, or executed as Python code.

Inputs and receipts are each bounded at 32768 bytes. Program text is bounded at
4096 bytes, with the existing interpreter's token, node, depth, parameter and
integer limits. The CLI also bounds process time, memory, file output and native
evaluation. Resource refusal produces an error, not an inferred test result.

## Result and evidence

The `transport/finite-predicate-receipt/1` records test, candidate, base, result,
binding and checker identities; the complete observed bit string; expected-table
digest; state count; failure count; and at most 16 displayed counterexamples.
The full bit string remains available even when displayed counterexamples are
truncated. Its status is `TESTED_FINITE_DOMAIN`.

Only an exact match yields `KNOWN_TRUE`; a differing bit yields `KNOWN_FALSE`.
The existing SPARK evaluator then computes the declared obligation. Other
predicate occurrences receive no invented evidence and remain unresolved. The
combined result has schema `transport/bound-test-evaluation/1`; it keeps source
residuals, surrounding context, unevaluated units and the native process record.

This is a separate profile from attributed reports. A quotation from a requirement
identifies what is being tested; it does not establish that a candidate passed.
The test receipt supplies the observed finite comparison instead.

## Identity and assurance

The finite checker identity covers its explicitly listed local helper files and
the resolved Python executable and version. These files are checked before and
after a run. It does not identify the entire outer CLI, loaded runtime image,
standard library, loader or operating system. Use a trusted, source-pinned
checkout for the outer adapter; integration receipts record its separate closure.
Same-user hostile races and host compromise are outside this identity claim.

The Python parser, finite interpreter and orchestration are tested, not formally
proved. This addition does not change the previously proved SPARK evaluator or
extend its proof to Python. Authentication, source entailment, semantic
completeness and current execution authority are not created by a passing test.

A complex requirement may be retained whole as a named proposition tested by an
explicit table. This is not decomposition of every clause into executable
operators. Preserve the original detailed reading and residuals alongside it;
do not remove unsupported operators from an existing tree to obtain acceptance.

## Reproduce controls

```sh
python3 -I -S -B -Werror install/test_finite_check.py
python3 -I -S -B -Werror install/test_bound_test_receipts.py \
  --bundle /absolute/installed/decoder \
  --native /absolute/transport_bound_eval_native \
  --evidence /absolute/new/evidence-directory
```

The unit suite uses synthetic bindings and includes a different held-out function.
The integration suite uses the actual decoder and native evaluator, preserves the
existing coding fixture and its detailed reading, and retains malformed and
substituted inputs. Neither suite alone establishes comparative agent benefit.
