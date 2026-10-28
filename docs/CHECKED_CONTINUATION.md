# Checked continuation from source to behavior

A fresh receiving agent can now recover this packaged requirement, propose a
patch, submit its exact bytes, and have its behavior checked against the source's
finite input domain. A separate source review checks the accompanying explanation.
The original-document baseline also passes. This is a working bounded acceptance
case, not evidence of reduced errors compared with original documents.

The synthetic case corrects a routing decision. It requires the requester's role,
an age from 0 through 12 hours inclusive, and a seal or a repair mode with a ticket.
The repair exception waives only the seal. The recipient's role is irrelevant.
The dossier also carries a revoked historical approval, conflicting old test
reports, missing current verification, and separately identified completed and
pending actions. Source statements never grant live execution or publication
permission.

## What the test found and changed

The first frozen pair produced structurally conforming answers and correct patches,
but both submissions failed. The checked wrapper put base64-encoded response data
in a command-line argument, exceeding the process helper's existing argument bound.
The advertised candidate limit was therefore not usable end to end.

The wrapper now passes a private request file with a pinned digest. The client
checks the bounded regular file before dispatch. Existing argument, request,
candidate and process limits remain unchanged. The real submission path saves an
exactly 32768-byte conforming candidate unchanged and refuses the adjacent
32769-byte candidate before dispatch. Controls cover changed digests, unsafe file
types, cleanup and failures after a save.

The initial pair remains failed. A mechanical replay separately saved its
unchanged answers. Then two new receiving agents ran a separately frozen
replication with the same sources, task, output contract and meaning package.
They received no previous answers or expected patch.

| Gate | Initial original | Initial transport | Repaired original | Repaired transport |
| --- | --- | --- | --- | --- |
| Response shape and named source records | PASS | PASS | PASS | PASS |
| Patch behavior over all 480 declared inputs | PASS | PASS | PASS | PASS |
| Independent review of frozen source obligations | PASS | PASS | PASS | PASS |
| Checked submission and exact saved-byte custody | FAIL | FAIL | PASS | PASS |

The typed interpreter accepts one fixed-signature function with one return
expression. It checks exact Boolean and integer types and a closed expression
grammar. It walks a bounded tree; it does not call `eval`, compile, import or
execute the proposed program. The fixture checker compares every declared input
against a separately authored predicate. Negative controls reject a swapped
actor, an exclusive upper bound, an overbroad exception, false approval, missing
evidence and unsafe syntax. These are executable checks, not a general proof that
an English requirement has been interpreted correctly.

Each receiver was configured as `gpt-6.1-sol` with high reasoning in a fresh
conversation. Separate GPT-6.1 source assessments used the predeclared obligations.
The captured metadata is not backend attestation, external user review or proof
of hidden-access isolation. Initial dispatch plaintext equality is unknown in the
available traces. The final chat notes are retained but were never substituted
for submitted candidate bytes. The second pair is a same-case repair replication,
not another held-out document or a native-compaction campaign.

## Cost and representation

| Item | Measured size |
| --- | ---: |
| Exact source bodies | 5364 bytes |
| Visible formula | 985 UTF-8 bytes |
| Complete share text, including identity and reference | 1076 UTF-8 bytes; 1075 Unicode code points |
| Meaning ZIP | 88454 bytes |
| Separate readable lexicon | 46468 bytes |

The reference is `attached:meaning.zip`; no public hosting or platform-specific
post-length compliance was tested. The decoder and helper setup are separate
dependencies, accounted for in the receipt. The package is larger than the source.
Two earlier authoring attempts exceeded the lexicon bound because operator
definitions repeat per typed unit; both refusals remain recorded. The successful
package has three typed coding units plus separate anchored interpretations for
history and action records. Their original text remains available. Opaque
propositions and residuals are not counted as proven semantic capture.

| Receiving run | Last cumulative token-usage observation |
| --- | ---: |
| Initial original | 661655 |
| Initial transport | 615305 |
| Repaired original | 380347 |
| Repaired transport | 389972 |

These observed cumulative totals include tool exchanges and repeated/cached
context. They are not source token counts, peak context use, invoices or a measured
compression ratio. No token, latency or monetary advantage is claimed. Exact
counters, calls and elapsed-time definitions are retained in the evidence.

## Reproduce and inspect

The [receipt](../receipts/checked-continuation-1.json) identifies the source-bound
results and [evidence ZIP](../examples/checked-continuation-v1/evidence.zip).
The archive includes sources, authoring input, matched share/meaning artifacts,
candidate bytes, assessments, retained failures and instructions. The decoder
dependency is explicit; independently rebuilt runtime identities are not assumed
interchangeable.

Run the generic expression controls from the repository root:

```sh
python3 -I -S -B -Werror install/test_fixture_expression.py
python3 -I -S -B -Werror install/check_source.py
```

Use the public source checker with independently held file digests:

```sh
python3 -I -S -B -Werror examples/checked-continuation-v1/check_response.py \
  --fixture examples/checked-continuation-v1/fixture.json \
  --fixture-sha256 "$held_fixture_digest" \
  --contract examples/checked-continuation-v1/response-contract.json \
  --contract-sha256 "$held_contract_digest" \
  --candidate "$candidate_path" --candidate-sha256 "$held_candidate_digest"
```

The checker reports deterministic shape, quotation, record and finite-behavior
results. Narrative fidelity remains a separate assessment. The Ada/SPARK source
and tested native decoder bundle were unchanged; this patch adds no new formal
proof. The next acceptance work is broader continuation and constrained-context
comparison, plus reducing authoring/retrieval overhead without losing required
source context. External users, desktop clients and marketplace acceptance remain
separate work.
