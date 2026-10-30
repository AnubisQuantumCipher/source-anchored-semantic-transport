# Closed semantic core: a source-bound example

[Copy the share text](share.txt), [download the matched meaning ZIP](meaning.zip),
and [read the package lexicon](lexicon.md). The archive contains the exact source,
finite model, typed tree, operator dictionary and runtime identities. The share
is the existing courier entry point; this additional closed formula is visible here:

```text
must(if(and(EVENT(), not(EXCEPTION())), ACTION(ACTOR)))
```

The exact source is `REQ_AUDIT: When E, A shall Q, unless X.` followed by LF.
The labels deliberately carry no assumed English or real-world interpretation.

| Symbol | Sort | Exact source-bound role | Byte span |
|---|---|---|---|
| EVENT | Nullary predicate | `E`, when-event | `[16,17)` |
| ACTOR | Term | `A`, actor | `[19,20)` |
| ACTION | Unary predicate | `Q`, shall-action on ACTOR | `[27,28)` |
| EXCEPTION | Nullary predicate | `X`, unless-condition | `[37,38)` |

| Operator | Fixed meaning in this fragment |
|---|---|
| `pred` | Explicit ordered-tuple lookup; absent, conflicting or unresolved reports stay UNRESOLVED. |
| `not` | Strong Kleene negation; UNRESOLVED stays UNRESOLVED. |
| `and` | False if either operand is false; true if both are true; otherwise unresolved. |
| `if` | Strong Kleene material implication: false only for known true antecedent and known false consequent. A false antecedent makes it true. |
| `must` | Fact → Norm: known true maps SATISFIED, known false VIOLATED, unresolved UNKNOWN. The Norm's truth remains UNRESOLVED. |
| `all` / `some` | Unary predicate over an explicitly listed finite domain. Empty all is true; empty some is false. These operators are defined but unused in this example. |

The supplied model reports EVENT() KNOWN_TRUE, ACTION(ACTOR) KNOWN_FALSE and
EXCEPTION() KNOWN_FALSE. The native evaluator returns **VIOLATED**, sort **NORM**,
truth **UNRESOLVED**. This is a verdict about that supplied finite model. The model
is input, not a certified observation. No decoded rule grants authority.
Activating the exception satisfies this material conditional vacuously; it does
not change the false ACTION report into a true fact.

The controlled parser checks the complete surface and exact role bindings of
one sentence shape. It does not establish English entailment or semantic
completeness. Grammar `transport/meaning/1` and `/2` remain documentary. A missing
model returns NOT_EVALUATED and NONE_NO_MODEL; every source reading remains
PROPOSED_STRUCTURED_READING. Quantities, clocks and the `100 ms` controller sentence
are outside the checked language fragment.

## Evidence and accounting

[receipt.json](receipt.json) binds the current sources and this evidence tree.
Its checker reads evidence only; it does not execute ZIP instructions, a native
binary or an AI. The native proof covers the exact written Step/Evaluate,
well-formed output, failure-reset and runtime-error/termination contracts on the
pinned SPARK sources. The retained final prover summary reports 1,368 checks,
zero unproved and zero justified checks. It is not a proof of Python, wire-to-JSON
functional equivalence, natural-language meaning or the world model.

The final local integration passed 12 test methods in normal and optimized
Python. The independent frozen controls passed 139 cases in three groups per
mode; parser tests passed 15 methods per mode. An additional fresh process used
relocated exact decoder/native dependencies and recovered the same source,
model, payload and result. Original and recovered native frames and every node
value match. This is a fresh CLI recipient, **not a fresh AI recipient**.

The complete share has 154 Unicode code points including its package reference
and trailing newlines; the ZIP is 23,361 bytes, the source 40 bytes and model
614 bytes. No social-platform counting compliance is claimed. Shared dependency
sizes and exact identities are listed separately in
[evidence/integration/dependency-accounting-04.json](evidence/integration/dependency-accounting-04.json).
No model tokens or model cost were measured because these runs made no model
calls. Storage reduction and behavioral superiority are not established here.

Failures remain in `evidence/`: serializer envelope validation, inherited
resource limits, a leaked directory descriptor, native build warnings, timed-out
proof attempts, five unproved obligations in proof03, and the review's corrected
proof03 provenance. Product03 is retained; the top-level pair is final product04.
The old engineering gate correctly refuses the newer source inventory and is
checked separately on its historical source revision. No old contract was removed.

## Reproduce

From the repository root, no native dependencies are needed to check the frozen
source-bound receipt and its tamper controls:

```sh
python3 -I -S -B -Werror examples/semantic-core-v3/receipt.py --check
python3 -I -S -B -Werror examples/semantic-core-v3/test_receipt.py -v
python3 -I -S -O -B -Werror examples/semantic-core-v3/test_receipt.py -v
```

The receipt checks current grammar3/native sources separately from the preserved
exact installed courier sources in `evidence/courier-sources`. The courier's
installer rewrites its declared runtime identity, so installed files must not be
silently substituted with checkout files. The recorded binary itself is an
explicit external dependency.

For native reproduction, follow [the recorded native commands](evidence/native/REPRODUCE.md)
and [the core interface documentation](../../docs/SEMANTIC_CORE.md). Native builds
and the frozen courier are separate dependencies, not hidden in the ZIP. An
independent rebuild is not promised byte-identical: an unmatched dependency must
be refused. Use the recorded exact artifacts to replay this package, or encode a
new package against a newly qualified dependency identity. The source and model
are inspectable without running either binary.

With explicitly supplied exact dependency paths and SHA-256 pins, run the
integration directly (choose a new private absolute test directory):

```sh
TRANSPORT_CORE_TEST_ROOT=/absolute/new/test-directory \
TRANSPORT_CORE_NATIVE=/absolute/transport_core_native \
TRANSPORT_CORE_NATIVE_SHA256=aa04e9aca4afa2663202eac7085329ac5e1f331057b418d3339c2ed17309c23b \
TRANSPORT_CORE_DECODER=/absolute/bin/semantic-transport \
TRANSPORT_CORE_DECODER_SHA256=7e028b1f02935d5673b5b19ca2d403d2134b9dc87bcbce226256be5dab1b476b \
python3 -I -S -B -Werror tests/test_transport_core_bridge.py -v
```

The integration command records its actual subprocess arguments, statuses and
outputs. Repeat with `-O` and a distinct new test directory. The frozen commands,
source snapshots and run results are in `evidence/integration/`. No client,
marketplace or hosted sharing acceptance is implied by this local result.
