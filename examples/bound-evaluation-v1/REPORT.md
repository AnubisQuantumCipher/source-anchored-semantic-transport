# Bound predicates now produce checked outcomes

The new evaluator connects each predicate occurrence to its own source-cited
reports. A typed obligation tree produces `SATISFIED`, `VIOLATED` or `UNKNOWN` in
SPARK. The receiving interface rejects a submitted outcome that disagrees with
that calculation. Bindings that name the wrong actor occurrence, predicate,
source revision or declared argument order are rejected. A report's quotation
is byte-checked; whether it supports the declared predicate remains unproved.

For example, the reviews fixture requires **both** review completions. With the
selected security-complete and validation-incomplete reports it evaluates to
`VIOLATED`. Including the older, conflicting validation-complete report produces
`UNKNOWN`. Report order does not decide which report is authoritative. These are
conditional results over supplied reports, not findings about what happened.

## Artifacts and reproduction

| Fixture | Share text | Meaning package | Readable keys |
| --- | --- | --- | --- |
| Reviews and correction history | [share.txt](reviews/share.txt) | [meaning.zip](reviews/meaning.zip) | [lexicon.md](reviews/lexicon.md) |
| Ordered actors under a prohibition | [share.txt](library/share.txt) | [meaning.zip](library/meaning.zip) | [lexicon.md](library/lexicon.md) |

Each folder also contains its original source files and explicit authoring plan.
The [profile and commands](../../docs/BOUND_EVALUATION.md) reproduce encoding,
typed binding checks, evaluation and source byte comparison using an installed
decoder and the new native evaluator. Rebuilding and re-encoding produces a new
package for that runtime; an independently rebuilt decoder is not promised to
accept the committed ZIPs. Those frozen ZIPs require the exact installed runtime
recorded in their manifests. That native dependency is not bundled here.

The [selected evidence archive](evidence-02.zip) and
[export receipt](../../receipts/bound-evaluation-2.json) retain source inventories,
proof output, test captures, review findings, exact candidate text, frozen
criteria, dispatch prompts and selected tool traces. Capture groups preserve
original UTF-8 file contents and identities. Marked metadata and tool records map
host paths; protected source, package, contract and candidate bytes are unchanged.
The export is a selection, not the complete working directory. It includes
identities of the old and repaired native executables, not those executables.
The first export mapped paths inside one capture group while retaining its
original nested hashes. That failed export is preserved privately; its failure
record is included here. This corrected export preserves every capture group
exactly.

## Observed acceptance

| Check | Result |
| --- | --- |
| Focused SPARK analysis | 214 checks; zero unproved, justified or `Assume` statements in the named analysis |
| Strict native build and C static analyzer | Passed |
| Final native input controls | 25 cases passed, including FIFO, device, directory, symlink and maximum frame |
| Bridge integration with actual pinned decoder | 22 tests passed, no skips; 29 bounded subprocesses |
| Original-source byte comparisons | Both fixtures matched exactly |
| Structure-only CI lane | 22 tests, seven native-dependent skips; no actual decoding or byte-recovery claim |
| Existing citation / expression / client regression suites | 26 / 20 / 9 tests passed |
| Fresh recipient trial 1 | **Failed interface setup**; stopped on refusal before reconstruction |
| Fresh recipient trial 2 | **Passed frozen B1–B8** source comparison and both computed-outcome checks |

The proof covers per-node evaluation, default tails, report-mask resolution,
typed connected parser success, consistent observations and rejection reset in
the named SPARK units. Its source inventory matches the final evaluator/parser
bytes. The IO repair did not alter those units. Byte-to-tree correspondence is
tested but absent from the parser postcondition. Python lowering, C/OS IO,
compiler correctness and English interpretation are not covered by that proof.

Independent review found an executable-path ambiguity and blocking FIFO input.
Both were repaired and given regression controls. Earlier strict-build failures
and the superseded native identity remain recorded. The first recipient failed
because its generated interface omitted the required initial `describe` request;
the second used a new prepared directory and repaired interface with the same
source and frozen criteria. The first failure was not overwritten.

## Receiving-agent evidence

The recipient received only the declared interface, packages and dependencies,
with `fork_turns:none`; original source files and acceptance criteria were held
separately. It retrieved all three records, preserved the correction history and
exact numeric literals, evaluated the selected and full report sets, and supplied
matching conclusions. A separate evaluator compared its explanation against the
original sources under criteria frozen before dispatch. No material omission,
contradiction or unsupported addition was found in this case.

The two recipients, reviewer and source evaluator have observed model identifier
`gpt-6.1-sol`, reasoning `high`. Exact dispatch arguments, selected raw tool records
and observed settings are retained. This was a shared-host test with withheld
inputs, not operating-system isolation or external-user validation. An incidental
`ResourceWarning` from the recipient's capture script is retained; the decoder
and evaluator commands returned successfully.

The numeric source literals survived exact byte recovery and the independently
assessed explanation. That observation applies to these fixtures. The computed
outcome checker does not assess arbitrary commentary or establish numerical
fidelity for untested documents.

## Storage and context cost

| Measured artifact | Reviews | Library |
| --- | ---: | ---: |
| Original source documents, bytes | 540 | 449 |
| Gzip of concatenated source documents, bytes | 302 | 254 |
| Explicit typed authoring plan, bytes | 3,418 | 3,295 |
| Complete share text, Unicode code points | 527 | 497 |
| Complete share text, UTF-8 bytes | 528 | 498 |
| Meaning ZIP, bytes | 55,055 | 54,443 |
| Separate readable lexicon, bytes | 31,372 | 31,037 |

These shares include their identity and `attached:meaning.zip` reference. They do
not meet a 200-character budget; no platform-specific counting rule was tested.
The readable lexicon is also inside the ZIP. Original source, report history and
documentary literals remain stored; report and history units are opaque, and
uncovered intervals remain explicit. Evaluation does not turn them into fully
interpreted semantics.

Shared dependencies measured separately: installed decoder files 1,943,944 bytes;
new evaluator executable 1,488,368 bytes; additive Python modules 20,639 bytes;
their local import closure 88,364 bytes, including those modules. Python, standard
library, OS and system libraries are additional dependencies. These small cases
lose the storage comparison with plain source and gzip. No amortized saving is
claimed.

The successful recipient's last cumulative host counters report 722,221 input
tokens, including 703,488 cached input tokens, and 5,264 output tokens. Those
counters include host instructions, tool definitions and repeated context; they
are not document token counts or billed cost. The failed trial's counters and
both timestamp intervals are retained too. Monetary cost is not reported. Native
and bridge process timings are captured, without a comparative latency claim.

## What this establishes and what remains

This closes a concrete gap between indexed source meaning and executable checks:
ground predicate bindings, ordered nominal types and conditional obligations now
have enforced behavior. It does not prove that an author chose the correct typed
reading, that cited reports are true, or that a matching conclusion makes its
surrounding prose correct. Quantification, conditions, exceptions, temporal
operators and other unsupported constructs explicitly refuse in this evaluation
profile; the transport format still preserves them and their residuals.

The tested native host is Linux aarch64 with Python 3.14.7. The source-only CI
configuration targets Ubuntu x64 with Python 3.14.10. Desktop and marketplace
acceptance, external adopters, broader independent audits and superiority over an
original-document workflow remain open. The next useful acceptance case is a
frozen multi-step task in which the same source-cited checks catch consequential
wrong continuations, compared with the original-document baseline under the same
limits. That comparison has not been performed for this new evaluator.
