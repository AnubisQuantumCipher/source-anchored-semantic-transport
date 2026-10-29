# Source-Anchored Semantic Transport: museum continuation

See the [results and downloadable pair](REPORT.md) for the frozen trial evidence.

Prepare the same fictional museum task for an original-document reader and a
Source-Anchored Semantic Transport reader, then check each first submitted draft
outside the receiving session. The task corrects a preview-queue predicate while
carrying both review requirements, an inclusive age range, a narrow maintenance
exception, superseded approval, conflicting reports and unfinished work.

[fixture.json](fixture.json) contains the sources and shared response contract.
[criteria.json](criteria.json) contains the evaluator's source quotations and
finite oracle. Keep the criteria with the evaluator. The sources are explicitly
fictional; the live request permits proposed patch data only.

## Prepare both receiving arms

Run from the repository root with an existing qualified decoder bundle. Follow
the [installation instructions](../../docs/INSTALL.md) for a source build. Hold
its installation-manifest digest separately. Preparation reserves 10000000000
free bytes plus its output and complete-recovery allowances; it compiles nothing.
Use a new absolute output directory outside the checkout and decoder bundle,
with an existing private parent.

```sh
python3 -I -S -B -Werror examples/heldout-release-v1/build_plan.py --check

CASE_ROOT=/absolute/new/museum-case
BUNDLE_ROOT=/absolute/qualified/decoder-bundle
HELD_INSTALL_SHA256='<held INSTALL.json digest>'

python3 -I -S -B -Werror examples/heldout-release-v1/prepare_case.py \
  --bundle "$BUNDLE_ROOT" \
  --expect-install-sha256 "$HELD_INSTALL_SHA256" \
  --output "$CASE_ROOT"
```

`prepare_case.py` freezes the inputs, encodes and validates the pair, recovers
every source byte, checks the declared focus dependencies, and creates
`receiver-original` and `receiver-transport`. It checks that both arms have the
same task, source metadata and held source digests. Its successful status is
`PREPARED_NOT_DISPATCHED`: no model has run and no answer has been accepted.

Deliver each receiver's `task.txt` and authenticated `interface.txt`/binding to a
fresh recipient. Start with `describe`, use the fixed reader session, and submit
one exact JSON draft through `finish`. Preparation checks and the evaluator's
criteria stay outside that receiving task. This setup does not establish an OS
sandbox or prove that hidden access is absent.

## Qualify paging before a receiving trial

For a large focus, use the reader's `focus_page` action rather than relying on a
surrounding tool to display the complete legacy `focus` response. The pages carry
at most 4096 canonical JSON bytes as base64, with a full-response digest and a
separate page digest. Each complete page response is bounded at 8192 bytes.
Use a trusted bounded data-decoding route; fluent narration cannot substitute
for base64 decoding or a byte comparison. See the [reader protocol](../../docs/HANDOFF_READER.md).

The following check uses a **separate session**, leaving the recipient's session
unused. Obtain `HELD_MANIFEST_SHA256` from the authenticated transport preparation
receipt's `manifest.sha256`, and `HELD_FOCUS_SHA256` from `focus-check.json`'s
`response.sha256`. Its output directory must be new and outside the receiver.

```sh
python3 -I -S -B -Werror examples/heldout-release-v1/check_paging.py \
  --receiver "$CASE_ROOT/receiver-transport" \
  --manifest-sha256 "$HELD_MANIFEST_SHA256" \
  --focus-reference "$CASE_ROOT/commands/focus.stdout" \
  --focus-sha256 "$HELD_FOCUS_SHA256" \
  --unit MU_TESTABLE_RULE \
  --output /absolute/new/museum-paging-check
```

The reference-file digest includes its exact file framing. Page `sha256` instead
identifies the canonical focus JSON without a final newline. The checker verifies
both identities, contiguous offsets, per-page bytes and full reassembly against
the reference. It refuses if the complete result cannot fit the unchanged call
budget. A passing paging check certifies byte delivery through this command path;
it does not certify a recipient's understanding.

## Check the immutable first response

After each arm submits, pin its exact first `candidate.json` using the successful
session receipt. Supply the frozen fixture and criteria pins from the preparation
evidence. Run the checker independently for each arm; do not edit a candidate
before assessment.

```sh
python3 -I -S -B -Werror examples/heldout-release-v1/check_response.py \
  --fixture "$CASE_ROOT/fixture.json" --fixture-sha256 "$HELD_FIXTURE_SHA256" \
  --criteria "$CASE_ROOT/criteria.json" --criteria-sha256 "$HELD_CRITERIA_SHA256" \
  --candidate /absolute/receiver/sessions/recipient/candidate.json \
  --candidate-sha256 "$HELD_FIRST_CANDIDATE_SHA256"
```

The checker validates the response shape, exact source quotations and ledger
states, applies the declared byte replacement, and interprets the bounded
expression over the specified finite table. It executes no candidate Python.
Narrative fidelity, historical interpretation and task-access claims need their
separate source/trace review. The oracle is an explicit author formalization,
not a proof of natural-language entailment.

## What this case changes and retains

The readable lexicon shares exact dictionaries by canonical-content SHA-256.
Each symbol dictionary has one reversible table containing its exact metadata
and canonical JSON string literals. Operator dictionaries keep their full
canonical content and readable definitions. Every unit retains its complete
tree, context, qualifications and exact references; verified registry expansion
reconstructs its original canonical payload. Embedded dictionaries in the machine
codec remain intact.

A qualified native-reuse operation can derive fresh runtime and installation
identities around the unchanged donor native bytes. Its receipt reports
`native_build=UNPERFORMED`; original source, build recipe, bootstrap, install,
native and compile-provenance checks remain required. This is distinct from a
fresh compiler run, and it adds no proof of Python or compiler correctness.
`install/transport_repackage.py` supplies that separate operation without changing
the original build command's reserve gate.

All source frames, typed dictionaries, declarations, readable material, index,
formula, manifest and ZIP headers count toward the unchanged 131072-byte archive
limit. This larger fixture retains full context; a short share formula is not a
whole-package compression result.

The first trial is retained: the original-document arm submitted, while the
transport arm stopped on its ninth call after the surrounding tool truncated a
complete reader focus response. No transport candidate is synthesized for that
trial. The retest uses identical `share.txt` and `meaning.zip` bytes with newly
prepared helper bindings. Its outcomes belong in the separately generated report
and receipts; this README does not promote pending review to acceptance. Neither
the deterministic checks nor a repaired trial establish behavioral superiority
or general semantic completeness.
