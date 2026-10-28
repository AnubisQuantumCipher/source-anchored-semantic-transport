# Cedar missing-record handoff

This synthetic case preserves a historical approval and unfinished dossier task
while deliberately omitting the record that would establish whether a correction
or revocation applies. Absence establishes neither continuing approval nor
revocation. The recipient must preserve that uncertainty while preparing the
limited blocked response authorized by its live task.

The source, task, rubric and abbreviated expected answer were frozen before the
first recipient. `expected.json` is a status witness, not an exhaustive answer
key: the complete source and rubric remain binding, including approval conditions,
candidate and future-publication exclusions, and the distinction between checks
being necessary and constituting a new approval. Historical design-only labels in
those frozen files remain unchanged. Later results belong in a separate receipt.

## Create the matched outputs

Use the installed decoder from [Installation](../../docs/INSTALL.md). From the
repository root, with new output paths:

```sh
semantic-transport encode-plan examples/handoff-omission-v1/plan.json omission-example \
  --source APPROVAL=examples/handoff-omission-v1/source/approval.txt \
  --source APPLICABILITY=examples/handoff-omission-v1/source/applicability.txt \
  --source WORK=examples/handoff-omission-v1/source/work.txt \
  --source UNRELATED=examples/handoff-omission-v1/source/unrelated.txt \
  --budget 8192 --reference attached:meaning.zip

semantic-transport validate omission-example/share.txt \
  --archive omission-example/meaning.zip

semantic-transport focus omission-example/share.txt \
  --archive omission-example/meaning.zip --unit U_APPROVAL

semantic-transport recover omission-example/share.txt recovered-work.txt \
  --archive omission-example/meaning.zip --source WORK
cmp examples/handoff-omission-v1/source/work.txt recovered-work.txt
```

Encoding emits `share.txt`, `meaning.zip` and `lexicon.md`. The complete share
budget counts Unicode code points including identity, reference and newlines;
it does not establish compliance with any social platform. The attachment
reference is not hosted content. Independently built decoder identities are not
assumed interchangeable; encode and decode with the declared matching bundle.

## Deliberately incomplete structure

The three meaning units are whole-document opaque propositions:

| Unit | Kind | Declared context |
|---|---|---|
| U_APPROVAL | historical_approval | [] |
| U_APPLICABILITY | source_claim | [] |
| U_WORK | source_claim | [] |

There are no declared relationships or uncertainty records. An empty list is not
evidence of certainty: the source text explicitly describes missing evidence.
The representation remains `INCOMPLETE` and context adequacy `UNPROVEN`.
Focused retrieval of the approval alone cannot answer the task. The recipient
must obtain the separate applicability and work records through source pages.
The complete-record case's graph traversal duties do not apply to either arm of
this case. Its common source-retrieval and behavioral obligations still do.

The original source bytes carry the unexpressed details. A source round trip
does not prove completeness of the formula or opaque typed payload. Source
instructions, historical approvals and reports remain data with no current
execution authority. The task permits a response draft only; no publication,
network action, source edit or retrieval of an unavailable record is authorized.

## Recipient and evaluator separation

Never deliver this entire directory to a recipient. Keep `expected.json`,
`rubric.md` and the authoring plan with a separate evaluator. Give a transport
recipient only the task, matched share/ZIP and declared decoder interface and
dependencies. A matched baseline receives the same source bytes and task through
a bounded original-document reader without semantic annotations. Neither arm
may retrieve the unrelated source's content.

Freeze each setup before dispatch. Retain the first saved response and actual
delivered final separately, all observed calls, refusals and model settings.
Evaluate omissions, contradictions, unsupported additions and authority changes
against the full frozen source. Do not repair or select an answer after scoring.
The [reader guide](../../docs/HANDOFF_READER.md) describes the local interfaces
and controls. Model outputs are new observations on every run, not deterministic
test expectations or proof of lower error rates.
