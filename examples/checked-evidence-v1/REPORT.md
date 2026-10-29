# Check citations before accepting a handoff draft

The checked submission interface now verifies candidate citations against the
recovered source before saving. A citation names an exact source revision and
byte interval. Mismatches between a selected quotation and its named source
revision or interval refuse, including altered numbers and actors. The caller
separately declares the response's fields and types.

Use the [source-evidence profile](../../install/RESPONSE_EVIDENCE.md). The new
profile is optional; existing structure-only submission keeps its output shape.
The native decoder and its Ada/SPARK source are unchanged.

## Evidence and results

The [selected evidence archive](evidence.zip) contains the synthetic source,
matched share text and meaning ZIP, contracts, candidates, captured tool results,
source inventories, retained failures and independent review. Its manifest maps
each exported entry to its original digest. Host paths are mapped only in marked
metadata and tool records; source, package, contract and candidate bytes remain
unchanged. Oversized integration receipts have explicitly marked summaries.
This is a selected export, not the complete private working directory.

| Check | Observed result |
| --- | --- |
| Pure citation validator | 26 tests passed |
| Real original-document and installed-decoder submission | 14 test methods passed; 53 bounded subprocesses |
| Source-only reproduction of those controls | 14 test methods passed; 26 bounded subprocesses |
| Existing contract / submission / client controls | 30 / 22 / 9 tests passed |
| Existing expression / preparation / reader controls | 20 / 13 / 13 tests passed |
| Static source checks | 60 files parsed; 510 installer functions within the enforced limit |
| Independent implementation review | Imported-dependency receipt gap fixed and rechecked; no unresolved finding in the reviewed scope |

The integration controls include altered numbers and actors, wrong revisions,
Unicode byte offsets, repeated text, missing contract pins, helper changes,
post-save uncertainty, terminal sessions and the maximum candidate/contract
combination. A genuine revocation quotation attached to a false `APPROVED`
claim **still passes quotation linkage**. That counterexample remains public:
this validator does not decide whether a claim follows from a quotation.

## Fresh receiving agents

Each recipient was configured with `fork_turns:none` and a receiving-directory
prompt. No original source file or evaluator criteria were separately supplied
in the held launch. The declared inputs were the matched package, fixed decoder
interface, dependencies and caller contracts. A separate evaluator compared the
first saved candidate with the source under criteria frozen before dispatch.

The first trial **failed** its required citation granularity. Its explanation
retained both repeated sentences but used one quotation spanning the whole
source. Structure, quotation linkage and saved-byte equality passed; they did
not override the failed criterion.

The caller then required a separate citation for every nonempty source line and
exactly five citation records. The old candidate failed the tightened structural
contract before dispatch. Distinct locations and complete line coverage remain
independently evaluated requirements; record count alone does not establish them.
The second trial **passed all eight unchanged criteria**, including distinct
locations for the repeated lines. The [public receipt](../../receipts/checked-evidence-1.json)
records both outcomes. It reuses the same source and criteria after this task/contract repair;
it is not a new held-out case or a comparative-superiority experiment.

Both recipients and the independent reviewer used observed `gpt-6.1-sol`, high
reasoning. Selected tool traces and final cumulative usage counters are retained.
The child traces do not expose the initial dispatched prompt as plaintext; that
equality remains UNKNOWN. This is separate review within the same model family,
not external user validation, backend attestation or an operating-system sandbox.

## Size and cost

| Artifact | Observed size |
| --- | --- |
| Original synthetic source | 224 bytes |
| Complete share text | 189 Unicode code points; 190 UTF-8 bytes |
| Meaning ZIP | 24,413 bytes |
| Readable lexicon export | 11,624 UTF-8 bytes |
| Shared installed decoder bundle files | 1,943,944 bytes including helpers and metadata; exact installed identity required |

The share count includes its identity and package reference. No platform counting
rule was tested. The full source and an opaque declared interpretation remain in
the package; this fixture isolates citation checking, not formula expressiveness
or semantic completeness. It loses the storage comparison with original text.

The first and second runs observed 344,671 / 344,099 input tokens and
2,484 / 2,125 output tokens, respectively, with six tool calls each. These are
the last cumulative host counters, including system/tool prompts and repeated
contexts, not document token counts or billed cost. Monetary cost was not measured.
Timestamp-to-final intervals are retained with JACKAL `exact` arithmetic receipts;
they are observations of these runs, not decoder performance guarantees.

## Reproduce

From this checkout:

```sh
python3 -I -S -B -Werror install/test_response_evidence.py
python3 -I -S -B -Werror install/test_evidence_finish.py \
  --evidence /absolute/new-source-only-controls
python3 -I -S -B -Werror install/test_evidence_finish.py \
  --bundle /absolute/existing-installed-bundle \
  --evidence /absolute/new-both-arm-controls
```

The source-only command needs no installed decoder or model. Transport-arm tests
require the declared decoder bundle. Frozen fixture plans, tasks, contracts and
receiving-interface captures are in the archive for reconstruction of the model
trial; another model run is a new observation, not a deterministic replay.
The tested native host is Linux aarch64. No new desktop-client or marketplace
acceptance, formal proof of the Python adapter, or broad semantic claim is made.
