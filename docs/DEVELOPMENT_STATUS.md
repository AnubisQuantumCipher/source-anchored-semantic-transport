# Development guide and current evidence

Status readback: **2026-10-30**. This guide distinguishes the public main baseline
from the additive development work in
[PR #15](https://github.com/AnubisQuantumCipher/source-anchored-semantic-transport/pull/15).
It is a development checkpoint, with scoped passing evidence and open acceptance
obligations. A documentation-only change does not install or merge these features.

## Which checkout provides what?

The main baseline inspected for this guide is
[`4cdec4855a9ce9e4128dc6e7c7a8a26d9e974345`](https://github.com/AnubisQuantumCipher/source-anchored-semantic-transport/tree/4cdec4855a9ce9e4128dc6e7c7a8a26d9e974345).
Its actual README, file tree and command parsers were read. The development
integration sources are identified separately below. Main remains at its baseline
for this readback; a passing development check is not a main-branch capability.

| Capability | Main baseline | PR #15 development checkout |
|---|---|---|
| Source-anchored typed records, formula, lexicon, matched `share.txt` / `meaning.zip` | Implemented, with exact source recovery and explicit interpretation limits | Retained; original profiles and evidence remain distinct |
| Read-only MCP, handoff preparation/client, bounded focus, checked submissions and source citations | Implemented | Retained alongside additive receiving work |
| Bounded predicate evaluation and recomputed finite test receipts | Implemented; see [bound evaluation](BOUND_EVALUATION.md) and [bound tests](BOUND_TESTS.md) | Retained; these contracts do not establish arbitrary English entailment |
| Whole-document framing, original/derived reading separation, PDF/EPUB extraction and OCR interfaces | Absent | Development document profile with separately identified original bytes, readings and native decoder |
| QUORUM source/quotation checks, declared conditions/exceptions, context dependencies, readings and replay | Absent | Deterministic replay and separately pinned policy/admission inputs |
| SENTINEL locators, census, proposed meaning graph, challenges, refinement history, analysis jobs and receiving evidence | Absent | Additive bounded APIs; proposed interpretations retain unproved semantic status |
| SENTINEL Ada/SPARK qualification policy and native bridge | Absent | Named-source kernel proof and separate bridge/wire/runtime evidence; no whole-system proof |
| ML-DSA-87 manifest endorsement and strict signed-document adapter | Absent | Actual provider controls and a finite actual signed/native synthetic round trip; production trust policy remains open |
| Whole-book meaning/OCR completeness, demonstrated superiority, human benefit or production acceptance | Not established | Not established |

Development-only references in this guide use pinned public source links so the
guide also works in a documentation-only PR based on main.

## How the pieces fit

```text
Original data and exact source identities
  -> source-bound reading / extraction record (when used)
  -> explicit typed records and proposed meaning graph
  -> independently fixed questions, references and challenge results
  -> scoped qualification policy / QUORUM replay
  -> formula + matched meaning ZIP + readable lexicon / evidence
  -> receiving checks, source recovery and proposed explanation
```

The arrows describe the available stages, not an assertion that every input has
completed them. Main implements the original transport and receiving stages.
PR #15 adds the document, QUORUM and SENTINEL stages. Original bytes, a derived
reading, a proposed graph and an explanation have separate identities and claims.
An exact recovery comparison establishes retained-byte recovery. A valid typed
record establishes its declared structural checks. Neither establishes that all
relevant meaning was captured.

**SAST** carries the formula, meaning keys, source material and evidence together.
The formula is an entry point; details retained only in the ZIP require that ZIP.
The receiver uses an independently accepted decoder and explicit local inputs.

**QUORUM** checks declared source quotations, conditions, exceptions, context
dependencies and retained reading history through deterministic replay. Votes,
matching records or model agreement do not establish source entailment or world
truth. Its sender prepares separate original-document and transport replay inputs;
preparation is not replay execution or semantic acceptance.

**SENTINEL** separates a proposed interpretation from its evidence and its checked
answers. Its census accounts for source/reading regions, pending work and opaque
material. Its graph records proposed relations, modality, attribution, uncertainty,
contradiction and alternatives. Quotation membership and graph consistency remain
separate from entailment. Its qualification is relative to independently fixed
finite questions, reference evidence, admissibility policy and retained failures.
Grammar3 conclusions are model-relative where a supplied formal model is bound;
that is a separate boundary from SENTINEL's finite-question qualification. Neither
can promote arbitrary prose to world truth. The native policy proof covers its
admissibility contracts, not English truth.
Missing or unknown mandatory evidence blocks the corresponding qualification;
an imported generation or a packaged evidence pointer is not qualification.
Consequential qualification decisions belong to the bounded native policy, with
Python providing orchestration and checked integration boundaries.

**ML-DSA-87** endorses the exact manifest under an independently admitted public
key and current revocation policy. The signed adapter verifies this before opening
frame payloads. That integrity endorsement establishes neither human authorship,
world truth, semantic completeness nor permission to act. The signed profile is
separate from the original unsigned formats.

## Commands on main

Follow [installation](INSTALL.md) to obtain the installed `semantic-transport`
command. From the repository root, this original example uses arguments present
in main's `tools/transport_cli.py` parser:

```sh
semantic-transport encode examples/authoring-v1/controller/authoring.json ./controller-output \
  --source SOURCE=examples/authoring-v1/controller/source.txt \
  --budget 1024 --reference 'attached:meaning.zip'
semantic-transport validate ./controller-output/share.txt \
  --archive ./controller-output/meaning.zip
semantic-transport recover ./controller-output/share.txt ./recovered.txt \
  --archive ./controller-output/meaning.zip --source SOURCE
cmp examples/authoring-v1/controller/source.txt ./recovered.txt
```

Use new output destinations. These commands exercise the original small-package
profile; they do not invoke QUORUM, SENTINEL, document extraction or signing.
The complete share budget counts Unicode code points, including identity,
reference and newlines. An insufficient budget refuses rather than silently
discarding meaning. An attached reference is an identifier, not public hosting.

The original [handoff client](HANDOFF_CLIENT.md), [source review](SOURCE_REVIEW.md)
and [assurance record](ASSURANCE.md) explain the available receiving and evaluation
interfaces and their retained failures.

## Commands in the development checkout only

Use PR #15's source and its separately accepted dependencies/native executable.
The examples below were checked against the source parsers; they were **not run
as part of this documentation edit**. Uppercase path/hash tokens are placeholders,
not runnable fixtures or authenticated identities.

For original-byte document transport, `--opaque` requests no derived reading:

```sh
python3 -B tools/transport_document_cli.py encode /ABSOLUTE/INPUT.bin \
  --title 'Original document' --out /ABSOLUTE/NEW_PACKAGE \
  --native /ABSOLUTE/ACCEPTED_DOCUMENT_NATIVE --opaque
python3 -B tools/transport_document_cli.py inspect \
  --archive /ABSOLUTE/NEW_PACKAGE/meaning.zip \
  --share /ABSOLUTE/NEW_PACKAGE/share.txt \
  --native /ABSOLUTE/ACCEPTED_DOCUMENT_NATIVE
python3 -B tools/transport_document_cli.py decode \
  --archive /ABSOLUTE/NEW_PACKAGE/meaning.zip \
  --share /ABSOLUTE/NEW_PACKAGE/share.txt \
  --native /ABSOLUTE/ACCEPTED_DOCUMENT_NATIVE --out /ABSOLUTE/NEW_RECOVERED.bin
cmp /ABSOLUTE/INPUT.bin /ABSOLUTE/NEW_RECOVERED.bin
```

For supported PDF/EPUB/text extraction, omit `--opaque` only when the declared
local extraction dependencies are available. Reading extraction, byte recovery
and OCR fidelity are separate checks. See the pinned
[document guide](https://github.com/AnubisQuantumCipher/source-anchored-semantic-transport/blob/99ac7a0c4e54eba0a12ac25cf15a86fb525e7a71/docs/LARGE_DOCUMENTS.md).

QUORUM preparation needs independently held source/runtime identities and a
caller-authored sender input. Its output directory must be new:

```sh
python3 -I -S -B -Werror install/prepare_quorum_sender.py \
  --checker-root /CHECKER_SOURCE --decoder-root /ACCEPTED_DECODER \
  --decoder-source-root /MATCHING_DECODER_SOURCE \
  --snapshot-file /ACCEPTED_SNAPSHOT.json --held-identities /HELD_IDENTITIES.json \
  --sender-input /SENDER_INPUT.json --out /NEW_OUTPUT \
  --budget 512 --reference attached:meaning.zip
```

This runs the pinned encoder and prepares replay commands. See the pinned
[sender guide](https://github.com/AnubisQuantumCipher/source-anchored-semantic-transport/blob/99ac7a0c4e54eba0a12ac25cf15a86fb525e7a71/docs/QUORUM_SENDER.md)
for the closed input schema and the separate replay step.

SENTINEL's inert payload inspection requires held payload, decoder and semantic
source identities:

```sh
PYTHONPATH=tools python3 -B -m sentinel_v1.cli --semantic-root SEMANTIC_DECODER_SHA256 inspect-payload \
  --payload /ABSOLUTE/DOCUMENT.sne1 --expect-payload PAYLOAD_SHA256 \
  --decoder-identity DECODER_RUNTIME_SHA256 --export /ABSOLUTE/NEW_EXPORT
```

This is graph-only inspection, not original-source resolution or qualification.
The pinned [receiving guide](https://github.com/AnubisQuantumCipher/source-anchored-semantic-transport/blob/99ac7a0c4e54eba0a12ac25cf15a86fb525e7a71/docs/SENTINEL_RECEIVING.md)
documents `pack`, `encode`, `decode` and `resolve`, including their held identities
and native requirements. Signed documents use the separate
[`transport_signed_document` API](https://github.com/AnubisQuantumCipher/source-anchored-semantic-transport/blob/99ac7a0c4e54eba0a12ac25cf15a86fb525e7a71/tools/transport_signed_document.py);
there is no signed-mode flag in the document CLI above.

## Evidence at exact source snapshots

| Snapshot or obligation | Recorded result and scope |
|---|---|
| Development integration `6d1dc268511ffa81777c7e4bbceadd6863392f62`, tree `fbdee51367fcadc160d2d441ee6cc577ec3b5f5b` | **TESTED:** all 52 selected local invocations passed with unchanged source; all 19 declared hosted PR workflows/jobs and their reported steps passed. This is the selected roster, not full fresh native/installed acceptance. |
| Actual signed/native synthetic fixture at that same source | **TESTED:** actual ML-DSA-87 provider path and unchanged real native helper recovered and independently compared 58 source bytes; two native invocations were recorded. Bad signature, wrong key and revoked-key controls all refused after opening only `manifest.json`, without opening frame payloads. Independent readback verified all 24 captured payloads and their pins. |
| Independent actual GPT-6.1 readback | Retained-evidence review only, with configured reviewer `gpt-6.1-sol`; receipt SHA-256 `a2adc9a96739f7eb484646f6693808896f8a2546e585fa7d6e509804640e9154`, public review SHA-256 `6dbe950620a1e5839b4636d106d5acd17e4ecc00e7e47bb742eca2f5f1ab9ec6`. It checked recorded evidence rather than rerunning provider/native work. Configured model identity is not independent provider attestation. |
| Later reconciliation repair `99ac7a0c4e54eba0a12ac25cf15a86fb525e7a71`, tree `926ee1c054ea057b9efabc9809db112baa6ea070` | Development counterpart `0cf913417011783646f6dec84f9b9e19c66c7299` carries the same code. **TESTED:** 50 focused controls in normal and optimized Python; separately frozen independent 13-method controls passed in both modes. The combined 54-invocation selected portable/static/actual-signing regression reports **PASSED** at this exact source. **OBSERVED:** all 19 declared hosted PR workflows/jobs and reported steps passed, with declared named steps present in order. **REVIEWED:** independent retained-evidence review checked all 54 actual commands, limits, zero exits, no-skip summaries and recorded stream hashes, with matching source snapshots. This is evidence readback, not a rerun or a process-containment proof. These results do not qualify a later documentation commit or establish full native acceptance. |
| Actual retained 69-job reconciliation replay | **TESTED:** every per-job receipt and the aggregate were byte-identical to the retained original run. Complete document validation fell from 72 calls to one under unchanged limits. The original fresh replay completed near its deadline; an earlier timeout remains a retained failure. This finite result is not a universal runtime bound. |
| Whole-book generation state after reconciliation | `INCOMPLETE_GENERATION`: one recorded import, 68 pending jobs. An import is structural admission, not semantic qualification. |
| Source13 native policy proof | **PROVED** only for the named historical proof sources/contracts: 139 checks, 85 flow and 54 prover, with the separately read roster of 46 entities. This readback is not a fresh whole-project proof; Python, English interpretation, extraction/OCR, host orchestration and world truth are outside that proof. |
| Earlier four-book recovery | Historical receipts establish exact recovery comparisons at their own pinned sources. They do not establish whole-book meaning or OCR accuracy. |
| Corrected four-patch book reading | Finite independent source-image comparison passed with normalized typography. This is not a newly sealed whole book, whole-reading acceptance or closure of unreviewed gaps. |

The hosted signing evidence includes the successful
[PR signing run](https://github.com/AnubisQuantumCipher/source-anchored-semantic-transport/actions/runs/41050508334).
That workflow executes actual crypto controls and explicitly mocked signed
orchestration controls. The separate actual signed/native fixture above supplies
finite integration evidence; the mocked tests alone do not supply it.

The later exact `99ac7a0` hosted roster also passed, including its
[signing run](https://github.com/AnubisQuantumCipher/source-anchored-semantic-transport/actions/runs/41058822318)
and [SENTINEL run](https://github.com/AnubisQuantumCipher/source-anchored-semantic-transport/actions/runs/41058822164).
The complete declared roster and ordered named-step check establish that hosted
execution scope; they are not a fresh native proof or whole-product acceptance.

For audit correlation, the retained `6d1dc268` 52-invocation receipt has SHA-256
`c925dbee96962bc037b4130d922a3849b1f9d947d8805aba5502adb012f83031`;
its 19-job hosted readback receipt has SHA-256
`f7be6e8e2832d21b8b70f3e86eb75d09bb405decfa0802c8474e145d72e076d6`.
The later `99ac7a0` selected combined regression receipt has SHA-256
`b2d7a167f698966a0c46fff57c57e555f94a07b0b432d41f3c4b5a363f4c4b9b`.
Its hosted readback receipt has SHA-256
`08459f67c50783585b3e0dc0448760573bc8bff6e75b6ccc13272450ab6e25f9`,
binding hosted metadata SHA-256
`824ffed7fd614cb3b40453fa4c6908f3e3c36ad3ad7bf9e2d5d5e6e699e00fba`.
The independent 54-invocation readback receipt has SHA-256
`bb7254f9e24236723392dc02992778b36f1d98b8d1afae875add24c9c17a7a6e`.
These identifiers bind the retained records; a hash is not authentication or an
independent reproduction. Private source material is required for private-corpus
reproduction and is not included in this guide.

## Reading older records

Historical documentation, acceptance matrices and sealed receipts retain their
original source epochs and labels, including `UNRUN`, `PENDING` and failed
attempts. Their statements describe that earlier scope. In particular, earlier
signing/native integration records can still say pending while a later,
separately pinned synthetic fixture has passed. Preserve those records unchanged
and use this dated guide as the current readback; do not retarget a receipt or
reinterpret an old pending entry as a success. Later results qualify only their
named sources and tested cases.

## What still blocks acceptance?

- Fresh complete native proof/assertion checks, installed and historical-decoder
  compatibility, and paired reproducibility on the exact intended candidate.
- Complete book generation, independently adjudicated meaning/context coverage,
  QUORUM admission and native qualification; independent OCR/fidelity evidence
  and every remaining unreviewed region.
- Actual supported-client runs, independent human/pilot evidence and the original
  comparative benefit gates. No universal certainty or superiority is established.
- Production key admission and current revocation policy. Upstream ML-DSA C
  Power-of-Ten control-flow/probabilistic-loop compliance remains
  **UNPROVEN_UNWAIVED**; no waiver or whole-product proof is implied.

The selected regression and hosted-job readback gates above are closed for
`99ac7a0`. The next integration work is the remaining fresh native, installation,
compatibility and reproducibility checks, together with the unfinished document
generation and receiving obligations. Preserve every existing failure.
Acceptance still requires the applicable fresh native/installed/reproducibility
evidence and the independent semantic, client and human evidence above before a
corresponding qualification or controlled release can be claimed.
