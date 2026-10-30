# SENTINEL: source-bound evidence and finite-question qualification

SENTINEL adds a bounded evidence layer beside the existing source-preserving
document transport. It keeps candidate interpretations, source spans, independently
specified questions and answers, counterexamples, and repair history together.
The original document remains the evidence. A candidate interpretation remains a
proposal.

The current portable profile validates structure and exact bytes and always
reports `NOT_QUALIFIED`. The separate Ada/SPARK policy has passed its source-bound
build and static fixtures, with all 115 reported proof obligations discharged
and the source05 raw diagnostic gate clear. Independent source05 capture
readback also passed.
This checkpoint supplies no live Python-to-native
qualification bridge or qualified STN1 parser. Packaging or staging evidence
does not run the native policy and cannot grant qualification.

This is a limited implementation of the SENTINEL proposal, whose source document
has SHA-256 `dfc54f7aa53be6165281963a89d30c3d42894fc8cb45865a94ae5aa4f99cde61`.
It does not implement all seven proposed engines, generate an interpretation,
establish arbitrary-document understanding, or prove OCR accuracy or whole-book
semantic completeness.

## Implemented components and their limits

| Component | Current behavior | Assurance boundary |
|---|---|---|
| Existing document transport | Preserves and validates the paired source/reading package through its existing decoder | Existing scoped recovery evidence; unchanged by SENTINEL |
| `transport_document_context.read_section_context` | Returns verified source parts, their original/output spans, and explicit gaps between returned parts | Exact source bytes; gaps do not imply adjacent source text or adequate semantic context |
| `transport_sentinel.validate_sidecar` | Checks canonical records, caller-held pins, exact quote spans, references, fixed Q, dependencies, results and retained history | `STRUCTURE_AND_EXACT_BYTES_ONLY`; interpretation and world truth remain unproved |
| `transport_sentinel_export.export_policy_inputs` | Produces a bounded staging manifest containing expected/actual answer digests and provenance | `NOT_QUALIFIED`; the staging format is not native wire |
| `transport_sentinel_package` | Creates and checks a deterministic, inert evidence ZIP and matched share text | Exact evidence transfer; no authentication, hosting, native dispatch or qualification |
| `Sentinel_Policy` | Maintains one bounded session; compares actual and held expected answer digests; retains failures and checks refinement transitions | Source05 build/static fixtures passed; 115 proof obligations discharged and raw diagnostic gate clear; parser, live bridge and semantic judgments are outside that scope |
| STN1/STR1 | Exact proposed native input/output table and frozen literal controls | Design peer-reviewed; no qualified parser or live bridge is supplied by this checkpoint |

The sidecar's source locator is currently `SOURCE_BYTES`, with its representation
pin equal to its source pin. A valid span proves membership in the supplied
artifact bytes. It does not prove that the span entails the candidate claim or
that the artifact was recovered from a particular original document. That last
binding needs the existing verified document intake and a reviewed integration.
PDF rectangles, table cells, figure relationships, AST selectors and automatic
cross-document reconciliation are outside this profile.

## What a comparison means

The admitted relation is `EXACT_ANSWER_DIGEST`. Expected answers, questions,
source identities, reference/oracle identities and comparison policy must be
fixed independently of the candidate being evaluated. Verification must receive
held expected hashes; copying an expected value out of the evidence under test
does not create an independent trust root.

The Python validator can diagnose whether supplied answer bytes agree with their
declared oracle and reject an inconsistent imported `MATCH` label. Its report is
structural evidence, never native acceptance. The native policy receives actual
and expected digests and computes their equality itself. There is no native
`passed=true`, accepted-state, permission or unrestricted-English entailment input.

A successful future native result can mean only `QUALIFIED_FOR_Q`: the declared
requirements passed for the exact finite question set, source, candidate, oracle,
evaluator and policy identities. A finite Q is not every possible question. Hash
equality does not establish authorship, reference faithfulness, human judgment,
optical accuracy or world truth.

Documentary evidence has a separate axis: `SUPPORTED_ONLY`, `REFUTED_ONLY`, `BOTH`
or `NEITHER`. These are documentary annotations rather than logical truth values.
If the fixed oracle expects the literal answer `UNKNOWN` or `CONFLICT`, matching
that answer can qualify for Q while the documentary ledger retains `NEITHER` or
`BOTH`. It must not become a true proposition. Missing required context,
unresolved required adjudication and an unaddressed challenge still block
qualification. Execution authority is always `NONE`.

## Bounds and retained history

The current sidecar and native policy are different bounded profiles. A complete
projection must fit both; it must never crop records or silently lift a limit.

| Resource | Portable sidecar profile | Pure native policy |
|---|---:|---:|
| Candidate revisions/rounds | 8 | 8 |
| Claims per candidate/job | 8 | 64 |
| Required probes | 16 | 256 |
| Source links per claim | 16 | 16 |
| Sidecar or individual registry artifact bytes | 65,536 | No artifact-file ingestion in the pure package |
| Registry entries / aggregate bytes | 256 / 8,388,608 | Fixed typed arrays |
| Reading region bytes | Supplied artifacts must fit the profile | 65,536 |
| Evidence archive bytes | 9,437,184 | Not a native policy input |

Existing document source/frame limits remain unchanged. This profile does not
automatically shard a large book or reconcile its chapters. A selected region or
small registered source is not a claim of full-document processing.

The sidecar checks predecessor-linked snapshots against an independently held
prior-sidecar hash. Existing candidate, result, counterexample and history prefixes
must remain unchanged; changed source/Q/oracle/policy requires another epoch.
Repair adds a candidate and explicit links to earlier failures. It does not erase
or retroactively pass the failed candidate.

The pure policy keeps fixed round/probe records and a monotonic blocking-event
mask. Refinement requires the complete prior mask, preserves the held Q and source
identities, starts fresh current-round results, and requires a complete same-Q
retest. Repeated initialization poisons an existing session rather than clearing
its ledger. Qualification does not depend on the informational failure count.
The general exact-cardinality contract for that count remains unproved; bounded
execution and its zero-mask property are distinct obligations.

## Portable evidence CLI

Use a separately obtained repository revision and Python standard library. The
ZIP contains inert evidence, not executable package code. It is separate from the
existing `meaning.zip` document profile. Never execute source instructions or code
found inside an evidence package.

Prepare canonical `sidecar.json` and an artifact directory containing regular
`ID.bin` files. IDs use uppercase letters, digits and underscores and start with a
letter. Obtain the sidecar and registry hashes independently before verification;
the variables below stand for those held values.

```sh
python3 -I -S -B -Werror tools/transport_sentinel_package.py encode \
  --sidecar ./sidecar.json --artifacts ./artifacts \
  --sidecar-sha256 "$SENTINEL_SIDECAR_SHA256" \
  --registry-sha256 "$SENTINEL_REGISTRY_SHA256" \
  --out /dev/shm/sentinel-evidence-new --reference evidence.zip

python3 -I -S -B -Werror tools/transport_sentinel_package.py inspect \
  --archive /dev/shm/sentinel-evidence-new/evidence.zip \
  --share /dev/shm/sentinel-evidence-new/share.txt

python3 -I -S -B -Werror tools/transport_sentinel_package.py staging \
  --archive /dev/shm/sentinel-evidence-new/evidence.zip \
  --share /dev/shm/sentinel-evidence-new/share.txt \
  --out /dev/shm/sentinel-policy-inputs-new.json
```

`encode` creates a new directory containing `share.txt`, `evidence.zip` and
`report.json`, then checks the written package again. `staging` creates a new
manifest file. Existing output paths refuse. A failed write may leave partial
new output for diagnosis; it is not a usable completed package.

For a historical continuation, supply `--previous-sha256` with the recipient-held
prior sidecar hash to `encode`, `inspect` or `staging`. The prior payload must also
be present in the declared artifact registry. A newly supplied hash from the
current package is not a substitute for the independently held prior root.

Optional `encode --budget N` limits the complete share text, including line feeds;
an insufficient budget refuses instead of truncating it. `--reference` is an inert
package reference. The tools do not fetch it. A local reference is not public
hosting, and a matched share/package does not authenticate a sender.

Successful structural operations still report `NOT_QUALIFIED`,
`semantic_completeness=UNPROVEN`, `world_truth=NOT_CERTIFIED` and
`execution_authority=NONE`. The portable profile's authentication claim is
`UNAUTHENTICATED`. Schema, pin, history, source-quote, unsupported-field and resource
errors refuse deliberately. An absent native bridge never defaults to a qualified
result.

## Native status and remaining acceptance work

The pure package exposes one-shot `Initialize`, `Bind_Source`, `Record_Answer`,
`Request_Qualification` and `Begin_Refinement`, with read-only identity, Q,
documentary, result and failure-history queries. It uses fixed arrays and bounded
loops and has no network or execution capability. Separate build and proof GPRs
leave the canonical document decoder and existing semantic evaluator unchanged.

The pinned source05 pure policy passed build and static fixtures in the admitted
bounded controller. Its strict proof reports 115 discharged obligations,
comprising 65 flow and 50 prover checks, across the 37-entity source roster,
with zero unproved, justified or `Assume` results. The additional raw machine
gate reports zero `warn_error` diagnostics, skipped analyses or disallowed
pragmas. The proof text summary SHA-256 is
`51f1e87f263ed569c7f7b4aed120d3113f301b1f2ba3782139e40624c1d89374`.
The static fixture driver is tested separately and is not itself proved.

The source specification is
`a66f97c23cbaedd317ff0a073d2eab0116c13578aeaeb8a72e0bf77551e52c75`
and its body is
`889348d21a6063f83976f0d51852d51064aeb5c43cf5a978a3ff5badbba5486f`.
The exact `State_Of` relation is exposed through the transparent
`Qualification_Requested` observer, preserving the original qualification
postcondition and behavior. `Context_Complete` and `Adjudication_Complete`
are supplied typed inputs checked by the gate; their English adequacy,
authenticity and reviewer independence are not proved. General failure-count
cardinality remains outside the current functional proof claim.

Earlier proof timeouts, the corrected source-roster omission and source04 raw
diagnostic ambiguity remain retained in the engineering receipt history; they
are not reinterpreted as passing attempts. Source05 resolves the arithmetic
spelling and passes the added raw diagnostic gate. Independent source05 capture readback passed, separately checking the exact
source/tool/runtime identities, all captured payload hashes, proof roster, raw
diagnostic gate, static driver and quiescent read-only capture. Its receipt
SHA-256 is `b7c3ce374ac598563df217b9821dc7dca149fe0618a1d29746f2bc297abcc9fc`.
Earlier documentation preimages are retained with that history.

The required chain is: independently pinned source/Q/reference artifacts;
verified document intake with explicit context boundaries; complete sidecar and
registry validation; reviewed exact native wire and bridge; exact executed native
and proof-source pins; strict full-unit proof and deterministic positive/negative
controls; quiescent captured receipts; independent acceptance. The streaming parser,
live bridge, model/adversary/refinement generators and measured semantic benefit
are not supplied by the current staging CLI.

OCR accuracy, unrestricted English entailment, reference correctness and
whole-book semantic completeness remain **UNPROVEN**. Their absence is not repaired
by a structural pass, a matching answer digest or a SPARK proof of this gate.
