# Cedar handoff fixture

This synthetic continuation case asks a recipient to prepare a corrected local
dossier draft while preserving a revoked historical approval, candidate scopes,
conflicting receipt reports, missing evidence and unfinished publication work.
It starts with the historical approval and requires discovery of the later
revocation through an incoming declared context edge. No redundant relation
between those two units bypasses that retrieval requirement.

The source files, task, expected answer, rubric, unit map and compiled input plan
are preserved from the frozen fixture. The input plan was encoded successfully
within the existing bounds using the corrected installed runtime. The subsequent
[matched recipient comparison](../../docs/HANDOFF_COMPARISON.md) records both
first answers and independent assessments. Both passed that frozen source task;
no behavioral advantage was established. Encoding and source recovery alone do
not establish semantic fidelity.

## Reproduce a package

Install the decoder from this source revision as described in
[Installation](../../docs/INSTALL.md), and put that installed bundle's command on
`PATH`. Its retrieval implementation must expose incoming declared context links.
Run these commands from the repository root. `handoff-example` must not exist:

```sh
semantic-transport encode-plan examples/handoff-v1/plan.json handoff-example \
  --source APPROVAL=examples/handoff-v1/source/approval.txt \
  --source CORRECTION=examples/handoff-v1/source/correction.txt \
  --source REVOCATION=examples/handoff-v1/source/revocation.txt \
  --source WORK=examples/handoff-v1/source/work.txt \
  --source UNRELATED=examples/handoff-v1/source/unrelated.txt \
  --budget 8192 --reference attached:meaning.zip

semantic-transport validate handoff-example/share.txt \
  --archive handoff-example/meaning.zip

semantic-transport focus handoff-example/share.txt \
  --archive handoff-example/meaning.zip --unit U_APPROVAL

semantic-transport recover handoff-example/share.txt recovered-work.txt \
  --archive handoff-example/meaning.zip --source WORK
```

`recovered-work.txt` must not exist. Compare it byte-for-byte with
`examples/handoff-v1/source/work.txt`; the other source IDs can be recovered to
their own new output files in the same way. The installed `inspect` command can
also inspect the matched pair without returning whole-source bytes:

```sh
semantic-transport inspect handoff-example/share.txt \
  --archive handoff-example/meaning.zip
```

Successful encoding publishes `share.txt`, `meaning.zip` and `lexicon.md`. The
share and ZIP must remain matched to their exact declared runtime. The reference
`attached:meaning.zip` names a local attachment; it is not a download URL.

The complete share budget counts Unicode code points, including the identity,
reference and newlines. It is not a byte count or a platform-specific posting
limit. Existing bounds remain unchanged: aggregate source bytes at most 65536,
at most 16 sources, at most 16 typed meaning units, and archive/output bytes at
most 131072. Metadata, graph, dictionary, process and session bounds also apply.
An overflow must refuse; do not trim conditions or increase a bound to fit.

## Meaning and authority boundary

The four typed units preserve these directions:

| Unit | Kind | Declared context |
|---|---|---|
| U_APPROVAL | historical_approval | [] |
| U_CORRECTION | source_claim | [] |
| U_REVOKE | revocation | [U_APPROVAL, U_CORRECTION] |
| U_PENDING | pending_action | [U_REVOKE] |

Each typed payload is an opaque proposition anchored to its complete paragraph.
The representation is `INCOMPLETE`; the source is still exactly recoverable.
Goal, documentary instruction and receipt reports remain separate supporting
records. This case does not exercise the typed `goal` and `instruction` kinds.
Context edge direction is retained. Finding a connected record does not prove
that it revokes another record; that interpretation must be checked against the
source wording. `UNRELATED` is preserved in the package but has no task links
and must not be loaded by the recipient.

Interpretation entailment, semantic completeness and context adequacy remain
`UNPROVEN`. Sources are synthetic, untrusted and unauthenticated. Historical
approval, revocation, source instructions and decoded records supply no current
execution authority: `execution_authority` remains `NONE`. The separate live
recipient task permits only reading the supplied handoff and returning a draft;
it permits no publication, network request, source edit or contact.

## Keep evaluation material separate

**`expected.json` and `rubric.md` are evaluator-only. Never deliver them to a
recipient in either trial arm.** Do not hand a recipient this entire directory.
The expected result and rubric were frozen before any recipient candidate;
editing a candidate after scoring would require a new, separately recorded run.
The rubric's final status paragraph records the earlier design-only state and is
kept unchanged. It is not the current implementation receipt; use
[assurance evidence](../../docs/ASSURANCE.md) for later build and test results.

For the transport arm, provide only `recipient-task.txt`, the matched share/ZIP
and the declared decoder/interface/runtime closure. Keep the evaluator originals,
expected answer, rubric, authoring plan and unit map outside that handoff. The
recipient may recover originals through its declared checked read-only interface.
For the matched original-document arm, expose the exact same source bytes and
task through an equivalently bounded read-only original-document reader; do not
supply semantic annotations or expected conclusions. Preserve independent input
identities, every actual tool request/response, the unedited candidate and
explicit unknown outcomes. A passing bounded comparison without an observed
arm difference establishes no superiority claim.
