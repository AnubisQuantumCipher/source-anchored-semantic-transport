# Repeated handoffs with fresh source access

Both approaches preserved their first answer through three receiving agents.
Neither passed every frozen output requirement, and this case does not establish
that transport reduces consequential errors compared with original documents.

The original-document arm had exact documents, digests and a neutral heading
index. The transport arm had the same sources plus declared relationships and
focused retrieval. Every hop could retrieve source evidence again. This is a
test of continuation with source refresh, not native compaction or recovery from
a predecessor alone. Each receiver used `gpt-6.1-sol` with high reasoning in a
fresh conversation context. The first final answer was passed unchanged to the
next receiver; no answer was repaired or retried.

## What happened

The synthetic Cedar dossier contains a corrected target, conditional historical
approval, its revocation and exception, conflicting validation reports, missing
current acknowledgements, unfinished actions, and corrected measurements. Both
arms kept the publication hold, source qualifications and pending work. The
reported historical `24 MiB`, corrected `26 MiB`, and unchanged `12 s` interval
survived in every recorded answer with their stated scope.

Every hop failed the frozen exact-output witness. Common failures included an
ambiguous authority field, the representation of conflicting reports, a variant
unknown token, and incomplete evidence membership in one category. The original
arm also used a different unknown token for independent build verification.
The delivered placeholder shape and vocabulary did not fully specify these
per-field encodings. Separate source assessments therefore distinguish exact
format failures from actual loss of meaning. The differing failure counts are
not evidence that one arm was semantically better.

Each arm's saved draft and actual final remained byte-identical to its own first
hop's respective output. Saved drafts include a final LF; observed final messages
do not. Both forms are retained separately. Protocol checks passed for all hops;
that does not turn the output failures into passes.

## Observed cost

These are each receiver's last cumulative usage observations, including its
tool exchanges. They are not document token counts or peak context measurements.

| Receiver | Tool calls | Cumulative input tokens | Output tokens |
| --- | ---: | ---: | ---: |
| Original, hop 1 | 7 | 420327 | 3760 |
| Original, hop 2 | 7 | 423865 | 3293 |
| Original, hop 3 | 7 | 424187 | 3323 |
| Transport, hop 1 | 6 | 416333 | 3607 |
| Transport, hop 2 | 5 | 348297 | 2765 |
| Transport, hop 3 | 6 | 419677 | 3094 |

The frozen share text has 908 Unicode code points, including identity and
`attached:meaning.zip`; it occupies 909 UTF-8 bytes. The matched archive is
102085 bytes. The separate readable lexicon is 57339 bytes. The archive declares
its exact decoder/runtime dependencies; these sizes do not include that shared
installation. There is no platform-specific post-length claim, public-hosting
claim, monetary-cost estimate or whole-package compression advantage here.

## Inspect and reproduce

The [public evidence receipt](../receipts/repeated-handoff-1.json) links the frozen
criteria, sources, exact first answers, prompts, observed calls, model settings,
source assessments, protocol checks and retained failures. Host-path redactions
in evidence are recorded; source and answer bytes are preserved. The matching
[share text](../examples/repeated-handoff-v1/results/transported/share.txt),
[meaning ZIP](../examples/repeated-handoff-v1/results/transported/meaning.zip),
[lexicon](../examples/repeated-handoff-v1/results/transported/lexicon.md) and
[authoring plan](../examples/repeated-handoff-v1/results/transported/authoring.json)
accompany the fixture.

From the repository root, set `held_closure_sha256` to the independently obtained
`public_dataset.closure_sha256` in the public receipt, then run:

```sh
python3 -I -S -B -Werror examples/repeated-handoff-v1/results/reproduce/check_public.py \
  --expect-closure-sha256 "$held_closure_sha256"
python3 -I -S -B -Werror examples/repeated-handoff-v1/results/reproduce/check_witness.py
```

The witness checker succeeds when it reproduces the recorded failures; it does
not report that the receiving answers passed. A fresh model rerun is a new trial,
not a deterministic reproduction of model answers. Local test and protocol
receipts do not authenticate a model backend or establish hidden-access isolation;
exact initial dispatch plaintext equality remains unknown.

The implementation consequence is an explicit, field-specific
[response contract and checked submission command](../install/CHECKED_FINISH.md).
It is an addition for future workflows, not a change to these frozen criteria or
a retrospective pass. A structurally conforming answer still needs comparison
with its source. Broader held-out tasks, native compaction, other models and
external users remain separate acceptance work.
