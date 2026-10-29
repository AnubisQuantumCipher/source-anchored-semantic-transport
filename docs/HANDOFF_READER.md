# Local handoff reader

The Source-Anchored Semantic Transport reader supports bounded local receiving
tasks with two explicit arms: `original` reads frozen source files, and
`transport` reads a frozen share/archive through an exact installed decoder.
It records retrieval and saves a candidate. The optional `finish_evidence` action
checks declared citation spans before saving. It does not evaluate narrative fidelity,
semantic completeness, current authority or whether a task has been completed.

## Reproduce the controls

From this source checkout, supply an existing installed bundle and a new evidence
directory whose parent exists:

```sh
python3 -I -S -B -Werror install/test_handoff_reader.py \
  --bundle /absolute/installed/bundle --evidence /absolute/newdirectory
```

This runs synthetic deterministic reader controls and retains subprocess output,
input identities and a receipt, including failures. It does not launch models.
The installed bundle is checked and reused; the command does not rebuild native
code. Existing source, package, session and process limits remain binding.

## Calls and candidate submission

An evaluator prepares and independently freezes a manifest before recipient
access. Use absolute paths for the manifest and session. The manifest stays
outside its content root; the session stays outside and cannot contain that
root or the transport decoder bundle. Begin a new session with `describe`:

```sh
python3 -I -S -B -Werror install/transport_handoff_reader.py \
  --manifest /absolute/frozen/manifest.json \
  --expect-manifest-sha256 HELD_MANIFEST_SHA256 \
  --session /absolute/new-session --request-json '{"action":"describe"}'
```

`HELD_MANIFEST_SHA256` must be the externally held lowercase SHA-256 digest of
the exact frozen manifest bytes. Computing a new digest from an arbitrary
received manifest does not establish that it is the intended handoff.

Reuse the same manifest, held digest and session for subsequent calls. Supply
exactly one of `--request-json JSON` or `--request /absolute/request.json`.
The request is a closed JSON object; duplicate fields, unknown fields, malformed
JSON and unsupported actions refuse. The available request shapes are:

```json
{"action":"describe"}
{"action":"catalog"}
{"action":"page","source":"SOURCE","offset":0}
{"action":"focus","unit":"U_SOURCE"}
{"action":"finish","candidate_base64":"eyJkcmFmdCI6InVuYXNzZXNzZWQifQ=="}
{"action":"finish_evidence","candidate_base64":"BASE64_CANDIDATE","evidence_contract_base64":"BASE64_EVIDENCE_CONTRACT","expect_evidence_contract_sha256":"HELD_EVIDENCE_CONTRACT_SHA256"}
```

`SOURCE` and `U_SOURCE` are illustrative identifiers, not guaranteed targets.
`focus` is available only in the transport arm. There is no `inspect` action.
Catalog returns source IDs, labels, media types, provenance, lengths and digests
in frozen order, without source contents or semantic annotations. Both arms use
the same catalog projection. Keep its metadata nonsemantic when preparing a
matched comparison.

`page` uses original byte offsets and returns at most 4096 source bytes, exact
base64, source/slice digests, interval and end status. Base64 is normative; UTF-8
text can be null if a page splits an encoded character. Original pages slice the
same bytes loaded and hash-checked for that call, without rereading the source.
Transport pages retain the installed receiver's declared review annotations.
Transport focus returns checked declared structures and source excerpts; it
does not establish that supplied links are semantically adequate.

The example finish payload decodes to `{"draft":"unassessed"}`. Replace it with
base64 of the actual candidate's exact JSON-object bytes. A successful finish
saves those bytes unedited as `candidate.json` and closes the session. Its
`DRAFT_SAVED_UNEDITED` response declares completeness `NOT_ASSESSED`; acceptance
of JSON syntax is not proof of faithful narration or useful continuation.

## Frozen manifest

The schema is `transport/handoff-reader/1`. Unknown top-level fields refuse.
Both arms require these fields:

| Field | Required contents |
|---|---|
| `schema` | Exact version above |
| `arm` | `original` or `transport` |
| `helpers` | Exact helper closure, each with absolute `path`, `bytes`, `sha256` |
| `python` | Resolved current interpreter's absolute `path`, `bytes`, `sha256` |
| `content` | Absolute `root` and exact `files` records with relative `path`, `bytes`, `sha256` |
| `sources` | Ordered records: `id`, `label`, `media_type`, `provenance`, `bytes` |
| `held_source_sha256` | Separately frozen original source digests keyed by source ID |

Original source records additionally require `path`, relative to `content.root`.
Their paths must correspond exactly to the content files. The original manifest
forbids `bundle` and `pair`; this arm neither imports nor executes the decoder.

Transport source records have no `path`. This arm additionally requires:

| Field | Required contents |
|---|---|
| `bundle` | Absolute external `path`, `install_sha256`, `snapshot_sha256` |
| `pair` | Relative content paths `share`, `archive`, and independently held `identity` of form `STS1:` plus full SHA-256 |

Transport content contains exactly the two distinct pair files. Source metadata,
order and held source digests must match the decoded sources. Bundle snapshot
identity is `sha(canonical(bundle_snapshot(bundle)))`, using the existing
installer helpers; it includes the local path and file modes. The snapshot is a
local dependency pin, not a portable package reference or author authentication.
Extra files, missing files, duplicate IDs/paths and unsupported links refuse.

The shared helper closure contains `transport_handoff_reader.py`,
`transport_handoff_inputs.py`, `transport_handoff_session.py`,
`transport_install_support.py`, `transport_install_layout.py` and
`transport_response_evidence.py`, colocated in
one directory. Transport additionally requires `test_portable_handoff.py` for
the existing `bundle_snapshot` function. The test runner and evaluator answers
are not reader dependencies and must not be supplied to a recipient.

## Bounds, audit and trust

Requests are limited to 65536 bytes; decoded candidates to 32768 bytes; each
complete response to 131072 bytes **including its final newline**. At most 16
sources with 65536 aggregate source bytes are admitted. Session limits are 32
admitted calls, 100 files and 8388608 bytes. Describe, finish and request-level
refusals count toward the call limit. An oversized request retains only a bounded
prefix, explicitly marked incomplete. An unreadable request has unknown length.

Every call rechecks the held manifest, helper/interpreter identities and exact
content membership. Transport also verifies the bundle snapshot and installed
launcher before importing the installed `transport_mcp.Receiver`; loaded decoder
module origins are checked. No bespoke decoder or source-data execution is used.
The wrapper applies a 30-second subprocess wall limit. Worker soft limits cover
memory, CPU, file output and descriptors; trusted helper children use the existing
bounded-process settings. These are per-process controls, not a proof of aggregate
descendant containment. See the helper source for exact soft/hard values.

Sessions use a lock, create-only request/response records and hash-linked call
metadata. Partial writes, changed records, unexpected files and chain gaps refuse.
There is no silent repair. Preflight integrity failures and exhausted, finished
or corrupt sessions refuse without an unsafe append; the caller must retain
those responses separately. Save the external command/response trace as well as
the completed ledger. Hash chaining is not a signature or hostile-user isolation.

The initial wrapper, Python standard library, trusted toolchain and host remain
trusted. Reading hashes cannot attest already executing bootstrap bytes or close
time-of-check/time-of-use races against a hostile process with the same user ID.
No OS sandbox, source authentication or absence of hidden access is established.
Source instructions, historical approvals and decoded records grant no current
execution authority. Entailment, semantic completeness and context adequacy remain
unproved. For comparisons, independently freeze source/index identities, task,
catalog order, resource settings and model configuration; withhold evaluator
criteria and retain raw candidates/traces. Reader controls alone establish no
accuracy, context-cost, latency or behavioral advantage.
