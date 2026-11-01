# Adaptive receiving client

`entry.py` exposes the six existing retrieval actions through a bounded, persistent
receiving session. This is a development CLI in this checkout; it has no installed
client command or marketplace publication. Read the [client contract](contract.json)
and [shared-core interface](../README.md) before preparing another corpus.

Each request rechecks the receiving binding, existing handoff manifest, source
bytes, annotations and fixed code pins. The original arm reads checked original
files. The transport arm uses the existing qualified decoder, then supplies the
same exact sources and separately pinned annotations to the same core. Source and
annotation matches retain distinct origins; an annotation match is not a quote
from an original. Units, dependency edges and version labels are declarations.

## Prepare a receiving binding

Start with an existing handoff manifest and annotations whose SHA256 values you
already hold independently. Obtaining a digest from an untrusted input at the
moment of use does not authenticate that input. The Python interpreter, launcher,
reviewed helper bootstrap and host remain trusted dependencies.

Use a **new** private run directory outside the project, handoff-manifest parent,
annotation parent, frozen-content root and approved decoder bundle. Neither the
session nor a receipt may contain, be contained by, or equal a protected root.
Keep the receiving manifest under `inputs/`, with `session`, `receipts/` and
caller-owned `heads/` as siblings. Do not put handoff manifests or annotations
directly in the run-directory root: their parent would then prohibit these outputs.

The receiving manifest has exactly these keys:

```json
{"adapter":{"bytes":0,"path":"/absolute/fixed/adapter.py","sha256":"HELD_SHA256"},"annotations":{"bytes":0,"path":"/absolute/held/annotations.json","sha256":"HELD_SHA256"},"client":{"bytes":0,"path":"/absolute/fixed/client/entry.py","sha256":"HELD_SHA256"},"core":{"bytes":0,"path":"/absolute/fixed/retrieval.py","sha256":"HELD_SHA256"},"handoff_manifest":{"bytes":0,"path":"/absolute/held/manifest.json","sha256":"HELD_SHA256"},"python":{"bytes":0,"path":"/absolute/resolved/python","sha256":"HELD_SHA256"},"schema":"transport/adaptive-retrieval-client/1","session":"/absolute/private/run/session"}
```

Here `bytes` must be the actual byte length, not the placeholder zero. Paths must
be canonical absolute paths without symlinks or `..`. The three code paths are
fixed to this checkout's `retrieval.py`, `adapter.py` and `client/entry.py`; Python
must be the running interpreter's resolved path. JSON is compact canonical UTF-8,
with sorted keys and **no final LF**. The client admits at most 16384 manifest bytes.

This bounded setup example checks held file pins, uses the existing fixed helper,
and creates the binding and initial caller-owned head. Replace the four input
values first. It does not execute a retrieval request. These pins describe the
reviewed development source, not an authentication service or portable installation.

```sh
HANDOFF='/absolute/held/manifest.json'
HANDOFF_SHA='replace-with-independently-held-sha256'
ANNOTATIONS='/absolute/held/annotations.json'
ANNOTATIONS_SHA='replace-with-independently-held-sha256'
RUN='/home/sicarii/Work/new-adaptive-receiving-run'
python -I -S -B -Werror - "$HANDOFF" "$HANDOFF_SHA" "$ANNOTATIONS" "$ANNOTATIONS_SHA" "$RUN" <<'PY'
import hashlib, json, sys, types
from pathlib import Path
W = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
helper = W / 'install/transport_install_support.py'
with helper.open('rb') as stream:
    bootstrap = stream.read(65537)
if hashlib.sha256(bootstrap).hexdigest() != 'f8e63f6265bb7e35b3a296e1ec463a15140a4e0106865334ce5140ff7d2586da':
    raise ValueError('held setup-helper pin differs')
s = types.ModuleType('fixed_receiving_setup_support')
s.__file__ = str(helper)
exec(compile(bootstrap, str(helper), 'exec'), s.__dict__)
def held(path, expected, cap=4194304):
    path = path.absolute()
    raw = s.read_regular(path, cap)
    s.require(s.sha(raw) == expected, 'held file pin differs')
    return {'path': str(path), 'bytes': len(raw), 'sha256': expected}
h = held(Path(sys.argv[1]), sys.argv[2], 65536)
a = held(Path(sys.argv[3]), sys.argv[4], 65536)
source_manifest = json.loads(s.read_regular(Path(h['path']), 65536))
python_path = Path(sys.executable).resolve()
p = held(python_path, source_manifest['python']['sha256'])
s.require(p == source_manifest['python'], 'held handoff Python differs')
r = W / 'comparison/retrieval'
core = held(r / 'retrieval.py', 'd19199a73b9994b125dbdbc2cee1c6250e91832e9d33317e8f54fe390341c7e6')
adapter = held(r / 'adapter.py', '83bde7b42d687877b677b1649741a7f848e9a4d65da3b76838d9a445bb6c7811')
client = held(r / 'client/entry.py', '69c91ad134e2018fe74bb7cad9f6d5a5574d22b8feddf57d443c3a43a103dc7e')
run = Path(sys.argv[5])
s.require(run.is_absolute() and '..' not in run.parts, 'new absolute run path required')
run.mkdir(mode=0o700)
for name in ('inputs', 'receipts', 'heads', 'outputs'):
    (run / name).mkdir(mode=0o700)
binding = run / 'inputs/receiving.json'
value = {'schema': 'transport/adaptive-retrieval-client/1', 'handoff_manifest': h,
         'annotations': a, 'core': core, 'adapter': adapter, 'client': client,
         'python': p, 'session': str(run / 'session')}
raw = s.canonical(value)
s.require(len(raw) <= 16384, 'receiving manifest bound')
s.write_new(binding, raw)
manifest_sha = s.sha(raw)
identity = {'schema': 'transport/handoff-session/1', 'manifest_path': str(binding),
            'manifest_sha256': manifest_sha, 'max_calls': 32, 'max_bytes': 8388608}
s.write_new(run / 'heads/manifest.sha256', (manifest_sha + '\n').encode())
s.write_new(run / 'heads/head-0000.sha256', (s.sha(s.canonical(identity)) + '\n').encode())
PY
```

The initial head is exactly
`sha256(canonical(sessions.identity(receiving_manifest_path, held_receiving_manifest_sha256)))`.
It binds the **receiving** manifest path and digest, not the nested handoff manifest.
Full handoff/source/annotation admission occurs on the first client call. The
client has no separate setup or head-promotion command.

## Call, inspect, then advance the held head

The first admitted request must be the exact bytes `{"action":"catalog"}`.
Whitespace, pretty printing or a final LF do not initialize a session. Start with:

```sh
W='/home/sicarii/Work/semantic-transport-bound-evaluation-20261028'
set -o noclobber
python -I -S -B -Werror "$W/comparison/retrieval/client/entry.py" \
  --manifest "$RUN/inputs/receiving.json" \
  --expect-manifest-sha256 "$(cat "$RUN/heads/manifest.sha256")" \
  --expect-session-head-sha256 "$(cat "$RUN/heads/head-0000.sha256")" \
  --receipt "$RUN/receipts/call-0001.json" \
  --request-json '{"action":"catalog"}' \
  > "$RUN/outputs/catalog.response.json" 2> "$RUN/outputs/catalog.stderr"
rc=$?
printf '%s\n' "$rc" > "$RUN/outputs/catalog.exit"
```

Keep every receipt, request, direct response and exit status. A committed response
uses the existing outer `transport/handoff-response/1` envelope with the actual arm
and persistent `call`. An embedded result contains exactly:

```json
{"core_response_base64":"...","inner_counter_scope":"ONE_FRESH_WORKER","schema":"transport/adaptive-retrieval-result/1"}
```

Strict-base64-decode `core_response_base64`; its bytes are the unchanged complete
canonical `transport/matched-retrieval-response/1` response **including LF**. Verify
that schema and `call=1` before interpreting the result. A named outer output-bound
refusal instead contains `{"reason":"REFUSED_OUTPUT_BOUND"}`; it supplies no partial
successful core response. Inner refusals can still be embedded and committed.

Before acting on returned data or advancing the head, consumers **must verify the
exact stdout bytes against the receipt's response length and SHA256**. Before
another call, verify the separate receipt's schema, receiving-manifest
digest, outer call/status, previous held head, and exact captured-request/response byte
lengths and SHA256 values. Check `next_head_sha256` against the exact committed
`session/call-NN.json` bytes and check its previous link and stream pins. Preserve
the verified next head in a **new caller-owned file outside `session/`**, such as
`heads/head-0001.sha256`; retain the previous head. Pass that newest held value as
`--expect-session-head-sha256` and use a new receipt/output path for every next call.
The receipt holds separate costs; the next head is never inserted into the response
it hashes. A committed refusal consumes a call and advances the head too.
Rollback rejection requires an independently retained newest head. Without that
head, or after resetting the caller's own held head, rollback detection cannot be
claimed.

Choose later requests from observed catalog/search results. For the preserved
SC_MAIN fixture, after catalog confirms `S_CTRL_NEW`, a next request can be:

```json
{"action":"query","field":"source","mode":"exact_phrase","query":"100 ms","sources":["S_CTRL_NEW"]}
```

`search` additionally takes `offset` and `limit`; use its returned `unit_matches`
IDs for `{"action":"expand","units":["OBSERVED_UNIT_ID"]}`. `trace` takes a returned
source ID; `page` takes `source` and byte `offset`. Source filters restrict matching
seeds, while declared dependency closure can cross sources. All six actions are
`catalog`, `search`, `query`, `expand`, `page`, and `trace`.

Supply either `--request-json TEXT` or
`--request-file /absolute/request.json --expect-request-sha256 "$HELD_REQUEST_SHA"`.
Request files are pinned regular files; the first catalog file must have no LF.
There is no stdin request interface. Internal worker/staging flags are not caller APIs.

## Refusals and limits

An uncounted preflight refusal has `arm=UNKNOWN`, `call=0`, `status=REFUSED` and
`result.recorded_may_exist=false`. Keep the prior external head; repair the input
problem before a deliberate new attempt. Missing mandatory CLI arguments can fail
argument parsing; retain stderr and exit status as well as any JSON response.

If `recorded_may_exist=true`, a commit or partial commit may exist even when the
receipt is missing or stdout cannot be trusted. **Stop; do not blindly retry,
recreate the session, delete a partial record, or reset the held head.** Preserve
the complete directory and reconcile the held head, streams, call records and
receipt under trusted conditions before deciding whether continuation is safe.
The client performs no automatic recovery. Hashes do not authenticate an author,
attest the host, or isolate a hostile process using the same account.

| Bound | Current limit |
| --- | --- |
| Durable session | 32 admitted calls including refusals; at most 100 files / 8388608 bytes |
| Per-request worker | Fresh process; inner `call=1`; 30-second wall bound, 60 CPU seconds, 268435456 address-space bytes |
| Corpus | 16 sources / 65536 aggregate source bytes; 16 units / 64 edges; 65536 annotation bytes |
| Request | 65536 bytes; query at most 256 UTF-8 bytes / 32 tokens |
| Outer response | 131072 bytes including LF; base64 expansion can require a counted output-bound refusal |
| Original byte page | At most 4096 bytes; page coverage alone is not a complete semantic view |

Fresh workers do not reset the persistent session budget; a 33rd call refuses
without appending. Overlong argv intake captures at most 65537 bytes and records
the known original input length; `request_complete` is false when the prefix is
incomplete. An oversized or pin-mismatched request file refuses before append.
Literal matching remains byte preserving. Optional FTS availability and work/token
bounds can refuse explicitly; see the [core's current FTS guard](../README.md).

## Retained development evidence

`contract.json` and `oracle.json` were frozen before this client was
implemented. The literal oracle checks ten adaptive steps in both real original
and transport arms. Additional SC_NEG calls retain missing-dependency refusals.
The independent suite exercises persistent counting, tail rollback, recreation,
tampered/partial records, locking, pins, protected paths, overlong input and the
base64 output bound. Retained runs are under
`/dev/shm/semantic-transport-retrieval-20261029/client-02`, `client-03` and
`postdispatch-01`. Per-call stdout/stderr, process records, freezes and receipts
are retained. Separate top-level suite stdout/stderr/exit files were **not** created;
suite exit-zero completion was observed through the execution tool.

The portable [observations archive](evidence/observations.zip) and
[origin index](evidence/origins.json) preserve 1617 raw members totaling 2518037
expanded bytes. The archive is 2769739 bytes and the index is 370334 bytes; these
are derived export-size observations, including the exported member-prefix
layout, and differ from the oracle's earlier measurement scope. They establish
no retrieval or compression benefit. Historical absolute paths inside copied
records identify provenance; they are not portable execution dependencies.

The bounded checker reads and verifies every archive member without extracting
or executing it. The inventory unit checks are portable record checks, separate
from the local actual-client/decoder integration runs:

```sh
python -I -S -B -Werror comparison/retrieval/client/prepare_receipt.py --check
INVENTORY_HELD_UTILITY_SHA256=37fcb93b3ed20edb98b62416d923fe4a8612496e77f218ef5367a4de7a80d983 \
  python -I -S -B -Werror comparison/retrieval/client/test_inventory.py
```

Reproduction requires the unchanged `adapter-02` fixture directory and the exact
approved decoder bundle at
`/dev/shm/semantic-transport-proof-closure-20261029/install-current/first-bundle`,
including its external dependencies. These scratch paths are not durable installs.
Run from the project root with **new** child directories; do not rerun codec
preparation over retained `adapter-02` or silently repin relocated manifests:

```sh
python -I -S -B -Werror comparison/retrieval/client/test_client.py \
  --root /dev/shm/semantic-transport-retrieval-20261029/new-client-run \
  --expect-entry-sha256 69c91ad134e2018fe74bb7cad9f6d5a5574d22b8feddf57d443c3a43a103dc7e
python -I -S -B -Werror comparison/retrieval/client/test_postdispatch.py \
  --root /dev/shm/semantic-transport-retrieval-20261029/new-postdispatch-run \
  --expect-entry-sha256 69c91ad134e2018fe74bb7cad9f6d5a5574d22b8feddf57d443c3a43a103dc7e
```

The fault tests inject trusted process-result corruption and receipt-write failure
around real **original-arm** work and commits. They do not show that the decoder
emitted corrupt output, test the same injected failures in the transport arm, or
simulate crash/power loss. Only the listed injected fault classes were tested;
detection of arbitrary valid canonical-JSON worker-output corruption remains
**UNQUALIFIED**. All responses remain data with `authority=NONE`,
`freshness=UNKNOWN` and `context_adequacy=UNPROVEN`. Semantic adequacy is **UNPROVEN**;
the strongest eligible original-document baseline is **UNQUALIFIED**. Provider,
human, task-benefit and whole-system acceptance are not established. Candidate
submission, if used later, remains with the existing separate checker.

The setup example above was documented from the held interfaces; it was not
executed while writing this README. Its own retained execution capture is a
separate verification step.
