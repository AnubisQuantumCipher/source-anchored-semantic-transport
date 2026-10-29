# Local handoff preparation and client

`install/transport_handoff_prepare.py` creates a receiving directory for either
original documents or an already encoded Source-Anchored Semantic Transport
pair. It runs no model and does not encode, interpret or execute source text.
The original arm has no decoder dependency. Both arms use the existing bounded
reader; the client supplies a shorter, fixed receiving-session command.

## Establish the inputs

Use a trusted checkout and Python executable. Obtain source/task byte lengths and
SHA-256 values from their owner or an independent verifier. For transport, also
obtain the exact installed-bundle snapshot and installation-manifest digests,
pair-file pins and independently held `STS1:...` package identity. A manifest or
checksum delivered alongside untrusted data does not establish those identities.
Hash comparison preserves an established identity; it does not establish source
truth, semantic completeness or current authority.

An authenticated preparation configuration has these exact fields. Unknown or
missing fields refuse. All input paths are canonical absolute local paths.

| Field | Required value |
| --- | --- |
| `schema` | `transport/handoff-preparation/1` |
| `arm` | `original` or `transport` |
| `task` | File pin for nonempty UTF-8 task text, at most 32768 bytes, no NUL |
| `python` | File pin for the resolved executable running the preparer/client/reader |
| `sources` | Ordered list of 1–16 explicitly supplied source records |

A file pin is exactly `{ "path": ABSOLUTE_PATH, "bytes": INTEGER,
"sha256": LOWERCASE_SHA256 }`. The integer must be nonnegative and SHA-256 must
have 64 hexadecimal characters. The ordinary file cap is 4194304 bytes.

Each original source record has exactly `id`, `label`, `media_type`, `provenance`,
`path`, `bytes`, `sha256`. Each transport source record has those same fields
except `path`. Source IDs match `[A-Z][A-Z0-9_]{0,31}` and must be unique. Each
source is at most 65536 bytes; their combined declared size is at most 65536.
Each label/media type/provenance is at most 1024 UTF-8 bytes; media type is
nonempty. Supply neutral metadata in the same order for a matched comparison.
Do not include answers, evaluator criteria or semantic annotations in the
original arm. This is a caller obligation; byte checks cannot decide neutrality.

Transport configurations additionally require exactly:

| Field | Exact contents |
| --- | --- |
| `bundle` | `{ "path": ABSOLUTE_BUNDLE, "install_sha256": HELD_INSTALL_DIGEST, "snapshot_sha256": HELD_SNAPSHOT_DIGEST }` |
| `pair` | `{ "share": FILE_PIN, "archive": FILE_PIN, "identity": HELD_STS1_IDENTITY }` |

`identity` has form `STS1:` followed by 64 lowercase hexadecimal characters.
Each pair file is at most 131072 bytes and their paths must differ. The bundle
snapshot is the existing `test_portable_handoff.bundle_snapshot` value serialized
with `transport_install_support.canonical`; it includes the declared bundle
location as well as file bytes, modes and runtime/install identities. Establish
that expected digest independently for the intended installed bundle. Preparation
checks it before copying and again afterward. Package/source metadata and held
source hashes must agree with the installed receiver's checked interpretation.

## Derive a configuration from authenticated held inputs

The following runnable example canonicalizes an already authenticated input
description into a create-only configuration and prints its derived config pin.
`held-inputs.json` must contain the exact fields above. Obtain its raw-file digest
through your independent trusted channel before this command. Do not compute a
digest of arbitrary received input and call that the expected value.

```sh
python3 -I -S -B -Werror - /absolute/trusted-checkout/install \
  /absolute/held-inputs.json EXTERNALLY_HELD_INPUTS_SHA256 \
  /absolute/new-config.json <<'PY'
import sys
from pathlib import Path
if len(sys.argv) != 5:
    raise SystemExit('expected install, held inputs, held digest, new config')
sys.path.insert(0, sys.argv[1])
from transport_handoff_inputs import digest, json_value
from transport_install_support import canonical, read_regular, require, sha, write_new
source, target = Path(sys.argv[2]), Path(sys.argv[4])
require(source.is_absolute() and target.is_absolute(), 'absolute paths required')
raw = read_regular(source, 65536)
require(sha(raw) == digest(sys.argv[3]), 'independent held-input identity differs')
encoded = canonical(json_value(raw))
write_new(target, encoded, 65536)
print(sha(encoded))
PY
```

The printed config digest is derived from authenticated bytes. The preparer
subsequently verifies the declared file pins, schema and bundle/package identity.
The description is supplied by the caller; this example invents no source facts.

## Prepare and receive

Use the derived config pin through the same trusted channel:

```sh
python3 -I -S -B -Werror install/transport_handoff_prepare.py \
  --config /absolute/new-config.json \
  --expect-config-sha256 DERIVED_AUTHENTICATED_CONFIG_SHA256 \
  --output /absolute/new-receiving-directory
```

The output parent must already exist. Existing output directories and symlinked
parents refuse. Transport output cannot overlap its source bundle. Preparation
copies exact content bytes, the reader helper closure and the client; transport
also copies the declared decoder. It checks the copied reader before publishing
`interface.txt` and `client-binding.json`. The original helper closure is exactly
the reader, its inputs/session modules, source-evidence validator and install support/layout modules;
transport adds `test_portable_handoff.py`. The client is pinned separately.

On success, `preparation.json` reports `PREPARED_NOT_DISPATCHED` and includes the
binding/interface/task/manifest pins. Authenticate this successful preparation
receipt and the binding pin before delivering the task and interface. Paths in
these files describe local dependencies; they are not portable public references.
Moving a directory requires a newly prepared, checked binding. Meaning-package
portability does not make the local Python executable or decoder paths portable.

Each client binding has exactly `schema: transport/handoff-client/1`, file pins
`manifest`, `reader`, `python`, `client`, and absolute `session`. The selected
session is `sessions/recipient`, initially absent inside an empty `sessions/`.
The retained preflight uses a separate validation session and consumes none of
the recipient's calls. Read `interface.txt` for the complete task and command.

```sh
python3 -I -S -B -Werror /absolute/receiving/helpers/transport_handoff_client.py \
  --binding /absolute/receiving/client-binding.json \
  --expect-binding-sha256 AUTHENTICATED_BINDING_SHA256 \
  --request-json '{"action":"describe"}'
```

Alternatively use `--stdin`, supplying one raw JSON object and EOF, or
`--request-file PATH --expect-request-sha256 HELD_DIGEST` for a bounded pinned
regular file. File input avoids the smaller command-line argument bound. Each call
uses one of these closed shapes:

```json
{"action":"describe"}
{"action":"catalog"}
{"action":"page","source":"SOURCE_ID","offset":0}
{"action":"focus","unit":"UNIT_ID"}
{"action":"finish","candidate_base64":"BASE64_OF_EXACT_UTF8_JSON_OBJECT_BYTES"}
{"action":"finish_evidence","candidate_base64":"BASE64_OF_EXACT_UTF8_JSON_OBJECT_BYTES","evidence_contract_base64":"BASE64_OF_EXACT_EVIDENCE_CONTRACT_BYTES","expect_evidence_contract_sha256":"HELD_EVIDENCE_CONTRACT_SHA256"}
```

Start with `describe`. `catalog` supplies the same nonsemantic source metadata
in both arms, not source contents or unit identifiers. `page` returns a checked
4096-byte source span. Transport callers can discover declared unit identifiers
in the page response's `result.review.meaning_units[].unit`, or use an explicit
task selector, before `focus`. Focus is available only in transport. Neither
source paging nor focus establishes context adequacy or semantic completeness.
Encode the exact UTF-8 bytes of your JSON object as base64 for `finish`; the
reader saves them unedited once. That save is not an answer-quality certificate.
`finish_evidence` checks selected candidate citations before saving; see the
[evidence contract](../install/RESPONSE_EVIDENCE.md). Use the checked wrapper when
both structural validation and source linkage are required.
For another transfer, prepare another new directory and binding explicitly.

## Bounds and failure handling

Requests are capped at 65536 bytes, candidates at 32768, responses at 131072
including their final LF, and sessions at 32 calls including admitted refusals.
Stdin additionally has a five-second deadline and 1024-read bound. The client
rechecks its binding/helper identities before and after a bounded reader process.
A post-call integrity refusal can occur after a reader action was recorded;
retain the response and session evidence rather than retrying automatically.
Preflight corruption or an exhausted/corrupt session refuses without an unsafe
log append. These mechanisms do not provide an operating-system sandbox,
backend attestation or hostile same-user race containment. Bootstrap code,
Python's standard library, loader and operating system remain trusted.

Preparation never deletes an arbitrary supplied path. Partial failures remain
with `preparation-failure.json` where writable, plus retained preflight process
outputs. No interface/binding is emitted before successful preflight. A later
write failure can leave those files without a success receipt: treat that entire
output as failed. This is create-only preparation, not an atomic publication of
the directory. Stop on refusal or truncated output and preserve explicit
unknowns. Source text and decoded records never grant execution authority.

Run deterministic preparation controls with a trusted installed bundle and a
new evidence directory; these exercise tools and integrity controls, not models:

```sh
python3 -I -S -B -Werror install/test_handoff_prepare.py \
  --bundle /absolute/installed/bundle --evidence /absolute/new-evidence-directory
```
