# Structurally checked draft submission

`transport_checked_finish.py` validates a candidate against an explicitly held
response contract, then submits those exact bytes through the existing pinned
handoff client. It does not change the reader, codec, source format or earlier
trial criteria. See [RESPONSE_CONTRACT.md](RESPONSE_CONTRACT.md) for the declarative
contract subset and [HANDOFF_CLIENT.md](../docs/HANDOFF_CLIENT.md) for receiving
directory preparation and the client binding.

Use an authenticated contract digest supplied independently by the contract owner
and a binding digest supplied independently by the receiving-directory preparer.
Computing a digest from arbitrary received input does not authenticate that input.
The following command uses shell variables already populated from those trusted
channels; paths are absolute and the candidate must be outside the reader session.

```sh
python3 -I -S -B -Werror install/transport_checked_finish.py \
  --contract "$contract_path" --expect-contract-sha256 "$held_contract_sha256" \
  --candidate "$candidate_path" \
  --binding "$binding_path" --expect-binding-sha256 "$held_binding_sha256"
```

The candidate is one UTF-8 JSON object, at most 32768 bytes, with no duplicate JSON
keys. UTF-8 BOM, UTF-16/32, literal NUL, invalid UTF-8 and lone surrogates are
refused before dispatch; valid escaped surrogate pairs retain their original bytes. The contract cap is 65536 bytes. The existing binding schema remains
`transport/handoff-client/1`; it has exactly `schema`, `manifest`, `session`,
`reader`, `python` and `client`. All entries other than schema/session are exact
`path`, `bytes`, `sha256` file records. The existing manifest supplies the helper,
source and, for transport only, installed decoder/package identities.

The copied client and reader helpers must equal this trusted local checkout's
counterparts. The helper directory has exactly the existing five original-reader
helpers plus the client; transport additionally requires `test_portable_handoff.py`.
No arbitrary client program or shadow helper is accepted. The binding Python must
be the currently running resolved executable and fit the unchanged 4 MiB file
cap. The adapter, validator and imported local dependencies remain trusted
bootstrap code: disk hashes do not attest already executing code or the host.

Shape failure, wrong held digest or a detected frozen-input mismatch before
client dispatch produces no client action. A new session receives `describe`
followed by `finish`; an existing session receives only `finish`. There are at
most two bounded client processes, each with a 35-second deadline and an 8192-byte per-stream
capture cap. The reader's existing 32-call session limit remains unchanged. Exact
source bytes and fixed client/helper identities are rechecked around dispatch.
Transport decoder validation remains the existing client's/reader's responsibility.

The adapter reads at most 48 tracked files and 16 MiB in aggregate, with existing
per-file caps. It executes fixed Python argv without a shell. Source strings,
contract descriptions and candidate strings are data; they are never executed.
It has no credential, network or install facility. Its complete JSON verdict,
including final LF, is bounded by 131072 bytes.

Exit 0 reports `DRAFT_SAVED_STRUCTURALLY_CHECKED` only after the real saved draft
matches the original candidate bytes. Exit 1 is `STRUCTURAL_MISMATCH`; exit 2 is
`REFUSED`. The verdict records bounded process observations, exact base64-encoded captured
stdout/stderr, their byte counts and hashes, and an explicit extent/completeness flag.
Only SUCCESS/EXIT_NONZERO captures are marked complete; output-limit, timeout or
other process refusals retain a prefix marked PREFIX_OR_INCOMPLETE. A capture
hash authenticates that captured prefix, not an unknown original stream.
Hard host termination or a missing/framing-invalid verdict is an external process
failure; it does not establish that no action was recorded. The verdict records
`reader_action_may_be_recorded`. Once a finish process has been dispatched, a
failure reports `draft_state: UNKNOWN_MAY_BE_SAVED`; inspect the original session
records before retrying. Partial reader writes or same-user races are not rolled
back or hidden. A refusal after describe can also leave a recorded action.

Structural conformance does not establish semantic correctness, completeness,
source approval, task completion or safe execution. For example, a candidate's
`source_approval: APPROVED` can conform structurally without being true. The
verdict itself reports `execution_authority: NONE`, independently of that source
claim. An exact saved candidate is a draft, not a completeness certificate.
Direct client finish remains available: using this command is mandatory only
within a workflow that explicitly selects it, not OS authority enforcement.

## Reproduce deterministic controls

From a trusted checkout, run the following. These commands create new temporary
evidence, require no private fixtures or installed decoder and run no models.
The freeze covers exactly the validator/model, both tests, example/docs, adapter,
freezer, existing support/layout/inputs/client/reader/session, and resolved Python.
Every listed file is checked before and after each test suite. The printed pin is
explicitly **self-derived test-source identity**, not independent authentication
of a contract, binding or checkout. The output directory is retained for review.

```sh
response_checks=$(mktemp -d)
test_pin=$(python3 -I -S -B -Werror install/freeze_response_contract_tests.py \
  --output "$response_checks/inputs.json")
python3 -I -S -B -Werror install/test_response_contract.py \
  --freeze "$response_checks/inputs.json" --expect-freeze-sha256 "$test_pin" \
  --evidence "$response_checks/contract"
python3 -I -S -B -Werror install/test_checked_finish.py \
  --freeze "$response_checks/inputs.json" --expect-freeze-sha256 "$test_pin" \
  --evidence "$response_checks/finish"
```

The submission controls use the actual original reader and preserve exact draft
whitespace/LF. They test refusal before client mutation for malformed, duplicate,
wrong-type and oversized candidates, identity mismatches and unexpected helpers.
They also test finished-session refusal and a real save followed by detected input
drift. They do not establish transport decoder behavior or model response quality.
