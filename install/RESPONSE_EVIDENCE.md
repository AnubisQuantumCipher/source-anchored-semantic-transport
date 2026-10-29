# Check response citations against their sources

The optional source-evidence profile checks citations inside a candidate before
the reader saves it. Each selected quotation must equal an exact byte interval
in the named, digest-pinned source. It rejects fabricated text, changed numbers,
misattributed source IDs and stale source revisions. The existing structural
contract still checks the response's fields and types.

A correct quotation does not establish that the surrounding claim follows from
it. A genuine revocation quote alongside an `APPROVED` claim is a retained test
that passes citation linkage while leaving semantics `NOT_ASSESSED`.

## Citation records and selectors

Each selected citation has exactly these fields:

| Field | Meaning |
| --- | --- |
| `source_id` | An existing source ID from the checked catalog |
| `source_sha256` | The full lowercase SHA-256 of that exact source revision |
| `start`, `end` | Exact integer, half-open **byte** offsets; Boolean values refuse |
| `quote` | Nonempty UTF-8 text whose encoded bytes equal the selected source interval |

There is no whitespace, line-ending or Unicode normalization. Repeated quotations
require their explicit location. A byte interval that cuts through a UTF-8
character cannot equal a valid UTF-8 quote. Other source bytes, including opaque
binary data, remain transportable; this citation profile selects UTF-8 text.

An evidence contract is a closed JSON object with schema
`transport/response-evidence-contract/1`, an inert `description`,
`response_contract_sha256`, and `selectors`. The response digest must match the
actual structural contract validated by the checked wrapper. A selector is a
list of field names; `*` traverses every item of a nonempty array. For example:

```json
[["claims", "*", "evidence"]]
```

This selects each `evidence` object inside `claims`. It does not select an
unrelated citation array elsewhere. Every selector must find at least one
record; missing fields, empty arrays and overlapping selections refuse. Only
the declared selections are checked. A contract's author remains responsible
for selecting all citations that the receiving workflow requires.

## Checked submission

Prepare the existing receiving client and structural response contract first.
Obtain their identities and the evidence-contract identity through the trusted
handoff channel. Then add the two evidence options to checked submission:

```sh
python3 -I -S -B -Werror install/transport_checked_finish.py \
  --contract "$response_contract" \
  --expect-contract-sha256 "$held_response_contract_sha256" \
  --candidate "$candidate" \
  --binding "$binding" --expect-binding-sha256 "$held_binding_sha256" \
  --evidence-contract "$evidence_contract" \
  --expect-evidence-contract-sha256 "$held_evidence_contract_sha256"
```

The evidence options are a required pair. If either is supplied incorrectly,
there is no fallback to ordinary submission. Both omitted retains the existing
structure-only mode and its result shape. A workflow requiring source linkage
must require `DRAFT_SAVED_SOURCE_LINKED`, a structural pass and the matching
`SOURCE_SPANS_MATCH` verdict; a plain saved draft is insufficient.

The wrapper binds candidate, structural contract, evidence contract, receiving
manifest and client identity. The candidate's bytes remain unchanged. The
compact verdict records the selected-record count and the digest of the
resolved links, whose locations and quotes remain in the candidate. Preserve
the candidate, contracts, enclosing binding and session records together.

The direct reader action `finish_evidence` accepts `candidate_base64`,
`evidence_contract_base64` and `expect_evidence_contract_sha256`. It checks
source linkage and saves within one session operation. It **does not** validate
the structural contract; its `response_contract_sha256` is a declaration until
the checked wrapper verifies it. Successful submission closes the session.
Pre-save refusal creates no candidate. Post-save integrity failure retains the
existing conservative `UNKNOWN_MAY_BE_SAVED` state and captured response.

## Bounds and reproduction

Evidence contracts are at most 8192 bytes, with at most 16 selectors of 8 tokens.
At most 64 citation records and 1024 traversal steps are admitted. Quotations
are at most 4096 UTF-8 bytes. The existing candidate, request, response, session,
source and process limits remain unchanged; the maximum-size candidate and
evidence contract are tested together through the real submission path.

This opt-in profile also restricts both JSON documents to 1024 values, depth 8,
128 entries per container, 128 UTF-8 bytes per key, 4096 UTF-8 bytes per string,
and signed 64-bit integers. Floating-point values, nonfinite values, NULs,
duplicate keys, invalid UTF-8 and a leading BOM refuse. These restrictions apply
to unselected fields too; a structurally valid candidate can therefore refuse
this profile. They are validation rules, not changes to the ordinary mode.

One named module joins the fixed reader helper closure, within its existing
limit. The test-source inventory now includes that dependency; this changes its
exact roster, not the product's resource limits. Older frozen trials keep their
original helper identities and results. Obtain a newly prepared binding to use
the new action; there is no automatic migration of old runtime identities.

```sh
python3 -I -S -B -Werror install/test_response_evidence.py
python3 -I -S -B -Werror install/test_evidence_finish.py \
  --evidence /absolute/new-original-controls
python3 -I -S -B -Werror install/test_evidence_finish.py \
  --bundle /absolute/existing-installed-bundle \
  --evidence /absolute/new-both-arm-controls
```

These are deterministic source-linkage controls. They do not certify narrative
entailment, context adequacy, author identity, current approval or execution
authority. The native decoder and Ada/SPARK source are unchanged; the Python
adapter and host remain part of the trusted computing base.
