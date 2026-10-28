# Bounded response contracts

This is an explicit syntax contract for future recipients. It does not encode a
fixture's expected answer, judge source meaning, prove completeness, decide
approval, or authorize execution. A conforming object can contain false claims.
Contract descriptions are inert text for people and recipients, never code.

The format is `transport/response-contract/1`. It is deliberately a small closed
instruction table, not JSON Schema. Every supported keyword is listed below;
unknown keywords, types, versions, missing fields and duplicate JSON keys refuse.
No fetch, references to external documents, supplied code, regular expressions,
unions, defaults, optional object keys or type coercions are supported.

The top object has exactly `schema`, `description`, `root`, `nodes`. Description
is a nonempty UTF-8 string of at most 1024 bytes. Nodes are an ordered list of
1–64 records. IDs match `[A-Z][A-Z0-9_]{0,31}`. Each record has required `id`,
`type`, and nonempty `description` (at most 1024 bytes), plus exactly the fields
for its type. References name only earlier nodes. The root must name the final
node, which must be an object. All nodes must be reachable from that root.
This gives an acyclic table; compilation and validation use bounded worklists,
without recursive traversal. A compiled value shape has depth at most eight.

| Type | Additional required fields | Optional fields |
| --- | --- | --- |
| `object` | `fields`: map from field name to earlier node ID | None |
| `string` | `min_bytes`, `max_bytes` | `enum`: nonempty list of unique strings |
| `integer` | `min`, `max` | None |
| `boolean` | None | None |
| `null` | None | None |
| `array` | `items`, `min_items`, `max_items`, `unique`, `unique_by` | None |

Objects are always closed: all declared fields are required, and extra keys
mismatch. At most 32 fields are permitted, named `[a-z][a-z0-9_]{0,63}`. String
lengths count UTF-8 bytes, inclusive, between zero and 4096. Enum lists contain
1–64 strings within those same declared bounds. Enums belong to that field;
a token valid for one field does not become valid everywhere.

Integers are JSON integers in the signed 64-bit range. Bounds are inclusive;
`min == max` is an explicit literal numeric restriction, never source evidence.
JSON booleans are not integers, and integers are not booleans. Decimal/exponent
number syntax, NaN, infinity and all floating-point values are unsupported.
`null` means literal JSON null only, not unspecified type or an unknown-status
placeholder. Types are always explicit.

Arrays have inclusive bounds between zero and 64. `items` names an earlier node.
`unique` is a JSON boolean. With `unique_by: null`, `unique: true` supports only
scalar item types and compares exact typed values. With a non-null `unique_by`,
`unique` must be true, items must be objects, and the named field must be a
required string with `min_bytes >= 1`. Those exact string IDs must be unique.
There is no Unicode normalization, fuzzy matching or semantic deduplication.
Required arrays are required object fields; minimum length can require entries.
The subset has no cross-field arithmetic, unit conversion or referential logic.

See `response_contract_example.json` for a complete generic contract. Its
`decoder_execution_authority` allows only `NONE`: decoding grants no execution
permission. Its separate `source_approval` field allows `APPROVED`, `REVOKED`, or
`UNKNOWN`. The validator does not select one or authenticate the claim.
`UNKNOWN` approval evidence and `NONE` decoder authority are distinct concepts.
The example contains no candidate names, source-specific numbers or expected
source answer. Author a future contract before receiving/evaluating responses;
do not derive truth assertions by narrowing a schema after observing answers.

## CLI and API

Obtain the expected contract SHA-256 through an independent trusted channel.
A checksum shipped alongside untrusted data does not establish that identity.
The candidate is read once, hashed for the verdict, then both files are checked
again before output. No file is changed. Pin checking does not authenticate
already running bootstrap code or exclude same-user replacement-and-restoration
races. Python, imported local helpers, standard library, loader and OS are trusted.

```sh
python3 -I -S -B -Werror install/transport_response_contract.py \
  --contract /absolute/contract.json \
  --expect-contract-sha256 INDEPENDENTLY_HELD_CONTRACT_SHA256 \
  --candidate /absolute/response.json
```

Exit 0 means `STRUCTURALLY_CONFORMANT`, 1 means `STRUCTURAL_MISMATCH`, and 2
means `REFUSED` (for example invalid/mismatched contract, malformed JSON or a
resource limit). Normal validation emits one complete JSON verdict with LF,
including `scope: STRUCTURE_ONLY`, `semantics: NOT_ASSESSED`,
`source_approval: NOT_ASSESSED` and `execution_authority: NONE`.
At most 16 diagnostics are returned; an early diagnostic cutoff is explicit.
No success verdict is emitted for an incomplete traversal. `--help` is ordinary
CLI help rather than a validation verdict. Validation never runs source data.

Programmatic use: `transport_response_contract_model.compile_contract(bytes)`
returns the compiled node table/root, and
`transport_response_contract.validate(candidate_bytes, compiled)` returns only
the structural result. Keep the compiled table private and unchanged; these API
functions assume the caller uses the actual compiler output. Authenticate raw
contract bytes before compiling when input identity matters. The CLI performs
that authentication and file rechecks.

Contract input is at most 65536 bytes; candidate input at most 32768. JSON nesting
is capped by the existing 12-level parser; objects/arrays have at most 128 members,
strings at most 4096 UTF-8 bytes, parsed contract values at most 4096 and candidate
values at most 1024. Verdicts are capped at 32768 bytes including LF. The CLI sets
address-space, CPU, file-size and descriptor limits. These are deterministic
engineering controls, not a formal proof of the Python runtime or whole system.

Encoding policy: contracts and candidates must be strict UTF-8 JSON without a BOM
or literal NUL bytes. UTF-16/32, invalid UTF-8 and lone surrogate values are refused.
Valid escaped surrogate pairs and ordinary multibyte UTF-8 are accepted without
normalization or replacement of the original bytes.
