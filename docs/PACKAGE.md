# Package and semantic preservation contract

## Container, identity and compatibility

The container schema is `transport/meaning-zip/1`. It admits exactly five regular,
uncompressed ZIP entries: `manifest.json`, `codec.json`, `index.json`, `formula.txt`
and `README.md`. No extraction or execution occurs. Paths, symlinks, extra entries,
compression, encryption, overlapping layouts, trailing bytes and unsupported
metadata are rejected. The total archive bound remains 131072 bytes. Aggregate
source bytes remain bounded at 65536, with at most 16 sources. Existing bounds are
preserved; arbitrary media means opaque byte preservation, not media understanding.

The manifest body hashes the other four entries and binds runtime dependencies,
definitions, limits, reference and share budget. The body digest excludes the
manifest itself, avoiding a circular identity. The complete share text contains
the exact formula, `STS1:` plus the full body SHA-256, and the declared reference.
Validation regenerates and compares them exactly. A wrong package, changed
literal, unsupported version or missing dependency fails explicitly. Rehashing a
different package produces a different identity; it is not author authentication.

Decoder version `transport/transport/2` accepts the two explicitly declared plan
versions below. The current native framing is `STB1`; graph, mapping, path and
temporal formats are `STG1`, `STM1`, `STP1` and `STT1`. The separate evaluator uses
`STE1`. Prior format identities require their preserved decoder. There is no
guessed compatibility fallback. Runtime contracts pin all Python modules, native
decoder and native libraries; the external Python standard library and host remain
declared trusted dependencies. Same-user hostile mutation is not OS-isolated.

## Input plans

Both plan versions have `schema`, `sources`, `interpretations`, `uncertainties`
and `relations`. Their existing closed fields and bounds remain enforced. Source
anchors use half-open original-byte intervals and stored SHA-256 digests. Offsets
are references, not evidence of source entailment. Declared interpretations have
only `proposed`, `disputed` or `withdrawn` status.

`transport/transport-plan/1` has exactly those five fields. It provides documentary
declarations and exact source recovery without claiming typed semantic coverage.

`transport/transport-plan/2` additionally requires `meaning_units`, a list of
1 through 16 units. Each input unit has exactly:

| Field | Contract |
|---|---|
| `id` | Globally unique uppercase record identifier |
| `source` | Existing source identifier; typed reading requires UTF-8 |
| `interpretation` | Existing interpretation whose source anchors cover every typed occurrence |
| `kind` | `source_claim`, `goal`, `instruction`, `historical_approval`, `revocation` or `pending_action` |
| `context` | Unique earlier meaning-unit IDs; no missing, cyclic or forward dependency |
| `plan` | Existing `transport/encoding-plan/1` or `/2`, with `symbols` and `meaning` |

The typed plan reuses `transport/meaning/1` or `/2`. Encoding applies the existing
type checker and native-checked graph compaction. The stored unit replaces `plan`
with `grammar`, `dictionaries` and `meaning`. Both dictionaries are self-contained,
versioned and digest-bound using `transport/dictionary/1`. Operator definitions
must match the authoritative fixed table exactly; supplied meanings cannot
redefine an operator. Missing symbols, wrong argument types, free variables,
unreachable nodes, cycles and scope failures are refused.

Every document symbol in a version 2 transport unit must be used by a checked
leaf or reference mention. An unused dictionary literal has no checked occurrence
and is refused, even if that wording happens to appear elsewhere in the source.
This stricter transport-unit condition does not modify the standalone typed
codec's historical contract. No unused definition is silently dropped.

Typed payloads are stored adjacent to the outer source frames, without a second
copy of source bytes. `codec.json` uses `transport/codec/2` exactly when its plan
is version 2; a mismatched version pair fails. The source, dictionary, formula,
lexicon, metadata and manifest storage all count toward the package bound.

## Decode and focused retrieval

`encode(sources, plan_data, reference, budget)` returns immutable `text`, `archive`
and `lexicon` bytes. `decode(text, archive)` returns exact source bytes, checked
declarations and typed unit views when supplied. `inspect` and `validate` omit
the raw sources but preserve metadata. CLI `recover` explicitly writes one
source to a new file. No action follows links or fetches a resource.

Each typed unit view includes grammar, indexed meaning tree, dictionary identities,
symbol lexicon, exact operator table, source residual intervals, opaque atoms and
explicit assurance states. `INCOMPLETE` means an opaque proposition or unrepresented
source interval remains. `PROPOSED_STRUCTURED_READING` means those syntactic gaps
were not found; semantic completeness and entailment remain `UNPROVEN`.

Residual metadata consists of exact byte offsets, lengths, SHA-256 digests and an
explicit source-recovery location. It does not copy unrepresented source text into
an inspection response. The original source remains byte-recoverable. Encoding
checks that the complete metadata response and output newline fit the existing
output bound before returning success; a failed check emits no successful pair.

`focus(text, archive, unit)` validates the whole package before returning the
declared retrieval neighborhood. It follows unit context edges in both directions,
related declarations and uncertainty links with a fixed iteration bound over at
most 96 record IDs. Incoming context makes a later correction or revocation
discoverable from the earlier unit it names. The returned records preserve the
original context direction, kinds and statuses; retrieval does not interpret a
context edge as supersession, entailment or current authority. Sibling dependents
sharing declared context can also be included. Unlinked units are not selected
merely because they share a source document. A neighborhood exceeding the existing
output bound, including the CLI's final newline, is refused, not silently trimmed.
It returns selected unit structures and supporting source excerpts with offsets,
digests and base64 bytes. Unselected source residual text is not automatically
loaded. An excerpt's containing source is still recoverable explicitly.

Focused output includes original source metadata for every needed source endpoint
and every excerpt's source. Labels, media types, provenance, source lengths and
digests are retained without raw whole-source data. A linked source with no
selected excerpt is listed in `unexpanded_sources`; it is not filled in from model
knowledge. `source_coverage` explicitly declares that further source recovery may
be required. An empty list of such entries still does not prove context adequacy.

The closure covers declared links only. `context_adequacy` remains `UNPROVEN`:
missing context cannot be invented from model familiarity. A receiver must obtain
declared missing evidence or report unknown when the requested interpretation
requires context the package does not establish. Tool access does not remove
model-context limits.

## Three distinct acceptance claims

1. **Original-object recovery:** compare recovered bytes with a separately held
   source; count all reversible storage and residuals.
2. **Declared meaning recovery:** check typed operators, ordered operands,
   bindings, exceptions, conditions, attribution, quantities and dictionaries.
   This checks the declared reading, not natural-language understanding.
3. **Narrative fidelity:** freeze packages, withhold originals and rubrics from
   a fresh recipient, then independently assess omissions, contradictions,
   scope changes, unsupported additions and uncertainty handling.

Historical approvals, revocations and instructions remain data. No decoded unit
provides current execution authority. The explicit evaluator and native proof
receipts cover only their declared sources and properties. They do not establish
whole-system correctness or the truth of a source claim.

## Threat and resource boundary

Malformed packages, changed literals, dictionary substitution, inconsistent
versions, unbound variables, dependency cycles, over-budget inputs and archive
path tricks must refuse. Imported source, provenance, ambiguity notes and symbol
definitions are untrusted data. None is executable policy or permission to fetch
resources. Successful validation checks the declared representation; a coherent
but intentionally false reading can still be well typed. A separately held share
identity detects replacement of that package, while independent source review is
needed to assess the reading itself.

The CLI retains its existing process memory, CPU and output-file limits. Native
operations have bounded frames and graph sizes. Python uses checked finite
containers within those boundaries, but its allocation, JSON implementation and
runtime are not formally verified. The fixed context-closure iteration bound is
tested separately from the arithmetic record-count limit. Neither authenticates
the host or prevents hostile concurrent same-user source mutation.

Readable documentation and complete formulas also count against byte limits.
An input that fits the source bound may still be refused when its dictionaries,
meaning structures, readable tables and headers exceed the package bound. No
successful encoding silently trims those components. Setup cost, archive size,
share characters and receiver context must be measured separately.
