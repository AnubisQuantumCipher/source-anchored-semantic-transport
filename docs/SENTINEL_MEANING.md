# Bounded census and meaning proposals

`sentinel_v1.census.build_census` partitions a supplied exact UTF8 reading into
intact paragraphs, a declared document/chapter/section hierarchy, and byte-bound
analysis shards. Paragraphs include their blank-line delimiters. Every byte is
accounted for as pending or opaque; a paragraph larger than 65536 bytes remains
opaque and is never silently cropped. Shards preserve source coordinates,
independent content identities and receipt hashes binding the original/revision/
representation and exact hierarchy/dependencies. Ancestor and transitive region
dependencies are visible. This operational accounting does not show that the
reading faithfully extracts the original, or that its meaning was understood.

The API accepts immutable reading bytes, a canonical binding record, optional
canonical hierarchy records and optional canonical dependency records. It handles
readings through 32MiB, 4096 paragraphs, 256 hierarchy regions, 512 dependencies
and 512 shards. These are additive analysis limits, not changes to legacy
transport capacities. Derived reading and original source identities remain
separate. Source, reading, proposition, context, test and unknown-meaning coverage
are reported separately. Initial potential claims are empty and processing stays
pending or opaque; this module does not invent a census of English propositions.

`sentinel_v1.graph.validate_graph(raw, artifacts, held_registry_sha256,
held_graph_sha256)` checks canonical `sentinel/meaning-graph/1` proposals against
a private snapshot of supplied byte windows. The source set retains package,
original source, source revision and representation identities separately from
window hashes and offsets. Each quoted interval is checked against those exact
supplied bytes. The returned source-set hash is SHA256 of the canonical source-set
list. Revisions and changed windows therefore invalidate connected held graph
identities. A source window is at most 65536 bytes; registry limits are 256
entries and 8MiB. Metadata is limited to 1MiB, graphs to 256 nodes/64 propositions
and 512 edges, and each node to 16 quoted intervals and 65536 total quoted bytes.

This pure check **does not prove that a supplied window came from its declared
package**. It reports `SUPPLIED_WINDOW_BYTES_ONLY` and `package_binding=UNPROVEN`.
The separately checked locator API must resolve and compare every window before
a receiving application claims package binding. Partial original windows cannot
be authenticated merely from the declared original SHA. Derived windows cannot
establish scanned transcription accuracy. No caller-provided `trusted` flag is
accepted, and no file, network address, model or native program is executed here.

The node categories preserve entities, references, events, propositions,
predicate arguments, modality, conditions, exceptions, quantifiers, time,
attribution, negation, uncertainty, revision, evidence, contradiction,
alternatives and opaque material. Origin labels distinguish source occurrence,
author assertion, attribution, agent inference, formal-model-relative proposals
and external evidence proposals. These are unadjudicated categories; an attributed
belief never automatically becomes a world fact. Quantities, units and English
modality remain quoted proposals unless an existing formal fragment is explicitly
checked. Graph text is bounded explanatory metadata, not a complete interpretation.

Each node carries fixed unproved assurance. Its documentary state is derived
from pinned, quote-checked `SUPPORT` and `REFUTATION` records: neither, support
only, refutation only, or both. These records are `DECLARED_UNADJUDICATED`; their
existence does not establish entailment. This four-state documentary annotation
is separate from the existing three-valued logic and from world truth. A caller
cannot set a green documentary label without the corresponding records.

Edge direction is explicit: predicate to argument; reference to proposed
referent; modifier to modified; condition/exception to qualified proposition;
quantifier to quantified node; earlier to later; proposition to attribution;
negation or uncertainty to qualified node; new revision to old; evidence to
proposed supported node; contradicting to contradicted; alternative to
alternative; dependent to prerequisite. Dependency, revision and temporal-order
subgraphs must be acyclic. Contradictory or cyclic reference proposals may remain
visible. No relation is automatically an execution authorization.

The [versioned schema catalog](../schemas/sentinel-meaning-graph-1.json) lists
every checked endpoint category. For example, `HAS_ARGUMENT` requires a predicate
or event followed by an argument, entity or reference; `EXCEPTION_TO` requires an
exception followed by a proposition, event or modality. `OPAQUE` is not a wildcard.
An incompatible edge refuses the graph. `SUPPORTS`, `CONTRADICTS`, `ALTERNATIVE_TO`
and `DEPENDS_ON` deliberately allow every node category as documentary proposals;
these links do not establish entailment. This endpoint check was added after an
independent test found an accepted entity-to-time argument edge. The failed input
and narrower earlier results remain in the evidence history.

`checked_formal_fragment` calls the unchanged `transport_semantics.checked_payload`
adapter for an explicit bounded old-format encoding plan, using the unchanged
dictionary builder and stored-payload checker on untransformed meaning. It does
not compact, invoke native correspondence, translate English or add truth functions. Component
proofs of the old codec do not prove these Python adapters or semantic fidelity.

The developmental controls in `tests/test_sentinel_meaning.py` exercise partition,
hierarchy, dependencies, opaque paragraphs, independent hashes, source windows,
quote mutation, caller mutation, registry closure, documentary records, assurance,
cycles and resource refusals in normal and optimized Python. They deny process
launch. Independent review and actual package-locator integration remain required.
Independent endpoint review now checks all relation categories and reruns the
dependent pure suites. Native source binding retains its separate source-bound
receipt and is not inferred from those tests. No full-book meaning, OCR accuracy,
human pilot, benefit or whole-mission acceptance
is established by this profile.
