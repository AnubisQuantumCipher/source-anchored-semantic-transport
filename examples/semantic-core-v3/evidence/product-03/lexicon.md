# Source-Anchored Semantic Transport lexicon.md

All metadata below are unverified declarations.
Original bytes are retained. Binary media are retained, not understood.
Anchors prove references to selected bytes only; they do not prove a reading.

<pre>
SOURCES
id: SOURCE
label: Original source
media_type: application/octet-stream
provenance: Caller supplied bytes; no authentication or authority.

id: CORE
label: Grammar 3 formula and keys
media_type: application/octet-stream
provenance: Caller supplied bytes; no authentication or authority.

id: MODEL
label: Supplied finite structure, not world truth
media_type: application/octet-stream
provenance: Caller supplied bytes; no authentication or authority.

INTERPRETATIONS
anchors: [{"sha256":"74db7b14176c0f5c266b42d34711518ad8afade12c2e638501bbe9d1d8639547","source":"CORE","span":[0,4955]}]
id: FORMAL_READING
label: Closed formula
provenance: Declared formalization; model-relative evaluation is a separate procedure.
status: proposed
text: n0=EVENT(); n1=ACTION(ACTOR); n2=EXCEPTION(); n3=not(n2); n4=and(n0,n3); n5=if(n4,n1); n6=must(n5)
{"and_table":[["UNRESOLVED","KNOWN_FALSE","UNRESOLVED"],["KNOWN_FALSE","KNOWN_FALSE","KNOWN_FALSE"],["UNRESOLVED","KNOWN_FALSE","KNOWN_TRUE"]],"entries":{"all":"Unary predicate and explicit finite domain to Fact: False if any False, True if all True, otherwise Unresolved. Empty domain True.","and":"Fact x Fact to Fact: False if either False; True if both True; otherwise Unresolved.","if":"Fact x Fact to Fact: strong Kleene material implication; False only for True then False.","must":"Fact to Norm: True maps Satisfied, False Violated, Unresolved Unknown. Norm Truth always Unresolved; no authority.","not":"Fact to Fact: strong Kleene negation; Unresolved remains Unresolved.","pred":"Fact: exact ordered tuple lookup. Missing, conflicting, or explicitly unresolved reports yield Unresolved.","some":"Unary predicate and explicit finite domain to Fact: True if any True, False if all False, otherwise Unresolved. Empty domain False."},"execution_authority":"NONE","fact_outcome":"UNKNOWN","if_table":[["UNRESOLVED","UNRESOLVED","KNOWN_TRUE"],["KNOWN_TRUE","KNOWN_TRUE","KNOWN_TRUE"],["UNRESOLVED","KNOWN_FALSE","KNOWN_TRUE"]],"interpretation":"SUPPLIED_MODEL_ONLY_NOT_WORLD_TRUTH","must_table":["UNKNOWN","VIOLATED","SATISFIED"],"norm_truth":"UNRESOLVED","not_table":["UNRESOLVED","KNOWN_TRUE","KNOWN_FALSE"],"schema":"transport/core-operators/3","signatures":{"all":"UnaryPredicate,FiniteDomain -&gt; Fact","and":"Fact,Fact -&gt; Fact","if":"Fact,Fact -&gt; Fact","must":"Fact -&gt; Norm","not":"Fact -&gt; Fact","pred":"Predicate(Term*) -&gt; Fact; exact declared arity 0..2","some":"UnaryPredicate,FiniteDomain -&gt; Fact"},"truth_order":["UNRESOLVED","KNOWN_FALSE","KNOWN_TRUE"]}

UNCERTAINTIES
RELATIONS
</pre>

Interpretation supplied: YES
Coverage is a byte-reference report; no semantic completeness is claimed.

## Fixed definitions

- Σ: Documentary source group only; not an arithmetic sum, universal quantifier or completeness claim.
- I: Ordered declared interpretation IDs and statuses; none means no interpretation was supplied.
- U: Ordered uncertainty IDs; none means no uncertainty record was supplied, not absence of uncertainty.
- R: Ordered declared relations, written first kind second; no causality, execution or authority is implied.
- anchor: Half-open offsets [begin,end) in exact original bytes with SHA-256 of the selected bytes; a reference only, not entailment.
- M: Typed meaning units with indexed operator trees, fixed dictionary identities and declared context dependencies; interpretation and adequacy remain unproved.
- supports: Declared support from the first record to the second; no entailment or truth is verified.
- contradicts: Declared conflict between the first record and the second; no inconsistency is proved.
- qualifies: The first record declares a qualification on the second; no scope or adequacy is verified.
- derived_from: The first record is declared derived from the second; no derivation is checked.
- supersedes: The first record is declared to replace the second in this reading; no authority is granted.

## Decoder and boundary

Use the separately supplied Transport decoder and matching runtime; never execute archive content.
This ZIP has exactly manifest.json, codec.json, index.json, formula.txt, README.md.
README.md is this lexicon.md document; the separately returned lexicon bytes are identical.
STS1 binds bytes and declarations, not author identity, truth, confidentiality or authority.
No reference is fetched. Missing or incompatible external dependencies refuse before reconstruction.
External trusted runtime; hash-then-use does not isolate hostile concurrent same-user mutation.
