# Reviewing source pages and interpretation gaps

A package preserves a particular source and particular declared readings. A recipient must still establish which record it intends to rely on and how much of that record its question requires. A document's instructions, a historical approval, and a recipient's present permission to act remain distinct.

## Inspect the bytes with their declared readings

The existing read-only MCP tool `transport_source_page` accepts a declared source ID and a byte offset. Its exact bytes, source and page digests, offsets, and normative base64 remain available. A page may split a UTF-8 character; in that case its text convenience field is null while the byte representation remains exact.

Each page now also carries a `review` object with schema `transport/source-page-review/1`. It associates that page with the typed readings declared for its source:

- Unit and interpretation identifiers, declared kind, interpretation status and representation status.
- Residual intervals and opaque-proposition spans intersecting the returned bytes, retaining the original intervals and separate page intersections.
- Per-reading grammar ambiguity indexes and source spans, including ambiguities outside the page whose notes remain available through the existing inspection tools.
- Declared dependency and uncertainty identifiers so the recipient can follow the existing `transport_focus` and `transport_inspect` interfaces for context.
- Explicit context and authority limits. An absent typed reading is distinguishable from a reading with no residual intersecting the page.

Residual intervals identify bytes outside one unit's declared spans, cues and mentions. They are not a score for semantic completeness. Different readings of the same source can have different residuals. A broad cue can cover all the bytes while its interpretation remains unproved. An opaque proposition retains its text without claiming to express that text's internal logic.

Do not treat an empty uncertainty list as evidence of certainty. It describes supplied records. Relevant uncertainty may be anchored in another part of the document or another declared source; dependency references must remain visible even when their text falls outside this page.

Use `transport_focus` for the selected unit's declared context and exact supporting excerpts. Use further source pages when those excerpts do not answer the question. The current tool does not decide whether an interpretation is legally, scientifically or operationally correct, and it does not decide whether a recipient has read enough.

## Bounds and errors

The existing source, page, archive, request-count and serialized-response bounds remain in force. Large annotation responses are refused explicitly rather than silently dropping readings or uncertainty. This feature does not increase the document envelope or add network retrieval. Arbitrary media can remain opaque bytes; text annotations do not establish media understanding.

The installed-product test command in [Assurance](ASSURANCE.md) exercises this response through the actual local MCP stdio adapter. It is separate from a desktop-client qualification or an AI narrative trial.

## Governing records and legal material

The implementation can carry legal material within its supported bounds, but it supplies no legal interpretation, signature verification, jurisdiction determination or current-authority decision. A pinned package identity specifies the bytes selected by its recipient. It does not establish that this is the governing version or that its accompanying interpretation is accepted by the relevant parties.

Authentication and revision controls need their own evidence and trust policy. [NIST's Digital Signature Standard](https://csrc.nist.gov/pubs/fips/186-5/final) addresses signature integrity and signatory authentication; it does not turn a signed reading into a complete or correct interpretation. [W3C PROV-DM](https://www.w3.org/TR/prov-dm/) supplies concepts for attribution, derivation, revision and invalidation that can inform a future interoperable provenance layer. This release does not claim to implement that standard or an authority registry.

As an informative records-management example, [NARA Bulletin 2015-03](https://www.archives.gov/records-mgmt/bulletins/2015/2015-03.html) distinguishes a record from authentication records supporting it. That guidance addresses US federal agencies; it is not a general legal rule for every use of this software.

An agent may report what the pinned source says, where a reading came from, and which gaps it encountered. It must not present a transported `must`, a provenance claim, or a past approval as a fresh grant of execution authority. The decoder continues to report that boundary explicitly.
