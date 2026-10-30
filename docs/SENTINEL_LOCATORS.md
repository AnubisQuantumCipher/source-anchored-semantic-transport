# Versioned package-bound evidence locators

`sentinel_v1.locators.resolve_locator` is a narrow byte-evidence adapter. It calls
existing document package validation; it does not decide interpretation,
qualification, truth, OCR accuracy or context sufficiency. Existing transport
formats, share/CRED behavior, raw `read_section` and recovery APIs are unchanged.
No full-share/CRED checker from the rejected draft is implemented.

The explicit API is:

```python
resolve_locator(archive, share, locator_raw, expected_locator_sha256,
                locator_registry, expected_locator_registry_sha256,
                revision_registry, expected_revision_registry_sha256,
                native=None)
```

The three expected SHA256s must be independently held by the caller. Registry
roots are hashes of canonical `{artifact_sha: {"sha256": artifact_sha,
"bytes": actual_length}}` maps. Registries contain actual immutable bytes and
are captured privately before hashing/resolution. Locator registry is at most64
records of32768bytes; revision registry at most8 records of4096bytes, combined
at most8MiB. A complete closure is required: no missing, cyclic, extra unreachable
artifact or silently omitted unsupported dependency.

Exact records and selector fields are frozen in the owner-reviewed locator
contract under the session evidence packet. Locator schema is
`sentinel/evidence-locator/1`: source identity includes original SHA/length and
package ID; representation is ORIGINAL or DERIVED_UTF8 with separate SHA/length
and reading-record pin; revision identifies actual canonical revision bytes,
not a latestness label. Revision schema is `sentinel/source-revision/1` and
preserves a bounded predecessor chain. Every dependency must have identical
source, representation and current revision. Historical predecessor bytes may
identify earlier sources but cannot be merged as current evidence.

SOURCE_BYTES, CODE_BYTES, DERIVED_UTF8, PAGE_TEXT and SECTION can resolve exact
nonempty byte spans. CODE_BYTES is not an AST or permission to execute. PAGE_TEXT
binds a declared reading segment/page number and retains a visual-fidelity
caveat; it does not verify the scanned page. PAGE_REGION, TABLE and FIGURE have
closed bounded shapes but return UNSUPPORTED: digest presence cannot invent
geometry or object mappings. Invalid shapes or mismatched evidence raise
`SentinelError(ValueError)`.

Supported dependency closure returns source-ordered parts with explicit half-open
byte spans, exact data and SHA256s, gaps and `coordinate_kind` SOURCE_BYTE or
DERIVED_UTF8_BYTE. It never merges different representations or revisions.
Overlap/adjacency may merge within that one space; disjoint gaps stay visible.
Final returned bytes must match every held quote hash. Derived slices must have
valid UTF8 boundaries. Selection is capped at64 distinct intervals/parts and
65536 aggregate bytes; overflow refuses without cropping.

A result remains `qualification=NOT_QUALIFIED`, `execution_authority=NONE`, with
interpretation/OCR accuracy/semantic completeness/context adequacy UNPROVEN.
UNSUPPORTED gives zero parts for the entire required intake. Package validation
and trusted runtime/host assumptions are inherited; descriptor-change checks do
not attest a hostile host. Unit controls mock package validation and prohibit
native/Popen dispatch. Actual package/native integration requires its own
admission and receipt, and is not established by those mocked tests.

## Closed record forms

A locator has exactly these fields; each SHA is a complete lowercase hexadecimal
SHA256, each byte count an exact integer (booleans are refused):

```text
{
  "schema": "sentinel/evidence-locator/1",
  "id": <bounded label>,
  "source": {"sha256": <original>, "bytes": <length>, "package_id": <checked package>},
  "representation": {
    "kind": "ORIGINAL" | "DERIVED_UTF8", "sha256": <representation>,
    "bytes": <length>, "record_sha256": null | <complete reading.json entry hash>
  },
  "selector": <one closed selector below>,
  "dependencies": [<exact locator artifact hashes>],
  "revision": {"id": <label>, "artifact_sha256": <revision record hash>,
               "previous_sha256": null | <predecessor record hash>}
}
```

An original representation must equal the source SHA/length and have null
record hash. A derived representation must equal the verified reading view and
its separately pinned complete reading record. No fallback source is selected.
Revision artifacts have exactly `schema="sentinel/source-revision/1"`, `id`,
`source_sha256`, `source_bytes`, and `previous_sha256`. Hash the complete
canonical record externally; no record embeds its own hash. The selected
revision must match the locator source; the bounded predecessor chain is
retained without asserting that the selected revision is latest or authentic.

| Selector kind | Additional exact fields | Behavior |
| --- | --- | --- |
| SOURCE_BYTES | start, end, quote_sha256 | Original raw bytes |
| CODE_BYTES | start, end, quote_sha256, language | Original bytes; language is an annotation |
| DERIVED_UTF8 | start, end, quote_sha256 | Reading bytes with valid UTF8 boundaries |
| PAGE_TEXT | segment_id, page, start, end, quote_sha256 | Declared page segment, same reading byte space |
| SECTION | section_id | Original section plus checked declared dependency closure |
| PAGE_REGION | page, coordinate_system, box, mapping_sha256 | UNSUPPORTED |
| TABLE / FIGURE | object_id, mapping_sha256 | UNSUPPORTED |

Every selector also contains `kind`. Spatial coordinate systems are the closed
names PIXELS_TOP_LEFT and POINTS_TOP_LEFT; a box is four nonnegative bounded
integers with strictly increasing axes. A valid declared mapping hash still
does not enable unsupported spatial retrieval. Unknown fields/tags, missing
artifacts, wrong pins, cycles or mixed coordinate/revision dependencies refuse.

Every quotation is a nonempty half-open byte interval and must match its held
hash in the final returned parts. An unsupported required dependency prevents
usable partial success. Gaps cover only intervals between returned parts;
they do not claim that omitted text elsewhere is irrelevant. Results are
in-memory dictionaries containing immutable part bytes; canonical JSON output
requires an explicitly designed binary representation rather than silently
serializing or dropping those bytes.
