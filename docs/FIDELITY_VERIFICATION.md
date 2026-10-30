# Conditional comparison to a held reference

`tools/transport_document_fidelity.py` compares the complete ordered reading
units against explicitly supplied reference text. It makes no normalization,
spelling correction, numerical interpretation or paraphrase. A match is
conditional on the supplied reference. Its authenticity, faithfulness to the
source, OCR truth, context adequacy and whole-book semantic completeness remain
unproved. This tool cannot prove OCR accuracy or semantic completeness across
formats. Requests for those stronger claims explicitly refuse, including when
all supplied bytes match.

## Frozen interface and schema

Public package API:

```python
verify_package_reference(archive, share, reference_manifest, reference_text,
                         expected_manifest_sha, native=None,
                         requested_claim='EXACT_REFERENCE_TEXT')
```

For supported conditional requests, it enters the existing
`transport_document.validated` context first. Unsupported proof requests refuse
before package work. The full
paired archive, source and derived reading checks run under their unchanged
limits before the reference comparison. The reloaded complete `reading.json`
metadata is re-pinned against the validated package entry, and its source/text
hashes and text length are explicitly rebound to the validated package body. It does not accept an unvalidated
snippet in place of a package. An opaque package without a reading view refuses.

Pure comparison API, also used by independent synthetic controls:

```python
compare_reference(reading_text_path, reading_record, reference_manifest_path,
                  reference_text_path, expected_manifest_sha,
                  requested_claim='EXACT_ORDERED_READING_TEXT_TO_HELD_REFERENCE_ONLY')
```

The pure API validates the full existing `transport/reading-view/1` record.
When a reference is present it also checks the complete reading text; with no
reference it returns the missing-reference result without comparing text. It has
no independent source file to authenticate.
The public package API supplies the source-bound record established by the
existing codec. The two explicit request spellings above name the same narrow
comparison; neither permits a fallback from OCR or semantic proof requests.

The reference manifest has exactly these six fields:

```json
{
  "schema": "transport/document-reference/1",
  "source_sha256": "caller-declared complete source SHA256",
  "format": "pdf",
  "text_sha256": "complete held reference text SHA256",
  "text_bytes": 0,
  "segments": []
}
```

The SHA fields must be lowercase hexadecimal SHA256 values; the example strings
are descriptive placeholders. `format` must equal the validated reading record's
`pdf`, `epub`, `markdown` or `text` format. Every reference segment has exactly
`id`, `kind`, `source_locator`, `start` and `end`. Its ID, kind and exact locator
must equal the corresponding reading unit in the same order. The reference
start/end values form a complete contiguous half-open UTF-8 byte partition;
reference offsets may differ from reading offsets when unit lengths differ.
Both texts must contain strict UTF-8 with every unit boundary valid. Duplicate
IDs, gaps, overlap, omission, reordering, changed locators and unknown fields
refuse. Reference labels, implicit source dictionaries and trust booleans are
not accepted.

The caller must supply the expected SHA256 of the exact manifest bytes
independently. The tool never calculates that expected value from the manifest
under test. Supplying all three reference inputs as `None` returns
`REFERENCE_MISSING`. A partial combination refuses. Named reference files that are absent refuse
`REFERENCE_FILE_MISSING`; malformed existing evidence also refuses.

## Result and limits

Results are `CONDITIONAL_EXACT_REFERENCE_MATCH`, `MISMATCH` or
`REFERENCE_MISSING`. They retain the fixed claim
`EXACT_ORDERED_READING_TEXT_TO_HELD_REFERENCE_ONLY`,
`reference_authentication=UNAUTHENTICATED`,
`reference_fidelity=UNPROVEN`, `OCR_accuracy=UNPROVEN`,
`semantic_completeness=UNPROVEN`, `context_adequacy=UNPROVEN`, and
`execution_authority=NONE`. Unsupported proof requests raise
`UNSUPPORTED_CLAIM`; they never produce a match status.

Mismatch reports count all mismatching units and include at most 64 entries with
unit ID and first differing byte offset relative to that unit. No source or
reference prose samples are printed. No numeric meaning is inferred from a
changed digit. Exact equality of text is not a proof that an OCR system read the
original pixels correctly or that the complete meaning was captured.

Reading/reference text limits are each 32 MiB, metadata 8 MiB, and the ordered
unit limit 65536. The reference is streamed without copying it into scratch.
Existing source, frame, archive and native execution limits remain unchanged.
The CLI preserves stricter inherited resource limits, caps address space at
1 GiB, wall time at 450 seconds and serialized output at 1 MiB. The development
admission's 64 MiB scratch allocation is not a new product source limit. A real
package integration must budget the existing codec's recovered source and frame
scratch plus its reserve; conditional reference comparison adds bounded stream
buffers rather than a second reference copy.

CLI example:

```sh
python3 -I -S -B tools/transport_document_fidelity.py \
  --archive meaning.zip --share share.txt --native /declared/document_native_decode \
  --reference-manifest reference.json --reference-text reference.txt \
  --expected-manifest-sha CALLER_HELD_SHA256
```

Exit status is zero only for the conditional exact match, one for mismatch or
missing reference, and two for refusal. Regular-file, symlink, size, declared
hash and descriptor-change checks fail closed. Concurrent hostile host changes
are not attested. No proof of the Python comparator or whole system is claimed.
