# SENTINEL portable exact-evidence container, contract 1

Frozen before container implementation. This is a separate container over
sentinel/sidecar-exact/1, not a change to transport, grammar 3, QUORUM, STS1 or CRED.
No native qualification or natural-language verdict may be inferred here.

The container is a deterministic, uncompressed ZIP with only regular files,
no comments, extras, encryption, ZIP64, symlinks, directories or duplicate paths.
Maximum archive bytes: 9437184. Maximum entries: 260. Maximum declared entry bytes:
65536. Maximum artifact aggregate bytes: 8388608. Artifact count: 1..256.
Entries are manifest.json, sidecar.json, registry.json, README.txt and
artifacts/ID.bin for the complete, strictly validated artifact registry.
Entry timestamps are 1980-01-01T00:00:00 and mode is regular 0600. Manifest/file
lists and registry lists are lexical by path/ID; neither aliases nor extra entries
are allowed. Archive parsing is bounded; nothing is extracted or executed.

The canonical manifest has exactly schema, sidecar_sha256, registry_sha256,
previous_sidecar_sha256, files, authentication, semantic_completeness,
qualification and execution_authority. Schema sentinel/evidence-zip/1. Files is
the complete list of nonmanifest records, each exactly path, bytes and sha256.
Its SHA-256 is the package identity; the manifest does not contain its own hash.
Share text is exactly two ASCII records plus trailing LF:
SENTINEL1:<64 lowercase hex identity>\nPKG:<reference>\n
Reference is a caller-provided printable ASCII string 1..256 bytes, with no
whitespace. It is a hint, never fetched. No local reference is called a public
link. A configured share budget counts Unicode code points, equivalent to bytes
for this ASCII profile; complete text including LF and PKG must fit or refuse.
Do not apply this convention to other clients or profiles.

Export validates the raw canonical sidecar and complete registry against two
caller-held SHA-256 values before creating an output directory. For an extension,
it requires an externally supplied previous_sidecar_sha256, resolves the previous
raw sidecar from its exact artifact Pin and passes both to the existing checker.
Genesis requires no previous pin. A digest is not authentication. Status values
remain NOT_QUALIFIED, UNPROVEN, UNAUTHENTICATED, NONE.

One encode workflow creates a NEW private directory and both share.txt and
evidence.zip plus a report. Existing directories/outputs refuse; no overwrite or
cleanup of prior artifacts. Failure may leave a clearly incomplete directory;
no success receipt until all create-only writes and final readback pass.

Import requires a caller-held share and supplied ZIP. It checks ZIP bounds and
exact entry metadata, matches manifest hash, validates all sizes/digests and exact
entry set, then invokes the existing sidecar validator with held sidecar/registry
pins from that matched manifest. Historical continuation additionally requires
the recipient's independently held previous-sidecar digest; an embedded history
pin alone cannot establish continuation. No instructions or dependencies are
executed. Inspect returns diagnostics; staging export returns the existing
NOT_QUALIFIED manifest, never a native verdict.

Required literal controls before admission: deterministic bytes for identical
inputs; matched export/import; exact artifact recovery; every missing entry;
extra/duplicate/traversal/absolute/backslash path; directory/symlink/device;
compression/encryption/extra/comment/noncanonical metadata; truncated ZIP;
wrong share/manifest/registry/sidecar/entry digest; unsupported schema; budget
boundary and one less; wrong or missing historical trust root; existing output;
no process/network execution; invalid semantic claims remain refused; all valid
results remain NOT_QUALIFIED and NONE. Tests must not treat a mocked validator
as evidence that the real graph was checked.

The original source in each evidence artifact is at most 65536 bytes here.
Whole books remain in the existing separate document ZIP and may be addressed
by its declared identity; this container is not a new whole-book parser.
Binary source bytes, code and model statements remain inert data. No scientific
truth, author identity, OCR accuracy, semantic completeness or action authority
is established by this container.
