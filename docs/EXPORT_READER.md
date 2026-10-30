# Read a standard export independently

`install/read_transport_export.py` is a standalone Python reader for
`transport/export/1`. It imports no producer, native decoder or transport module.
It checks an independently held digest of `export.json`, then checks every listed
file, its length, digest, source bindings and declared format versions. Sources,
metadata and explanation text remain separate selectable outputs.

Use an export made by the existing installed command:

```sh
semantic-transport render share.txt new-export \
  --archive meaning.zip --explanation explanation.json
```

Retain the producer's `export_sha256` separately. Deliver that identity through
the intended trusted channel. Computing a fresh expected digest from a received
directory does not detect substitution of that entire directory.

The reader is a single file with Python standard-library dependencies. No service
or package installation is required:

```sh
python3 -I -S -B install/read_transport_export.py inspect new-export \
  --expect-export-sha256 "$HELD_EXPORT_SHA256"
python3 -I -S -B install/read_transport_export.py recover new-export original.bin \
  --source SOURCE --expect-export-sha256 "$HELD_EXPORT_SHA256"
python3 -I -S -B install/read_transport_export.py explanation new-export explanation.txt \
  --expect-export-sha256 "$HELD_EXPORT_SHA256"
python3 -I -S -B install/read_transport_export.py metadata new-export metadata.json \
  --expect-export-sha256 "$HELD_EXPORT_SHA256"
```

Output paths must be new files. Every command validates the complete export before
returning anything. `inspect` returns a bounded checklist without raw source or
explanation bodies. Selected outputs preserve exact bytes without an added newline.
The API `read_export(directory, expected_export_sha256)` returns a dictionary with
ordered source records and bytes, `explanation_bytes`, `metadata_bytes`, parsed
unverified metadata, the manifest and explicit claim limits. Invalid input raises
`ExportReadError` with a stable `code`.

Consumers must require both a complete bounded JSON response and exit status
zero. Recoverable short stream writes are completed. If an output stream fails
after accepting a prefix, that prefix cannot be retracted; it is not an accepted
response. Selected-file cleanup is attempted on failure, and cleanup failure is
reported rather than silently treated as success.

The [versioned reader contract](../examples/independent-export-reader-v1/evidence/contract.md)
specifies the complete field, type and path rules. Bounds include aggregate export
bytes of 131072, aggregate source bytes of 65536, at most 16 sources, JSON nesting
of 12 and at most 19 regular files. Unknown versions, missing or extra files,
symlinks, hardlinks, special files, duplicate JSON keys and mismatched bindings
are errors. All input and output path components are checked without following
symlinks. There is no network fetch or supplied-code execution.

`VERIFIED_AGAINST_PINNED_EXPORT` means the loaded bytes match that held export
identity. It does not prove their author, truth, freshness, semantic completeness,
or the recorded native producer execution. Source-bearing metadata remains
unverified data. Explanation text has no execution authority. The recorded raw
explanation-envelope digest is retained as a declaration: its original JSON
serialization is not reconstructed. A separate original-byte comparison is
required when qualifying original recovery.

This is an independently written reader based on the frozen export contract,
not an external organization or human validation. Python, the operating system
and hash collision resistance remain assumptions. Hash checks do not isolate
hostile concurrent mutation by the same user. Linux/aarch64 is the local exercised
platform; other clients and installations require their own acceptance evidence.

Reproduction instructions and retained first results are in the
[independent reader example](../examples/independent-export-reader-v1/README.md).
