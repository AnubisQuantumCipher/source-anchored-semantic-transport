# Portable codec source distribution

`install/transport_source_distribution.py` exports the exact source inputs already
declared by `install/SOURCE.json`, a controller example, and readable instructions.
A recipient can check and extract these inputs without executing imported code.
It uses the existing installer; it does not introduce another codec or change
the identity required by existing meaning packages.

This distribution is deliberately scoped to the **codec installer source and
controller demo**. It is not a full project snapshot: evaluator extensions,
development tests and retained evidence remain in the repository. A meaning ZIP
is a different artifact, produced by the encoder and containing document data.

## Export and receive

Use the verifier from a trusted checkout at the intended commit. Hold the
expected source and archive digests separately from an untrusted download.
Replace the placeholder digests below with the intended identities. All output
paths must be absolute, new, and have an existing user-owned parent that is not
group/world writable.

```sh
python3 -I -S -B -Werror install/transport_source_distribution.py pack \
  --source-root /absolute/trusted/checkout \
  --expect-source '<SOURCE.json SHA-256>' \
  --archive /absolute/output/codec-source.zip \
  --receipt /absolute/output/source-export.json

python3 -I -S -B -Werror install/transport_source_distribution.py inspect \
  --archive /absolute/output/codec-source.zip \
  --expect-archive '<archive SHA-256>' \
  --expect-source '<SOURCE.json SHA-256>'

python3 -I -S -B -Werror install/transport_source_distribution.py unpack \
  --archive /absolute/output/codec-source.zip \
  --expect-archive '<archive SHA-256>' \
  --expect-source '<SOURCE.json SHA-256>' \
  --output /absolute/output/new-source
```

`pack` creates a ZIP and a receipt, then checks their exact bytes. `inspect` makes
no filesystem changes. `unpack` validates the entire archive before creating its
destination, writes private non-executable files, and compares every recovered
file with the validated payload. The source inventory is checked again after
extraction. A failed operation may leave earlier completed output files; keep
them for diagnosis and do not use a failed extraction. Existing targets are
never replaced. Multi-file publication is not claimed atomic.

After a source trust decision, follow `README-DISTRIBUTION.md` in the extracted
directory. It supplies the build, encode, validate, recover and `cmp` commands.
No toolchain is downloaded, no service is installed, and the archive verifier
does not run those instructions. A new build still derives its actual runtime
identity. Retain the exact runtime required by each existing meaning package;
this export does not provide cross-host binary reproducibility or migration.

## Format and limits

The `transport/source-distribution/1` manifest is canonical JSON with a sorted
inventory of member names, lengths and SHA-256 digests. It excludes itself,
identifies the original `SOURCE.json` digest, and declares its narrow scope.
The separately held archive digest binds the entire ZIP, including that manifest.
These checks establish integrity against those identities, not authorship or
permission to execute source code.

ZIP entries use a fixed order, timestamp, regular-file metadata and no
compression. Validation rebuilds the expected archive and compares every byte.
It refuses extra or missing members, duplicate names, symlinks, traversal,
compressed/encrypted entries, comments, trailing data, incompatible manifests,
changed source pins and noncanonical layouts. Only the fixed installer closure,
two named demo files and generated documentation are accepted.

| Resource | Bound |
|---|---:|
| ZIP bytes | 1048576 |
| Entries | 128 |
| Bytes per entry | 131072 |
| Expanded bytes | 4194304 |
| CLI address space soft limit | 268435456 bytes |
| CLI CPU soft limit | 20 seconds |
| CLI open descriptors soft limit | 64 |
| Free-space reserve | 10000000000 bytes |

Before writes, a preflight adds twice the rounded file allocation and directory
allocation allowance to the reserve. This is an observed allowance for outputs
and a complete comparison copy, not a filesystem reservation: concurrent writers
and filesystem metadata overhead cannot be excluded by a free-space reading.
OS write failures propagate; no successful receipt is emitted for a failed
readback. Direct Python APIs apply input bounds but do not establish process
limits; those limits belong to the CLI entry point.

## Reproduce the controls

```sh
python3 -I -S -B -Werror install/prepare_source.py --check
python3 -I -S -B -Werror install/test_source_distribution.py -v
python3 -I -S -B -Werror install/check_source.py
```

The tests exercise deterministic packing, exact source/demo recovery, manifest
scope, independent pins, hostile ZIP metadata, early API bounds, create-only
writes, private output parents and insufficient space. They run in CI alongside
the existing controls. This Python layer is tested, not formally proved. Native
source, proof obligations and prior failure evidence are unchanged. Export and
extraction do not establish a fresh native build, another architecture's runtime,
desktop-client acceptance or better agent behavior.
