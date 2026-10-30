# Explicit historical QUORUM receipt replay

The document feature changed `install/check_source.py` to retain the legacy
128-file analysis budget while adding an explicit nine-module document profile.
The old checker is outside `install/SOURCE.json`, but it is pinned by seven
retained QUORUM component receipts. Treating it as universally unsealed was
incorrect. Commit `26a6c5b0057c8dd22d466fd3e45427920d77b377` consequently made the
old current-tree receipt commands refuse. The failed command remains a valid
failure; no old receipt or preparer is rewritten here.

`replay_historical.py --component NAME` reconstructs the exact receipt-listed
input tree for graph, input, source, claim, impact, context or reading. Each
retained receipt and its unchanged preparer are pinned by `historical-inputs/manifest.json`.
Only two source paths receive historical bytes: `install/check_source.py` and
`.github/workflows/source.yml`. Their snapshots and hashes were derived with
`git show` from commit `ad2befaf7e89e73790bd5ab462158225f4b864b2`.
Every other receipt-listed input must still match its current repository bytes.
The unchanged preparer then runs its original `--check` in the temporary tree.
The historical checker is an input to receipt derivation; it is not executed
against the expanded current source tree.

This checks historical receipt continuity and current non-alias component bytes.
It does not claim that the historical checker or workflow equals current CI.
Current component oracle tests remain in `source.yml`, and the current static
checker runs separately with its unchanged legacy-128/document-9 bounds.
`dependency_inventory.json` enumerates explicit historical checker pins found
in retained example evidence, including archived intermediate receipt epochs.
Those archived epochs retain their original scope and are not rewritten.

Resource limits are explicit: at most 511 receipt-listed inputs plus the retained
receipt, one MiB per input, 16 MiB aggregate staged payload, sequential temporary
trees, and 30 seconds per unchanged pure receipt derivation. The actual largest
selected input is 345456 bytes; the largest profile stages 504 payload files.
Paths, duplicate rows, symlinks, input size, snapshots, retained receipts,
unchanged preparers and current component hashes are checked before execution.
The code trusts this repository, the fixed pinned preparers and the host Python;
it is not a hostile-code sandbox or a whole-system proof.

Pure boundary controls:

```sh
python3 -I -S -B -Werror examples/document-profile-v1/test_replay_historical.py
python3 -I -S -B -O -Werror examples/document-profile-v1/test_replay_historical.py
python3 -I -S -B -Werror tests/check_document_profile.py
python3 -I -S -B -Werror install/check_source.py
```

These controls reject missing and tampered snapshots, changed current components,
changed retained receipts, unsafe paths, oversized files, unknown profiles and
symlinks. They do not rerun model, native or product campaigns.

The 16 MiB budget covers staged payload bytes. Directory metadata is separately
bounded by 512 payload paths with at most 32 components each, and the two
subprocess log files each have a 64 KiB limit. The payload budget does not claim
that total allocated temporary-filesystem blocks are at most 16 MiB. Local
qualification uses an assigned `TMPDIR` below `/dev/shm`; CI uses its runner
temporary directory. No `HOME` override is required for the isolated derivation.
