# QUORUM historical replay and current source continuity

The version 1 receipt is a sealed historical observation, including exact pins
for the root README and the original workflow. Running its unchanged preparer
against a later README refuses with `Receipt differs from retained inputs`.
The refused docs integration job is run `41060701896`, job `124079404520`.
Neither that refusal nor any version 1 byte is replaced by this repair.

The workflow now uses two source views. The historical checkout is pinned to
`3e0d8602353e42a772927c8adaa32a73e7cc3b0a`. Its receipt and every declared
input were compared against the retained version 1 pins before selecting it.
The unchanged historical `prepare_receipt.py --check` runs in that view.
This verifies the sealed replay at its declared source epoch; it does not
relabel the complete current checkout as covered by historical observations.

The current checkout still runs the original `install/test_quorum_replay.py`
in normal and optimized Python, and the unchanged `install/check_source.py`.
The new checker additionally compares every version 1 receipt file against
both views. All code, runtime and retained evidence pins must remain exact.
Only two mismatches are admitted, with mandatory replacement checks:

- `README.md`: the exact dated development-status insertion is pinned, and
  removing only its declared byte range must reproduce the original README
  pin. Any change outside that insertion refuses.
- `.github/workflows/quorum-replay.yml`: the exact workflow transition is
  pinned, including both current test lanes, existing source checks, the
  pinned second checkout, unchanged historical receipt check, and normal
  and optimized continuity checks and negative controls.

The version 1 tree and this version 2 tree have closed file rosters; unknown
empty directories, symlinks and special entries also refuse. Unknown
QUORUM source filenames in `tools` or `install` also refuse. The manifest
explicitly names pre-existing sender, version 2 and other test files that
are separately versioned and outside the historical receipt. Their bytes,
unrelated project features, and other documentation are not retroactively
covered by the historical replay.

`manifest.json` is bound by a digest embedded in the checker. The manifest
pins the workflow, README transition, tests, this document and checker. The
checker pin normalizes only its single embedded manifest digest to zeros
to avoid a circular digest. This is source continuity under the reviewed
Git source identity, not authentication independent of that source or a
defense against replacing the checker and its entire trust context.

Each file read is limited to 1 MiB; aggregate reads to 32 MiB; tree and
source-directory work to 2,048 entries, using bounded directory iterators.
The controls use explicit refusals
and functions of at most 60 lines. They add no provider, network, native
or prover execution. The tests overlay one bounded input read at a time,
leaving all retained files untouched, and require the expected refusal.
They cover code, workflow, README body, old receipt, current and historical
archive bytes, new manifest, checker, and unknown archive/source entries.
An independent temporary-tree control checks unknown empty-directory refusal.
Both normal and optimized Python must pass.

From the current checkout, with a separate historical checkout or a verified
export of all version 1 declared inputs plus its receipt:

```sh
python3 -I -S -B -Werror examples/quorum-replay-continuity-v2/check_continuity.py --historical-root /path/to/historical
python3 -I -S -B -O -Werror examples/quorum-replay-continuity-v2/check_continuity.py --historical-root /path/to/historical
python3 -I -S -B -Werror examples/quorum-replay-continuity-v2/test_continuity.py --historical-root /path/to/historical
python3 -I -S -B -O -Werror examples/quorum-replay-continuity-v2/test_continuity.py --historical-root /path/to/historical
```

`CHECKED` means the stated byte-continuity checks passed; `TESTED` describes
executed controls. Formal proof, whole-system semantic completeness,
external validation and product acceptance retain their previous boundaries.
Hosted validation of this repair and independent review are separate gates.
