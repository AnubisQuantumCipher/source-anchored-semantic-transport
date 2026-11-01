# Native proof and installed workflow closure

This checkpoint re-ran the applicable native proof projects and exercised the
current source through two separate local installations. It also exercised
original historical recipient/MCP tests on their original runtime and fixtures.
The product source, original fixtures, runtime bundles and historical receipts
were preserved. This is engineering evidence for the development round.

| Scope | Observed result |
| --- | --- |
| Core SPARK project | 813 checks; 0 justified; 0 unproved |
| Expanded evaluator SPARK project | 1120 checks; 0 justified; 0 unproved |
| Bound evaluator proof project | 214 checks; 0 justified; 0 unproved |
| Current installed regression | 118 tests, no skips |
| Current installed product/SDK compatibility | 9 tests, no skips |
| Bound native integration / receipt tests | 22 / 13 tests, no skips |
| Preparation / recipient retrieval / evidence finish | 13 / 13 / 14 tests, no skips |
| Original historical recipient / SDK tests | 54 / 10 tests, no skips |
| Separate same-host builds | Complete file bytes and modes match, including launcher |
| Portable exchange | Six frozen handoffs plus recorded refusal controls |
| Current producer to independent export reader | Source and metadata bytes match |

The three proof projects overlap. Their totals must not be added to imply a
larger independent proof. Their reports enumerate every analyzed unit, including
SPARK-Off entries with zero analyzed subprograms. The source inventory and exact
commands are part of [the derived receipt](receipt.json).

Proof covers the explicit contracts and verification conditions of the listed
SPARK units. Native IO/main programs, the C file boundary, Python orchestration,
the compiler, standard libraries and operating system remain outside that proof.
The bound parser's complete input-byte-to-tree correspondence is not proved.
Natural-language interpretation, semantic completeness, author authentication,
current authority and whole-system correctness are not established by these
proof results. The dependency and threat boundaries remain in the existing
[assurance contract](../../docs/ASSURANCE.md).

## Recheck the retained evidence

From the repository root, with Python 3.14 and no native toolchain required:

```sh
python3 -I -S -B -Werror examples/engineering-closure-v1/test_receipt.py
python3 -I -S -B -O -Werror examples/engineering-closure-v1/test_receipt.py
python3 -I -S -B -Werror examples/engineering-closure-v1/receipt.py --check
python3 -I -S -B -Werror install/prepare_source.py --check
```

These commands recheck recorded evidence and source identities. They do not
rerun GNATprove or reconstruct a historical execution. The checker checks every
individual command's result and captured stdout/stderr digest, exact proof
options and unit coverage, suite counts and skip status, current source pins,
paired installation inventories and retained timeout attempts. Negative controls
alter source, streams, proof coverage, proof status, suite status, skips and an
installation entry. All must refuse. A passing aggregate driver exit alone is
insufficient; the temporary driver that caught suite errors is preserved.
`contract.json` is reviewed local checking policy with literal expected report
rows. It is not an authenticated statement from a prover or an independent
semantic oracle. Hold the repository commit and receipt identity separately;
coherently replacing the checker, policy and evidence is outside this integrity
reference. The checker fixes the required projects and suites and refuses
missing source-inventory entries.

## Re-run the native proof

Use a fresh source copy and the trusted toolchain declared in
[tool-identities.json](evidence/tool-identities.json). Provisioning the toolchain
is separate. The observed host was Linux aarch64 with Python 3.14.7,
GNAT/GNATprove 16.1.0 and GPRbuild 26.0.0. The retained process receipts carry
exact executable paths, arguments, timing and captured stream hashes.

```sh
gnatprove -P transport.gpr -U --level=2 --report=all \
  --warnings=error --checks-as-errors=on --proof-warnings=on -j1
gnatprove -P evaluation/transport_eval.gpr -U --level=2 --report=all \
  --warnings=error --checks-as-errors=on --proof-warnings=on -j1
gnatprove -P evaluation/transport_bound_eval_proof.gpr -U --level=2 --report=all \
  --warnings=error --checks-as-errors=on --proof-warnings=on -j1
```

Allow the recorded proof-specific resource envelope before running these
commands. Initial and repeated 120-second runs timed out. Their original logs
remain in `evidence/core-proof*` and `evidence/evaluation-proof*`. The final runs
used a 600-second per-process wall/CPU allowance with unchanged proof settings.
Memory, per-file, stream and scratch limits are recorded in
[the correction admission](evidence/proof-resource-correction.json). Stream and
scratch checks are sampled refusal thresholds, not hard aggregate descendant
containment. The trusted toolchain must not escape its process group.

Partial prover caches remain pinned locally, with identities in
[partial-proof-state-pins.json](evidence/partial-proof-state-pins.json). They are
not required for this receipt check and are not included in this repository.
The original timeouts remain failed attempts; later success does not erase them.

## Re-run installed workflows

Follow [the existing installer](../../docs/INSTALL.md) twice in separate private
directories, once from this source and once from an independently copied,
verified `install/SOURCE.json` input set. Each build must independently compile
and pass the install check. Compare all files and directories, including their
modes and generated `bin/semantic-transport`, before testing exchange.

The retained [installer driver](evidence/install_current.py) and command receipts
show the observed invocations; its absolute paths describe that historical run.
They are data, not an automatically portable or privileged installation script.
Given matching private bundles, choose new output directories for each command:

```sh
python3 -I -S -B -Werror install/test_installed_regression.py \
  --bundle "$FIRST_BUNDLE" --evidence "$NEW_RESULTS/regression"
python3 -I -S -B -Werror install/test_handoff_prepare.py \
  --bundle "$FIRST_BUNDLE" --evidence "$NEW_RESULTS/prepare"
python3 -I -S -B -Werror install/test_handoff_reader.py \
  --bundle "$FIRST_BUNDLE" --evidence "$NEW_RESULTS/reader"
python3 -I -S -B -Werror install/test_evidence_finish.py \
  --bundle "$FIRST_BUNDLE" --evidence "$NEW_RESULTS/finish"
```

Product/SDK, portable exchange and bound-native commands also require their
declared historical fixture/bundle or compiled evaluator. See their exact
`current-product.json`, `current-portable.json`, `bound-native-integration.json`
and `bound-test-receipts.json` invocations in `evidence/`. An unavailable pinned
dependency leaves that reproduction unperformed; substituting a new runtime
does not reproduce the original test.

For independent standard-export recovery, follow
[the reader interface](../../docs/EXPORT_READER.md). The current-producer bridge
in [current_export.py](evidence/current_export.py) delivered only the standalone
reader and closed export to a fresh directory/process. This is a separately
implemented reader, not external-human reproduction or hostile filesystem
isolation. Its explanation was deliberately empty; no new model reconstruction
was measured in this bridge.

## Remaining acceptance

The [independent review](evidence/reviews/native-closure-review-20261029.json)
and [handoff supplement](evidence/reviews/native-handoff-closure-review-20261029.json)
record exact reviewed evidence and exclusions. These are configured GPT-6.1
engineering reviews, not authenticated provider attestations or external users.
The [inherited-lane mapping](evidence/reviews/native-handoff-closure-review-inventory-addendum-20261029.json)
retains unexecuted variants and earlier-tranche verification gaps. This
checkpoint does not claim all inherited engineering gates are closed.

Same-host reproducibility does not establish compatibility across independent
hosts, architectures or toolchain/library versions. The newly built bundle also
has a different launcher identity from the older qualified public-share wrapper;
that wrapper retains its explicit supported pin. No adapter was silently
retargeted. Desktop-client, native x86_64 and marketplace acceptance remain
unperformed.

Independent human users, authorized real tasks, the four-week pilot, external
reproduction and uncertainty-supported total-work benefit remain required.
No advantage over originals or product acceptance is claimed here.
