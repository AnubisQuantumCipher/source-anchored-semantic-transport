# Native source workflow

**Status: TESTED public development mechanics.** Receiver benefit, semantic adequacy, formal integration proof, and strongest-baseline qualification remain open.

The frozen inputs are [contract.json](contract.json) (`4f341b46d3c7…`), [oracle.json](oracle.json) (`780c03a429ef…`), and [contract-io-addendum.json](contract-io-addendum.json) (`f932f753d115…`). The oracle fixes bytes, index, citations and failure controls before execution.

## Prepare and verify

Use the adapter-compatible **old handoff manifest** for the original or actual qualified decoder arm. Both preserve identical source bytes/annotations through the existing adapter/core and separate candidate checker. No new codec or retrieval engine is introduced.

Replace uppercase placeholders with held values. Use canonical absolute paths and private output/receipt parents outside protected project/input/content/bundle roots. Workspace and receipt must be new and nonoverlapping.

```sh
python3 -I -S -B -Werror comparison/workflow/native_workspace.py prepare \
  --manifest /ABS/inputs/ARM-manifest.json \
  --expect-manifest-sha256 HELD_HANDOFF_SHA256 \
  --annotations /ABS/inputs/annotations.json \
  --expect-annotations-sha256 HELD_ANNOTATIONS_SHA256 \
  --expect-core-sha256 HELD_CORE_SHA256 \
  --workspace /ABS/outputs/source-workspace \
  --receipt /ABS/receipts/prepare.json

python3 -I -S -B -Werror comparison/workflow/native_workspace.py verify \
  --workspace /ABS/outputs/source-workspace \
  --expect-workspace-manifest-sha256 HELD_WORKSPACE_MANIFEST_SHA256
```

Keep `workspace_manifest.sha256` from the complete matching external receipt outside the workspace; pass that retained digest to verification. `workspace.json` inventories every other file. Verification checks the complete tree, identities, views, bounds, modes, and unsafe/extra paths. It needs fixed local code, without original input paths or the native decoder bundle.

The Python API is `prepare_workspace(manifest, held_manifest_sha256, annotations, held_annotations_sha256, held_core_sha256, workspace, receipt)` and `verify_workspace(workspace, held_workspace_manifest_sha256)`. Use a fresh process per API invocation. Results are canonical JSON bytes without LF; preparation writes identical bytes create-only to the external receipt. CLI success adds one LF and exits zero.

## Complete output tree

```text
source-workspace/
  sources/ID.bin     exact original UTF-8 or opaque bytes
  annotations.json  exact pinned annotation bytes
  catalog.json      complete core catalog response, including LF
  index.txt         ASCII source/unit/reference tables, final LF
  versions.json     canonical declared metadata, no LF
  workspace.json    canonical complete inventory, no LF
```

Files are `0400`; directories are `0500`. These modes and pins do not isolate hostile same-UID processes. Bounds remain 16 sources/65,536 aggregate source bytes, 16 units/64 edges, and 65,536 annotation bytes. The 32-file/1 MiB workspace cap covers metadata overhead.

Labels remain untrusted: authority `NONE`, freshness `UNKNOWN`, context adequacy `UNPROVEN`, governing version `UNKNOWN`. Whole-unit boundaries are declared. Unknown/conflicting labels, conditions, exceptions, uncertainty, and missing/cyclic references remain data. Existing dependency refusals still apply; full files establish no complete procedure or permission.

## Native reading

After verification, use ordinary tools; these example IDs belong to the public fixture:

```sh
native_root=/ABS/outputs/source-workspace
cat "$native_root/index.txt"
rg -n -- '100 ms|MAINTENANCE' "$native_root/sources/S_CTRL_NEW.bin"
cat "$native_root/sources/S_CTRL_NEW.bin"
diff -u -- "$native_root/sources/S_DEF_OLD.bin" "$native_root/sources/S_DEF_NEW.bin"
```

Read complete required context. Citations identify source, declared revision, source SHA-256, and zero-based byte span `[begin,end)`. Opaque bytes receive no inferred text extraction.

Originals may remain in place without mandatory copy/import cost; this workspace is one eligible affordance. Both arms may use native tools, common annotations/index, and the checker. Other eligible baseline search workflows remain allowed. Native reads have no overall 32-operation quota; the optional client keeps its separate durable 32-call budget. Charge copy/index/cold setup and warm verification separately.

## Failure handling

Prepare success requires complete canonical stdout plus LF, zero exit, and matching receipt bytes. Never accept partial stdout. After emission starts, no second stdout record is appended; sink failure gives bounded stderr diagnostics where possible and nonzero exit. Preserve captured bytes.

Refusals report `workspace_may_exist`/`stage_may_exist`. Publication or receipt failures can leave a tree; outside-API failures after possible execution conservatively report possible existence. Inspect retained state before recovery. Verification never publishes, repairs, or removes an existing tree. No automatic retry, overwrite, or blind rollback.

## Reproduce and assess the evidence

From the repository root, choose a new child of a private temporary directory:

```sh
python3 -I -S -B -Werror comparison/workflow/test_workflow.py \
  --root /ABS/new-portable-run --mode portable \
  --expect-product-sha256 4679aae738dd3efb9c4840e677ec6e55e8a423dd7c8522a0addf6612a6bbfbc1
```

For optimized execution, add interpreter `-O` and harness `--optimized`, using another new output directory. Portable tests author their original-only input manifests from held literals. Local `--mode local` additionally requires the exact qualified native decoder and retained adapter fixtures declared in the oracle; it is not a portable native-decoder installation test.

Run substantive native search/read/diff controls against a completed run using independently retained SHA-256 values for its `T-preparation.json` and `receipt.json`:

```sh
python3 -I -S -B -Werror comparison/workflow/test_native_tools.py \
  --campaign-root /ABS/completed-run \
  --expect-campaign-sha256 HELD_PREPARATION_SHA256 \
  --expect-campaign-receipt-sha256 HELD_RUN_RECEIPT_SHA256 \
  --root /ABS/new-native-tool-run
```

Recorded results: portable normal and optimized runs passed; the local original/actual-decoder run passed for all three cases. The additional local boundary suite passed 22 process calls, including isolated hardlink/aggregate/directory checks, inherited caps, blocked decoder selection, and real postrename failures. Native tool controls passed both local arms and portable original. Their optimized runtime was not performed. `test_boundaries.py --root NEW_PRIVATE_CHILD` needs the retained local transport fixture even though its unapproved decoder is never invoked.

The main fixture contains 2,269 original source bytes. Its verified workspace costs 28,357 bytes for the original arm and 28,358 for transport; these include all source copies and metadata. Recorded transport carrier bytes are 21,664. These small examples add overhead. Per-phase timings, complete raw tool streams, source pins and retained first failures are in the observation evidence. Host cache state is uncontrolled. Model tokens, active human work, receiver behavior and comparative benefit were not measured here.

Check the recorded-byte receipt separately from fresh behavior:

```sh
python3 -I -S -B -Werror comparison/workflow/prepare_receipt.py --check
```

Reader controls use another new private output directory:

```sh
python3 -I -S -B -Werror comparison/workflow/test_evidence.py \
  --root /ABS/new-reader-controls --expect-reader-sha256 HELD_READER_SHA256
```

The normal and optimized controls passed nine archive cases, one missing-process-stream case and a fresh malformed-DEFLATE CLI refusal each. Add interpreter `-O` and harness `--optimized` for the second mode. The held reader digest is recorded in `receipt.json` and the CI workflow.

The evidence archive retains frozen code/inputs, process streams, receipts and review records. Reproducible materialized test input/output trees are excluded; the archive is never extracted or executed by its checker. Existing Ada/SPARK source and proof receipts remain unchanged. No new formal proof or fresh receiving-agent acceptance is claimed by these tests.

`evidence-first` retains the initial collection and its reader failure: an existing-file test sentinel had a `.json` name but was raw data. The corrected reader distinguishes record namespaces from opaque test data and requires every scheduled native record and both streams.
