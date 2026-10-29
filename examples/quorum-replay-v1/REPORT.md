# Full replay development report

The original-document and ZIP paths now execute the same complete QUORUM
checker. The ZIP-only public example passes with its Body and original-source
sidecars absent. The installed decoder, source inventory and actual imported
module bytes are checked before replay. The [recipient instructions](PREPARATION.md)
and [matched artifacts](recipient/) are included.

This is a tested development checkpoint. It does not establish product benefit
or external acceptance. The [derived receipt](receipt.json) binds current source
to retained complete observations; the [evidence inventory](evidence/inventory.json)
maps preserved files to their original locations and hashes. Historical absolute
paths in receipts describe the test host, not portable installation instructions.

## Results

| Scope | Result |
|---|---|
| Frozen replay cases, original and ZIP arms, normal and `-O` | PASS: complete stdout, stderr and exit status |
| Additional reviewer literals on both arms, normal and `-O` | PASS after the explicit empty-source oracle correction below |
| Missing files, changed identities, unsupported versions, malformed input, reference and graph failures, imported-result mismatch | PASS: required refusals retained |
| ZIP receiver with all evaluator source sidecars absent | PASS; original-document arm with required files absent refuses |
| Copied helper with valid normal and optimized stale bytecode caches | PASS: checked source executes, sentinel caches do not |
| Preloaded-module and module-count controls | PASS in instrumented pre-entry processes |
| Wrong-origin private audit control | PASS as a private helper projection only |
| Public preparer | PASS: positive preparation, nine refusals and one isolated ownership control |
| Public prepared invocation | PASS in normal and `-O`, independently reviewed |
| Portable core suite | PASS: 22 complete results with synthetic host observations |
| Fresh AI narrative or human study for this fixture | UNPERFORMED |
| Whole-system proof, semantic entailment and completeness | UNPROVEN |
| External validation and comparative continuation benefit | PENDING |

Local runtime observations used Python 3.14.7 on the existing Linux/Omarchy
installation. The CI workflow is configured to exercise the pure core on Python 3.14.10; it cannot
qualify the native installed decoder. Independent GPT-6.1 engineering review
included separate executions. It is not external human validation. The existing
Ada/SPARK implementation and its receipts were preserved without a native rebuild.

For paired replay results, only the top-level Request identity differs by input
arm. Removing that declared binding gives equal complete results. Both arms use
the same annotations and checker. This demonstrates finite parity, not superiority.

## Retained failures and repairs

- Source review found that the first loader could consume bytecode after hashing
  source. That source freeze was declared ineligible before product execution.
  The replacement compiles the checked bytes and passed the cache controls.
- The earlier transport adapter depended on source sidecars. Its successor
  recovers those bytes from the ZIP; separate absence controls passed.
- The handwritten empty-source expectation incorrectly said `MATCH`. The
  pre-existing contract required `EMPTY_SOURCE_MATCH_NONPROBATIVE`. Original
  failures and oracle remain; an independently reviewed revision changes only
  that expected field. The product was unchanged.
- A fixture constructor shared identity objects between cases. A deliberately
  damaged candidate contaminated later host expectations, causing ten transport
  mismatches in each interpreter mode. The constructor now owns its copies and
  verifies trusted roots remain unchanged. Corrected cases passed without
  changing the checker or expected semantic results. An incomplete review and
  a similar reviewer-tool mistake remain recorded.
- Host preparation discrepancies and public-preparer review findings were
  corrected before the affected executions. Original drafts are retained.

## Accounting

The complete share text measures **150 Unicode code points / 151 UTF-8 bytes**,
including the package identity and attachment reference. The ZIP is **23,700
bytes**; the separate readable lexicon is **2,911 bytes**. These are observed file
measurements, not a social platform's counting rules.

The fixture contains **228 original-source bytes** plus a **10,210-byte QUORUM
Body**. Shared dependencies are reported separately: the fixed checker roster is
**312,112 bytes** and the pinned decoder snapshot's files total **1,943,944 bytes**.
These sums have JACKAL status `exact` on measured lengths; the echoed `parsed=`
expressions and raw responses are retained in the accounting receipt. They are
not formal-bounded results or whole-installation cost totals: Python, native
libraries, matching decoder source, preparation and review work also matter.

The observed accepted result was 2,587 bytes in either arm. Host receipts were
6,411 bytes for originals and 6,675 bytes for transport. Raw subprocess timings
include interpreter startup and qualification and are retained per run; they
are not a controlled latency comparison. Model tokens, model cost, human effort
and amortized economic benefit were not measured in this deterministic run.
The larger archive and additional tool output are visible costs, not hidden
compression savings.
