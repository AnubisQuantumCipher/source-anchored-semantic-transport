# Acceptance scope and reproduction

This checkpoint publishes source and bounded local workflows. It does not declare the whole product complete or ready for a marketplace. Read the machine-readable [checkpoint receipt](../receipts/checkpoint-1.json) alongside the commands below.

## Original checkpoint controls

| Scope | Result |
|---|---|
| Installer mechanics | 21 deterministic tests passed, with a retained process-group escape counterexample outside the declared trusted-toolchain scope. |
| Source closure and exact transformations | 13 controls passed, including changed identity, duplicate pins, malformed metadata and unsafe launcher paths. |
| Existing codec, semantic, authoring and export suites on a rebuilt runtime | 110 unchanged tests passed. |
| Installed command and MCP product controls | 8 tests passed, including matching encoding outputs, exact recovery, selected-unit expansion, export verification, tamper refusal, and old/new runtime incompatibility after a positive old-runtime baseline. |
| Native build | Strict project flags retained; expected ELF interpreter/libraries checked; embedded RPATH/RUNPATH absent. |
| Independent code review | Two installer findings repaired: loader alias binding and launcher site-startup boundary. |
| Whole-system semantics, model behavior and compiler correctness | UNPROVEN. No new receiving-model trial or formal proof campaign was run for this install checkpoint. |
| Desktop clients, x86_64 runtime and marketplace | UNPERFORMED. Local SDK stdio is not desktop-client acceptance. |

Counts describe separate scopes and must not be merged into a whole-system proof. Ordinary source hashing is an integrity observation. The receipt identifies the exact source inventory and local artifacts involved.

## Repeated-build and handoff follow-up

The [follow-up receipt](../receipts/reproducibility-1.json) records a narrowly scoped repair to compiler debug metadata. Two fresh builds from separate copies of the pinned source produced byte-identical installed bundles on the observed Linux `aarch64` host. The native executable's allocated sections and Ada/GPR source remain unchanged from the earlier build. Strict checks and exact runtime identities remain required.

The unchanged codec suites and installed-product controls passed on this new runtime. A [new deterministic handoff harness](REPRODUCIBILITY.md) passed six fixtures, recovering source bytes and comparing declared typed relationships and uncertainty with separately retained expectations. Swapped archives, changed literals, invalid shares, missing archives and incompatible runtimes were refused. Wrong-pin and runtime-mismatch preflights also refused before launching a child command. Independent GPT-6.1 reviews cover the binary comparison and final harness within their stated scopes.

This result closes the observed build-metadata obstacle for that pair. It does not replace the original failed comparison, establish compatibility across hosts, or qualify AI prose. No receiving-model trial or new formal proof campaign was performed.

## Reproduce without changing frozen fixtures

From the source directory:

```sh
python3 -I -S -B -Werror install/prepare_source.py --check
python3 -I -S -B -Werror install/check_source.py
python3 -I -S -B -Werror install/test_install_support.py -v
python3 -I -S -B -Werror install/test_install_layout.py -v

python3 -I -S -B -Werror install/test_installed_regression.py \
  --bundle /absolute/path/to/installed-bundle \
  --evidence /absolute/path/to/new-regression-evidence
python3 -I -S -B -Werror install/test_install_product.py \
  --bundle /absolute/path/to/installed-bundle \
  --evidence /absolute/path/to/new-product-evidence
```

The product runner performs an actual MCP stdio exchange only when the declared SDK dependencies are present; missing dependencies must remain visible in its report. Optional historical controls require the explicitly supplied old pair and decoder. Their absence is reported as unperformed; public source does not pretend to include private historical archives.

The regression runner copies a checked installed runtime, unchanged test sources and explicit synthetic fixtures into temporary test storage. It runs four suites against that copy. Original recipient/pagination and frozen MCP test sources are retained under `tests/`; they require their original frozen runtime/packages and are **not** silently retargeted or included in this fresh-runtime count. Running unrestricted discovery from an unbuilt checkout is not the supported reproduction command.

CI runs source inventory, installer mechanics, transformation and syntax/function-size controls on its declared Linux runner. That CI scope does not qualify an Omarchy installation or substitute for local integration evidence.

## Failures and limitations retained

- The initial build identity read included access time and falsely refused an unchanged tool after reading it. The repaired check compares content-relevant identity and modification metadata; the failed receipt is retained locally.
- A process that creates a new session can escape process-group cleanup. The counterexample remains a failed general-containment claim. The installer requires a trusted nonescaping toolchain; aggregate descendant resource containment remains unproved.
- A product-test invocation initially isolated the historical CLI in a way that removed its sibling import path. That failed harness run was retained before repairing the test invocation and repeating the full scoped controls.
- The original source-preserving workflow retains earlier model reconstruction failures. Exact retained bytes did not guarantee an agent copied a large diagram faithfully. No new model success is inferred from installation tests.
- An independently built binary may have a different identity. The package contract requires exact runtime identity, so independently rebuilt decoders are not promised interchangeable. Binary reproducibility and cross-build compatibility are separate requirements.
- The repeated isolated build from the public source copy produced a different native binary hash. This is a retained **NOT_BYTE_IDENTICAL** result, not a reproducibility pass.
- The first public-checkout source-control run exposed a missing sibling-import bootstrap in the installer-support test script. That failed run was retained and the test entry point repaired before repeating the controls.
- Review then caught the test script treating `-v` as an evidence directory name. Its CLI now parses `-v` and `--evidence` explicitly; the accidentally produced traces were retained outside the public source tree.
- Semantic payloads may contain opaque or incomplete interpretations. All source bytes remain recoverable under the exact-source contract; that does not make the typed payload semantically complete.

## Formal methods

Ada/SPARK contracts and evaluator sources are included unchanged. Existing local proof receipts retain their precise source and exclusion scopes; they were not rerun for the installer, and private historical receipts are not republished as if they were new public CI evidence. Native IO/entry code, Python integration, compiler correctness and language understanding are outside those source proofs.

For a new proof campaign, use the exact recorded toolchain and `gnatprove -U` with strict warnings, preserving project proof obligations and recording source hashes, tool versions, all unproved/justified conditions and raw results. No proof claim is valid merely because parsing or testing passes. Do not reduce assertions or contracts to obtain a green result.

## Numerical reporting

Report a green numerical consistency check only for a comparison actually performed. Byte-for-byte recovered source equality supports unchanged source figures within those bytes. It does not prove quantities in an AI narrative, inferred arithmetic, factual truth, or an interpretation. Missing comparisons must be NOT_CHECKED, never decorative checkmarks.
