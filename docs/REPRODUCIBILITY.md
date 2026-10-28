# Repeated builds and package handoff

A package identifies an exact decoder runtime. If unchanged source produces a different native binary every time it is built, independently installed decoders cannot exchange that package under the existing identity contract. The repair addresses that concrete obstacle without loosening identity validation.

## Observed cause and repair

The original repeated builds differed only in `.debug_info` and `.debug_str`. GPRbuild supplied process-dependent configuration/mapping filenames to GNAT, and the default compiler option recording embedded those filenames in `DW_AT_producer`.

The installer now passes `-gno-record-gcc-switches`. This suppresses the appended compiler option string, while retaining `-g`, compiler-version information and the project's strict warnings/assertions. The [GCC option definition](https://gcc.gnu.org/onlinedocs/gcc/Debugging-Options.html#index-grecord-gcc-switches) describes this metadata behavior. The build command receipt and pinned project retain the fixed build options. Neither the Ada/GPR source nor decoder identity validation changes.

Independent comparison found all allocated ELF section headers and payloads unchanged from the previous binary. Source, type, line and variable-location debugging remains present. The earlier NOT_BYTE_IDENTICAL result is retained; it is not relabeled as a pass.

## Paired build contract

Use the [installation command](INSTALL.md) twice with separate source copies, distinct new destination/receipt directories, and the same separately held source-inventory digest. Each build independently compiles the native decoder. Do not copy the first installation as the second build.

Compare the complete native binaries, `RUNTIME.json`, every installed module, and the generated launcher. The local paired run produced byte-identical complete installations, including `INSTALL.json`. Its scope is one Linux `aarch64` host with the same selected compiler, Python executable and declared native libraries. This is an observation for those inputs, not a proof for all hosts, compilers or architectures.

A different source distribution, compiler output or dependency identity can still change the runtime and must cause refusal. Old packages retain their original decoder. Do not erase native identity checks or silently regenerate package metadata to make incompatible installations appear compatible.

## Handoff acceptance

The deterministic harness creates packages with one installed CLI, copies only the share text and meaning ZIP into a receiving directory, and invokes the other installed CLI in fresh processes. A separate harness holds the original bytes and expected structure for comparison. No original source document is copied into the receiver directory.

This is process-level separation of inputs, not a filesystem sandbox or an independent AI narrative run. The harness reports narrative fidelity and model-token use as unperformed. It cannot prove that an AI would preserve every meaning in its own prose.

```sh
python3 -I -B -Werror install/test_portable_handoff.py \
  --sender-bundle /absolute/path/to/first-built-bundle \
  --receiver-bundle /absolute/path/to/second-built-bundle \
  --mismatched-bundle /absolute/path/to/incompatible-old-bundle \
  --expect-runtime-sha256 "$HELD_RUNTIME_SHA256" \
  --evidence /absolute/path/to/new-handoff-evidence
```

Set `HELD_RUNTIME_SHA256` to the independently retained `RUNTIME.json` digest from the build acceptance evidence. The harness requires that pin before executing either installed CLI. It also checks that its implementation files and all installations remain unchanged. Each run needs a new evidence directory. An incompatible old bundle is required for the runtime-refusal control; retain it with its own declared dependencies.

The cases cover the emotional sentence, controller timing/maintenance exception, parallel review requirements, attributed uncertainty and quantities, a recipe, and opaque/empty sources. Recoveries are compared byte-for-byte. Explicit typed meaning units and focused source anchors are compared against the declared plan; this does not independently validate the original interpretation of that plan.

Controls require refusal of swapped or altered packages, invalid share text, a missing archive and an incompatible decoder after positive baseline checks. They retain the original packages and input identities. The evidence reports source, share, ZIP, dependency and tool-output sizes separately; it does not claim whole-package compression savings.

The [source-bound public receipt](../receipts/reproducibility-1.json) for the paired build and handoff is separate from the [original checkpoint receipt](../receipts/checkpoint-1.json). Read both results with their limits. General semantic completeness, cross-architecture compatibility and desktop-client behavior remain unproved or unperformed.
