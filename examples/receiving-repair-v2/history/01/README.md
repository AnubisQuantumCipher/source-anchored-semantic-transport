# Public receiving repair: source recovery, citations, and observed continuation

This is a completed **public development repair demonstration** of the same SC_MAIN task used in the retained first trial. The original transport receiver failed because its workspace parent was not private. The repair connects the existing private-directory staging implementation to the real receiving workflow. It uses new create-only paths, unchanged task/source/oracle/package bytes, and the same pinned decoder dependencies.

The fresh receiver recovered all 12 sources byte-for-byte and returned 11 exact citations covering all required source intervals. Its saved first answer equals the observed plaintext final answer. A separate fresh source assessor recorded all 30 required items as `SUPPORTED` and all 22 frozen forbidden items as `NOT_OBSERVED`. The answer disclosed its recovery workflow, compromising the planned masking; the assessor explicitly declined to claim independent blinded completion. The original failed paired trial remains failed. This retry does not establish comparative benefit or general semantic completeness.

## Inspect the outputs

- [Compact share text](share.txt): 246 Unicode code points / 247 UTF-8 bytes, including the package reference. This counting convention is not a claim of platform compliance.
- [Matched meaning ZIP](meaning.zip): 21,417 bytes, with operative identity `STS1:50de2aef74afcbd21b6148bfa3d52dcda9977f6b21ab89c0b3d3c99ac6643454`.
- [Exact receiver answer](answer.json): first saved submission, without repair or pretty-printing.
- [Evidence archive](evidence.tar.gz): 344 regular entries, 468,081 compressed bytes; 2,139,601 payload bytes. It contains the frozen contracts, source oracle, selected runtime/helper source snapshots, interfaces, launch records, package, recovered files, safe event captures, assessments, controls, and retained failures.
- [Machine-checkable receipt](receipt.json): byte pins, source comparison, repeated citation validation, observed metadata, and explicit limits.

The source payload is 2,269 bytes. Neither the meaning package nor the evidence archive is smaller than that source. The compact share is an entry point into an explicit dependency; supporting information has not disappeared. The evidence archive is an audit bundle, not additional required decoder input.

## Reproduce the portable checks

From the repository root, with Python 3 and its standard library:

```sh
python3 -I -S -B -Werror examples/receiving-repair-v2/test_receipt.py
python3 -I -S -O -B -Werror examples/receiving-repair-v2/test_receipt.py
python3 -I -S -B -Werror examples/receiving-repair-v2/receipt.py --check
python3 -I -S -O -B -Werror examples/receiving-repair-v2/receipt.py --check
```

These commands check retained evidence. They do not launch models, execute archive instructions, install a service, or rebuild the decoder. The checker reads the gzip/TAR in memory without extracting it; compressed input and expansion are bounded at 4 MiB, individual entries at 1 MiB, and the entry count at 512. It rejects unsafe names, links, special entries, duplicates, malformed/truncated data, missing inventory entries, changed current source, and mismatched fixed trial identities. The 24 test methods include altered quantities, dropped citations, swapped definitions, final-answer substitution, erased failures, model-identity changes, and false assessment upgrades.

`pack_evidence.py --out NEW_FILE` reproduces collation only on the original host while its declared original evidence paths are available. The public checker needs neither those private paths nor native executables. Original dependency identities remain in the frozen config/manifest; native binaries and raw model journals are deliberately absent from this audit bundle. Executing a new decoder run requires those exact declared dependencies or a separately qualified replacement. Portable receipt checking is not a claim that independent runtime rebuilds were tested.

## What changed in the receiving workflow

`comparison/receiving/stage_repair.py` is a reusable create-only staging command. Its exact command/config are retained under `trial/preflight/`. It validates source and dependency pins before creation, walks caller-supplied anchor components without following symlinks, and checks private ownership and mode at every new ancestor and payload boundary. It never modifies the first trial's directories or dispatches an agent. The source task, annotations, package and source identities remain unchanged; only the manifest content location and receiving output paths are relocated.

Staging and native decoding are separate processes with different existing bounds. The staging helper uses 512 MiB address space, 30 CPU seconds and a 4 MiB file limit. The unchanged qualified native dependency uses 1 GiB, 120 CPU seconds, a 32 MiB file limit and 128 file descriptors. Applying the staging ceilings to the old native dependency caused the retained first preflight refusal. The successful distinct preflight used the original native profile and refused to launch if either inherited soft or hard limits were too low; it did not raise inherited limits. Staging directories remain mode 0700 and payloads 0600; the decoder publishes its existing read-only source snapshot as 0500 directories and 0400 files.

## Evidence and interpretation boundaries

| Check | Recorded result |
|---|---|
| New staging controls | 16 methods passed in normal and optimized Python; independently repeated |
| Native preflight and fresh receiver recovery | 12 original source entries byte-identical |
| First saved answer versus observed final | Exact UTF-8 equality |
| Citation membership and required interval coverage | 11 citations, complete required coverage |
| Source assessor findings | 30 required items supported; 22 forbidden items not observed |
| Blinded assessment completion | Not asserted: workflow disclosure compromised masking |
| Original paired trial / comparative benefit | First trial failed; benefit not established |
| General semantics, source truth, current authority | Not proved / not authenticated / none granted |

Both fresh agents were dispatched as `gpt-6.1-sol`, high reasoning, without inherited conversation turns. The captured model metadata confirms model and effort; observed Codex CLI version is `0.162.0-alpha.17.2`. Exact interfaces, prompts and settings are archived. Protocol-level input separation does not prove OS confinement or absence of hidden access. The public checker verifies pinned projections; it cannot independently authenticate a private provider journal or backend dispatch.

Usage records remain separate and unaggregated in the receipt. The receiver's last observed cumulative `total_token_usage` record reports 331,559 input tokens, 4,278 output tokens and 335,837 total tokens, with 291,840 cached input tokens. Its reported lifecycle duration is 62,625 ms. The assessor's corresponding record reports 371,700 input, 8,114 output and 379,814 total tokens, with 351,744 cached input tokens; reported duration is 121,978 ms. These are observed client fields, not a reconstructed billing total or a sum across repeated cumulative records. Currency cost and a controlled context-consumption advantage were not established.

The archive preserves the original private-parent failure; the lower-profile native preflight refusal; seal-checker failures and source snapshots; the assessor capture's correctly refused oversized candidate; and a reviewer's initial wrong historical-pin comparison. The receiver also wrote its answer using an ad hoc Python `assert` with a write side effect. That command ran under normal Python and its output bytes were independently checked, but optimized Python would omit the write. It is retained as an **observed engineering discipline failure**, not a qualified reusable implementation. No answer or historical receipt was edited to conceal it.

Only whitelisted tool call/output records, final text and selected model/lifecycle/usage metadata were exported from model activity. Raw journals, reasoning messages, and turn-context records were not exported. Proof claims for the separate Ada/SPARK semantic core are unchanged; this receiving trial adds empirical observations, not a new formal proof or a completed external-user study.
