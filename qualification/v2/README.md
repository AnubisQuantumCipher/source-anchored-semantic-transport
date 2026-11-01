# Native qualification v2

This is a separate source epoch for the bounded SENTINEL policy and STN1 wire controls. The source05 foundation under `sentinel_native/` and its original receipts remain unchanged. Three policy files here override their source05 counterparts in a new, read-only build tree; the other policy files, native wire files and generic build helpers are shared by exact pin.

The retained source13 evidence records 139 discharged checks (85 flow, 54 prover), all 46 source-derived entities, eight explicit postcondition entities and the Session default-initial-condition obligation. The separate native wire run checked all 51 frozen literal cases and 901 strict prefixes. The exact receipts, raw proof summary, machine diagnostics, wire progress and independent readbacks are retained losslessly in `evidence.json.gz`.

`literal-fixtures.json.gz` stores the original 62 synthetic fixture files as canonical JSON/base64 inside deterministic gzip. Compression changes storage only. Preparation checks the exact name roster and every expanded raw byte count and SHA256 against `manifest.json`; it does the same for all eleven evidence files. Both compressed archives together must remain within 512 KiB. Each expanded section and the aggregate prepared payload, including the preparation receipt, are bounded to 8 MiB. The source file bound is 128 KiB. None of these data files is executed.

The manifest also pins the three preparation modules, the source-derived proof roster, three controller modules and all 61 normalized build inputs. Its caller-held SHA256 is `974a25025c133548b943cd4ef5b7ba514c6b9e31235521a78f5361949bc8fb5f`. The preparation tool never calculates that expected value from the manifest under test.

Check the package without invoking native code:

```sh
python3 -I -S -B -Werror tools/sentinel_v1/native_build.py --mode check --manifest-sha256 974a25025c133548b943cd4ef5b7ba514c6b9e31235521a78f5361949bc8fb5f
```

Prepare a reviewable tree in a new directory whose existing parent is private and owned by the caller:

```sh
mkdir -m700 /dev/shm/sentinel-v2-development
python3 -I -S -B -Werror tools/sentinel_v1/native_build.py --mode prepare --manifest-sha256 974a25025c133548b943cd4ef5b7ba514c6b9e31235521a78f5361949bc8fb5f --out /dev/shm/sentinel-v2-development/inspection
```

Explicit `--mode policy` or `--mode wire`, with another new `--out` and `--toolchain-root /path/to/existing/gnat`, hands execution to the existing fixed bounded policy or wire builder. It does not install tools or replace a decoder. Source preparation precedes the builder's shared monotonic deadline; the builder retains its existing admission, phase, namespace, PID ownership, hard quota, read-only capture and refusal rules. Missing namespace support has no weaker fallback. The wire profile does not rerun the separate policy proof.

Source preparation returns `SOURCE_PREPARED_UNQUALIFIED`. Pin verification and successful compilation are not semantic eligibility decisions. Only the native policy evaluates the finite supplied probe relation. Caller-supplied context/adjudication declarations, oracle authentication and faithful reference answers remain external assumptions. Parser correctness is tested by these finite controls, not formally proved; aggregate or peak stack, hostile-host attestation, natural-language truth, OCR accuracy, full-book semantic completeness and the complete SAST-SENTINEL acceptance mission remain unproved. Execution authority remains `NONE`.

The reusable `qualification_command(prepared, mode, toolchain_root, source_root, expected_manifest_sha)` boundary rechecks the independently supplied repository and held manifest pin, derives the exact overlay payload pins, and rejects jointly altered prepared files and reports. A preparation report is never its own provenance.
