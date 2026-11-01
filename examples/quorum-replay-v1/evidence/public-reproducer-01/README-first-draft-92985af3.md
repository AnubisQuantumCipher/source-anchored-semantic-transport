# Public ZIP-only replay preparation

This preparer creates one local invocation for the committed positive F02 fixture. It does not import replay modules, qualify a host, run the decoder, encode a package, or run the bootstrap. The unchanged fixture's complete expected result is copied with only its mechanically defined Request pin substituted.

Use the exact checker release you have independently verified, an independently qualified decoder installation, its matching decoder SOURCE tree, and that installation's canonical snapshot file. The snapshot embeds the decoder root path; moving the installation requires separately qualifying and holding a matching snapshot pin. INSTALL/RUNTIME/SOURCE/snapshot digests are not guessed or regenerated as trusted expected values by this preparer.

Supply `held-identities.json` as a closed canonical JSON object (no trailing newline):

```json
{"bootstrap_entry":{"bytes":0,"sha256":"REPLACE_WITH_INDEPENDENTLY_HELD_DIGEST"},"bundle_snapshot":{"bytes":0,"sha256":"REPLACE_WITH_INDEPENDENTLY_HELD_DIGEST"},"decoder_install_descriptor":{"bytes":0,"sha256":"REPLACE_WITH_INDEPENDENTLY_HELD_DIGEST"},"runtime_descriptor":{"bytes":0,"sha256":"REPLACE_WITH_INDEPENDENTLY_HELD_DIGEST"},"schema":"quorum/public-held-identities/1","source_manifest":{"bytes":0,"sha256":"REPLACE_WITH_INDEPENDENTLY_HELD_DIGEST"}}
```

The placeholders above are deliberately invalid. Use independently held actual lengths and lowercase SHA-256 values, and canonicalize the completed object. Verify the preparer/release source before using it. Choose a new absolute output directory whose parent exists.

```bash
python -I -S prepare_public_replay.py \
  --checker-root /absolute/verified-checker \
  --decoder-root /absolute/qualified-decoder \
  --decoder-source-root /absolute/matching-decoder-source \
  --held-identities /absolute/held-identities.json \
  --snapshot-file /absolute/qualified-installed-snapshot.json \
  --fixture-manifest /absolute/verified-checker/examples/quorum-replay-v1/fixture-manifest.json \
  --out /absolute/new-replay-inputs
```

Review `preparation-receipt.json`, `checker-descriptor.json`, `request.json`, `envelope.json`, `invocation.json`, and `expected.json`. `command.txt` contains the exact later bootstrap command; `result-command.json` contains its argv vector. The command is not executed by preparation. Before executing it, independently compare the bootstrap entry's actual length and digest with the held release pin. The bootstrap's self-check is defense, not authentication.

The runtime invocation deliberately names nonexistent Body/original paths under `ABSENT_EVALUATOR_SIDECARS`. The preparer reads committed fixture annotation metadata to construct the independently supplied Request; it writes no original-source or Body sidecars. Actual runtime Body and source bytes must be recovered from the committed ZIP by the already qualified decoder. The receiver still needs the declared decoder, matching SOURCE tree, checker/runtime roots, ZIP/share, generated Request/envelope and held identities. It does not need the original source files.

After owner review, execute the printed argv directly, retaining stdout, stderr and exit status separately. Require exit 0, exact canonical stdout bytes plus LF equal to `expected.json` plus LF, and a complete actual bootstrap qualification receipt on stderr. Also run the same invocation with Python `-O`; preserve both results and any failure. Count complete stdout plus stderr under the existing combined output cap. Qualification and replay remain byte/structure checks with no source authenticity, current authority, natural-language completeness, or model-identity attestation claim.

No repository files are modified by this preparation draft. Publishing it, its fixture manifest, and its exact qualification dependencies remains the owner's release step.
