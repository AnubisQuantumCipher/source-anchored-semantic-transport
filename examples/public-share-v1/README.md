# Display-only public marker

The [public share](public-share.txt) preserves the readable formula and adds
`CRED:<SHA-256 of the STS1 line>` immediately below STS1. It belongs with the
existing [canonical share](../quorum-replay-v1/recipient/share.txt),
[meaning ZIP](../quorum-replay-v1/recipient/meaning.zip), and
[readable lexicon](../quorum-replay-v1/recipient/lexicon.md).

Use the canonical share for decoding. The public share is a display companion;
the unchanged decoder rejects it as canonical input. CRED is freely computable
and provides no authorship, membership or execution authority.

See [the interface and recipient instructions](../../docs/PUBLIC_SHARE.md) for
the one-command encoding workflow and existing-share formatter. The complete
public text is counted against the requested budget. The ZIP reference here is
an attachment reference; nothing has been uploaded to a hosting service.
This example measures 220 Unicode code points and 221 UTF-8 bytes, including the
marker and reference. Its original canonical share is unchanged.

## Reproduce the portable checks

From the repository root:

```sh
python3 -I -S -B -Werror install/test_public_share.py
python3 -I -S -B -O -Werror install/test_public_share.py
python3 -I -S -B -Werror examples/public-share-v1/prepare_receipt.py --check
```

The formatter tests require Python's standard library. The actual encoder
comparison additionally requires the exact qualified installed decoder and its
dependencies. Its retained result is not a claim that every independent rebuild
or platform was exercised.

With that decoder and the source digest held from the receipt, reproduce the
same wrapper comparisons in a new evidence directory:

```sh
python3 -I -S -B -Werror examples/public-share-v1/wrapper/run.py \
  --oracle examples/public-share-v1/wrapper/oracle.json \
  --module install/transport_public_share.py \
  --expect-source-sha256 "$HELD_PUBLIC_SHARE_SHA256" \
  --encoder /absolute/decoder/bin/semantic-transport \
  --out /absolute/new-wrapper-evidence
```

The fixture includes the exact inputs and direct-encoder baseline artifacts.
The harness compares complete stdout, stderr and output bytes in both interpreter
modes. It does not need the original development directories.

The [receipt](receipt.json) binds source files to the observations and independent
review. Formatter expectations were frozen independently before implementation.
They cover exact output bytes, Unicode budget boundaries, malformed inputs,
marker-looking source text and create-only output. Additional boundary checks
cover byte limits and the API's exact integer type.

The actual encoder comparison checks that direct encoding and the companion
workflow preserve identical canonical outputs for identical inputs. Failure
controls cover a stale launcher pin, an existing public output, and a public
budget too small after otherwise successful encoding. Earlier findings and
failed observations are retained with their corrections.

These are development tests. Existing Ada/SPARK code and proof receipts are
unchanged; no new formal-proof, authentication or semantic-completeness claim is
made by this presentation feature.
