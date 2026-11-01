# SENTINEL exact-evidence checkpoint

This working development case retains three proposed interpretations, five frozen
questions, fifteen answer records, two counterexamples and three repair links.
The final interpretation repairs both mistakes; the failed records remain.
The questions distinguish a maintenance exception from a prohibition, an
obligation from an observation, and uncertainty from conflicting testimony.
The answers are manually authored development oracles, not independent human
validation or a demonstration of arbitrary-document understanding.

One export emits a matched `share.txt` and `evidence.zip`. The archive carries
the complete registered evidence. This supplementary evidence share is an
identity/reference, not a replacement for the existing visible document formula,
readable lexicon and `meaning.zip` workflow.

Run from the complete source checkout, using a new output directory each time:

```sh
python3 -I -S -B -Werror examples/sentinel-exact-v1/create_fixture.py \
  --out /dev/shm/sentinel-input-new

SENTINEL_DEMO_SOURCE_SHA=$(python3 -I -S -B -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["sidecar_sha256"])' \
  /dev/shm/sentinel-input-new/pins.json)
SENTINEL_DEMO_REGISTRY_SHA=$(python3 -I -S -B -c \
  'import json,sys; print(json.load(open(sys.argv[1]))["registry_sha256"])' \
  /dev/shm/sentinel-input-new/pins.json)

python3 -I -S -B -Werror tools/transport_sentinel_package.py encode \
  --sidecar /dev/shm/sentinel-input-new/sidecar.json \
  --artifacts /dev/shm/sentinel-input-new/artifacts \
  --sidecar-sha256 "$SENTINEL_DEMO_SOURCE_SHA" \
  --registry-sha256 "$SENTINEL_DEMO_REGISTRY_SHA" \
  --out /dev/shm/sentinel-output-new --budget 200 \
  --reference https://example.invalid/SENTINEL-DEMO/evidence.zip

python3 -I -S -B -Werror tools/transport_sentinel_package.py inspect \
  --archive /dev/shm/sentinel-output-new/evidence.zip \
  --share /dev/shm/sentinel-output-new/share.txt
```

The actual retained local CLI trial produced a 130-character ASCII share and a
155,636-byte ZIP. The URL is an unfetched placeholder; hosting is untested.
These figures measure the evidence container, not net information compression,
model context consumption or superiority over original documents. The test pins
are generated before encoding; this manual fixture does not authenticate an author.

[Specification and interfaces](../../docs/SENTINEL.md) explain source intake,
history, uncertainty, dependencies and bounds. [The source-bound receipt](evidence/receipt.json)
pins the tested source, raw proof reports, reviewed controls and retained failures.
Its pure Ada/SPARK policy proof covers 115 reported obligations. It does not prove
Python, optical recognition, English interpretation, the oracle, or a native
stream parser. The public checkpoint supplies no native qualification bridge;
portable validation always reports `NOT_QUALIFIED` and authority `NONE`.

Recheck the frozen source and retained public evidence without executing it:

```sh
python3 -I -S -B -Werror examples/sentinel-exact-v1/freeze_receipt.py --check
python3 -I -S -B -Werror tests/check_sentinel_profile.py
python3 -I -S -B -Werror tests/test_transport_document_context.py
python3 -I -S -B -Werror tests/test_transport_sentinel.py
python3 -I -S -B -Werror tests/test_transport_sentinel_package.py
python3 -I -S -B -Werror tests/test_sentinel_qualification.py
```

Repeat the controls with `-O` to test optimized Python. These tests do not launch
the native toolchain. Strict native reproduction needs the declared GNAT toolchain,
Linux aarch64, the caller-held proof roster under `evidence/artifacts/build-oracle/`,
and the bounded builder documented in the source. No private attachment, book,
executable, model trial or public hosting is included in this checkpoint.
