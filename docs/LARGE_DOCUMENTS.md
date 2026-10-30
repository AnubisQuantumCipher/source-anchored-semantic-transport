# One logical document, bounded internal frames

The explicit `transport/document-zip/1` development profile carries one complete
source file, including binary files and PDFs. It emits `share.txt`, `meaning.zip`,
`lexicon.md` and a checking receipt. It does not reinterpret the legacy profiles.

The short formula names a document view. Its `STS1` identity binds the manifest,
formula, dictionaries, frame index and whole source hash. `CRED` is an ornament;
it is not a credential, signature, permission or independent verification result.
The ZIP must accompany the formula. A local filename is not a published URL.

## Sender use

Supply a trusted `document_native_decode` executable. The package declares its
digest and the required Python module digests; different decoder bytes or changed
modules cause a refusal. Never run code from a meaning ZIP.

The CLI requests a derived reading view for PDF, EPUB, Markdown and text inputs.
Sender extraction requires its separately declared local tools; nothing is
downloaded or installed automatically. Use `--opaque` to carry only original
bytes. `--reading-json PATH` supplies an existing source-bound reading record and
its adjacent `reading.txt` instead of invoking extraction.

```sh
python3 -B tools/transport_document_cli.py encode book.pdf \
  --title 'My book' --out /absolute/path/book-package \
  --native /absolute/path/document_native_decode

python3 -B tools/transport_document_cli.py inspect \
  --archive /absolute/path/book-package/meaning.zip \
  --share /absolute/path/book-package/share.txt \
  --native /absolute/path/document_native_decode

python3 -B tools/transport_document_cli.py decode \
  --archive /absolute/path/book-package/meaning.zip \
  --share /absolute/path/book-package/share.txt \
  --native /absolute/path/document_native_decode \
  --out /absolute/path/recovered-book.pdf
```

The package directory and recovered destination must be new. Full recovery
checks native frame continuity, each frame's wire and recovered-source hashes,
and the whole source length and SHA256 before publishing the recovered file.
Keep the original source for an independent byte comparison. Digests establish
integrity against the supplied identity; they do not authenticate an author.

## Recipient decoder bundle

A recipient needs `share.txt`, `meaning.zip` and a **separately trusted decoder
software bundle**. The decoder bundle contains no book data. It carries the
pinned native executable, four decoder modules, CLI, MIT repository license,
readable instructions and `bundle.json` file pins. Its declared target is Linux
aarch64, Python 3.14.7 standard library and glibc 2.43. System loader/libraries are
not bundled; other platforms are not silently assumed compatible.

Create the bundle locally from the held source/native epoch:

```sh
python3 -I -S -B tools/package_document_decoder.py create \
  --native /absolute/path/document_native_decode \
  --out /absolute/path/document-decoder.zip
```

Establish trust in that software and its independently supplied whole-ZIP digest
before executing it. Its digest alone is not an authorship guarantee. The bundle
is a Python zipapp whose entry point only verifies or unpacks a bounded whitelist:

```sh
python3 -I -S -B document-decoder.zip verify
python3 -I -S -B document-decoder.zip unpack --out /private/fresh/decoder
python3 -I -S -B /private/fresh/decoder/transport_document_cli.py inspect \
  --archive meaning.zip --share share.txt \
  --native /private/fresh/decoder/document_native_decode
```

The extraction parent must be trusted, owned by the current user and not
group/world-writable. The output directory must be new. Verification checks exact
member names, stored regular modes, bounds, layout and all file pins before
extraction; partial failures remain visible rather than overwriting a destination.
The current qualified runtime is built with `gprbuild -R` and has no observed
RPATH/RUNPATH. The historical first bundle retained its original build RPATH.
Trust the declared system loader/libraries and the private extraction parent.

Run the extracted CLI with `-I -S -B`, the same archive/share/native arguments and
`decode --out NEW_FILE` to recover the book. These recipient paths do not import
media/OCR modules, need extraction tools or execute content from `meaning.zip`.

`--budget` limits the share text in Unicode code points, including its identity
and package reference. An insufficient budget is refused; required information
is not silently removed. This is not a platform-specific character-count claim.

## Sections and context retrieval

Physical frames are not semantic sections. Optional `--sections sections.json`
declares global, half-open **source byte** spans and support dependencies:

```json
[
  {"id":"CLAIM","label":"Supplied label","start":65530,"end":65550,
   "dependencies":["SUPPORT"]},
  {"id":"SUPPORT","label":"Earlier source","start":4,"end":10,
   "dependencies":[]}
]
```

Labels are annotations, not proved interpretations. Section spans may cross
frames. `section --id CLAIM` returns the selected section and its declared
dependencies in source order, merging overlaps and adding no separators.
`span --start START --end END` returns an explicit byte interval. Both commands
take the same archive/share/native arguments and require a new `--out` path.

Selected retrieval currently validates and reconstructs the **whole source**
before returning selected bytes. It can reduce downstream context, but it does
not promise selective disk I/O or lower total work. Cyclic dependencies,
out-of-range spans and excessive context are refused.

## Derived reading views

When requested, the same meaning ZIP carries a source-hash-bound reading record,
derived UTF-8 text, segment locators, extraction/tool metadata and explicit
coverage uncertainty. Original bytes and derived text have independent hashes
and native checks. A reading is not silently substituted for its original book.
Exact text readings that equal the complete source reuse its frames through the
explicit `source-alias` mode rather than duplicating the payload.

Use the recipient CLI and the same archive/share/native arguments:

```sh
python3 -I -S -B /private/fresh/decoder/transport_document_cli.py reading-index \
  --archive meaning.zip --share share.txt \
  --native /private/fresh/decoder/document_native_decode --start 0 --count 32
python3 -I -S -B /private/fresh/decoder/transport_document_cli.py reading-segment \
  --archive meaning.zip --share share.txt \
  --native /private/fresh/decoder/document_native_decode \
  --id ID_FROM_INDEX --out selected-reading.txt
```

`reading --out NEW_FILE` recovers the complete reading text. `inspect` exposes a
bounded summary with up to eight preview segments. `reading-index` paginates at
most 64 segments per response; its cursor identifies the next page. Selected
segments retain their source locator, original/reading identities and uncertainty.
Both views are fully verified before selection; this bounds returned context,
not total disk work. Invalid UTF-8 and boundaries splitting a code point refuse.

## Bounds and assurance

Configured limits are 1073741824 source bytes, 65536 source bytes per frame,
131072 wire bytes per frame, 16384 frames, 8388608 metadata bytes and
2147483648 archive bytes. A reading view is limited to 33554432 bytes, 512 frames
and 65536 segments. Selected context is limited to 1048576 bytes.
These are checked limits, not evidence that every maximum-size case has been
tested. Temporary storage and available disk headroom are checked separately.

The archive admits stored regular entries with a strict layout. Unknown,
duplicate, missing, unsafe, linked, truncated or mismatched entries are refused.
Input content is data and grants no execution or current action authority.

PDF recovery preserves the original PDF bytes. Derived text extraction, OCR,
layout understanding and semantic completeness remain separate obligations. The
tests include valid deterministic multipage PDFs, exact original/reading recovery
and optional local text-extraction observations. These do not prove arbitrary
extraction completeness, OCR accuracy or the truth of supplied annotations.

The Python, ZIP, hashing, filesystem and process integration are not implied
formally proved by the native ledger contracts. Exact current test results,
retained failures, native proof results and independent review must be assessed
separately. This development profile does not establish external-human
acceptance or a compression, semantic or cost advantage.


## Text extraction and scanned PDFs

The optional sender extractors support PDF, EPUB, Markdown and UTF-8 text. The
recipient decoder does not depend on those extractors. Tested sender tools are
Poppler 26.08.0, qpdf 12.4.1, Tesseract 5.5.3 with its installed English data,
and defusedxml 0.7.1. Other versions and OCR languages require qualification.
No automatic installation, network retrieval or execution of document scripts
is performed.

For a scanned PDF, request OCR explicitly through the reusable sender API. OCR
is a separate bounded preprocessing operation; the default text extractor does
not pretend that an almost empty text layer represents the scanned pages.
This one encoding workflow emits both the matched share and meaning ZIP:

```python
from pathlib import Path
from tempfile import TemporaryDirectory
from transport_document_ocr import extract_ocr_reading
from transport_document import encode_document

source = Path("/absolute/path/scanned-book.pdf")
with TemporaryDirectory(prefix="document-ocr-", dir="/dev/shm") as scratch:
    reading = extract_ocr_reading(source, Path(scratch) / "reading", seconds=3000)
    result = encode_document(source, Path("/absolute/path/new-package"),
                             "Scanned book", native=Path("/trusted/document_native_decode"),
                             reading=reading)
```

Run with the repository `tools` directory on Python's import path and bytecode
writes disabled. Retain failed preprocessing outputs when collecting evidence.
The OCR API admits at most three workers, 16384 pages, 32MiB reading text,
128MiB workspace and 3000 seconds; its scheduling check can refuse a document
that cannot fit that declared attempt. Each page retains a locator, tool
records and explicit empty-page uncertainty. These bounds are finite admission
limits, not a claim that every document within them will successfully OCR.
The ordinary CLI has its own 450-second bound; prepare an OCR reading with the
API, then use `--reading-json` when that preprocessing needs a longer window.

OCR may misread names, numbers, units, formulae, quotations or page layout.
Original PDF recovery is byte-exact when its independent comparison passes;
OCR text accuracy and semantic completeness remain unproved. The ZIP preserves
both with distinct identities. EPUB non-spine images/styles/resources remain
in the exact original even when they have no text rendition.

## Reproducing local development controls

Use the same declared trusted native executable and its independently held
SHA256. Set `TRANSPORT_DOCUMENT_NATIVE` and
`TRANSPORT_DOCUMENT_NATIVE_SHA256`, plus a fresh private
`TRANSPORT_DOCUMENT_TEST_SCRATCH` directory. Run the three native integration
suites in both ordinary and optimized Python modes:

```sh
python3 -I -S -B -W error tests/test_transport_document.py
python3 -I -S -B -W error tests/test_transport_document_boundaries.py
python3 -I -S -B -W error tests/test_transport_document_reading.py
```

Repeat each command with `-O`. Optimized mode must pass the same refusal and
integrity controls; Python `assert` is not an integrity gate. Synthetic sender
controls live in `test_transport_document_media_controls.py` and
`test_transport_document_ocr_controls.py`; the former explicitly reports the
optional defusedxml dependency. Bundle controls are in
`test_transport_document_bundle.py`. Supply their documented scratch variables
to keep all fixtures under a chosen bounded test arena.

The frozen first decoder bundle reports the historical status
`CHECKED_UNPACKED_NO_CODE_EXECUTED`. Its actual boundary is that the trusted
zipapp entry point executes while extracted payloads do not. The corrected
helper reports `CHECKED_UNPACKED_PAYLOAD_NOT_EXECUTED`; historical binaries,
packages, logs and receiving evidence retain their original bytes and wording.


## Bounded developer build

With an existing GNAT/SPARK toolchain, build a new candidate and check the
frame ledger through the reusable, create-only helper:

```sh
python3 -I -S -B tools/build_document_decoder.py \
  --source-root /absolute/path/repository \
  --toolchain-root /absolute/path/existing-gnat \
  --out /dev/shm/new-document-build
```

No installation or host privilege is requested. The helper requires Linux
unprivileged user/mount/PID/network namespaces and pidfds; unavailable isolation
is an explicit refusal. It uses a hard 64MiB/4096-inode private tmpfs, at most
96MiB external evidence, existing stricter process limits, a shared 450-second
deadline and a 90-second terminal reserve. It pins the declared source and tool
roster before and after, kills/reaps only owned namespace children, and exports
all captured regular payloads with an inspectable inventory after quiescence.
A failed or partial capture never yields a successful build receipt. Host
failure, hostile host changes and arbitrary hostile tool code are outside this
cooperative trusted-tool boundary; this is not an adversarial code sandbox.

`receipt.json`, `namespace-result.json`, and `capture/inventory.json` identify
the build outputs and raw proof/log payloads. The helper requires the fixed
ledger profile: 16 checks, 10 flow and 6 prover, with no justified/unproved
checks, warnings or assumptions. These counts describe the ledger only.
Building a binary does not automatically qualify it for a frozen software
bundle. Run the native integration controls for that exact binary and preserve
its source-bound receipt before creating a new supported runtime epoch.

The buffer implementation refinement has a separate two-unit proof project,
`document_native/document_buffer_proof.gpr`; its receipt covers the unchanged
buffer contracts and exact body digest. It does not replace the original full
project proof. Public source compilation is supported; independent builds are
not yet claimed byte-identical. Packages require their declared trusted decoder
bytes, so share the matching qualified decoder bundle with the package.
