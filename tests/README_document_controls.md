# Document transport controls

These are deterministic development controls. They do not establish semantic
completeness, OCR accuracy, authentication, or external acceptance. Fixtures are
synthetic; no supplied book content is needed or retained in this directory.

Set `TRANSPORT_DOCUMENT_TEST_SCRATCH` to a private temporary directory. The
fallback is `/dev/shm/transport-document-tests`; each suite creates its own
retained run directory. `TRANSPORT_DOCUMENT_SCRATCH` separately selects temporary
files created by the transport implementation. The existing byte, reading and
boundary suites require `TRANSPORT_DOCUMENT_NATIVE` and
`TRANSPORT_DOCUMENT_NATIVE_SHA256` to identify a built decoder.

Run each suite directly from any working directory, using its absolute filename:

```sh
python -I -S -B -W error tests/test_transport_document.py
python -I -S -B -W error tests/test_transport_document_boundaries.py
python -I -S -B -W error tests/test_transport_document_reading.py
python -I -S -B -W error tests/test_transport_document_media_controls.py
python -I -S -B -W error tests/test_transport_document_ocr_controls.py
```

Repeat with `-O` before the filename. The paths above assume the repository is
the working directory. Source resolution inside every suite is repository
relative, regardless of the working directory.

The media suite explicitly loads the optional `defusedxml` dependency from the
interpreter's configured installed `purelib` when isolated `-S` operation omits
it. Missing `defusedxml` produces a named skip. Its synthetic PDF control also
requires the fixed `/usr/bin/pdfinfo`, `/usr/bin/pdftotext` and `/usr/bin/qpdf`
tools used by the extractor; a missing tool is a refusal, not a successful test.
No dependency is downloaded or installed. EPUB entries are generated locally.

The OCR boundary suite mocks rendering, process creation and signals. Its
collection and hash fixtures are small synthetic regular files; it requires no
book, OCR executable or trained data. Each media/OCR suite retains source pins,
its bounded fixtures and a JSON result in its scratch run directory. These two
suite fixture roots each have an enforced 8 MiB storage cap. Original transport
suite resource caps are unchanged.

The separate `document-profile.yml` workflow pins Linux x64 Python 3.14.10 and
installs only the hash-pinned universal `defusedxml` wheel into runner temporary
storage. It runs bundle7, OCR36 and media29 controls in normal/optimized isolated
modes, plus bounded AST/function-size checks. `TRANSPORT_DOCUMENT_TEST_PURE=1`
replaces the media PDF tool boundary with deterministic outputs and denies
process creation there. It exercises page parsing and byte spans, and does not
claim to execute Poppler/qpdf in CI. The default local media mode retains the
real synthetic PDF tool control.

`TRANSPORT_DOCUMENT_XML_PATH` explicitly selects the dependency directory under
`-S`; `TRANSPORT_DOCUMENT_REQUIRE_XML=1` makes absence a hard error. An exit77
from optional mode is nonzero and fails the workflow. Local reproduction may
use an already installed dependency directory without installing anything.
The wheel SHA is from the official PyPI release JSON linked in
`document-profile-requirements.txt`; pip checks downloaded bytes against it.

Native70 controls require the declared qualified native binary and remain
separate local Linux aarch64 evidence. This workflow does not fabricate a
Linux x64 native result. Workflow source is not evidence of a hosted run;
that requires the pushed revision's hosted result and readback.

The developer helper is `tools/build_document_decoder.py --out NEW_PRIVATE_DIR
--toolchain-root EXISTING_GNAT_ROOT [--source-root REPOSITORY]`. Its output directory
must be new and below `/dev/shm`. It requires existing GNAT tools and unprivileged
Linux user, mount, PID and network namespaces; unavailable isolation refuses the
build. It mounts a private 64 MiB/4096-inode tmpfs and retains quiescent captures
of failed runs. A failed readonly remount never qualifies its capture. The helper
keeps its exact ledger proof scope separate from native execution, Python
orchestration, English semantics and whole-system correctness.

Portable helper controls run without compiler or prover dispatch:

```sh
python3 -I -S -B -Werror tests/test_document_build_helper.py
python3 -I -S -B -O -Werror tests/test_document_build_helper.py
```

These controls test refusals, the fixed proof summary profile, resource-limit
preservation, bounded commands and source structure. Passing them does not
qualify an actual native build or establish a proof of this Python helper.

The helper trusts the supplied repository, existing toolchain, Linux kernel and
cooperative GNAT tools. It does not claim a hostile-child capability or storage
sandbox. A shared 450-second monotonic deadline reserves 90 seconds for terminal
work; a phase is refused unless its full declared time bound fits before that
reserve. Capture progress is append-only. Partial exports and failure metadata
are retained and never qualify a successful build. Host crashes and unrecoverable
external filesystem failures can lose unexported private state; complete capture
is required for success.

The legacy installer syntax checker now has two explicit bounded profiles. The
legacy profile retains its original maximum of 128 files and its original
function-size policy. A second profile contains exactly the nine named top-level
document modules in `install/check_source.py`; every declared member is required,
and every function in those nine modules is limited to 60 lines. Both profiles
parse and compile every selected file. Unknown future modules remain in the
legacy profile and consume that unchanged budget. Document build submodules
remain covered by `tests/check_document_profile.py`.

This is an explicit source-analysis budget extension for the document feature.
It preserves coverage while permitting a separately bounded nine-file batch;
raising the legacy guard or excluding files by a wildcard would weaken that
coverage boundary. Each file still has a 128 KiB input bound, and analysis remains
sequential. The additional risk is the fixed extra batch's analysis time; the
existing workflow wall limits still apply. Syntax and function-size checks do
not establish termination, correctness or whole-system proof. The sealed legacy
`install/SOURCE.json` inventory is unchanged and is checked independently.

Partition controls exercise 129-file legacy rejection, every missing declared
document member, unknown-file retention, disjoint complete parsing, syntax
errors and oversized functions:

```sh
python3 -I -S -B -Werror tests/test_source_profile_partition.py
python3 -I -S -B -O -Werror tests/test_source_profile_partition.py
```
