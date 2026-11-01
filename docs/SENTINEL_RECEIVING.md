# SNE1 receiving profile

SNE1 is an inert, indexed semantic-evidence source document carried by the existing SAST document codec. Its encoded form is the existing one formula plus `meaning.zip`. The complete SNE1 header, index and entries are recovered and checked by the existing whole-source identity. There is no second ZIP parser, network retrieval, source-selected executable or model dispatch.

This profile transports **proposed** graph ideas and evidence. It grants no execution authority, truth, qualification, authenticity, semantic completeness, OCR accuracy or benefit claim. Its constants are `NOT_QUALIFIED`, `NONE`, `UNPROVEN` and `UNAUTHENTICATED`. Bundled admission records are checked against their bundled pins; they are not independently held acceptance. A native-evidence pointer checks referenced bytes, not the claimed proof.

## Prepare and inspect inert data

Run the CLI as a module from the repository root, with the existing Python tools directory on the import path:

```sh
PYTHONPATH=tools python3 -B -m sentinel_v1.cli --semantic-root SEMANTIC_DECODER_SHA256 pack \
  --input-dir /absolute/operator-input \
  --manifest /absolute/operator-input/manifest.json \
  --expect-manifest MANIFEST_SHA256 \
  --output /absolute/new/document.sne1

PYTHONPATH=tools python3 -B -m sentinel_v1.cli --semantic-root SEMANTIC_DECODER_SHA256 inspect-payload \
  --payload /absolute/new/document.sne1 --expect-payload PAYLOAD_SHA256 \
  --decoder-identity DECODER_RUNTIME_SHA256 \
  --export /absolute/new/inert-export
```

Substitute independently held hashes. Neither command decodes a base package. Inspection reports `NOT_PERFORMED_GRAPH_ONLY`; it is not source-backed receiving. Export creates a new private directory with fixed record names and hexadecimal artifact names. Files are regular and create-only; existing destinations and symlinks refuse. A failure can leave partial new output; it is never silently retried or overwritten.

The canonical input manifest has exactly:

```json
{"schema":"sentinel/bundle-input/1","records":{"GRAPH":{"sha256":"64hex","bytes":123}},"artifacts":{"64hex":{"sha256":"64hex","bytes":4}},"bases":[],"decoder_identity_sha256":"64hex"}
```

The example is a shape, not a valid fixture: use real hashes, sizes and at least one matching base. `GRAPH.json` and `HASH.bin` are the only derived input names. Manifest data cannot supply file paths. Each base has exactly `package_id`, `source_sha256`, `source_bytes`, `archive_sha256`, `archive_bytes`, `decoder_identity_sha256` and `decoder_source_sha256`. Every graph source must match a base's original identity; unused or duplicate bases refuse.

`bundle.decoder_pins(explicit_native_path)` derives the runtime identity from the unchanged decoder's native hash, loaded module epochs and runtime declaration. The separately returned source identity hashes that decoder's module-epoch map. Computing these identities reads files; it does not run the native executable. A receiver must hold acceptable identities independently, rather than adopting an arbitrary sender's values.

## Existing SAST encode and decode

```sh
PYTHONPATH=tools python3 -B -m sentinel_v1.cli --semantic-root SEMANTIC_DECODER_SHA256 encode \
  --payload /absolute/new/document.sne1 --expect-payload PAYLOAD_SHA256 \
  --output /absolute/new/sast-package --native /absolute/qualified/native \
  --budget 1024 --display-profile OVERVIEW

PYTHONPATH=tools python3 -B -m sentinel_v1.cli --semantic-root SEMANTIC_DECODER_SHA256 decode \
  --archive /absolute/sast-package/meaning.zip \
  --share /absolute/sast-package/share.txt --native /absolute/qualified/native \
  --decoder-identity DECODER_RUNTIME_SHA256
```

These are actual native operations and require the caller's appropriate admission. Pure developmental tests mock them. Encoding snapshots the held payload before codec work, supplies complete proposed typed node labels and all explicit graph relationships, and relies on the unchanged codec's title, section and Unicode codepoint budget checks. The visible formula uses proposition and typed context-node symbols; the normal SAST lexicon contains the complete JSON-escaped proposed texts. Nothing is truncated to fit. Required labels over 255 UTF-8 bytes, a graph title over 255 bytes, no proposition, over 64 total display nodes, or an insufficient share budget refuse. A display section covers the complete graph record, not an invented source interpretation.

Decoding verifies the outer SAST pair and the full indexed source, then presents the graph. It still reports graph-only base resolution. Merely opening this evidence document does not authenticate or recover its separately referenced original sources.

## Required source-backed resolution

`resolve` additionally requires an operator-held canonical registration JSON, its held hash, and an independently held base identity root:

```sh
PYTHONPATH=tools python3 -B -m sentinel_v1.cli --semantic-root SEMANTIC_DECODER_SHA256 resolve \
  --archive /absolute/evidence/meaning.zip --share /absolute/evidence/share.txt \
  --native /absolute/qualified/native --decoder-identity DECODER_RUNTIME_SHA256 \
  --registrations /absolute/operator/base-registrations.json \
  --expect-registrations REGISTRATIONS_SHA256 --expect-base-root BASE_ROOT_SHA256
```

Registrations are exactly `{"PACKAGE_ID":{"archive":"/absolute/base/meaning.zip","share":"/absolute/base/share.txt","native":"/absolute/qualified/native"}}`, with all and only the declared base package IDs. These paths are caller capabilities, never received document instructions. The base root is SHA256 of canonical JSON mapping package ID to its complete seven-field base declaration. The receiver compares actual streamed archive SHA/size, decoder runtime and source epoch with that held declaration before and after resolution. The unchanged locator API validates the base package, recovered whole original, coordinate/revision identities and requested quotes. A direct raw-original handle is not accepted as SAST fallback.

The required paired `LOCATORS`/`REVISIONS` records identify complete bounded locator and revision registries. All graph source windows must resolve through them; missing, disjoint, altered or unsupported windows refuse the required source-backed path. A spatial selector's well-formed shape alone never produces source bytes.

The API `resolve_registered(decoded, registrations, held_root)` and CLI return graph binding receipts and exact source-order context parts as `span`, `data_hex`, `sha256`, with explicit gaps and coordinate kind. Hex preserves arbitrary original bytes; it is not a semantic rendering. All returned parts together are capped at 65,536 source bytes per intake. Larger requests refuse without truncation. Exact bytes may be decoded only under a caller's separately chosen interpretation. Original and derived coordinates remain distinct; reading-view declarations do not prove extraction fidelity. A context can match graph windows and still omit semantically necessary context.

## Closed records and bounds

Required `GRAPH` uses the actual graph validator. Optional `CENSUS` is recomputed against the full supplied reading artifact, hierarchy and dependencies. `CHALLENGES`/`ADMISSION` and `ASSESSMENTS`/`ASSESSMENT_ADMISSION` are paired and pass their existing validators; `REFINEMENT` uses its history checker. `FORMAL` replays the existing pure, unchanged, no-compaction adapter against pinned source and plan bytes. `NATIVE_RECEIPT` remains a three-pin evidence pointer. Unknown fields, unknown record names, missing dependencies or malformed optional records refuse rather than being ignored.

There are at most 11 fixed record types, each at most 1 MiB, at most 256 registry artifacts totaling 8 MiB, and the graph itself consumes a registry slot if it is not already present. At most 64 bases and locator sets are allowed; each locator set has at most 64 locator and eight revision artifacts. The canonical index is at most 65,536 bytes and SNE1 at most 20,971,520 bytes. A full reading that exceeds the artifact profile cannot be silently represented as a complete census. Whole original and base archive limits remain the existing 1 GiB and 2 GiB limits; this profile's tests do not qualify either maximum.

The CLI preserves stricter inherited limits while imposing 1 GiB address space, 64 MiB file output, 64 descriptors, zero core dump and 450-second CPU/wall limits. It emits at most 1 MiB of JSON and returns nonzero on refusal. Host filesystem integrity, native/tool trust and the inherited decoder's host assumptions remain prerequisites; these hashes do not attest a hostile host or prevent every external pathname race. Pure tests provide mocked integration evidence only. Native receiving, full-book semantic acceptance, independent reviewer authenticity and the original mission's comparative/human gates require separate evidence.


## Explicit OVERVIEW and semantic decoder source binding

`COMPLETE` remains the default display profile and preserves strict refusal when all typed nodes/relations cannot fit the existing display limits. `--display-profile OVERVIEW` is a distinct caller choice: the formula lists all main proposition symbols and explicitly labels the display an overview. It does not show every relationship in that short formula. The complete typed graph remains byte-exact inside the SNE source carried in `meaning.zip`. The generated `semantic-graph.md` alongside the package contains every node ID, kind, origin, documentary state, full proposed text and every declared edge, plus an inert escaped copy of the complete canonical graph. It is at most 8 MiB and create-only. The normal SAST formatter/metadata remain unchanged. An insufficient budget still refuses the whole share; no required symbol is silently dropped.

The new operational index schema is `sentinel/semantic-evidence-document/2`. It additionally declares `semantic_decoder_root_sha256` and an exact fixed source-pin roster, separately from the old SAST runtime/native identity. New `pack_bound`/`unpack_bound` require the receiver's independently held semantic source root. That root must come from the receiver's accepted installation/source review; adopting a sender's index root is not independent verification.

Actual CLI entry requires `--semantic-root` before the subcommand. A stdlib-only fresh-process bootstrap checks all fixed named source files before importing operative semantic dependencies, rejects already-imported operative dependencies, imports only those local trusted names, verifies their paths, refuses any imported local-tools module outside the fixed roster (at most 512 inspected modules), then checks all pins again. Files are held regular descriptors with `NOFOLLOW`/`NONBLOCK`, 1 MiB each, 16 MiB aggregate, and stable descriptor identity/size/time checks. The bundle and CLI also use the unchanged helper to compare their actual loaded top-level code object with compiled declared source. Existing core loaded-epoch guards remain. A later source or declared dependency mismatch refuses before accepting a bound payload or dispatching native work. Indexes cannot select or download code.

This establishes code-loaded-from-held-sources only under the stated trusted installation, single-owner filesystem and non-ABA assumptions. The package initializer was selected by Python before bootstrap; it and Python/stdlib/toolchain trust remain explicit prerequisites. These source pins do not attest a hostile host or the whole Python/OS runtime. Bound library entrypoints refuse an already-imported/unadmitted interpreter. Profile1 library pack/unpack remain explicitly unbound historical interfaces; their old source03 failure receipts are preserved. Source04 applies current graph/history checks to those interfaces without changing the identity claim of historical artifacts.

Optional challenge and assessment records now must bind the current graph and source set, not just a different graph present in the registry. A refinement history requires paired current challenges/admission, the same fixed test contract/source set and the current graph as its last candidate. Every historical raw answer, replay result and dependency impact is rechecked by the existing refinement replay function. A consistent-looking status label or self-minted history receipt is insufficient. Bundled admissions still do not become independently held authority.


Source04's initial 22-file bootstrap roster omitted the operative disjoint-context dependency. That failure and its observed positive CLI receipt remain retained with their original root; they are not full-closure acceptance. Source05 adds the unchanged `transport_document_context.py` to the 23-file fixed roster and checks imported local-module closure. Changing only that dependency invalidates the held root before imports. Standard Python import/bytecode-cache correctness remains a trusted-runtime prerequisite; source pins are not a proof of arbitrary loaded Python/OS state.

Injected MemoryError controls exercise fixed bounded `REFUSED`/`NONE`, nonzero exits in both fresh bootstrap and execute guards. They do not raise inherited memory limits. Actual allocator/OS failures can still prevent output delivery; a nonzero/incomplete process is never a qualified result.
