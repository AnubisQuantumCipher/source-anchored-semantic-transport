# Source-Anchored Semantic Transport: authoring

Turn an explicit, source-linked reading into a matched share text, readable
lexicon and meaning ZIP. You write exact quotations instead of calculating
offsets. The compiler checks source identity, quotation occurrences and the
existing typed structure, then uses the existing package encoder and decoder.

This is an authoring interface. It does not infer a correct interpretation of an
arbitrary document. Source claims, instructions and historical approvals remain
data; successful compilation grants no permission to act.

## Encode a reading

From the source directory after following [Installation](docs/INSTALL.md) and putting the selected bundle on PATH:

```sh
semantic-transport encode \
  examples/authoring-v1/controller/authoring.json new-controller \
  --source SOURCE=examples/authoring-v1/controller/source.txt \
  --budget 4096 --reference attached:meaning.zip
```

The destination must not exist. One successful command publishes:

| File | Purpose |
|---|---|
| `share.txt` | Complete visible formula, package identity and reference |
| `meaning.zip` | Matched, source-preserving package |
| `lexicon.md` | Readable symbols and fixed operator definitions; also inside the ZIP |
| `plan.json` | Compiled input plan for the existing codec |
| `review.json` | Input/source/producer identities, source excerpts, declared structure, uncertainty and residual locations |

The authoring input is not a new package format. A recipient needs the matched
share/ZIP and the declared base decoder, not this authoring extension, this
conversation, or the original local source paths. A local attached file or an
`example.invalid` placeholder is not a public download link.

With the selected decoder bundle on PATH, validate and inspect a received pair, then
recover its source with the ID shown by inspection:

```sh
semantic-transport validate new-controller/share.txt \
  --archive new-controller/meaning.zip
semantic-transport inspect new-controller/share.txt \
  --archive new-controller/meaning.zip
semantic-transport recover new-controller/share.txt \
  recovered-source.bin --archive new-controller/meaning.zip --source SOURCE
```

`recovered-source.bin` must not exist. This uses only the base decoder and the
received pair. The optional separately distributed explanation exporter is not
required for these commands. Source bytes are authoritative; any AI explanation
must remain separately marked until its fidelity is evaluated.

For review before encoding, replace `encode` with `compile` and omit `--budget`
and `--reference`. It publishes only `plan.json` and `review.json`. Inspect the
source excerpts beside the formula and retain the input authoring document.
Review metadata exposes decoded bytes as base64 to preserve arbitrary bytes and
avoid treating embedded source markup as executable content.

## Write an authoring document

The closed JSON schema is `transport/authoring/1`. Its required top-level fields
are `schema`, `sources`, `interpretations`, `uncertainties`, `relations`, and
`meaning_units`. Unknown fields and versions refuse.

Source declarations have the existing `id`, `label`, `media_type`, `provenance`
fields plus a required lowercase `sha256` digest of the entire original byte
stream. The explicit `--source ID=PATH` arguments must match exactly. Compute
the digest with `sha256sum SOURCE_FILE`; do not normalize whitespace or encoding.
A change anywhere in a source refuses, even outside a selected quotation.
The source digest detects a change; it does not authenticate an author.

Outer interpretations, uncertainty records and relations retain the existing
[package contract](docs/PACKAGE.md). Replace each input anchor with:

```json
{"source":"SOURCE","selection":{"quote":"maintenance mode is active at arrival","at":null}}
```

`at: null` requires exactly one occurrence. When the quotation repeats, set `at`
to its original **UTF-8 byte offset**, not a character index. A missing quotation,
wrong offset, invalid Unicode or repeated occurrence without a selection refuses.
The compiler never chooses a likely occurrence or rewrites spelling or numbers.

For binary data or an empty source, use an explicit byte interval and the digest
of those exact selected bytes:

```json
{"source":"SOURCE","selection":{"span":[0,0],"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}
```

That example selects only an empty source. Intervals are half-open `[begin,end)`.
Binary references preserve bytes; they do not establish media understanding.

## Keep relationships explicit

Each typed unit retains the existing `id`, `source`, `interpretation`, `kind`,
`context`, and `plan` fields. Keep conditions, exceptions, scope, qualifications,
quantities, attribution and required context in the declared structure. An
instruction, a goal, a source claim, a historical approval, a revocation and an
unfinished action have distinct unit kinds. No kind authorizes execution.

The inner `transport/encoding-plan/1` or `/2` remains the existing grammar:

- `symbols` maps readable token names to exact source literals.
- Nodes remain ordered; arguments identify earlier nodes by index.
- Replace each node `span` and reference-mention `span` with a selection object.
- Replace a node `cue` with a selection object, or `null` for an explicitly absent cue.
- Replace ambiguity `span` fields with selection objects; keep their notes.
- Keep all other fields and the root unchanged.

For example, a literal node can be written as:

```json
{"op":"text","symbol":"DURATION","span":{"quote":"100","at":null}}
```

The exact operator dictionary and existing type checker still govern behavior.
There is no supplied code, operator override, dynamic import, or alternate
decoder. Use an opaque proposition and an explicit uncertainty when the current
operators cannot express a passage faithfully. Its original source survives;
that does not turn the opaque proposition into a complete semantic model.

An empty `meaning_units` list compiles to documentary plan version 1. A nonempty
list compiles to typed plan version 2. Documentary records are allowed, with
`interpretation_supplied` reporting whether any reading was supplied. They must
not be presented as a fully structured interpretation.

## What the checks establish

Compilation establishes exact source pins and occurrences, the admitted schema,
declared dependencies, existing type/binding checks and native-checked graph
compaction. The review retains the proposed/disputed/withdrawn statuses,
uncertainties, declared relationships, fixed definitions and residual locations.

It does **not** prove that a quotation entails its interpretation. A well-typed
but wrong choice of `if` versus `unless` is still possible. Broad operator cues
can cover source bytes without expressing their role. Even zero residual bytes
cannot establish semantic completeness. The report therefore keeps entailment,
completeness and context adequacy `UNPROVEN`, and execution authority `NONE`.

The authoring document's raw serialization is hashed, not included verbatim in
the meaning ZIP. Its compiled declarations are retained there. Preserve the
authoring document separately if its exact formatting or revision history matters.
The review binds the compiler's own file hash; the base runtime is separately
checked. Hostile concurrent same-user modification is outside this boundary.

The supported Python entry points are `compile_plan`, `compile_outputs`, and
`encode`. They validate untrusted inputs. `review` and `publish` are internal
composition helpers; neither is an independent verifier for arbitrary supplied
artifacts. Use the existing decoder to validate an issued share/ZIP pair.

## Bounds and refusal

Source and authoring-document limits are 65536 bytes each; there are at most
16 sources. Existing metadata, graph, dictionary and archive limits remain in
force. Review excerpts are deduplicated by exact source interval and their total
selected byte length is bounded at 65536; overlapping nonidentical intervals
count separately. No excerpt is silently dropped to fit the review.

Each output is at most 131072 bytes; all authoring outputs together are at most
393216 bytes. CLI memory/CPU/file limits match the local tools. Output publication
uses create-only atomic directory rename. Invalid input or insufficient budget
refuses before publishing a successful output directory. Disk/OS failure can
still prevent cleanup and must be reported; this is not a crash-durability proof.

The whole share budget counts Unicode code points, including its identity,
reference and newlines. No platform-specific counting compliance is asserted.
The compiler never shortens the formula to force a fit.

## Reproduce the checks

From the public source checkout, run the unchanged authoring suite with the other self-contained suites against a copied installed runtime:

```sh
python3 -I -S -B -Werror install/test_installed_regression.py \
  --bundle /absolute/path/to/installed-bundle \
  --evidence /absolute/path/to/new-regression-evidence
```

The installer derives this extension for its build-specific runtime. Follow
[Installation](docs/INSTALL.md) and retain that exact bundle for its packages.
No client, service, hosting configuration or package-manager state is changed.
