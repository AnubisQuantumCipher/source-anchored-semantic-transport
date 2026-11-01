# Matched source retrieval

Both original files and a verified meaning ZIP can now feed one retrieval core
with the same held annotations. The core finds literal or ranked text matches,
returns complete declared units and their cross-source dependencies, pages exact
original bytes, and traces declared versions without choosing a governing one.
This closes a comparison-interface gap; it does not establish a benefit over
originals or validate a natural-language interpretation.

## Core interface

```python
corpus = Corpus(source_id_to_bytes, canonical_annotation_bytes, held_annotation_sha256)
try:
    response_bytes = corpus.call(canonical_request_bytes)
    separate_costs = corpus.metrics()
finally:
    corpus.close()
```

Use `retrieval.py` from this directory. Its only project dependency is the exact
approved `install/prepare_quorum_replay.py`; the module checks that helper before
loading its bounded canonical-JSON parser. Python, its standard library, SQLite
when requested, and the operating system remain trusted dependencies. No payload
selects a program, imports code, fetches a resource, or grants execution authority.

The [input contract](contract.json) and [response contract](response-contract.json)
fix closed fields and named refusal outcomes. JSON uses compact UTF-8, sorted
keys, no final newline on inputs, no duplicate keys, floats, negative integer
literals or non-finite values. Signed quantities can remain exact source bytes
or explicit strings; this interface does not reinterpret them. Responses end in
one LF. A snapshot digest binds the exact annotations and sorted source pins.
Every response states `authority=NONE`, `freshness=UNKNOWN`,
`context_adequacy=UNPROVEN` and that its content is untrusted data.

| Action | Purpose |
| --- | --- |
| `catalog` | Original identities, complete annotation records and unresolved dependency IDs. |
| `search` | Paged discovery; source and annotation matches have distinct origin labels. |
| `query` | All matching unit seeds plus their entire declared dependency closure. No hidden top-k. |
| `expand` | Complete selected units and every reachable declared dependency. |
| `page` | At most 4096 exact original bytes, including opaque data or split UTF-8. |
| `trace` | All explicitly related versions, conservative byte-change enclosures and changed dependency bindings. |

A search/query request supplies `query`, `mode`, explicit `sources`, and `field`
(`source`, `annotation`, or `both`). Search additionally supplies `offset` and
`limit`. For example:

```json
{"action":"query","field":"source","mode":"exact_phrase","query":"100 ms","sources":["S_CTRL_NEW"]}
```

Literal phrases and ASCII-space-separated token conjunctions are case sensitive
and byte preserving. Filters restrict matching seeds, never required dependency
closure. Missing or cyclic reachable dependencies refuse the whole expansion.
No-match remains unknown. Unannotated full-source hits stay visible; they do not
create invented meaning units. Unit boundaries and dependency links are supplied
by the author and remain unproved interpretations. Cataloging unresolved links
is not successful validation of a semantic package.

Optional `fts5` uses SQLite `unicode61 remove_diacritics 0`, token conjunctions,
parameter binding and BM25 ranking with stable source/unit/origin ties. Supplied
SQL and MATCH operators are never executed. Its matching normalization does not
change original bytes or assert semantic equivalence. It refuses explicitly when
unavailable, over budget, or unsuccessful; it never substitutes another lane.
SQLite documents a silent token truncation limit. The implementation therefore
uses the more conservative raw run limit of 8192 bytes between definite ASCII
whitespace separators, allowing for Unicode folding growth. Larger valid source
runs still work through the literal modes. The source review supporting this
guard is recorded separately from any formal proof or installed-library source
attestation. See [SQLite FTS5](https://sqlite.org/fts5.html) and its
[Unicode tokenizer source](https://github.com/sqlite/sqlite/blob/master/ext/fts5/fts5_tokenize.c).

## Limits and receiving adapter

The existing product bounds remain: 16 sources and 65536 aggregate original
bytes, 16 declared units, 64 dependency edges and 65536 annotation bytes. Requests
fit 65536 bytes; responses fit 131072 bytes including LF. An expansion that cannot
fit refuses without truncation; original byte pages remain available. A corpus
processes at most 32 calls including refusals, then returns a saturating refusal.
Search offsets are explicitly limited to 0..16, sufficient for this unit bound.

The local adapter adds fixed helper, interpreter, manifest, source and decoder
checks before passing the recovered bytes and the identical external annotations
to this core. It accepts the qualified local decoder bundle named in its source;
that exact local dependency has not been replaced with a supposedly compatible
rebuild. Original files do not need a decoder installation. Each adapter instance
requires a fresh process. Its CLI enforces address-space, CPU and file bounds plus
a 30-second worker wall bound. Its schedule aggregate output bound is 131072
bytes; this is distinct from the core's per-response bound. Imported core/API
callers must enforce appropriate outer process limits themselves. Python/SQLite
allocation is bounded operationally, not statically allocated or formally proved.

```sh
python3 -I -S -B -Werror comparison/retrieval/adapter.py \
  --manifest /absolute/manifest.json --expect-manifest-sha256 "$HELD_MANIFEST" \
  --annotations /absolute/annotations.json --expect-annotations-sha256 "$HELD_ANNOTATIONS" \
  --expect-core-sha256 "$HELD_CORE" --requests /absolute/requests.jsonl \
  --metrics /absolute/new-cost-record.json
```

Stdout contains the unchanged canonical core responses. Timing and carrier costs
are written separately, create-only. Neither path authenticates the author,
checks current permission, or protects against a hostile owner of the host.
Version/revocation labels remain source declarations; stored approval is data.

## Reproduce and interpret the evidence

Portable core tests and retained-record checks run without the native decoder:

```sh
python3 -I -S -B -Werror comparison/retrieval/run_tests.py
python3 -I -S -B -O -Werror comparison/retrieval/run_tests.py
python3 -I -S -B -Werror comparison/retrieval/prepare_receipt.py --check
```

The portable runner passes 71 controls in normal and optimized Python locally,
including 13 strict FTS controls that require actual matching/ranking rather
than accepting an optional-capability refusal. Local versions are Python 3.14.7
and SQLite 3.53.4. CI uses Ubuntu x86_64 with Python 3.14.10; its portable core
checks do not execute the locally pinned native decoder.

The original independent test source and literal oracle remain unchanged. The
runner supplies portable copies of their initially local archive evidence.
The first core execution failed the declared refusal spelling for a Boolean
page offset. Both failures and the unchanged tests are retained; the corrected
core passes the same requirements. Earlier static-review findings and repaired
adapter preparation checks are also retained.

With the exact approved existing local decoder and its dependencies, reproduce
actual codec preparation and matched import in a **new** scratch child:

```sh
python3 -I -S -B -Werror comparison/retrieval/test_adapter.py prepare \
  --root /dev/shm/semantic-transport-retrieval-20261029/new-run
python3 -I -S -B -Werror comparison/retrieval/test_adapter.py run \
  --root /dev/shm/semantic-transport-retrieval-20261029/new-run \
  --expect-core-sha256 "$HELD_CORE" --attempt attempt-01
```

Preparation freezes the oracle-derived expectations before actual encoding.
The runner checks those original pins before and after execution. The transport
carrier contains exact sources, while both arms receive the same external
annotations, counted separately. The harness checks full returned unit bytes,
metadata, closure, opaque pages and version traces against the source fixture;
byte-identical arm responses alone are not its only check. Manifest, annotation
and core pin tampering, executable-helper selection and decoder substitution
must refuse.

Local actual-codec results: SC_MAIN returned 18 responses totaling 40400 bytes;
SC_NEG returned 6 totaling 10094 bytes. Each complete response stream matched
between the original and transport arms. These runs used literal modes, without
an FTS index. They do not establish portability of the pinned native decoder.

| Scenario | Original carrier bytes | Transport share + ZIP bytes | Same external annotations bytes |
| --- | ---: | ---: | ---: |
| SC_MAIN | 2269 | 21664 | 7898 |
| SC_NEG | 2016 | 19161 | 6444 |

Carrier, annotations, setup, source recovery, per-query time and optional index
size are separate observations. These fresh-process runs leave host cache state
uncontrolled. Selected implementation/interpreter dependencies are accounted
separately in the receipt; full transitive setup, model tokens, monetary cost,
human preparation/maintenance and total task work remain unmeasured. These
fixtures favor originals in carrier size; no superiority claim follows.

This public development corpus spans personal notes, multilingual text,
conditional timing, parallel reviews, attributed uncertainty, quantities,
revocation data, broken dependencies and opaque bytes. It is not a fresh holdout
or external-user trial. A stronger original-document workflow can also use native
search/navigation without this API's session cap. Qualification against that
strongest eligible workflow and prespecified total-work/uncertainty gates remains
open. Ada/SPARK source and proof obligations are unchanged; these Python and
SQLite checks add no whole-system or semantic-completeness proof.
