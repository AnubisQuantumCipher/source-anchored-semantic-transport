# Conventional transfer baseline

This is a working original-file transfer and recovery boundary for the matched
comparison. It gives the originals arm ordinary ZIP compression, verified cache
reuse and actual local `rsync` block deltas. It does not qualify the strongest
retrieval baseline or measure human work. The readable index is a file catalog.

## Prepare and recover

`transfer.py` accepts one canonical UTF-8 JSON request: sorted keys, compact
separators, no trailing newline, duplicate keys or floating-point values.

```json
{"current":[{"bytes":5,"id":"NOTICE","path":"/absolute/current.txt","revision":"v2","sha256":"<held lowercase SHA-256>"}],"prior":[],"schema":"transport/transfer-comparison-input/1"}
```

Every current and prior file must be supplied with its actual byte count and
digest. A claimed cache entry with missing or changed bytes refuses preparation.
Aliases and revision labels stay separate from deduplicated content objects.

```sh
python3 -I -S -B -Werror comparison/transfer/transfer.py \
  /absolute/request.json /absolute/private-parent/new-output
```

The parent must already be private and owned by the caller. Outputs are
create-only. Add `--with-rsync --expect-rsync-sha256 <independently-held-pin>` to
exercise the fixed `/usr/bin/rsync` binary. No network destination, arbitrary
command or source-supplied code is executed. Source files are checked again at
the end. Each available ZIP profile produces separate setup, cold and warm
archives and binding records. STORED and DEFLATE are required; unavailable
optional compression backends are reported explicitly.

The reusable `restore(archive_bytes, held_archive_sha256,
held_manifest_sha256, actual_cache)` API returns alias-to-original-byte mappings.
Cache keys are full SHA-256 digests of the supplied byte values. A warm archive
requires those exact cached values; it does not fetch missing objects. No ZIP
member is extracted as a filesystem path. Digests check integrity against the
held identity; they do not authenticate an author or establish currency.

## Accounting

Setup means empty recipient to the explicitly supplied prior state. Cold means
empty recipient to current state. Warm means that verified prior state to the
same current state. ZIP and rsync use identical current manifest/catalog bytes;
rsync uses stable alias paths so changed files can reuse matching blocks.
The setup transfer and its verification happen before the warm rsync transfer.

Count ZIP bytes **and binding bytes**. Setup costs are separate from per-update
costs. Rsync reports its actual protocol sent/received, literal/matched bytes,
elapsed time, command and complete log identities. These are different metrics
from the on-disk ZIP artifact size; neither is silently substituted for network
cost. OS page-cache state is uncontrolled. Selected helper/interpreter files
are counted separately; complete transitive dependencies, human work, model
tokens and monetary cost remain unmeasured. A smaller archive cannot establish
less total task work or a semantic advantage.

## Bounds and controls

Requests are at most 65536 bytes; each version has at most 32 aliases and 1048576
source bytes. Actual cache objects together fit 1048576 bytes. Archives fit
2097152 bytes; the sampled final tree plus report must fit 33554432 bytes before
successful completion. This aggregate check is not a hard filesystem quota
during rsync execution. The CLI sets address-space,
CPU and per-file limits; each local rsync call has a wall timeout. Imported APIs
enforce their explicit input checks but do not install process resource limits.
Stable private filesystem ownership and trusted Python/OS libraries remain
assumptions; this Python integration is tested, not formally proved.

```sh
python3 -I -S -B -Werror comparison/transfer/test_transfer.py
python3 -I -S -B -O -Werror comparison/transfer/test_transfer.py
```

The initial literal expectations were independently authored before the core,
but their original raw oracle was not retained during API-label finalization.
Its recorded digest remains in the current oracle; complete byte verification
of that earlier freeze is unavailable. The retained finalized oracle was held
before the first API controls. Controls retain malformed inputs,
incorrect pins, missing cache data, exact/over bounds, metadata changes and
multiple aliases for identical bytes. Same-checker bridge evidence is recorded
separately from the mechanics report. Neither source recovery nor checker
agreement establishes natural-language entailment, current authority, human
benefit or external validation.

Local qualification uses Python 3.14.7 and rsync 3.5.1-g04355d27 on Linux aarch64.
The actual rsync controls require the exact held executable digest; other hosts
report those controls skipped/UNRUN. The Ubuntu Python 3.14.10 CI job exercises
portable controls and checks retained evidence identities. A green CI job does
not establish that the local pinned rsync or native decoder ran on that host.

## Frozen checker bridge

`bridge.py` restores eight caller inputs from a conventional warm DEFLATE ZIP
and explicit prior cache, then runs the unchanged qualified checker. Each arm's
complete stdout must equal its corresponding frozen published result; no result
fields are normalized away. The original and transport results have different
request identities, so their complete stdout is not interchangeable.

The harness takes explicit `--original-invocation`, `--transport-invocation` and
`--observations` paths. It hardpins the accepted full invocation and expected
output bytes. It also needs the exact externally declared decoder installation,
source root, checker files, Python and OS dependencies. These are recorded in
the bridge receipt; the harness does not substitute a newer runtime. Reproduction
is local to that qualified dependency set, not a portable client acceptance.

```sh
python3 -I -S -B -Werror comparison/transfer/bridge.py \
  /dev/shm/semantic-transport-transfer-comparison-20261029/bridge-01/NEW_RUN \
  --original-invocation "$HELD_ORIGINAL_INVOCATION" \
  --transport-invocation "$HELD_TRANSPORT_INVOCATION" \
  --observations "$HELD_PUBLISHED_OBSERVATIONS"
```

The private output parent must exist; the run directory must be new. The first
harness run refused a mismatched file-resource limit before checker execution.
That refusal is retained. Transfer preparation and checker replay now use their
separate existing resource profiles. Coherent tampering with either invocation
or expected stdout is tested at the prelaunch boundary, with zero child calls.

The [owner observations](evidence/owner-observations.json),
[independent review](evidence/independent-review.json) and
[bridge result](evidence/bridge-final-result.json) retain the exact tested scope.
The observed DEFLATE artifacts are included with their binding records:

| Phase | ZIP bytes | Binding bytes |
| --- | ---: | ---: |
| [Setup](evidence/deflate9-setup.zip) | 1703 | 379 |
| [Cold](evidence/deflate9-cold.zip) | 11219 | 379 |
| [Warm](evidence/deflate9-warm.zip) | 10384 | 379 |

These are artifact measurements, with setup and reader dependencies separate.
The [complete transfer report](evidence/bridge-transfer-report.json) preserves
all available compression profiles, actual local rsync statistics and timing.
No model or human task-cost result is inferred from these byte counts.

```sh
python3 -I -S -B -Werror comparison/transfer/receipt.py --check
```

That command checks source and retained observation identities; it does not
rerun the checker, perform formal proof or approve a product release.
