# Clean native proof reproduction

These records test whether the published native source can be built and proved
with fresh project objects, rather than relying on the accepted incremental
proof session. The native source, contracts, solver settings and proof oracle
remain fixed. The Python supervisor is a separately tested integration boundary.

| Record | Observation | Outcome |
| --- | --- | --- |
| [First](first/README.md) | A runtime entry was rejected as special; its precise path, type and creator were not captured. | FAILED; no complete proof result |
| [Second](second/README.md) | The supervisor incorrectly required generated temporary directories to persist after the build. | FAILED; proof NOT_RUN |
| [Third](third/README.md) | A listed temporary `.s` file disappeared before metadata inspection. | FAILED; build interrupted; proof NOT_RUN |
| [Fourth](fourth/README.md) | Build succeeded; the global process census exhausted its fixed rounds on a disappeared PID whose membership remains UNKNOWN. | FAILED; proof interrupted before a complete summary |
| [Fifth item](fifth/README.md) | A frozen cgroup supervisor candidate passed 69 selected controls per Python mode. Its live-control harness and exception qualification remain incomplete; reviewer failures are retained. | Native NOT_RUN; no task or launch admission |

Each attempt retains its source and tool identities, launch and process records,
raw streams, controls and independent engineering review. Later complete cleanup
does not convert an earlier failed observation into success. The first
collation's original diagnosis is qualified by the additive
[correction](first/collation-diagnosis-correction.json): its exact cause remains
UNKNOWN.

The data archives contain regular files only. Their indexes list intentionally
omitted special test entries. Native task objects, executable binaries and proof
caches are excluded. The second archive retains four supervisor `.pyc` files as
inert data; nested ZIPs are also opaque. Historical local paths and identities
remain in the receipts. Membership and hash checks execute no archived content.

The original exact local proof oracle requires all 1368 checks, comprising
342 flow and 1026 prover checks across 21 unit rows, with no justified or unproved
checks. That oracle is not reduced when supervision fails. These counts describe
the scoped SPARK contracts, not natural-language entailment, complete semantic
capture, Python correctness or a benefit over original documents.
