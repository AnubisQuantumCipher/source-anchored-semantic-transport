# QUORUM dependency component

The internal graph checker computes which declared dependents require review
after a node changes. It rejects missing indices, duplicate edges, invalid
types, limit exhaustion and cycles anywhere in the graph. A separate helper
orders event predecessors deterministically and refuses incomplete or cyclic
histories. Neither helper changes source records or grants authority.

Run the frozen development controls from the repository root:

```sh
python3 -I -S -B -Werror install/test_quorum_graph.py
python3 -I -S -B -Werror install/check_source.py
```

Use `--evidence /new/path/results.json` to retain every literal result from
the two development parity arms. The target must not exist. Both arms use
the same checker and annotations. This checks component parity; it does not
measure a benefit over original documents or exercise package extraction.

The [contract](contract.json), [independent oracle](oracle.json),
[edge-boundary addendum](oracle-addendum.json) and [prefeature review](review.json)
were frozen before implementation. Their original proposal/UNRUN labels are
preserved as authorship history; test results belong in separate receipts.

`tools/transport_quorum_graph.py` exposes `reverse_reachable(graph)` and
`predecessor_order(predecessors)`. It accepts decoded, caller-owned builtin
values within the contract limits; callers must not mutate them concurrently.
These functions are internal components, not raw-byte parsers or a public
QUORUM replay endpoint. They do not verify digests, quotations, interpretations,
assessor provenance, update authenticity or current applicability. The new
component is not yet part of the installed decoder bundle. The existing
decoder, native proof obligations and historical failures remain unchanged.

Formal proof of this Python component and complete replay integration remain
unproved. External validation and the full product acceptance gates remain
pending.
