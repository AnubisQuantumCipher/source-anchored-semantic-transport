# Independent standard-export reader

These development fixtures were created by the existing qualified installed
producer. A separately implemented standard-library reader consumes the exports
without the producer's code or native executable. The qualification harness
holds originals separately and compares every recovered byte, including opaque
content, multilingual text, empty content and an incomplete typed reading.

```sh
python3 -I -S -B -Werror install/test_export_reader.py --evidence-dir /tmp/reader-controls-normal
python3 -I -S -B -O -Werror install/test_export_reader.py --evidence-dir /tmp/reader-controls-optimized
python3 -I -S -B -Werror examples/independent-export-reader-v1/reproduce.py /tmp/export-reader-results
python3 -I -S -B -Werror examples/independent-export-reader-v1/receipt.py --check
```

Use a new results directory. `reproduce.py` copies only the standalone reader and
export into each recipient directory. It invokes inspection and selected recovery
in normal and optimized Python, while the harness retains the source oracle.
This filesystem arrangement is not a hostile-process sandbox. No native decoder
is required to replay the frozen comparisons.

The exports retain producer/runtime declarations, but the reader never executes
or authenticates them. Explanations are manually authored, explicitly unverified
test data; this is not a new receiving-model narrative trial. The typed fixture
deliberately retains residual source content. Recovery does not upgrade that
reading to a complete semantic representation.

The producer invocation records identify the actual installed endpoint used.
`evidence/installed-before.json` and `installed-after-producer.json` record its
unchanged bytes. Their local paths are historical provenance, not dependencies
for replay. `evidence/contract.md`, `oracle.json` and `controls-oracle.json` were
frozen before reader implementation. The implementer received the contract but
not producer code or tests. The test author did not inspect reader code.

`evidence/accounting.json` counts full exports separately from original sources,
explanations and metadata. These exports add storage overhead. The matched
development baseline is direct original copies with the same source index and
supporting data. No task-time advantage, token saving, semantic superiority,
external user validation or product acceptance follows from these comparisons.

The receipt binds exact implementation, controls, fixture and observed result
bytes. Rechecking it confirms those bytes; rerunning the commands checks current
behavior. Neither replaces the outstanding complete proof, behavioral comparison,
external reproduction and human acceptance gates.
