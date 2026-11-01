# Portable independent accounting controls

The accepted reproduction entry point is `../run_tests.py`. It verifies the ZIP,
index and independent runner against fixed SHA256 pins, checks every explicit
archive member, and stages only verified data in a new private directory. Builder
sources inside the ZIP are retained inert data; archive code is never executed.
The separate trusted runner executes product source bytes checked against their
held digest through `compile` and `exec`; it does not load product bytecode caches.

Create a private scratch parent and pass that parent plus the accounting task's
capacity root explicitly:

```sh
python3 -I -S -B -Werror comparison/accounting/run_tests.py \
  --scratch-parent /ABS/PRIVATE_PARENT --capacity-root /ABS/TASK_CAPACITY_ROOT
```

The parent must be inside the capacity root. Admission accounts for the existing
allocated task footprint, pinned portable source bytes and a bounded staging
reservation. It refuses if the task would exceed 8 MiB or staging would exceed
4 MiB. It preserves the new staging directory and raw normal/optimized reports;
there is no automatic cleanup. Source and fixture data remain unchanged.

Both modes execute all 48 literal cases through the CLI, with 46 applicable API
cases. The optimized runner explicitly passes `-O` to its CLI children. UNKNOWN
work remains numeric-free, cumulative observations remain NONADDITIVE, ordered
attempts and exact measurement anchors are checked, and caller binding mutation
fails the tests. Original deterministic fixtures, proof obligations and expected
statuses remain unchanged.

The original 42 raw fixtures were frozen before implementation. Six boundary
fixtures were materialized afterward from the already frozen literal oracle
requirements. The ZIP preserves those exact raw identities. The B06 duplicate-ID
negative request retains historical private paths as inert data: duplicate IDs
must refuse before opening any referenced file. All successful CLI requests are
generated using the current verified extraction root.

The original portable suite and its historical receipt leave exact valid-input
byte-cap intersections and output-overflow reachability explicitly UNRUN.
Separate postimplementation [API boundary controls](boundary_check.py) now test
valid exact-cap plan and ledger inputs and an output-overflow refusal, in normal
and optimized modes. They read a pinned ZIP in memory without extraction; they
add no CLI boundary coverage. The original fixtures and receipt remain unchanged.

No model/human study, benefit, formal proof, authenticity, measurement truth or
final acceptance follows from these tests. Earlier recursive preparation code
and v4 runners are historical preparation evidence, not the accepted portable
execution path.
