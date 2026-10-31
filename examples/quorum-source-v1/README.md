# Exact sources and quotation membership

This internal component checks original source bytes, embedded Blob encodings,
and byte-span quotations after canonical Body validation. It reports `MATCH`,
`DIFFERS`, or `EMPTY_SOURCE_MATCH_NONPROBATIVE` for each valid selector. A
self-consistent quotation digest cannot make a quotation match a different source.

```python
from transport_quorum_source import check_source_membership

result = check_source_membership(body_bytes, (
    (source_alias, complete_source_key, original_bytes),
))
```

The input must contain immutable bytes and exact builtin tuples and key
dictionaries. `contract.json` specifies the closed interface, refusal order and
bounds. No source text is executed or interpreted. The output contains identities
and indexes, not source or quotation content. Authentication stays `UNVERIFIED`,
authority `NONE`, and freshness `UNKNOWN`.

Body bytes consume the reserved metadata source slot. Every supplied source copy,
including equal copies under separate aliases, counts against the existing source
count and byte limits. The implementation checks encoded lengths before decoding
scratch data. Canonical JSON Blobs have the explicit bounded numeric/depth profile
in the contract; original source bytes remain opaque.

From the repository root:

```sh
python3 -I -S -B -Werror install/test_quorum_source.py
python3 -I -S -B -Werror examples/quorum-source-v1/prepare_receipt.py --check
python3 -I -S -B -Werror install/test_quorum_input.py
python3 -I -S -B -Werror install/check_source.py
```

`oracle.json` binds 18 complete expected result envelopes. `focused/` retains
49 independently prepared controls, their raw candidates, manual expectations,
and separate stdlib observations. Both sets were frozen before implementation.
The reviewer added refusal-order, resource and hostile host-key controls, which
also run in CI. Two first implementation defects are retained with their fixes:
the invalid-alias error code and decoded-budget refusal order.
The test harness applies the same checker and annotations to original-document
and transport development arms; this checks parity and does not measure benefit.
Historical absolute paths in preparation records identify where evidence was
created. The repository tests use only local portable fixtures.

This component is not integrated into the installed decoder yet. Full replay
reference closure, claim comparison, update effects and aggregation require their
remaining checks. Byte membership does not prove entailment, semantic completeness,
currentness or authority. Python execution is tested, not formally proved; the
existing Ada/SPARK assurance and its separate scope are unchanged.
