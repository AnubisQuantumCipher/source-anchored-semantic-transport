# Check a declared reading against a structured source

This internal checker compares five explicit fields: subject, action, modality,
condition and exception. It detects changed actors, removed negation, changed
permissions and dropped exceptions when those distinctions are present in the
declared structures.

```python
from transport_quorum_claim import check_claim_structure

result = check_claim_structure(body_bytes, (
    (source_alias, complete_source_key, original_bytes),
))
```

The checker first verifies the complete source/Blob/quotation boundary. Structural
comparison requires exactly one selector that matches an entire nonempty source
in the pinned `DeclarationSource` format. Partial scope remains unresolved;
an unequal quotation cannot qualify a reading. Opaque prose remains explicitly
unsupported by this comparison. Nothing extracts a declaration from prose.

Both the claimed and original condition trees must have valid backward references
and no unreachable nodes. Both sides' external references require explicit links
to exact supplied source versions. A difference between the structures does not
excuse a missing definition. Ordered operands remain ordered; no Boolean
simplification hides a changed representation.

Run from the repository root:

```sh
python3 -I -S -B -Werror install/test_quorum_claim.py
python3 -I -S -B -Werror examples/quorum-claim-v1/prepare_receipt.py --check
python3 -I -S -B -Werror install/test_quorum_source.py
python3 -I -S -B -Werror install/test_quorum_input.py
python3 -I -S -B -Werror install/check_source.py
```

`oracle.json` binds 22 complete manual results. `focused/` contains 45 independently
frozen minimal pairs, including negation, exception, actor, scope and dependency
controls. Historical preparation paths are provenance only; tests load the
portable repository fixtures.

`MATCHED_DECLARATION_STRUCTURE_ONLY` means exact identity of the explicit structures.
It does not establish natural-language entailment or correct interpretation.
Primary-source anchoring requires a `SOURCE` dependency. Other declared roles can
bind an exact reference identity, with `semantic_role_relevance=UNPROVEN` retained.
Full reference closure and applicability are not evaluated by this internal stage.
The installed decoder and full replay acceptance remain separate unfinished work.
