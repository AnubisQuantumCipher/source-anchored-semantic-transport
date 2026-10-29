# Exact task and input context

This component checks that a declared assessment input contains the intended
task, claim revision, sources, dependencies, registry, rules, prompt and settings.
Every digest-bearing reference uses the complete canonical record and its type.
A raw response cannot become a prompt by reusing its payload digest.

The internal interface is:

```python
check_context_bindings(body_raw, originals, held_update_pins)
```

It first runs the existing input, source, claim and change-impact gates. It then
checks global identifiers, canonical array order, static Seat declarations,
Task rosters and source sets, conflict labels, and every InputManifest including
unused manifests. Multiple revisions of a claim remain distinct. Ordered guard
operands and history links retain their order. Missing, stale or wrong-type
references return explicit errors; no context is fetched or inferred.

`body_raw` contains complete canonical Body bytes. `originals` is the exact tuple
of `(alias_id, SourceKey, immutable_bytes)` accepted by the source component.
`held_update_pins` contains the separately supplied event pins required by the
impact component. Missing held pins cannot be reconstructed as trusted inputs.
The [contract](contract.json) and [design addendum](design-addendum.json) define
the exact interface, refusal order and unchanged resource bounds.

The returned record index identifies records structurally. Dynamic Reading,
RunEvidence, Challenge and Withdrawal references are explicitly deferred; their
presence in that index does not make them valid assessment inputs. Declared
identity evidence remains unauthenticated, and opaque source contents cannot
establish temporal independence. No decoded instruction grants permission.

Run from the repository root:

```sh
python3 -I -S -B -Werror install/test_quorum_context.py
python3 -I -S -B -O -Werror install/test_quorum_context.py
python3 -I -S -B -Werror examples/quorum-context-v1/prepare_receipt.py --check
python3 -I -S -B -Werror install/test_quorum_impact.py
```

The suite compares complete frozen outputs, including independent substitution,
namespace, ordering and refusal-precedence cases. Hostile caller types and
ownership checks exercise the public boundary. Synthetic helper probes are
labeled separately and do not prove public-input reachability of every bound.
First runs, preparation failures and prior receipts remain available. Original
annotation and transport projection use the same checker and annotations;
this development parity is not evidence of a transport advantage.

The receipt binds the tested source and independently observed results. This is
tested Python, not a new SPARK proof. Installed decoder files remain unchanged.
Full replay must still enforce its own frozen global gate order, runtime and
externally held identities; chaining component interfaces is not that proof.
External validation and measured benefit remain pending.
