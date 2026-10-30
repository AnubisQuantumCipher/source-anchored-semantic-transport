# Closed semantic core, grammar 3

This profile assigns a denotation to a bounded formal formula in a supplied finite
model. It does not establish that the model describes the world or that an authored
formula captures an arbitrary document. The transport archive remains a courier.
`transport/meaning/1` and `/2` and their operator dictionaries remain documentary.
Their accepted definitions and exact runtime bundles are unchanged.

The implementation extends `Transport_Eval.Step` and `Evaluate` in Ada/SPARK.
Python checks source bindings, types, dictionaries and package identity and packs
the native input; it does not calculate truth or obligation outcomes. Native proof
and test status must be read from the accompanying source-bound qualification
receipt, not inferred from this document or a successful build.

## The closed fragment

One grammar identifier: `transport/meaning/3`. Topologically ordered nodes have a
final root; all nodes must be reachable. There are no implicit variables, inferred
arguments, arithmetic, clocks, substitutions or general quantified bodies.

| Operator | Inputs | Result and denotation |
|---|---|---|
| `pred` | Declared predicate, ordered ground terms | Fact from exact tuple lookup |
| `not` | Fact | Strong Kleene negation |
| `and` | Fact, Fact | False if either False, True if both True, otherwise Unresolved |
| `if` | Fact, Fact | Strong Kleene material implication; False only for True then False |
| `all(P,D)` | Unary predicate, explicit finite domain | Universal fold of tuple values; empty domain True |
| `some(P,D)` | Unary predicate, explicit finite domain | Existential fold of tuple values; empty domain False |
| `must` | Fact | Norm: True→Satisfied, False→Violated, Unresolved→Unknown |

Every Norm retains `Truth=Unresolved`. `must(p)` never changes the value of `p`.
Norms cannot be passed to `not`, `and`, `if`, another `must`, or a quantifier.
Satisfaction of a material conditional can be vacuous: a false event or a true
exception can make the conditional satisfied without the action occurring.
No result grants execution authority or establishes permission.

A model declares terms, predicates of arity zero through two, named finite domains,
and tuple reports. Terms, predicates and domains share a unique namespace bounded
by 64 symbols. There are at most 256 nodes and 256 tuple rows. Domain membership is
explicit and unique. A missing tuple is Unresolved. Conflicting True/False reports,
or an explicit Unresolved report alongside a known report, remain Unresolved.
Duplicate identical reports are rejected. These are open-world tuple rules over
explicit finite quantifier domains; there is no inference about unlisted objects.
Floats, unsupported fields, wrong roles, wrong arity and incompatible versions fail
closed. The same bounds and role checks apply at the native boundary.

## Source translation is a separate check

The controlled profile accepts exactly one complete sentence:

```text
REQ-AUDIT: When a valid sample arrives, the controller shall append that sample to the audit log, unless maintenance mode is active.
```

The optional exception is represented as:

```text
must(if(and(EVENT(), not(EXCEPTION())), ACTION(ACTOR)))
```

Without an exception the guard is `EVENT()`. Exact byte spans bind every role to its
source phrase. The source identifier is metadata, not another asserted fact. The
parser checks the entire sentence, with at most one trailing newline. It accepts
bounded ASCII word phrases and a defined list of reserved-word exclusions. The
phrases are **opaque model labels**: the parser does not resolve pronouns, infer
lexical meaning, identify real events, or certify that a report of an action is true.

For a matched source the authored tree **and** role bindings must exactly equal the
parser's result, including operand order and actor identity. Even a `declared` plan
cannot bypass that equality. An unsupported source can still travel with an explicit
formal reading in `declared` mode, with `translation=NOT_IN_FRAGMENT` and source
semantic completeness UNPROVEN. Its formal formula may be evaluated in its model;
that does not evaluate the prose. `requirement` mode refuses unsupported input.

The existing requirement containing `within 100 ms` is unchanged and outside this
fragment. No deadline is stripped to make it pass. Cause, belief, attribution,
recommendation, permission and temporal operators retain their documentary profiles.

## Package and receiving workflow

The existing ZIP contains retained source frames named `SOURCE`, `CORE`, and, when
supplied, `MODEL`. `CORE` contains the versioned formal plan, exact operator dictionary,
source digest, model digest, translation result and required evaluator identities.
`MODEL` carries the complete finite structure, including its symbol definitions.
The ordinary manifest covers these bytes without changing the archive profile.

The canonical `share.txt` remains the operative package reference. `lexicon.md`
contains the formal reading and operator definitions. The evaluator first invokes
the declared original decoder, verifies package identity, recovers those source
frames, checks all bindings and dependencies, then invokes only the caller-selected,
digest-pinned native evaluator. Archive instructions never select executable code.
A changed model, dictionary, source, package, helper or evaluator is refused.
No model means `NOT_EVALUATED`, `semantic_scope=NONE_NO_MODEL`, with no truth or
norm outcome. Source interpretation stays `PROPOSED_STRUCTURED_READING`, including
when the formal formula has an evaluated denotation in its supplied model.

The current canonical share is the courier's source/interpretation index and
package key. The formal node expression is in `lexicon.md` and `CORE`; the share
index itself does not acquire grammar 3 semantics. The [frozen example and
qualification receipt](../examples/semantic-core-v3/README.md) provide the matched
share, archive, source, model and receiving result.

The native STC3 frame and each native result are retained in the private work
folder. Results bind package, payload, source, model, frame and evaluator digests.
Hash integrity is not authorship, world truth, legal force, secrecy or permission.
A separate entailment procedure is not implemented: its status remains NOT_CHECKED.
QUORUM agreement does not turn these model-relative results into world facts.

## Local commands

Use the existing qualified decoder bundle and a separately built core executable.
They are explicit dependencies, not paths or code supplied by an archive. The core
CLI is `python3 -I -S -B -Werror tools/transport_core_cli.py`. Its `draft` command takes
`--source SOURCE --output PLAN`; `encode` takes `--source`, `--plan`, optional `--model`,
`--decoder`, `--decoder-sha256`, `--native`, `--native-sha256`, and a new `--work` folder.
`evaluate` uses the same pinned dependencies and a new work folder with `--share` and
`--archive`. Work-folder parents must be private mode 0700. Output is create-only;
failed work is retained. `--budget` counts the complete share in Unicode code points,
including reference and digest; it does not claim a platform-specific counting rule.

Build with the project's GNAT environment and `gprbuild -P evaluation/transport_core.gpr`.
Set `TRANSPORT_CORE_OBJ` and `TRANSPORT_CORE_BIN` to explicit private output folders;
set `TMPDIR` to the admitted temporary directory. Tests use
`evaluation/transport_core_checks.gpr`. Proof uses the same core project with `-U`,
strict warnings and the recorded resource limits. Keep all prior evaluator and parser
checks. The qualification receipt supplies exact commands, source pins and failures.

Python regressions are `tests/test_transport_core.py`,
`tests/test_transport_core_language.py`, and `tests/test_transport_core_bridge.py`.
Native and integration groups require explicit dependency paths and digests; a skip
is not a pass. See each test's environment contract and the recorded invocation.

## Claim boundary

The semantic claim is the denotation of this closed formal grammar under its exact
supplied model. Source translation conformance, source byte recovery, interpretation
adequacy, authentication and factual truth are separate obligations. Arbitrary source
meaning and whole-system proof remain UNPROVEN. Existing failed receiving trials and
external validation requirements remain in force.
