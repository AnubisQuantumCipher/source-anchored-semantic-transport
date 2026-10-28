# Source-Anchored Semantic Transport

Carry a readable relational formula, its meaning keys, and the original evidence together.

One encoding produces a compact share text, a matched meaning ZIP, and a readable lexicon. The ZIP carries the exact sources, typed relationships, qualifications, uncertainty, provenance, operator definitions, and recovery instructions. The receiving decoder checks the pair and exposes the recovered material for a human or an AI to explain.

The [checked continuation case](docs/CHECKED_CONTINUATION.md) now follows a fresh agent from source retrieval to a proposed patch, exact submission, finite-domain behavior checks and separate source review. Both transport and the original-document baseline passed after a real submission defect was repaired. The initial failures remain available; this case does not show that transport outperforms the baseline.

This is an open-source implementation under the [MIT license](LICENSE), targeting Omarchy. It is a **development checkpoint**, with bounded local functionality and explicit acceptance limits. It is not an official client plugin, an Omarchy marketplace release, or a claim of complete natural-language understanding.

## What is implemented

- Source-anchored authoring with exact quotations or byte spans; ambiguous repeated quotations require an explicit location.
- Typed semantic records and scoped relations, including conditions, exceptions, quantifiers, attribution and uncertainty.
- Formula, lexicon and operator definitions that remain tied to the declared source entries.
- Create-only encoding, package validation, exact byte recovery, selected meaning-unit expansion, and readable export.
- Bounded archive handling and explicit refusals for changed identities, missing dependencies, unsupported versions and invalid input.
- An Ada/SPARK native component and a separate evaluator source tree. Proof scope is distinct from Python orchestration and language interpretation.
- A local CLI, a read-only MCP adapter, and a source-build installer that derives an exact runtime identity without editing the original source pins.
- A reusable handoff preparer and compact receiving client with a fixed session, checked inputs, and an unedited draft submission.
- An opt-in checked submission command that validates explicit field types, allowed values and unique action IDs before saving a draft.
- A bounded, typed Boolean-expression interpreter for fixture bindings: it checks proposed patches against supplied states without executing candidate Python code.

## Start

Follow [Installation](docs/INSTALL.md), then use the resulting command:

```sh
semantic-transport encode examples/authoring-v1/controller/authoring.json ./controller-output \
  --source SOURCE=examples/authoring-v1/controller/source.txt \
  --budget 1024 --reference 'attached:meaning.zip'
semantic-transport validate ./controller-output/share.txt \
  --archive ./controller-output/meaning.zip
semantic-transport recover ./controller-output/share.txt ./recovered.txt \
  --archive ./controller-output/meaning.zip --source SOURCE
cmp examples/authoring-v1/controller/source.txt ./recovered.txt
```

The encoder also writes `lexicon.md`, `plan.json` and `review.json`. Each output directory must be new. The budget counts Unicode code points in the **complete** share text, including its package identity, reference and newlines. It is not a platform-specific post-length guarantee. A budget that cannot fit the declared formula is refused; meaning is never silently dropped to make it fit.

Use an explicitly supplied ZIP alongside the share text. HTTPS references are bounded identifiers for separately supplied content; the decoder does not fetch them. A local path or placeholder is not public hosting.

## Three separate claims

| Claim | Contract |
|---|---|
| Exact source recovery | Recover retained bytes and compare them directly. Source and residual storage count in the package. |
| Structured meaning recovery | Check the explicit typed representation, spans, scopes, dependencies and transformations. Correct structure does not prove that a human-authored interpretation follows from the source. |
| AI narrative reconstruction | Evaluate the receiving agent's explanation against the original evidence. Fluency, an archive round trip, and model agreement do not establish completeness. |

The short formula is an entry point into the package. It cannot independently recreate details that only the package carries. Arbitrary input bytes can be retained, but arbitrary media understanding and complete semantic capture remain unproved. These small examples may cost more bytes and context than the original text; package size reduction is not the acceptance gate.

## Read next

- [Installation and uninstall](docs/INSTALL.md)
- [Authoring schema and examples](AUTHORING.md)
- [Package and semantic schema](docs/PACKAGE.md)
- [Assurance, tests and known failures](docs/ASSURANCE.md)
- [Repeated builds and package handoff](docs/REPRODUCIBILITY.md)
- [Fresh recipient trials, measured costs and remaining unknowns](docs/RECIPIENT_TRIALS.md)
- [Matched original-document and transport handoff comparison](docs/HANDOFF_COMPARISON.md)
- [Local handoff reader and deterministic controls](docs/HANDOFF_READER.md)
- [Prepare a receiving directory and use the compact client](docs/HANDOFF_CLIENT.md)
- [Validate a response contract and submit exact draft bytes](install/CHECKED_FINISH.md)
- [Missing-record trial and retained failures](docs/MISSING_RECORD_HANDOFF.md)
- [Three-hop comparison and its retained output failures](docs/REPEATED_HANDOFF.md)
- [Checked coding continuation, repaired submission and baseline comparison](docs/CHECKED_CONTINUATION.md)
- [Source review, interpretation gaps and governing records](docs/SOURCE_REVIEW.md)
- [Reproducible handoff with corrections, revocation and missing evidence](examples/handoff-v1/README.md)
- [Security boundaries](SECURITY.md)
- [Contribution rules](CONTRIBUTING.md)
- [License scope](LICENSE-SCOPE.md)

Use the exact decoder bundle and declared dependencies identified by a package. Independently rebuilt bundles are not assumed compatible. Digests detect changes; they do not authenticate an author, make a claim true, encrypt information, or grant permission to act.
