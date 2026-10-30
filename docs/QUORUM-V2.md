# Recorded assessment policies

QUORUM version 2 computes a declared assessment threshold from externally held
run bindings. It supports up to nine seats and preserves every submitted reading,
including dissent, abstentions, duplicates and withdrawn records. Version 1 replay
and the native semantic evaluator are unchanged.

The result answers: **do these admitted recorded assessments meet this policy?**
It does not decide whether the source claim is true, whether a narrative entails
the source, or whether an agent may act.

## Inputs and trust roots

The pure API takes four raw JSON documents:

| Document | Purpose |
| --- | --- |
| `policy` | Required seats, support threshold, supporting-family threshold, exact claim/task/source-set context |
| `registry` | One externally assigned model and family for each required seat |
| `admissions` | Stable run identities, exact reading/response/prompt/settings bindings, origin and withdrawal state |
| `ballot` | The complete candidate readings and their response text |

The caller supplies the exact SHA-256 of the first three documents separately.
Those values must come from the caller's chosen trust channel, not the candidate
package. Computing them from an unknown package and immediately trusting them
does not authenticate anything. The verifier checks relative integrity against
the supplied roots. Protecting and choosing those roots remains the caller's job.

The family registry controls the policy's grouping. A family name in a candidate
cannot override it. Matching a held registry is not provider authentication or
evidence that different assessors have independent errors. `OBSERVED_ONLY`,
`SYNTHETIC_ONLY` and `MIXED` classify the externally held origin declarations.

An admission binds the canonical bytes of the entire reading, including its
stance. It also binds the raw response digest. The verifier hashes the supplied
UTF-8 response text, but does not interpret prose to infer whether it supports
the declared stance. Prompt, settings and source pins are references in the pure
policy interface; the live replay adapter adds the source/package checks below.

The exact closed shapes, bounds, canonicalization and result meanings are in
[`quorum-v2-contract.json`](quorum-v2-contract.json). Input JSON whitespace is
allowed; held roots cover the exact input bytes. A reading digest uses UTF-8
canonical JSON with sorted keys, compact separators and no terminal newline.

## Policy behavior

Every required seat must have one eligible reading. An abstention supplies
attendance but contributes no support. Eligible opposition or dispute blocks
the threshold. Only eligible supporting seats contribute to the supporting
family count.

Multiple candidate records for the same seat or stable run are all excluded;
none wins by ordering. Duplicate keys in the externally held registry or run
admissions refuse the document. Identical response text from distinct admitted
runs is allowed. Missing admissions and withdrawn readings remain visible and
ineligible. Ineligible dissent remains visible but does not veto.

The first applicable verdict is:

1. `MISSING_ELIGIBLE_SEATS`
2. `BLOCKED_DISSENT`
3. `INSUFFICIENT_SUPPORT`
4. `INSUFFICIENT_FAMILY_DIVERSITY`
5. `RECORDED_SUPPORT_THRESHOLD_MET`

All failed conditions are returned, not only the first. The output distinguishes
whether the policy requires multiple families, whether supporting readings span
multiple assigned families, and whether a policy requiring them actually passed.

## Local CLI and API

No installation or network service is required. From the repository root:

```sh
python3 -I -B tools/transport_quorum_v2.py \
  --policy=examples/quorum-v2/source-replay-example/policy.json \
  --registry=examples/quorum-v2/source-replay-example/registry.json \
  --admissions=examples/quorum-v2/source-replay-example/admissions.json \
  --ballot=examples/quorum-v2/source-replay-example/ballot.json \
  --expect-policy-sha256=0ec0dad504fb1af52a6bbc7c30019c975d6756c4143723f63f6a0fb6d46299b8 \
  --expect-registry-sha256=d5795decce33a00e3f532084555848239536858ffd428673efe1a9719666a774 \
  --expect-admissions-sha256=266c0eb4a157c6bd9a406e523078030bd543eb2e4271568d6e67556979519aa6
```

This example is explicitly synthetic. It establishes executable policy behavior,
not external assessors or provider identities. The standalone CLI exits zero
when evaluation completes, including an unmet threshold, and exits two for a
refusal. Consumers must inspect `verdict`, not infer a passed threshold from the
process exit code.

For a trusted local Python caller, add the repository's `tools` directory to its
module search path and call:

```python
from transport_quorum_v2_policy import evaluate
result = evaluate((policy_bytes, registry_bytes, admissions_bytes, ballot_bytes),
                  {"policy": held_policy_sha256,
                   "registry": held_registry_sha256,
                   "admissions": held_admissions_sha256})
```

## Live source replay

`tools/transport_quorum_v2_replay.py` accepts the same policy arguments plus:

```text
--bootstrap=/absolute/path/install/transport_quorum_bootstrap.py
--expect-bootstrap-sha256=<held admitted bootstrap digest>
--invocation=/absolute/path/to/prepared-v1/invocation.json
--expect-invocation-sha256=<held invocation digest>
--request=/absolute/path/to/prepared-v1/request.json
--expect-request-sha256=<held request digest>
--claim-id=CLAIM_A
--revision=V1
```

Prepare the V1 invocation through the existing qualified replay workflow. The
adapter accepts only the original admitted bootstrap and fixed checker/helper,
interpreter, runtime and source identities in
[`quorum-v2-replay-admitted.json`](quorum-v2-replay-admitted.json). Physical paths
may relocate. A caller's hash of different code does not admit that code.

The adapter executes the bootstrap with bounded capture and the original V1
nested-process limits. Lower inherited limits cause an explicit refusal; the
adapter does not raise them. It checks the actual canonical result and
qualification receipt, the request identity and the uniquely selected claim.
The policy context is derived from that claim digest, the request's task digest,
and the digest of its canonical external-source-pin array.

The composed result preserves the full source replay and qualification receipt
beside the policy result. `NEEDS_REVALIDATION` remains visible even when the
assessment threshold is met. There is no overall truth or authority verdict.
An arbitrary saved result cannot substitute for the live child process.

The V1 source/package/dependency checks retain their original limits and meaning.
Auxiliary V1 imported-receipt arguments are currently refused by this adapter.
The adapter's combined message budget is conservatively capped at 65,536 bytes:
policy documents, invocation/request/descriptor metadata and declared package,
envelope, share, body and original-source lengths are counted, including source
bytes already inside the archive. Shared decoder and checker setup is reported
separately. Declared runtime file totals do not include the operating system or
the full Python standard library. The composed output is capped at 131,072 bytes
without dropping retained fields.

## Verification and reproduction

The independent policy oracle was frozen before implementation. Run it in normal
and optimized Python modes, with a new output path for every run:

```sh
gzip -dc examples/quorum-v2/oracle.json.gz > /new/oracle.json
python3 -I -B install/test_quorum_v2.py --oracle=/new/oracle.json --fixtures=examples/quorum-v2/policy-inputs.zip --output=/new/policy-run.json
python3 -I -B -O install/test_quorum_v2.py --oracle=/new/oracle.json --fixtures=examples/quorum-v2/policy-inputs.zip --output=/new/policy-optimized.json
python3 -I -B install/test_quorum_v2_replay.py --options=/path/to/adapter-options.json --output=/new/replay-run.json
```

The oracle identity is pinned in the test harness; the fixture ZIP is read with
bounds and per-entry identity checks without filesystem extraction.
`adapter-options.json` contains
the eight external replay arguments named above, using snake_case keys and no
`expect_` prefix on the three digest fields. It points to a separately prepared,
qualified V1 installation; the test does not silently rebuild one. The source
fixture and held policy roots are under `examples/quorum-v2/source-replay-example`.

Policy and orchestration code are tested Python, not SPARK-proved authority code.
The native semantics proof is separate and receives no votes from this layer.
Synthetic family-diversity cases are not evidence of a live cross-provider run.
The available observed receiver records used one model family and were not
schema-conforming QUORUM assessments; no assessment or stance was invented for
them. Authentication, semantic entailment and statistical independence remain
outside this policy verdict.
