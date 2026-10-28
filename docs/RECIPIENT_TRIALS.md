# Fresh recipient reconstruction trials

Two first-candidate explanations passed the frozen, source-grounded obligations for their respective fixtures. This is evidence for these observed reconstructions, with important unknowns; it is not whole-product acceptance or a proof that an arbitrary interpretation is complete.

The machine-readable [trial receipt](../receipts/recipient-trials-1.json) binds the observations to the tested public commit, exact runtime, candidates, criteria and separate assessments. This follow-up changes documentation and evidence only. The decoder, resource bounds, typed operators and proof obligations are unchanged.

## What was tested

| Fixture | Source-grounded obligations | Result class | Exact recovered and exported source |
|---|---:|---|---|
| Historical COSMOGONY plan and separate CRAM addendum | 76 passed | `BOUNDED_OBSERVED_SOURCE_COMPARISON` | Byte equality checked |
| Synthetic library-loan passage | 8 passed | `BOUNDED_OBSERVED_SOURCE_COMPARISON` | Byte equality checked |

The plan assessment covers its architecture, rules and relationships, the separate Compressed RAM addendum, numbers, conditions, and the distinction between proposals, reported evidence and established results. Its documentary package retains the complete source and section structure; it does not claim a complete typed semantic interpretation. The loan case covers both required reviews, attribution, the revoked earlier approval and the unspecified return date. It is an existing held-out fixture, not a newly sampled corpus or a statistical generalization test.

The source evaluator had the originals and frozen criteria separately. Recipients were requested with `fork_turns: none`, actual model `gpt-6.1-sol` and reasoning effort `high`. Each received a decoder interface and a handoff containing only the matched share/ZIP and declared runtime closure. Original evaluation sources and expected answers were not placed in that handoff. A recipient could obtain source text through verified decoder pages; that is part of the declared recovery contract.

Each recipient submitted one candidate. Neither candidate was edited or retried after scoring. A separate GPT-6.1 protocol reviewer checked the observable calls, exact executable-source bytes including final newlines, output equality with the runner ledger, complete page coverage, source equality, immutable inputs and unchanged narrative export. Both protocol results are `OBSERVED_PASS_BOUNDED_PROTOCOL`.

The recipient's task was to explain the source faithfully. The deterministic export retained the literal source alongside that prose. The agent was not required to regenerate every diagram glyph from memory. These prose-only criteria were frozen before the trials. They do not turn the earlier failed exact-copy trial into a pass.

## Limits of the observation

- The child launch payload is encrypted in the available record. The exact requested prompt and observed subsequent interface read are retained, but plaintext dispatch equality remains `UNKNOWN`.
- Observed model/effort fields are recorded settings, not an independent backend attestation. Fresh-context requests and inspected tool traces do not establish an operating-system sandbox or rule out hidden host access.
- Source fidelity is an independent model assessment against explicit obligations. It is not a machine-checked proof of semantic completeness, legal interpretation or factual truth.
- No matched uncompacted/native-compaction baseline was run. Lower error rates, lower context consumption and better continuation behavior remain unproved.
- No desktop client, marketplace integration, cross-model trial or new formal proof campaign was exercised here. The exact runtime remains required; cross-host compatibility is not inferred.

For those reasons the receipt deliberately keeps whole-trial acceptance at `UNKNOWN_NOT_A_UNIVERSAL_ACCEPTANCE_CLAIM`, while reporting the narrower observed passes separately.

## Storage and short-text accounting

All sizes below are measured bytes, except the complete share-text column, which counts Unicode code points including identity, reference and newlines. These counts do not claim any platform's character-counting compliance.

| Item | Plan | Loan |
|---|---:|---:|
| Original source bytes | 35,304 | 187 |
| Complete share text, code points | 672 | 683 |
| Share text bytes | 673 | 684 |
| Meaning ZIP bytes | 81,545 | 71,506 |
| Share plus ZIP bytes | 82,218 | 72,190 |
| Source-only gzip bytes | 13,473 | 152 |
| Straightforward JSON source envelope bytes | 36,702 | 208 |
| Recipient interface bytes | 18,843 | 10,243 |
| Initial launch message bytes | 991 | 991 |

Both attempts with a 200-character budget were refused before an output directory was published: `complete share character budget exceeded; no fields dropped`. This campaign does not demonstrate a 200-character post. The plan's share text is shorter than its source; the loan's share text is larger. Both archives are larger than their originals. The gzip and JSON comparisons retain source text only and do not supply equivalent interpretation, integrity and protocol machinery.

The shared runtime manifest and its declared files occupy 1,850,696 bytes. The external trial runner occupies 30,442 bytes and its process helper 8,408 bytes. The Python standard library, native libraries and operating system remain external dependencies whose installed storage was not measured. The complete source is retained in these packages; no claim is made that the visible formula eliminates that storage or captures every meaning independently.

The receipt includes JACKAL `exact` rational arithmetic for reuse levels of 1, 10 and 100 equal-sized messages. It charges share/ZIP, full interface and launch instructions per message, sharing only the decoder and two protocol helpers. For example, the plan cold-start calculation was echoed as `parsed=(1850696+30442+8408+1*(82218+18843+991))/1`, with `exact=1991598`. At reuse 10 and 100, the returned per-message results are respectively `exact=1455033/5` and `exact=6047373/50`. The loan results are `exact=1972970`, `exact=1361893/5` and `exact=5115973/50`. Full echoed expressions and non-claims are in the receipt. This is exact rational arithmetic over observed file counts, **not** `formal-bounded`, not proof of the measurements, and not total installed-system cost. External dependencies, provider infrastructure, evaluation traces and filesystem metadata are excluded and unmeasured.

## Actual model-context observations

| Observable | Plan | Loan |
|---|---:|---:|
| Recipient tool calls | 14 | 6 |
| Highest observed input tokens for one request | 81,167 | 59,157 |
| Last cumulative input-token observation | 943,030 | 375,137 |
| Cached input-token component | 870,656 | 363,776 |
| Last cumulative output-token observation | 11,285 | 2,999 |
| Last cumulative total-token observation | 954,315 | 378,136 |

These are the available runner/provider usage records, not tokenizations of the source or package. They include framework/system/tool prompts and repeated context. Overlapping cumulative records were not summed, and cached inputs are not an additional amount to add to total inputs. The receipt retains reasoning-output observations separately. Per-action runner latency is recorded in nanoseconds; it excludes model generation and is not an end-to-end latency measurement. Monetary cost, energy and matched-baseline latency were not measured. These trials support no context-cost saving claim.

## Reproduction and evidence access

Use the [source-build installation](INSTALL.md) and the [deterministic handoff harness](REPRODUCIBILITY.md) to reproduce the public codec/package controls with separately built, matching runtimes. Its command remains:

```sh
python3 -I -B -Werror install/test_portable_handoff.py \
  --sender-bundle /absolute/path/to/first-built-bundle \
  --receiver-bundle /absolute/path/to/second-built-bundle \
  --mismatched-bundle /absolute/path/to/incompatible-old-bundle \
  --expect-runtime-sha256 "$HELD_RUNTIME_SHA256" \
  --evidence /absolute/path/to/new-handoff-evidence
```

This command reproduces deterministic controls; it does not launch or score an AI recipient. The public synthetic loan source and typed plan are in [the held-out fixture directory](../fixtures/semantic-heldout-v1). The installed `transport_recipient_runner.py` and `transport_recipient_process.py` provide the bounded model-facing runner. Use their installed versions: installation binds the process helper to the exact built runtime. The uninstalled source helper retains its historical runtime pin and must not be silently retargeted.

For a new model trial, freeze the source, package, exact decoder/dependencies, interface, source-only criteria and launch settings before asking a recipient to explain anything. Give the recipient only the interface and declared handoff. Keep evaluation originals separate, record every actual tool request/response and candidate, then compare source and explanation independently. Bind the final assessment to those bytes and preserve all refusals. Different model outputs must be evaluated as new candidates, never substituted into this receipt.

This public checkpoint contains a derived, nonprivate receipt. The complete plan, recipient explanations, prompts, raw session records and detailed source quotations in the evaluator reports remain in the owner's local evidence archive. They were not uploaded to public hosting. Consequently, third parties cannot reproduce this particular private plan assessment from the public receipt alone. Hashes identify the retained evidence; they do not authenticate it or make unavailable evidence independently inspectable. The private campaign's preparation/trace-export scripts are also retained locally, not presented as a shipped universal model launcher.

## Failures retained and next acceptance boundary

The earlier full-view delivery failure and paged diagram-copy failure remain recorded. New preparation attempts refused an array passed to an object-only serializer and an incorrect source identifier before a recipient was launched. An initial finalizer refused a non-Boolean regex object during preflight before writing output; a new finalizer used an explicit Boolean check. No source, resource or identity contract was relaxed to resolve these harness mistakes.

The next useful behavioral evidence is a preregistered, matched task comparison measuring consequential errors, corrections, dependency retrieval, revoked approvals, pending-work resumption and actual context costs. These two reconstructions do not establish that advantage. A governing-record or legal workflow would additionally require explicit authentication, version/amendment handling and current-authority enforcement outside the decoder's present claims; decoded obligations remain data, never authorization to act.
