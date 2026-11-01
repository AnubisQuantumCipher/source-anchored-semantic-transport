# Recorded review and matched four-arm data harness

These modules prepare and check bounded evidence without model or provider
dispatch. Registered SAST retrieval and source-backed assessment APIs invoke the
existing validated native decoder. They establish neither semantic truth nor
qualification.

`assessments.checked_assessments` checks graph/source/task pins, quote bytes,
reviewer provenance and independently held adjudication records. It preserves
confirmed mismatch, supported alternative, unresolved ambiguity, unsupported
challenge, missing reference evidence and tool/process failure as separate
categories. The first two require source quotes and a held adjudication pin.
That pin establishes matching declared evidence, not English entailment or
reviewer independence. Declared model names remain distinct from recorded
observed-identity artifacts, which remain unverified. Manual fixtures cannot
mint observed invocation identity. No confidence score or vote count establishes
truth. `check_source_assessments` additionally uses the existing package locator
resolver and graph-window binding; its unit controls mock that package boundary.

`quorum_aggregate` calls the unchanged `check_reading_aggregation` entry with its
original arguments. Its errors, counts, missing evidence and deferred gates are
retained. No threshold is reimplemented here. The fixed legacy adapters check
source SHA and the loaded entry code against that source; their baseline
dependencies and host remain trusted. This is not a whole-program proof.

`comparison.prepare_four_arms` prepares matched task bytes and exact inventories:

* A: complete original source and declared ordinary strong retrieval.
* B: the existing SAST share/archive/lexicon and verified retrieval capabilities.
* C: only the proposed graph view, with no original/window artifact or source tool.
* D: the same graph view plus the SAST pair and verified fallback capabilities.

The private evaluator oracle, expected answer, criteria and adjudication are
kept in a separate evaluator view. A held oracle hash is mandatory. The tool
does not verify oracle independence, pre-candidate chronology or held-out custody.
Graph text may quote source, so a graph-only view is not a claim of uncontaminated
experimental blinding. Actual fresh receiver context/tool isolation, actual SAST
verification and actual model trials remain unperformed until separately checked.

The initial in-memory profile refuses originals exceeding its registry limits
(1MiB per artifact, 8MiB aggregate). It never substitutes snippets for Arm A.
`prepare_four_arms_handles` instead holds caller-registered regular file
descriptors, checks the complete original SHA/size and descriptor identity, and
supports originals through the unchanged 1GiB source ceiling without copying
them into the registry. Registered paths come from the operator out of band,
never from source text or graph fields. `read_registered` returns at most65536
bytes; `search_registered` scans the complete held file with bounded chunks,
preserves cross-chunk matches and refuses match overflow without truncation.
The context closes every descriptor. Registries are single-owner; concurrent
jobs require separate contexts, and the existing two-job ceiling is unchanged.
Descriptor checks do not attest hostile host control. These source-handle tools
are capabilities awaiting an admitted receiver runner, not a model launch.

`stage_four_arms` checks held preparation inventory and snapshots all immutable
payloads before any write, caps total staging at32MiB, and reuses unchanged
`comparison/receiving/private_staging` exclusive private-directory writes.
Receiver and evaluator paths are separate. This establishes private inputs,
not same-UID isolation or fresh hidden-context exclusion. A write failure may
leave partial files; the adapter never overwrites, retries or deletes them.

`record_results` requires all four arm records, with explicit unrun and process
failures. Successful submissions bind the exact raw response and declared
provenance. Reference matching is byte-exact, with no normalization. Pairwise
ties and losses are retained; they are not a statistical superiority analysis.
Semantic error and fidelity metrics are never inferred by Python. Missing
tokens, latency, memory, disk, cost and human effort remain `NOT_MEASURED`.
Supplied measurements need exact pinned records and stay recorded-unverified.
The existing source-handoff checker adapter checks source membership/required
spans only and preserves `interpretation=NOT_ASSESSED`. Existing capture_trace
must capture an actual future run; this module does not synthesize that evidence.

Self-authored controls are developmental. Independent source/test review,
actual package-bound integrations, held-out multi-arm trials, the human pilot,
declared statistical analysis and the original benefit gate remain required.
The streaming API artifact was recorded after its first untested code but
before tests; its prospective owner requirements preceded code. It is not
represented as an independently frozen preimplementation oracle.

## Versioned streaming SAST comparison profile

The earlier `prepare_four_arms_handles` profile is retained as limited developmental preparation. Its Arm D original-handle inventory does **not** establish production SAST fallback. Its in-memory SAST archive requirement cannot qualify full-book baselines. New whole-book work must use `prepare_four_arms_streaming` and `sentinel/four-arm-streaming-plan/1`.

The new plan has exactly `schema`, `task_pin`, `graph_pin`, `original_pins`, `sast_bases`, `retrieval_pin`, `oracle_pin`. The small registry holds the graph, windows, task and private evaluator records; it never needs the whole SAST archive. `sast_bases` contains at most 16 exact seven-field SNE1 base identities (package ID, whole original SHA/size, whole archive SHA/size, decoder runtime and decoder source epoch SHA). All graph original/package identities must match; no snippet substitutes for an original.

The contextmanager API is:

```python
with prepare_four_arms_streaming(plan_raw, held_plan_sha, registry, held_registry_sha,
        oracle_raw, held_oracle_sha, original_paths, sast_registrations,
        held_base_root) as (prepared, capabilities):
    # No model is dispatched by preparation.
    ...
```

`original_paths` maps original SHA to caller-registered absolute `Path`. `sast_registrations` maps package ID to absolute `archive`, `share`, `native` paths, with the independently held base root described in the receiving profile. Received documents and model answers never select these paths. The preparation schema is `sentinel/four-arm-preparation/2`.

Roles are explicit: A alone receives whole original handles plus strong search/read/neighbor access; B receives existing SAST archive capabilities; C receives graph only, without raw windows or source/archive handles; D receives the same verified SAST capability as B plus the graph. D does not receive A's direct original handles. Paths and live descriptors remain outside model-facing views. The evaluator-only oracle, expected answer, criteria and adjudication stay separate. All four arms receive identical task bytes.

The existing SAST decoder validates every registered base before preparation. Whole archive SHA/size and runtime/source pins are checked around it, and package ID plus whole recovered original SHA/size must match. Formula and readable lexicon are reconstructed by the unchanged metadata function and matched to their validated entry pins. Share checking uses the unchanged operative codec rule. B and D receive identical exact share/lexicon display bytes, plus the same base identity inventory. The full archives stay registered out of band; they are neither copied into the 1 MiB artifact profile nor silently omitted as capabilities.

`read_sast_registered`, `search_sast_registered` and `resolve_sast_registered` traverse freshly validated registered SAST packages. Reads are at most 65,536 bytes. Search needles are at most 4096 bytes, with at most 256 returned matches; overflow refuses without truncation. Original bytes and derived reading views are explicit coordinates. The derived reading bound remains 32 MiB; its extraction fidelity is unproved. Locator access uses the unchanged locator API and its exact parts/gaps contract. Whole original and archive bounds remain 1 GiB and 2 GiB; the controls exercise a 1,048,577-byte registered fixture, not either maximum. Real decoding needs the caller's separately reserved temporary/global capacity and native admission; the preparation wrapper does not reserve an entire real-book campaign for the caller.

The new role inventories are checked again before unchanged private staging. A's `registered_sources` contains original pins only; B and D have identical `registered_sast` entries; C has neither. Display files remain bounded to 1 MiB each, 36 per view and 32 MiB per whole staged packet. Larger displays refuse explicitly while archive capabilities remain whole. Staging checks the preparation bytes, not current native execution; actual fresh receiver isolation and reproducible dispatch remain separate acceptance obligations. After context exit, original descriptors close and SAST handle rows are marked inactive.

The existing recorded-observation logic accepts this explicitly checked preparation version. Exact held-reference ties/losses, missing metrics and failures remain visible; `NOT_ESTABLISHED` superiority, `UNPERFORMED` statistical analysis and `UNPROVEN` semantic completeness do not change. Pure tests mock SAST/native validation and deny process dispatch. A green preparation suite is not four-arm study acceptance, independent model provenance, source adequacy, truth or mission completion.

An owner-recorded synthetic registered-source integration reports four actual native decoder calls for role separation, exact source/read/search and refusal checks (receipt SHA256 `5ee0ebf2b362fa203cb3f91cad52108ae2255c9ac59b5b4cc77db95126f4a735`). That receipt binds its stated comparison and intermediate bundle source epoch; it is not current bound-SNE decoder acceptance, fresh model execution, a full-book study or a statistical result. The developmental unit suite remains explicitly mocked.
