# Proposed authoring map; not a compiled plan

Source documents are synthetic and unauthenticated. The expected outcome concerns fidelity to these documents, not the truth of receipt reports. All exact source bytes must be retained.

Use four typed units, in this order, each with one complete paragraph anchor including every sentence in that block. An opaque `atom` is acceptable and must remain `INCOMPLETE`; it is preferable to an unsupported claim of complete formal representation.

| Unit | Kind | Source/block | Context |
|---|---|---|---|
| U_APPROVAL | historical_approval | approval.txt / APPROVAL | [] |
| U_CORRECTION | source_claim | correction.txt / CORRECTION | [] |
| U_REVOKE | revocation | revocation.txt / REVOCATION | [U_APPROVAL, U_CORRECTION] |
| U_PENDING | pending_action | work.txt / PENDING | [U_REVOKE] |

Keep separate documentary interpretation records for GOAL, INSTRUCTION, BUILD, SECURITY, VALIDATION_A, VALIDATION_B and MISSING. Each anchors its entire block in work.txt. Their labels and text must preserve their different roles: GOAL is desired state; INSTRUCTION is documentary procedure; receipt reports are source claims; MISSING is uncertainty. Do not label all of them established facts or current instructions from the user.

Connect each supporting interpretation to U_PENDING with an anchored declared `qualifies` or `supports` relation that states its actual documentary role. Connect a declared uncertainty for missing acknowledgement and time to U_PENDING. Do not add a direct relation between U_APPROVAL and U_REVOKE: that would mask the incoming-context retrieval case. The approval is mentioned by the revocation source itself; `context` alone must never be interpreted as a revocation target or as a semantic inference.

The source catalog includes unrelated.txt under UNRELATED. It has no unit, context, relation or uncertainty links to this task. It must not appear among retrieved content. The baseline also sees it in its catalog and must not read it.

Starting from U_APPROVAL must expose a faithful record of the incoming declared context edge from U_REVOKE, keeping the direction U_REVOKE -> U_APPROVAL. U_CORRECTION is a separate outgoing dependency of U_REVOKE. The follow-on dependent U_PENDING and its supporting records must become discoverable. The interface may reveal incoming edge descriptors first and require explicit retrieval; it need not redefine those incoming records as prerequisites of the original approval. Record actual retrieval, not an assumed closure policy.

All source, metadata, archive, output, graph and session bounds remain unchanged. Four typed units do not prove that the archive fits: duplicated dictionaries/readable definitions must be measured after encoding. Refusal on overflow is an acceptable preparation result, never permission to raise bounds or drop clauses. A smaller documentary representation can be designed only as a new, separately frozen candidate.
