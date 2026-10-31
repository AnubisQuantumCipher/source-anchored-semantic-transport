# Recovered knowledge and relationships

This is a reconstruction from the supplied transport package only. The recovered sources label themselves manually supplied frozen development fixtures, without semantic qualification. They do not establish a real ferry policy, authenticated issuer, current service status or passenger eligibility.

## Source content

Package source `ACCESS_NOTICE` says, verbatim:

```text
Avis provisoire — accès à la navette.
Les résidents peuvent embarquer avec une réservation confirmée, sauf pendant les exercices de sécurité.
日本語補足：悪天候の場合は運航を見合わせる可能性があります。再開時刻は未定です。
This notice is a development example; consult the separate timetable revision before use.
```

Readable interpretation (my unverified translation): this provisional shuttle-access notice permits residents to board with a confirmed reservation, except during safety exercises. The Japanese supplement says service may be suspended in bad weather and the resumption time is undecided. The English sentence explicitly identifies a development example and directs attention to a separate timetable revision. The weather suspension is a possibility, not a reported actual suspension; no reopening time is promised.

Package source `TIMETABLE_BEFORE` says:

```text
Provisional timetable: pier access by the east gate; confirmation pending.
```

Package source `TIMETABLE_AFTER` says:

```text
Revised provisional timetable: east gate closed; accessible route awaiting confirmation.
```

The revised context closes the east gate; it does not supply a confirmed accessible alternative. Both timetable texts remain provisional. A reader cannot retain the earlier east-gate access direction as current access guidance merely because the access-notice quotation is unchanged.

## Explicit records in package source Q_RECORDS

`FERRY_ACCESS:V1` (claim ID `FERRY_ACCESS`, revision `V1`) is attributed to an independently authored development example, with no model observation. Its opaque prose describes confirmed-booking qualification, safety-exercise exception, uncertain weather suspension and timetable review. It explicitly omits live service status, authenticated issuer, eligibility decision and complete operating policy. Its uncertainty says manual interpretation only: multilingual entailment and translation equivalence are unchecked.

`NOTICE_SPAN` selects the entire recovered `ACCESS_NOTICE` byte sequence. Its matching quoted bytes establish source membership only; they do not establish interpretation truth. `ACCESS_BYTES` declares the claim dependent on that notice as SOURCE. `TIMETABLE_CONTEXT` declares the same claim dependent on the old `TIMETABLE` version as CONTEXT. Both dependencies mean `DECLARED_REVALIDATION_DEPENDENCY_ONLY`; they are declarations, not demonstrated semantic entailment.

`TIMETABLE_REVISION` declares a REPLACEMENT of the old timetable version by the new version, with issuer claim `DECLARED_EDITOR`, no predecessor event, no correction text or evidence, and status `INFORMATIONAL_QUARANTINED`. `TIMETABLE_PROV` attributes it to a development timetable editor, method `MANUALLY_AUTHORED_ILLUSTRATION`, origin `MANUAL_DEVELOPMENT_FIXTURE`, authentication `UNVERIFIED`, no run evidence and no assertion of actual service or issuer authentication. The revision's relation to the claim follows the old timetable source through `TIMETABLE_CONTEXT`.

`FERRY_TASK` selects the notice and both timetable versions, references `POLICY`, `REGISTRY` and `RULE_0` through `RULE_3`, and has freshness `UNKNOWN`, null task text, empty context-dependency list and an empty expected-seat roster for the claim. `REGISTRY` has no seats and permits only manual-fixture or unverified identities without authentication. There are no readings, withdrawals, challenges, run evidence, input manifests, blobs or history. Therefore no independent model agreement or dissent is present.

`POLICY` specifies `PURE_INFORMATIONAL_REPLAY` through the body mode, authority `NONE`, freshness `UNKNOWN`, unauthenticated informational quarantine, manual fixtures only (not model runs), actual model observations ineligible when unverified, independent fields without a threshold, claim-level structural comparison, and refusal on missing declared targets, source/claim cycles or update-predecessor cycles. `RULE_0` checks source membership, `RULE_1` declaration identity, `RULE_2` declared dependency impact and `RULE_3` recorded stance counts. Every rule is deterministic replay only with consequence ceiling `INFORMATIONAL`.

## Observed replay and limits

The pinned authoritative bootstrap exited successfully with `accepted_result: true`, bootstrap status `QUALIFIED_FIXED_HOST` and replay `RECOMPUTED_INFORMATIONAL`. These are replay/qualification observations, not acceptance of ferry-access truth. It reported `NOTICE_SPAN: MATCH` and declared preconditions `MATCH`; `FERRY_ACCESS:V1` remains `claim_truth: NOT_ASSESSED`, `interpretation: UNRESOLVED_UNSUPPORTED_PROFILE`, `semantic_completeness: UNPROVEN`, `freshness: UNKNOWN`, and `current_authority: NONE`.

It reported `change_impact: NEEDS_REVALIDATION`, triggered by quarantined `TIMETABLE_REVISION`, with the impact path through `TIMETABLE_CONTEXT` from the old timetable. No decisive readings were recorded; observation class is `NO_RECORDED_READINGS`, agreement `NO_DECISIVE_READINGS`, threshold `NOT_DEFINED`. Source authentication remains `UNVERIFIED`.

Transport inspection reported native-decoded and hash-checked source bytes, author authentication `NOT_AUTHENTICATED`, declarations `UNVERIFIED`, interpretation entailment/media understanding `UNPROVEN`, semantic completeness `NOT_CLAIMED`, and no confidentiality. Transport-level interpretations, relations and coverage spans are absent; relationships described above are recovered Q_RECORDS declarations. The runtime explicitly does not isolate hostile concurrent same-user mutation.

## Missing context and optional commentary

No external reality checks, authentic service operator, complete operating policy, live weather/status, authenticated editor, confirmed alternate route, model-run evidence or validated multilingual interpretation was supplied. Exact bytes were recovered; faithful semantic interpretation remains unproved. The smallest sound next step for relying on the ferry claim would be authenticated current operating information and revalidation against the changed timetable; acceptance would require evidence for the conditions, exceptions, accessibility route and interpretation, not a quotation match alone. No such action was taken.
