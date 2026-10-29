# Audit repair evidence

The isolated test import, receiving setup, and QUORUM replay/policy integration
have been repaired. Their earlier failures remain available.

| Finding | Current evidence |
| --- | --- |
| Isolated language-test import | Fixed in `4f4200f`; exact normal and optimized entrances passed, with successful hosted CI. |
| Receiving preflight | Private create-only staging and the decoder's declared runtime profile pass. All 12 recovered sources match their original bytes. |
| Fresh receiving agent | A fresh `gpt-6.1-sol` receiver performed recovery and returned its first answer with all 11 required citation records. Saved and observed final bytes match. |
| Source interpretation assessment | A separate fresh assessor recorded all 30 required items as supported and all 22 forbidden items as not observed. Workflow disclosure compromised masking, so blinded assessment completion is not claimed. |
| QUORUM threshold and replay | Nine-seat policy support, live source replay, explicit dissent/withdrawal handling, and coherent model-to-family assignments are implemented and tested. Dependency warnings survive a successful threshold. |
| Actual cross-family observation | A fresh OpenAI observation completed. The second provider's sole attempt failed because its login expired. No identity, stance, or admission was invented for that failure. |

The matched [share text](../examples/receiving-repair-v2/share.txt),
[meaning ZIP](../examples/receiving-repair-v2/meaning.zip),
[first answer](../examples/receiving-repair-v2/answer.json), and
[receiving receipt](../examples/receiving-repair-v2/README.md) are public artifacts.
That receipt includes exact model/settings observations, tool traces excluding
private reasoning, source comparisons, costs reported by the client, original
failures, and the assessment limitations.

The [QUORUM verification entry point](../examples/quorum-v2/README.md) links its
contracts, interfaces, independent controls, correction history and commands.
The [receiving independent review](../examples/receiving-repair-v2-review/review.json)
also exercises coherent tampering against the published evidence checker.

These repairs preserve the previously sealed native semantic-core source and
proof evidence. No new whole-system proof follows from the Python tests, source
recovery or model explanations. General semantic completeness, measured benefit
over the strengthened original-document baseline, external human validation,
and final release acceptance remain unestablished. This is a reviewed engineering
checkpoint, not a release or a waiver of those requirements.
