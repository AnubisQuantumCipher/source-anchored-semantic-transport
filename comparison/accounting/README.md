# Work accounting completeness validator

This deterministic utility checks whether a ledger covers a caller-held, frozen
inventory of attempts and work slots, with measurements bound to exact evidence
bytes. It reports declared coverage only. It calculates no totals, savings,
benefit, primary endpoint or acceptance decision, and grants no authority.

## Coverage contract

The plan declares ordered attempts, including task, arm, cache condition, actor,
role, outcome and an optional earlier `retry_of` attempt. Failed, unsafe and
unrun attempts stay in that inventory. Retry links must preserve task, arm,
actor and role. The checker cannot detect work omitted from the frozen plan or
verify when the plan was frozen.

Each attempt needs a `human_active_ns` slot for every phase: `setup`,
`annotation`, `inference`, `indexing`, `fetch`, `task`, `retry`, `correction`,
`cleanup` and `maintenance`. The human `task` slot is required. Other slots may
be declared `not_applicable` in the plan with a reason; the ledger cannot change
applicability afterward. Model elapsed time, machine elapsed time and owner
administration time have separate metrics and cannot fill a human-work slot.
Provider cumulative/incremental input/output tokens and currency-qualified
`money_minor_units` are separate dimensions.

The ledger must contain exactly one record per declared slot:

| Record status | Meaning |
| --- | --- |
| `RECORDED` | References one matching, uniquely used source measurement. |
| `UNKNOWN` | Required work lacks a measurement; a nonempty reason is required. No numeric value is supplied or inferred. |
| `NOT_APPLICABLE` | Matches a plan-declared exemption; the report carries its plan reason, while the ledger reason is empty. |

`UNKNOWN` is never zero. Any unknown slot yields `INCOMPLETE`; otherwise the
report is `RECORDED_COMPLETE`. That status includes permitted exemptions and
means completeness of the declared inventory only. Invalid input yields a
named `REFUSED` result.

Every recorded measurement retains its artifact ID and SHA-256 anchor, slot,
metric, currency, integer value and interval. Unused, duplicated or rebound
measurements refuse. Cumulative provider observations carry
`aggregation: "NONADDITIVE_OBSERVATION"`; other measurements carry
`aggregation: "NO_AGGREGATION"`. Neither label authorizes summation. Recorded
time intervals must have increasing endpoints and, for the same actor and time
metric across attempts or arms, use the same clock and never overlap. These
checks do not establish clock trust or the truth of a measurement.

## API and input documents

[`accounting.py`](accounting.py) exposes:

```python
report = validate(
    plan_bytes, held_plan_sha256,
    ledger_bytes, held_ledger_sha256,
    artifact_bindings,  # {artifact_id: exact_evidence_bytes}
)
```

Supply actual `bytes` and independently held lowercase SHA-256 identities. The
API checks the held plan and ledger identities and the exact artifact roster;
it does not install process resource limits. The closed document schemas are:

| Schema | Contents |
| --- | --- |
| `transport/accounting-plan/1` | `attempts` and `slots`; each slot fixes its attempt, phase, metric, currency, applicability and reason. |
| `transport/accounting-ledger/1` | `plan_sha256`, artifact descriptors (`id`, `bytes`, `sha256`) and records (`slot`, `status`, `measurement`, `reason`). |
| `transport/accounting-evidence/1` | `plan_sha256` and measurements (`id`, `slot`, `metric`, `currency`, `value`, `interval`). |

Documents use canonical JSON: sorted keys, compact separators, ASCII escaping,
no trailing newline, duplicate keys, floating-point values or extra fields.
[`tests/README.md`](tests/README.md) describes the pinned raw fixtures and their
preserved preparation history.

## CLI

[`check.py`](check.py) accepts a canonical `transport/accounting-request/1`
document containing `plan`, `ledger` and `artifacts`. Plan and ledger descriptors
contain `path`, `bytes` and `sha256`; artifact descriptors also contain `id`.
All paths must be absolute regular-file paths without symlinks, empty path
components, `.` or `..`. File identity and size are checked around each read.
Hold the plan and ledger pins outside the request:

```sh
python3 -I -S -B -Werror comparison/accounting/check.py \
  --request /absolute/request.json \
  --expect-plan-sha256 "$HELD_PLAN_SHA256" \
  --expect-ledger-sha256 "$HELD_LEDGER_SHA256"
```

The CLI writes one canonical JSON result plus a newline. Exit status is zero for
`RECORDED_COMPLETE` and `INCOMPLETE`, and nonzero for refusal or output failure;
callers must inspect the result status. It sets address-space, CPU, per-file and
open-descriptor limits to 268435456 bytes, 30 seconds, 131072 bytes and 64,
respectively, without raising stricter inherited limits.

## Bounds and evidence limits

| Boundary | Limit |
| --- | --- |
| Each plan, ledger, evidence or CLI request document | 65536 bytes |
| Attempts / slots / artifacts / total measurements | 32 / 128 / 32 / 128 |
| Combined evidence bytes | 1048576 bytes |
| JSON nesting depth | 12 |
| Nonnegative measurement and interval integers | 9223372036854775807 |
| Encoded result, including newline | 131072 bytes |

The JSON helper is checked against its fixed source digest before loading.
Trusted Python, libraries, source files and OS behavior remain assumptions.
Reports explicitly retain `authority: "NONE"`, `measurement_truth: "UNPROVEN"`,
`source_authentication: "UNKNOWN"`, `clock_trust: "UNKNOWN"`,
`hidden_work_detection: "NONE"`, `prespecification_timing: "NOT_VERIFIED"`, and
`benefit` and `acceptance` as `"NOT_ASSESSED"`. This Python integration is
TESTED within the retained scope, not formally proved.

## Reproduce deterministic controls

```sh
python3 -I -S -B -Werror comparison/accounting/run_tests.py \
  --scratch-parent /ABS/PRIVATE_TASK_PARENT \
  --capacity-root /ABS/TASK_CAPACITY_ROOT
```

The scratch parent must be caller-owned, mode `0700`, and inside the accounting
task's capacity root. Admission includes the existing allocated task footprint,
portable source bytes and a staging reservation under an 8 MiB task cap; staging
is limited to 4 MiB. These checks are not a filesystem quota. The runner checks
the fixed ZIP, index and independent-runner pins, extracts only verified data,
and preserves its stage and separate normal/optimized reports. Archive builder
sources remain inert. No dependency installation is required.

The [retained local receipt](tests/evidence/portable-local-receipt.json) records
46 applicable API PASS cases and 48 CLI PASS cases in each of normal and
optimized execution. Two cases are CLI-only and explicitly API `UNRUN`.
The [CI workflow](../../.github/workflows/work-accounting.yml) runs this same
entry point on Ubuntu 24.04 with Python 3.14.10 in a fresh private directory used
as both scratch parent and capacity root. A new CI outcome is separate from the
retained local observation.

The historical local receipt lists two runtime obligations as **UNRUN**. Separate
postimplementation [boundary controls](tests/boundary_check.py) now test both:
valid 65536-byte plan and ledger inputs are accepted in separate cases, and a
valid input whose full report exceeds the output limit returns `OUTPUT_BOUND`.
These three API controls pass in normal and optimized execution. Their fixed
ZIP is read in memory without extraction; the earlier receipt remains unchanged.
These added cases do not establish CLI boundary coverage.

```sh
python3 -I -S -B -Werror comparison/accounting/tests/boundary_check.py
python3 -I -S -B -O -Werror comparison/accounting/tests/boundary_check.py
```

No human/model or held-out campaign, measurement-truth finding, benefit result,
whole inherited proof/suite closure or final acceptance follows from these
controls. Source-bound hosted CI reproduction remains a separate observation.
