# Actual accounting CLI boundary qualification

TESTED local observation: six recorded calls PASS in normal and optimized Python. Exact-plan and exact-ledger return INCOMPLETE with exit0; overflow returns the literal OUTPUT_BOUND refusal with exit1. Every complete stdout equals its frozen qualified API reference including the final LF; all stderr files are empty. This is API/CLI byte equivalence, not an independent semantic oracle or formal proof.

The data-only ZIP contains 140 unique regular-file members, 1417483 expanded bytes, and 1 explicit symlink/special omissions. The index retains source paths, exact bytes/hashes and original stat observations. Nested ZIPs remain opaque bytes; no archived code was executed.

C/ retains design, literal expectations, v1 failures/preservation, both runners, helpers and implementation reviews. Q/ retains preparation, exact inputs, API references, root launch admission, all six dispatch journals/raw streams, mode reports and terminal result. D/ retains parent launch streams/exit, admissions and the independent actual-result review. The independent GPT-6.1 review is engineering review, not external-human validation.

Historical API-only/CLI-UNRUN receipts are unchanged. This additive result closes only the named actual-CLI boundary item. Benefit, measurement truth, study validity, whole-system proof and ACCEPTED_V1 remain unestablished.

Local runtime: /usr/bin/python3.14, executable SHA256 c6bc1ef497b896b7575c546b13f9bafe52e2066f184fdd3fec6af4b5b6349947, supported source HEAD b8aefc51a51d6f391e58460b95074f28f654f50a. This profile does not attest libraries/OS or establish portability to another host.

Historical root command (inspect only; it requires its original private paths and create-only launch state):

```text
/usr/bin/python3.14 -I -S -B -Werror /dev/shm/semantic-transport-cli-boundary-design-20261029/runner_v2.py run
```

Recorded actual CLI argv arrays, preserved verbatim in Q/dispatch-v2/*--intent.json:

```json
[
  [
    "/usr/bin/python3.14",
    "-I",
    "-S",
    "-B",
    "-Werror",
    "/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/comparison/accounting/check.py",
    "--request",
    "/dev/shm/semantic-transport-cli-boundary-qualification-20261029/stage/exact-plan/request.json",
    "--expect-plan-sha256",
    "b85a48cf44b74013fab97485ff951c36b4bdc16e3a5cff0c785e975eae0b07e5",
    "--expect-ledger-sha256",
    "02dd539e72f0dd7be775209f39a7f01a6351fb75f393fbe268ba0e1d2a1a8624"
  ],
  [
    "/usr/bin/python3.14",
    "-I",
    "-S",
    "-B",
    "-Werror",
    "/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/comparison/accounting/check.py",
    "--request",
    "/dev/shm/semantic-transport-cli-boundary-qualification-20261029/stage/exact-ledger/request.json",
    "--expect-plan-sha256",
    "250284a4587844a0d43172fd259650efc90399107279851548e3f6e6854cd183",
    "--expect-ledger-sha256",
    "265ac9bbd9ad5a08d67ad7c27df6faf621da54efb95439a378768e3b57f9b73d"
  ],
  [
    "/usr/bin/python3.14",
    "-I",
    "-S",
    "-B",
    "-Werror",
    "/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/comparison/accounting/check.py",
    "--request",
    "/dev/shm/semantic-transport-cli-boundary-qualification-20261029/stage/overflow/request.json",
    "--expect-plan-sha256",
    "6a00e3cdf3a1c86682f3c006497973119d98607f6aa4f61253cf9a9dfbf1cab7",
    "--expect-ledger-sha256",
    "3c9ea0f0994a41519149866babbef90e671168e4198f335a841a7f4f64d34f13"
  ],
  [
    "/usr/bin/python3.14",
    "-I",
    "-S",
    "-B",
    "-O",
    "-Werror",
    "/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/comparison/accounting/check.py",
    "--request",
    "/dev/shm/semantic-transport-cli-boundary-qualification-20261029/stage/exact-plan/request.json",
    "--expect-plan-sha256",
    "b85a48cf44b74013fab97485ff951c36b4bdc16e3a5cff0c785e975eae0b07e5",
    "--expect-ledger-sha256",
    "02dd539e72f0dd7be775209f39a7f01a6351fb75f393fbe268ba0e1d2a1a8624"
  ],
  [
    "/usr/bin/python3.14",
    "-I",
    "-S",
    "-B",
    "-O",
    "-Werror",
    "/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/comparison/accounting/check.py",
    "--request",
    "/dev/shm/semantic-transport-cli-boundary-qualification-20261029/stage/exact-ledger/request.json",
    "--expect-plan-sha256",
    "250284a4587844a0d43172fd259650efc90399107279851548e3f6e6854cd183",
    "--expect-ledger-sha256",
    "265ac9bbd9ad5a08d67ad7c27df6faf621da54efb95439a378768e3b57f9b73d"
  ],
  [
    "/usr/bin/python3.14",
    "-I",
    "-S",
    "-B",
    "-O",
    "-Werror",
    "/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/comparison/accounting/check.py",
    "--request",
    "/dev/shm/semantic-transport-cli-boundary-qualification-20261029/stage/overflow/request.json",
    "--expect-plan-sha256",
    "6a00e3cdf3a1c86682f3c006497973119d98607f6aa4f61253cf9a9dfbf1cab7",
    "--expect-ledger-sha256",
    "3c9ea0f0994a41519149866babbef90e671168e4198f335a841a7f4f64d34f13"
  ]
]
```

Inspect the archive/index as untrusted data. `python3 -I -S -B -Werror collate.py check` checks only bounded archive membership/bytes/hashes; it executes no archive content. Historical absolute-path drivers are not portable automatic launchers. For separately authorized reproduction, use the existing comparison/accounting/check.py request interface: stage pinned plan/ledger/evidence bytes in a new private directory, construct a new canonical transport/accounting-request/1 with those absolute paths and held bytes/SHA256 descriptors, then supply --request NEW_REQUEST --expect-plan-sha256 HELD_PLAN_SHA --expect-ledger-sha256 HELD_LEDGER_SHA. Preserve independent pins and use the recorded -I -S -B -Werror flags, adding -O for the optimized mode. No automatic reproduction or new execution is authorized by this bundle.

Credential scan: fixed private-key/provider-token patterns found no match in the raw bytes archived here. This is a heuristic observation, not proof that arbitrary secrets cannot exist; no private participant data was supplied in this admitted scope.
