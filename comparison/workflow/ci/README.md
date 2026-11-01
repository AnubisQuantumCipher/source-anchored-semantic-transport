# CI dependency correction

The first hosted native source workflow at commit
`e0d3175a0292f1661a165ad149ee310799a3a143` failed before product execution:
the Ubuntu runner did not contain `/usr/bin/rg`. The complete failed job log
is retained in `failed-job.log` (run 40907623429, job 123566600279).

The correction installs ripgrep on the ephemeral hosted runner. Installation
failure fails the job. Native controls, source pins and resource limits stay
in force; each fresh campaign records its actual tool versions and digests.
The distribution package is not claimed to be a reproducible binary pin.

The sealed parent receipt includes the old workflow hash. It is preserved
unchanged, together with `parent-workflow.yml`. The new receipt reader executes
the pinned parent inventory reader, then compares the entire resulting object
with the sealed parent receipt. Only the declared workflow pin may differ.
The separate receipt binds both workflow versions and this correction's files.
It does not silently regenerate the old receipt or waive any source binding.

Reproduce from the repository root:

```sh
python3 -I -S -B -Werror comparison/workflow/ci/test_delta.py
python3 -I -S -B -O -Werror comparison/workflow/ci/test_delta.py
python3 -I -S -B -Werror comparison/workflow/ci/prepare_receipt.py --check
python3 -I -S -B -O -Werror comparison/workflow/ci/prepare_receipt.py --check
```

The original `comparison/workflow/prepare_receipt.py --check` remains a check
for its frozen parent commit. Use the delta reader on this corrected tree.
This receipt checks retained bytes and evidence continuity. Hosted execution
success requires a separately observed successful CI run. Semantic fidelity,
continuation benefit and external acceptance remain unproved.
