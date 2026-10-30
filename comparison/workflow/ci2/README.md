# Hosted evidence-control path

At `c13b9a8a8dd1f6d3d2811705ab52ea9b85b1f303`, hosted portable product
controls passed in both Python modes and the native tool controls passed.
The next step failed because the unchanged evidence-control harness requires
its root to be a direct child of
`/dev/shm/semantic-transport-native-workflow-20261029`. CI had supplied `/tmp`.
The complete second failure is `failed-job.log` (run 40909422964,
job 123573007482). The first dependency failure remains in `../ci`.

The workflow now creates the required private tmpfs parent and uses new direct
children. It changes no test, product code, resource bound or success criterion.
The prior delta checker is reused byte-for-byte. It checks the complete base
inventory and permits only the current workflow pin to differ. This new receipt
binds its checked result and the new correction files; earlier receipts remain
unchanged and apply to their own frozen commits.

From the repository root:

```sh
python3 -I -S -B -Werror comparison/workflow/ci/test_delta.py
python3 -I -S -B -O -Werror comparison/workflow/ci/test_delta.py
python3 -I -S -B -Werror comparison/workflow/ci2/prepare_receipt.py --check
python3 -I -S -B -O -Werror comparison/workflow/ci2/prepare_receipt.py --check
```

The receipt verifies recorded bytes and source continuity. A successful hosted
run is separate execution evidence. It does not establish semantic fidelity,
comparative benefit, native x86_64 decoder acceptance or external validation.
