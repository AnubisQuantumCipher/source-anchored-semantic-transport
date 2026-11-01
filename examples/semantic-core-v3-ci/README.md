# Isolated CI entry point repair

Commit `13681d09ea132f84e1c890d839122a9bd6a50672` introduced two CI defects:
the source workflow and source checker changed despite being bound by earlier
QUORUM receipts, and the language test omitted its direct-execution import setup.
The hosted failure and a local reproduction are retained here.

The historical files are restored exactly. Grammar 3 controls now have a separate
push/PR workflow. The language test adds only its repository-local import
bootstrap; all test cases and runtime files are unchanged.

The sealed `semantic-core-v3` evidence belongs to commit `13681d0` and is checked
on that exact checkout. `check_continuity.py` verifies its complete inventory and
all original source pins against the current tree, allowing only the exact
import bootstrap. It also enforces the core function-size bounds. This preserves
the original proof and integration scope without rewriting its receipt.

Reproduce the current controls:

```sh
python3 -I -S -B -Werror examples/semantic-core-v3-ci/check_continuity.py
python3 -I -S -B -Werror examples/semantic-core-v3-ci/test_continuity.py
python3 -I -S -B -O -Werror examples/semantic-core-v3-ci/test_continuity.py
python3 -I -S -B -Werror tests/test_transport_core_language.py
python3 -I -S -B -O -Werror tests/test_transport_core_language.py
```

These checks establish source continuity and the repaired test entry point.
They do not qualify the cross-family QUORUM policy or replace the failed
receiving-agent attempt. Those findings require their own implementation and runs.
