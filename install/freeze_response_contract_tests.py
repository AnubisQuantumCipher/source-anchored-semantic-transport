#!/usr/bin/env python3
"""Create-only self-derived test-source freeze; NOT independent authentication."""
import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
from transport_install_support import canonical, read_regular, require, sha, write_new

HERE = Path(__file__).absolute().parent
NAMES = ('transport_response_contract.py', 'transport_response_contract_model.py', 'test_response_contract.py',
         'response_contract_example.json', 'RESPONSE_CONTRACT.md', 'transport_checked_finish.py',
         'test_checked_finish.py', 'CHECKED_FINISH.md', 'freeze_response_contract_tests.py',
         'transport_install_support.py', 'transport_install_layout.py', 'transport_handoff_inputs.py',
         'transport_handoff_client.py', 'transport_handoff_reader.py', 'transport_handoff_session.py',
         'transport_response_evidence.py')


def snapshot():
    paths = [HERE / name for name in NAMES] + [Path(sys.executable).resolve()]
    require(len(paths) == 17 and len(set(paths)) == 17, 'exact test closure differs')
    files, total = [], 0
    for path in paths:
        raw = read_regular(path, 4194304)
        total += len(raw)
        require(total <= 16777216, 'aggregate test dependency bound')
        files.append(dict(path=str(path), bytes=len(raw), sha256=sha(raw)))
    return files


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    require(args.output.is_absolute() and not args.output.exists(), 'new absolute freeze file required')
    files = snapshot()
    value = dict(schema='transport/response-test-inputs/1', status='SELF_DERIVED_TEST_SOURCE_IDENTITY', files=files,
                 scope='LOCAL_TEST_REPRODUCTION_ONLY', independent_authentication=False, execution_authority='NONE')
    raw = canonical(value) + b'\n'
    require(snapshot() == files, 'test closure changed while freezing')
    write_new(args.output, raw, 32768)
    sys.stdout.write(sha(raw) + '\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
