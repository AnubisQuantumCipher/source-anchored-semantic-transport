"""Create once, or check, the exact source-bound Python core receipt."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
MODULES = ('__init__', 'common', 'bindings', 'census', 'graph', 'locators', 'challenges', 'refinement')
TESTS = ('common', 'meaning', 'locators', 'challenges', 'refinement')
REPORTS = ('endpoint-contract.json', 'endpoint-oracle.json', 'endpoint-review.json',
           'refinement-review.json', 'boolean-target-failure.json', 'historical-impact-failure.json',
           'endpoint-sort-failure.json', 'core-tests.json')


def artifact(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular artifact required: ' + str(path))
    with path.open('rb') as stream:
        raw = stream.read(131_073)
    if len(raw) > 131_072:
        raise ValueError('artifact bound: ' + str(path))
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def paths():
    result = ['tools/sentinel_v1/' + name + '.py' for name in MODULES]
    result += ['tests/test_sentinel_' + name + '.py' for name in TESTS]
    result += ['schemas/sentinel-meaning-graph-1.json',
               'examples/sentinel-v1-core/check_endpoints.py',
               'examples/sentinel-v1-core/freeze_core.py']
    names = list(REPORTS)
    for suite in TESTS:
        for mode in ('normal', 'optimized'):
            names.extend('test_sentinel_' + suite + '-' + mode + '.' + stream
                         for stream in ('stdout', 'stderr'))
    return result + ['examples/sentinel-v1-core/evidence/' + name for name in names]


def payload():
    tests = json.loads((HERE / 'evidence/core-tests.json').read_bytes())
    if tests['status'] != 'PASS' or len(tests['runs']) != 10:
        raise ValueError('exact five-suite normal/optimized receipt required')
    for key, expected in tests['source_pins_before'].items():
        if artifact(ROOT / key)['sha256'] != expected or tests['source_pins_after'][key] != expected:
            raise ValueError('test source changed: ' + key)
    return {'schema': 'sentinel/python-core-receipt/1',
        'baseline_commit': '3e0d8602353e42a772927c8adaa32a73e7cc3b0a',
        'foundation_commit': 'bb00d7526254eb5aa55f4dbaa3a2761018243c18',
        'artifacts': {name: artifact(ROOT / name) for name in paths()},
        'status': 'TESTED_SCOPED_PYTHON_CORE', 'proof': 'NOT_A_FORMAL_PROOF',
        'independent_assessment': 'RECORDED_AGENT_ENGINEERING_REVIEW_NOT_CERTIFICATION',
        'scope': 'BOUNDARIES_CENSUS_GRAPH_REFERENCE_CHALLENGES_AND_REFINEMENT_ONLY',
        'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE',
        'semantic_completeness': 'UNPROVEN', 'fresh_receivers': 'NOT_COVERED',
        'native_wire': 'NOT_COVERED', 'comparative_superiority': 'NOT_ESTABLISHED'}


def main():
    if sys.argv[1:] not in (['--create'], ['--check']):
        raise ValueError('use --create or --check')
    expected = (json.dumps(payload(), indent=2, sort_keys=True) + '\n').encode()
    target = HERE / 'evidence/receipt.json'
    if sys.argv[1:] == ['--create']:
        with target.open('xb') as stream:
            if stream.write(expected) != len(expected):
                raise ValueError('short receipt write')
    elif target.read_bytes() != expected:
        raise ValueError('receipt or artifact mismatch; do not retarget old evidence')
    print('Scoped Python core receipt matches exact source and retained evidence.')


if __name__ == '__main__':
    main()
