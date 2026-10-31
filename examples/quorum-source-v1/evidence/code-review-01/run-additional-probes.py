"""Independent frozen host/stage/resource probes; no product mutation."""

import hashlib
import json
from pathlib import Path
import sys

TASK_ROOT = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
EVIDENCE_ROOT = Path(__file__).resolve().parent
SOURCE_NAMES = ('transport_quorum_source.py', 'transport_quorum_input.py',
                'transport_quorum_shape.py', 'transport_schema.py', 'transport_wire.py')


def pins() -> dict:
    return {name: hashlib.sha256((TASK_ROOT / 'tools' / name).read_bytes()).hexdigest()
            for name in SOURCE_NAMES}


def arguments(case: dict) -> tuple:
    result = tuple((item['alias'], dict(item['key']), bytes.fromhex(item['hex']))
                   for item in case['originals'])
    if case['construction'] == 'sixteen_null_entries':
        return (None,) * 16
    if case['construction'] == 'same_alias_twice_65536_bytes':
        alias, key, _ = result[0]
        data = b'a' * 65536
        return ((alias, key, data), (alias, key, data))
    return result


def run_case(case: dict, checker) -> dict:
    raw = (EVIDENCE_ROOT / case['body_file']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != case['body_sha256']:
        raise ValueError('independent candidate identity changed')
    observed = checker(raw, arguments(case))
    compared = observed
    if 'selector_statuses' in case['expected'] and observed['status'] == 'ok':
        compared = dict(status=observed['status'], stage=observed['stage'],
                        selector_statuses=[v['status'] for v in observed['selectors']])
    return dict(id=case['id'], passed=compared == case['expected'],
                observed=observed, expected=case['expected'])


def host_probe(case: dict, checker) -> dict:
    calls = {'hash': 0, 'equality': 0}
    class TrapKey(str):
        def __hash__(self):
            calls['hash'] += 1
            return str.__hash__(self)

        def __eq__(self, other):
            calls['equality'] += 1
            return str.__eq__(self, other)

    raw = (EVIDENCE_ROOT / case['body_file']).read_bytes()
    alias, key, data = arguments(case)[0]
    hostile = {'logical_source_id': key['logical_source_id'],
               'sha256': key['sha256'], TrapKey('bytes'): key['bytes']}
    calls.update(hash=0, equality=0)
    observed = checker(raw, ((alias, hostile, data),))
    expected = dict(status='error', stage='SOURCE_ARGUMENTS', error='SOURCE_KEY_SHAPE')
    return dict(id='H01_NO_HOST_KEY_CALLBACKS', observed=observed, expected=expected,
                callbacks=dict(calls), passed=observed == expected and not any(calls.values()))


def main() -> None:
    before = pins()
    sys.path.insert(0, str(TASK_ROOT / 'tools'))
    from transport_quorum_source import check_source_membership
    source = (EVIDENCE_ROOT / 'additional-probes.json').read_bytes()
    cases = json.loads(source)['cases']
    if len(cases) != 14:
        raise ValueError('frozen probe count changed')
    outcomes = [run_case(case, check_source_membership) for case in cases]
    outcomes.append(host_probe(cases[3], check_source_membership))
    after = pins()
    result = dict(schema='quorum/source-independent-probe-results/1',
        source_pins=before, source_pins_after=after,
        probes_sha256=hashlib.sha256(source).hexdigest(), outcomes=outcomes,
        passed=before == after and all(v['passed'] for v in outcomes),
        full_replay='UNRUN', formal_proof='UNPROVEN')
    target = Path(sys.argv[1])
    raw = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    with target.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('short evidence write')
    print(json.dumps({'passed': result['passed'],
                      'failed': [v['id'] for v in outcomes if not v['passed']]}))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
