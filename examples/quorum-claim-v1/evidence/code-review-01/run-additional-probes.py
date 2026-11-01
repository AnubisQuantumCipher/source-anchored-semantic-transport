"""Independent preimplementation-frozen Claim boundary probes."""

import base64
import hashlib
import inspect
import json
from pathlib import Path
import sys
from unittest.mock import patch

TASK_ROOT = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
EVIDENCE_ROOT = Path(__file__).resolve().parent
SOURCE_NAMES = ('transport_quorum_claim.py', 'transport_quorum_source.py',
                'transport_quorum_input.py', 'transport_quorum_shape.py',
                'transport_quorum_body.schema.json', 'transport_schema.py',
                'transport_wire.py')


def pins() -> dict:
    return {name: hashlib.sha256((TASK_ROOT / 'tools' / name).read_bytes()).hexdigest()
            for name in SOURCE_NAMES}


def run_case(case: dict, checker, source_module) -> dict:
    raw = (EVIDENCE_ROOT / case['body_file']).read_bytes()
    recipe = (EVIDENCE_ROOT / case['originals_file']).read_bytes()
    if hashlib.sha256(raw).hexdigest() != case['body_sha256']:
        raise ValueError('Body probe pin mismatch')
    if hashlib.sha256(recipe).hexdigest() != case['originals_sha256']:
        raise ValueError('Originals probe pin mismatch')
    originals = tuple((v['alias_id'], dict(v['key']),
                       base64.b64decode(v['base64'], validate=True))
                      for v in json.loads(recipe)['items'])
    if case['mode'] == 'source_output_cap_one':
        with patch.object(source_module, 'MAX_OUTPUT', 1):
            observed = checker(raw, originals)
    elif case['mode'] == 'originals_list':
        observed = checker(raw, list(originals))
    elif case['mode'] is None:
        observed = checker(raw, originals)
    else:
        raise ValueError('unfrozen probe mode')
    return dict(id=case['id'], observed=observed, expected=case['expected'],
                passed=observed == case['expected'])


def main() -> None:
    before = pins()
    sys.path.insert(0, str(TASK_ROOT / 'tools'))
    import transport_quorum_claim as claim
    import transport_quorum_source as source
    raw = (EVIDENCE_ROOT / 'additional-probes.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != '1ad79aecf506ddde09370dd32194f1b35b121ca857324ac289235410d4757a7e':
        raise ValueError('frozen probe manifest changed')
    cases = json.loads(raw)['cases']
    if len(cases) != 13:
        raise ValueError('frozen probe count changed')
    outcomes = [run_case(v, claim.check_claim_structure, source) for v in cases]
    parameters = inspect.signature(claim.check_claim_structure).parameters
    api = list(parameters)
    outcomes.append(dict(id='C14_NO_EXTERNAL_SCHEMA_ROOT_API', observed=api,
                         expected=['body_raw', 'originals'],
                         passed=api == ['body_raw', 'originals']))
    after = pins()
    result = dict(schema='quorum/claim-independent-additional-probe-results/1',
        source_pins=before, source_pins_after=after, outcomes=outcomes,
        probes_sha256=hashlib.sha256(raw).hexdigest(),
        passed=before == after and all(v['passed'] for v in outcomes),
        full_replay='UNRUN', formal_proof='UNPROVEN')
    encoded = json.dumps(result, sort_keys=True, separators=(',', ':')).encode()
    with Path(sys.argv[1]).open('xb') as stream:
        if stream.write(encoded) != len(encoded):
            raise OSError('short evidence write')
    print(json.dumps({'passed': result['passed'],
                     'failed': [v['id'] for v in outcomes if not v['passed']]}))
    raise SystemExit(0 if result['passed'] else 1)


if __name__ == '__main__':
    main()
