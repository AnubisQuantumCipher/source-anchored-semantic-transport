"""Replay the separately frozen endpoint-category oracle, no native/model calls."""
from copy import deepcopy
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools')); sys.path.insert(0, str(ROOT / 'tests'))
from sentinel_v1 import graph
from sentinel_v1.common import SentinelError, canonical, digest
from test_sentinel_meaning import fixture, root_of


def main():
    path = Path(__file__).resolve().parent / 'evidence/endpoint-oracle.json'
    raw = path.read_bytes()
    if len(raw) > 16384:
        raise ValueError('oracle bound')
    cases = json.loads(raw)['cases']
    if len(cases) != 20:
        raise ValueError('frozen case count')
    for case in cases:
        value, registry = fixture()
        value['nodes'][0]['kind'] = case['source_kind']
        second = deepcopy(value['nodes'][0]); second.update(id='OTHER', kind=case['target_kind'])
        value['nodes'].append(second)
        value['edges'] = [{'from': 'C1', 'to': 'OTHER', 'kind': case['relation']}]
        encoded = canonical(value)
        try:
            graph.validate_graph(encoded, registry, root_of(registry), digest(encoded))
        except SentinelError:
            observed = False
        else:
            observed = True
        if observed is not case['allowed']:
            raise ValueError('endpoint oracle mismatch: ' + repr(case))
    print('20 frozen endpoint cases PASS; structural categories only')


if __name__ == '__main__':
    main()
