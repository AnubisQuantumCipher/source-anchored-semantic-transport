#!/usr/bin/env python3
"""Run frozen development graph oracles; preserve both parity-arm outputs."""

import argparse
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import transport_quorum_graph as graph

FIXTURES = ROOT / 'examples/quorum-graph-v1'
PINS = {
    'contract.json': '77b5a8338a93cf4d27703756c707005dd99ffa0507f9187cef0e1eeb1a734a6b',
    'oracle.json': '5cb3a7fe16707a285170c1c939f517ce4b6d07bd4cca7f9880440da2a84dcd56',
    'oracle-addendum.json': '49098105e857be5a993061cae578c819892d2176010cbaf90bc34cbd7f9ec5cc',
    'review.json': 'cceec14ab68e37d09fa1eee577ff95cd7315eaac1afdbb89abfde05dfe09d2e4',
}
OUTCOMES = []


def serialized(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def frozen(name: str) -> dict:
    path = FIXTURES / name
    if path.is_symlink() or not path.is_file():
        raise ValueError('fixture must be a regular source file')
    with path.open('rb') as stream:
        raw = stream.read(32769)
    if len(raw) > 32768 or hashlib.sha256(raw).hexdigest() != PINS[name]:
        raise ValueError('frozen fixture pin mismatch: ' + name)
    return json.loads(raw)


def corpus() -> tuple[list, list]:
    frozen('contract.json')
    frozen('review.json')
    original, additional = frozen('oracle.json'), frozen('oracle-addendum.json')
    graphs = original['graph_cases'] + additional['graph_cases']
    predecessors = original['predecessor_cases']
    if len(graphs) != 49 or len(predecessors) != 23:
        raise ValueError('frozen case count mismatch')
    return graphs, predecessors


class FrozenGraphTests(unittest.TestCase):
    def compare_case(self, case, kind):
        original = serialized(case['input'])
        outputs = []
        for arm in ('original_annotation', 'transport_projection'):
            value = json.loads(original)
            result = (graph.reverse_reachable(value) if kind == 'graph'
                      else graph.predecessor_order(value))
            OUTCOMES.append({'case': case['id'], 'arm': arm, 'result': result,
                             'expected': case['expected'],
                             'input_unchanged': serialized(value) == original})
            outputs.append(result)
            self.assertEqual(serialized(value), original)
            self.assertEqual(result, case['expected'])
        self.assertEqual(outputs[0], outputs[1])
        self.assertIsNot(outputs[0], outputs[1])
        if outputs[0]['status'] == 'ok':
            key = 'nodes' if kind == 'graph' else 'order'
            self.assertIsNot(outputs[0][key], outputs[1][key])
            # Mutating one result cannot affect another result or a later call.
            outputs[0][key].append(-1)
            self.assertEqual(outputs[1], case['expected'])
            outputs[0][key].pop()

    def test_frozen_graph_cases(self):
        graphs, _ = corpus()
        for case in graphs:
            with self.subTest(case=case['id']):
                self.compare_case(case, 'graph')

    def test_frozen_predecessor_cases(self):
        _, predecessors = corpus()
        for case in predecessors:
            with self.subTest(case=case['id']):
                self.compare_case(case, 'predecessor')

    def test_non_json_host_shapes(self):
        class DictSubclass(dict):
            pass

        empty = dict(schema=graph.GRAPH_SCHEMA, node_count=0, edges=[], changed_nodes=[])
        self.assertEqual(graph.reverse_reachable(DictSubclass(empty)),
                         {'status': 'error', 'error': 'G_OBJECT'})
        edge_tuple = dict(schema=graph.GRAPH_SCHEMA, node_count=2,
                          edges=[(1, 0)], changed_nodes=[0])
        self.assertEqual(graph.reverse_reachable(edge_tuple),
                         {'status': 'error', 'error': 'G_EDGE_SHAPE'})
        self.assertEqual(graph.predecessor_order((None, 0)),
                         {'status': 'error', 'error': 'P_ARRAY'})

    def test_result_mutation_cannot_poison_later_call(self):
        value = dict(schema=graph.GRAPH_SCHEMA, node_count=2,
                     edges=[[1, 0]], changed_nodes=[0])
        first = graph.reverse_reachable(value)
        first['nodes'].clear()
        first['status'] = 'invented'
        self.assertEqual(graph.reverse_reachable(value), {'status': 'ok', 'nodes': [0, 1]})
        first = graph.predecessor_order([None, 0])
        first['order'].clear()
        self.assertEqual(graph.predecessor_order([None, 0]), {'status': 'ok', 'order': [0, 1]})


def write_evidence(path: Path, result) -> None:
    source = ROOT / 'tools/transport_quorum_graph.py'
    value = {'schema': 'quorum/graph-development-results/1',
             'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
             'fixture_pins': PINS, 'python': sys.version,
             'passed': result.wasSuccessful(), 'test_methods': result.testsRun,
             'case_arm_outputs': OUTCOMES, 'scope': 'TESTED_COMPONENT_ONLY',
             'upstream_parsing': 'UNQUALIFIED', 'formal_proof': 'UNPROVEN',
             'full_replay': 'UNRUN', 'external_validation': 'EXTERNAL_VALIDATION_PENDING',
             'benefit': 'NOT_MEASURED; identical checker/annotations parity only'}
    raw = serialized(value)
    if len(raw) > 131072:
        raise ValueError('test evidence output cap exceeded')
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('short test evidence write')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path)
    args = parser.parse_args()
    result = unittest.TextTestRunner(verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(FrozenGraphTests))
    if args.evidence is not None:
        write_evidence(args.evidence, result)
    raise SystemExit(0 if result.wasSuccessful() else 1)


if __name__ == '__main__':
    main()
