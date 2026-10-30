"""Bounded refinement controls with manual development references, no models."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tests'))
from sentinel_v1 import refinement as r
from sentinel_v1.bindings import registry_root
from sentinel_v1.common import SentinelError, canonical, digest, parse
from test_sentinel_challenges import packet


def advance(previous, value, registry, admission, answer=b'WRONG', changes=None):
    raw, authority = canonical(value), canonical(admission)
    registry[digest(answer)] = answer
    return r.advance(previous, None if previous is None else digest(previous), raw, digest(raw),
        registry, registry_root(registry), authority, digest(authority), {'Q1': answer},
        [] if changes is None else changes)


def revised(value, registry, admission, text):
    graph = parse(registry[value['graph_sha256']])
    graph['nodes'][0]['text'] = text
    raw = canonical(graph); registry[digest(raw)] = raw
    value['graph_sha256'] = digest(raw); admission['graph_sha256'] = digest(raw)


class RefinementControls(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('no execution')).start()

    def test_repair_retains_original_failure_and_invalidates_dependencies(self):
        value, registry, admission, _locator = packet()
        first = advance(None, value, registry, admission)
        old = parse(first)
        self.assertEqual(old['outcome'], 'UNRESOLVED')
        self.assertEqual(len(old['rounds'][0]['counterexamples']), 1)
        revised(value, registry, admission, 'Universal rule retains its maintenance exception.')
        second = parse(advance(first, value, registry, admission, b'MATERIAL_CHANGE', ['C1']))
        self.assertEqual(second['rounds'][0], old['rounds'][0])
        self.assertEqual(second['rounds'][1]['invalidated_nodes'], ['C1'])
        self.assertEqual(second['rounds'][1]['repair_parent_sha256s'],
                         [old['rounds'][0]['counterexamples'][0]['sha256']])
        self.assertEqual(second['outcome'], 'READY_FOR_NATIVE_POLICY_REVIEW')
        self.assertEqual(second['qualification'], 'NOT_QUALIFIED')

    def test_repeated_candidate_and_undeclared_changes_refuse(self):
        value, registry, admission, _locator = packet()
        first = advance(None, value, registry, admission)
        with self.assertRaises(SentinelError): advance(first, value, registry, admission)
        revised(value, registry, admission, 'Changed proposal')
        with self.assertRaises(SentinelError): advance(first, value, registry, admission)

    def test_edited_history_or_removed_counterexample_refuses(self):
        value, registry, admission, _locator = packet()
        first = advance(None, value, registry, admission)
        for change in ('removed', 'summary', 'result'):
            edited = parse(first)
            if change == 'removed': edited['rounds'][0]['counterexamples'] = []
            elif change == 'summary': edited['outcome'] = 'READY_FOR_NATIVE_POLICY_REVIEW'
            else: edited['rounds'][0]['results'][0]['status'] = 'MATCH_REFERENCE'
            raw = canonical(edited)
            with self.subTest(change=change), self.assertRaises(SentinelError):
                r.history_checked(raw, digest(raw))
        with self.assertRaises(SentinelError): r.history_checked(first, '0' * 64)

    def test_changed_oracles_or_source_cannot_borrow_qualification(self):
        value, registry, admission, _locator = packet()
        first = advance(None, value, registry, admission)
        revised(value, registry, admission, 'Changed proposal')
        probe = value['probes'][0]
        probe['id'] = 'Q2'
        with self.assertRaises(SentinelError):
            advance(first, value, registry, admission, changes=['C1'])

    def test_eight_round_bound_and_no_cycle(self):
        value, registry, admission, _locator = packet()
        prior = None
        for ordinal in range(8):
            if ordinal:
                revised(value, registry, admission, 'Candidate version ' + str(ordinal))
            prior = advance(prior, value, registry, admission,
                            changes=[] if ordinal == 0 else ['C1'])
        self.assertEqual(parse(prior)['outcome'], 'EXHAUSTED')
        revised(value, registry, admission, 'Candidate ninth version')
        with self.assertRaises(SentinelError):
            advance(prior, value, registry, admission, changes=['C1'])

    def test_impact_propagates_both_directions_conservatively(self):
        graph = {'nodes': [{'id': value} for value in ('CLAIM', 'EXCEPTION', 'OTHER')],
            'edges': [{'from': 'EXCEPTION', 'to': 'CLAIM', 'kind': 'EXCEPTION_TO'}]}
        self.assertEqual(r.affected(graph, ['CLAIM']), ['CLAIM', 'EXCEPTION'])
        self.assertEqual(r.affected(graph, ['OTHER']), ['OTHER'])

    def test_missing_exception_node_can_be_added_without_erasing_claim(self):
        value, registry, admission, _locator = packet()
        first = advance(None, value, registry, admission)
        graph = parse(registry[value['graph_sha256']])
        node = deepcopy(graph['nodes'][0])
        node.update(id='MAINTENANCE_EXCEPTION', kind='EXCEPTION', text='Unless maintenance is active.')
        graph['nodes'].append(node)
        graph['edges'].append({'from': node['id'], 'to': 'C1', 'kind': 'EXCEPTION_TO'})
        raw = canonical(graph); registry[digest(raw)] = raw
        value['graph_sha256'] = digest(raw); admission['graph_sha256'] = digest(raw)
        result = parse(advance(first, value, registry, admission, b'MATERIAL_CHANGE',
                               ['C1', 'MAINTENANCE_EXCEPTION']))
        self.assertEqual(result['rounds'][-1]['invalidated_nodes'], ['C1', 'MAINTENANCE_EXCEPTION'])

    def test_missing_raw_historical_answer_blocks_refinement(self):
        value, registry, admission, _locator = packet()
        first = advance(None, value, registry, admission)
        registry.pop(digest(b'WRONG'))
        revised(value, registry, admission, 'Repaired candidate')
        with self.assertRaises(SentinelError):
            advance(first, value, registry, admission, b'MATERIAL_CHANGE', ['C1'])

    def test_historical_impact_is_recomputed_from_each_graph_pair(self):
        value, registry, admission, _locator = packet()
        first = advance(None, value, registry, admission)
        revised(value, registry, admission, 'Second proposed reading')
        second = advance(first, value, registry, admission, changes=['C1'])
        revised(value, registry, admission, 'Third proposed reading')
        for ordinal, key, replacement in ((0, 'changed_nodes', ['C1']),
                (0, 'invalidated_nodes', ['C1']), (1, 'changed_nodes', []),
                (1, 'invalidated_nodes', [])):
            edited = parse(second)
            edited['rounds'][ordinal][key] = replacement
            with self.subTest(ordinal=ordinal, key=key), self.assertRaises(SentinelError):
                advance(canonical(edited), value, registry, admission, changes=['C1'])


if __name__ == '__main__':
    unittest.main()
