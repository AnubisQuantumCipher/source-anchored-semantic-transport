"""Developmental material-change oracles; not held-out language-understanding trials."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tests'))
from sentinel_v1 import challenges as q
from sentinel_v1 import bindings
from sentinel_v1.common import SentinelError, canonical, digest, identity, parse
from test_sentinel_meaning import fixture


def packet():
    before = b'All controllers shall log every sample unless maintenance is active.'
    graph, registry = fixture(before)
    evidence = graph['nodes'][0]['evidence'][0]
    evidence.update(end=len(before), quote_sha256=digest(before))
    graph['nodes'][0]['text'] = before.decode()
    source = graph['source_set'][0]
    locator = {'schema': 'sentinel/evidence-locator/1', 'id': 'L1',
        **{key: source[key] for key in ('source', 'revision', 'representation')},
        'selector': {'kind': 'SOURCE_BYTES', 'start': 0, 'end': len(before),
                     'quote_sha256': digest(before)}, 'dependencies': []}
    after, transformation = q.mutate(before, 0, 3, b'Some', 'CHANGING_PROPOSED')
    blobs = [canonical(graph), canonical(graph['source_set']), canonical(locator), before,
             after, b'Some', Path(q.__file__).read_bytes(), b'MATERIAL_CHANGE',
             b'Manual development oracle: all versus some is material for this task.',
             b'No independent human or model assessment supplied.']
    for raw in blobs:
        registry[digest(raw)] = raw
    probe = {'id': 'Q1', 'claim_id': 'C1', 'target_locator_sha256': digest(canonical(locator)),
        'input_pin': identity(after), 'transformation': transformation, 'oracle_pin': None,
        'checker_sha256': q.SOURCE_EPOCH}
    oracle = {'schema': 'sentinel/challenge-oracle/1', 'probe_id': 'Q1',
        'input_sha256': digest(after), 'source_set_sha256': digest(canonical(graph['source_set'])),
        'answer_pin': identity(blobs[7]), 'relation': 'MATERIAL_DIFFERENCE',
        'adjudication_pin': identity(blobs[8]), 'provenance_pin': identity(blobs[9])}
    oracle_raw = canonical(oracle); registry[digest(oracle_raw)] = oracle_raw
    probe['oracle_pin'] = identity(oracle_raw)
    value = {'schema': q.PROFILE, 'graph_sha256': digest(canonical(graph)),
        'source_set_sha256': oracle['source_set_sha256'], 'probes': [probe]}
    admission = {'schema': 'sentinel/challenge-admission/1',
        'graph_sha256': value['graph_sha256'], 'source_set_sha256': value['source_set_sha256'],
        'checker_sha256': q.SOURCE_EPOCH, 'oracles': {'Q1': digest(oracle_raw)}}
    return value, registry, admission, locator


class ChallengeControls(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('native/models forbidden')).start()

    def replay(self, value, registry, admission, answers=None):
        raw, held = canonical(value), canonical(admission)
        return parse(q.replay(raw, digest(raw), registry, bindings.registry_root(registry),
            held, digest(held), {'Q1': b'MATERIAL_CHANGE'} if answers is None else answers))

    def test_manual_reference_match_is_not_qualification(self):
        value, registry, admission, _locator = packet()
        result = self.replay(value, registry, admission)
        self.assertEqual(result['results'][0]['status'], 'MATCH_REFERENCE')
        self.assertEqual(result['qualification'], 'NOT_QUALIFIED')
        self.assertEqual(result['execution_authority'], 'NONE')
        self.assertIn('NOT_MODEL_EXECUTION', result['scope'])

    def test_mismatch_missing_answer_and_unresolved_oracle(self):
        value, registry, admission, _locator = packet()
        self.assertEqual(self.replay(value, registry, admission, {'Q1': b'UNCHANGED'})
                         ['results'][0]['status'], 'MISMATCH_REFERENCE')
        self.assertEqual(self.replay(value, registry, admission, {})['results'][0]['status'], 'UNRUN')
        value['probes'][0]['oracle_pin'] = None; admission['oracles'] = {}
        self.assertEqual(self.replay(value, registry, admission)['results'][0]['status'],
                         'UNRESOLVED_ORACLE')

    def test_oracle_cannot_admit_itself_or_retarget_input(self):
        for change in ('admission', 'input', 'class', 'target'):
            value, registry, admission, _locator = packet()
            if change == 'admission': admission['oracles']['Q1'] = '0' * 64
            elif change == 'input': value['probes'][0]['input_pin'] = identity(b'wrong')
            elif change == 'class': value['probes'][0]['transformation']['class'] = 'PRESERVING_PROPOSED'
            else: value['probes'][0]['claim_id'] = 'MISSING'
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.replay(value, registry, admission)

    def test_generator_cannot_mark_its_own_equivalence(self):
        value, registry, admission, _locator = packet()
        value['probes'][0]['transformation']['oracle_status'] = 'QUALIFIED'
        with self.assertRaises(SentinelError):
            self.replay(value, registry, admission)

    def test_missing_or_wrong_checker_and_duplicate_probe(self):
        for change in ('missing', 'forged', 'duplicate'):
            value, registry, admission, _locator = packet()
            if change == 'missing': registry.pop(q.SOURCE_EPOCH)
            elif change == 'forged':
                registry[digest(b'fake checker')] = b'fake checker'
                value['probes'][0]['checker_sha256'] = digest(b'fake checker')
                admission['checker_sha256'] = digest(b'fake checker')
            else: value['probes'].append(deepcopy(value['probes'][0]))
            with self.subTest(change=change), self.assertRaises(SentinelError):
                self.replay(value, registry, admission)

    def test_changed_graph_window_and_source_set_refuse(self):
        for change in ('window', 'set'):
            value, registry, admission, _locator = packet()
            if change == 'window':
                window = b'All controllers shall log every sample unless maintenance is active.'
                registry.pop(digest(window))
            else:
                raw = canonical([]); registry[digest(raw)] = raw
                value['source_set_sha256'] = digest(raw); admission['source_set_sha256'] = digest(raw)
            with self.subTest(change=change), self.assertRaises(SentinelError):
                self.replay(value, registry, admission)

    def test_replay_mutations_do_not_normalize_numbers_or_unicode(self):
        before = '225Q at 100 ms — µ'.encode()
        for start, end, replacement in ((0, 4, b'226Q'), (8, 11, b'101'), (0, 0, b'')):
            after, record = q.mutate(before, start, end, replacement, 'CHANGING_PROPOSED')
            registry = {digest(raw): raw for raw in (before, after, replacement)}
            self.assertEqual(q.transformation(record, registry), after)
        for start, end in ((True, 1), (0, len(before) + 1), (-1, 0)):
            with self.assertRaises(SentinelError):
                q.mutate(before, start, end, b'', 'CHANGING_PROPOSED')

    def test_unknown_answers_and_answer_resource_bounds(self):
        value, registry, admission, _locator = packet()
        for answers in ({'OTHER': b'yes'}, {'Q1': bytearray(b'yes')}, {'Q1': b'x' * 65537}):
            with self.assertRaises(SentinelError):
                self.replay(value, registry, admission, answers)

    def test_resolved_source_wrapper_checks_full_graph_binding(self):
        value, registry, admission, locator = packet()
        before = q.artifact(value['probes'][0]['transformation']['before_pin'], registry)
        resolution = {'status': 'RESOLVED_BYTES', 'locator_sha256': digest(canonical(locator)),
            'package_id': locator['source']['package_id'], 'coordinate_kind': 'SOURCE_BYTE',
            **{key: locator[key] for key in ('source', 'revision', 'representation')},
            'parts': [{'span': [0, len(before)], 'data': before, 'sha256': digest(before)}],
            'dependency_locator_sha256s': []}
        raw, held = canonical(value), canonical(admission)
        args = (raw, digest(raw), registry, bindings.registry_root(registry), held, digest(held),
                {'Q1': b'MATERIAL_CHANGE'}, 'archive', 'share', canonical(locator),
                digest(canonical(locator)), {}, '0' * 64, {}, '0' * 64)
        with patch('sentinel_v1.locators.resolve_locator', return_value=resolution):
            result = parse(q.replay_source_bound(*args))
            self.assertEqual(result['source_evidence']['status'], 'CHECKED_WINDOW_BYTES_TO_VALIDATED_PACKAGE')
            resolution['revision'] = dict(resolution['revision'], id='SWAPPED')
            with self.assertRaises(SentinelError): q.replay_source_bound(*args)


if __name__ == '__main__':
    unittest.main()
