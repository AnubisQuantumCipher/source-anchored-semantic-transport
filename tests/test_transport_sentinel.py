"""Pure development fixtures; no actor, native policy, OCR or qualification."""
import ast
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import transport_sentinel as subject
from transport_document_io import canonical, digest, DocumentError
from transport_sentinel_export import export_policy_inputs

REQUIREMENT = (b'REQ-AUDIT: When a valid sample arrives, the controller shall append that sample '
               b'to the audit log, unless maintenance mode is active.\n')
CONFLICT = b'Witness A alleges the sample was logged. Witness B denies the sample was logged.\n'
QUESTIONS = [
    ('Q_REQUIRED', 'Valid sample arrives, maintenance inactive: does this requirement impose logging?',
     'REQUIRED'),
    ('Q_EXCEPTION', 'Maintenance active: does this sentence still establish the logging requirement?',
     'NO_REQUIREMENT_ESTABLISHED'),
    ('Q_PROHIBITION', 'Does the maintenance exception itself prohibit logging?',
     'PROHIBITION_NOT_ESTABLISHED'),
    ('Q_OCCURRED', 'Does the requirement alone establish that logging occurred?', 'UNKNOWN'),
    ('Q_CONFLICT', 'Does witness text contain both support and refutation of logged status?', 'CONFLICT')]
ANSWERS = [
    ['REQUIRED', 'REQUIRED', 'PROHIBITION_NOT_ESTABLISHED', 'UNKNOWN', 'CONFLICT'],
    ['REQUIRED', 'NO_REQUIREMENT_ESTABLISHED', 'PROHIBITED', 'UNKNOWN', 'CONFLICT'],
    ['REQUIRED', 'NO_REQUIREMENT_ESTABLISHED', 'PROHIBITION_NOT_ESTABLISHED', 'UNKNOWN', 'CONFLICT']]


class Fixture:
    def __init__(self, rounds=3):
        self.artifacts = {}
        self.source = self.put('REQUIREMENT', REQUIREMENT)
        self.other = self.put('CONFLICT_SOURCE', CONFLICT)
        self.source_set = self.put('SOURCE_SET', [self.source, self.other])
        self.note = self.put('NOTE', b'UNATTESTED MANUAL DEVELOPMENT FIXTURE')
        self.policy = self.put('POLICY', b'NO NATIVE POLICY OR PROOF')
        self.empty = self.put('UNKNOWN_REGIONS', [])
        self.graph = self.put('GRAPH', {'nodes': ['CLAIM'], 'edges': []})
        self.locators = [self.locator(self.source, REQUIREMENT, 'REQ'),
                         self.locator(self.other, CONFLICT, 'CONFLICT')]
        self.oracles, self.probes = self.questions()
        self.q_set = self.put('Q_SET', self.probes)
        self.oracle_set = self.put('ORACLE_SET', self.oracles)
        self.candidates, self.results, self.failures = [], [], []
        self.events = []
        for revision in range(rounds):
            self.add_round(revision)
        self.document = self.top()

    def put(self, name, data):
        raw = data if type(data) is bytes else canonical(data)
        self.artifacts[name] = raw
        return {'id': name, 'sha256': digest(raw), 'bytes': len(raw)}

    def locator(self, source, raw, suffix):
        return {'source_pin': source, 'representation_pin': source,
                'unit_id': suffix, 'kind': 'SOURCE_BYTES',
                'selector_pin': self.put('SELECTOR_' + suffix, {'start': 0, 'end': len(raw)}),
                'quote_pin': self.put('QUOTE_' + suffix, raw)}

    def questions(self):
        probes, oracles = [], []
        for index, (name, question, expected) in enumerate(QUESTIONS):
            question_pin = self.put('QUESTION_' + str(index), question.encode())
            oracle = {'id': 'ORACLE_' + str(index), 'question_pin': question_pin,
                      'source_set_pin': self.source_set,
                      'answer_pin': self.put('EXPECTED_' + str(index), expected.encode()),
                      'adjudication_pin': self.note, 'provenance_pin': self.note,
                      'trust_policy_pin': self.note, 'kind': 'MANUAL_DEVELOPMENT_FIXTURE'}
            oracles.append(oracle)
            probes.append({'id': name, 'claim_id': 'CLAIM', 'question_pin': question_pin,
                           'scenario_pin': self.note,
                           'source_evidence': [self.locators[index == 4]],
                           'oracle_pin': self.put(oracle['id'], oracle),
                           'relation': 'EXACT_ANSWER_DIGEST', 'checker_pin': self.note,
                           'materiality_pin': self.note})
        return oracles, probes

    def add_event(self, kind, record_pin):
        sequence = len(self.events)
        previous = None if sequence == 0 else self.put('H_' + str(sequence - 1), self.events[-1])
        self.events.append({'sequence': sequence, 'previous_pin': previous, 'kind': kind,
                            'record_pin': record_pin, 'evidence_pin': self.note})

    def add_round(self, revision):
        claim = {'id': 'CLAIM', 'claim_text_pin': self.put('CLAIM_TEXT_' + str(revision),
                 ('Opaque candidate ' + str(revision)).encode()), 'evidence': [self.locators[0]],
                 'required_context': [self.source, self.other], 'interpretation': 'OPAQUE_PROPOSED',
                 'formal_payload_pin': None, 'interpretation_entailment': 'UNPROVEN'}
        previous = None if revision == 0 else self.put(self.candidates[-1]['id'], self.candidates[-1])
        candidate = {'id': 'C' + str(revision), 'revision': revision, 'predecessor_pin': previous,
                     'source_set_pin': self.source_set, 'q_set_pin': self.q_set, 'claims': [claim],
                     'dependency_graph_pin': self.graph, 'unknown_regions_pin': self.empty,
                     'change_reason_pin': None if revision == 0 else self.note}
        self.candidates.append(candidate)
        candidate_pin = self.put(candidate['id'], candidate)
        self.add_event('CANDIDATE', candidate_pin)
        for failure in self.failures:
            payload = {'candidate_pin': candidate_pin,
                       'counterexample_pin': self.put(failure['id'], failure)}
            self.add_event('REPAIR_LINK', self.put('REPAIR_' + str(revision) + '_' + failure['id'], payload))
        for index in range(5):
            self.add_result(revision, index, candidate_pin)

    def add_result(self, revision, index, candidate_pin):
        actual = ANSWERS[revision][index]
        expected = QUESTIONS[index][2]
        status = 'MATCH' if actual == expected else 'MISMATCH'
        probe = self.probes[index]
        row = {'id': 'R_' + str(revision) + '_' + str(index), 'candidate_pin': candidate_pin,
               'probe_pin': self.put(probe['id'], probe), 'oracle_pin': probe['oracle_pin'],
               'answer_pin': self.put('ANSWER_' + str(revision) + '_' + str(index), actual.encode()),
               'input_manifest_pin': self.note, 'evaluator_pin': self.note,
               'run_evidence_pin': self.note, 'comparison_receipt_pin': self.note, 'status': status}
        self.results.append(row)
        result_pin = self.put(row['id'], row)
        self.add_event('RESULT', result_pin)
        if status == 'MISMATCH':
            failure = {'id': 'F_' + str(revision) + '_' + str(index), 'candidate_pin': candidate_pin,
                       'probe_result_pin': result_pin, 'source_evidence': [self.locators[index == 4]],
                       'expected_pin': self.oracles[index]['answer_pin'], 'actual_pin': row['answer_pin'],
                       'status': 'CONFIRMED_RELATIVE_TO_ORACLE', 'resolution_event_pins': []}
            self.failures.append(failure)
            self.add_event('COUNTEREXAMPLE', self.put(failure['id'], failure))

    def top(self):
        qualification = {'candidate_pin': self.put(self.candidates[-1]['id'], self.candidates[-1]),
                         'q_set_pin': self.q_set, 'oracle_set_pin': self.oracle_set,
                         'source_set_pin': self.source_set, 'policy_pin': self.policy,
                         'results_pin': self.put('RESULTS_' + str(len(self.candidates)), self.results),
                         'failure_history_pin': self.put('HISTORY_' + str(len(self.candidates)), self.events),
                         'kernel_pin': None, 'kernel_qualification_pin': None, 'native_decision_pin': None,
                         'status': 'NOT_QUALIFIED', 'ceiling': 'DEVELOPMENT_FIXTURE_ONLY',
                         'semantic_completeness': 'UNPROVEN', 'world_truth': 'NOT_CERTIFIED',
                         'execution_authority': 'NONE'}
        return {'schema': 'sentinel/sidecar-exact/1', 'design_source_pin': self.note,
                'previous_sidecar_pin': None,
                'source_set_pin': self.source_set, 'q_set_pin': self.q_set,
                'oracle_set_pin': self.oracle_set, 'policy_pin': self.policy,
                'candidates': self.candidates, 'probes': self.probes, 'oracles': self.oracles,
                'results': self.results, 'counterexamples': self.failures, 'history': self.events,
                'ledger': [{'claim_id': 'CLAIM', 'support_pins': [self.source],
                            'refutation_pins': [self.other], 'state': 'BOTH',
                            'meaning': 'DOCUMENTARY_EVIDENCE_NOT_TRUTH'}],
                'qualification': qualification}

    def prune(self, document=None):
        pending, used = [self.document if document is None else document], set()
        for _ in range(32768):
            if not pending:
                return {key: self.artifacts[key] for key in used}
            row = pending.pop()
            if type(row) is list:
                pending.extend(row)
            elif type(row) is dict:
                if set(row) == {'id', 'bytes', 'sha256'} and row['id'] not in used:
                    used.add(row['id'])
                    try:
                        pending.append(json.loads(self.artifacts[row['id']]))
                    except (ValueError, UnicodeError):
                        pass
                else:
                    pending.extend(row.values())
        raise ValueError('fixture reachability bound')

    def arguments(self, document=None, artifacts=None):
        value = self.document if document is None else document
        supplied = self.prune(value) if artifacts is None else artifacts
        raw = canonical(value)
        return raw, supplied, digest(raw), digest(subject.registry_manifest(supplied))


class SentinelControls(unittest.TestCase):
    def setUp(self):
        self.process = patch.object(subprocess, 'Popen', side_effect=AssertionError('process forbidden'))
        self.process.start()
        self.addCleanup(self.process.stop)
        self.fixture = Fixture()

    def refused(self, document=None, artifacts=None, pattern=None):
        arguments = self.fixture.arguments(document, artifacts)
        with self.assertRaisesRegex(DocumentError, pattern or '.'):
            subject.validate_sidecar(*arguments)

    def extension(self):
        previous, current = Fixture(1), Fixture(3)
        for name, data in previous.prune().items():
            if name in current.artifacts:
                self.assertEqual(data, current.artifacts[name])
            current.artifacts[name] = data
        raw = canonical(previous.document)
        current.document['previous_sidecar_pin'] = current.put('PREVIOUS_SNAPSHOT', raw)
        return previous, current, raw

    def test_frozen_literal_sources_and_expected_answers_are_unchanged(self):
        self.assertEqual(hashlib.sha256(REQUIREMENT).hexdigest(),
                         'fb38a9f804dc4f1a362286e7ac6fea3448401619cee6c2457e653596b357a02c')
        self.assertEqual(hashlib.sha256(CONFLICT).hexdigest(),
                         '8375b6cf0af827d936e1930ac23c510de7b921327e87f76df3c4b39984ef1065')
        self.assertEqual([name for name, _, _ in QUESTIONS],
                         ['Q_REQUIRED', 'Q_EXCEPTION', 'Q_PROHIBITION', 'Q_OCCURRED', 'Q_CONFLICT'])
        self.assertEqual([row['status'] for row in self.fixture.results[:5]],
                         ['MATCH', 'MISMATCH', 'MATCH', 'MATCH', 'MATCH'])
        self.assertEqual([row['status'] for row in self.fixture.results[5:10]],
                         ['MATCH', 'MATCH', 'MISMATCH', 'MATCH', 'MATCH'])
        self.assertEqual([row['status'] for row in self.fixture.results[10:]], ['MATCH'] * 5)

    def test_repaired_literal_retains_both_failures_without_qualification(self):
        report = subject.validate_sidecar(*self.fixture.arguments())
        self.assertEqual(report['retained_results'], 15)
        self.assertEqual(report['retained_failures'], 2)
        self.assertEqual(report['repair_links'], 3)
        self.assertEqual(report['qualification'], 'NOT_QUALIFIED')
        self.assertEqual(report['execution_authority'], 'NONE')
        self.assertEqual(report['semantic_completeness'], 'UNPROVEN')

    def test_export_has_actual_expected_digests_and_no_verdict_authority(self):
        value = json.loads(export_policy_inputs(*self.fixture.arguments()))
        self.assertEqual(value['status'], 'NOT_QUALIFIED')
        self.assertEqual(value['probes'][3]['expected_answer_sha256'], digest(b'UNKNOWN'))
        self.assertEqual(value['probes'][4]['expected_answer_sha256'], digest(b'CONFLICT'))
        self.assertEqual(value['results'][1]['actual_answer_sha256'], digest(b'REQUIRED'))
        self.assertEqual(value['results'][1]['blocker'], 'NONE')
        self.assertNotIn('MATCH', repr(value))
        for forbidden in ('accepted', 'eligible', 'PASS', 'QUALIFIED_FOR_Q'):
            self.assertNotIn(forbidden, repr(value))

    def test_wrong_sidecar_and_registry_expected_pins_refuse(self):
        args = list(self.fixture.arguments())
        for index in (2, 3):
            changed = list(args)
            changed[index] = '0' * 64
            with self.assertRaisesRegex(DocumentError, 'pin mismatch'):
                subject.validate_sidecar(*changed)

    def test_current_unreachable_registry_artifact_refuses(self):
        artifacts = self.fixture.prune()
        artifacts['UNREACHABLE'] = b'cannot hide this byte artifact'
        self.refused(artifacts=artifacts, pattern='unreachable current')

    def test_pin_bytes_and_missing_required_context_refuse(self):
        for remove in (True, False):
            artifacts = self.fixture.prune()
            if remove:
                del artifacts['REQUIREMENT']
            else:
                artifacts['REQUIREMENT'] = REQUIREMENT.replace(b'unless', b'except')
            self.refused(artifacts=artifacts, pattern='unresolved|pin mismatch')

    def test_exact_source_quote_and_selector_refuse_wrong_bytes(self):
        for name in ('QUOTE_REQ', 'SELECTOR_REQ'):
            artifacts = self.fixture.prune()
            artifacts[name] = b'WRONG' if name == 'QUOTE_REQ' else canonical({'start': 0, 'end': 1})
            self.refused(artifacts=artifacts, pattern='pin mismatch')

    def test_old_relation_and_unsupported_locator_and_formal_fragment_refuse(self):
        for field, value in (('relation', 'EXACT_CLOSED_LABEL'), ('relation', 'EXACT_CANONICAL_BYTES'),
                             ('relation', 'EXISTING_GRAMMAR3_NATIVE_VALUE')):
            changed = copy.deepcopy(self.fixture.document)
            changed['probes'][0][field] = value
            self.refused(changed, pattern='unsupported')
        changed = copy.deepcopy(self.fixture.document)
        changed['probes'][0]['source_evidence'][0]['kind'] = 'PDF_REGION'
        self.refused(changed, pattern='unsupported')
        changed = copy.deepcopy(self.fixture.document)
        changed['candidates'][0]['claims'][0]['interpretation'] = 'EXISTING_GRAMMAR3'
        self.refused(changed, pattern='unsupported')

    def test_imported_result_ledger_and_qualification_escalation_refuse(self):
        for key, expected in (('results', 'MATCH'), ('ledger', 'SUPPORTED_ONLY'),
                              ('qualification', 'QUALIFIED_FOR_Q')):
            changed = copy.deepcopy(self.fixture.document)
            if key == 'results':
                changed[key][1]['status'] = expected
            elif key == 'ledger':
                changed[key][0]['state'] = expected
            else:
                changed[key]['status'] = expected
            self.refused(changed)

    def test_empty_q_missing_duplicate_and_wrong_kind_results_refuse(self):
        for operation in ('empty_q', 'missing', 'duplicate', 'wrong_kind'):
            changed = copy.deepcopy(self.fixture.document)
            if operation == 'empty_q':
                changed['probes'] = []
            elif operation == 'missing':
                changed['results'].pop()
            elif operation == 'duplicate':
                changed['results'].append(changed['results'][0])
            else:
                changed['results'][0]['probe_pin'] = changed['results'][0]['candidate_pin']
            self.refused(changed)

    def test_erased_failure_and_nonempty_future_resolution_backlink_refuse(self):
        changed = copy.deepcopy(self.fixture.document)
        changed['counterexamples'].pop(0)
        self.refused(changed, pattern='omission|record')
        changed = copy.deepcopy(self.fixture.document)
        changed['counterexamples'][0]['resolution_event_pins'] = [self.fixture.note]
        self.refused(changed, pattern='count')

    def test_unknown_fields_duplicate_json_and_noncanonical_payload_refuse(self):
        changed = copy.deepcopy(self.fixture.document)
        changed['accepted'] = True
        self.refused(changed, pattern='fields')
        arguments = list(self.fixture.arguments())
        for raw in (arguments[0] + b'\n', b'{"schema":1,"schema":2}', b'\xff'):
            arguments[0], arguments[2] = raw, digest(raw)
            with self.assertRaises(DocumentError):
                subject.validate_sidecar(*arguments)

    def test_resource_bounds_boolean_integer_and_depth_refuse(self):
        args = list(self.fixture.arguments())
        for raw in (b' ' * 65537, b'[' * 33 + b'0' + b']' * 33):
            changed = [raw, args[1], digest(raw), args[3]]
            with self.assertRaises(DocumentError):
                subject.validate_sidecar(*changed)
        changed = copy.deepcopy(self.fixture.document)
        changed['candidates'][0]['revision'] = False
        self.refused(changed)
        with self.assertRaisesRegex(DocumentError, 'count'):
            subject.registry_manifest({'A' + str(i): b'' for i in range(257)})
        with self.assertRaisesRegex(DocumentError, 'byte'):
            subject.registry_manifest({'LARGE': b'x' * 65537})

    def test_owned_ast_functions_are_bounded_and_compile(self):
        for relative in ('tools/transport_sentinel.py', 'tools/transport_sentinel_export.py',
                         'tests/test_transport_sentinel.py'):
            path = ROOT / relative
            raw = path.read_bytes()
            self.assertLessEqual(len(raw), 131072)
            tree = ast.parse(raw, filename=str(path))
            compile(tree, str(path), 'exec', dont_inherit=True)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, node.name)

    def test_valid_append_keeps_declared_prior_snapshot_aggregates_reachable(self):
        _, current, raw = self.extension()
        arguments = current.arguments()
        self.assertIn('HISTORY_1', arguments[1])
        self.assertIn('RESULTS_1', arguments[1])
        result = subject.validate_sidecar(*arguments, previous_raw=raw,
                                           expected_previous_sha256=digest(raw))
        self.assertEqual(result['retained_failures'], 2)
        self.assertEqual(result['qualification'], 'NOT_QUALIFIED')
        exported = json.loads(export_policy_inputs(*arguments, previous_raw=raw,
                             expected_previous_sha256=digest(raw)))
        self.assertEqual(len(exported['results']), 15)

    def test_append_missing_previous_tuple_or_snapshot_pin_refuses(self):
        _, current, raw = self.extension()
        for supplied, pin in ((None, None), (raw, None), (None, digest(raw)), (raw, '0' * 64)):
            with self.assertRaises(DocumentError):
                subject.validate_sidecar(*current.arguments(), previous_raw=supplied,
                                         expected_previous_sha256=pin)
        artifacts = current.prune()
        del artifacts['PREVIOUS_SNAPSHOT']
        with self.assertRaisesRegex(DocumentError, 'unresolved'):
            subject.validate_sidecar(*current.arguments(artifacts=artifacts), previous_raw=raw,
                                     expected_previous_sha256=digest(raw))

    def test_append_cannot_hide_unreachable_extra_or_redefine_old_pinid(self):
        _, current, raw = self.extension()
        for name, value in (('NEW_HIDDEN', b'hidden'), ('RESULTS_1', b'changed prior aggregate')):
            artifacts = current.prune()
            artifacts[name] = value
            with self.assertRaisesRegex(DocumentError, 'unreachable|pin mismatch'):
                subject.validate_sidecar(*current.arguments(artifacts=artifacts), previous_raw=raw,
                                         expected_previous_sha256=digest(raw))

    def test_exact_prior_prefix_and_fixed_q_cannot_be_rewritten(self):
        previous, current, _ = self.extension()
        for key in ('candidates', 'results', 'counterexamples', 'history', 'probes', 'oracles'):
            changed = copy.deepcopy(current.document)
            if key in ('probes', 'oracles'):
                changed[key][0]['id'] = 'CHANGED'
            else:
                changed[key][0]['injected'] = 'rewritten'
            with self.assertRaisesRegex(DocumentError, 'rewritten|epoch changed'):
                subject.check_prefix(previous.document, changed)
        with self.assertRaisesRegex(DocumentError, 'does not progress'):
            subject.check_prefix(previous.document, previous.document)

    def test_source_quote_and_selector_content_checks_after_valid_repins(self):
        locator = copy.deepcopy(self.fixture.locators[0])
        locator['quote_pin'] = self.fixture.put('WRONG_QUOTE', b'This is not the cited source')
        artifacts = self.fixture.artifacts
        context = subject.registry_context(artifacts, digest(subject.registry_manifest(artifacts)))
        with self.assertRaisesRegex(DocumentError, 'source quote mismatch'):
            subject.source_locator(locator, [self.fixture.source], context)
        for selector in ({'start': False, 'end': 1}, {'start': 0, 'end': 134},
                         {'start': 1, 'end': 1}, {'start': -1, 'end': 1}):
            locator = copy.deepcopy(self.fixture.locators[0])
            locator['selector_pin'] = self.fixture.put('WRONG_SELECTOR', selector)
            context = subject.registry_context(artifacts, digest(subject.registry_manifest(artifacts)))
            with self.assertRaises(DocumentError):
                subject.source_locator(locator, [self.fixture.source], context)

    def test_dependency_cycles_unknown_nodes_and_edge_overflow_refuse(self):
        for graph in ({'nodes': ['CLAIM'], 'edges': [['CLAIM', 'CLAIM']]},
                      {'nodes': ['CLAIM'], 'edges': [['CLAIM', 'UNKNOWN']]},
                      {'nodes': ['CLAIM'], 'edges': [['CLAIM', 'CLAIM']] * 65}):
            candidate = copy.deepcopy(self.fixture.candidates[0])
            candidate['dependency_graph_pin'] = self.fixture.put('BAD_GRAPH', graph)
            artifacts = self.fixture.artifacts
            context = subject.registry_context(artifacts, digest(subject.registry_manifest(artifacts)))
            with self.assertRaises(DocumentError):
                subject.dependency_graph(candidate, context)

    def test_unknown_false_and_conflict_true_stay_exact_mismatches(self):
        answers = copy.deepcopy(ANSWERS)
        answers[2][3], answers[2][4] = 'FALSE', 'TRUE'
        with patch.dict(globals(), {'ANSWERS': answers}):
            changed = Fixture()
        result = subject.validate_sidecar(*changed.arguments())
        self.assertEqual(result['retained_failures'], 4)
        self.assertEqual([row['status'] for row in changed.results[-2:]], ['MISMATCH', 'MISMATCH'])
        self.assertEqual(changed.document['ledger'][0]['state'], 'BOTH')
        self.assertEqual(result['qualification'], 'NOT_QUALIFIED')

    def test_consistent_spurious_label_counterexample_is_now_refused(self):
        original = Fixture.add_result
        def spurious(fixture, revision, index, candidate_pin):
            count = len(fixture.failures)
            original(fixture, revision, index, candidate_pin)
            if len(fixture.failures) > count:
                failure = fixture.failures[-1]
                failure['status'] = 'SPURIOUS_RELATIVE_TO_ORACLE'
                fixture.events[-1]['record_pin'] = fixture.put(failure['id'], failure)
        with patch.object(Fixture, 'add_result', spurious):
            bad = Fixture()
        self.assertEqual(len(bad.failures), 2)
        self.assertEqual([row['status'] for row in bad.results if row['status'] != 'MATCH'],
                         ['MISMATCH', 'MISMATCH'])
        with self.assertRaisesRegex(DocumentError, 'unsupported SENTINEL value'):
            subject.validate_sidecar(*bad.arguments())

    def test_registry_swap_after_hash_cannot_bind_different_bytes(self):
        old_note = self.fixture.artifacts['NOTE']
        replacement = old_note[:-1] + b'!'
        original_put = Fixture.put
        def changed_note(fixture, name, value):
            return original_put(fixture, name, replacement if name == 'NOTE' else value)
        with patch.object(Fixture, 'put', changed_note):
            changed = Fixture()
        artifacts = changed.prune()
        artifacts['NOTE'] = old_note
        arguments = changed.arguments(artifacts=artifacts)
        with self.assertRaisesRegex(DocumentError, 'artifact pin mismatch'):
            subject.validate_sidecar(*arguments)
        original_manifest = subject.registry_manifest
        observed = []
        def swap(captured):
            manifest = original_manifest(captured)
            artifacts['NOTE'] = replacement
            observed.append(True)
            return manifest
        with patch.object(subject, 'registry_manifest', side_effect=swap):
            with self.assertRaisesRegex(DocumentError, 'artifact pin mismatch'):
                subject.validate_sidecar(*arguments)
        self.assertEqual(observed, [True])
        self.assertEqual(artifacts['NOTE'], replacement)

    def test_matching_private_snapshot_ignores_later_caller_mutation(self):
        arguments = self.fixture.arguments()
        artifacts = arguments[1]
        original_manifest = subject.registry_manifest
        def mutate_caller(captured):
            manifest = original_manifest(captured)
            artifacts['NOTE'] = b'caller changed this after capture'
            artifacts['LATE_HIDDEN'] = b'not part of the captured inventory'
            return manifest
        with patch.object(subject, 'registry_manifest', side_effect=mutate_caller):
            report = subject.validate_sidecar(*arguments)
        self.assertEqual(report['registry_sha256'], arguments[3])
        self.assertEqual(report['qualification'], 'NOT_QUALIFIED')
        self.assertNotEqual(digest(subject.registry_manifest(artifacts)), arguments[3])

    def test_structural_dict_mutation_during_bounded_capture_refuses(self):
        artifacts = {'FIRST': b'one', 'SECOND': b'two'}
        original_identifier = subject.identifier
        def grow(name):
            original_identifier(name)
            artifacts['NEW'] = b'growth after iterator creation'
        with patch.object(subject, 'identifier', side_effect=grow):
            with self.assertRaisesRegex(DocumentError, 'mutated during snapshot'):
                subject.registry_snapshot(artifacts)


if __name__ == '__main__':
    unittest.main()
