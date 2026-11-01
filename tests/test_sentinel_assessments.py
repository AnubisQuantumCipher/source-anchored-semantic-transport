"""Developmental recorded-review/four-arm controls; no provider or native calls."""
from contextlib import contextmanager
import base64
from copy import deepcopy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools')); sys.path.insert(0, str(ROOT / 'tests'))
from sentinel_v1 import assessments as a, comparison as c, bindings
from sentinel_v1.common import SentinelError, canonical, digest, identity, parse
from test_sentinel_meaning import fixture


def put(registry, raw):
    registry[digest(raw)] = raw
    return identity(raw)


def reviewer(registry, response=b'answer'):
    return {'origin': 'MANUAL_FIXTURE', 'declared_identity': 'manual development fixture',
            'observed_identity_pin': None, 'invocation_pin': None,
            'settings_pin': put(registry, b'{}'), 'prompt_pin': put(registry, b'Task'),
            'raw_response_pin': put(registry, response)}


def review_packet(category='UNRESOLVED_AMBIGUITY'):
    graph, registry = fixture()
    graph_pin = put(registry, canonical(graph)); source_pin = put(registry, canonical(graph['source_set']))
    task = put(registry, b'Task')
    record = {'id': 'R1', 'claim_id': 'C1', 'category': category,
              'evidence': deepcopy(graph['nodes'][0]['evidence']),
              'explanation_pin': put(registry, b'Declared explanation, not a truth proof.'),
              'reviewer': reviewer(registry)}
    value = {'schema': 'sentinel/assessments/1', 'graph_sha256': graph_pin['sha256'],
             'source_set_sha256': source_pin['sha256'], 'task_pin': task, 'records': [record]}
    admission = {'schema': 'sentinel/assessment-admission/1',
                 **{key: value[key] for key in ('graph_sha256', 'source_set_sha256', 'task_pin')},
                 'adjudications': {}}
    if category in ('CONFIRMED_MISMATCH', 'SUPPORTED_ALTERNATIVE'):
        admission['adjudications']['R1'] = {'record_sha256': digest(canonical(record)),
            'category': category, 'adjudication_pin': put(registry, b'Held manual adjudication fixture')}
    return value, admission, registry


def comparison_packet(original=None):
    graph, registry = fixture()
    original = b'A--B' if original is None else original
    if original != b'A--B':
        source = graph['source_set'][0]
        source['source'].update(identity(original))
        source['representation'].update(identity(original))
    graph_pin = put(registry, canonical(graph)); put(registry, canonical(graph['source_set']))
    if len(original) <= 1048576:
        put(registry, original)
    task = put(registry, b'Task')
    oracle = {'schema': 'sentinel/comparison-oracle/1', 'task_pin': task,
              'expected_answer_pin': put(registry, b'answer'),
              'criteria_pin': put(registry, b'Manual fixed expected bytes only.'),
              'adjudication_pin': put(registry, b'No actual independent model trial.')}
    oracle_raw = canonical(oracle)
    plan = {'schema': 'sentinel/four-arm-plan/1', 'task_pin': task, 'graph_pin': graph_pin,
            'original_pins': [identity(original)], 'oracle_pin': identity(oracle_raw),
            'sast': {'share_pin': put(registry, b'fake share; SAST verification UNPERFORMED'),
                     'archive_pin': put(registry, b'fake archive; not decoded'),
                     'lexicon_pin': put(registry, b'fake lexicon')},
            'retrieval_pin': put(registry, canonical({'schema': 'sentinel/retrieval-capabilities/1',
                                                     **c.CAPABILITIES}))}
    return plan, registry, oracle_raw


class AssessmentControls(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('native/model dispatch forbidden')).start()
        self.temp = tempfile.TemporaryDirectory(prefix='sentinel-assessment-')
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)

    def review(self, value, admission, registry):
        raw, admitted = canonical(value), canonical(admission)
        return a.checked_assessments(raw, digest(raw), registry, bindings.registry_root(registry),
                                      admitted, digest(admitted))

    def prepared(self, plan, registry, oracle):
        raw = canonical(plan)
        return c.prepare_four_arms(raw, digest(raw), registry, bindings.registry_root(registry),
                                    oracle, digest(oracle))

    def test_six_assessment_categories_and_no_consensus_truth(self):
        for category in a.CATEGORIES:
            value, admission, registry = review_packet(category)
            result = self.review(value, admission, registry)
            self.assertEqual(result['records'][0]['category'], category)
            self.assertEqual(result['qualification'], 'NOT_QUALIFIED')
            self.assertEqual(result['independent_review'], 'UNPROVEN')
            self.assertEqual(result['execution_authority'], 'NONE')

    def test_confirmed_needs_quote_and_held_adjudication(self):
        value, admission, registry = review_packet('CONFIRMED_MISMATCH')
        admission['adjudications'] = {}
        with self.assertRaises(SentinelError): self.review(value, admission, registry)
        value, admission, registry = review_packet('SUPPORTED_ALTERNATIVE')
        value['records'][0]['evidence'] = []
        with self.assertRaises(SentinelError): self.review(value, admission, registry)

    def test_quote_task_admission_record_mutations_refuse(self):
        for mutation in ('quote', 'task', 'record', 'category', 'duplicate'):
            value, admission, registry = review_packet('CONFIRMED_MISMATCH')
            if mutation == 'quote': value['records'][0]['evidence'][0]['quote_sha256'] = digest(b'B')
            elif mutation == 'task': admission['task_pin'] = put(registry, b'Other task')
            elif mutation == 'record': admission['adjudications']['R1']['record_sha256'] = '0' * 64
            elif mutation == 'category': admission['adjudications']['R1']['category'] = 'SUPPORTED_ALTERNATIVE'
            else: value['records'] *= 2
            with self.subTest(mutation=mutation), self.assertRaises(SentinelError):
                self.review(value, admission, registry)

    def test_declared_identity_cannot_mint_observed_invocation(self):
        value, admission, registry = review_packet()
        value['records'][0]['reviewer']['declared_identity'] = 'GPT-6.1 claimed only'
        result = self.review(value, admission, registry)
        self.assertEqual(result['records'][0]['reviewer']['observed_identity'], 'NOT_RECORDED')
        value['records'][0]['reviewer']['observed_identity_pin'] = put(registry, b'claimed model')
        with self.assertRaises(SentinelError): self.review(value, admission, registry)
        value['records'][0]['reviewer']['origin'] = 'RECORDED_EXTERNAL_RUN'
        with self.assertRaises(SentinelError): self.review(value, admission, registry)
        value['records'][0]['reviewer']['invocation_pin'] = put(registry, b'recorded invocation')
        result = self.review(value, admission, registry)
        self.assertEqual(result['records'][0]['reviewer']['observed_identity'], 'RECORDED_BYTES_UNVERIFIED')

    def test_source_assessment_wrapper_requires_exact_resolved_graph(self):
        value, admission, registry = review_packet()
        graph = bindings.graph_from_registry(value['graph_sha256'], registry)
        source = graph['source_set'][0]
        resolution = {'status': 'RESOLVED_BYTES', **{key: source[key] for key in
                      ('source', 'representation', 'revision')}, 'locator_sha256': digest(b'locator'),
                      'package_id': source['source']['package_id'], 'coordinate_kind': 'SOURCE_BYTE',
                      'parts': [{'span': [0, 4], 'data': b'A--B', 'sha256': digest(b'A--B')}]}
        raw, admitted = canonical(value), canonical(admission)
        args = (raw, digest(raw), registry, bindings.registry_root(registry), admitted, digest(admitted),
                'archive', 'share', b'locator', digest(b'locator'), {}, '0' * 64, {}, '0' * 64)
        with patch('sentinel_v1.locators.resolve_locator', return_value=resolution):
            result = a.check_source_assessments(*args)
            self.assertEqual(result['source_evidence']['status'], 'CHECKED_WINDOW_BYTES_TO_VALIDATED_PACKAGE')
            resolution['parts'][0]['data'] = b'B--B'
            with self.assertRaises(SentinelError): a.check_source_assessments(*args)

    def test_quorum_adapter_preserves_original_error_and_no_new_threshold(self):
        pin = digest((ROOT / 'tools/transport_quorum_reading.py').read_bytes())
        result = a.quorum_aggregate(b'{}', (), (), (), pin)
        self.assertEqual(result['legacy_result']['status'], 'error')
        self.assertEqual(result['execution_authority'], 'NONE')
        self.assertIn('NOT_SOURCE_TRUTH', result['scope'])
        with self.assertRaises(SentinelError): a.quorum_aggregate(b'{}', (), (), (), '0' * 64)

    def test_four_matched_tasks_c_no_source_or_private_oracle(self):
        plan, registry, oracle = comparison_packet(); prepared = self.prepared(plan, registry, oracle)
        views = prepared['views']
        self.assertEqual({files['task.txt'] for files in views.values()}, {b'Task'})
        self.assertEqual(set(views['C']), {'task.txt', 'capabilities.json', 'graph.json'})
        self.assertEqual(views['C']['graph.json'], views['D']['graph.json'])
        self.assertEqual(views['B']['meaning.zip'], views['D']['meaning.zip'])
        self.assertEqual([raw for name, raw in views['A'].items() if name.startswith('original-')], [b'A--B'])
        self.assertTrue(all(oracle not in files.values() for files in views.values()))
        self.assertEqual(prepared['evaluator']['oracle.json'], oracle)
        self.assertEqual(prepared['manifest']['models'], 'NOT_DISPATCHED')

    def test_original_snippet_or_weakened_baseline_refuses(self):
        plan, registry, oracle = comparison_packet(); plan['original_pins'] = [put(registry, b'A')]
        with self.assertRaises(SentinelError): self.prepared(plan, registry, oracle)
        plan, registry, oracle = comparison_packet()
        recipe = {'schema': 'sentinel/retrieval-capabilities/1', **deepcopy(c.CAPABILITIES)}
        recipe['A'] = ['READ_ORIGINAL']
        plan['retrieval_pin'] = put(registry, canonical(recipe))
        with self.assertRaises(SentinelError): self.prepared(plan, registry, oracle)

    def test_private_staging_reuses_existing_exclusive_mode_and_pins(self):
        plan, registry, oracle = comparison_packet(); prepared = self.prepared(plan, registry, oracle)
        anchor = self.folder / 'private'; anchor.mkdir(mode=0o700)
        staging_pin = digest((ROOT / 'comparison/receiving/private_staging.py').read_bytes())
        result = c.stage_four_arms(prepared, digest(canonical(prepared['manifest'])), anchor, staging_pin)
        self.assertEqual(result['models'], 'NOT_DISPATCHED')
        for arm in c.ARMS:
            for name, raw in prepared['views'][arm].items():
                path = anchor / 'receivers' / arm / 'input' / name
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((anchor / 'evaluation/input/oracle.json').read_bytes(), oracle)
        with self.assertRaises(OSError):
            c.stage_four_arms(prepared, digest(canonical(prepared['manifest'])), anchor, staging_pin)

    def test_staging_tamper_refuses_before_any_legacy_write(self):
        for mutation in ('data', 'extra', 'mutable'):
            plan, registry, oracle = comparison_packet(); prepared = self.prepared(plan, registry, oracle)
            held = digest(canonical(prepared['manifest']))
            if mutation == 'data': prepared['views']['C']['task.txt'] = b'changed'
            elif mutation == 'extra': prepared['views']['C']['oracle.json'] = oracle
            else: prepared['views']['A']['task.txt'] = bytearray(b'Task')
            with patch.object(c, 'legacy_entry', side_effect=AssertionError('write before snapshot validation')):
                with self.subTest(mutation=mutation), self.assertRaises(SentinelError):
                    c.stage_four_arms(prepared, held, self.folder, '0' * 64)

    def submissions(self, prepared, registry):
        rows = []
        for arm, status, answer in (('A', 'RECORDED', b'answer'), ('B', 'RECORDED', b'wrong'),
                                    ('C', 'UNRUN', None), ('D', 'TOOL_PROCESS_FAILURE', None)):
            rows.append({'arm': arm, 'status': status,
                'answer_pin': None if answer is None else put(registry, answer),
                'provenance': None if status == 'UNRUN' else reviewer(registry, b'' if answer is None else answer),
                'metrics': {key: None for key in c.METRICS}, 'measurement_pin': None})
        return {'schema': 'sentinel/four-arm-submissions/1',
                'manifest_sha256': digest(canonical(prepared['manifest'])), 'records': rows}

    def results(self, prepared, submissions, registry, oracle):
        meta, raw = canonical(prepared['manifest']), canonical(submissions)
        return c.record_results(meta, digest(meta), raw, digest(raw), registry,
                                bindings.registry_root(registry), oracle, digest(oracle))

    def test_recorded_ties_losses_failures_and_missing_metrics(self):
        plan, registry, oracle = comparison_packet(); prepared = self.prepared(plan, registry, oracle)
        submissions = self.submissions(prepared, registry)
        result = self.results(prepared, submissions, registry, oracle)
        self.assertEqual([row['status'] for row in result['results']],
                         ['MATCH_REFERENCE', 'MISMATCH_REFERENCE', 'UNRUN', 'TOOL_PROCESS_FAILURE'])
        self.assertEqual(result['ties_and_losses'][0]['relation'], 'B_REFERENCE_LOSS')
        self.assertTrue(all(row['measurement'] == 'NOT_MEASURED' for row in result['results']))
        self.assertEqual(result['superiority'], 'NOT_ESTABLISHED')
        self.assertEqual(result['statistical_analysis'], 'UNPERFORMED')
        submissions['records'][1]['answer_pin'] = submissions['records'][0]['answer_pin']
        submissions['records'][1]['provenance'] = deepcopy(submissions['records'][0]['provenance'])
        self.assertEqual(self.results(prepared, submissions, registry, oracle)
                         ['ties_and_losses'][0]['relation'], 'TIE_REFERENCE_MATCH')

    def test_submission_and_metric_tamper_refuses(self):
        for mutation in ('duplicate', 'bool_metric', 'unrun_answer', 'wrong_response', 'measurement_missing'):
            plan, registry, oracle = comparison_packet(); prepared = self.prepared(plan, registry, oracle)
            submissions = self.submissions(prepared, registry)
            if mutation == 'duplicate': submissions['records'][3]['arm'] = 'A'
            elif mutation == 'bool_metric': submissions['records'][0]['metrics']['tokens'] = True
            elif mutation == 'unrun_answer': submissions['records'][2]['answer_pin'] = identity(b'answer')
            elif mutation == 'wrong_response': submissions['records'][0]['provenance']['raw_response_pin'] = put(registry, b'other')
            else: submissions['records'][0]['metrics']['tokens'] = 17
            with self.subTest(mutation=mutation), self.assertRaises(SentinelError):
                self.results(prepared, submissions, registry, oracle)

    def test_measurement_exact_recorded_evidence_not_self_measured_cost(self):
        plan, registry, oracle = comparison_packet(); prepared = self.prepared(plan, registry, oracle)
        submissions = self.submissions(prepared, registry); row = submissions['records'][0]
        row['metrics']['tokens'] = 17
        measurement = {'schema': 'sentinel/measurement/1', 'metrics': deepcopy(row['metrics']),
                       'method': 'MANUAL_FIXTURE', 'provenance_pin': put(registry, b'Not actual provider usage')}
        row['measurement_pin'] = put(registry, canonical(measurement))
        result = self.results(prepared, submissions, registry, oracle)
        self.assertEqual(result['results'][0]['measurement'], 'RECORDED_BYTES_UNVERIFIED')
        row['metrics']['tokens'] = 18
        with self.assertRaises(SentinelError): self.results(prepared, submissions, registry, oracle)

    def test_nested_measurement_boolean_is_not_numeric_one(self):
        plan, registry, oracle = comparison_packet(); prepared = self.prepared(plan, registry, oracle)
        submissions = self.submissions(prepared, registry); row = submissions['records'][0]
        row['metrics']['tokens'] = 1
        malformed = deepcopy(row['metrics']); malformed['tokens'] = True
        measurement = {'schema': 'sentinel/measurement/1', 'metrics': malformed,
                       'method': 'MANUAL_FIXTURE', 'provenance_pin': put(registry, b'fixture')}
        row['measurement_pin'] = put(registry, canonical(measurement))
        with self.assertRaises(SentinelError): self.results(prepared, submissions, registry, oracle)

    def test_graph_only_arm_cannot_declare_original_handle_capability(self):
        plan, registry, oracle = comparison_packet(); prepared = self.prepared(plan, registry, oracle)
        manifest = deepcopy(prepared['manifest'])
        manifest['arms']['C']['registered_sources'] = plan['original_pins']
        with self.assertRaises(SentinelError): c.manifest_checked(manifest)

    def test_restaging_cannot_weaken_arm_template_under_new_manifest_pin(self):
        plan, registry, oracle = comparison_packet(); prepared = self.prepared(plan, registry, oracle)
        prepared['views']['A']['capabilities.json'] = canonical({'capabilities': ['READ_ORIGINAL']})
        prepared['manifest']['arms']['A']['inventory']['capabilities.json'] = identity(
            prepared['views']['A']['capabilities.json'])
        with patch.object(c, 'legacy_entry', side_effect=AssertionError('write before template validation')):
            with self.assertRaises(SentinelError):
                c.stage_four_arms(prepared, digest(canonical(prepared['manifest'])), self.folder, '0' * 64)

    def test_exact_reference_comparison_never_normalizes_answer(self):
        plan, registry, oracle = comparison_packet(); prepared = self.prepared(plan, registry, oracle)
        submissions = self.submissions(prepared, registry); row = submissions['records'][0]
        row['answer_pin'] = put(registry, b'answer\n'); row['provenance'] = reviewer(registry, b'answer\n')
        self.assertEqual(self.results(prepared, submissions, registry, oracle)
                         ['results'][0]['status'], 'MISMATCH_REFERENCE')

    def test_streaming_large_original_without_copy_and_exact_search(self):
        payload = ((b'A--B' + b'x' * 65536)[:65535] + b'needle' + b'x' * 1048577)[:1048577]
        plan, registry, oracle = comparison_packet(payload)
        with self.assertRaises(SentinelError): self.prepared(plan, registry, oracle)
        path = self.folder / 'registered-original'; path.write_bytes(payload)
        raw = canonical(plan); key = digest(payload)
        with c.prepare_four_arms_handles(raw, digest(raw), registry, bindings.registry_root(registry),
                                         oracle, digest(oracle), {key: path}) as (prepared, handles):
            self.assertEqual(prepared['manifest']['source_profile'], 'REGISTERED_HANDLES')
            self.assertFalse(any(name.startswith('original-') for name in prepared['views']['A']))
            self.assertEqual(c.read_registered(handles, key, 65535, 65541), b'needle')
            self.assertEqual(c.search_registered(handles, key, b'needle'), [65535])
            with self.assertRaises(SentinelError): c.search_registered(handles, key, b'x', 2)
            with self.assertRaises(SentinelError): c.read_registered(handles, key, 0, 65537)
            stream = handles[key]['stream']
        self.assertTrue(stream.closed)

    def test_registered_symlink_wrong_hash_and_mutation_refuse(self):
        source = self.folder / 'source'; source.write_bytes(b'A--B')
        alias = self.folder / 'alias'; alias.symlink_to(source)
        expected = {digest(b'A--B'): identity(b'A--B')}
        with self.assertRaises(OSError):
            with c.registered_sources({digest(b'A--B'): alias}, expected): pass
        source.write_bytes(b'B--B')
        with self.assertRaises(SentinelError):
            with c.registered_sources({digest(b'A--B'): source}, expected): pass
        source.write_bytes(b'A--B')
        with self.assertRaises(SentinelError):
            with c.registered_sources({digest(b'A--B'): source}, expected) as handles:
                source.write_bytes(b'B--B')
                c.read_registered(handles, digest(b'A--B'), 0, 1)

    def test_legacy_source_handoff_checker_keeps_membership_only_scope(self):
        oracle = {'schema': 'transport/source-handoff-oracle/1',
            'sources': [{'id': 'SOURCE', 'revision': 'R1', 'raw_base64': base64.b64encode(b'A').decode(),
                         'sha256': digest(b'A')}],
            'required_spans': [{'source': 'SOURCE', 'begin': 0, 'end': 1}], 'obligations': []}
        answer = {'schema': 'transport/source-handoff-answer/1', 'narrative': 'A declared answer.',
            'evidence': [{'source': 'SOURCE', 'revision': 'R1', 'source_sha256': digest(b'A'),
                          'begin': 0, 'end': 1, 'quote': 'A'}]}
        oracle_raw = canonical(oracle)
        result = c.check_source_handoff(canonical(answer), oracle_raw, digest(oracle_raw),
            digest((ROOT / 'comparison/receiving/check_answer.py').read_bytes()))
        self.assertEqual(result['status'], 'PASS')
        self.assertEqual(result['interpretation'], 'NOT_ASSESSED')


class StreamingComparisonControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='streaming-comparison-')
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('native/model forbidden')).start()

    def packet(self, original=b'A--B', large_archive=False):
        import transport_document as document
        from sentinel_v1.bundle import decoder_pins
        plan, registry, oracle = comparison_packet(original)
        proposal = parse(registry[plan['graph_pin']['sha256']])
        package = proposal['source_set'][0]['source']['package_id']
        path = self.folder / 'source'; path.write_bytes(original)
        archive = self.folder / 'meaning.zip'
        archive.write_bytes(b'z' * (1048577 if large_archive else 7))
        share = self.folder / 'share.txt'
        native = self.folder / 'native'
        section = {'id': 'A', 'label': 'Literal section', 'start': 0, 'end': 4,
                   'dependencies': [], 'sha256': digest(original[:4])}
        record = deepcopy(document.reading_module.EMPTY)
        (self.folder / 'reading.json').write_bytes(document.canonical(record))
        entries = document.metadata('Fixture', [section], record)
        share.write_bytes(document.share_for(entries['formula.txt'].decode(), package, 'meaning.zip', None))
        body = {'source': identity(original), 'title': 'Fixture',
                'entries': {name: identity(raw) for name, raw in entries.items()}, 'reading': None}
        runtime, epoch = digest(b'mocked native runtime'), digest(b'mocked decoder sources')
        base = {'package_id': package, 'source_sha256': digest(original), 'source_bytes': len(original),
                'archive_sha256': document.file_digest(archive, document.MAX_ARCHIVE)[0],
                'archive_bytes': archive.stat().st_size, 'decoder_identity_sha256': runtime,
                'decoder_source_sha256': epoch}
        plan.pop('sast'); plan['schema'] = 'sentinel/four-arm-streaming-plan/1'; plan['sast_bases'] = [base]
        config = {package: {'archive': archive, 'share': share, 'native': native}}
        return plan, registry, oracle, config, digest(canonical({package: base})), path, body, [section]

    @contextmanager
    def preparation(self, packet):
        import transport_document as document
        plan, registry, oracle, config, held, path, body, sections = packet
        package = next(iter(config))
        @contextmanager
        def validated(*_args):
            yield path, body, package, sections
        runtime = digest(b'mocked native runtime')
        epoch = digest(b'mocked decoder sources')
        raw = canonical(plan)
        with patch('sentinel_v1.bundle.decoder_pins', return_value=(config[package]['native'], runtime, epoch)), \
             patch.object(document, 'validated', validated):
            with c.prepare_four_arms_streaming(raw, digest(raw), registry, bindings.registry_root(registry),
                    oracle, digest(oracle), {digest(path.read_bytes()): path}, config, held) as result:
                yield result

    def test_large_original_and_archive_registered_without_registry_copy(self):
        original = b'A--B' + b'x' * 1048573
        packet = self.packet(original, large_archive=True)
        plan, registry = packet[:2]
        self.assertEqual(plan['sast_bases'][0]['archive_bytes'], 1048577)
        self.assertNotIn(digest(original), registry)
        self.assertNotIn(plan['sast_bases'][0]['archive_sha256'], registry)
        with self.preparation(packet) as (prepared, capabilities):
            manifest = prepared['manifest']
            self.assertEqual(manifest['schema'], 'sentinel/four-arm-preparation/2')
            self.assertTrue(manifest['arms']['A']['registered_sources'])
            self.assertFalse(manifest['arms']['D']['registered_sources'])
            self.assertIs(capabilities['B'], capabilities['D'])
            self.assertEqual(capabilities['C'], {})
            self.assertNotIn('meaning.zip', prepared['views']['B'])
            self.assertEqual(c.read_registered(capabilities['A'], digest(original), 0, 4), b'A--B')
            package = plan['sast_bases'][0]['package_id']
            self.assertEqual(c.read_sast_registered(capabilities['D'], package, 0, 4), b'A--B')
            self.assertEqual(c.search_sast_registered(capabilities['B'], package, b'A--B'), [0])
        self.assertTrue(all(not row['active'] for row in capabilities['B'].values()))
        with self.assertRaises(SentinelError):
            c.read_sast_registered(capabilities['D'], package, 0, 1)

    def test_four_arm_roles_same_task_private_oracle_and_no_raw_graph_windows(self):
        packet = self.packet()
        with self.preparation(packet) as (prepared, capabilities):
            views = prepared['views']; oracle = packet[2]
            self.assertEqual({files['task.txt'] for files in views.values()}, {b'Task'})
            self.assertNotIn(oracle, [raw for files in views.values() for raw in files.values()])
            self.assertNotIn('source_set', parse(views['C']['graph.json']))
            self.assertFalse(prepared['manifest']['arms']['C']['registered_sast'])
            self.assertFalse(prepared['manifest']['arms']['B']['registered_sources'])
            self.assertNotEqual(set(capabilities['A']), set(capabilities['D']))
            for name in views['B'].keys() - {'task.txt', 'capabilities.json'}:
                self.assertEqual(views['B'][name], views['D'][name])

    def test_wrong_archive_source_package_runtime_and_held_root_refuse(self):
        import transport_document as document
        for mutation in ('archive', 'source', 'package', 'runtime', 'root'):
            packet = list(self.packet()); plan, config, body = packet[0], packet[3], packet[6]
            if mutation == 'archive': next(iter(config.values()))['archive'].write_bytes(b'altered')
            elif mutation == 'source': body['source']['sha256'] = digest(b'wrong')
            elif mutation == 'package':
                plan['sast_bases'][0]['package_id'] = digest(b'wrong package')
            elif mutation == 'runtime': plan['sast_bases'][0]['decoder_identity_sha256'] = digest(b'changed')
            else: packet[4] = digest(b'wrong root')
            with self.subTest(mutation=mutation), self.assertRaises(SentinelError):
                with self.preparation(packet): self.fail('wrong registered package accepted')

    def test_display_lexicon_entry_tamper_refuses(self):
        packet = self.packet()
        packet[6]['entries']['lexicon.md']['sha256'] = digest(b'changed display')
        with self.assertRaisesRegex(SentinelError, 'display metadata mismatch'):
            with self.preparation(packet): self.fail('tampered display accepted')

    def test_source_and_reading_reads_remain_bounded_and_separate(self):
        packet = self.packet(); plan, body = packet[0], packet[6]
        reading = b'Exact derived text.'
        (self.folder / 'reading.txt').write_bytes(reading)
        with self.preparation(packet) as (_prepared, capabilities):
            package = plan['sast_bases'][0]['package_id']
            with self.assertRaises(SentinelError):
                c.read_sast_registered(capabilities['D'], package, 0, 1, reading=True)
            body['reading'] = identity(reading)
            self.assertEqual(c.read_sast_registered(capabilities['D'], package, 0, 5, reading=True), b'Exact')
            self.assertEqual(c.search_sast_registered(capabilities['D'], package, b'derived', reading=True), [6])
            with self.assertRaises(SentinelError):
                c.read_sast_registered(capabilities['D'], package, 0, 65537)
            with self.assertRaises(SentinelError):
                c.search_sast_registered(capabilities['D'], package, b'-', maximum=1)
            body['reading']['bytes'] = 33554433
            with self.assertRaises(SentinelError):
                c.read_sast_registered(capabilities['D'], package, 0, 1, reading=True)

    def test_new_profile_stages_exact_files_and_refuses_role_injection_before_write(self):
        packet = self.packet()
        with self.preparation(packet) as (prepared, _capabilities):
            anchor = self.folder / 'stage'; anchor.mkdir(mode=0o700)
            pin = digest((ROOT / 'comparison/receiving/private_staging.py').read_bytes())
            held = digest(canonical(prepared['manifest']))
            result = c.stage_four_arms(prepared, held, anchor, pin)
            self.assertEqual(result['models'], 'NOT_DISPATCHED')
            self.assertEqual(result['sast_package_verification'], 'REGISTERED_BASES_CHECKED_AT_PREPARATION_NOT_STAGING')
            for arm in c.ARMS:
                for name, raw in prepared['views'][arm].items():
                    self.assertEqual((anchor / 'receivers' / arm / 'input' / name).read_bytes(), raw)
            for arm, field, value in (('D', 'registered_sources', packet[0]['original_pins']),
                                     ('C', 'registered_sast', packet[0]['sast_bases'])):
                changed = deepcopy(prepared); changed['manifest']['arms'][arm][field] = value
                with patch.object(c, 'legacy_entry', side_effect=AssertionError('must refuse before write')):
                    with self.assertRaises(SentinelError):
                        c.stage_four_arms(changed, digest(canonical(changed['manifest'])), anchor, pin)

    def test_streaming_recorded_results_do_not_promote_study_acceptance(self):
        packet = self.packet()
        with self.preparation(packet) as (prepared, _capabilities):
            registry, oracle = packet[1], packet[2]
            submissions = AssessmentControls.submissions(self, prepared, registry)
            result = AssessmentControls.results(self, prepared, submissions, registry, oracle)
            self.assertEqual(result['superiority'], 'NOT_ESTABLISHED')
            self.assertEqual(result['statistical_analysis'], 'UNPERFORMED')
            self.assertEqual(result['execution_authority'], 'NONE')

    def test_archive_change_during_validated_context_refuses_before_public_return(self):
        import transport_document as document
        packet = self.packet(); plan, registry, oracle, config, held, source, body, sections = packet
        package = next(iter(config)); base = plan['sast_bases'][0]
        @contextmanager
        def changed(*_args):
            yield source, body, package, sections
            config[package]['archive'].write_bytes(b'changed')
        with patch.object(document, 'validated', changed), \
             patch('sentinel_v1.bundle.decoder_pins', return_value=(config[package]['native'],
                  base['decoder_identity_sha256'], base['decoder_source_sha256'])):
            raw = canonical(plan)
            with self.assertRaises(SentinelError):
                with c.prepare_four_arms_streaming(raw, digest(raw), registry, bindings.registry_root(registry),
                        oracle, digest(oracle), {digest(source.read_bytes()): source}, config, held):
                    self.fail('publication before archive postcheck')


if __name__ == '__main__':
    unittest.main()
