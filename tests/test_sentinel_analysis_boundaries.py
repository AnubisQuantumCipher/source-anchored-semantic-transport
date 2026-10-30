"""Serialized prompt and source-plan controls; manual fixtures prove structure only."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools')); sys.path.insert(0, str(ROOT / 'tests'))
from sentinel_v1 import analysis as a, graph
from sentinel_v1.common import SentinelError, canonical, digest, identity, parse
from sentinel_v1.bindings import registry_root
from test_sentinel_meaning import binding
from test_sentinel_assessments import put, reviewer


def proposed(prepared):
    request = parse(prepared['request']); raw = prepared['reading']
    first = raw.decode('utf-8')[0].encode('utf-8')
    evidence = {'source_id': 'S1', 'start': request['source_set'][0]['window']['start'],
        'end': request['source_set'][0]['window']['start'] + len(first), 'quote_sha256': digest(first)}
    node = {'id': 'C1', 'kind': 'PROPOSITION', 'origin': 'SOURCE_OCCURRENCE',
        'text': 'Manual structural fixture only.', 'evidence': [evidence], 'documentary_state': 'NEITHER',
        'support_records': [], 'refutation_records': [], 'assurance': dict(graph.ASSURANCE)}
    candidate = canonical({'schema': graph.PROFILE, 'source_set': request['source_set'],
        'nodes': [node], 'edges': [], 'assurance': dict(graph.ASSURANCE)})
    registry = {digest(value): value for value in prepared.values()}
    provenance = reviewer(registry, candidate); provenance['prompt_pin'] = identity(prepared['prompt'])
    return candidate, registry, provenance


def imported(prepared, candidate, registry, provenance):
    raw = canonical(provenance)
    return a.import_candidate(prepared['request'], digest(prepared['request']), candidate,
        digest(candidate), registry, registry_root(registry), raw, digest(raw))


def plan_packet(raw):
    binding_raw = canonical(binding(raw))
    packet = a.plan_document_jobs(raw, binding_raw)
    return binding_raw, packet, parse(packet['plan'])


def check_plan(plan, census):
    raw = canonical(plan)
    return a.checked_model_plan(raw, digest(raw), census, digest(census))


def exact_source(prefix=b'', name='SHARD0001'):
    low, high = 1, 65536 - len(prefix)
    for _ in range(17):
        if low > high: break
        middle = (low + high) // 2; raw = prefix + b'x' * middle
        census = a.build_census(raw, canonical(binding(raw)))
        descriptor, prompt = a.model_descriptor(raw, census['binding'], census['shards'][0],
            ['P0001'], [0, len(raw)], name)
        if len(prompt) == 65536: return raw
        if len(prompt) < 65536: low = middle + 1
        else: high = middle - 1
    raise AssertionError('literal exact boundary fixture unavailable')


class AnalysisBoundaryControls(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('no provider/native execution')).start()

    def test_exact_complete_prompt_boundary_and_structural_import(self):
        for prefix in (b'', b'"\\\t\x00\x01' + 'éα😀'.encode()):
            with self.subTest(prefix=prefix):
                raw = exact_source(prefix)
                prepared = a.prepare_job(raw, canonical(binding(raw)), 'SHARD0001')
                self.assertEqual(len(prepared['prompt']), 65536)
                candidate, registry, provenance = proposed(prepared)
                a.request_checked(prepared['request'], digest(prepared['request']), registry)
                result = parse(imported(prepared, candidate, registry, provenance))
                self.assertEqual(result['observed_provenance']['origin'], 'MANUAL_FIXTURE')
                self.assertEqual(result['assurance'], graph.ASSURANCE)
                self.assertEqual(parse(prepared['request'])['max_response_bytes'], 65536)
                over = raw + b'x'
                with self.assertRaises(SentinelError):
                    a.prepare_job(over, canonical(binding(over)), 'SHARD0001')

    def test_exact_one_over_is_explicit_unadmitted_whole_paragraph(self):
        raw = exact_source(name='JOB0001') + b'x'
        census = a.build_census(raw, canonical(binding(raw)))
        _, prompt = a.model_descriptor(raw, census['binding'], census['shards'][0],
            ['P0001'], [0, len(raw)], 'JOB0001')
        self.assertEqual(len(prompt), 65537)
        _, packet, plan = plan_packet(raw)
        self.assertEqual(plan['jobs'], [])
        self.assertEqual([row['paragraph_id'] for row in plan['unadmitted']], ['P0001'])
        self.assertEqual(plan['status'], 'INCOMPLETE_UNADMITTED_PARAGRAPHS')
        check_plan(plan, packet['census'])

    def test_escaping_and_unicode_budget_recovered_exactly(self):
        raw = (b'"\\\t\x00\x01' + 'éα😀'.encode()) * 3000
        _, packet, plan = plan_packet(raw)
        self.assertLess(len(raw), 65536)
        self.assertEqual(len(plan['unadmitted']), 1)
        self.assertGreater(plan['unadmitted'][0]['prompt_pin']['bytes'], 65536)
        raw = ('éα😀 paragraph.\n\n' * 1600).encode()
        bind, packet, plan = plan_packet(raw)
        reconstructed = bytearray()
        for row in plan['jobs']:
            prepared = a.prepare_planned_job(raw, bind, packet['plan'], digest(packet['plan']), row['id'])
            self.assertEqual(parse(prepared['prompt'])['SOURCE_DATA'].encode(), prepared['reading'])
            self.assertLessEqual(len(prepared['prompt']), 65536)
            reconstructed.extend(prepared['reading'])
        self.assertEqual(bytes(reconstructed), raw)

    def test_whole_paragraph_split_and_source_order(self):
        raw = b'A' * 32000 + b'\n\n' + b'B' * 32000
        _, packet, plan = plan_packet(raw)
        self.assertEqual(len(plan['jobs']), 2)
        self.assertEqual([p for row in plan['jobs'] for p in row['paragraph_ids']], ['P0001', 'P0002'])
        self.assertEqual(b''.join(raw[row['span'][0]:row['span'][1]] for row in plan['jobs']), raw)
        check_plan(plan, packet['census'])

    def test_tampered_plan_missing_duplicate_bool_context_and_source_refuse(self):
        raw = b'A' * 32000 + b'\n\n' + b'B' * 32000
        _, packet, original = plan_packet(raw)
        for kind in ('missing', 'duplicate', 'bool', 'context', 'source'):
            value = deepcopy(original)
            if kind == 'missing': value['jobs'].pop()
            elif kind == 'duplicate': value['jobs'][1]['paragraph_ids'] = ['P0001']
            elif kind == 'bool': value['jobs'][0]['span'][0] = False
            elif kind == 'context': value['jobs'][0]['dependency_regions'] = ['UNDECLARED']
            else: value['binding_sha256'] = '0' * 64
            with self.subTest(kind=kind), self.assertRaises(SentinelError): check_plan(value, packet['census'])

    def test_request_prompt_reading_plan_and_provenance_tamper_refuse(self):
        raw = b'Whole paragraph and exception.'
        bind, packet, plan = plan_packet(raw)
        prepared = a.prepare_planned_job(raw, bind, packet['plan'], digest(packet['plan']), plan['jobs'][0]['id'])
        candidate, registry, provenance = proposed(prepared)
        imported(prepared, candidate, registry, provenance)
        for kind in ('context', 'plan', 'reading', 'prompt', 'missing-provenance', 'response-size'):
            job, reg, prov = dict(prepared), dict(registry), deepcopy(provenance)
            request = parse(job['request'])
            if kind == 'context': request['required_context_regions'] = ['UNDECLARED']
            elif kind == 'plan': request['plan_sha256'] = '0' * 64
            elif kind == 'reading': reg[request['reading_pin']['sha256']] = b'X' * len(raw)
            elif kind == 'prompt': reg[request['prompt_pin']['sha256']] = b'wrong'
            elif kind == 'missing-provenance': prov['raw_response_pin'] = None
            else:
                with self.assertRaises(SentinelError):
                    imported(job, candidate + b' ' * 65537, reg, prov)
                continue
            job['request'] = canonical(request)
            with self.subTest(kind=kind), self.assertRaises(SentinelError): imported(job, candidate, reg, prov)

    def test_opaque_empty_and_unadmitted_distinct(self):
        _, _, empty = plan_packet(b'')
        self.assertEqual(empty['status'], 'EMPTY_READING')
        _, _, opaque = plan_packet(b'x' * 65537)
        self.assertEqual(len(opaque['opaque']), 1)
        self.assertEqual(opaque['jobs'], [])
        self.assertEqual(opaque['unadmitted'], [])

    def test_exact_planned_prompt_boundary_imports(self):
        raw = exact_source(name='JOB0001')
        bind, packet, plan = plan_packet(raw)
        self.assertEqual(plan['jobs'][0]['prompt_pin']['bytes'], 65536)
        prepared = a.prepare_planned_job(raw, bind, packet['plan'], digest(packet['plan']), 'JOB0001')
        candidate, registry, provenance = proposed(prepared)
        result = parse(imported(prepared, candidate, registry, provenance))
        self.assertEqual(result['scope'], 'STRUCTURALLY_CHECKED_PROPOSAL_NOT_SEMANTIC_ACCEPTANCE')

    def test_reordered_jobs_refuse_even_with_relabelled_ids(self):
        _, packet, plan = plan_packet(b'A' * 32000 + b'\n\n' + b'B' * 32000)
        plan['jobs'].reverse()
        for index, row in enumerate(plan['jobs'], 1): row['id'] = f'JOB{index:04d}'
        with self.assertRaises(SentinelError): check_plan(plan, packet['census'])

    def test_context_is_preserved_in_prompt_and_import(self):
        raw = b'Rule and its exception.\n\nDefinition supporting the rule.'
        cut = raw.index(b'Definition')
        hierarchy = canonical([{'id': 'DOCUMENT', 'parent': None, 'kind': 'DOCUMENT', 'start': 0, 'end': len(raw)},
            {'id': 'RULE', 'parent': 'DOCUMENT', 'kind': 'SECTION', 'start': 0, 'end': cut},
            {'id': 'DEF', 'parent': 'DOCUMENT', 'kind': 'SECTION', 'start': cut, 'end': len(raw)}])
        deps = canonical([{'from': 'RULE', 'to': 'DEF'}]); bind = canonical(binding(raw))
        packet = a.plan_document_jobs(raw, bind, hierarchy, deps)
        plan = parse(packet['plan']); row = plan['jobs'][0]
        prepared = a.prepare_planned_job(raw, bind, packet['plan'], digest(packet['plan']), row['id'], hierarchy, deps)
        self.assertIn('DEF', parse(prepared['prompt'])['required_context_regions_not_supplied'])
        self.assertEqual(parse(prepared['request'])['required_context_regions'], row['dependency_regions'])
        candidate, registry, provenance = proposed(prepared)
        imported(prepared, candidate, registry, provenance)
        request = parse(prepared['request']); request['required_context_regions'] = []
        prepared['request'] = canonical(request)
        with self.assertRaises(SentinelError): imported(prepared, candidate, registry, provenance)

    def test_legacy_v1_remains_explicit_and_separate(self):
        raw = b'Historical manual fixture.'
        job = a.prepare_job(raw, canonical(binding(raw)), 'SHARD0001')
        prompt = parse(job['prompt']); del prompt['operational_job']; job['prompt'] = canonical(prompt)
        request = parse(job['request']); del request['plan_sha256']; del request['job_id']
        request['schema'] = 'sentinel/analysis-request/1'; request['max_response_bytes'] = 1048576
        request['prompt_pin'] = identity(job['prompt']); job['request'] = canonical(request)
        candidate, registry, provenance = proposed(job)
        imported(job, candidate, registry, provenance)
        request['schema'] = a.MODEL_REQUEST; bad = canonical(request)
        with self.assertRaises(SentinelError): a.request_checked(bad, digest(bad), registry)

    def test_core_and_plan_limits_refuse_without_cropping(self):
        with self.assertRaises(SentinelError): plan_packet(b'x\n\n' * 4097)
        _, packet, plan = plan_packet(b'x')
        plan['jobs'] = plan['jobs'] * 4097
        with self.assertRaises(SentinelError): check_plan(plan, packet['census'])
        oversized = b' ' * 1048577
        with self.assertRaises(SentinelError):
            a.checked_model_plan(oversized, digest(oversized), packet['census'], digest(packet['census']))

    def test_external_origin_requires_actual_retained_invocation_bytes(self):
        job = a.prepare_job(b'Rule.', canonical(binding(b'Rule.')), 'SHARD0001')
        candidate, registry, provenance = proposed(job)
        provenance['origin'] = 'RECORDED_EXTERNAL_RUN'
        with self.assertRaises(SentinelError): imported(job, candidate, registry, provenance)

    def test_empty_reconciliation_never_claims_generation(self):
        _, packet, _ = plan_packet(b'')
        registry = {digest(value): value for value in packet.values()}
        records = canonical({'schema': 'sentinel/planned-analysis-attempts/1',
            'plan_sha256': digest(packet['plan']), 'census_sha256': digest(packet['census']), 'attempts': []})
        value = parse(a.reconcile_document_jobs(packet['plan'], digest(packet['plan']), packet['census'],
            digest(packet['census']), records, digest(records), registry, registry_root(registry)))
        self.assertEqual(value['status'], 'EMPTY_READING')
        self.assertEqual(value['execution_evidence'], 'NO_EXECUTION_RECORDED')

    def test_malformed_completion_provenance_refuses_explicitly(self):
        bind, packet, plan = plan_packet(b'Source paragraph.')
        prepared = a.prepare_planned_job(b'Source paragraph.', bind, packet['plan'], digest(packet['plan']), 'JOB0001')
        candidate, registry, provenance = proposed(prepared)
        result = imported(prepared, candidate, registry, provenance); put(registry, result)
        bad = canonical({}); put(registry, bad)
        row = {'job_id': 'JOB0001', 'ordinal': 1, 'request_sha256': digest(prepared['request']),
            'status': 'ANALYZED_PROPOSED', 'graph_sha256': digest(candidate),
            'provenance_sha256': digest(bad), 'result_pin': identity(result)}
        records = canonical({'schema': 'sentinel/planned-analysis-attempts/1',
            'plan_sha256': digest(packet['plan']), 'census_sha256': digest(packet['census']), 'attempts': [row]})
        with self.assertRaises(SentinelError):
            a.reconcile_document_jobs(packet['plan'], digest(packet['plan']), packet['census'],
                digest(packet['census']), records, digest(records), registry, registry_root(registry))

    def test_failed_attempt_evidence_rounds_and_history_retained(self):
        bind, packet, plan = plan_packet(b'Source paragraph.')
        prepared = a.prepare_planned_job(b'Source paragraph.', bind, packet['plan'], digest(packet['plan']), 'JOB0001')
        registry = {digest(value): value for value in prepared.values()}
        failure = put(registry, b'Pure test interruption evidence; no model execution.')
        base = {'job_id': 'JOB0001', 'ordinal': 1, 'request_sha256': digest(prepared['request']),
            'status': 'INTERRUPTED', 'graph_sha256': None, 'provenance_sha256': None, 'result_pin': failure}
        history = []
        for index in range(1, 9):
            row = dict(base); row['ordinal'] = index; history.append(row)
        records = {'schema': 'sentinel/planned-analysis-attempts/1', 'plan_sha256': digest(packet['plan']),
            'census_sha256': digest(packet['census']), 'attempts': history}
        raw = canonical(records)
        result = parse(a.reconcile_document_jobs(packet['plan'], digest(packet['plan']), packet['census'],
            digest(packet['census']), raw, digest(raw), registry, registry_root(registry)))
        self.assertEqual(result['status'], 'ACCOUNTED_WITH_FAILURES')
        self.assertEqual(result['history'], history)
        self.assertEqual(result['attempts_retained'], 8)
        records['attempts'].append(dict(base, ordinal=9)); raw = canonical(records)
        with self.assertRaises(SentinelError):
            a.reconcile_document_jobs(packet['plan'], digest(packet['plan']), packet['census'],
                digest(packet['census']), raw, digest(raw), registry, registry_root(registry))
        registry.pop(failure['sha256']); records['attempts'] = [base]; raw = canonical(records)
        with self.assertRaises(SentinelError):
            a.reconcile_document_jobs(packet['plan'], digest(packet['plan']), packet['census'],
                digest(packet['census']), raw, digest(raw), registry, registry_root(registry))

    def test_manual_fixture_cannot_be_recorded_generation_completion(self):
        raw = b'Source paragraph.'
        bind, packet, plan = plan_packet(raw)
        prepared = a.prepare_planned_job(raw, bind, packet['plan'], digest(packet['plan']), plan['jobs'][0]['id'])
        candidate, registry, provenance = proposed(prepared)
        result = imported(prepared, candidate, registry, provenance)
        provenance_raw = canonical(provenance); put(registry, provenance_raw); put(registry, result)
        row = {'job_id': plan['jobs'][0]['id'], 'ordinal': 1, 'request_sha256': digest(prepared['request']),
            'status': 'ANALYZED_PROPOSED', 'graph_sha256': digest(candidate),
            'provenance_sha256': digest(provenance_raw), 'result_pin': identity(result)}
        records = canonical({'schema': 'sentinel/planned-analysis-attempts/1',
            'plan_sha256': digest(packet['plan']), 'census_sha256': digest(packet['census']), 'attempts': [row]})
        with self.assertRaises(SentinelError):
            a.reconcile_document_jobs(packet['plan'], digest(packet['plan']), packet['census'],
                digest(packet['census']), records, digest(records), registry, registry_root(registry))


if __name__ == '__main__': unittest.main()
