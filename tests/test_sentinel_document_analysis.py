"""Developmental controls for the separate document layer, never native/model runs."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
from sentinel_v1 import document_analysis as d, census
from sentinel_v1.common import SentinelError, canonical, digest, identity, parse
from sentinel_v1.bindings import registry_root
from test_sentinel_meaning import binding
from test_sentinel_assessments import reviewer, put


def setup(raw):
    bound = canonical(binding(raw)); plan = d.plan_document_jobs(raw, bound)
    index, groups = d.document_checked(raw, bound, plan['index'], digest(plan['index']), plan['blocks'])
    return bound, plan, index, groups


def prepared(raw):
    bound, plan, index, groups = setup(raw)
    job = d.prepare_document_job(raw, bound, plan['index'], digest(plan['index']), plan['blocks'], groups[0]['id'])
    registry = {digest(v): v for v in job.values()}
    request = parse(job['request']); template = parse(job['prompt'])['output_template']
    template['nodes'][0]['text'] = 'Development fixture only.'
    proposal = canonical(template); provenance = reviewer(registry, proposal)
    provenance['prompt_pin'] = identity(job['prompt']); prov = canonical(provenance)
    return bound, plan, index, groups, job, registry, proposal, prov


def import_fixture(raw, packet):
    bound, plan, _, _, job, registry, proposal, prov = packet
    return d.import_candidate(job['request'], digest(job['request']), proposal, digest(proposal),
        raw, bound, plan['index'], digest(plan['index']), plan['blocks'], registry, registry_root(registry), prov, digest(prov))


class DocumentDevelopmentControls(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('no model/native')).start()

    def test_4097_paragraphs_preserve_old_refusal_and_absolute_blocks(self):
        raw = b'x\n\n' * 4097
        with self.assertRaises(SentinelError): census.build_census(raw, canonical(binding(raw)))
        bound, plan, index, groups = setup(raw)
        self.assertEqual(index['paragraph_count'], 4097)
        first, second = [parse(plan['blocks'][p['sha256']]) for p in index['paragraph_blocks']]
        self.assertEqual(first['rows'][-1]['span'], [12285, 12288])
        self.assertEqual(second['rows'][0]['span'], [12288, 12291])
        self.assertEqual(second['binding'], parse(bound))
        self.assertEqual(sum(len(row['paragraph_ids']) for row in groups), 4097)

    def test_prompt_self_contained_and_manual_structural_import(self):
        raw = 'A rule unless éα😀 exception.'.encode()
        packet = prepared(raw); job = packet[4]; prompt = parse(job['prompt'])
        for key in ('instructions', 'output_template', 'critical_constraints', 'relation_endpoint_kinds', 'SOURCE_DATA'):
            self.assertIn(key, prompt)
        self.assertEqual(prompt['SOURCE_DATA'].encode(), raw)
        result = parse(import_fixture(raw, packet))
        self.assertEqual(result['scope'], 'STRUCTURAL_PROPOSAL_ONLY')
        self.assertEqual(result['observed_provenance']['origin'], 'MANUAL_FIXTURE')

    def test_source_block_order_missing_extra_and_binding_tamper(self):
        raw = b'x\n\n' * 4097; bound, plan, index, _ = setup(raw)
        for kind in ('missing', 'extra', 'order', 'binding'):
            blocks, altered = dict(plan['blocks']), deepcopy(index)
            if kind == 'missing': blocks.pop(index['paragraph_blocks'][0]['sha256'])
            elif kind == 'extra': blocks[digest(b'{}')] = b'{}'
            elif kind == 'order': altered['paragraph_blocks'].reverse()
            else: altered['binding']['source']['package_id'] = '0' * 64
            encoded = canonical(altered)
            with self.subTest(kind=kind), self.assertRaises(SentinelError):
                d.document_checked(raw, bound, encoded, digest(encoded), blocks)

    def test_prompt_response_and_source_tamper_refuse(self):
        raw = b'Whole rule and exception.'; packet = prepared(raw)
        import_fixture(raw, packet)
        for kind in ('prompt', 'source', 'response', 'provenance'):
            values = list(packet); registry = dict(packet[5]); values[5] = registry
            if kind == 'prompt': registry[digest(packet[4]['prompt'])] = b'wrong'
            elif kind == 'response': values[6] = b'x' * 65537
            elif kind == 'provenance': values[7] = canonical({})
            with self.subTest(kind=kind), self.assertRaises(SentinelError):
                import_fixture(b'X' * len(raw) if kind == 'source' else raw, values)

    def test_opaque_unadmitted_empty_and_escaping(self):
        _, _, empty, groups = setup(b''); self.assertEqual(groups, [])
        self.assertEqual(empty['paragraph_count'], 0)
        _, _, _, groups = setup(b'x' * 65537)
        self.assertEqual(groups[0]['status'], 'OPAQUE'); self.assertEqual(groups[0]['span'], [0, 65537])
        _, _, _, groups = setup(b'"' * 40000)
        self.assertEqual(groups[0]['status'], 'PROMPT_BUDGET_UNADMITTED')
        self.assertEqual(groups[0]['span'], [0, 40000])

    def test_whole_paragraph_unicode_split_and_job_order(self):
        raw = ('é' * 16000 + '\n\n' + 'α' * 16000).encode()
        bound, plan, index, groups = setup(raw)
        self.assertEqual(len(groups), 2)
        self.assertEqual(b''.join(raw[r['span'][0]:r['span'][1]] for r in groups), raw)
        for row in groups:
            job = d.prepare_document_job(raw, bound, plan['index'], digest(plan['index']), plan['blocks'], row['id'])
            self.assertLessEqual(len(job['prompt']), 65536)
            self.assertEqual(parse(job['prompt'])['SOURCE_DATA'].encode(), job['reading'])

    def test_generation_message_exact_bytes_and_malformed_refusal(self):
        job = prepared(b'Whole rule.')[4]
        self.assertEqual(d.generation_message(job), job['prompt'])
        bad = {'request': canonical({'schema': d.REQUEST}), 'prompt': b'x', 'reading': b'x'}
        with self.assertRaises(SentinelError): d.generation_message(bad)
        request = parse(job['request']); request['reading_pin'] = identity(b'x'); request['prompt_pin'] = identity(b'x')
        forged = {'request': canonical(request), 'prompt': b'x', 'reading': b'x'}
        with self.assertRaises(SentinelError): d.generation_message(forged)

    def test_unselected_prompt_pin_tamper_refuses_entire_document(self):
        raw = b'A' * 32000 + b'\n\n' + b'B' * 32000
        bound, plan, index, groups = setup(raw)
        self.assertEqual(len(groups), 2)
        value = parse(plan['blocks'][index['job_blocks'][0]['sha256']])
        value['rows'][1]['prompt_pin']['sha256'] = '0' * 64
        changed = canonical(value); blocks = dict(plan['blocks'])
        blocks.pop(index['job_blocks'][0]['sha256']); blocks[digest(changed)] = changed
        index['job_blocks'][0] = identity(changed); iraw = canonical(index)
        with self.assertRaises(SentinelError):
            d.prepare_document_job(raw, bound, iraw, digest(iraw), blocks, groups[0]['id'])

    def test_block_cumulative_reserve_precedes_store_mutation(self):
        store = {digest(b'x'): b'x'}; before = dict(store)
        with patch.object(d, 'TOTAL_METADATA', d.METADATA + 5):
            with self.assertRaises(SentinelError): d.admit_block(store, b'123456')
        self.assertEqual(store, before)

    def test_direct_dict_count_guard_precedes_field_allocation(self):
        for function, value in ((d.generation_message, dict.fromkeys(range(4))),
                                (d.reconciliation_inputs, dict.fromkeys(range(7)))):
            with patch.object(d, 'fields', side_effect=AssertionError('unexpected allocation')):
                with self.assertRaises(SentinelError): function(value)

    def test_manual_cannot_complete_generation_and_empty_never_does(self):
        raw = b'Whole rule.'; packet = prepared(raw)
        bound, plan, _, groups, job, registry, proposal, prov = packet
        result = import_fixture(raw, packet); put(registry, result); put(registry, prov)
        row = {'ordinal': 1, 'status': 'ANALYZED_PROPOSED', 'request_sha256': digest(job['request']),
            'graph_sha256': digest(proposal), 'provenance_sha256': digest(prov), 'result_pin': identity(result)}
        records = canonical({'schema': 'sentinel/document-job-attempts/1', 'index_sha256': digest(plan['index']),
            'job_id': groups[0]['id'], 'attempts': [row]})
        admission = canonical({'schema': 'sentinel/document-generation-admission/1',
            'index_sha256': digest(plan['index']), 'job_id': groups[0]['id'], 'entries': [],
            'authority': 'OPERATOR_HELD_RECORDED_EVIDENCE_NOT_PROVIDER_AUTHENTICATION'})
        with self.assertRaises(SentinelError):
            d.reconcile_job(raw, bound, plan['index'], digest(plan['index']), plan['blocks'], groups[0]['id'],
                records, digest(records), registry, registry_root(registry), admission, digest(admission))
        bound, plan, _, _ = setup(b'')
        value = parse(d.reconcile_document(b'', bound, plan['index'], digest(plan['index']), plan['blocks'], {}))
        self.assertEqual(value['status'], 'EMPTY_READING')


if __name__ == '__main__': unittest.main()
