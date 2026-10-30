"""Aggregate replay contracts: validated-source cost, byte identity and refusal isolation."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
from sentinel_v1 import document_analysis as d
from sentinel_v1.bindings import registry_root
from sentinel_v1.common import SentinelError, canonical, digest, identity, parse
from test_sentinel_document_analysis_independent import (declared_record_fixture,
    declared_inputs, mutate_block, planned, rows)


def aggregate(packet, inputs):
    return d.reconcile_document(*packet[:2], packet[2], digest(packet[2]), packet[3], inputs)


def fixture(raw=b'A' * 32000 + b'\n\n' + b'B' * 32000 + b'\n\n' + b'C' * 32000):
    packet = planned(raw); groups = rows(parse(packet[2]), packet[3], 'job_blocks')
    if len(groups) > 3: raise RuntimeError('development fixture job bound')
    inputs = {}
    for row in groups:
        inputs.update(declared_inputs(declared_record_fixture(raw, True, row['id'])))
    return packet, inputs


def repin(value, key, change):
    parsed = parse(value[key + '_raw']); change(parsed); raw = canonical(parsed)
    value[key + '_raw'], value[key + '_held'] = raw, digest(raw)


class AggregateContextControls(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('no native/model dispatch')).start()

    def test_source_validation_cost_is_independent_of_jobs_and_recorded_attempts(self):
        packet, inputs = fixture(); self.assertEqual(len(inputs), 3)
        expected = {}
        for job, value in inputs.items():
            expected[job] = identity(d.reconcile_job(*packet[:2], packet[2], digest(packet[2]),
                                                   packet[3], job, **value))
        with patch.object(d, 'document_checked', wraps=d.document_checked) as full, \
             patch.object(d, 'units_checked', wraps=d.units_checked) as units, \
             patch.object(d, 'groups_checked', wraps=d.groups_checked) as groups:
            result = parse(aggregate(packet, inputs))
        self.assertEqual((full.call_count, units.call_count, groups.call_count), (1, 1, 1))
        self.assertEqual(result['replayed_job_receipts'], expected)
        self.assertEqual(result['status'], 'RECORDED_GENERATION_IMPORTS_REPLAYED')
        self.assertEqual(result['semantic_completeness'], 'UNPROVEN')
        self.assertEqual(result['execution_authority'], 'NONE')

    def test_changed_source_binding_index_and_blocks_never_reuse_previous_call(self):
        value = declared_record_fixture(); packet = value[0]; inputs = declared_inputs(value)
        aggregate(packet, inputs)
        binding = parse(packet[1]); binding['source']['package_id'] = '0' * 64
        invalid = [(*((b'X' + packet[0][1:]), packet[1], packet[2], packet[3]),),
            (packet[0], canonical(binding), packet[2], packet[3]),
            (packet[0], packet[1], packet[2] + b' ', packet[3]),
            mutate_block(packet, 'paragraph_blocks', lambda block: block['rows'][0].update(sha256='0' * 64)),
            mutate_block(packet, 'job_blocks', lambda block: block['rows'][0].update(dependency_regions=['MISSING']))]
        blocks = dict(packet[3]); key = next(iter(blocks)); blocks[key] += b' '
        invalid.append((*packet[:3], blocks))
        for altered in invalid:
            with self.subTest(kind=identity(altered[2])), self.assertRaises(SentinelError):
                aggregate(altered, inputs)
        self.assertEqual(parse(aggregate(packet, inputs))['status'], 'RECORDED_GENERATION_IMPORTS_REPLAYED')

    def test_records_registry_admission_and_job_tampering_refuse_after_success(self):
        value = declared_record_fixture(retained_failure=True); packet = value[0]
        original = declared_inputs(value); aggregate(packet, original); job = value[1]['id']
        for kind in ('records-pin', 'records-job', 'registry-root', 'registry-byte',
                     'admission-pin', 'admission-entry', 'attempt-job', 'generation-import'):
            inputs = deepcopy(original); supplied = inputs[job]
            if kind == 'records-pin': supplied['records_raw'] += b' '
            elif kind == 'records-job': repin(supplied, 'records', lambda row: row.update(job_id='JOB99999'))
            elif kind == 'registry-root': supplied['registry_held'] = '0' * 64
            elif kind == 'registry-byte':
                key = next(iter(supplied['registry'])); supplied['registry'][key] = b'changed'
            elif kind == 'admission-pin': supplied['admission_raw'] += b' '
            elif kind == 'admission-entry': repin(supplied, 'admission', lambda row: row.update(entries=[]))
            elif kind == 'attempt-job': inputs['JOB99999'] = inputs.pop(job)
            else:
                attempt = parse(supplied['records_raw'])['attempts'][-1]
                supplied['registry'].pop(attempt['result_pin']['sha256'])
                supplied['registry_held'] = registry_root(supplied['registry'])
            with self.subTest(kind=kind), self.assertRaises(SentinelError): aggregate(packet, inputs)

    def test_cross_document_context_cannot_persist_between_calls(self):
        first = declared_record_fixture(b'First rule.'); second = declared_record_fixture(b'Other rule.')
        aggregate(first[0], declared_inputs(first)); aggregate(second[0], declared_inputs(second))
        with self.assertRaises(SentinelError): aggregate(second[0], declared_inputs(first))
        with self.assertRaises(SentinelError): aggregate(first[0], declared_inputs(second))
        self.assertEqual(parse(aggregate(first[0], declared_inputs(first)))['status'],
                         'RECORDED_GENERATION_IMPORTS_REPLAYED')


if __name__ == '__main__': unittest.main()
