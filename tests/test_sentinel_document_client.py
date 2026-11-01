"""Real envelope boundaries and full paragraph/source preservation controls."""
from copy import deepcopy
from pathlib import Path
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / 'tools'), str(ROOT / 'tests')]
from sentinel_v1 import document_client as client, document_analysis as document
from sentinel_v1.common import SentinelError, canonical, digest, identity, parse
from sentinel_v1.bindings import registry_root
from test_sentinel_meaning import binding
from test_sentinel_assessments import reviewer


class DocumentClientTests(unittest.TestCase):
    def test_exact_full_frame_boundary_and_utf8(self):
        self.assertEqual(len(client.frame_bytes('é', b'x' * 65526)), 65536)
        with self.assertRaisesRegex(SentinelError, 'complete client frame'):
            client.frame_bytes('é', b'x' * 65527)
        self.assertEqual(client.frame_bytes('é', b'A')[:10], b'SPG1\0\0\0\2\xc3\xa9')

    def test_repartition_preserves_all_bytes_and_original_import(self):
        raw = (('"éα😀' * 250) + '\n\n').encode() * 40
        bound = canonical(binding(raw)); dispatch = 'Read all in untruncated chunks.'
        plan = client.plan(raw, bound, dispatch)
        index, rows = document.document_checked(raw, bound, plan['index'], digest(plan['index']), plan['blocks'])
        self.assertEqual(b''.join(raw[r['span'][0]:r['span'][1]] for r in rows), raw)
        self.assertEqual(sum(len(r['paragraph_ids']) for r in rows), 40)
        value = client.checked(plan['client'], digest(plan['client']), raw, bound,
            plan['index'], digest(plan['index']), plan['blocks'])
        self.assertTrue(all(r['status'] == 'FRAME_ADMITTED' for r in value['jobs']))
        job = client.prepare(plan['client'], digest(plan['client']), raw, bound,
            plan['index'], digest(plan['index']), plan['blocks'], rows[0]['id'])
        self.assertLessEqual(len(job['frame']), 65536)
        proposal = canonical(parse(job['prompt'])['output_template'])
        registry = {digest(job[k]): job[k] for k in ('prompt', 'reading', 'request')}
        provenance = reviewer(registry, proposal); provenance['prompt_pin'] = identity(job['prompt'])
        prov = canonical(provenance)
        result = document.import_candidate(job['request'], digest(job['request']), proposal, digest(proposal),
            raw, bound, plan['index'], digest(plan['index']), plan['blocks'], registry,
            registry_root(registry), prov, digest(prov))
        self.assertEqual(parse(result)['scope'], 'STRUCTURAL_PROPOSAL_ONLY')

    def test_singleton_over_client_budget_stays_accounted_and_refuses(self):
        raw = b'A' * 54000; bound = canonical(binding(raw))
        base = document.plan_document_jobs(raw, bound)
        _, rows = document.document_checked(raw, bound, base['index'], digest(base['index']), base['blocks'])
        self.assertEqual(rows[0]['status'], 'ADMITTED')
        plan = client.plan(raw, bound, 'R' * 4096)
        value = parse(plan['client'])
        self.assertEqual(value['jobs'][0]['status'], 'FRAME_UNADMITTED')
        index, rows = document.document_checked(raw, bound, plan['index'], digest(plan['index']), plan['blocks'])
        self.assertEqual(rows[0]['span'], [0, len(raw)])
        self.assertEqual(index['paragraph_count'], 1)
        with self.assertRaisesRegex(SentinelError, 'not admitted'):
            client.prepare(plan['client'], digest(plan['client']), raw, bound,
                plan['index'], digest(plan['index']), plan['blocks'], 'JOB00001')

    def test_tampered_dispatch_index_or_frame_refuses(self):
        raw = b'A shall act unless B.\n\nCorrection: only after C.'
        bound = canonical(binding(raw)); plan = client.plan(raw, bound, 'Read all.')
        original = parse(plan['client'])
        for changed in ('dispatch', 'index', 'frame', 'status'):
            value = deepcopy(original)
            if changed == 'dispatch': value['dispatch'] += 'x'
            elif changed == 'index': value['index_pin']['sha256'] = '0' * 64
            elif changed == 'frame': value['jobs'][0]['frame_pin']['bytes'] += 1
            else: value['jobs'][0]['status'] = 'FRAME_UNADMITTED'
            raw_value = canonical(value)
            with self.subTest(changed=changed), self.assertRaises(SentinelError):
                client.checked(raw_value, digest(raw_value), raw, bound,
                    plan['index'], digest(plan['index']), plan['blocks'])

    def test_empty_and_unreadable_singletons_remain_explicit(self):
        for raw in (b'', b'x' * 65537, b'"' * 40000):
            bound = canonical(binding(raw)); plan = client.plan(raw, bound, 'Read all.')
            index, rows = document.document_checked(raw, bound, plan['index'], digest(plan['index']), plan['blocks'])
            self.assertEqual(b''.join(raw[r['span'][0]:r['span'][1]] for r in rows), raw)
            self.assertEqual(index['job_count'], 0)
            self.assertEqual(len(parse(plan['client'])['jobs']), len(rows))

    def test_targeted_partition_is_explicit_and_preserves_every_paragraph(self):
        raw = (b'A' * 1000 + b'\n\n') * 40; bound = canonical(binding(raw))
        old = client.plan(raw, bound, 'Read all.')
        plan = client.plan_targeted(raw, bound, 'Read all.', 20000)
        value = client.checked(plan['client'], digest(plan['client']), raw, bound,
            plan['index'], digest(plan['index']), plan['blocks'])
        self.assertEqual(value['schema'], client.TARGETED)
        self.assertEqual(value['packing_target_bytes'], 20000)
        self.assertGreater(len(value['jobs']), len(parse(old['client'])['jobs']))
        self.assertTrue(all(row['packing_target_met'] for row in value['jobs']))
        _, rows = document.document_checked(raw, bound, plan['index'], digest(plan['index']), plan['blocks'])
        self.assertEqual(b''.join(raw[row['span'][0]:row['span'][1]] for row in rows), raw)
        self.assertEqual(sum(len(row['paragraph_ids']) for row in rows), 40)
        self.assertEqual(parse(old['client'])['schema'], client.PROFILE)
        self.assertNotIn('packing_target_bytes', parse(old['client']))

    def test_target_miss_singleton_explicit_but_hard_limit_unchanged(self):
        raw = b'Whole indivisible source paragraph.'; bound = canonical(binding(raw))
        plan = client.plan_targeted(raw, bound, 'Read all.', 1)
        value = client.checked(plan['client'], digest(plan['client']), raw, bound,
            plan['index'], digest(plan['index']), plan['blocks'])
        self.assertFalse(value['jobs'][0]['packing_target_met'])
        self.assertEqual(value['jobs'][0]['status'], 'FRAME_ADMITTED')
        job = client.prepare(plan['client'], digest(plan['client']), raw, bound,
            plan['index'], digest(plan['index']), plan['blocks'], 'JOB00001')
        self.assertEqual(job['reading'], raw); self.assertLessEqual(len(job['frame']), 65536)

    def test_invalid_target_version_or_target_flag_refuses(self):
        raw = b'A\n\nB'; bound = canonical(binding(raw))
        for target in (0, -1, True, 65537, '20000'):
            with self.subTest(target=target), self.assertRaises(SentinelError):
                client.plan_targeted(raw, bound, 'Read all.', target)
        plan = client.plan_targeted(raw, bound, 'Read all.', 20000)
        for kind in ('version', 'flag', 'target'):
            value = parse(plan['client'])
            if kind == 'version': value['schema'] += 'unknown'
            elif kind == 'flag': value['jobs'][0]['packing_target_met'] = False
            else: value['packing_target_bytes'] = 1
            encoded = canonical(value)
            with self.subTest(kind=kind), self.assertRaises(SentinelError):
                client.checked(encoded, digest(encoded), raw, bound,
                    plan['index'], digest(plan['index']), plan['blocks'])


if __name__ == '__main__':
    unittest.main()
