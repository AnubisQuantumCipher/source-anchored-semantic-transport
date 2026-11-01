"""Developmental source-display controls; no model/native/network dispatch."""
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/'tools'), str(ROOT/'tests')]
from sentinel_v1 import document_display as display, document_analysis as analysis
from sentinel_v1.common import canonical, digest, identity, parse, SentinelError
from sentinel_v1.bindings import registry_root
from test_sentinel_meaning import binding
from test_sentinel_document_analysis import prepared, import_fixture
from transport_schema import operator_dictionary


def base(raw=b'Book title\n\nChapter one\n\nBody and its exception.'):
    bound = canonical(binding(raw)); plan = analysis.plan_document_jobs(raw, bound)
    return raw, bound, plan


def reference(kind='PLACEHOLDER', value='PLACEHOLDER:meaning.zip', package=None):
    return canonical({'schema': display.REFERENCE, 'kind': kind, 'value': value, 'package_id': package})


def render(packet, titles=None, ref=None, budget=1048576, unit='UNICODE_CODEPOINTS', imports=()):
    raw, bound, plan = packet; ref = reference() if ref is None else ref
    return display.render_document_display(raw, bound, plan['index'], digest(plan['index']), plan['blocks'],
        ref, digest(ref), budget, unit, titles, None if titles is None else digest(titles), imports)


def anchors(packet, rows):
    return canonical({'schema': display.TITLES, 'index_sha256': digest(packet[2]['index']), 'titles': rows})


def title(raw, name, region, role, start, end):
    return {'id': name, 'region_id': region, 'role': role, 'span': [start,end], 'sha256': digest(raw[start:end])}


def candidate(packet):
    raw = packet[0]; info = list(prepared(raw))
    result = import_fixture(raw, info)
    bound, plan, _, _, job, registry, proposal, provenance = info
    return {'request_raw':job['request'], 'request_held':digest(job['request']),
        'graph_raw':proposal, 'graph_held':digest(proposal), 'registry':registry,
        'registry_held':registry_root(registry), 'provenance_raw':provenance,
        'provenance_held':digest(provenance), 'import_raw':result, 'import_held':digest(result)}


class DisplayControls(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subprocess,'Popen',side_effect=AssertionError('no process/model/native/network')).start()

    def test_anchored_titles_headings_and_no_invented_mainideas(self):
        packet = base(); raw = packet[0]
        titles = anchors(packet,[title(raw,'BOOK','DOCUMENT','REGION_TITLE',0,10),
            title(raw,'CHAPTER','DOCUMENT','SOURCE_HEADING',12,23)])
        result=render(packet,titles); machine=parse(result['machine'])
        self.assertIn(b'Book title',result['overview']); self.assertIn(b'Chapter one',result['lexicon'])
        self.assertEqual(machine['formula_symbols'],['R001','H001'])
        self.assertEqual(machine['model_analysis'],'UNPERFORMED')
        self.assertEqual(machine['semantic_completeness'],'UNPROVEN')
        self.assertEqual(machine['share_status'],'SHARE_PREVIEW_NOT_VERIFIED_PACKAGE')
        self.assertIn(b'00000000000000000000000000000000',result['share_preview'])

    def test_missing_titles_are_explicit_not_book_familiarity(self):
        result=render(base()); value=parse(result['machine'])
        self.assertEqual(value['entries'][0]['label'],'DOCUMENT')
        self.assertEqual(value['entries'][0]['title_status'],'TITLE_UNSUPPLIED')
        self.assertIn(b'main ideas UNPERFORMED',result['formula'])

    def test_exact_budget_and_one_below_count_complete_reference(self):
        packet=base(); ref=reference(value='PLACEHOLDER:long-exact-package-reference.zip')
        result=render(packet,ref=ref); count=parse(result['machine'])['share_measurement']['count']
        self.assertEqual(render(packet,ref=ref,budget=count)['share_preview'],result['share_preview'])
        with self.assertRaises(SentinelError): render(packet,ref=ref,budget=count-1)
        self.assertIn(b'PKG:PLACEHOLDER:long-exact-package-reference.zip',result['share_preview'])

    def test_byte_and_codepoint_conventions_are_distinct_and_not_platform(self):
        packet=base(); ref=reference(value='PLACEHOLDER:é😀')
        result=render(packet,ref=ref); measured=parse(result['machine'])['share_measurement']
        self.assertEqual(measured['utf8_bytes'],len(result['share_preview']))
        self.assertEqual(measured['unicode_codepoints'],len(result['share_preview'].decode()))
        self.assertGreater(measured['utf8_bytes'],measured['unicode_codepoints'])
        render(packet,ref=ref,budget=measured['utf8_bytes'],unit='UTF8_BYTES')
        with self.assertRaises(SentinelError):render(packet,ref=ref,budget=measured['unicode_codepoints'],unit='UTF8_BYTES')
        self.assertEqual(measured['platform_limit'],'NOT_CLAIMED')

    def test_reference_kinds_local_unhosted_and_old_source_identity_refuse(self):
        packet=base(); result=render(packet,ref=reference('LOCAL_ARTIFACT','meaning.zip'))
        self.assertEqual(parse(result['machine'])['hosting'],'LOCAL_UNHOSTED')
        render(packet,ref=reference('HTTPS_URL','https://example.invalid/meaning.zip'))
        for ref in (reference('HTTPS_URL','javascript:run'),reference('LOCAL_ARTIFACT','../secret'),
                    reference(package=parse(packet[1])['source']['package_id'])):
            with self.assertRaises(ValueError):render(packet,ref=ref)

    def test_tampered_anchor_source_utf8_control_and_bool_refuse(self):
        packet=base('é title\n\nBody.'.encode()); raw=packet[0]
        original=title(raw,'BOOK','DOCUMENT','REGION_TITLE',0,8)
        for kind in ('hash','bool','split','outside','control'):
            row=deepcopy(original)
            if kind=='hash':row['sha256']='0'*64
            elif kind=='bool':row['span'][0]=False
            elif kind=='split':row['span']=[1,8];row['sha256']=digest(raw[1:8])
            elif kind=='outside':row['span'][1]=len(raw)+1
            else:row['span']=[0,10];row['sha256']=digest(raw[:10])
            with self.subTest(kind=kind),self.assertRaises(ValueError):render(packet,anchors(packet,[row]))

    def test_untrusted_markup_is_literal_escaped_not_instructions(self):
        packet=base(b'<script>run()</script>\n\nBody')
        row=title(packet[0],'BOOK','DOCUMENT','REGION_TITLE',0,22)
        result=render(packet,anchors(packet,[row]))
        self.assertNotIn(b'<script>',result['overview']); self.assertIn(b'&lt;script&gt;',result['overview'])
        self.assertEqual(parse(result['machine'])['entries'][0]['label'],'<script>run()</script>')

    def test_opaque_unadmitted_and_empty_statuses_visible(self):
        for raw,status in ((b'x'*65537,'OPAQUE'),(b'"'*40000,'PROMPT_BUDGET_UNADMITTED')):
            result=render(base(raw)); value=parse(result['machine'])
            self.assertEqual(value['status_counts'][status],1)
            self.assertEqual(value['nonadmitted_groups'][0]['span'],[0,len(raw)])
            self.assertIn(display.cell(status).encode(),result['lexicon'])
        self.assertEqual(parse(render(base(b''))['machine'])['document_processing'],'EMPTY_READING')

    def test_full_imported_proposal_is_explicit_and_receipt_tamper_refuses(self):
        packet=base(); item=candidate(packet)
        result=render(packet,imports=(item,)); value=parse(result['machine'])
        self.assertIn('P001',value['formula_symbols'])
        self.assertIn(b'PROPOSED',result['lexicon']); self.assertIn(b'Development fixture only',result['lexicon'])
        self.assertEqual(value['candidate_graphs'][0]['observed_provenance']['origin'],'MANUAL_FIXTURE')
        bad=dict(item); changed=parse(item['import_raw']);changed['job_id']='WRONG'
        bad['import_raw']=canonical(changed);bad['import_held']=digest(bad['import_raw'])
        with self.assertRaises(SentinelError):render(packet,imports=(bad,))
        with self.assertRaises(SentinelError):render(packet,imports=(item,item))

    def test_operator_definitions_reuse_exact_dictionary(self):
        result=render(base()); value=parse(result['machine'])
        self.assertEqual(value['operator_dictionary'],operator_dictionary('2'))
        self.assertEqual(value['operator_dictionary_pin'],identity(canonical(operator_dictionary('2'))))
        self.assertIn(b'no entailment or world',result['operators'])

    def test_64_symbols_complete_and_65_refuses_instead_of_drop(self):
        raw=b''.join(('H%02d\n\n'%i).encode() for i in range(64));packet=base(raw)
        rows=[title(raw,'H%02d'%i,'DOCUMENT','SOURCE_HEADING',i*5,i*5+3) for i in range(64)]
        result=render(packet,anchors(packet,rows[:63]))
        self.assertEqual(len(parse(result['machine'])['formula_symbols']),64)
        self.assertIn(b'H063',result['formula'])
        with self.assertRaises(SentinelError):render(packet,anchors(packet,rows))

    def test_changed_full_source_and_partial_anchor_reference_refuse(self):
        packet=base(); bad=(b'X'*len(packet[0]),packet[1],packet[2])
        with self.assertRaises(SentinelError):render(bad)
        ref=reference()
        with self.assertRaises(SentinelError):
            display.render_document_display(*packet[:2],packet[2]['index'],digest(packet[2]['index']),
                packet[2]['blocks'],ref,digest(ref),1048576,title_anchors_raw=b'{}')


if __name__=='__main__':unittest.main()
