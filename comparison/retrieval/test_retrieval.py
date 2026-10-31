"""Independent contract tests; authored from frozen literal oracle, never product source.

These tests check bounded retrieval structure and exact source copies. They do not
prove natural-language completeness, source truth, permission, or a strongest
retrieval baseline. Fixture UTF-8 and raw-byte input routes are compared here;
actual original/transport adapter verification belongs to the outer protocol.
The request JSON subset is canonical UTF-8 with no floats or negative integers;
source attributes and unit annotations are data, never permission or freshness.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
ARCHIVE = Path('/dev/shm/semantic-transport-retrieval-20261029')
ORACLE_SHA = '23525546f46513b5d1c45acfa2161d6d5266ae2446d88deff66f4aa7d5a690f3'
CONTRACT_SHA = 'd1e9799ec2adbfb9ab0f0c42fe0c5b7f271821a782db4c21e55e4d2f681213dc'
RESPONSE_SHA = '06671d73d65e8846f28708c38c98aeb3e7e03b51542e465ff9a4ea8411f54e34'


def canonical(value):
    """Return the frozen canonical UTF-8 JSON encoding without a newline."""
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':')).encode('utf-8')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pinned_json(path, expected):
    data = path.read_bytes()
    if sha(data) != expected:
        raise AssertionError(f'Fixture pin mismatch: {path.name}')
    value = json.loads(data)
    if data != canonical(value):
        raise AssertionError(f'Fixture is not canonical: {path.name}')
    return value


def annotation_source(source):
    attrs = {key: source[key] for key in
             ('family_id', 'version_id', 'version_state', 'current_authority')}
    return {'id': source['id'], 'revision': source['version_id'],
            'encoding': source['encoding'], 'media_type': source['mime_type'],
            'bytes': source['byte_length'], 'sha256': source['sha256'],
            'attributes': attrs}


def annotation_unit(unit):
    return {'id': unit['id'], 'source': unit['source_id'],
            'span': [unit['source_byte_start'], unit['source_byte_end']],
            'sha256': unit['quote_sha256'], 'whole_unit': unit['whole_unit'],
            'dependencies': list(unit['dependencies']),
            'annotations': copy.deepcopy(unit['annotations'])}


def scenario_input(oracle, scenario_id, route):
    scenario = next(s for s in oracle['scenarios'] if s['id'] == scenario_id)
    records = [s for s in oracle['sources'] if s['id'] in scenario['source_ids']]
    source_bytes = {}
    for source in records:
        raw = base64.b64decode(source['raw_base64'], validate=True)
        if route == 'fixture_utf8' and source['encoding'] == 'utf-8':
            raw = source['raw_utf8'].encode('utf-8')
        if sha(raw) != source['sha256'] or len(raw) != source['byte_length']:
            raise AssertionError('Original fixture byte identity failed')
        source_bytes[source['id']] = raw
    annotations = {'schema': 'transport/retrieval-annotations/1',
                   'sources': [annotation_source(s) for s in records],
                   'units': [annotation_unit(u) for u in oracle['units']
                             if u['id'] in scenario['unit_ids']]}
    return source_bytes, canonical(annotations)


def synthetic(text, annotations=None, attrs=None, encoding='utf-8'):
    raw = text.encode('utf-8') if isinstance(text, str) else text
    source = {'id': 'S_SYNTH', 'revision': 's1', 'encoding': encoding,
              'media_type': 'text/plain' if encoding == 'utf-8'
              else 'application/octet-stream',
              'bytes': len(raw), 'sha256': sha(raw),
              'attributes': {} if attrs is None else copy.deepcopy(attrs)}
    unit = {'id': 'U_SYNTH', 'source': 'S_SYNTH', 'span': [0, len(raw)],
            'sha256': sha(raw), 'whole_unit': True, 'dependencies': [],
            'annotations': {} if annotations is None else
            copy.deepcopy(annotations)}
    doc = {'schema': 'transport/retrieval-annotations/1',
           'sources': [source], 'units': [unit]}
    return {'S_SYNTH': raw}, canonical(doc)


def request(action, **fields):
    return canonical({'action': action, **fields})


def search_request(action='search', query='needle', sources=None,
                   mode='exact_phrase', field='source', **fields):
    selected = ['S_SYNTH'] if sources is None else sources
    return request(action, query=query, sources=selected, mode=mode,
                   field=field, **fields)


def load_core():
    """Load only when the frozen tests are executed after the stability notice."""
    spec = importlib.util.spec_from_file_location('bounded_retrieval_core',
                                                HERE / 'retrieval.py')
    if spec is None or spec.loader is None:
        raise AssertionError('Retrieval module loader unavailable')
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


# Response-shape assertions and test cases follow only after a frozen supplement.

class ContractCase(unittest.TestCase):
    """Shared fixtures; every corpus is explicitly closed after its test."""

    @classmethod
    def setUpClass(cls):
        cls.oracle = pinned_json(HERE / 'oracle.json', ORACLE_SHA)
        cls.contract = pinned_json(HERE / 'contract.json', CONTRACT_SHA)
        cls.response_contract = pinned_json(HERE / 'response-contract.json',
                                             RESPONSE_SHA)
        cls.core = load_core()

    def setUp(self):
        self.opened = []
        self.inputs = {}
        self.calls = {}

    def tearDown(self):
        for corpus in self.opened:
            corpus.close()

    def new(self, sources, annotations):
        corpus = self.core.Corpus(sources, annotations, sha(annotations))
        self.opened.append(corpus)
        self.inputs[id(corpus)] = (dict(sources), json.loads(annotations),
                                   sha(annotations))
        self.calls[id(corpus)] = 0
        return corpus

    def scenario(self, scenario_id='SC_MAIN', route='fixture_raw_bytes'):
        return self.new(*scenario_input(self.oracle, scenario_id, route))

    def reject_init(self, sources, annotations, pin=None):
        expected = sha(annotations) if pin is None else pin
        with self.assertRaises(self.core.RetrievalError):
            self.core.Corpus(sources, annotations, expected)

    def changed_annotations(self, source, change):
        value = json.loads(source)
        change(value)
        return canonical(value)


class AdmissionTests(ContractCase):
    def test_annotation_pin_mismatch(self):
        sources, annotations = synthetic('needle')
        self.reject_init(sources, annotations, '0' * 64)

    def test_unknown_annotation_fields(self):
        sources, annotations = synthetic('needle')
        mutations = [lambda d: d.update(extra='hidden'),
                     lambda d: d['sources'][0].update(extra='hidden'),
                     lambda d: d['units'][0].update(extra='hidden')]
        for change in mutations:
            with self.subTest(mutation=mutations.index(change)):
                bad = self.changed_annotations(annotations, change)
                self.reject_init(sources, bad)

    def test_source_actor_swap_tampering(self):
        sources, annotations = scenario_input(self.oracle, 'SC_MAIN',
                                             'fixture_raw_bytes')
        changed = dict(sources)
        original = changed['S_REVIEWS']
        changed['S_REVIEWS'] = original.replace(b'Reviewer A', b'Reviewer B')
        self.assertNotEqual(original, changed['S_REVIEWS'])
        self.reject_init(changed, annotations)

    def test_source_numeric_byte_tampering(self):
        sources, annotations = scenario_input(self.oracle, 'SC_MAIN',
                                             'fixture_raw_bytes')
        for source_id, before, after in [('S_CTRL_NEW', b'100 ms', b'101 ms'),
                                         ('S_QUANTITY', b'12 L', b'13 L')]:
            with self.subTest(source=source_id):
                changed = dict(sources)
                changed[source_id] = changed[source_id].replace(before, after)
                self.assertNotEqual(sources[source_id], changed[source_id])
                self.reject_init(changed, annotations)

    def test_recomputed_source_hash_cannot_hide_bad_quote_hash(self):
        sources, annotations = synthetic('Reviewer A must pass.')
        changed = {'S_SYNTH': b'Reviewer B must pass.'}
        doc = json.loads(annotations)
        doc['sources'][0]['sha256'] = sha(changed['S_SYNTH'])
        self.reject_init(changed, canonical(doc))

    def test_unit_span_and_quote_hash_validation(self):
        sources, annotations = synthetic('needle')
        mutations = [lambda d: d['units'][0].update(span=[0, 7]),
                     lambda d: d['units'][0].update(span=[-1, 2]),
                     lambda d: d['units'][0].update(sha256='0' * 64),
                     lambda d: d['units'][0].update(whole_unit=False)]
        for change in mutations:
            with self.subTest(mutation=mutations.index(change)):
                bad = self.changed_annotations(annotations, change)
                self.reject_init(sources, bad)

    def test_duplicate_identity_and_bool_length(self):
        sources, annotations = synthetic('needle')
        mutations = [lambda d: d['sources'].append(copy.deepcopy(d['sources'][0])),
                     lambda d: d['units'].append(copy.deepcopy(d['units'][0])),
                     lambda d: d['sources'][0].update(bytes=True)]
        for change in mutations:
            with self.subTest(mutation=mutations.index(change)):
                bad = self.changed_annotations(annotations, change)
                self.reject_init(sources, bad)

    def test_source_set_mismatch(self):
        sources, annotations = synthetic('needle')
        self.reject_init({}, annotations)
        self.reject_init({**sources, 'S_EXTRA': b'extra'}, annotations)

    def test_source_count_bound(self):
        records = []
        sources = {}
        for number in range(17):
            source_id = f'S_{number}'
            sources[source_id] = b'x'
            records.append({'id': source_id, 'revision': 's1',
                            'encoding': 'utf-8', 'media_type': 'text/plain',
                            'bytes': 1, 'sha256': sha(b'x'), 'attributes': {}})
        annotations = canonical({'schema': 'transport/retrieval-annotations/1',
                                 'sources': records, 'units': []})
        self.reject_init(sources, annotations)

    def test_unit_bound_is_sixteen_per_invocation(self):
        all_sources = {s['id']: base64.b64decode(s['raw_base64'], validate=True)
                       for s in self.oracle['sources']}
        doc = {'schema': 'transport/retrieval-annotations/1',
               'sources': [annotation_source(s) for s in self.oracle['sources']],
               'units': [annotation_unit(u) for u in self.oracle['units']]}
        self.assertGreater(len(doc['units']), 16)
        self.reject_init(all_sources, canonical(doc))

    def test_aggregate_source_byte_bound(self):
        self.reject_init(*synthetic(b'x' * 65537))

    def test_annotation_byte_bound(self):
        self.reject_init(*synthetic('needle', attrs={'padding': 'x' * 65536}))

    def test_dependency_edge_bound(self):
        sources, annotations = synthetic('needle')
        doc = json.loads(annotations)
        doc['units'][0]['dependencies'] = [f'U_DEP_{i}' for i in range(65)]
        self.reject_init(sources, canonical(doc))

    def test_invalid_declared_utf8(self):
        self.reject_init(*synthetic(b'\xff', encoding='utf-8'))

    def test_nonbytes_source_rejected(self):
        _, annotations = synthetic('needle')
        self.reject_init({'S_SYNTH': 'needle'}, annotations)

    def test_annotation_pin_detects_changed_permission_data(self):
        sources, annotations = synthetic('needle', attrs={'authority': 'NONE'})
        changed = self.changed_annotations(
            annotations,
            lambda d: d['sources'][0]['attributes'].update(authority='GRANTED'))
        self.reject_init(sources, changed, sha(annotations))


class FrozenOracleTests(unittest.TestCase):
    """Fixture integrity only; literal expectations are never regenerated by search."""

    def test_raw_v2_archive_is_exact_working_source(self):
        raw = (HERE / 'oracle.json').read_bytes()
        self.assertEqual(sha(raw), ORACLE_SHA)
        self.assertEqual(raw, (ARCHIVE / 'oracle.v2.raw.json').read_bytes())
        self.assertEqual(raw, canonical(json.loads(raw)))
        self.assertFalse(raw.endswith(b'\n'))

    def test_initial_archive_retains_original_identity(self):
        raw = (ARCHIVE / 'oracle.initial.raw.json').read_bytes()
        self.assertEqual(len(raw), 46593)
        self.assertEqual(sha(raw),
                         'b93bda359afd87920e1ff1b073b6deaf4174f454b58628ca49bc276079dfeb37')

    def test_declared_scenario_inputs_use_identical_bytes_and_annotations(self):
        oracle = pinned_json(HERE / 'oracle.json', ORACLE_SHA)
        for scenario in oracle['scenarios']:
            with self.subTest(scenario=scenario['id']):
                first = scenario_input(oracle, scenario['id'], 'fixture_utf8')
                second = scenario_input(oracle, scenario['id'],
                                        'fixture_raw_bytes')
                self.assertEqual(first, second)
                annotations = json.loads(first[1])
                self.assertLessEqual(len(annotations['units']), 16)
                self.assertLessEqual(len(annotations['sources']), 16)
                self.assertLessEqual(sum(map(len, first[0].values())), 65536)
                self.assertLessEqual(len(first[1]), 65536)

    def test_all_raw_quotes_and_byte_anchors_are_exact(self):
        oracle = pinned_json(HERE / 'oracle.json', ORACLE_SHA)
        sources = {s['id']: base64.b64decode(s['raw_base64'], validate=True)
                   for s in oracle['sources']}
        for unit in oracle['units']:
            with self.subTest(unit=unit['id']):
                quote = sources[unit['source_id']][unit['source_byte_start']:
                                                   unit['source_byte_end']]
                self.assertEqual(quote, base64.b64decode(
                    unit['raw_quote_base64'], validate=True))
                self.assertEqual(sha(quote), unit['quote_sha256'])
                if 'raw_quote_utf8' in unit:
                    self.assertEqual(quote, unit['raw_quote_utf8'].encode('utf-8'))

    def test_split_no_match_scope_preserves_original_query(self):
        oracle = pinned_json(HERE / 'oracle.json', ORACLE_SHA)
        query = next(q for q in oracle['queries'] if q['id'] == 'Q_NO_MATCH')
        invocations = [i for i in oracle['query_invocations']
                       if i['query_id'] == 'Q_NO_MATCH']
        self.assertEqual(len(invocations), 2)
        union = set()
        for invocation in invocations:
            union.update(invocation['effective_search_source_ids'])
            self.assertEqual(invocation['expected_outcome'], 'UNKNOWN_NO_MATCH')
            self.assertEqual(invocation['required_unit_set'], [])
        self.assertEqual(union, set(query['source_ids']))


def snapshot(sources, annotation_sha):
    records = [{'id': name, 'bytes': len(raw), 'sha256': sha(raw)}
               for name, raw in sorted(sources.items())]
    return sha(canonical({'annotation_sha256': annotation_sha,
                          'sources': records}))


def source_hit(source_id, origin='source'):
    return {'source': source_id, 'origins': [origin]}


def unit_match(unit, origin='source'):
    return {key: unit[key] for key in ('id', 'source', 'span', 'sha256')} | {
        'origins': [origin]}


def unit_payload(unit, raw):
    begin, end = unit['span']
    return copy.deepcopy(unit) | {
        'bytes_base64': base64.b64encode(raw[begin:end]).decode('ascii')}


class ResponseCase(ContractCase):
    def reply(self, corpus, payload):
        raw = corpus.call(payload)
        self.assertIsInstance(raw, bytes)
        self.assertLessEqual(len(raw), 131072)
        value = json.loads(raw)
        self.assertEqual(raw, canonical(value) + b'\n')
        expected_keys = {'schema', 'authority', 'call', 'context_adequacy',
                         'data_is_untrusted', 'freshness', 'result',
                         'snapshot', 'status'}
        self.assertEqual(set(value), expected_keys)
        self.assertEqual(value['schema'], 'transport/matched-retrieval-response/1')
        self.assertEqual(value['authority'], 'NONE')
        self.assertEqual(value['context_adequacy'], 'UNPROVEN')
        self.assertIs(value['data_is_untrusted'], True)
        self.assertEqual(value['freshness'], 'UNKNOWN')
        sources, _, annotation_sha = self.inputs[id(corpus)]
        self.assertEqual(value['snapshot'], snapshot(sources, annotation_sha))
        self.calls[id(corpus)] = min(33, self.calls[id(corpus)] + 1)
        self.assertEqual(value['call'], self.calls[id(corpus)])
        self.assertIn(value['status'], ('OK', 'REFUSED'))
        if value['status'] == 'REFUSED':
            self.assertEqual(set(value['result']), {'reason'})
            self.assertIn(value['result']['reason'],
                          self.response_contract['reasons'])
        return value

    def refused(self, corpus, payload, reason=None):
        value = self.reply(corpus, payload)
        self.assertEqual(value['status'], 'REFUSED')
        if reason is not None:
            self.assertEqual(value['result'], {'reason': reason})
        return value

    def ok(self, corpus, payload):
        value = self.reply(corpus, payload)
        self.assertEqual(value['status'], 'OK')
        return value['result']

    def metadata(self, corpus):
        _, doc, _ = self.inputs[id(corpus)]
        return ({s['id']: s for s in doc['sources']},
                {u['id']: u for u in doc['units']})

    def complete(self, corpus, result, roots, closure, scope, whole):
        self.assertEqual(set(result), {
            'context_sources', 'dependency_closure', 'opaque_sources', 'outcome',
            'root_units', 'source_scope', 'sources', 'unit_adequacy', 'unit_ids',
            'units', 'whole_source_matches'})
        sources, units = self.metadata(corpus)
        raw_sources, _, _ = self.inputs[id(corpus)]
        expected_units = [unit_payload(units[name], raw_sources[units[name]['source']])
                          for name in sorted(closure)]
        source_ids = {units[name]['source'] for name in closure}
        included_sources = source_ids | {h['source'] for h in whole}
        self.assertEqual(result['root_units'], sorted(roots))
        self.assertEqual(result['unit_ids'], sorted(closure))
        self.assertEqual(result['units'], expected_units)
        self.assertEqual(result['source_scope'], sorted(scope))
        self.assertEqual(result['sources'], [sources[s] for s in sorted(included_sources)])
        self.assertEqual(result['context_sources'], sorted(source_ids - set(scope)))
        self.assertEqual(result['whole_source_matches'], whole)
        self.assertEqual(result['dependency_closure'], 'ALL_REACHABLE_DECLARED_EDGES')
        self.assertEqual(result['unit_adequacy'], 'DECLARED_NOT_PROVEN')
        self.assertEqual(result['opaque_sources'], sorted(
            s for s in scope if sources[s]['encoding'] == 'opaque'))


class LiteralOracleTests(ResponseCase):
    def test_all_literal_queries_and_complete_closures_identically(self):
        queries = {q['id']: q for q in self.oracle['queries']}
        units = {u['id']: u for u in self.oracle['units']}
        refusals = {'REFUSE_MISSING_DEPENDENCY': 'REFUSED_MISSING_DEPENDENCY',
                    'REFUSE_DEPENDENCY_CYCLE': 'REFUSED_DEPENDENCY_CYCLE'}
        for invocation in self.oracle['query_invocations']:
            with self.subTest(invocation=invocation['id']):
                query = queries[invocation['query_id']]
                selected = invocation['effective_search_source_ids']
                payload = search_request('query', query=query['query_utf8'],
                                         sources=selected, mode=query['match_mode'])
                arms = [self.scenario(invocation['scenario_id'], route)
                        for route in ('fixture_utf8', 'fixture_raw_bytes')]
                replies = [self.reply(arm, payload) for arm in arms]
                self.assertEqual(replies[0], replies[1])
                expected = invocation['expected_outcome']
                if expected in refusals:
                    self.assertEqual(replies[0]['status'], 'REFUSED')
                    self.assertEqual(replies[0]['result'], {'reason': refusals[expected]})
                    continue
                self.assertEqual(replies[0]['status'], 'OK')
                roots = query['expected_root_units']
                whole = [source_hit(s) for s in sorted({units[u]['source_id']
                                                       for u in roots})]
                result = replies[0]['result']
                self.assertEqual(result['outcome'], expected)
                self.complete(arms[0], result, roots,
                              invocation['expected_dependency_closure'], selected, whole)

    def test_expand_retains_complete_whole_units_and_cross_source_context(self):
        corpus = self.scenario()
        result = self.ok(corpus, request('expand', units=['U_CTRL_NEW']))
        self.assertEqual(result['outcome'], 'EXPAND_COMPLETE')
        self.complete(corpus, result, ['U_CTRL_NEW'],
                      ['U_CTRL_NEW', 'U_DEF_NEW', 'U_MAINT'],
                      ['S_CTRL_NEW'], [])

    def test_expand_two_versions_keeps_both_distinct_identities(self):
        corpus = self.scenario()
        roots = ['U_CTRL_OLD', 'U_CTRL_NEW']
        result = self.ok(corpus, request('expand', units=roots))
        self.complete(corpus, result, roots,
                      ['U_CTRL_NEW', 'U_CTRL_OLD', 'U_DEF_NEW', 'U_DEF_OLD', 'U_MAINT'],
                      ['S_CTRL_OLD', 'S_CTRL_NEW'], [])

    def test_expand_missing_dependency_and_cycle_refuse_without_partial_payload(self):
        corpus = self.scenario('SC_NEG')
        cases = [(['U_MISSING_RULE'], 'REFUSED_MISSING_DEPENDENCY'),
                 (['U_CYCLE_A'], 'REFUSED_DEPENDENCY_CYCLE')]
        for roots, reason in cases:
            with self.subTest(roots=roots):
                self.refused(corpus, request('expand', units=roots), reason)

    def test_catalog_preserves_full_metadata_and_marks_unresolved_dependency(self):
        corpus = self.scenario('SC_NEG')
        result = self.ok(corpus, request('catalog'))
        sources, units = self.metadata(corpus)
        self.assertEqual(result, {
            'interpretation_validation': 'NOT_PERFORMED',
            'source_coverage': 'ALL_HELD_ORIGINAL_BYTES',
            'sources': [sources[s] for s in sorted(sources)],
            'units': [units[u] for u in sorted(units)],
            'unresolved_dependency_ids': ['U_ABSENT_SHEET']})


class SearchTests(ResponseCase):
    def test_literal_search_pagination_does_not_hide_other_roots(self):
        corpus = self.scenario()
        scope = ['S_CTRL_NEW', 'S_CTRL_OLD']
        _, units = self.metadata(corpus)
        expected = [unit_match(units[u]) for u in ['U_CTRL_NEW', 'U_CTRL_OLD']]
        pages = []
        for offset in range(3):
            result = self.ok(corpus, search_request(query='Kite controller',
                             sources=scope, limit=1, offset=offset))
            self.assertEqual(set(result), {'next_offset', 'offset', 'opaque_sources',
                             'outcome', 'ranking', 'source_scope', 'total_unit_matches',
                             'unit_matches', 'whole_source_matches'})
            self.assertEqual(result['unit_matches'], expected[offset:offset + 1])
            self.assertEqual(result['total_unit_matches'], 2)
            self.assertEqual(result['source_scope'], sorted(scope))
            self.assertEqual(result['whole_source_matches'],
                             [source_hit(s) for s in sorted(scope)])
            self.assertEqual(result['ranking'], 'LITERAL_ID_ORDER')
            self.assertEqual(result['outcome'], 'MATCHES')
            self.assertEqual(result['offset'], offset)
            self.assertEqual(result['next_offset'], 1 if offset == 0 else None)
            self.assertEqual(result['opaque_sources'], [])
            pages.extend(result['unit_matches'])
        self.assertEqual(pages, expected)

    def test_unit_annotation_hits_are_separately_labeled(self):
        corpus = self.scenario()
        _, units = self.metadata(corpus)
        result = self.ok(corpus, search_request(query='multilingual_quote',
                         sources=['S_MULTI'], field='annotation', limit=16, offset=0))
        self.assertEqual(result['unit_matches'],
                         [unit_match(units['U_CAFE_NFC'], 'annotation')])
        self.assertEqual(result['whole_source_matches'], [])
        source_only = self.ok(corpus, search_request(query='multilingual_quote',
                              sources=['S_MULTI'], limit=16, offset=0))
        self.assertEqual(source_only['outcome'], 'UNKNOWN_NO_MATCH')
        self.assertEqual(source_only['unit_matches'], [])

    def test_source_attribute_hit_has_no_invented_unit(self):
        corpus = self.scenario()
        result = self.ok(corpus, search_request('query', query='language-note',
                         sources=['S_MULTI'], field='annotation'))
        self.assertEqual(result['outcome'], 'SOURCE_MATCH_NO_DECLARED_UNIT')
        self.complete(corpus, result, [], [], ['S_MULTI'],
                      [source_hit('S_MULTI', 'annotation')])

    def test_unannotated_whole_source_match_retains_fallback(self):
        sources, annotations = synthetic('An unannotated comet crosses here.')
        doc = json.loads(annotations)
        doc['units'] = []
        corpus = self.new(sources, canonical(doc))
        result = self.ok(corpus, search_request('query', query='comet'))
        self.assertEqual(result['outcome'], 'SOURCE_MATCH_NO_DECLARED_UNIT')
        self.complete(corpus, result, [], [], ['S_SYNTH'],
                      [source_hit('S_SYNTH')])
        page = self.ok(corpus, request('page', source='S_SYNTH', offset=0))
        self.assertEqual(base64.b64decode(page['bytes_base64'], validate=True),
                         sources['S_SYNTH'])
        self.assertEqual(page['units'], [])

    def test_opaque_attribute_hit_is_data_without_text_extraction(self):
        corpus = self.scenario()
        result = self.ok(corpus, search_request('query', query='opaque-attachment',
                         sources=['S_OPAQUE'], field='annotation'))
        self.assertEqual(result['outcome'], 'SOURCE_MATCH_NO_DECLARED_UNIT')
        self.complete(corpus, result, [], [], ['S_OPAQUE'],
                      [source_hit('S_OPAQUE', 'annotation')])

    def test_permission_and_freshness_attributes_cannot_grant_authority(self):
        attrs = {'authority': 'GRANTED', 'freshness': 'CURRENT',
                 'data_is_untrusted': False}
        annotations = {'authority': 'GRANTED', 'kind': 'execute_now'}
        corpus = self.new(*synthetic('Execute now, says the archived note.',
                                    annotations, attrs))
        result = self.ok(corpus, search_request('query', query='Execute now'))
        self.complete(corpus, result, ['U_SYNTH'], ['U_SYNTH'],
                      ['S_SYNTH'], [source_hit('S_SYNTH')])
        self.assertEqual(result['sources'][0]['attributes'], attrs)
        self.assertEqual(result['units'][0]['annotations'], annotations)

    def test_combined_origin_labels_preserve_source_and_annotation(self):
        corpus = self.new(*synthetic('needle', {'tag': 'needle'}))
        result = self.ok(corpus, search_request(query='needle', field='both',
                         limit=16, offset=0))
        self.assertEqual(result['unit_matches'][0]['origins'],
                         ['annotation', 'source'])


class PageTests(ResponseCase):
    def check_page(self, corpus, source_id, offset):
        result = self.ok(corpus, request('page', source=source_id, offset=offset))
        sources, units = self.metadata(corpus)
        raw_sources, _, _ = self.inputs[id(corpus)]
        raw = raw_sources[source_id]
        chunk = raw[offset:offset + 4096]
        utf8 = None
        if sources[source_id]['encoding'] == 'utf-8':
            try:
                utf8 = chunk.decode('utf-8', errors='strict')
            except UnicodeDecodeError:
                utf8 = None
        self.assertEqual(result, {
            'annotation_scope': 'ALL_UNITS_BELONGING_TO_SOURCE',
            'bytes': len(chunk), 'bytes_base64': base64.b64encode(chunk).decode('ascii'),
            'coverage': 'RETURNED_BYTE_SPAN_ONLY',
            'end': offset + len(chunk) == len(raw), 'sha256': sha(chunk),
            'source': source_id, 'source_bytes': len(raw),
            'source_sha256': sha(raw), 'span': [offset, offset + len(chunk)],
            'units': [units[u] for u in sorted(units)
                      if units[u]['source'] == source_id], 'utf8': utf8})
        return result

    def test_byte_pages_preserve_split_utf8_and_full_annotation_scope(self):
        corpus = self.new(*synthetic('x' * 4095 + 'é終line'))
        first = self.check_page(corpus, 'S_SYNTH', 0)
        second = self.check_page(corpus, 'S_SYNTH', 4096)
        aligned = self.check_page(corpus, 'S_SYNTH', 4095)
        self.assertIsNone(first['utf8'])
        self.assertIsNone(second['utf8'])
        self.assertEqual(aligned['utf8'], 'é終line')
        self.assertEqual(first['units'], second['units'])
        raw, _, _ = self.inputs[id(corpus)]
        self.check_page(corpus, 'S_SYNTH', len(raw['S_SYNTH']))

    def test_opaque_page_is_exact_bytes_with_no_inferred_utf8(self):
        corpus = self.scenario()
        result = self.check_page(corpus, 'S_OPAQUE', 0)
        self.assertIsNone(result['utf8'])

    def test_corpus_owns_fixed_snapshot_after_caller_changes_mapping(self):
        sources, annotations = synthetic('needle')
        corpus = self.new(sources, annotations)
        sources['S_SYNTH'] = b'forged'
        result = self.check_page(corpus, 'S_SYNTH', 0)
        self.assertEqual(base64.b64decode(result['bytes_base64'], validate=True),
                         b'needle')


class RefusalTests(ResponseCase):
    def test_closed_request_shapes_types_and_canonical_json(self):
        corpus = self.new(*synthetic('needle'))
        malformed = [request('not_an_action'), request('catalog', extra='hidden'),
                     b'{"action": "catalog"}',
                     b'{"action":"catalog","action":"catalog"}',
                     request('page', source='S_SYNTH', offset=True),
                     request('page', source='S_SYNTH', offset=1.5),
                     request('page', source='S_SYNTH', offset=-1)]
        for payload in malformed:
            with self.subTest(payload=payload):
                self.refused(corpus, payload, 'REFUSED_SCHEMA')

    def test_unknown_empty_and_duplicate_source_scopes(self):
        corpus = self.new(*synthetic('needle'))
        for scope in [[], ['S_UNKNOWN'], ['S_SYNTH', 'S_SYNTH']]:
            with self.subTest(scope=scope):
                self.refused(corpus, search_request('query', sources=scope),
                             'REFUSED_SOURCE_SCOPE')
        self.refused(corpus, request('page', source='S_UNKNOWN', offset=0),
                     'REFUSED_SOURCE_SCOPE')

    def test_invalid_expand_roots_and_page_offset(self):
        corpus = self.new(*synthetic('needle'))
        for roots in [[], ['U_UNKNOWN'], ['U_SYNTH', 'U_SYNTH']]:
            with self.subTest(roots=roots):
                self.refused(corpus, request('expand', units=roots),
                             'REFUSED_QUERY')
        self.refused(corpus, request('page', source='S_SYNTH', offset=7),
                     'REFUSED_QUERY')

    def test_empty_queries_and_ascii_space_token_rule(self):
        corpus = self.new(*synthetic('needle'))
        self.refused(corpus, search_request('query', query=''), 'REFUSED_QUERY')
        self.refused(corpus, search_request('query', query='   ', mode='all_tokens'),
                     'REFUSED_QUERY')
        result = self.ok(corpus, search_request('query', query='   '))
        self.assertEqual(result['outcome'], 'UNKNOWN_NO_MATCH')

    def test_query_byte_token_and_pagination_bounds(self):
        corpus = self.new(*synthetic('x'))
        cases = [search_request('query', query='x' * 257),
                 search_request('query', query=' '.join(['x'] * 33), mode='all_tokens'),
                 search_request(limit=17, offset=0),
                 search_request(limit=0, offset=0),
                 search_request(limit=1, offset=17)]
        for payload in cases:
            with self.subTest(payload=payload):
                self.refused(corpus, payload, 'REFUSED_BOUND')
        allowed = self.ok(corpus, search_request('query', query='x' * 256))
        self.assertEqual(allowed['outcome'], 'UNKNOWN_NO_MATCH')
        allowed_tokens = self.ok(corpus, search_request(
            'query', query=' '.join(['x'] * 32), mode='all_tokens'))
        self.assertEqual(allowed_tokens['root_units'], ['U_SYNTH'])

    def test_oversized_request_has_explicit_bound_refusal(self):
        corpus = self.new(*synthetic('needle'))
        payload = request('catalog', extra='x' * 65536)
        self.assertGreater(len(payload), 65536)
        self.refused(corpus, payload, 'REFUSED_BOUND')

    def test_complete_output_overflow_refuses_without_truncation(self):
        sources, annotations = synthetic('Z' * 65536)
        doc = json.loads(annotations)
        doc['units'] = [dict(doc['units'][0], id=f'U_WIDE_{i}')
                        for i in range(16)]
        corpus = self.new(sources, canonical(doc))
        self.refused(corpus, search_request('query', query='Z'),
                     'REFUSED_OUTPUT_BOUND')

    def test_refusals_count_toward_saturating_session_budget(self):
        corpus = self.new(*synthetic('needle'))
        for _ in range(32):
            self.refused(corpus, request('not_an_action'), 'REFUSED_SCHEMA')
        for _ in range(2):
            reply = self.refused(corpus, request('catalog'), 'REFUSED_CALL_BOUND')
            self.assertEqual(reply['call'], 33)

    def test_closed_corpus_refuses(self):
        corpus = self.new(*synthetic('needle'))
        corpus.close()
        self.opened.remove(corpus)
        self.refused(corpus, request('catalog'), 'REFUSED_CLOSED')

    def test_refusal_reason_is_stable_between_both_fixture_routes(self):
        arms = [self.scenario('SC_MAIN', route)
                for route in ('fixture_utf8', 'fixture_raw_bytes')]
        payloads = [request('catalog', extra='hidden'),
                    search_request('query', sources=['S_UNKNOWN']),
                    request('expand', units=['U_UNKNOWN'])]
        for payload in payloads:
            results = [self.refused(arm, payload) for arm in arms]
            self.assertEqual(results[0], results[1])


class FtsTests(ResponseCase):
    def optional_fts(self, corpus, payload):
        reply = self.reply(corpus, payload)
        if reply['status'] == 'REFUSED':
            self.assertIn(reply['result']['reason'],
                          ('REFUSED_FTS_UNAVAILABLE', 'REFUSED_FTS_WORK_BOUND'))
            return None
        return reply['result']

    def test_optional_fts_returns_named_lane_or_explicit_refusal(self):
        corpus = self.scenario()
        result = self.optional_fts(corpus, search_request(query='train',
                                  sources=['S_PERSONAL'], mode='fts5', limit=16, offset=0))
        if result is None:
            return
        self.assertEqual(result['outcome'], 'MATCHES')
        self.assertEqual(result['ranking'], 'SQLITE_FTS5_BM25')
        self.assertEqual([u['id'] for u in result['unit_matches']], ['U_NOTEBOOK'])
        self.assertEqual(result['unit_matches'][0]['origins'], ['source'])

    def test_fts_query_operators_are_quoted_tokens(self):
        corpus = self.scenario()
        result = self.optional_fts(corpus, search_request(query='train OR nonexistent',
                                  sources=['S_PERSONAL'], mode='fts5', limit=16, offset=0))
        if result is not None:
            self.assertEqual(result['outcome'], 'UNKNOWN_NO_MATCH')
            self.assertEqual(result['unit_matches'], [])
            self.assertEqual(result['whole_source_matches'], [])

    def test_fts_token_bound_does_not_silently_truncate(self):
        corpus = self.new(*synthetic('a'))
        reply = self.reply(corpus, search_request('query', mode='fts5',
                           query=' '.join(['a'] * 33)))
        self.assertEqual(reply['status'], 'REFUSED')
        self.assertIn(reply['result']['reason'],
                      ('REFUSED_FTS_TOKEN_BOUND', 'REFUSED_FTS_UNAVAILABLE'))
        accepted = self.optional_fts(corpus, search_request('query', mode='fts5',
                                     query=' '.join(['a'] * 32)))
        if accepted is not None:
            self.assertEqual(accepted['root_units'], ['U_SYNTH'])

    def test_fts_index_run_bound_preserves_literal_lane(self):
        corpus = self.new(*synthetic('x' * 32769 + ' needle'))
        literal = self.ok(corpus, search_request('query', query='needle'))
        self.assertEqual(literal['root_units'], ['U_SYNTH'])
        refused = self.reply(corpus, search_request('query', query='needle', mode='fts5'))
        self.assertEqual(refused['status'], 'REFUSED')
        self.assertIn(refused['result']['reason'],
                      ('REFUSED_FTS_TOKEN_BOUND', 'REFUSED_FTS_UNAVAILABLE'))


def difference_enclosure(left, right, left_id, right_id):
    prefix = 0
    for index in range(min(len(left), len(right))):
        if left[index] != right[index]:
            break
        prefix = index + 1
    old_end, new_end = len(left), len(right)
    for _ in range(min(len(left), len(right)) - prefix):
        if left[old_end - 1] != right[new_end - 1]:
            break
        old_end -= 1
        new_end -= 1
    return {'from': left_id, 'to': right_id, 'bytes_equal': left == right,
            'from_span': [prefix, old_end], 'to_span': [prefix, new_end],
            'scope': 'ONE_CONSERVATIVE_REPLACEMENT_ENCLOSURE'}


class TraceTests(ResponseCase):
    def trace_pair(self, corpus, selected, other, bindings):
        result = self.ok(corpus, request('trace', source=selected))
        source_meta, _ = self.metadata(corpus)
        raw_sources, _, _ = self.inputs[id(corpus)]
        self.assertEqual(result, {
            'source': selected,
            'family': source_meta[selected]['attributes']['family_id'],
            'governing_version': 'UNKNOWN',
            'version_labels': 'DECLARED_NOT_AUTHENTICATED',
            'versions': [source_meta[s] for s in sorted([selected, other])],
            'comparisons': [difference_enclosure(raw_sources[selected],
                            raw_sources[other], selected, other)],
            'unit_bindings': bindings})
        return result

    def test_unchanged_core_retains_changed_declared_definition_binding(self):
        corpus = self.scenario()
        result = self.trace_pair(corpus, 'S_CTRL_NEW', 'S_CTRL_OLD', [{
            'left': 'U_CTRL_NEW', 'right': 'U_CTRL_OLD',
            'quote_unchanged': True, 'dependency_ids_changed': True,
            'dependency_source_keys_changed': True}])
        self.assertIs(result['comparisons'][0]['bytes_equal'], True)
        self.assertEqual(result['governing_version'], 'UNKNOWN')

    def test_changed_external_definition_has_exact_byte_difference_enclosure(self):
        corpus = self.scenario()
        result = self.trace_pair(corpus, 'S_DEF_NEW', 'S_DEF_OLD', [])
        comparison = result['comparisons'][0]
        self.assertIs(comparison['bytes_equal'], False)
        sources, _, _ = self.inputs[id(corpus)]
        begin, end = comparison['from_span']
        prior_begin, prior_end = comparison['to_span']
        rebuilt = (sources['S_DEF_NEW'][:begin]
                   + sources['S_DEF_OLD'][prior_begin:prior_end]
                   + sources['S_DEF_NEW'][end:])
        self.assertEqual(rebuilt, sources['S_DEF_OLD'])

    def test_trace_does_not_select_revoked_or_prior_permission(self):
        corpus = self.scenario()
        result = self.trace_pair(corpus, 'S_APPROVAL_NEW', 'S_APPROVAL_OLD', [])
        self.assertEqual(result['governing_version'], 'UNKNOWN')
        self.assertEqual(result['version_labels'], 'DECLARED_NOT_AUTHENTICATED')

    def test_trace_without_family_preserves_self_only(self):
        corpus = self.new(*synthetic('needle'))
        sources, _ = self.metadata(corpus)
        result = self.ok(corpus, request('trace', source='S_SYNTH'))
        self.assertEqual(result, {'source': 'S_SYNTH', 'family': None,
                         'governing_version': 'UNKNOWN',
                         'version_labels': 'DECLARED_NOT_AUTHENTICATED',
                         'versions': [sources['S_SYNTH']], 'comparisons': [],
                         'unit_bindings': []})


class EqualityAndMetricsTests(ResponseCase):
    def test_same_action_schedule_is_byte_identical_between_fixture_routes(self):
        arms = [self.scenario('SC_MAIN', route)
                for route in ('fixture_utf8', 'fixture_raw_bytes')]
        schedule = [request('catalog'),
                    search_request('query', query='café', sources=['S_MULTI']),
                    request('page', source='S_MULTI', offset=0),
                    request('trace', source='S_CTRL_NEW'),
                    request('expand', units=['U_REVIEW_RULE']),
                    request('not_an_action')]
        for payload in schedule:
            replies = [self.reply(corpus, payload) for corpus in arms]
            self.assertEqual(replies[0], replies[1])
            self.assertEqual(canonical(replies[0]), canonical(replies[1]))

    def test_metrics_are_separate_fresh_dicts_without_result_identity_effect(self):
        arms = [self.new(*synthetic('needle')) for _ in range(2)]
        first = arms[0].metrics()
        self.assertIsInstance(first, dict)
        first['forged_metric'] = 'not internal state'
        second = arms[0].metrics()
        self.assertIsInstance(second, dict)
        self.assertNotIn('forged_metric', second)
        replies = [self.reply(corpus, request('catalog')) for corpus in arms]
        self.assertEqual(replies[0], replies[1])
        self.assertNotIn('metrics', replies[0])


def small_declared_corpus(records):
    """Build explicit public development fixtures, separate from the raw oracle."""
    if len(records) > 16:
        raise ValueError('Development fixture source bound exceeded')
    sources = {}
    source_records = []
    units = []
    for source_id, unit_ids, raw, family in records:
        sources[source_id] = raw
        source_records.append({'id': source_id, 'revision': 'v1',
                               'encoding': 'utf-8', 'media_type': 'text/plain',
                               'bytes': len(raw), 'sha256': sha(raw),
                               'attributes': {'family_id': family}})
        for unit_id in unit_ids:
            units.append({'id': unit_id, 'source': source_id,
                          'span': [0, len(raw)], 'sha256': sha(raw),
                          'whole_unit': True, 'dependencies': [],
                          'annotations': {}})
    if len(units) > 16:
        raise ValueError('Development fixture unit bound exceeded')
    return sources, canonical({'schema': 'transport/retrieval-annotations/1',
                               'sources': source_records, 'units': units})


class PreExecutionRegressionTests(ResponseCase):
    def test_trace_binding_pairs_are_globally_sorted_by_left_then_right(self):
        records = [('S_MAIN', ['U_A', 'U_Z'], b'same quoted core', 'family'),
                   ('S_B', ['U_Y'], b'same quoted core', 'family'),
                   ('S_C', ['U_B'], b'same quoted core', 'family')]
        corpus = self.new(*small_declared_corpus(records))
        result = self.ok(corpus, request('trace', source='S_MAIN'))
        pairs = [('U_A', 'U_B'), ('U_A', 'U_Y'),
                 ('U_Z', 'U_B'), ('U_Z', 'U_Y')]
        self.assertEqual(result['unit_bindings'], [
            {'left': left, 'right': right, 'quote_unchanged': True,
             'dependency_ids_changed': False,
             'dependency_source_keys_changed': False}
            for left, right in pairs])
        self.assertEqual(result['governing_version'], 'UNKNOWN')

    def test_equal_fts_score_ties_use_source_before_unit_identity(self):
        records = [('S_A', ['U_Z'], b'shared identical token', 'family'),
                   ('S_B', ['U_A'], b'shared identical token', 'family')]
        corpus = self.new(*small_declared_corpus(records))
        result = self.reply(corpus, search_request(query='shared',
                            sources=['S_A', 'S_B'], mode='fts5', limit=16, offset=0))
        if result['status'] == 'REFUSED':
            self.assertIn(result['result']['reason'],
                          ('REFUSED_FTS_UNAVAILABLE', 'REFUSED_FTS_WORK_BOUND'))
            return
        matches = result['result']['unit_matches']
        self.assertEqual([(u['source'], u['id']) for u in matches],
                         [('S_A', 'U_Z'), ('S_B', 'U_A')])
        self.assertEqual(result['result']['ranking'], 'SQLITE_FTS5_BM25')


if __name__ == '__main__':
    unittest.main(verbosity=2)
