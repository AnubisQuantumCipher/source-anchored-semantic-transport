"""Literal locator controls with package validation mocked; native/Popen forbidden."""
from contextlib import contextmanager
from copy import deepcopy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from sentinel_v1 import locators as subject
from sentinel_v1.common import SentinelError, canonical, digest, identity


def registry_root(registry):
    return digest(canonical({key: identity(raw) for key, raw in registry.items()}))


def section(name, start, end, dependencies=()):
    return {'id': name, 'label': 'inert annotation', 'start': start, 'end': end,
            'dependencies': list(dependencies), 'sha256': digest(b'declared')}


class LocatorControls(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ.get('SENTINEL_LOCATOR_TEST_SCRATCH', tempfile.gettempdir()))
        self.temp = tempfile.TemporaryDirectory(prefix='locator-control-', dir=base)
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.path = self.folder / 'source'
        self.package_id = digest(b'synthetic package, validated mocked')
        self.sections = [section('A', 0, 1, ['B']), section('B', 3, 4)]
        self.calls = []
        self.resize(b'A--B')
        self.addCleanup(patch.stopall)
        patch.object(subject.document, 'validated', self.validated).start()
        patch.object(subprocess, 'Popen', side_effect=AssertionError('native/Popen forbidden')).start()

    def resize(self, data):
        self.path.write_bytes(data)
        self.body = {'source': identity(data), 'reading': None, 'entries': {}}
        self.revision = {'schema': 'sentinel/source-revision/1', 'id': 'R1',
            'source_sha256': digest(data), 'source_bytes': len(data), 'previous_sha256': None}
        self.revisions = {digest(canonical(self.revision)): canonical(self.revision)}

    @contextmanager
    def validated(self, archive, share, native):
        self.calls.append((archive, share, native))
        yield self.path, self.body, self.package_id, self.sections

    def original(self):
        return {'kind': 'ORIGINAL', **self.body['source'], 'record_sha256': None}

    def derived(self):
        text = bytes.fromhex('41c3a90a420a')
        self.reading_text = text
        self.record = {'schema': 'transport/reading-view/1', 'format': 'pdf',
            'tool_versions': {'fixture': 'MOCKED_NO_ACTUAL_PDF'},
            'source_sha256': self.body['source']['sha256'], 'text_sha256': digest(text),
            'text_bytes': len(text), 'segments': [
                {'id': 'p1', 'label': 'inert', 'kind': 'page', 'start': 0, 'end': 4,
                 'source_locator': {'page': 1}},
                {'id': 'p2', 'label': 'inert', 'kind': 'page', 'start': 4, 'end': 6,
                 'source_locator': {'page': 2}}],
            'uncertainty': ['Visual fidelity UNPROVEN'], 'coverage': {}, 'text_path': 'reading.txt'}
        raw = canonical(self.record)
        (self.folder / 'reading.json').write_bytes(raw)
        (self.folder / 'reading.txt').write_bytes(text)
        self.body['reading'] = identity(text)
        self.body['entries']['reading.json'] = identity(raw)
        return {'kind': 'DERIVED_UTF8', **identity(text), 'record_sha256': digest(raw)}

    def node(self, selector=None, name='L1', dependencies=(), representation=None):
        key = digest(canonical(self.revision))
        return {'schema': 'sentinel/evidence-locator/1', 'id': name,
            'source': {**self.body['source'], 'package_id': self.package_id},
            'representation': self.original() if representation is None else representation,
            'selector': selector or {'kind': 'SOURCE_BYTES', 'start': 0, 'end': 1,
                                      'quote_sha256': digest(b'A')},
            'dependencies': list(dependencies),
            'revision': {'id': self.revision['id'], 'artifact_sha256': key,
                         'previous_sha256': self.revision['previous_sha256']}}

    def call(self, node=None, extra=(), revisions=None, held_locators=None, held_revisions=None,
             raw=None, supplied_registry=None, expected=None):
        node = self.node() if node is None else node
        raw = canonical(node) if raw is None else raw
        selected = digest(raw) if expected is None else expected
        registry = {digest(raw): raw}
        registry.update({digest(canonical(v)): canonical(v) for v in extra})
        if supplied_registry is not None:
            registry = supplied_registry
        revs = self.revisions if revisions is None else revisions
        return subject.resolve_locator('archive', 'share', raw, selected, registry,
            registry_root(registry) if held_locators is None else held_locators,
            revs, registry_root(revs) if held_revisions is None else held_revisions, 'native')

    def test_literal_source_and_bound_receipt(self):
        value = self.call()
        self.assertEqual(value['parts'], [{'span': [0, 1], 'data': b'A', 'sha256': digest(b'A')}])
        self.assertEqual(value['coordinate_kind'], 'SOURCE_BYTE')
        self.assertEqual(value['source'], self.node()['source'])
        self.assertEqual(value['revision'], self.node()['revision'])
        self.assertEqual(value['qualification'], 'NOT_QUALIFIED')
        self.assertEqual(value['execution_authority'], 'NONE')
        self.assertEqual(value['semantic_completeness'], 'UNPROVEN')
        self.assertEqual(self.calls, [('archive', 'share', 'native')])

    def test_original_binary_mid_utf8_is_exact_byte(self):
        self.resize(bytes.fromhex('41c3a90a420a'))
        node = self.node({'kind': 'SOURCE_BYTES', 'start': 1, 'end': 2,
                          'quote_sha256': digest(bytes.fromhex('c3'))})
        self.assertEqual(self.call(node)['parts'][0]['data'], bytes.fromhex('c3'))

    def test_derived_utf8_literal_and_boundary_refusal(self):
        rep = self.derived()
        node = self.node({'kind': 'DERIVED_UTF8', 'start': 1, 'end': 3,
                          'quote_sha256': digest(bytes.fromhex('c3a9'))}, representation=rep)
        result = self.call(node)
        self.assertEqual(result['parts'][0]['data'], bytes.fromhex('c3a9'))
        self.assertEqual(result['coordinate_kind'], 'DERIVED_UTF8_BYTE')
        node['selector'].update(end=2, quote_sha256=digest(bytes.fromhex('c3')))
        with self.assertRaises(SentinelError):
            self.call(node)

    def test_declared_page_identity_and_extent(self):
        node = self.node({'kind': 'PAGE_TEXT', 'segment_id': 'p1', 'page': 1,
                          'start': 0, 'end': 1, 'quote_sha256': digest(b'A')},
                         representation=self.derived())
        result = self.call(node)
        self.assertEqual(result['parts'][0]['data'], b'A')
        self.assertIn('NOT_VISUALLY_ADJUDICATED', result['page_mapping'])
        for changes in ({'page': 2}, {'segment_id': 'missing'}, {'end': 5}, {'page': True}):
            bad = deepcopy(node); bad['selector'].update(changes)
            with self.assertRaises(SentinelError):
                self.call(bad)

    def test_disjoint_section_retains_gap_legacy_unchanged(self):
        value = self.call(self.node({'kind': 'SECTION', 'section_id': 'A'}))
        self.assertEqual([p['span'] for p in value['parts']], [[0, 1], [3, 4]])
        self.assertEqual([p['data'] for p in value['parts']], [b'A', b'B'])
        self.assertEqual(value['gaps'], [[1, 3]])
        self.assertEqual(subject.document.read_section('archive', 'share', 'A', 'native'), b'AB')

    def test_section_missing_cycle_unknown_and_representation_refuse(self):
        for sections in ([section('A', 0, 1, ['MISSING'])],
                         [section('A', 0, 1, ['B']), section('B', 3, 4, ['A'])]):
            self.sections = sections
            with self.assertRaises(SentinelError):
                self.call(self.node({'kind': 'SECTION', 'section_id': 'A'}))
        self.sections = [section('A', 0, 1)]
        with self.assertRaises(SentinelError):
            self.call(self.node({'kind': 'SECTION', 'section_id': 'UNKNOWN'}))
        with self.assertRaises(SentinelError):
            self.call(self.node({'kind': 'SECTION', 'section_id': 'A'}, representation=self.derived()))

    def test_source_package_representation_and_quote_mutations(self):
        original = self.node()
        for path, value in ((('source', 'sha256'), digest(b'wrong')), (('source', 'package_id'), digest(b'other')),
                            (('source', 'bytes'), 5), (('representation', 'sha256'), digest(b'other')),
                            (('selector', 'quote_sha256'), digest(b'B'))):
            bad = deepcopy(original); bad[path[0]][path[1]] = value
            with self.assertRaises(SentinelError):
                self.call(bad)

    def test_integer_and_nonempty_bounds(self):
        for start, end in ((True, 1), (0, True), (-1, 1), (3, 1), (0, 5), (1, 1)):
            node = self.node(); node['selector'].update(start=start, end=end)
            with self.assertRaises(SentinelError):
                self.call(node)

    def test_closed_json_unknown_fields_duplicates_and_noncanonical(self):
        original = self.node()
        for path in ('root', 'selector', 'source', 'revision', 'representation'):
            node = deepcopy(original)
            target = node if path == 'root' else node[path]
            target['trusted'] = True
            with self.assertRaises(SentinelError):
                self.call(node)
        raw = canonical(original)
        for bad in (raw + b'\n', raw[:-1] + b',"id":"duplicate"}', b'{"float":1.5}'):
            with self.assertRaises(SentinelError):
                self.call(raw=bad)

    def test_overcap_root_refuses_before_digest_or_validation(self):
        with patch.object(subject, 'digest', side_effect=AssertionError('overcap root hash')), \
             patch.object(subject.document, 'validated', side_effect=AssertionError('overcap validation')):
            with self.assertRaisesRegex(SentinelError, 'locator byte bound'):
                subject.resolve_locator('a', 's', b' ' * 32769, '0' * 64,
                                        None, '0' * 64, None, '0' * 64)

    def test_wrong_missing_registry_and_expected_pins(self):
        for kwargs in ({'held_locators': digest(b'wrong')}, {'held_revisions': digest(b'wrong')},
                       {'expected': digest(b'wrong')}, {'supplied_registry': {}}, {'revisions': {}},
                       {'revisions': {'bad': b'raw'}}, {'revisions': {digest(b'x'): bytearray(b'x')}}):
            with self.assertRaises(SentinelError):
                self.call(**kwargs)
        with self.assertRaises(SentinelError):
            subject.resolve_locator('a', 's', b'{}', digest(b'{}'), None, digest(b'x'),
                                    self.revisions, registry_root(self.revisions))

    def test_same_space_dependency_closure_merges_only_actual_adjacency(self):
        other = self.node({'kind': 'SOURCE_BYTES', 'start': 3, 'end': 4,
                           'quote_sha256': digest(b'B')}, 'B')
        root = self.node(dependencies=[digest(canonical(other))])
        value = self.call(root, [other])
        self.assertEqual([p['data'] for p in value['parts']], [b'A', b'B'])
        self.assertEqual(value['gaps'], [[1, 3]])
        self.assertEqual(value['dependency_locator_sha256s'], [digest(canonical(other))])

    def test_dependency_missing_duplicate_unreachable_and_mixed_spaces(self):
        other = self.node(name='OTHER')
        with self.assertRaises(SentinelError):
            self.call(extra=[other])
        with self.assertRaises(SentinelError):
            self.call(self.node(dependencies=[digest(b'absent')]))
        key = digest(canonical(other))
        with self.assertRaises(SentinelError):
            self.call(self.node(dependencies=[key, key]), [other])
        variants = [deepcopy(other), deepcopy(other)]
        variants[0]['representation'] = self.derived()
        variants[1]['revision']['id'] = 'R0'
        for changed in variants:
            with self.assertRaises(SentinelError):
                self.call(self.node(dependencies=[digest(canonical(changed))]), [changed])

    def test_cycle_check_unit_without_claiming_hash_cycle_public_fixture(self):
        a, b = self.node(name='A'), self.node(name='B')
        a['dependencies'], b['dependencies'] = ['b' * 64], ['a' * 64]
        with self.assertRaisesRegex(SentinelError, 'cyclic'):
            subject.locator_records({'a' * 64: canonical(a), 'b' * 64: canonical(b)}, 'a' * 64)

    def test_registry_caller_mutation_cannot_change_snapshot(self):
        raw = canonical(self.node()); key = digest(raw)
        caller = {key: raw}; held = registry_root(caller)
        original = subject.registry_snapshot
        def mutate_original(registry, expected):
            snapshot = original(registry, expected)
            if registry is caller:
                caller.clear(); caller[digest(b'changed')] = b'changed'
            return snapshot
        with patch.object(subject, 'registry_snapshot', side_effect=mutate_original):
            result = self.call(raw=raw, supplied_registry=caller, held_locators=held)
        self.assertEqual(result['parts'][0]['data'], b'A')
        self.assertNotEqual(registry_root(caller), held)

    def test_historical_revision_different_source_is_lineage_only(self):
        old = {'schema': 'sentinel/source-revision/1', 'id': 'R0', 'source_sha256': digest(b'OLD'),
               'source_bytes': 3, 'previous_sha256': None}
        old_raw = canonical(old); self.revision['previous_sha256'] = digest(old_raw)
        current_raw = canonical(self.revision)
        self.revisions = {digest(old_raw): old_raw, digest(current_raw): current_raw}
        result = self.call()
        self.assertEqual(result['parts'][0]['data'], b'A')
        self.assertEqual(result['revision']['previous_sha256'], digest(old_raw))

    def test_revision_missing_predecessor_mismatch_and_extra(self):
        self.revision['previous_sha256'] = digest(b'absent')
        raw = canonical(self.revision); self.revisions = {digest(raw): raw}
        with self.assertRaises(SentinelError):
            self.call()
        self.resize(b'A--B')
        other = dict(self.revision, id='UNUSED'); raw = canonical(other)
        with self.assertRaises(SentinelError):
            self.call(revisions=dict(self.revisions, **{digest(raw): raw}))
        bad = self.node(); bad['revision']['id'] = 'wrong'
        with self.assertRaises(SentinelError):
            self.call(bad)

    def test_exact_eight_revision_boundary_and_ninth_refused(self):
        registry, previous = {}, None
        for ordinal in range(8):
            self.revision = dict(self.revision, id='R' + str(ordinal), previous_sha256=previous)
            raw = canonical(self.revision); previous = digest(raw); registry[previous] = raw
        self.revisions = registry
        self.assertEqual(self.call()['parts'][0]['data'], b'A')
        self.revision = dict(self.revision, id='R8', previous_sha256=previous)
        raw = canonical(self.revision); self.revisions[digest(raw)] = raw
        with self.assertRaises(SentinelError):
            self.call()

    def test_known_unsupported_and_malformed_mapping(self):
        selectors = [
            {'kind': 'PAGE_REGION', 'page': 1, 'coordinate_system': 'PIXELS_TOP_LEFT',
             'box': [0, 0, 10, 10], 'mapping_sha256': digest(b'unverified')},
            {'kind': 'TABLE', 'object_id': 'T1', 'mapping_sha256': digest(b'unverified')},
            {'kind': 'FIGURE', 'object_id': 'F1', 'mapping_sha256': digest(b'unverified')}]
        with patch.object(subject, 'selected_parts', side_effect=AssertionError('unsupported read')):
            for selector in selectors:
                result = self.call(self.node(selector))
                self.assertEqual(result['status'], 'UNSUPPORTED')
                self.assertEqual(result['parts'], [])
                self.assertEqual(result['selected_bytes'], 0)
        selectors[0]['mapping_sha256'] = None
        with self.assertRaises(SentinelError):
            self.call(self.node(selectors[0]))

    def test_unsupported_dependency_blocks_entire_intake(self):
        other = self.node({'kind': 'TABLE', 'object_id': 'T1',
                           'mapping_sha256': digest(b'map')}, 'TABLE')
        root = self.node(dependencies=[digest(canonical(other))])
        with patch.object(subject, 'selected_parts', side_effect=AssertionError('partial green')):
            value = self.call(root, [other])
        self.assertEqual((value['status'], value['parts']), ('UNSUPPORTED', []))

    def test_code_is_only_exact_bytes_and_unknown_tag_refuses(self):
        node = self.node({'kind': 'CODE_BYTES', 'start': 0, 'end': 1,
                          'quote_sha256': digest(b'A'), 'language': 'python'})
        self.assertEqual(self.call(node)['parts'][0]['data'], b'A')
        node['selector']['kind'] = 'AUTO_BEST_GUESS'
        with self.assertRaises(SentinelError):
            self.call(node)

    def test_exact_context_caps_and_aggregate_overflow_before_read(self):
        self.resize(b'x' * 65536)
        node = self.node({'kind': 'SOURCE_BYTES', 'start': 0, 'end': 65536,
                          'quote_sha256': digest(b'x' * 65536)})
        self.assertEqual(self.call(node)['selected_bytes'], 65536)
        self.resize(b'x' * 65537)
        other = self.node({'kind': 'SOURCE_BYTES', 'start': 32768, 'end': 65537,
                           'quote_sha256': digest(b'x' * 32769)}, 'B')
        root = self.node({'kind': 'SOURCE_BYTES', 'start': 0, 'end': 32768,
                          'quote_sha256': digest(b'x' * 32768)}, dependencies=[digest(canonical(other))])
        with patch.object(subject, 'selected_parts', side_effect=AssertionError('overflow read')):
            with self.assertRaises(SentinelError):
                self.call(root, [other])

    def test_exact64_disjoint_parts_and_section65_refuses(self):
        self.resize(b'x!' * 64)
        self.sections = [section('A' + str(i), i * 2, i * 2 + 1) for i in range(64)]
        self.sections[0]['dependencies'] = ['A' + str(i) for i in range(1, 64)]
        value = self.call(self.node({'kind': 'SECTION', 'section_id': 'A0'}))
        self.assertEqual(len(value['parts']), 64)
        self.assertEqual(value['parts'][-1]['span'], [126, 127])
        self.sections.append(section('OVER', 0, 1))
        with self.assertRaises(SentinelError):
            self.call(self.node({'kind': 'SECTION', 'section_id': 'A0'}))

    def test_reading_record_pin_text_binding_and_no_fallback(self):
        rep = self.derived()
        node = self.node({'kind': 'DERIVED_UTF8', 'start': 0, 'end': 1,
                          'quote_sha256': digest(b'A')}, representation=rep)
        (self.folder / 'reading.json').write_bytes(b'{}')
        with self.assertRaises(SentinelError):
            self.call(node)
        self.body['reading'] = None
        with self.assertRaises(SentinelError):
            self.call(node)

    def test_validation_refusal_no_selected_access_and_descriptor_change(self):
        @contextmanager
        def refuse(*_args):
            raise ValueError('package refused')
            yield
        with patch.object(subject.document, 'validated', refuse), \
             patch.object(subject, 'selected_parts', side_effect=AssertionError('unvalidated read')):
            with self.assertRaises(SentinelError):
                self.call()
        before = subject.file_identity
        count = {'n': 0}
        def changed(stream):
            value = before(stream); count['n'] += 1
            return value if count['n'] == 1 else value[:-1] + (value[-1] + 1,)
        with patch.object(subject, 'file_identity', side_effect=changed):
            with self.assertRaisesRegex(SentinelError, 'descriptor changed'):
                self.call()

    def test_symlink_size_change_and_final_quote_binding(self):
        actual = self.folder / 'actual'; self.path.rename(actual); self.path.symlink_to(actual)
        with self.assertRaises(SentinelError):
            self.call()
        self.path.unlink(); actual.rename(self.path)
        self.path.write_bytes(b'B--B')
        with self.assertRaisesRegex(SentinelError, 'quote mismatch'):
            self.call()
        self.path.write_bytes(b'A')
        with self.assertRaisesRegex(SentinelError, 'size changed'):
            self.call()

    def test_function_size_and_no_subprocess_in_locator_module(self):
        import ast
        path = ROOT / 'tools/sentinel_v1/locators.py'
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, node.name)
            if isinstance(node, ast.Import):
                self.assertFalse(any(alias.name == 'subprocess' for alias in node.names))


if __name__ == '__main__':
    unittest.main()
