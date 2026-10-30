"""Nested integration controls; trusted codec mocked, native dispatch forbidden."""
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
from sentinel_v1 import collection, collection_document as subject, document_analysis, common
from sentinel_v1.common import SentinelError, canonical, digest, identity, parse


def registry_root(registry):
    return digest(canonical({key: identity(raw) for key, raw in registry.items()}))


class CollectionDocumentControls(unittest.TestCase):
    def setUp(self):
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('native/model forbidden')).start()
        patch.object(os, 'execv', side_effect=AssertionError('exec forbidden')).start()
        self.temp = tempfile.TemporaryDirectory(prefix='collection-document-test-')
        self.addCleanup(self.temp.cleanup); self.root = Path(self.temp.name)
        self.source = self.root / 'source'; self.raw = b'Alpha.\n\nCONTEXT GAP\n\nOmega.'
        self.outer_share = self.root / 'outer-share'
        self.outer_share.write_bytes(subject.document.share_for('synthetic_formula', digest(b'outer'), 'meaning.zip', None))
        self.original_outer_share = self.outer_share.read_bytes()
        self.source.write_bytes(self.raw); self.package = digest(b'mocked base package')
        self.runtime = {'format': 'mocked runtime', 'native_sha256': digest(b'operator fixed native')}
        self.decoder = digest(subject.document.canonical(self.runtime))
        self.adapter_identity = {'schema': 'MOCKED_FIXED_ADAPTER_IDENTITY'}
        self.body = {'source': identity(self.raw), 'reading': None, 'entries': {}}
        self.revision = {'schema': 'sentinel/source-revision/1', 'id': 'R1',
            'source_sha256': digest(self.raw), 'source_bytes': len(self.raw), 'previous_sha256': None}
        self.binding = {'source': {**identity(self.raw), 'package_id': self.package},
            'representation': {'kind': 'ORIGINAL', **identity(self.raw), 'record_sha256': None},
            'revision': {'id': 'R1', 'artifact_sha256': digest(canonical(self.revision)), 'previous_sha256': None}}
        last = self.raw.index(b'Omega.')
        self.sections = [{'id': 'A', 'label': 'first', 'start': 0, 'end': 6, 'dependencies': ['B']},
            {'id': 'B', 'label': 'last', 'start': last, 'end': len(self.raw), 'dependencies': []}]
        self.calls, self.reservations, self.serial = [], [], 0
        self.payloads = self.initial_payloads(); self.pack()
        patch.object(subject.document, 'native_path', return_value=Path('/operator/native')).start()
        patch.object(subject.document, 'runtime', return_value=self.runtime).start()
        self.real_adapter_runtime = subject.adapter_runtime
        self.identity_mock = patch.object(subject, 'adapter_runtime', return_value=self.adapter_identity).start()
        patch.object(subject.document, 'scratch_root', return_value=self.root).start()
        patch.object(subject.document, 'reserve', side_effect=lambda _root, total: self.reservations.append(total)).start()
        patch.object(subject, 'decode_plan', side_effect=self.plan).start()
        patch.object(subject.document, 'validated', self.validated).start()

    def initial_payloads(self):
        planned = document_analysis.plan_document_jobs(self.raw, canonical(self.binding))
        readable = canonical({'schema': 'sentinel/collection-readable/1', 'text': 'Proposed explanation only.',
            'status': 'PROPOSED_UNREVIEWED', 'execution_authority': 'NONE'})
        rows = [('ARCHIVE', 'BASE_ARCHIVE', b'unchanged mocked archive bytes'),
            ('SHARE', 'BASE_SHARE', b'unchanged mocked share bytes'),
            ('INDEX', 'DOCUMENT_INDEX', planned['index']), ('DICT', 'DICTIONARY', readable),
            ('GUIDE', 'INSTRUCTIONS', readable), ('REV', 'REVISION',
             canonical({'schema': 'sentinel/collection-revisions/1', 'records': [self.revision]}))]
        rows.extend(('BLOCK' + str(n), 'CENSUS_BLOCK', raw)
                    for n, raw in enumerate(planned['blocks'].values()))
        return rows

    def pack(self):
        self.serial += 1; entries = []
        for name, kind, raw in self.payloads:
            path = self.root / (name + str(self.serial)); path.write_bytes(raw)
            entries.append({'id': name, 'kind': kind, 'path': path, 'pin': identity(raw)})
        self.collection_path = self.root / ('collection' + str(self.serial))
        pin = collection.pack_file(entries, self.binding, self.decoder, self.collection_path)
        data = {kind: raw for _name, kind, raw in self.payloads}
        self.held = {'collection_sha256': pin['sha256'], 'base_archive': identity(data['BASE_ARCHIVE']),
            'base_share': identity(data['BASE_SHARE']), 'decoder_root_sha256': self.decoder,
            'outer_share': identity(self.original_outer_share)}
        self.held['adapter_descriptor_sha256'] = digest(canonical(self.adapter_identity))

    def plan(self, archive, _share, _native):
        return (100, self.held['collection_sha256'], digest(b'outer')) if archive == 'outer' else (
            200, self.body['source']['sha256'], self.package)

    @contextmanager
    def validated(self, archive, _share, _native):
        self.calls.append(str(archive))
        if archive == 'outer':
            yield self.collection_path, {'source': identity(self.collection_path.read_bytes())}, digest(b'outer'), []
        else:
            yield self.source, self.body, self.package, self.sections

    def open(self, held=None):
        return subject.verified_document('outer', self.outer_share, self.held if held is None else held, '/native')

    def replace_payload(self, kind, change):
        self.payloads = [(name, entry_kind, change(raw) if entry_kind == kind else raw)
                         for name, entry_kind, raw in self.payloads]
        self.pack()

    def node(self, selector, name='L1', dependencies=()):
        return {'schema': 'sentinel/evidence-locator/1', 'id': name, **deepcopy(self.binding),
                'selector': selector, 'dependencies': list(dependencies)}

    def select(self, context, node, extra=()):
        raw = canonical(node); registry = {digest(raw): raw}
        registry.update({digest(canonical(row)): canonical(row) for row in extra})
        return subject.selected_source(context, raw, digest(raw), registry, registry_root(registry))

    def test_full_nested_validation_and_operational_report(self):
        with self.open() as context:
            report = context.report()
            self.assertEqual(report['binding'], self.binding)
            self.assertEqual(report['paragraph_count'], 3)
            self.assertEqual(report['execution_authority'], 'NONE')
            self.assertEqual(report['qualification'], 'NOT_QUALIFIED')
            self.assertEqual(report['semantic_completeness'], 'UNPROVEN')
            self.assertEqual(report['readable']['INSTRUCTIONS']['status'], 'PROPOSED_UNREVIEWED')
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(self.reservations), 2)
        self.assertEqual(self.reservations[1], self.reservations[0] + 200)
        with self.assertRaisesRegex(SentinelError, 'closed'): context.report()

    def test_separate_ranges_keep_gap_and_original_coordinates(self):
        last = self.raw.index(b'Omega.')
        other = self.node({'kind': 'SOURCE_BYTES', 'start': last, 'end': len(self.raw),
                           'quote_sha256': digest(b'Omega.')}, 'L2')
        first = self.node({'kind': 'SOURCE_BYTES', 'start': 0, 'end': 6,
                          'quote_sha256': digest(b'Alpha.')}, dependencies=[digest(canonical(other))])
        with self.open() as context:
            result = self.select(context, first, [other])
        self.assertEqual([p['data'] for p in result['parts']], [b'Alpha.', b'Omega.'])
        self.assertEqual(result['gaps'], [[6, last]])
        self.assertEqual(result['coordinate_kind'], 'SOURCE_BYTE')
        self.assertEqual(result['execution_authority'], 'NONE')
        with self.assertRaisesRegex(SentinelError, 'live'): self.select(context, first, [other])

    def test_exact_section_reference_and_dependency_parts(self):
        with self.open() as context:
            result = self.select(context, self.node({'kind': 'SECTION', 'section_id': 'A'}))
        self.assertEqual([p['data'] for p in result['parts']], [b'Alpha.', b'Omega.'])
        self.assertEqual(result['section_references'][0]['section_id'], 'A')

    def test_held_decoder_and_source_mismatch_before_recovery(self):
        for key in ('decoder_root_sha256', 'collection_sha256'):
            held = deepcopy(self.held); held[key] = digest(b'wrong')
            if key == 'collection_sha256':
                with patch.object(subject, 'decode_plan', return_value=(100, digest(b'actual outer'), digest(b'outer'))):
                    with self.assertRaises(SentinelError):
                        with self.open(held): self.fail('wrong held source accepted')
            else:
                with self.assertRaises(SentinelError):
                    with self.open(held): self.fail('wrong runtime accepted')
        self.assertEqual(self.calls, [])

    def test_swapped_base_share_pin_stops_before_inner_decoder(self):
        held = deepcopy(self.held); held['base_archive'], held['base_share'] = held['base_share'], held['base_archive']
        with self.assertRaisesRegex(SentinelError, 'held inner'):
            with self.open(held): self.fail('swapped package pair accepted')
        self.assertEqual(self.calls, ['outer'])

    def test_outer_and_inner_preflight_drift_fail(self):
        with patch.object(subject, 'decode_plan', side_effect=[(100, self.held['collection_sha256'], digest(b'wrong outer'))]):
            with self.assertRaisesRegex(SentinelError, 'outer package changed'):
                with self.open(): self.fail('outer drift')
        self.calls.clear()
        with patch.object(subject, 'decode_plan', side_effect=[self.plan('outer', None, None), (200, digest(self.raw), digest(b'wrong inner'))]):
            with self.assertRaisesRegex(SentinelError, 'inner package changed'):
                with self.open(): self.fail('inner drift')

    def test_aggregate_budget_refusal_before_each_extraction(self):
        with patch.object(subject, 'decode_plan', return_value=(subject.document.MAX_TEMP, self.held['collection_sha256'], digest(b'outer'))):
            with self.assertRaises(SentinelError):
                with self.open(): self.fail('outer aggregate exceeded')
        self.assertEqual(self.calls, [])
        with patch.object(subject, 'decode_plan', side_effect=[self.plan('outer', None, None), (subject.document.MAX_TEMP, digest(self.raw), self.package)]):
            with self.assertRaises(SentinelError):
                with self.open(): self.fail('inner aggregate exceeded')
        self.assertEqual(self.calls, ['outer'])

    def test_document_index_or_block_tamper_repin_still_refuses(self):
        original = deepcopy(self.payloads)
        for kind in ('DOCUMENT_INDEX', 'CENSUS_BLOCK'):
            self.payloads = deepcopy(original)
            def change(raw):
                value = parse(raw)
                if kind == 'DOCUMENT_INDEX': value['paragraph_count'] += 1
                else: value['context_sha256'] = digest(b'wrong context')
                return canonical(value)
            self.replace_payload(kind, change)
            with self.subTest(kind=kind), self.assertRaises(SentinelError):
                with self.open(): self.fail('internally changed metadata accepted')

    def test_revision_missing_predecessor_or_wrong_source_refuses(self):
        original = deepcopy(self.payloads)
        for field, value in (('source_sha256', digest(b'other source')), ('previous_sha256', digest(b'missing'))):
            self.payloads = deepcopy(original)
            def change(raw):
                envelope = parse(raw); envelope['records'][0][field] = value
                return canonical(envelope)
            self.replace_payload('REVISION', change)
            with self.subTest(field=field), self.assertRaises(SentinelError):
                with self.open(): self.fail('bad revision accepted')

    def test_readable_docs_cannot_promote_authority_or_status(self):
        original = deepcopy(self.payloads)
        for field, value in (('execution_authority', 'EXECUTE'), ('status', 'ACCEPTED'), ('text', '')):
            self.payloads = deepcopy(original)
            def change(raw):
                record = parse(raw); record[field] = value; return canonical(record)
            self.replace_payload('INSTRUCTIONS', change)
            with self.subTest(field=field), self.assertRaises(SentinelError):
                with self.open(): self.fail('instruction authority accepted')

    def test_representation_mismatch_and_bad_quote_refuse(self):
        with self.open() as context:
            node = self.node({'kind': 'SOURCE_BYTES', 'start': 0, 'end': 6, 'quote_sha256': digest(b'wrong')})
            with self.assertRaises(SentinelError): self.select(context, node)
            node = self.node({'kind': 'DERIVED_UTF8', 'start': 0, 'end': 6, 'quote_sha256': digest(b'Alpha.')})
            with self.assertRaises(SentinelError): self.select(context, node)

    def test_file_and_document_reading_changes_refuse(self):
        self.source.write_bytes(b'wrong recovered source')
        with self.assertRaises(SentinelError):
            with self.open(): self.fail('reading not bound to index')
        self.source.write_bytes(self.raw)
        raw = self.collection_path.read_bytes(); self.collection_path.write_bytes(raw[:-1] + b'!')
        with self.assertRaises(SentinelError):
            with self.open(): self.fail('collection file differs')

    def test_missing_document_block_refuses_after_repin(self):
        self.payloads = [row for row in self.payloads if row[1] != 'CENSUS_BLOCK']
        self.pack()
        with self.assertRaises(SentinelError):
            with self.open(): self.fail('missing document blocks accepted')

    def test_strict_held_shapes_and_integer_pins_refuse(self):
        for change in ('extra', 'bool', 'zero', 'sha'):
            held = deepcopy(self.held)
            if change == 'extra': held['unknown'] = True
            if change == 'bool': held['base_archive']['bytes'] = True
            if change == 'zero': held['base_share']['bytes'] = 0
            if change == 'sha': held['decoder_root_sha256'] = 'bad'
            with self.subTest(change=change), self.assertRaises(SentinelError):
                with self.open(held): self.fail('malformed held input accepted')
        self.assertEqual(self.calls, [])

    def configure_derived(self):
        self.raw = bytes.fromhex('41c3a90a0a42'); original = b'original binary PDF fixture'
        self.source.write_bytes(original); (self.root / 'reading.txt').write_bytes(self.raw)
        record = {'schema': 'transport/reading-view/1', 'format': 'pdf',
            'tool_versions': {'fixture': 'MOCKED_NO_OCR'}, 'source_sha256': digest(original),
            'text_sha256': digest(self.raw), 'text_bytes': len(self.raw), 'segments': [
                {'id': 'p1', 'label': 'inert', 'kind': 'page', 'start': 0, 'end': len(self.raw),
                 'source_locator': {'page': 1}}], 'uncertainty': ['Visual fidelity UNPROVEN'],
            'coverage': {}, 'text_path': 'reading.txt'}
        encoded = canonical(record); (self.root / 'reading.json').write_bytes(encoded)
        self.body = {'source': identity(original), 'reading': identity(self.raw),
                     'entries': {'reading.json': identity(encoded)}}
        self.revision['source_sha256'] = digest(original); self.revision['source_bytes'] = len(original)
        self.binding['source'] = {**identity(original), 'package_id': self.package}
        self.binding['revision']['artifact_sha256'] = digest(canonical(self.revision))
        self.binding['representation'] = {'kind': 'DERIVED_UTF8', **identity(self.raw),
                                         'record_sha256': digest(encoded)}
        self.payloads = self.initial_payloads(); self.pack()

    def test_derived_utf8_coordinates_and_utf8_split_refusal(self):
        self.configure_derived()
        selector = {'kind': 'DERIVED_UTF8', 'start': 0, 'end': 3, 'quote_sha256': digest(self.raw[:3])}
        with self.open() as context:
            result = self.select(context, self.node(selector))
            self.assertEqual(result['coordinate_kind'], 'DERIVED_UTF8_BYTE')
            self.assertEqual(result['parts'][0]['data'], self.raw[:3])
            self.assertEqual(result['source'], self.binding['source'])
            self.assertEqual(result['OCR_accuracy'], 'UNPROVEN')
            selector.update(end=2, quote_sha256=digest(self.raw[:2]))
            with self.assertRaises((SentinelError, UnicodeError)):
                self.select(context, self.node(selector))

    def test_derived_reading_metadata_cannot_detach_from_base(self):
        self.configure_derived()
        (self.root / 'reading.json').write_bytes(canonical({'schema': 'tampered'}))
        with self.assertRaises(SentinelError):
            with self.open(): self.fail('detached reading metadata accepted')

    def test_complete_outer_share_suffix_or_same_book_wrong_pair_refuse_before_preflight(self):
        subject.document.share_checked(self.original_outer_share, 'synthetic_formula', digest(b'outer'))
        changed = self.original_outer_share + b'\nUNDECLAREDTRAILINGINSTRUCTION'
        subject.document.share_checked(changed, 'synthetic_formula', digest(b'outer'))
        alternatives = (changed, subject.document.share_for('synthetic_formula', digest(b'outer'), 'other.zip', None))
        for raw in alternatives:
            self.outer_share.write_bytes(raw)
            with patch.object(subject, 'decode_plan', side_effect=AssertionError('preflight must not run')):
                with self.subTest(raw=raw), self.assertRaisesRegex(SentinelError, 'complete share differs'):
                    with self.open(): self.fail('non-admitted complete share accepted')
        self.assertEqual(self.calls, [])
        self.outer_share.write_bytes(self.original_outer_share)
        with self.open() as context: self.assertEqual(context.report()['execution_authority'], 'NONE')

    def test_outer_share_pin_missing_bool_or_candidate_changed_refuses(self):
        for variant in ('missing', 'bool'):
            held = deepcopy(self.held)
            if variant == 'missing': del held['outer_share']
            else: held['outer_share']['bytes'] = True
            with self.subTest(variant=variant), self.assertRaises(SentinelError):
                with self.open(held): self.fail('bad share pin admitted')
        self.assertEqual(self.calls, [])
        with self.assertRaisesRegex(SentinelError, 'complete share differs'):
            with self.open(): self.outer_share.write_bytes(self.original_outer_share + b'changed during use')

    def test_wrong_adapter_identity_before_decode_and_drift_before_exposure(self):
        held = deepcopy(self.held); held['adapter_descriptor_sha256'] = digest(b'wrong full adapter')
        with self.assertRaisesRegex(SentinelError, 'held adapter'):
            with self.open(held): self.fail('wrong adapter accepted')
        self.assertEqual(self.calls, [])
        self.identity_mock.side_effect = [self.adapter_identity, {'schema': 'CHANGED'}]
        with self.assertRaisesRegex(SentinelError, 'held adapter'):
            with self.open(): self.fail('changed adapter exposed')

    def test_changed_adapter_at_context_exit_refuses(self):
        self.identity_mock.side_effect = [self.adapter_identity, self.adapter_identity, {'schema': 'CHANGED'}]
        with self.assertRaisesRegex(SentinelError, 'held adapter'):
            with self.open() as context: self.assertEqual(context.report()['execution_authority'], 'NONE')

    def test_fixed_source_epoch_mutation_and_missing_source_refuse(self):
        original = subject.adapter_sources()
        self.assertEqual(set(original), set(subject.ADAPTER_SOURCES))
        for name in subject.ADAPTER_SOURCES:
            changed = deepcopy(original); changed[name]['sha256'] = digest(b'changed dependency')
            with patch.object(subject, 'adapter_sources', return_value=changed):
                with self.subTest(name=name), self.assertRaisesRegex(SentinelError, 'since import'):
                    self.real_adapter_runtime('/unused')

    def test_missing_fixed_dependency_and_changed_native_identity_refuse(self):
        original = subject.document.file_digest
        def missing(path, cap):
            if Path(path).name == 'common.py': raise FileNotFoundError('injected missing fixed source')
            return original(path, cap)
        with patch.object(subject.document, 'file_digest', side_effect=missing):
            with self.assertRaises(FileNotFoundError): self.real_adapter_runtime('/unused')
        native = self.root / 'identity-only-native'; native.write_bytes(b'fixed identity fixture, never executed')
        with patch.object(subject, 'loaded_checked'):
            before = self.real_adapter_runtime(native)
            native.write_bytes(b'changed identity fixture, never executed')
            after = self.real_adapter_runtime(native)
        self.assertNotEqual(digest(canonical(before)), digest(canonical(after)))
        with patch.object(subject, 'adapter_runtime', return_value=after):
            with self.assertRaisesRegex(SentinelError, 'held adapter'):
                subject.adapter_checked(native, digest(canonical(before)))

    def test_live_original_and_derived_whole_identity_must_remain_bound(self):
        with self.open() as context:
            self.source.write_bytes(b'X' * len(self.raw))
            with self.assertRaisesRegex(SentinelError, 'complete original'):
                self.select(context, self.node({'kind': 'SECTION', 'section_id': 'A'}))
        self.source.write_bytes(self.raw); self.configure_derived()
        with self.open() as context:
            (self.root / 'reading.txt').write_bytes(self.raw[:-1] + b'Z')
            node = self.node({'kind': 'PAGE_TEXT', 'page': 1, 'segment_id': 'p1',
                'start': 0, 'end': 3, 'quote_sha256': digest(self.raw[:3])})
            with self.assertRaisesRegex(SentinelError, 'complete bound representation'):
                self.select(context, node)

    def test_full_identity_checked_again_after_selection(self):
        original = subject.locators._resolve_bound
        def changed(*args):
            result = original(*args); self.source.write_bytes(b'X' * len(self.raw)); return result
        with self.open() as context, patch.object(subject.locators, '_resolve_bound', side_effect=changed):
            with self.assertRaisesRegex(SentinelError, 'complete original'):
                self.select(context, self.node({'kind': 'SECTION', 'section_id': 'A'}))

    def test_share_drift_after_plan_cannot_enter_corresponding_decoder(self):
        original = self.plan
        def outer_drift(archive, share, native):
            result = original(archive, share, native)
            if archive == 'outer': Path(share).write_bytes(self.original_outer_share + b'changed')
            return result
        with patch.object(subject, 'decode_plan', side_effect=outer_drift), self.assertRaises(SentinelError):
            with self.open(): self.fail('outer share drift decoded')
        self.assertEqual(self.calls, []); self.outer_share.write_bytes(self.original_outer_share)
        def inner_drift(archive, share, native):
            result = original(archive, share, native)
            if archive != 'outer': Path(share).write_bytes(b'changed inner')
            return result
        with patch.object(subject, 'decode_plan', side_effect=inner_drift), self.assertRaises(SentinelError):
            with self.open(): self.fail('inner share drift decoded')
        self.assertEqual(self.calls, ['outer'])

    def test_loaded_common_function_literal_alias_and_missing_new_binding(self):
        path = ROOT / 'tools/sentinel_v1/common.py'; raw = path.read_bytes()
        subject.module_checked(common, raw, path)
        appended = raw + b'\nSOURCE_CHANGED_AFTER_DEPENDENCY_IMPORT = True\n'
        with self.assertRaisesRegex(SentinelError, 'binding missing'):
            subject.module_checked(common, appended, path)
        with patch.object(common, 'CLAIMS', 63), self.assertRaisesRegex(SentinelError, 'literal differs'):
            subject.module_checked(common, raw, path)
        with patch.object(common, 'json', object()), self.assertRaisesRegex(SentinelError, 'alias differs'):
            subject.module_checked(common, raw, path)
        with patch.object(common, 'digest', lambda value: 'changed'), self.assertRaisesRegex(SentinelError, 'function differs'):
            subject.module_checked(common, raw, path)

    def test_default_only_source_and_live_default_changes_refuse(self):
        path = ROOT / 'tools/sentinel_v1/common.py'; raw = path.read_bytes()
        changed = raw.replace(b'def label(value, cap=64):', b'def label(value, cap=63):')
        self.assertNotEqual(changed, raw)
        with self.assertRaisesRegex(SentinelError, 'default differs'):
            subject.module_checked(common, changed, path)
        with patch.object(common.label, '__defaults__', (63,)):
            with self.assertRaisesRegex(SentinelError, 'default differs'):
                subject.module_checked(common, raw, path)

    def test_keyword_defaults_and_unsupported_expressions_fail_closed(self):
        import ast
        def sample(*, limit=64):
            return limit
        node = ast.parse('def sample(*, limit=64): pass').body[0]
        subject.defaults_checked(sample, node, {})
        with patch.object(sample, '__kwdefaults__', {'limit': 63}):
            with self.assertRaisesRegex(SentinelError, 'keyword default differs'):
                subject.defaults_checked(sample, node, {})
        unsupported = ast.parse('def label(value, cap=untrusted()): pass').body[0]
        with self.assertRaisesRegex(SentinelError, 'unsupported adapter default'):
            subject.defaults_checked(common.label, unsupported, {})


if __name__ == '__main__':
    unittest.main()
