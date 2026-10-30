"""Pure SNE1 controls. SAST/native calls are mocked; no model or archive execution."""
from contextlib import contextmanager
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'tests'))
from sentinel_v1 import bundle, cli, graph
from sentinel_v1.common import SentinelError, canonical, digest, identity
from sentinel_v1.bindings import registry_root
import test_sentinel_meaning as meaning_fixture


DECODER = digest(b'declared decoder fixture only')
SOURCE_EPOCH = digest(b'declared old decoder source fixture')


def fixture():
    value, artifacts = meaning_fixture.fixture()
    raw = canonical(value)
    source = value['source_set'][0]['source']
    base = {'package_id': source['package_id'], 'source_sha256': source['sha256'],
            'source_bytes': source['bytes'], 'archive_sha256': digest(b'archive'),
            'archive_bytes': 7, 'decoder_identity_sha256': DECODER,
            'decoder_source_sha256': SOURCE_EPOCH}
    return {'GRAPH': raw}, artifacts, [base]


def packed(records=None, artifacts=None, bases=None):
    initial = fixture()
    records = initial[0] if records is None else records
    artifacts = initial[1] if artifacts is None else artifacts
    bases = initial[2] if bases is None else bases
    return bundle.pack(records, artifacts, registry_root(artifacts), bases, DECODER)


def rebuilt(raw, change, suffix=b''):
    count = int.from_bytes(raw[4:8], 'big')
    value = json.loads(raw[8:8 + count])
    change(value)
    header = canonical(value)
    return b'SNE1' + len(header).to_bytes(4, 'big') + header + raw[8 + count:] + suffix


class Output:
    def __init__(self):
        self.buffer = io.BytesIO()


class BundleControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='sentinel-bundle-')
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.addCleanup(patch.stopall)
        patch.object(subprocess, 'Popen', side_effect=AssertionError('Popen/native forbidden')).start()

    def decode(self, raw):
        return bundle.unpack(raw, digest(raw), DECODER)

    def call_cli(self, argv):
        output = Output()
        with patch.object(sys, 'stdout', output):
            status = cli.main(argv)
        return status, json.loads(output.buffer.getvalue())

    def registered(self, raw=None):
        raw = packed() if raw is None else raw
        index, records, artifacts = self.decode(raw)
        decoded = dict(index=index, records=records, artifacts=artifacts)
        base = index['bases'][0]
        archive = self.folder / 'base.zip'; archive.write_bytes(b'archive')
        config = {base['package_id']: {'archive': archive, 'share': self.folder / 'base.share',
                                       'native': self.folder / 'native'}}
        held = digest(canonical({base['package_id']: base}))
        return decoded, config, held

    def locator_fixture(self):
        records, artifacts, bases = fixture()
        value = json.loads(records['GRAPH'])
        source = value['source_set'][0]
        revision = {'schema': 'sentinel/source-revision/1', 'id': 'R1',
            'source_sha256': source['source']['sha256'], 'source_bytes': 4, 'previous_sha256': None}
        revraw = canonical(revision); revkey = digest(revraw)
        source['revision']['artifact_sha256'] = revkey
        node = {'schema': 'sentinel/evidence-locator/1', 'id': 'L1',
                **{key: deepcopy(source[key]) for key in ('source', 'representation', 'revision')},
                'selector': {'kind': 'SOURCE_BYTES', 'start': 0, 'end': 4, 'quote_sha256': digest(b'A--B')},
                'dependencies': []}
        locraw = canonical(node); lockey = digest(locraw)
        artifacts.update({revkey: revraw, lockey: locraw})
        records['GRAPH'] = canonical(value)
        records['LOCATORS'] = canonical({'schema': 'sentinel/locator-sets/1',
            'sets': [{'root': lockey, 'locator_keys': [lockey], 'revision_keys': [revkey]}]})
        records['REVISIONS'] = canonical({'schema': 'sentinel/revision-pins/1', 'keys': [revkey]})
        return records, artifacts, bases, node, lockey

    def test_complete_roundtrip_and_no_authority(self):
        raw = packed(); index, records, artifacts = self.decode(raw)
        self.assertEqual(packed(records, artifacts, index['bases']), raw)
        self.assertEqual(index['qualification'], 'NOT_QUALIFIED')
        self.assertEqual(index['execution_authority'], 'NONE')
        self.assertEqual(index['semantic_completeness'], 'UNPROVEN')
        self.assertEqual(bundle.checked_components(index, records, artifacts), (index, records, artifacts))
        with self.assertRaises(SentinelError):
            bundle.unpack(raw, digest(b'wrong'), DECODER)
        with self.assertRaises(SentinelError):
            bundle.unpack(raw, digest(raw), digest(b'other decoder'))

    def test_index_offsets_sizes_duplicates_versions_and_eof_refuse(self):
        raw = packed()
        mutations = (lambda v: v['items'][0].update(offset=False),
            lambda v: v['items'][0].update(bytes=True),
            lambda v: v['items'][1].update(id=v['items'][0]['id']),
            lambda v: v.update(schema='other'),
            lambda v: v.update(qualification='QUALIFIED'),
            lambda v: v['items'][0].update(kind='EXECUTE'),
            lambda v: v['items'][0].update(id='../outside'))
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.decode(rebuilt(raw, mutation))
        for changed in (raw[:-1], raw + b'x', b'NOPE' + raw[4:]):
            with self.assertRaises(ValueError):
                self.decode(changed)

    def test_required_graph_base_closed_fields_and_registry_slot_refuse(self):
        records, artifacts, bases = fixture()
        variants = ({'OTHER': records['GRAPH']}, {}, {'GRAPH': b'{}'})
        for changed in variants:
            with self.assertRaises(ValueError):
                packed(changed, artifacts, bases)
        for field, changed in (('archive_bytes', True), ('source_bytes', 5), ('extra', 'bad')):
            rows = deepcopy(bases); rows[0][field] = changed
            with self.assertRaises(ValueError):
                packed(records, artifacts, rows)
        extras = {digest(str(i).encode()): str(i).encode() for i in range(255)}
        extras.update(artifacts)
        self.assertEqual(len(extras), 256)
        with self.assertRaisesRegex(ValueError, 'graph consumes registry'):
            packed(records, extras, bases)

    def test_optional_schemas_and_paired_admissions_refuse(self):
        records, artifacts, bases = fixture()
        for name in bundle.RECORDS:
            if name == 'GRAPH':
                continue
            changed = dict(records, **{name: b'{}'})
            with self.subTest(name=name), self.assertRaises(ValueError):
                packed(changed, artifacts, bases)
        pointer = {'schema': 'sentinel/native-evidence-pointer/1',
            'receipt_pin': identity(b'x'), 'source_pins_pin': identity(b'x'), 'scope_pin': identity(b'x')}
        artifacts[digest(b'x')] = b'x'; records['NATIVE_RECEIPT'] = canonical(pointer)
        self.assertIn('NATIVE_RECEIPT', self.decode(packed(records, artifacts, bases))[1])
        pointer['receipt_pin']['bytes'] = True
        records['NATIVE_RECEIPT'] = canonical(pointer)
        with self.assertRaises(ValueError):
            packed(records, artifacts, bases)

    def test_locator_registry_shapes_complete_revision_binding(self):
        records, artifacts, bases, node, key = self.locator_fixture()
        self.decode(packed(records, artifacts, bases))
        value = json.loads(records['LOCATORS'])
        value['sets'][0]['revision_keys'] = []
        records['LOCATORS'] = canonical(value)
        with self.assertRaises(ValueError):
            packed(records, artifacts, bases)
        node['selector']['start'] = False
        bad = canonical(node); artifacts[digest(bad)] = bad
        value['sets'][0].update(root=digest(bad), locator_keys=[digest(bad)],
            revision_keys=[node['revision']['artifact_sha256']])
        records['LOCATORS'] = canonical(value)
        with self.assertRaises(ValueError):
            packed(records, artifacts, bases)

    def test_visible_main_ideas_relations_and_no_truncation(self):
        raw = packed(); index, records, artifacts = self.decode(raw)
        sections, lexicon, visible = bundle.presentation(index, records, artifacts)
        text = json.loads(records['GRAPH'])['nodes'][0]['text']
        self.assertEqual(lexicon, {'P1': text})
        self.assertIn('P1', visible)
        self.assertEqual(raw[sections[0]['start']:sections[0]['end']], records['GRAPH'])
        changed = json.loads(records['GRAPH']); changed['nodes'][0]['text'] = 'x' * 256
        records['GRAPH'] = canonical(changed)
        raw = packed(records, artifacts, index['bases']); index, records, artifacts = self.decode(raw)
        with self.assertRaisesRegex(ValueError, 'complete visible idea'):
            bundle.presentation(index, records, artifacts)

    def test_export_exact_create_only_and_component_snapshot(self):
        index, records, artifacts = self.decode(packed())
        out = self.folder / 'export'
        result = bundle.export_entries(index, records, artifacts, out)
        self.assertEqual(result['status'], 'EXPORTED_INERT_DATA_ONLY')
        self.assertEqual((out / 'record-GRAPH.json').read_bytes(), records['GRAPH'])
        self.assertEqual((out / 'index.json').read_bytes(), canonical(index))
        with self.assertRaises(ValueError):
            bundle.export_entries(index, records, artifacts, out)
        for changed in (dict(index, graph_sha256=digest(b'bad')), dict(index, items=[])):
            fresh = self.folder / 'uncreated'
            with self.assertRaises(ValueError):
                bundle.export_entries(changed, records, artifacts, fresh)
            self.assertFalse(fresh.exists())
        link = self.folder / 'link'; link.symlink_to(out, target_is_directory=True)
        with self.assertRaises(ValueError):
            bundle.export_entries(index, records, artifacts, link)

    def test_write_payload_checks_all_bytes_and_never_overwrites(self):
        path = self.folder / 'payload'
        bundle.write_payload(path, b'abc')
        self.assertEqual(path.read_bytes(), b'abc')
        with self.assertRaises(FileExistsError):
            bundle.write_payload(path, b'different')
        with patch.object(bundle.os, 'write', return_value=0), self.assertRaises(ValueError):
            bundle.write_payload(self.folder / 'short', b'x')

    def test_registration_requires_complete_whole_archive_runtime_and_source_pins(self):
        decoded, config, held = self.registered()
        with patch.object(bundle, 'decoder_pins', return_value=(self.folder / 'native', DECODER, SOURCE_EPOCH)):
            self.assertEqual(bundle.register_bases(decoded, config, held), config)
            for changed in ({}, {key: dict(row, archive=Path('relative')) for key, row in config.items()}):
                with self.assertRaises(ValueError):
                    bundle.register_bases(decoded, changed, held)
            with self.assertRaises(ValueError):
                bundle.register_bases(decoded, config, digest(b'other held registry'))
            config[next(iter(config))]['archive'].write_bytes(b'altered')
            with self.assertRaises(ValueError):
                bundle.register_bases(decoded, config, held)
        decoded, config, held = self.registered()
        with patch.object(bundle, 'decoder_pins', return_value=(self.folder / 'native', digest(b'wrong'), SOURCE_EPOCH)):
            with self.assertRaises(ValueError):
                bundle.register_bases(decoded, config, held)

    def test_source_resolution_full_window_or_explicit_refusal(self):
        records, artifacts, bases, node, key = self.locator_fixture()
        decoded, config, held = self.registered(packed(records, artifacts, bases))
        resolution = {'status': 'RESOLVED_BYTES', 'source': node['source'],
            'revision': node['revision'], 'representation': node['representation'],
            'parts': [{'span': [0, 4], 'data': b'A--B'}], 'gaps': [], 'locator_sha256': key,
            'package_id': node['source']['package_id'], 'coordinate_kind': 'SOURCE_BYTE'}
        with patch.object(bundle, 'decoder_pins', return_value=(self.folder / 'native', DECODER, SOURCE_EPOCH)), \
             patch('sentinel_v1.locators.resolve_locator', return_value=resolution) as resolver:
            result = bundle.resolve_registered(decoded, config, held)
            self.assertEqual(result['status'], 'ALL_GRAPH_WINDOWS_RESOLVED_TO_REGISTERED_BASES')
            self.assertEqual(result['bindings'][0]['checked_source_ids'], ['S1'])
            self.assertEqual(result['qualification'], 'NOT_QUALIFIED')
            self.assertEqual(resolver.call_count, 1)
            self.assertEqual(result['contexts'][0]['parts'][0]['data_hex'], b'A--B'.hex())
            self.assertEqual(result['source_context_bytes'], 4)
            for changes in ({'status': 'UNSUPPORTED'}, {'parts': [{'span': [0, 1], 'data': b'A'}]},
                            {'parts': [{'span': [0, 4], 'data': b'FAKE'}]}):
                with patch('sentinel_v1.locators.resolve_locator', return_value=dict(resolution, **changes)):
                    with self.assertRaises(ValueError):
                        bundle.resolve_registered(decoded, config, held)

    def test_outer_decode_validated_only_and_runtime_before_native(self):
        raw = packed(); path = self.folder / 'source'; path.write_bytes(raw)
        @contextmanager
        def validated(*_args):
            yield path, {'source': identity(raw)}, digest(b'outer package'), []
        with patch.object(bundle, 'decoder_pins', return_value=(path, DECODER, SOURCE_EPOCH)), \
             patch('transport_document.validated', validated):
            result = bundle.decode_with_sast('archive', 'share', DECODER, path)
            self.assertEqual(result['base_resolution'], 'NOT_PERFORMED_GRAPH_ONLY')
            self.assertEqual(result['native_receipts'], 'POINTERS_NOT_PROOF_VERIFICATION')
        with patch.object(bundle, 'decoder_pins', return_value=(path, digest(b'wrong'), SOURCE_EPOCH)), \
             patch('transport_document.validated', side_effect=AssertionError('must refuse before native')):
            with self.assertRaises(ValueError):
                bundle.decode_with_sast('archive', 'share', DECODER, path)

    def test_encoder_held_actual_reread_and_private_source(self):
        raw = packed(); path = self.folder / 'source'; path.write_bytes(raw)
        observed = []
        def encode(source, output, title, reference, budget, sections, native):
            output.mkdir()
            observed.append(source.read_bytes())
            path.write_bytes(b'caller later changed')
            self.assertEqual(source.read_bytes(), raw)
            self.assertTrue(sections)
            return {'status': 'MOCKED_NO_NATIVE'}
        with patch.object(bundle, 'decoder_pins', return_value=(path, DECODER, SOURCE_EPOCH)), \
             patch('transport_document.encode_document', side_effect=encode):
            result = bundle.encode_with_sast(path, self.folder / 'package', 'ideas', 'meaning.zip', 200, path, digest(raw))
            self.assertEqual(result['status'], 'MOCKED_NO_NATIVE')
            self.assertEqual(observed, [raw])
            with self.assertRaises(ValueError):
                bundle.encode_with_sast(path, self.folder / 'unused', 'ideas', 'meaning.zip', 200, path, digest(raw))
        self.assertFalse((self.folder / 'unused').exists())

    def test_cli_pack_inspect_export_and_errors(self):
        records, artifacts, bases = fixture(); folder = self.folder / 'inputs'; folder.mkdir()
        for name, raw in records.items():
            (folder / (name + '.json')).write_bytes(raw)
        for key, raw in artifacts.items():
            (folder / (key + '.bin')).write_bytes(raw)
        manifest = {'schema': 'sentinel/bundle-input/1', 'records': {k: identity(v) for k, v in records.items()},
            'artifacts': {k: identity(v) for k, v in artifacts.items()}, 'bases': bases,
            'decoder_identity_sha256': DECODER}
        manifest_raw = canonical(manifest); path = self.folder / 'manifest'; path.write_bytes(manifest_raw)
        payload = self.folder / 'payload'
        status, value = self.call_cli(['pack', '--input-dir', str(folder), '--manifest', str(path),
            '--expect-manifest', digest(manifest_raw), '--output', str(payload)])
        self.assertEqual(status, 0); self.assertEqual(value['status'], 'SNE1_DATA_WRITTEN_NOT_SAST_ENCODED')
        status, value = self.call_cli(['inspect-payload', '--payload', str(payload),
            '--expect-payload', digest(payload.read_bytes()), '--decoder-identity', DECODER,
            '--export', str(self.folder / 'export')])
        self.assertEqual(status, 0); self.assertIn('P1', value['lexicon'])
        self.assertEqual(value['base_resolution'], 'NOT_PERFORMED_GRAPH_ONLY')
        status, value = self.call_cli([])
        self.assertEqual((status, value['status']), (1, 'REFUSED'))

    def test_input_manifest_refuses_names_and_aggregate_before_extra_reads(self):
        records, artifacts, bases = fixture()
        value = {'schema': 'sentinel/bundle-input/1', 'records': {'../outside': identity(b'X')},
            'artifacts': {}, 'bases': bases, 'decoder_identity_sha256': DECODER}
        raw = canonical(value)
        with patch.object(cli, 'read_file', side_effect=AssertionError('outside read forbidden')):
            with self.assertRaises(ValueError):
                cli.input_manifest(self.folder, raw, digest(raw))
        value['records'] = {}; value['artifacts'] = {digest(str(i).encode()):
            {'sha256': digest(str(i).encode()), 'bytes': 1048576} for i in range(9)}
        raw = canonical(value)
        with patch.object(cli, 'read_file', return_value=b'x') as read:
            with self.assertRaises(ValueError):
                cli.input_manifest(self.folder, raw, digest(raw))
            self.assertEqual(read.call_count, 0)


    def test_census_and_formal_records_recomputed_not_schema_only(self):
        from sentinel_v1 import census
        records, artifacts, bases = fixture()
        reading = b'A--B'
        result = census.build_census(reading, canonical(meaning_fixture.binding(reading)))
        records['CENSUS'] = canonical(result)
        source = b'Claim. Residual text.'
        plan = {'schema': 'transport/encoding-plan/1', 'symbols': {'S0': 'Claim'},
                'meaning': {'schema': 'transport/meaning/1', 'nodes': [
                    {'op': 'text', 'symbol': 'S0', 'span': [0, 5]},
                    {'op': 'pred', 'args': [0], 'cue': [0, 0]}], 'root': 1, 'ambiguities': []}}
        plan_raw = canonical(plan)
        artifacts.update({digest(source): source, digest(plan_raw): plan_raw})
        formal = {'schema': 'sentinel/formal-fragment/1', 'source_pin': identity(source),
                  'plan_pin': identity(plan_raw), 'result': graph.checked_formal_fragment(source, plan_raw)}
        records['FORMAL'] = canonical(formal)
        self.decode(packed(records, artifacts, bases))
        formal['result']['adapter'] = 'SELF_QUALIFIED'
        records['FORMAL'] = canonical(formal)
        with self.assertRaises(ValueError):
            packed(records, artifacts, bases)
        records.pop('FORMAL')
        result['semantic_completeness'] = 'PROVED'
        records['CENSUS'] = canonical(result)
        with self.assertRaises(ValueError):
            packed(records, artifacts, bases)

    def test_registry_257_and_header_bound_before_content_use(self):
        records, artifacts, bases = fixture()
        extras = {digest(str(i).encode()): str(i).encode() for i in range(257)}
        with patch.object(bundle, 'content_checked', side_effect=AssertionError('must refuse before graph')):
            with self.assertRaises(ValueError):
                packed(records, extras, bases)
        for size in (0, bundle.INDEX_CAP + 1, 4294967295):
            raw = b'SNE1' + size.to_bytes(4, 'big') + b'x'
            with self.assertRaises(ValueError):
                self.decode(raw)

    def test_visible_relationships_budget_and_full_labels_preserved(self):
        import transport_document as document
        records, artifacts, bases = fixture(); value = json.loads(records['GRAPH'])
        second = deepcopy(value['nodes'][0]); second['id'] = 'C2'; second['text'] = 'An explicit exception.'
        exception = deepcopy(second); exception.update(id='E1', kind='EXCEPTION', text='Unless an exception applies.')
        value['nodes'].extend([second, exception])
        value['edges'] = [{'from': 'E1', 'to': 'C1', 'kind': 'EXCEPTION_TO'}]
        records['GRAPH'] = canonical(value)
        index, records, artifacts = self.decode(packed(records, artifacts, bases))
        sections, lexicon, visible = bundle.presentation(index, records, artifacts)
        self.assertIn('N3:EXCEPTION_TO:P1', visible)
        self.assertEqual(lexicon['N3'], 'Unless an exception applies.')
        self.assertTrue(sections[2]['label'].startswith('EXCEPTION:'))
        self.assertEqual(lexicon['P2'], 'An explicit exception.')
        formula = document.formula_for(visible, sections)
        with self.assertRaisesRegex(ValueError, 'share budget too small'):
            document.share_for(formula, digest(b'package'), 'meaning.zip', 1)
        with self.assertRaises(ValueError):
            bundle.presentation(index, records, artifacts, 'x' * 256)

    def test_context_part_bytes_gaps_and_aggregate_cap(self):
        base = {'status': 'RESOLVED_BYTES', 'parts': [
            {'span': [0, 1], 'data': b'A'}, {'span': [3, 4], 'data': b'B'}], 'gaps': [[1, 3]],
            'locator_sha256': digest(b'locator'), 'source': {}, 'representation': {},
            'revision': {}, 'coordinate_kind': 'SOURCE_BYTE'}
        value, count = bundle.context_output(base, 2)
        self.assertEqual(count, 2); self.assertEqual(value['gaps'], [[1, 3]])
        self.assertEqual([bytes.fromhex(p['data_hex']) for p in value['parts']], [b'A', b'B'])
        with self.assertRaisesRegex(ValueError, 'source intake byte cap'):
            bundle.context_output(base, 1)
        changed = dict(base, parts=[{'span': [0, 1], 'data': b'XX'}])
        with self.assertRaises(ValueError):
            bundle.context_output(changed, 10)

    def test_registration_snapshots_declared_rows_before_external_io(self):
        import transport_document as document
        decoded, config, held = self.registered()
        original = document.file_digest
        def changed(path, cap):
            value = original(path, cap)
            decoded['index']['bases'][0]['source_sha256'] = digest(b'later caller mutation')
            return value
        with patch.object(document, 'file_digest', side_effect=changed), \
             patch.object(bundle, 'decoder_pins', return_value=(self.folder / 'native', DECODER, SOURCE_EPOCH)):
            self.assertEqual(bundle.register_bases(decoded, config, held), config)
        self.assertNotEqual(decoded['index']['bases'][0]['source_sha256'], fixture()[2][0]['source_sha256'])

    def test_cli_limits_preserve_stricter_inherited_resources_and_timer(self):
        with patch.object(cli.resource, 'getrlimit', return_value=(1, 2)), \
             patch.object(cli.resource, 'setrlimit') as setter, \
             patch.object(cli.signal, 'signal'), \
             patch.object(cli.signal, 'getitimer', return_value=(0.5, 0)), \
             patch.object(cli.signal, 'setitimer') as timer:
            cli.limits()
        for call in setter.call_args_list:
            soft, hard = call.args[1]
            self.assertLessEqual(soft, 1); self.assertEqual(hard, 2)
        timer.assert_called_once_with(cli.signal.ITIMER_REAL, 0.5)


    def overview_fixture(self):
        records, artifacts, bases = fixture(); value = json.loads(records['GRAPH'])
        for index in range(2, 22):
            node = deepcopy(value['nodes'][0]); node.update(id='C' + str(index), text='Full proposed idea ' + str(index))
            value['nodes'].append(node)
        value['edges'] = [{'from': 'C1', 'to': 'C' + str(i), 'kind': 'DEPENDS_ON'} for i in range(2, 22)]
        records['GRAPH'] = canonical(value)
        return packed(records, artifacts, bases)

    def test_overview_large_relation_graph_keeps_full_package_and_readable_lexicon(self):
        raw = self.overview_fixture(); index, records, artifacts = self.decode(raw)
        with self.assertRaises(ValueError):
            bundle.presentation(index, records, artifacts)
        sections, lexicon, visible = bundle.presentation(index, records, artifacts, display_profile='OVERVIEW')
        self.assertEqual(len(sections), 21); self.assertEqual(len(lexicon['relations']), 20)
        self.assertIn('OVERVIEW', visible)
        self.assertEqual(lexicon['scope'], 'OVERVIEW_MAIN_PROPOSITIONS_ONLY_RELATION_DETAILS_IN_GRAPH')
        readable = bundle.graph_lexicon(records, artifacts).decode()
        for i in range(2, 22):
            self.assertIn('Full proposed idea ' + str(i), readable)
        self.assertEqual(readable.count('| P1 | DEPENDS&#95;ON |'), 20)
        self.assertEqual(self.decode(raw)[1]['GRAPH'], records['GRAPH'])

    def test_overview_long_node_text_escaped_not_truncated_and_unknown_profile_refuses(self):
        records, artifacts, bases = fixture(); value = json.loads(records['GRAPH'])
        text = '<script>untrusted</script> | [x] ``` ' + 'x' * 3800
        value['nodes'][0]['text'] = text; records['GRAPH'] = canonical(value)
        index, records, artifacts = self.decode(packed(records, artifacts, bases))
        with self.assertRaises(ValueError):
            bundle.presentation(index, records, artifacts)
        sections, lexicon, _visible = bundle.presentation(index, records, artifacts, display_profile='OVERVIEW')
        self.assertEqual(lexicon['nodes'][0]['text'], text)
        readable = bundle.graph_lexicon(records, artifacts).decode()
        self.assertNotIn('<script>', readable); self.assertIn('&lt;script&gt;', readable)
        self.assertIn('&#124;', readable); self.assertIn('&#96;', readable)
        self.assertIn('x' * 3800, readable)
        with self.assertRaises(ValueError):
            bundle.presentation(index, records, artifacts, display_profile='SILENT_DROP')

    def test_overview_unchanged_share_budget_counts_complete_share(self):
        import transport_document as document
        index, records, artifacts = self.decode(self.overview_fixture())
        sections, _lexicon, title = bundle.presentation(index, records, artifacts, display_profile='OVERVIEW')
        formula = document.formula_for(title, sections)
        share = document.share_for(formula, digest(b'package'), 'meaning.zip', None)
        self.assertTrue(all(section['id'] in formula for section in sections))
        with self.assertRaises(ValueError):
            document.share_for(formula, digest(b'package'), 'meaning.zip', 1)
        self.assertEqual(document.share_for(formula, digest(b'package'), 'meaning.zip', len(share.decode())), share)

    def test_bound_profile_requires_admitted_interpreter_and_independent_source_identity(self):
        records, artifacts, bases = fixture()
        with self.assertRaisesRegex(ValueError, 'fresh admitted CLI'):
            bundle.pack_bound(records, artifacts, registry_root(artifacts), bases, DECODER, digest(b'held'))
        sources = cli.fixed_snapshot(); held = digest(canonical(sources))
        semantic = {'root_sha256': held, 'sources': sources}
        with patch.object(bundle, 'semantic_identity', return_value=semantic):
            raw = bundle.pack_bound(records, artifacts, registry_root(artifacts), bases, DECODER, held)
            index, actual_records, actual_artifacts = bundle.unpack_bound(raw, digest(raw), DECODER, held)
            self.assertEqual(index['schema'], bundle.PROFILE_BOUND)
            self.assertEqual(index['semantic_decoder_sources'], sources)
            self.assertEqual(actual_records, records); self.assertEqual(actual_artifacts, artifacts)
            for mutation in (lambda v: v.update(semantic_decoder_root_sha256=digest(b'other')),
                             lambda v: v['semantic_decoder_sources'].update({'source-selected.py': identity(b'code')})):
                altered = rebuilt(raw, mutation)
                with self.assertRaises(ValueError):
                    bundle.unpack_bound(altered, digest(altered), DECODER, held)
            with self.assertRaises(ValueError):
                bundle.unpack(raw, digest(raw), DECODER)

    def test_fresh_bootstrap_rejects_wrong_held_root_and_preimported_modules(self):
        sources = cli.fixed_snapshot(); held = digest(canonical(sources))
        with self.assertRaisesRegex(ValueError, 'source root mismatch'):
            cli.fresh_bootstrap(['--semantic-root', digest(b'wrong')])
        with self.assertRaisesRegex(ValueError, 'imported before bootstrap'):
            cli.fresh_bootstrap(['--semantic-root', held])
        with self.assertRaises(ValueError):
            cli.fresh_bootstrap([])


    def test_context_dependency_pin_and_closed_local_import_roster(self):
        from types import SimpleNamespace
        sources = cli.fixed_snapshot()
        self.assertIn('transport_document_context.py', sources)
        held = digest(canonical(sources)); changed = deepcopy(sources)
        changed['transport_document_context.py'] = identity(b'only this declared dependency changed')
        with patch.object(cli, 'fixed_snapshot', return_value=changed), \
             patch.object(cli.importlib, 'import_module', side_effect=AssertionError('must refuse before import')):
            with self.assertRaisesRegex(ValueError, 'source root mismatch'):
                cli.fresh_bootstrap(['--semantic-root', held])
        root = ROOT / 'tools'
        with patch.object(cli.sys, 'modules', {'valid': SimpleNamespace(__file__=str(root / 'sentinel_v1/common.py'))}):
            cli.closed_imports(root)
        with patch.object(cli.sys, 'modules', {'bad': SimpleNamespace(__file__=str(root / 'undeclared.py'))}):
            with self.assertRaisesRegex(ValueError, 'undeclared local'):
                cli.closed_imports(root)


    def test_memory_error_refuses_main_and_fresh_bootstrap_with_fixed_reason(self):
        output = Output()
        with patch.object(cli, 'execute', side_effect=MemoryError('untrusted huge details')), \
             patch.object(cli, 'arguments', return_value=object()), patch.object(sys, 'stdout', output):
            status = cli.main([])
        value = json.loads(output.buffer.getvalue())
        self.assertEqual(status, 1)
        self.assertEqual(value, {'status': 'REFUSED', 'reason': 'memory limit', 'execution_authority': 'NONE'})
        output = Output()
        with patch.object(cli, 'fresh_bootstrap', side_effect=MemoryError('details')), \
             patch.object(sys, 'stdout', output), self.assertRaises(SystemExit) as raised:
            cli.bootstrap_or_refuse([])
        self.assertEqual(raised.exception.code, 1)
        self.assertEqual(json.loads(output.buffer.getvalue()), value)


if __name__ == '__main__':
    unittest.main()
