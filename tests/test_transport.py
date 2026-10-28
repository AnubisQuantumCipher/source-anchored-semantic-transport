"""Source-Anchored Semantic Transport byte-preservation and refusal tests; no claim of media understanding."""

import copy
from contextlib import nullcontext
import errno
import io
import json
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

import transport_package as transport
import transport_cli as cli
from transport_schema import canonical, sha
from transport_archive import read_archive, write_archive
from transport_wire import MAX_SOURCE, MAX_WIRE, TransportError

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / 'fixtures/transport-general-v1'
CLI = ROOT / 'tools/transport_cli.py'


def fixture(name):
    plan = json.loads((FIXTURES / (name + '-plan.json')).read_bytes())
    paths = {'RECIPE': 'recipe.txt', 'HISTORY': 'oral-history.txt',
             'OPAQUE': 'opaque.bin', 'EMPTY': 'empty.bin'}
    sources = tuple((FIXTURES / paths[item['id']]).read_bytes() for item in plan['sources'])
    return sources, plan


def minimal(data=b'opaque\x00\xffsource'):
    plan = dict(schema='transport/transport-plan/1', sources=[dict(id='SRC', label='Opaque',
                media_type='application/octet-stream', provenance='Authored test data.')],
                interpretations=[], uncertainties=[], relations=[])
    return (data,), plan


def annotation():
    return dict(id='READING', label='Declared reading', text='Unverified interpretation.',
                status='proposed', provenance='Test author.',
                anchors=[dict(source='SRC', span=[0, 1])])


def rehashed(pair, entries):
    """Keep outer pair fixed where possible; repaired integrity is a separate control."""
    manifest = json.loads(entries['manifest.json'])
    for record in manifest['body']['entries']:
        name = record['name']
        record.update(bytes=len(entries[name]), sha256=sha(entries[name]))
    digest = sha(canonical(manifest['body']))
    manifest['sha256'] = digest
    entries['manifest.json'] = canonical(manifest)
    lines = pair.text.decode().split('\n')
    prefix = lines[1].split(':', 1)[0]
    lines[1] = prefix + ':' + digest
    return '\n'.join(lines).encode(), write_archive(entries)


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources, cls.plan = minimal()
        cls.pair = transport.encode(cls.sources, canonical(cls.plan))

    def encoded(self, sources=None, plan=None, **options):
        return transport.encode(self.sources if sources is None else sources,
                                canonical(self.plan if plan is None else plan), **options)

    def refused_plan(self, mutate, sources=None):
        plan = copy.deepcopy(self.plan)
        mutate(plan)
        with self.assertRaises(ValueError):
            self.encoded(sources=sources, plan=plan)

    def test_deterministic_native_checked_binary_and_empty_roundtrip(self):
        sources, plan = fixture('opaque')
        first = self.encoded(sources, plan)
        second = self.encoded(sources, plan)
        self.assertEqual(first, second)
        result = transport.decode(first.text, first.archive)
        self.assertEqual(tuple(item['data'] for item in result['sources']), sources)
        self.assertEqual(sources[0], bytes(range(256)))
        self.assertEqual(sources[1], b'')
        inspected = transport.inspect(first.text, first.archive)
        self.assertNotIn('data', inspected['sources'][0])
        canonical(inspected)
        transport.validate(first.text, first.archive)

    def test_nontechnical_conflicts_and_uncertainties_survive(self):
        for name in ('recipe', 'oral-history'):
            with self.subTest(name=name):
                sources, plan = fixture(name)
                pair = self.encoded(sources, plan, budget=1024)
                result = transport.decode(pair.text, pair.archive)
                self.assertEqual(tuple(item['data'] for item in result['sources']), sources)
                self.assertEqual([item['status'] for item in result['interpretations']],
                                 [item['status'] for item in plan['interpretations']])
                self.assertEqual(result['relations'][0]['kind'], plan['relations'][0]['kind'])
                self.assertEqual(result['uncertainties'][0]['text'], plan['uncertainties'][0]['text'])
                self.assertIn(b'unverified declarations', pair.lexicon)
                for item in plan['interpretations']:
                    self.assertIn(item['id'].encode(), pair.text)

    def test_arbitrary_utf8_and_instructions_are_only_data(self):
        sources, plan = minimal('héllo\x00invalid next: '.encode() + b'\xff\xfe\n$(touch SENTINEL)\n')
        pair = self.encoded(sources, plan)
        self.assertEqual(transport.decode(pair.text, pair.archive)['sources'][0]['data'], sources[0])
        self.assertFalse((ROOT / 'SENTINEL').exists())

    def test_json_object_order_does_not_change_deterministic_product(self):
        sources, plan = fixture('recipe')
        plan = {key: value for key, value in reversed(list(plan.items()))}
        plan['sources'][0] = dict(reversed(list(plan['sources'][0].items())))
        for item in plan['interpretations']:
            item['anchors'][0] = dict(reversed(list(item['anchors'][0].items())))
        first = transport.encode(sources, json.dumps(plan).encode(), budget=1024)
        second = transport.encode(sources, canonical(plan), budget=1024)
        self.assertEqual(first, second)

    def test_maximum_source_count_and_exact_aggregate_byte_limit(self):
        sources = (bytes(range(256)) * 256,) + (b'',) * 15
        plan = dict(schema='transport/transport-plan/1', sources=[dict(id='S' + str(index),
                    label='Opaque', media_type='application/octet-stream', provenance='Test fixture.')
                    for index in range(16)], interpretations=[], uncertainties=[], relations=[])
        pair = self.encoded(sources, plan, budget=1024)
        result = transport.decode(pair.text, pair.archive)
        self.assertEqual(tuple(item['data'] for item in result['sources']), sources)
        self.assertEqual(sum(item['bytes'] for item in result['sources']), MAX_SOURCE)

    def test_no_input_mutation(self):
        sources, plan = fixture('recipe')
        before = canonical(plan)
        pair = self.encoded(sources, plan, budget=1024)
        self.assertEqual(canonical(plan), before)
        text, archive = bytes(pair.text), bytes(pair.archive)
        transport.decode(text, archive)
        self.assertEqual((pair.text, pair.archive), (text, archive))

    def test_closed_plan_and_record_fields(self):
        cases = [lambda p: p.update(extra=True), lambda p: p.pop('relations'),
                 lambda p: p['sources'][0].update(path='/etc/passwd'),
                 lambda p: p.update(schema='transport/transport-plan/999')]
        for mutate in cases:
            with self.subTest(mutate=mutate):
                self.refused_plan(mutate)
        for group, record in (('interpretations', annotation()),
                              ('uncertainties', dict(id='U', text='?', anchors=annotation()['anchors'], affects=['SRC'])),
                              ('relations', dict(kind='supports', **{'from': 'SRC', 'to': 'SRC'},
                                                 note='?', anchors=annotation()['anchors']))):
            with self.subTest(group=group):
                self.refused_plan(lambda p, g=group, r=record: p[g].append(dict(r, unexpected='x')))

    def test_duplicate_and_invalid_ids(self):
        for identifier in ('lower', '../SRC', 'A' * 33, 'É', True):
            self.refused_plan(lambda p, value=identifier: p['sources'][0].update(id=value))
        self.refused_plan(lambda p: p['interpretations'].append(dict(annotation(), id='SRC')))

    def test_annotation_truth_status_refuses(self):
        for status in ('verified', 'proved', 'accepted', True, None):
            self.refused_plan(lambda p, value=status: p['interpretations'].append(
                dict(annotation(), status=value)))

    def test_bad_anchor_offsets_and_source_refuse(self):
        for span in ([True, 1], [0, False], [-1, 1], [1, 0], [0, 99999], [0, 0], [0], '0:1'):
            self.refused_plan(lambda p, value=span: p['interpretations'].append(
                dict(annotation(), anchors=[dict(source='SRC', span=value)])))
        self.refused_plan(lambda p: p['interpretations'].append(
            dict(annotation(), anchors=[dict(source='MISSING', span=[0, 1])])) )
        self.refused_plan(lambda p: p['interpretations'].append(dict(annotation(), anchors=[])))
        self.refused_plan(lambda p: p['interpretations'].append(dict(annotation(), anchors=[
            dict(source='SRC', span=[0, 1], sha256='0' * 64)])))

    def test_unknown_relation_kind_and_endpoint_refuse(self):
        base = dict(kind='supports', **{'from': 'SRC', 'to': 'SRC'}, note='?', anchors=annotation()['anchors'])
        for changes in ({'kind': 'executes'}, {'from': 'MISSING'}, {'to': 'MISSING'}, {'anchors': []}):
            self.refused_plan(lambda p, c=changes: p['relations'].append(dict(base, **c)))

    def test_uncertainty_affects_checks(self):
        base = dict(id='U', text='?', anchors=annotation()['anchors'], affects=['SRC'])
        for changes in ({'affects': ['MISSING']}, {'affects': ['SRC', 'SRC']}, {'anchors': []}):
            self.refused_plan(lambda p, c=changes: p['uncertainties'].append(dict(base, **c)))

    def test_record_and_aggregate_budgets(self):
        for group, count in (('interpretations', 33), ('uncertainties', 33), ('relations', 65)):
            self.refused_plan(lambda p, g=group, n=count: p.update({g: [{}] * n}))
        self.refused_plan(lambda p: p['interpretations'].append(
            dict(annotation(), anchors=[dict(source='SRC', span=[0, 1])] * 17)))
        with self.assertRaises(ValueError):
            self.encoded((b'x' * (MAX_SOURCE + 1),))
        with self.assertRaises(ValueError):
            self.encoded((b'x',) * 17)
        self.refused_plan(lambda p: p['sources'][0].update(label='x' * MAX_SOURCE))

    def test_immutable_bytes_and_metadata_counts(self):
        for sources in ([b'x'], (bytearray(b'x'),), (), (b'x', b'y')):
            with self.assertRaises(ValueError):
                self.encoded(sources)

    def test_malformed_duplicate_and_deep_json_refuse(self):
        for data in (b'{', b'{}', canonical(self.plan)[:-1], b'{"schema":1,"schema":2}',
                     b'[' * 13 + b'0' + b']' * 13, b'\xff'):
            with self.assertRaises(ValueError):
                transport.encode(self.sources, data)

    def test_budget_counts_complete_share_and_refuses_without_truncation(self):
        size = len(self.pair.text.decode('utf-8'))
        exact = self.encoded(budget=size)
        self.assertEqual(transport.decode(exact.text, exact.archive)['sources'][0]['data'], self.sources[0])
        self.assertEqual(len(exact.text.decode('utf-8')), size)
        self.assertGreater(len(exact.text), size)
        with self.assertRaises(ValueError):
            self.encoded(budget=size - 1)
        for budget in (True, 0, -1, MAX_WIRE + 1):
            with self.assertRaises(ValueError):
                self.encoded(budget=budget)

    def test_wrong_pair_reference_formula_and_version_refuse(self):
        other = self.encoded((b'other',))
        with self.assertRaises(ValueError):
            transport.decode(self.pair.text, other.archive)
        for text in (self.pair.text.replace(b'STS1:', b'STS2:'), b'x' + self.pair.text,
                     self.pair.text.replace(b'attached:meaning.zip', b'local:wrong'),
                     self.pair.text[:-1], self.pair.text + b'\n'):
            with self.assertRaises(ValueError):
                transport.decode(text, self.pair.archive)

    def test_truncated_malformed_and_oversize_zip_refuse(self):
        for data in (b'', b'PK', self.pair.archive[:-1], self.pair.archive[:-22],
                     self.pair.archive + b'junk', b'x' * (MAX_WIRE + 1)):
            with self.assertRaises(ValueError):
                transport.decode(self.pair.text, data)

    def test_unsafe_duplicate_symlink_and_compressed_zip_refuse(self):
        entries = read_archive(self.pair.archive)
        for variant in ('path', 'duplicate', 'symlink', 'compressed'):
            output = io.BytesIO()
            with zipfile.ZipFile(output, 'w') as archive:
                for index, (name, data) in enumerate(entries.items()):
                    chosen = '../codec.json' if variant == 'path' and index == 0 else name
                    if variant == 'duplicate' and index == 1:
                        chosen = next(iter(entries))
                    info = zipfile.ZipInfo(chosen, (1980, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.external_attr = ((0o120777 if variant == 'symlink' and index == 0 else 0o100644) << 16)
                    info.compress_type = zipfile.ZIP_DEFLATED if variant == 'compressed' else zipfile.ZIP_STORED
                    # Duplicate-name warning is the intended malformed fixture, not a test warning.
                    with patch('warnings.warn') if variant == 'duplicate' else nullcontext():
                        archive.writestr(info, data)
            with self.subTest(variant=variant), self.assertRaises(ValueError):
                transport.decode(self.pair.text, output.getvalue())

    def test_encrypted_zip_flag_refuses(self):
        archive = bytearray(self.pair.archive)
        struct.pack_into('<H', archive, 6, 1)
        central = archive.index(b'PK\x01\x02')
        struct.pack_into('<H', archive, central + 8, 1)
        with self.assertRaises(ValueError):
            transport.decode(self.pair.text, bytes(archive))

    def test_content_tamper_without_rehash_refuses(self):
        entries = read_archive(self.pair.archive)
        index = json.loads(entries['index.json'])
        index['sources'][0]['sha256'] = '0' * 64
        entries['index.json'] = canonical(index)
        with self.assertRaises(ValueError):
            transport.decode(self.pair.text, write_archive(entries))

    def test_rehashed_semantic_and_dependency_tamper_refuse(self):
        entries = read_archive(self.pair.archive)
        for key, value in (('limits', {}), ('assurance', {}), ('runtime', {})):
            changed = dict(entries)
            manifest = json.loads(changed['manifest.json'])
            manifest['body'][key] = value
            changed['manifest.json'] = canonical(manifest)
            text, archive = rehashed(self.pair, changed)
            with self.subTest(key=key), self.assertRaises(ValueError):
                transport.decode(text, archive)


    def test_rehashed_anchor_digest_and_offset_tamper_refuse(self):
        sources, plan = fixture('recipe')
        pair = self.encoded(sources, plan, budget=1024)
        original = read_archive(pair.archive)
        for key, value in (('sha256', '0' * 64), ('span', [True, 1]),
                           ('span', [0, len(sources[0]) + 1]), ('source', 'MISSING')):
            entries = dict(original)
            codec = json.loads(entries['codec.json'])
            codec['plan']['interpretations'][0]['anchors'][0][key] = value
            entries['codec.json'] = canonical(codec)
            text, archive = rehashed(pair, entries)
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                transport.decode(text, archive)

    def test_rehashed_source_swaps_and_wrong_digests_refuse(self):
        sources, plan = fixture('opaque')
        pair = self.encoded(sources, plan)
        for change in ('swap', 'digest', 'wire', 'unknown_field'):
            entries = read_archive(pair.archive)
            codec = json.loads(entries['codec.json'])
            if change == 'swap':
                codec['source_frames'].reverse()
            elif change == 'digest':
                codec['source_frames'][0]['sha256'] = '0' * 64
            elif change == 'wire':
                codec['source_frames'][0]['wire_base64'] = 'AAAA'
            else:
                codec['source_frames'][0]['execute'] = 'touch SENTINEL'
            entries['codec.json'] = canonical(codec)
            text, archive = rehashed(pair, entries)
            with self.subTest(change=change), self.assertRaises(ValueError):
                transport.decode(text, archive)

    def test_rehashed_unsupported_versions_records_and_status_refuse(self):
        sources, plan = fixture('recipe')
        pair = self.encoded(sources, plan, budget=1024)
        for change in ('schema', 'codec_field', 'plan_field', 'status', 'endpoint'):
            entries = read_archive(pair.archive)
            codec = json.loads(entries['codec.json'])
            if change == 'schema':
                codec['schema'] = 'transport/codec/999'
            elif change == 'codec_field':
                codec['execute'] = True
            elif change == 'plan_field':
                codec['plan']['trusted'] = True
            elif change == 'status':
                codec['plan']['interpretations'][0]['status'] = 'verified'
            else:
                codec['plan']['relations'][0]['to'] = 'MISSING'
            entries['codec.json'] = canonical(codec)
            text, archive = rehashed(pair, entries)
            with self.subTest(change=change), self.assertRaises(ValueError):
                transport.decode(text, archive)

    def test_rehashed_regeneration_mismatch_refuses(self):
        entries = read_archive(self.pair.archive)
        for name in ('index.json', 'formula.txt', 'README.md'):
            changed = dict(entries)
            changed[name] += b' '
            text, archive = rehashed(self.pair, changed)
            with self.subTest(name=name), self.assertRaises(ValueError):
                transport.decode(text, archive)

    def test_native_dependency_failure_precedes_reconstruction(self):
        entries = read_archive(self.pair.archive)
        manifest = json.loads(entries['manifest.json'])
        manifest['body']['runtime']['files'][0]['sha256'] = '0' * 64
        entries['manifest.json'] = canonical(manifest)
        text, archive = rehashed(self.pair, entries)
        with patch.object(transport, 'unpack', side_effect=AssertionError('native decode reached')) as native:
            with self.assertRaises(ValueError):
                transport.decode(text, archive)
            native.assert_not_called()
        with patch.object(transport, 'CORE', Path('/nonexistent/transport-native-fixture')):
            with patch.object(transport, 'unpack', side_effect=AssertionError('native decode reached')) as native:
                with self.assertRaisesRegex(ValueError, 'dependency'):
                    transport.decode(self.pair.text, self.pair.archive)
                native.assert_not_called()

    def test_rehashing_unverified_declarations_is_not_authentication(self):
        # An author may create a fully coherent new declaration. Integrity cannot
        # authenticate the old author or prove the declared reading.
        sources, plan = fixture('recipe')
        plan['interpretations'][0]['text'] = 'An attacker supplied another reading.'
        changed = self.encoded(sources, plan, budget=1024)
        result = transport.decode(changed.text, changed.archive)
        self.assertEqual(result['interpretations'][0]['text'], plan['interpretations'][0]['text'])
        self.assertEqual(result['assurance']['author_authentication'], 'NOT_AUTHENTICATED')
        self.assertEqual(result['assurance']['interpretation_entailment'], 'UNPROVEN')

    def test_aggregate_limit_across_two_sources(self):
        sources, plan = fixture('opaque')
        with self.assertRaises(ValueError):
            self.encoded((b'x' * MAX_SOURCE, b'x'), plan)

    def test_manifest_wrong_schema_refuses_after_rehash(self):
        entries = read_archive(self.pair.archive)
        manifest = json.loads(entries['manifest.json'])
        manifest['schema'] = 'transport/meaning-zip/999'
        entries['manifest.json'] = canonical(manifest)
        text, archive = rehashed(self.pair, entries)
        with self.assertRaises(ValueError):
            transport.decode(text, archive)


class TransportCLITests(unittest.TestCase):
    def run_cli(self, *args, cwd=None):
        environment = {'PATH': '/usr/bin:/bin', 'PYTHONPATH': str(ROOT / 'tools'),
                       'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'PYTHONWARNINGS': 'error'}
        return subprocess.run([sys.executable, '-W', 'error', str(CLI), *map(str, args)],
                              cwd=cwd, env=environment, capture_output=True, timeout=60, check=False)

    def create(self, root, data=b'opaque\x00\xff\n$(touch SENTINEL)\n'):
        sources, plan = minimal(data)
        source, plan_path = root / 'source.bin', root / 'plan.json'
        source.write_bytes(sources[0])
        plan_path.write_bytes(canonical(plan))
        return source, plan_path

    def test_subprocess_encode_inspect_decode_validate_and_exact_recover(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, plan = self.create(root)
            out = root / 'encoded'
            result = self.run_cli('encode', plan, out, '--source', 'SRC=' + str(source), cwd=root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual({item.name for item in out.iterdir()}, set(cli.NAMES))
            for action in ('inspect', 'decode', 'validate'):
                result = self.run_cli(action, out / 'share.txt', '--archive', out / 'meaning.zip')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn('data', json.loads(result.stdout)['sources'][0])
            recovered = root / 'recovered.bin'
            result = self.run_cli('recover', out / 'share.txt', recovered,
                                  '--archive', out / 'meaning.zip', '--source', 'SRC')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(recovered.read_bytes(), source.read_bytes())
            self.assertFalse((root / 'SENTINEL').exists())

    def test_source_argument_ids_reorder_to_plan_order(self):
        sources, plan = fixture('opaque')
        args = ['EMPTY=' + str(FIXTURES / 'empty.bin'), 'OPAQUE=' + str(FIXTURES / 'opaque.bin')]
        self.assertEqual(cli.source_bytes(canonical(plan), args), sources)

    def test_explicit_sources_exact_match_and_total_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, plan = self.create(root)
            for args in ([], ['SRC=' + str(source)] * 2, ['OTHER=' + str(source)],
                         ['../SRC=' + str(source)], ['SRC='], ['SRC=' + str(source)] * 17):
                with self.subTest(args=args), self.assertRaises(ValueError):
                    cli.source_bytes(plan.read_bytes(), args)
            source.write_bytes(b'x' * (MAX_SOURCE + 1))
            with self.assertRaises(ValueError):
                cli.source_bytes(plan.read_bytes(), ['SRC=' + str(source)])

    def test_budget_refusal_leaves_no_outputs_or_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, plan = self.create(root)
            result = self.run_cli('encode', plan, root / 'out', '--source', 'SRC=' + str(source), '--budget', '1')
            self.assertEqual(result.returncode, 1)
            self.assertIn(b'REFUSED:', result.stderr)
            self.assertFalse((root / 'out').exists())
            self.assertEqual(list(root.glob('.transport-stage-*')), [])

    def test_directory_collision_never_overwrites_even_empty_destination(self):
        for occupied in (False, True):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                destination = root / 'out'
                destination.mkdir()
                if occupied:
                    (destination / 'sentinel').write_bytes(b'keep')
                before = {item.name: item.read_bytes() for item in destination.iterdir()}
                with self.assertRaises(OSError):
                    cli.publish(destination, dict(zip(cli.NAMES, (b'a', b'b', b'c'))))
                self.assertEqual({item.name: item.read_bytes() for item in destination.iterdir()}, before)
                self.assertEqual(list(root.glob('.transport-stage-*')), [])

    def test_publication_failure_cleans_only_owned_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch('transport_cli.write_new', side_effect=OSError('injected write failure')):
                with self.assertRaises(OSError):
                    cli.publish(root / 'out', dict(zip(cli.NAMES, (b'a', b'b', b'c'))))
            self.assertFalse((root / 'out').exists())
            self.assertEqual(list(root.glob('.transport-stage-*')), [])

    def test_atomic_rename_unavailable_refuses_and_cleans(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch('transport_cli.rename_new', side_effect=OSError(errno.ENOSYS, 'unavailable')):
                with self.assertRaises(OSError):
                    cli.publish(root / 'out', dict(zip(cli.NAMES, (b'a', b'b', b'c'))))
            self.assertFalse((root / 'out').exists())
            self.assertEqual(list(root.glob('.transport-stage-*')), [])

    def test_recover_collision_and_missing_id_preserve_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, plan = self.create(root)
            out = root / 'out'
            result = self.run_cli('encode', plan, out, '--source', 'SRC=' + str(source))
            self.assertEqual(result.returncode, 0, result.stderr)
            recovered = root / 'existing'
            recovered.write_bytes(b'preserve')
            for identifier in ('SRC', 'MISSING', '../SRC'):
                result = self.run_cli('recover', out / 'share.txt', recovered,
                                      '--archive', out / 'meaning.zip', '--source', identifier)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(recovered.read_bytes(), b'preserve')

    def test_symlink_source_and_destination_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, plan = self.create(root)
            link = root / 'link'
            link.symlink_to(source)
            result = self.run_cli('encode', plan, root / 'out', '--source', 'SRC=' + str(link))
            self.assertEqual(result.returncode, 1)
            self.assertFalse((root / 'out').exists())
            with self.assertRaises(OSError):
                cli.publish(link, dict(zip(cli.NAMES, (b'a', b'b', b'c'))))
            self.assertTrue(link.is_symlink())
            self.assertEqual(source.read_bytes(), b'opaque\x00\xff\n$(touch SENTINEL)\n')

    def test_publication_is_complete_before_atomic_rename(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            destination = root / 'out'
            real_rename = cli.rename_new
            def observed(stage, target):
                self.assertFalse(destination.exists())
                self.assertEqual({item.name for item in stage.iterdir()}, set(cli.NAMES))
                real_rename(stage, target)
            with patch('transport_cli.rename_new', side_effect=observed):
                cli.publish(destination, dict(zip(cli.NAMES, (b'a', b'b', b'c'))))
            self.assertEqual([ (destination / name).read_bytes() for name in cli.NAMES],
                             [b'a', b'b', b'c'])

    def test_publication_late_failure_leaves_no_partial_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_write = cli.write_new
            def failure(path, data):
                if path.name == 'lexicon.md':
                    raise OSError('injected final-file failure')
                return real_write(path, data)
            with patch('transport_cli.write_new', side_effect=failure):
                with self.assertRaises(OSError):
                    cli.publish(root / 'out', dict(zip(cli.NAMES, (b'a', b'b', b'c'))))
            self.assertEqual(list(root.iterdir()), [])

    def test_atomic_rename_rejects_nul_and_oversize_paths(self):
        for invalid in ('bad\x00path', 'x' * 4096):
            with self.assertRaises(ValueError):
                cli.rename_new(Path('stage'), Path(invalid))

    def test_no_archive_or_reference_fetch(self):
        result = self.run_cli('inspect', FIXTURES / 'recipe.txt')
        self.assertEqual(result.returncode, 2)
        self.assertIn(b'--archive', result.stderr)
        sources, plan = minimal()
        with patch('socket.create_connection', side_effect=AssertionError('network forbidden')):
            pair = transport.encode(sources, canonical(plan), reference='https://live.example/a.zip')
            self.assertEqual(transport.decode(pair.text, pair.archive)['sources'][0]['data'], sources[0])


if __name__ == '__main__':
    unittest.main()
