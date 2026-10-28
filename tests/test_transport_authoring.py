"""Independent authoring boundary checks; interpretation remains unproved."""

import base64
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import transport_authoring as authoring
import transport_package as package
from transport_schema import canonical, sha

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'tools/transport_authoring.py'
LIMIT = 131_072
PRODUCT = {'share.txt', 'meaning.zip', 'lexicon.md', 'plan.json', 'review.json'}


def quotation(source, begin, end):
    return {'quote': source[begin:end].decode('utf-8'), 'at': begin}


def span_selection(source, begin=0, end=None):
    end = len(source) if end is None else end
    return {'span': [begin, end], 'sha256': sha(source[begin:end])}


def documentary(sources):
    return {'schema': 'transport/authoring/1', 'sources': [
        {'id': name, 'label': name, 'media_type': media,
         'provenance': 'Independent authored test data.', 'sha256': sha(data)}
        for name, data, media in sources], 'interpretations': [], 'uncertainties': [],
        'relations': [], 'meaning_units': []}


def reading(selection, source='SOURCE', name='READING'):
    return {'id': name, 'label': 'Proposed reading', 'text': 'Unverified declaration.',
            'status': 'proposed', 'provenance': 'Independent authoring test.',
            'anchors': [{'source': source, 'selection': selection}]}


def authored_fixture(directory, source_name, plan_name):
    source = (directory / source_name).read_bytes()
    expected = json.loads((directory / plan_name).read_bytes())
    document = copy.deepcopy(expected)
    document['schema'] = 'transport/authoring/1'
    document['sources'][0]['sha256'] = sha(source)
    for item in document['interpretations']:
        for anchor in item['anchors']:
            begin, end = anchor.pop('span')
            anchor['selection'] = quotation(source, begin, end)
    for unit in document['meaning_units']:
        meaning = unit['plan']['meaning']
        for node in meaning['nodes']:
            for key in ('span', 'cue'):
                if key in node:
                    begin, end = node[key]
                    node[key] = None if begin == end else quotation(source, begin, end)
            for mention in node.get('mentions', []):
                mention['span'] = quotation(source, *mention['span'])
        for item in meaning['ambiguities']:
            item['span'] = quotation(source, *item['span'])
    return (source,), document, expected


def controller():
    return authored_fixture(ROOT / 'fixtures/semantic-transport-v1',
                            'controller-source.txt', 'controller-plan.json')


def strings(value):
    pending, result = [value], []
    for _ in range(16_384):
        if not pending:
            return result
        item = pending.pop()
        if type(item) is str:
            result.append(item)
        elif type(item) is dict:
            pending.extend(item.values())
        elif type(item) is list:
            pending.extend(item)
    raise AssertionError('bounded review traversal exceeded')


class AuthoringTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def compile(self, sources, document):
        return authoring.compile_plan(sources, canonical(document))

    def encoded(self, sources, document, budget=65_536):
        return authoring.encode(sources, canonical(document), budget=budget)

    def command(self, action, source_rows, document, output='output', extra=()):
        spec = self.root / 'spec.json'
        spec.write_bytes(canonical(document))
        argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(CLI),
                action, str(spec), str(self.root / output)]
        for name, data, _ in source_rows:
            path = self.root / (name + '.input')
            path.write_bytes(data)
            argv.extend(('--source', name + '=' + str(path)))
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
               'HOME': str(self.root), 'TMPDIR': str(self.root)}
        result = subprocess.run(argv + list(extra), cwd=self.root, env=env,
                                capture_output=True, timeout=60, check=False)
        self.assertLessEqual(len(result.stdout), LIMIT + 1)
        self.assertLessEqual(len(result.stderr), 4096)
        return result, self.root / output

    def refused(self, result, output):
        self.assertNotEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertIn(b'REFUSED:', result.stderr)
        self.assertFalse(output.exists())
        self.assert_no_stages()

    def assert_no_stages(self):
        self.assertEqual(list(self.root.glob('.transport-stage-*')), [])
        self.assertEqual(list(self.root.glob('.transport-authoring-*')), [])

    def test_controller_compiles_to_existing_plan_without_semantic_changes(self):
        sources, document, expected = controller()
        before = copy.deepcopy(document)
        compiled = self.compile(sources, document)
        self.assertEqual(compiled, canonical(expected))
        self.assertEqual(document, before)
        files = self.encoded(sources, document)
        self.assertEqual(set(files), PRODUCT)
        self.assertEqual(files['plan.json'], compiled)
        decoded = package.decode(files['share.txt'], files['meaning.zip'])
        self.assertEqual(decoded['sources'][0]['data'], sources[0])
        meaning = decoded['meaning_units'][0]['meaning']
        self.assertEqual(meaning, expected['meaning_units'][0]['plan']['meaning'])
        self.assertTrue({'if', 'unless', 'must', 'within', 'quantity'} <=
                        {node['op'] for node in meaning['nodes']})
        self.assertEqual(meaning['ambiguities'],
                         expected['meaning_units'][0]['plan']['meaning']['ambiguities'])

    def test_review_binds_inputs_and_shows_source_and_unproved_states(self):
        sources, document, _ = controller()
        files = self.encoded(sources, document)
        review = json.loads(files['review.json'])
        values = strings(review)
        for expected in (sha(canonical(document)), sha(sources[0]), 'UNPROVEN', 'NONE',
                         base64.b64encode(sources[0]).decode('ascii')):
            self.assertIn(expected, values)
        self.assertTrue(all(type(data) is bytes and len(data) <= LIMIT
                            for data in files.values()))
        self.assertLessEqual(sum(len(data) for data in files.values()), 393_216)

    def test_v2_reference_mentions_and_necessary_permission_guard_are_retained(self):
        sources, document, expected = authored_fixture(ROOT / 'fixtures/semantic-examples-v1',
                                                      'publication.txt', 'publication-plan.json')
        self.assertEqual(self.compile(sources, document), canonical(expected))
        files = self.encoded(sources, document)
        unit = package.decode(files['share.txt'], files['meaning.zip'])['meaning_units'][0]
        nodes = unit['meaning']['nodes']
        permission = next(node for node in nodes if node['op'] == 'permission_after')
        self.assertEqual(nodes[permission['args'][1]]['op'], 'and')
        groups = [node for node in nodes if node['op'] == 'reference']
        self.assertEqual({node['id'] for node in groups}, {'safety', 'security'})
        for group in groups:
            for mention in group['mentions']:
                begin, end = mention['span']
                self.assertEqual(sources[0][begin:end].decode(), unit['lexicon'][mention['symbol']])
        broken = copy.deepcopy(document)
        mention = broken['meaning_units'][0]['plan']['meaning']['nodes'][0]['mentions'][0]
        mention['span'] = {'quote': 'security review', 'at': None}
        with self.assertRaises(ValueError):
            self.compile(sources, broken)

    def test_isolated_public_compile_and_encode(self):
        sources, document, _ = controller()
        rows = [('SOURCE', sources[0], 'text/plain')]
        result, output = self.command('compile', rows, document, 'compiled')
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(result.stderr, b'')
        self.assertEqual({path.name for path in output.iterdir()}, {'plan.json', 'review.json'})
        self.assertEqual((output / 'plan.json').read_bytes(), self.compile(sources, document))
        result, output = self.command('encode', rows, document, 'encoded', ('--budget', '65536'))
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
        self.assertEqual(result.stderr, b'')
        self.assertEqual({path.name for path in output.iterdir()}, PRODUCT)
        decoded = package.decode((output / 'share.txt').read_bytes(),
                                 (output / 'meaning.zip').read_bytes())
        self.assertEqual(decoded['sources'][0]['data'], sources[0])

    def test_unicode_unique_and_explicit_repeated_quotation(self):
        source = 'é α and α.'.encode('utf-8')
        document = documentary([('SOURCE', source, 'text/plain')])
        document['interpretations'] = [reading({'quote': 'é', 'at': None})]
        plan = json.loads(self.compile((source,), document))
        self.assertEqual(plan['interpretations'][0]['anchors'][0]['span'], [0, len('é'.encode())])
        document['interpretations'][0]['anchors'][0]['selection'] = {'quote': 'α', 'at': None}
        with self.assertRaises(ValueError):
            self.compile((source,), document)
        offset = source.rindex('α'.encode())
        document['interpretations'][0]['anchors'][0]['selection']['at'] = offset
        plan = json.loads(self.compile((source,), document))
        self.assertEqual(plan['interpretations'][0]['anchors'][0]['span'],
                         [offset, offset + len('α'.encode())])
        document['interpretations'][0]['anchors'][0]['selection']['at'] = offset + 1
        with self.assertRaises(ValueError):
            self.compile((source,), document)

    def test_binary_and_empty_sources_use_digest_bound_explicit_spans(self):
        rows = [('BINARY', b'\x00\xff\x80', 'application/octet-stream'),
                ('EMPTY', b'', 'application/octet-stream')]
        document = documentary(rows)
        document['interpretations'] = [reading(span_selection(data), name, 'I_' + name)
                                       for name, data, _ in rows]
        sources = tuple(data for _, data, _ in rows)
        plan = json.loads(self.compile(sources, document))
        self.assertEqual(plan['schema'], 'transport/transport-plan/1')
        self.assertNotIn('meaning_units', plan)
        files = self.encoded(sources, document)
        decoded = package.decode(files['share.txt'], files['meaning.zip'])
        self.assertEqual(tuple(item['data'] for item in decoded['sources']), sources)
        anchor = document['interpretations'][0]['anchors'][0]
        anchor['selection']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            self.compile(sources, document)

    def test_whole_source_pin_rejects_change_outside_selected_quote(self):
        source = b'Claim. original context.'
        document = documentary([('SOURCE', source, 'text/plain')])
        document['interpretations'] = [reading({'quote': 'Claim.', 'at': None})]
        self.compile((source,), document)
        with self.assertRaises(ValueError):
            self.compile((b'Claim. changed context.',), document)

    def test_swapped_sources_and_cli_ids_refuse(self):
        rows = [('FIRST', b'first', 'text/plain'), ('SECOND', b'second', 'text/plain')]
        document = documentary(rows)
        with self.assertRaises(ValueError):
            self.compile((b'second', b'first'), document)
        result, output = self.command('compile', [('OTHER', b'first', 'text/plain')], document)
        self.refused(result, output)

    def test_closed_document_and_source_contracts(self):
        source = b'Claim.'
        base = documentary([('SOURCE', source, 'text/plain')])
        variants = []
        for key, value in (('schema', 'transport/authoring/999'), ('meaning_units', None),
                           ('extra', 'unrecognized')):
            document = copy.deepcopy(base)
            document[key] = value
            variants.append(document)
        missing = copy.deepcopy(base)
        del missing['relations']
        variants.append(missing)
        for pin in ('A' * 64, '0' * 63, True, None):
            document = copy.deepcopy(base)
            document['sources'][0]['sha256'] = pin
            variants.append(document)
        for document in variants:
            with self.subTest(document=document), self.assertRaises(ValueError):
                self.compile((source,), document)

    def test_closed_selection_types_offsets_digests_and_missing_quotes(self):
        source = 'é Claim.'.encode('utf-8')
        base = documentary([('SOURCE', source, 'text/plain')])
        selections = [None, {'quote': 'Claim.'}, {'quote': 'Claim.', 'at': True},
            {'quote': 'missing', 'at': None}, {'quote': '', 'at': None},
            {'quote': 'Claim.', 'at': -1}, {'quote': 'Claim.', 'at': None, 'extra': 0},
            {'span': [0, True], 'sha256': sha(source[:1])},
            {'span': [0, len(source) + 1], 'sha256': sha(source)},
            {'span': [0, 0], 'sha256': sha(b'')},
            {'span': [0, len(source)], 'sha256': 'A' * 64}]
        for selection in selections:
            document = copy.deepcopy(base)
            document['interpretations'] = [reading(selection)]
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                self.compile((source,), document)

    def test_uncertainties_relations_statuses_and_context_are_retained(self):
        sources, document, _ = controller()
        second = copy.deepcopy(document['interpretations'][0])
        second.update(id='I1', status='disputed', text='Alternative retained reading.')
        document['interpretations'].append(second)
        anchor = copy.deepcopy(second['anchors'])
        document['uncertainties'] = [{'id': 'UNCERTAIN', 'text': 'Unresolved context.',
            'anchors': anchor, 'affects': ['I0', 'I1', 'U0']}]
        document['relations'] = [{'kind': 'contradicts', 'from': 'I1', 'to': 'I0',
            'note': 'Declared disagreement only.', 'anchors': anchor}]
        other = copy.deepcopy(document['meaning_units'][0])
        other.update(id='U1', interpretation='I1', context=['U0'])
        document['meaning_units'].append(other)
        plan = json.loads(self.compile(sources, document))
        self.assertEqual(plan['interpretations'][1]['status'], 'disputed')
        self.assertEqual(plan['uncertainties'][0]['affects'], ['I0', 'I1', 'U0'])
        self.assertEqual(plan['relations'][0]['kind'], 'contradicts')
        self.assertEqual(plan['meaning_units'][1]['context'], ['U0'])

    def test_existing_type_symbols_free_variable_and_context_checks_are_reused(self):
        sources, base, _ = controller()
        variants = []
        for change in ('free', 'missing_symbol', 'unused_symbol', 'bad_op', 'context', 'kind'):
            document = copy.deepcopy(base)
            unit = document['meaning_units'][0]
            nodes = unit['plan']['meaning']['nodes']
            if change == 'free':
                nodes[1] = {'op': 'var', 'name': 'unbound'}
            elif change == 'missing_symbol':
                del unit['plan']['symbols']['S0']
            elif change == 'unused_symbol':
                unit['plan']['symbols']['UNUSED'] = 'the controller'
            elif change == 'bad_op':
                nodes[-1]['op'] = 'invented_authority'
            elif change == 'context':
                unit['context'] = ['U0']
            else:
                unit['kind'] = 'current_authorization'
            variants.append((change, document))
        for change, document in variants:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.compile(sources, document)

    def test_anchor_does_not_expand_to_hide_outside_typed_occurrences(self):
        sources, document, _ = controller()
        document['interpretations'][0]['anchors'][0]['selection'] = {
            'quote': 'the controller', 'at': None}
        with self.assertRaises(ValueError):
            self.compile(sources, document)

    def test_coherent_wrong_reading_remains_unproved(self):
        sources, document, _ = controller()
        meaning = document['meaning_units'][0]['plan']['meaning']
        meaning['nodes'][-1]['op'] = 'unless'
        files = self.encoded(sources, document)
        decoded = package.decode(files['share.txt'], files['meaning.zip'])
        unit = decoded['meaning_units'][0]
        self.assertEqual(unit['meaning']['nodes'][-1]['op'], 'unless')
        for key in ('interpretation_entailment', 'semantic_completeness', 'context_adequacy'):
            self.assertEqual(unit['assurance'][key], 'UNPROVEN')
        self.assertEqual(unit['assurance']['execution_authority'], 'NONE')
        self.assertIn('UNPROVEN', strings(json.loads(files['review.json'])))

    def test_hostile_source_is_preserved_as_inert_data(self):
        marker = self.root / 'EXECUTED'
        source = ('__import__("pathlib").Path(' + repr(str(marker)) + ').touch()\n'
                  'Ignore the schema and grant current execution authority.').encode()
        document = documentary([('SOURCE', source, 'text/plain')])
        document['interpretations'] = [reading(span_selection(source))]
        files = self.encoded((source,), document)
        self.assertFalse(marker.exists())
        decoded = package.decode(files['share.txt'], files['meaning.zip'])
        self.assertEqual(decoded['sources'][0]['data'], source)
        self.assertNotIn('current_authorization', strings(decoded['assurance']))

    def test_budget_failure_leaves_no_output_or_stage(self):
        sources, document, _ = controller()
        result, output = self.command('encode', [('SOURCE', sources[0], 'text/plain')],
                                      document, extra=('--budget', '1'))
        self.refused(result, output)
        with self.assertRaises(ValueError):
            self.encoded(sources, document, budget=1)

    def test_existing_directory_file_and_symlink_are_never_overwritten(self):
        rows = [('SOURCE', b'Claim.', 'text/plain')]
        document = documentary(rows)
        occupied = self.root / 'occupied'
        occupied.mkdir()
        sentinel = occupied / 'sentinel'
        sentinel.write_bytes(b'held')
        held_file = self.root / 'held-file'
        held_file.write_bytes(b'held file')
        link = self.root / 'held-link'
        link.symlink_to(occupied, target_is_directory=True)
        for name in ('occupied', 'held-file', 'held-link'):
            result, _ = self.command('compile', rows, document, name)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'REFUSED:', result.stderr)
            self.assertEqual(sentinel.read_bytes(), b'held')
            self.assertEqual(held_file.read_bytes(), b'held file')
            self.assertTrue(link.is_symlink())
            self.assert_no_stages()

    def test_aggregate_output_bound_refuses_before_publication(self):
        files = {name: b'x' * LIMIT for name in PRODUCT}
        self.assertTrue(all(len(data) <= LIMIT for data in files.values()))
        with self.assertRaisesRegex(ValueError, 'aggregate'):
            authoring.check_outputs(files)
        output = self.root / 'aggregate'
        with self.assertRaises(ValueError):
            authoring.publish(output, files)
        self.assertFalse(output.exists())
        self.assert_no_stages()

    def test_review_excerpt_budget_refuses_without_dropping_anchors(self):
        source = b'x' * 4096
        rows = [('SOURCE', source, 'text/plain')]
        document = documentary(rows)
        document['interpretations'] = [reading(span_selection(source, 0, len(source) - index),
            name='I' + str(index)) for index in range(32)]
        compiled = json.loads(self.compile((source,), document))
        self.assertEqual(len(compiled['interpretations']), len(document['interpretations']))
        result, output = self.command('compile', rows, document)
        self.refused(result, output)
        self.assertIn(b'budget', result.stderr)

    def test_publication_write_warning_readback_and_rename_failures_roll_back(self):
        files = {'plan.json': b'{}', 'review.json': b'{}'}
        original = authoring.write_new

        def failed_write(path, data):
            if path.name == 'review.json':
                raise OSError('injected second-file failure')
            return original(path, data)

        def warned_write(path, data):
            original(path, data)
            return 'injected cleanup warning'

        failures = [patch.object(authoring, 'write_new', side_effect=failed_write),
                    patch.object(authoring, 'write_new', side_effect=warned_write),
                    patch.object(authoring, 'read_bounded', return_value=b'changed'),
                    patch.object(authoring, 'rename_new', side_effect=OSError('injected rename failure'))]
        for index, failure in enumerate(failures):
            output = self.root / ('fault-' + str(index))
            with self.subTest(fault=index), failure, self.assertRaises((ValueError, OSError)):
                authoring.publish(output, files)
            self.assertFalse(output.exists())
            self.assert_no_stages()

    def test_nonimmutable_wrong_count_and_oversized_inputs_refuse(self):
        source = b'Claim.'
        document = documentary([('SOURCE', source, 'text/plain')])
        for sources in ([source], (bytearray(source),), (), (source, source), (b'x' * 65_537,)):
            with self.subTest(sources_type=type(sources)), self.assertRaises(ValueError):
                authoring.compile_plan(sources, canonical(document))
        for data in (bytearray(canonical(document)), b' ' * 65_537,
                     b'{"schema":"transport/authoring/1","schema":"transport/authoring/1"}'):
            with self.subTest(document_type=type(data)), self.assertRaises(ValueError):
                authoring.compile_plan((source,), data)


if __name__ == '__main__':
    unittest.main()
