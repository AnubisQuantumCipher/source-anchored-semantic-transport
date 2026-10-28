"""Incoming declared context is retrieval evidence, never inferred authority."""

import base64
import copy
import itertools
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import transport_package as package
from transport_schema import canonical, sha


def fixture():
    texts = ('Deploy the canary.', 'Revoke the canary instruction.',
             'Weather notes.', 'The revocation scope remains disputed.')
    names = ('ORIGINAL', 'REVISION', 'UNRELATED', 'SCOPE')
    readings, units = [], []
    for index, (name, text) in enumerate(zip(names, texts, strict=True)):
        anchor = dict(source=name, span=[0, len(text.encode())])
        readings.append(dict(id='I' + str(index), label=name, text=text, status='proposed',
            provenance='Synthetic declaration; not authority.', anchors=[anchor]))
        if index < 3:
            meaning = dict(schema='transport/meaning/1', nodes=[
                dict(op='atom', symbol='S0', span=anchor['span'])], root=0, ambiguities=[])
            units.append(dict(id='U' + str(index), source=name, interpretation='I' + str(index),
                kind=('instruction', 'revocation', 'source_claim')[index],
                context=['U0'] if index == 1 else [], plan=dict(schema='transport/encoding-plan/1',
                    symbols={'S0': text}, meaning=meaning)))
    plan = dict(schema='transport/transport-plan/2', sources=[dict(id=name, label=name,
        media_type='text/plain; charset=utf-8', provenance='Synthetic fixture.') for name in names],
        interpretations=readings, meaning_units=units, uncertainties=[dict(id='Q',
            text='Revocation applicability remains unproved.', affects=['U1'],
            anchors=copy.deepcopy(readings[1]['anchors']))], relations=[dict(kind='qualifies',
            **{'from': 'I3', 'to': 'U1'}, note='Declared scope; not an authority decision.',
            anchors=copy.deepcopy(readings[3]['anchors']))])
    return tuple(text.encode() for text in texts), plan


def encode(sources, plan):
    return package.encode(sources, canonical(plan), budget=65536)


def graph_view(contexts):
    return dict(meaning_units=[dict(id='U' + str(index), interpretation='I' + str(index),
                source='S' + str(index), context=['U' + str(parent) for parent in parents])
                for index, parents in enumerate(contexts)], relations=[], uncertainties=[])


def connected_vertices(contexts, start):
    """Independent undirected adjacency traversal for the finite component control."""
    adjacency = [set(parents) for parents in contexts]
    for child, parents in enumerate(contexts):
        for parent in parents:
            adjacency[parent].add(child)
    found, pending = {start}, [start]
    for _ in range(len(contexts)):
        if not pending:
            return found
        vertex = pending.pop()
        for neighbour in sorted(adjacency[vertex]):
            if neighbour not in found:
                found.add(neighbour)
                pending.append(neighbour)
    if pending:
        raise ValueError('independent graph traversal exceeded its vertex bound')
    return found


class ContextRetrievalTests(unittest.TestCase):
    def test_earlier_instruction_retrieves_later_revocation_scope_and_uncertainty(self):
        sources, plan = fixture()
        pair = encode(sources, plan)
        view = package.decode(pair.text, pair.archive)
        self.assertEqual(tuple(item['data'] for item in view['sources']), sources)
        for selected in ('U0', 'U1'):
            with self.subTest(selected=selected):
                focused = package.focus(pair.text, pair.archive, selected)
                self.assertEqual([item['id'] for item in focused['meaning_units']], ['U0', 'U1'])
                self.assertEqual([item['id'] for item in focused['interpretations']], ['I0', 'I1', 'I3'])
                self.assertEqual([item['id'] for item in focused['uncertainties']], ['Q'])
                self.assertEqual([item['id'] for item in focused['sources']], ['ORIGINAL', 'REVISION', 'SCOPE'])
                self.assertEqual([item['context'] for item in focused['meaning_units']], [[], ['U0']])
                self.assertEqual([item['kind'] for item in focused['meaning_units']], ['instruction', 'revocation'])
                self.assertEqual(focused['context_adequacy'], 'UNPROVEN')
                self.assertEqual(focused['execution_authority'], 'NONE')
                self.assertTrue(all(item['representation'] == 'INCOMPLETE' for item in focused['meaning_units']))
                for excerpt in focused['source_excerpts']:
                    position = next(i for i, item in enumerate(plan['sources']) if item['id'] == excerpt['source'])
                    begin, end = excerpt['span']
                    self.assertEqual(base64.b64decode(excerpt['bytes_base64'], validate=True), sources[position][begin:end])
                    self.assertEqual(excerpt['sha256'], sha(sources[position][begin:end]))
                self.assertEqual(canonical(focused), canonical(package.focus(pair.text, pair.archive, selected)))

    def test_incoming_context_is_not_limited_to_a_revocation_kind(self):
        for kind in ('source_claim', 'goal', 'instruction', 'historical_approval', 'revocation', 'pending_action'):
            sources, plan = fixture()
            plan['meaning_units'][1]['kind'] = kind
            pair = encode(sources, plan)
            with self.subTest(kind=kind):
                focused = package.focus(pair.text, pair.archive, 'U0')
                self.assertEqual(focused['meaning_units'][1]['kind'], kind)
                self.assertEqual(focused['execution_authority'], 'NONE')

    def test_shared_source_alone_does_not_select_disconnected_reading(self):
        sources, plan = fixture()
        plan['meaning_units'][2]['source'] = 'ORIGINAL'
        plan['meaning_units'][2]['plan'] = copy.deepcopy(plan['meaning_units'][0]['plan'])
        plan['interpretations'][2]['anchors'] = copy.deepcopy(plan['interpretations'][0]['anchors'])
        pair = encode(sources, plan)
        self.assertEqual([item['id'] for item in package.focus(pair.text, pair.archive, 'U0')['meaning_units']],
                         ['U0', 'U1'])

    def test_missing_context_link_is_not_invented_from_the_word_revocation(self):
        sources, plan = fixture()
        plan['meaning_units'][1]['context'] = []
        pair = encode(sources, plan)
        focused = package.focus(pair.text, pair.archive, 'U0')
        self.assertEqual([item['id'] for item in focused['meaning_units']], ['U0'])
        self.assertEqual(focused['uncertainties'], [])
        self.assertEqual(focused['context_adequacy'], 'UNPROVEN')

    def test_all_four_vertex_backward_context_graphs_match_independent_components(self):
        # Pure traversal control; package validation is exercised by the other cases.
        edges = [(child, parent) for child in range(4) for parent in range(child)]
        for mask in itertools.product((False, True), repeat=len(edges)):
            contexts = [[] for _ in range(4)]
            for present, (child, parent) in zip(mask, edges, strict=True):
                if present:
                    contexts[child].append(parent)
            for selected in range(4):
                vertices = connected_vertices(contexts, selected)
                expected = {prefix + str(index) for index in vertices for prefix in ('U', 'I', 'S')}
                with self.subTest(mask=mask, selected=selected):
                    self.assertEqual(package.focused_ids(graph_view(contexts), 'U' + str(selected)), expected)

    def test_existing_maximum_unit_chain_keeps_all_declared_vertices(self):
        contexts = [[]] + [[index - 1] for index in range(1, 16)]
        expected = {prefix + str(index) for index in range(16) for prefix in ('U', 'I', 'S')}
        for selected in ('U0', 'U7', 'U15'):
            self.assertEqual(package.focused_ids(graph_view(contexts), selected), expected)

    def test_valid_package_with_oversized_complete_focus_refuses_instead_of_trimming(self):
        sources, plan = fixture()
        sources = (sources[0] + b'x' * 6000,) + sources[1:]
        plan['interpretations'][0]['anchors'] = [dict(source='ORIGINAL', span=[0, len(sources[0]) - index])
                                                 for index in range(16)]
        pair = encode(sources, plan)
        self.assertEqual(tuple(item['data'] for item in package.decode(pair.text, pair.archive)['sources']), sources)
        with self.assertRaisesRegex(ValueError, 'canonical output budget exceeded'):
            package.focus(pair.text, pair.archive, 'U0')

    def test_complete_cli_response_reserves_its_final_newline_at_exact_boundary(self):
        # Fixed geometry from the independently retained successful over-cap response.
        for padding in (16, 17):
            sources, plan = fixture()
            sources = (sources[0] + b'x' * 5488,) + sources[1:]
            plan['interpretations'][0]['anchors'] = [dict(source='ORIGINAL', span=[0, len(sources[0]) - index])
                                                     for index in range(16)]
            plan['interpretations'][0]['text'] += 'p' * padding
            pair = encode(sources, plan)
            self.assertEqual(tuple(item['data'] for item in package.decode(pair.text, pair.archive)['sources']), sources)
            with self.subTest(padding=padding), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'share.txt').write_bytes(pair.text)
                (root / 'meaning.zip').write_bytes(pair.archive)
                cli = Path(package.__file__).parent / 'transport_cli.py'
                result = subprocess.run([sys.executable, '-E', '-s', '-S', '-B', '-Werror', str(cli),
                    'focus', str(root / 'share.txt'), '--archive', str(root / 'meaning.zip'), '--unit', 'U0'],
                    capture_output=True, timeout=30, check=False, cwd=root,
                    env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'})
                if padding == 16:
                    focused = package.focus(pair.text, pair.archive, 'U0')
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, b'')
                    self.assertEqual(result.stdout, canonical(focused) + b'\n')
                    self.assertEqual(len(result.stdout), package.MAX_WIRE)
                else:
                    with self.assertRaisesRegex(ValueError, 'focused output including newline'):
                        package.focus(pair.text, pair.archive, 'U0')
                    self.assertEqual(result.returncode, 1)
                    self.assertEqual(result.stdout, b'')
                    self.assertIn(b'REFUSED: Transport focused output including newline', result.stderr)


if __name__ == '__main__':
    unittest.main()
