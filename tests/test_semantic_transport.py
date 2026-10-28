"""Typed documentary connections retain source evidence without granting authority."""

import argparse
import base64
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import transport_cli as cli
import transport_codec as codec
import transport_package as package
from transport_archive import read_archive, write_archive
from transport_schema import canonical, sha

ROOT = Path(__file__).resolve().parents[1]
CORPUS = json.loads((ROOT / 'corpus/codec-cases.json').read_bytes())['cases']
SEMANTICS = json.loads((ROOT / 'corpus/codec-semantics-cases.json').read_bytes())['cases']
BUDGET = 65_536


def selected(name, cases=CORPUS):
    return copy.deepcopy(next(item for item in cases if item['id'] == name))


def connected(case, count=1):
    source = case['source'].encode('utf-8')
    readings = [dict(id='I' + str(index), label='Declared reading', text='Supplied interpretation.',
        status='proposed', provenance='Authored test corpus; interpretation remains unproved.',
        anchors=[dict(source='SOURCE', span=[0, len(source)])]) for index in range(count)]
    units = [dict(id='U' + str(index), source='SOURCE', interpretation='I' + str(index),
        kind='source_claim', context=[], plan=copy.deepcopy(case['plan'])) for index in range(count)]
    plan = dict(schema='transport/transport-plan/2', sources=[dict(id='SOURCE', label=case['id'],
        media_type='text/plain; charset=utf-8', provenance='Retained authored corpus source.')],
        interpretations=readings, uncertainties=[], relations=[], meaning_units=units)
    return (source,), plan


def small_case():
    return dict(id='RESIDUAL', source='Claim. Unrepresented residual text.', plan=dict(
        schema='transport/encoding-plan/1', symbols={'S0': 'Claim'}, meaning=dict(
        schema='transport/meaning/1', nodes=[dict(op='text', symbol='S0', span=[0, 5]),
        dict(op='pred', args=[0], cue=[0, 0])], root=1, ambiguities=[])))


def encode(sources, plan, budget=BUDGET):
    return package.encode(sources, canonical(plan), budget=budget)


def unit(pair):
    return package.decode(pair.text, pair.archive)['meaning_units'][0]


def rehashed(pair, change):
    entries = read_archive(pair.archive)
    value = json.loads(entries['codec.json'])
    change(value)
    entries['codec.json'] = canonical(value)
    manifest = json.loads(entries['manifest.json'])
    for item in manifest['body']['entries']:
        name = item['name']
        item.update(bytes=len(entries[name]), sha256=sha(entries[name]))
    manifest['sha256'] = sha(canonical(manifest['body']))
    entries['manifest.json'] = canonical(manifest)
    lines = pair.text.split(b'\n')
    lines[1] = b'STS1:' + manifest['sha256'].encode('ascii')
    return b'\n'.join(lines), write_archive(entries)


class SemanticTransportTests(unittest.TestCase):
    def assert_residual_metadata(self, gaps, source, source_id='SOURCE'):
        for gap in gaps:
            self.assertEqual(set(gap), {'span', 'bytes', 'sha256', 'text_location'})
            begin, end = gap['span']
            data = source[begin:end]
            self.assertEqual(gap['bytes'], len(data))
            self.assertEqual(gap['sha256'], sha(data))
            self.assertIn('recover', gap['text_location'])
            self.assertIn(source_id, gap['text_location'])

    def test_every_existing_corpus_case_has_exact_typed_content_dictionaries_and_source(self):
        for case in CORPUS + SEMANTICS:
            with self.subTest(case=case['id'], grammar=case['plan']['meaning']['schema']):
                sources, plan = connected(case)
                paired = encode(sources, plan)
                actual = package.decode(paired.text, paired.archive)
                expected = codec.decode(codec.encode(sources[0], canonical(case['plan'])).package)
                typed = actual['meaning_units'][0]
                self.assertEqual(actual['schema'], 'transport/decoded/2')
                self.assertEqual(actual['sources'][0]['data'], sources[0])
                self.assertEqual(typed['meaning'], expected['meaning'])
                self.assertEqual(typed['grammar'], case['plan']['meaning']['schema'])
                self.assertEqual(typed['lexicon'], expected['lexicon'])
                self.assertEqual(typed['operator_definitions'], expected['operator_definitions'])
                self.assertEqual(typed['formula'], expected['formula'])
                self.assert_residual_metadata(typed['residuals'], sources[0])
                canonical(package.inspect(paired.text, paired.archive))
                self.assertEqual(typed['representation'], expected['representation'])
                self.assertEqual([item['span'] for item in typed['residuals']],
                                 [item['span'] for item in expected['residuals']])
                self.assertEqual({item['role'] for item in typed['dictionaries']}, {'operators', 'symbols'})
                self.assertTrue(all('content' not in item for item in typed['dictionaries']))
                self.assertIn(b'M[U0:source_claim', paired.text)
                self.assertEqual(read_archive(paired.archive)['README.md'], paired.lexicon)
                self.assertEqual(typed['assurance']['execution_authority'], 'NONE')
                self.assertEqual(typed['assurance']['interpretation_entailment'], 'UNPROVEN')
                self.assertEqual(typed['assurance']['semantic_completeness'], 'UNPROVEN')

    def test_controller_keeps_actor_exception_quantity_and_all_every_quantifiers(self):
        sources, plan = connected(selected('CONTROLLER'))
        typed = unit(encode(sources, plan))
        ops = [node['op'] for node in typed['meaning']['nodes']]
        self.assertTrue({'if', 'unless', 'within', 'must', 'quantity'} <= set(ops))
        self.assertIn('100', typed['lexicon'].values())
        self.assertIn('ms', typed['lexicon'].values())
        self.assertIn('the controller', typed['lexicon'].values())
        sources, plan = connected(selected('ALL_CONTROLLERS'))
        typed = unit(encode(sources, plan))
        self.assertEqual([node['op'] for node in typed['meaning']['nodes']].count('all'), 2)
        self.assertIn('unless', [node['op'] for node in typed['meaning']['nodes']])

    def test_publication_requires_both_review_references_without_current_approval(self):
        sources, plan = connected(selected('PARALLEL_BOTH', SEMANTICS))
        typed = unit(encode(sources, plan))
        nodes = typed['meaning']['nodes']
        permission = next(node for node in nodes if node['op'] == 'permission_after')
        both = nodes[permission['args'][1]]
        parallel = next(node for node in nodes if node['op'] == 'parallel')
        completed = {nodes[index]['args'][1] for index in both['args']}
        running = {nodes[index]['args'][1] for index in parallel['args']}
        self.assertEqual(both['op'], 'and')
        self.assertEqual(completed, running)
        self.assertEqual(len(completed), 2)
        self.assertEqual(typed['assurance']['execution_authority'], 'NONE')

    def test_emotional_reading_has_no_invented_literals_or_meaning_nodes(self):
        case = selected('EMOTION')
        sources, plan = connected(case)
        typed = unit(encode(sources, plan))
        self.assertEqual(typed['lexicon'], case['plan']['symbols'])
        self.assertEqual(typed['meaning'], case['plan']['meaning'])
        self.assertEqual(set(node['op'] for node in typed['meaning']['nodes']), {'atom', 'and'})
        self.assertEqual(typed['representation'], 'INCOMPLETE')

    def test_all_declared_minimal_pairs_remain_distinct(self):
        for left, right in (('ALL', 'SOME'), ('MUST', 'MAY'), ('BEFORE', 'AFTER'),
                            ('IF', 'UNLESS'), ('BELIEF', 'FACT')):
            with self.subTest(left=left, right=right):
                first_source, first_plan = connected(selected(left))
                second_source, second_plan = connected(selected(right))
                first, second = encode(first_source, first_plan), encode(second_source, second_plan)
                self.assertNotEqual(first.text, second.text)
                self.assertNotEqual(unit(first)['meaning'], unit(second)['meaning'])
                self.assertEqual(package.decode(first.text, first.archive)['sources'][0]['data'], first_source[0])
                self.assertEqual(package.decode(second.text, second.archive)['sources'][0]['data'], second_source[0])

    def test_incomplete_representation_has_exact_residuals_and_source_fallback(self):
        sources, plan = connected(small_case())
        paired = encode(sources, plan)
        decoded = package.decode(paired.text, paired.archive)
        typed = decoded['meaning_units'][0]
        self.assertEqual(typed['representation'], 'INCOMPLETE')
        self.assertTrue(typed['residuals'])
        self.assert_residual_metadata(typed['residuals'], sources[0])
        self.assertEqual(decoded['sources'][0]['data'], sources[0])
        inspected = package.inspect(paired.text, paired.archive)
        self.assertNotIn('data', inspected['sources'][0])
        self.assertEqual(inspected['meaning_units'][0], typed)

    def test_nul_residual_metadata_is_bounded_and_source_remains_exact(self):
        case = small_case()
        case['source'] = 'Claim.' + '\x00' * 22_000
        sources, plan = connected(case)
        paired = encode(sources, plan)
        decoded = package.decode(paired.text, paired.archive)
        inspected = package.inspect(paired.text, paired.archive)
        self.assertEqual(decoded['sources'][0]['data'], b'Claim.' + b'\x00' * 22_000)
        self.assertEqual(inspected['meaning_units'][0]['representation'], 'INCOMPLETE')
        self.assertEqual(inspected['meaning_units'][0]['residuals'][0]['span'], [5, len(sources[0])])
        self.assert_residual_metadata(inspected['meaning_units'][0]['residuals'], sources[0])
        self.assertLessEqual(len(canonical(inspected)), package.MAX_WIRE)
        self.assertEqual(package.validate(paired.text, paired.archive), inspected)

    def test_cli_inspect_validate_and_explicit_recover_nul_residual(self):
        case = small_case()
        case['source'] = 'Claim.' + '\x00' * 22_000
        sources, plan = connected(case)
        paired = encode(sources, plan)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            share, archive, recovered = root / 'share.txt', root / 'meaning.zip', root / 'recovered'
            share.write_bytes(paired.text)
            archive.write_bytes(paired.archive)
            for action in ('inspect', 'validate', 'recover'):
                argv = [sys.executable, '-B', '-Werror', str(ROOT / 'tools/transport_cli.py'),
                        action, str(share)]
                if action == 'recover':
                    argv.append(str(recovered))
                    argv += ['--source', 'SOURCE']
                argv += ['--archive', str(archive)]
                result = subprocess.run(argv, cwd=root, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'},
                    capture_output=True, timeout=60, check=False)
                with self.subTest(action=action):
                    self.assertEqual(result.returncode, 0, (result.stdout, result.stderr))
                    value = json.loads(result.stdout)
                    self.assertEqual(result.stderr, b'')
                    if action != 'recover':
                        self.assert_residual_metadata(value['meaning_units'][0]['residuals'], sources[0])
                        self.assertNotIn('data', value['sources'][0])
                    else:
                        self.assertEqual(recovered.read_bytes(), sources[0])
                        self.assertEqual(value['sha256'], sha(sources[0]))

    def test_uninterpreted_binary_source_can_accompany_typed_text_exactly(self):
        sources, plan = connected(small_case())
        binary = b'\xff\x00\xfe'
        plan['sources'].append(dict(id='BINARY', label='Uninterpreted bytes',
            media_type='application/octet-stream', provenance='Controlled fixture.'))
        paired = encode(sources + (binary,), plan)
        value = package.decode(paired.text, paired.archive)
        self.assertEqual(tuple(item['data'] for item in value['sources']), sources + (binary,))
        self.assertEqual(value['meaning_units'][0]['source'], 'SOURCE')

    def test_input_mutation_and_duplicate_source_frames_are_absent(self):
        sources, plan = connected(selected('CONTROLLER'))
        before = canonical(plan)
        paired = encode(sources, plan)
        self.assertEqual(canonical(plan), before)
        codec_value = json.loads(read_archive(paired.archive)['codec.json'])
        self.assertEqual(len(codec_value['source_frames']), 1)
        stored = codec_value['plan']['meaning_units'][0]
        self.assertNotIn('plan', stored)
        self.assertNotIn('source_frame', stored)
        self.assertNotIn('frame_hex', canonical(stored).decode())
        self.assertEqual(codec_value['schema'], 'transport/codec/2')

    def test_all_unit_kinds_and_interpretation_statuses_grant_no_authority(self):
        for kind in ('source_claim', 'goal', 'instruction', 'historical_approval', 'revocation', 'pending_action'):
            sources, plan = connected(small_case())
            plan['meaning_units'][0]['kind'] = kind
            typed = unit(encode(sources, plan))
            self.assertEqual(typed['kind'], kind)
            self.assertEqual(typed['assurance']['execution_authority'], 'NONE')
        for status in ('proposed', 'disputed', 'withdrawn'):
            sources, plan = connected(small_case())
            plan['interpretations'][0]['status'] = status
            self.assertEqual(unit(encode(sources, plan))['assurance']['execution_authority'], 'NONE')

    def test_unknown_fields_kinds_statuses_and_global_identifier_collisions_refuse(self):
        for change in ('field', 'kind', 'status', 'collision', 'unknown-source', 'unknown-reading', 'count'):
            sources, plan = connected(small_case())
            item = plan['meaning_units'][0]
            if change == 'field':
                item['trusted'] = True
            elif change == 'kind':
                item['kind'] = 'current_authorization'
            elif change == 'status':
                plan['interpretations'][0]['status'] = 'verified'
            elif change == 'collision':
                item['id'] = 'SOURCE'
            elif change == 'unknown-source':
                item['source'] = 'MISSING'
            elif change == 'unknown-reading':
                item['interpretation'] = 'MISSING'
            else:
                sources, plan = connected(small_case(), 17)
            with self.subTest(change=change), self.assertRaises(ValueError):
                encode(sources, plan)

    def test_bad_types_binding_cycles_grammar_and_versions_refuse(self):
        for change in ('type', 'binding', 'cycle', 'grammar', 'version'):
            sources, plan = connected(selected('ALL_CONTROLLERS'))
            typed = plan['meaning_units'][0]['plan']
            nodes = typed['meaning']['nodes']
            quantifier = next(node for node in nodes if node['op'] == 'all')
            if change == 'type':
                nodes[-1]['args'][0] = True
            elif change == 'binding':
                quantifier['args'][0] = quantifier['args'][1]
            elif change == 'cycle':
                nodes[-1]['args'][-1] = len(nodes) - 1
            elif change == 'grammar':
                typed['meaning']['schema'] = 'transport/meaning/999'
            else:
                typed['schema'] = 'transport/encoding-plan/999'
            with self.subTest(change=change), self.assertRaises(ValueError):
                encode(sources, plan)

    def test_changed_numeric_dictionary_literal_refuses(self):
        sources, plan = connected(selected('CONTROLLER'))
        symbols = plan['meaning_units'][0]['plan']['symbols']
        key = next(name for name, text in symbols.items() if text == '100')
        symbols[key] = '101'
        with self.assertRaisesRegex(ValueError, 'symbol occurrence mismatch'):
            encode(sources, plan)

    def test_every_leaf_cue_and_reference_mention_requires_interpretation_anchor(self):
        for case in (selected('CONTROLLER'), selected('PARALLEL_BOTH', SEMANTICS)):
            sources, plan = connected(case)
            plan['interpretations'][0]['anchors'][0]['span'] = [0, 1]
            with self.subTest(case=case['id']), self.assertRaises(ValueError):
                encode(sources, plan)
        sources, plan = connected(small_case())
        plan['sources'].append(dict(plan['sources'][0], id='OTHER'))
        plan['meaning_units'][0]['source'] = 'OTHER'
        with self.assertRaises(ValueError):
            encode(sources + sources, plan)

    def test_ambiguity_outside_interpretation_anchor_refuses(self):
        case = small_case()
        case['source'] = 'Claim. tail'
        case['plan']['meaning']['ambiguities'] = [dict(span=[7, 11], note='Unresolved tail context.')]
        sources, plan = connected(case)
        plan['interpretations'][0]['anchors'][0]['span'] = [0, 6]
        with self.assertRaisesRegex(ValueError, 'outside.*anchors'):
            encode(sources, plan)

    def test_context_cycles_forward_missing_duplicate_and_swapped_references_refuse(self):
        for context in (['U0'], ['U1'], ['MISSING'], ['U0', 'U0'], [True]):
            sources, plan = connected(small_case(), 2)
            target = plan['meaning_units'][1] if context == ['U0', 'U0'] else plan['meaning_units'][0]
            target['context'] = context
            with self.subTest(context=context), self.assertRaises(ValueError):
                encode(sources, plan)
        sources, plan = connected(small_case(), 2)
        plan['meaning_units'][0]['context'] = ['U1']
        plan['meaning_units'][1]['context'] = ['U0']
        with self.assertRaises(ValueError):
            encode(sources, plan)

    def test_rehashed_missing_dictionary_bad_grammar_and_numeric_dictionary_refuse(self):
        sources, plan = connected(selected('CONTROLLER'))
        paired = encode(sources, plan)
        for change in ('missing', 'grammar', 'version', 'number', 'type'):
            def alter(value):
                item = value['plan']['meaning_units'][0]
                if change == 'missing':
                    item['dictionaries'].pop()
                elif change == 'grammar':
                    item['grammar'] = 'transport/meaning/999'
                elif change == 'version':
                    value['schema'] = 'transport/codec/999'
                elif change == 'number':
                    reference = next(entry for entry in item['dictionaries'] if entry['role'] == 'symbols')
                    key = next(key for key, text in reference['content']['entries'].items() if text == '100')
                    reference['content']['entries'][key] = '101'
                    reference['sha256'] = sha(canonical(reference['content']))
                else:
                    item['meaning']['nodes'][-1]['args'][0] = True
            text, archive = rehashed(paired, alter)
            with self.subTest(change=change), self.assertRaises(ValueError):
                package.decode(text, archive)

    def test_raw_source_and_anchor_digest_tamper_refuse_even_with_rehashed_outer_identity(self):
        sources, plan = connected(small_case())
        paired = encode(sources, plan)
        for change in ('source', 'anchor'):
            def alter(value):
                if change == 'source':
                    value['source_frames'][0]['sha256'] = '0' * 64
                else:
                    value['plan']['interpretations'][0]['anchors'][0]['sha256'] = '0' * 64
            text, archive = rehashed(paired, alter)
            with self.subTest(change=change), self.assertRaises(ValueError):
                package.decode(text, archive)

    def test_valid_wrong_reading_requires_external_identity_or_independent_assessment(self):
        sources, plan = connected(selected('ALL'))
        original = encode(sources, plan)
        altered = copy.deepcopy(plan)
        nodes = altered['meaning_units'][0]['plan']['meaning']['nodes']
        next(node for node in nodes if node['op'] == 'all')['op'] = 'some'
        wrong_reading = encode(sources, altered)
        accepted = unit(wrong_reading)
        self.assertNotEqual(accepted['meaning'], unit(original)['meaning'])
        self.assertEqual(accepted['assurance']['interpretation_entailment'], 'UNPROVEN')
        with self.assertRaises(ValueError):
            package.decode(original.text, wrong_reading.archive)
        self.assertEqual(package.decode(wrong_reading.text, wrong_reading.archive)['sources'][0]['data'], sources[0])

    def test_focus_dependency_closure_retains_relevant_links_and_excludes_unrelated_units(self):
        sources, plan = connected(small_case(), 3)
        plan['meaning_units'][0]['kind'] = 'historical_approval'
        plan['meaning_units'][1]['kind'] = 'pending_action'
        plan['meaning_units'][1]['context'] = ['U0']
        anchors = plan['interpretations'][0]['anchors']
        plan['relations'] = [dict(kind='qualifies', **{'from': 'I1', 'to': 'I0'}, note='Declared context only.', anchors=anchors)]
        plan['uncertainties'] = [dict(id='Q', text='Current applicability unproved.', affects=['U1'], anchors=anchors)]
        plan['sources'].append(dict(id='UNRELATED', label='Unrelated',
            media_type='application/octet-stream', provenance='Outside focused declared context.'))
        paired = encode(sources + (b'unrelated',), plan)
        focused = package.focus(paired.text, paired.archive, 'U1')
        expected_source = package.inspect(paired.text, paired.archive)['sources'][0]
        self.assertEqual(focused['sources'], [expected_source])
        self.assertNotIn('data', focused['sources'][0])
        self.assertEqual([item['id'] for item in focused['meaning_units']], ['U0', 'U1'])
        self.assertEqual([item['id'] for item in focused['interpretations']], ['I0', 'I1'])
        self.assertEqual([item['id'] for item in focused['uncertainties']], ['Q'])
        self.assertEqual(len(focused['relations']), 1)
        self.assertEqual(focused['context_adequacy'], 'UNPROVEN')
        self.assertEqual(focused['execution_authority'], 'NONE')
        for excerpt in focused['source_excerpts']:
            begin, end = excerpt['span']
            data = base64.b64decode(excerpt['bytes_base64'])
            self.assertEqual(data, sources[0][begin:end])
            self.assertEqual(excerpt['sha256'], sha(data))
        for item in focused['meaning_units']:
            self.assert_residual_metadata(item['residuals'], sources[0])
            original = next(value for value in package.decode(paired.text, paired.archive)['meaning_units']
                            if value['id'] == item['id'])
            self.assertEqual(item['residuals'], original['residuals'])
        with self.assertRaises(ValueError):
            package.focus(paired.text, paired.archive, 'MISSING')

    def test_coherent_context_swap_changes_identity_without_proving_adequacy(self):
        sources, plan = connected(small_case(), 3)
        plan['meaning_units'][2]['context'] = ['U0']
        original = encode(sources, plan)
        plan['meaning_units'][2]['context'] = ['U1']
        altered = encode(sources, plan)
        self.assertEqual(package.focus(altered.text, altered.archive, 'U2')['context_adequacy'], 'UNPROVEN')
        with self.assertRaises(ValueError):
            package.decode(original.text, altered.archive)

    def test_unused_dictionary_entries_cannot_claim_checked_source_occurrences(self):
        for literal in ('INVENTED non-source approval', 'Claim'):
            sources, plan = connected(small_case())
            plan['meaning_units'][0]['plan']['symbols']['GHOST'] = literal
            with self.subTest(literal=literal), self.assertRaisesRegex(ValueError, 'unused.*symbol'):
                encode(sources, plan)

    def test_focus_bare_source_endpoint_retains_metadata_without_invented_excerpts(self):
        sources, plan = connected(small_case())
        for name in ('BARE', 'UNRELATED'):
            plan['sources'].append(dict(id=name, label=name + ' label',
                media_type='application/octet-stream', provenance='Authored test attribution.'))
        plan['relations'] = [dict(kind='derived_from', **{'from': 'U0', 'to': 'BARE'},
            note='Declared source dependency, no excerpt supplied.', anchors=plan['interpretations'][0]['anchors'])]
        pair = encode(sources + (b'bare source', b'unrelated source'), plan)
        result = package.focus(pair.text, pair.archive, 'U0')
        metadata = package.inspect(pair.text, pair.archive)['sources']
        self.assertEqual(result['sources'], metadata[:2])
        self.assertEqual(result['unexpanded_sources'], ['BARE'])
        self.assertEqual({item['source'] for item in result['source_excerpts']}, {'SOURCE'})
        self.assertEqual([item['id'] for item in result['meaning_units']], ['U0'])
        self.assertEqual(result['source_coverage'], 'DECLARED_EXCERPTS_ONLY_FURTHER_SOURCE_MAY_BE_REQUIRED')
        self.assertTrue(all('data' not in item for item in result['sources']))

    def test_dictionary_and_input_key_order_do_not_change_readback_or_output(self):
        sources, plan = connected(selected('CONTROLLER'))
        first = encode(sources, plan)
        typed = plan['meaning_units'][0]['plan']
        typed['symbols'] = dict(reversed(list(typed['symbols'].items())))
        reordered = dict(reversed(list(plan.items())))
        second = package.encode(sources, json.dumps(reordered).encode(), budget=BUDGET)
        self.assertEqual(first.text, second.text)
        self.assertEqual(first.archive, second.archive)
        self.assertEqual(first.lexicon, second.lexicon)
        self.assertEqual(unit(first), unit(second))

    def test_share_read_boundary_delivers_bytes_within_declared_wire_cap(self):
        # Boundary control uses a stub validator, not a claimed valid large pair.
        data = b'x' * 20_000
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            share, archive = root / 'share.txt', root / 'meaning.zip'
            share.write_bytes(data)
            archive.write_bytes(b'controlled archive placeholder')
            args = argparse.Namespace(action='validate', share=share, archive=archive)
            with patch.object(cli.transport_package, 'validate', return_value={'control': True}) as verifier:
                self.assertEqual(cli.opened(args), {'control': True})
                verifier.assert_called_once_with(data, b'controlled archive placeholder')

    def test_small_budget_refuses_without_source_or_unit_dropping_and_without_outputs(self):
        sources, plan = connected(selected('CONTROLLER'))
        with self.assertRaises(ValueError):
            encode(sources, plan, budget=200)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, metadata, output = root / 'source', root / 'plan.json', root / 'new-output'
            source.write_bytes(sources[0])
            metadata.write_bytes(canonical(plan))
            result = subprocess.run([sys.executable, '-B', '-Werror', str(ROOT / 'tools/transport_cli.py'),
                'encode', str(metadata), str(output), '--source', 'SOURCE=' + str(source), '--budget', '200'],
                cwd=root, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, capture_output=True, timeout=60, check=False)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertFalse(output.exists())
            self.assertEqual(list(root.glob('.transport-stage-*')), [])


if __name__ == '__main__':
    unittest.main()
