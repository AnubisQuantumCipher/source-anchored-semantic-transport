#!/usr/bin/env python3
"""Bounded source-bound evaluation controls against a pinned installed decoder."""
import argparse
import ast
import copy
import importlib
import os
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import bound_evaluation_fixtures as fixtures
import transport_bound_contract as contract
import transport_bound_evaluate as evaluator
import transport_bound_lowering as lowering
import transport_handoff_inputs as inputs
from test_portable_handoff import bundle_snapshot
from transport_install_support import canonical, read_regular, require, run_bounded, sha, write_new

ROOT = Path(__file__).absolute().parents[1]
HERE = ROOT / 'install'
CONFIG = {}


def pin(path):
    return dict(path=str(path), **inputs.record(read_regular(path)))


def save(path, value):
    write_new(path, canonical(value), inputs.CAP)


def closure():
    pending = [Path(__file__).name, 'transport_bound_evaluate.py', 'transport_handoff_prepare.py']
    found = {}
    for _ in range(64):
        if not pending:
            break
        name = pending.pop()
        if name in found:
            continue
        raw = read_regular(HERE / name)
        found[name] = pin(HERE / name)
        for node in ast.walk(ast.parse(raw)):
            modules = [node.module] if isinstance(node, ast.ImportFrom) else (
                [item.name for item in node.names] if isinstance(node, ast.Import) else [])
            for module in modules:
                candidate = (module or '').split('.')[0] + '.py'
                if (HERE / candidate).is_file() and candidate not in found:
                    pending.append(candidate)
    require(not pending and len(found) <= 64, 'test dependency closure bound')
    return [found[name] for name in sorted(found)]


def source_freeze():
    files = closure()
    if CONFIG['structure_only']:
        local_tools = sorted((ROOT / 'tools').glob('*.py'))
        require(len(local_tools) <= 64, 'local tool source closure bound')
        files.extend(pin(path) for path in local_tools)
    for name in fixtures.NAMES:
        files.extend(pin(fixtures.EXAMPLES / name / filename)
                     for filename in ('plan.json', 'requirement.txt', 'evidence.txt', 'history.txt'))
    return dict(schema='transport/bound-evaluation-test-freeze/1', files=files,
                python=pin(Path(sys.executable).resolve()),
                bundle=None if CONFIG['structure_only'] else bundle_snapshot(CONFIG['bundle']),
                prepared_manifest=pin(CONFIG['prepared']) if CONFIG['prepared'] else None,
                native=pin(CONFIG['native']) if CONFIG['native'] else None)


def invoke(argv, timeout=45):
    number = CONFIG['processes']
    require(number < 64, 'test process count bound')
    CONFIG['processes'] += 1
    result = run_bounded(argv, CONFIG['evidence'], inputs.ENV, timeout=timeout, cap=32768)
    prefix = 'process-%02d' % number
    for stream in ('stdout', 'stderr'):
        write_new(CONFIG['evidence'] / (prefix + '.' + stream), result[stream], 32768)
    save(CONFIG['evidence'] / (prefix + '.json'),
         {key: item for key, item in result.items() if key not in ('stdout', 'stderr')}
         | {stream: inputs.record(result[stream]) for stream in ('stdout', 'stderr')})
    return result


def encode(name):
    if CONFIG['structure_only']:
        return synthetic(name)
    data = fixtures.sources(name)
    plan = fixtures.plan(name, data)
    require(read_regular(fixtures.EXAMPLES / name / 'plan.json') == canonical(plan), 'fixture plan not reproducible')
    output = CONFIG['evidence'] / (name + '-encoded')
    argv = [str(CONFIG['bundle'] / 'bin/semantic-transport'), 'encode-plan',
            str(fixtures.EXAMPLES / name / 'plan.json'), str(output), '--budget', '8192',
            '--reference', 'attached:meaning.zip']
    for key in fixtures.SOURCE_IDS:
        argv.extend(['--source', key + '=' + str(fixtures.EXAMPLES / name / (key.lower() + '.txt'))])
    result = invoke(argv)
    require(result['status'] == 'SUCCESS' and result['exit_code'] == 0 and not result['stderr'], 'fixture encode refused')
    share = read_regular(output / 'share.txt')
    identity = 'STS1:' + share.decode('utf-8').split('STS1:', 1)[1].split()[0]
    module = importlib.import_module('transport_mcp')
    require(Path(module.__file__).absolute() == CONFIG['bundle'] / 'tools/transport_mcp.py', 'decoder origin differs')
    receiver = module.Receiver(share, read_regular(output / 'meaning.zip'), identity)
    require({item['id']: item['data'] for item in receiver.decoded['sources']} == data, 'source bytes changed')
    return finish_fixture(name, receiver.decoded, output, plan)


def finish_fixture(name, decoded, output, plan):
    native_pin = sha(read_regular(CONFIG['native'])) if CONFIG['native'] else '0' * 64
    declared = fixtures.contract(name, decoded, native_pin)
    raw = canonical(declared)
    compiled = contract.compile_contract(raw, decoded, sha(raw))
    save(CONFIG['evidence'] / (name + '-contract.json'), declared)
    reports = [fixtures.report(compiled, 0, 'KNOWN_TRUE')]
    if name == 'reviews':
        reports.append(fixtures.report(compiled, 1, 'KNOWN_FALSE'))
    save(CONFIG['evidence'] / (name + '-observations.json'), fixtures.observations(compiled, reports))
    return dict(decoded=decoded, compiled=compiled, contract=declared, output=output, plan=plan)


def synthetic(name):
    """CI-only view construction: no encoder, native decoder, compaction or recovery."""
    from transport_meaning import check_meaning
    from transport_semantics import dictionary_pair, unit_view
    data = fixtures.sources(name)
    plan = fixtures.plan(name, data)
    require(read_regular(fixtures.EXAMPLES / name / 'plan.json') == canonical(plan), 'fixture plan not reproducible')
    units = []
    for item in plan['meaning_units']:
        grammar, dictionaries, symbols = dictionary_pair(item['plan'])
        meaning = item['plan']['meaning']
        check_meaning(meaning, data[item['source']], symbols['entries'])
        stored = {key: value for key, value in item.items() if key != 'plan'}
        stored.update(grammar=grammar, dictionaries=dictionaries, meaning=meaning)
        units.append(unit_view(stored, data[item['source']]))
    decoded = dict(schema='transport/decoded/2', identity='STS1:' + sha(canonical(plan)), meaning_units=units,
        sources=[dict(item, data=data[item['id']], **inputs.record(data[item['id']])) for item in plan['sources']],
        uncertainties=plan['uncertainties'], relations=plan['relations'])
    return finish_fixture(name, decoded, None, plan)


def prepare(fixture):
    if CONFIG['prepared']:
        manifest = inputs.json_value(read_regular(CONFIG['prepared']))
        require(manifest['pair']['identity'] == fixture['decoded']['identity'], 'prepared fixture identity differs')
        return CONFIG['prepared']
    task = CONFIG['evidence'] / 'task.txt'
    write_new(task, b'Evaluate the selected declared requirement conditional on explicit reports.\n')
    snapshot = CONFIG['before']['bundle']
    output = fixture['output']
    config = dict(schema='transport/handoff-preparation/1', arm='transport', task=pin(task),
        python=pin(Path(sys.executable).resolve()),
        sources=[dict(item, **inputs.record(fixtures.sources('reviews')[item['id']])) for item in fixture['plan']['sources']],
        bundle=dict(path=str(CONFIG['bundle']), install_sha256=snapshot['install_manifest']['sha256'],
                    snapshot_sha256=sha(canonical(snapshot))),
        pair=dict(share=pin(output / 'share.txt'), archive=pin(output / 'meaning.zip'), identity=fixture['decoded']['identity']))
    path, target = CONFIG['evidence'] / 'prepare.json', CONFIG['evidence'] / 'prepared'
    save(path, config)
    result = invoke([sys.executable, '-I', '-S', '-B', '-Werror', str(HERE / 'transport_handoff_prepare.py'),
                     '--config', str(path), '--expect-config-sha256', sha(canonical(config)), '--output', str(target)])
    require(result['exit_code'] == 0 and not result['stderr'], 'fixture preparation refused')
    require(inputs.json_value(result['stdout'])['status'] == 'PREPARED_NOT_DISPATCHED', 'preparation incomplete')
    return target / 'manifest.json'


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / 'tools' if CONFIG['structure_only'] else CONFIG['bundle'] / 'tools'))
        CONFIG['fixtures'] = {name: encode(name) for name in fixtures.NAMES}
        if CONFIG['native']:
            CONFIG['manifest'] = prepare(CONFIG['fixtures']['reviews'])

    def setUp(self):
        self.fixture = CONFIG['fixtures']['reviews']
        self.compiled = self.fixture['compiled']

    def compile(self, value, decoded=None):
        raw = canonical(value)
        return contract.compile_contract(raw, decoded or self.fixture['decoded'], sha(raw))

    def observed(self, reports, compiled=None):
        selected = compiled or self.compiled
        raw = canonical(fixtures.observations(selected, reports))
        return lowering.observations(raw, selected, sha(raw))

    def report(self, occurrence, truth, source='EVIDENCE', compiled=None):
        return fixtures.report(compiled or self.compiled, occurrence, truth, source)

    def compute(self, reports, compiled=None):
        if not CONFIG['native']:
            self.skipTest('native integration explicitly UNRUN')
        selected = compiled or self.compiled
        observed = self.observed(reports, selected)
        lowered = lowering.lower(selected, observed)
        number = CONFIG['processes']
        path = CONFIG['evidence'] / ('frame-%02d.stv' % number)
        write_new(path, lowered['frame'], 1542)
        result = invoke([str(CONFIG['native']), str(path)])
        self.assertEqual((result['status'], result['exit_code'], result['stderr']), ('SUCCESS', 0, b''))
        parsed = lowering.native_result(result['stdout'], lowered)
        save(CONFIG['evidence'] / ('evaluation-case-%02d.json' % number), dict(
            status='TESTED_CONDITIONAL_EVALUATION', contract_sha256=selected['contract_sha256'],
            observations=fixtures.observations(selected, reports), frame_sha256=sha(lowered['frame']),
            results=parsed, outcome=parsed[-1]['value'], source_entailment='UNPROVEN', execution_authority='NONE'))
        return parsed[-1]['value'], parsed

    def test_sources_literals_and_explicit_unevaluated_scope(self):
        for name in fixtures.NAMES:
            item = CONFIG['fixtures'][name]
            self.assertEqual({s['id']: s['data'] for s in item['decoded']['sources']}, fixtures.sources(name))
            self.assertEqual(item['compiled']['unevaluated_units'], ['U_EVIDENCE', 'U_HISTORY'])
            self.assertIn(b'1/3', item['compiled']['sources']['REQUIREMENT'])
            context = item['compiled']['context']
            self.assertEqual([unit['id'] for unit in context['units']], ['U_REQUIREMENT', 'U_EVIDENCE', 'U_HISTORY'])
            self.assertEqual(context['uncertainties'][0]['id'], 'REPORT_AUTHENTICITY')
            self.assertEqual(context['relations'][0]['kind'], 'qualifies')
        self.assertIn(b'6.62607015e-34 J s', self.compiled['sources']['REQUIREMENT'])
        self.assertEqual([b['identity']['predicate']['id'] for b in self.compiled['bindings'].values()],
                         ['SECURITY_COMPLETE', 'VALIDATION_COMPLETE'])

    def test_exact_lowering_and_missing_conflict_masks(self):
        reports = [self.report(0, 'KNOWN_TRUE'), self.report(1, 'KNOWN_FALSE'), self.report(1, 'KNOWN_TRUE', 'HISTORY')]
        observed = self.observed(reports)
        lowered = lowering.lower(self.compiled, observed)
        rows = [(1, 4, 0, 0), (4, 0, 1, 0), (1, 6, 0, 0), (4, 0, 3, 0), (5, 0, 2, 4)]
        self.assertEqual(lowered['frame'], b'STV1\x00\x05' + b''.join(struct.pack('>BBHH', *row) for row in rows))
        self.assertEqual(self.observed([])['masks'], {})
        self.assertEqual(len(observed['reports']), 3)

    def test_true_false_missing_and_conflicting_reports(self):
        if not CONFIG['native']:
            self.skipTest('native integration explicitly UNRUN')
        first = self.report(0, 'KNOWN_TRUE')
        truth = self.report(1, 'KNOWN_TRUE', 'HISTORY')
        false = self.report(1, 'KNOWN_FALSE')
        for reports, outcome in (([first, truth], 'SATISFIED'), ([first, false], 'VIOLATED'),
                                 ([first], 'UNKNOWN'), ([first, truth, false], 'UNKNOWN'),
                                 ([first, false, truth], 'UNKNOWN'), ([], 'UNKNOWN')):
            with self.subTest(outcome=outcome, reports=reports):
                self.assertEqual(self.compute(reports)[0], outcome)

    def test_explicit_unresolved_does_not_become_truth(self):
        first = self.report(0, 'KNOWN_TRUE')
        for reports in ([first, self.report(1, 'UNRESOLVED')],
                        [first, self.report(1, 'UNRESOLVED'), self.report(1, 'KNOWN_TRUE', 'HISTORY')]):
            self.assertEqual(self.compute(reports)[0], 'UNKNOWN')

    def test_heldout_not_and_ordered_actor_arguments(self):
        fixture = CONFIG['fixtures']['library']
        compiled = fixture['compiled']
        value = copy.deepcopy(fixture['contract'])
        args = value['bindings'][0]['arguments']
        args[0], args[2] = args[2], args[0]
        with self.assertRaisesRegex(ValueError, 'ordered argument'):
            self.compile(value, fixture['decoded'])
        for truth, outcome, source in (('KNOWN_TRUE', 'VIOLATED', 'EVIDENCE'),
                                       ('KNOWN_FALSE', 'SATISFIED', 'HISTORY'), ('UNRESOLVED', 'UNKNOWN', 'EVIDENCE')):
            self.assertEqual(self.compute([self.report(0, truth, source, compiled)], compiled)[0], outcome)

    def test_fact_conjunction_inside_obligation(self):
        decoded = copy.deepcopy(self.fixture['decoded'])
        unit = decoded['meaning_units'][0]
        old = unit['meaning']['nodes']
        nodes = [old[index] for index in (0, 1, 2, 4, 5, 6)]
        nodes[5]['args'] = [4, 3]
        nodes.extend([dict(op='and', args=[2, 5], cue=[0, 0]), dict(op='must', args=[6], cue=[0, 0])])
        unit['meaning'].update(nodes=nodes, root=7)
        value = fixtures.contract('reviews', decoded, self.fixture['contract']['native_sha256'])
        compiled = self.compile(value, decoded)
        reports = [self.report(0, 'KNOWN_TRUE', compiled=compiled), self.report(1, 'KNOWN_FALSE', compiled=compiled)]
        lowered = lowering.lower(compiled, self.observed(reports, compiled))
        self.assertEqual([item['sort'] for item in lowered['trace']], ['FACT', 'FACT', 'FACT', 'NORM'])
        self.assertEqual(self.compute(reports, compiled)[0], 'VIOLATED')

    def test_wrong_nominal_sort_and_predicate_occurrence(self):
        for field in ('sort', 'node', 'predicate'):
            value = copy.deepcopy(self.fixture['contract'])
            if field == 'sort':
                value['terms'][0]['sort'] = 'PERSON'
            elif field == 'node':
                value['bindings'][0]['node'] = value['bindings'][1]['node']
            else:
                value['bindings'][0]['predicate'] = value['bindings'][1]['predicate']
            with self.assertRaises(ValueError):
                self.compile(value)

    def test_package_unit_source_and_held_contract_pins(self):
        for key in ('package_identity', 'unit_sha256', 'source_sha256', 'unit_id', 'source_id'):
            value = copy.deepcopy(self.fixture['contract'])
            value[key] = 'MISSING' if key.endswith('_id') else '0' * 64
            with self.assertRaises(ValueError):
                self.compile(value)
        with self.assertRaises(ValueError):
            contract.compile_contract(canonical(self.fixture['contract']), self.fixture['decoded'], '0' * 64)

    def test_changed_source_revision_and_unit_order_reject(self):
        for change in ('source', 'unit'):
            decoded = copy.deepcopy(self.fixture['decoded'])
            if change == 'source':
                decoded['sources'][0]['data'] += b' revised'
            else:
                decoded['meaning_units'][0]['meaning']['nodes'][-1]['args'].reverse()
            with self.assertRaises(ValueError):
                self.compile(self.fixture['contract'], decoded)

    def test_observation_binding_contract_and_external_pins(self):
        value = fixtures.observations(self.compiled, [self.report(0, 'KNOWN_TRUE')])
        for change in ('binding', 'contract', 'external'):
            altered = copy.deepcopy(value)
            if change == 'binding':
                altered['records'][0]['binding_sha256'] = '0' * 64
            elif change == 'contract':
                altered['contract_sha256'] = '0' * 64
            raw = canonical(altered)
            with self.assertRaises(ValueError):
                lowering.observations(raw, self.compiled, '0' * 64 if change == 'external' else sha(raw))
        changed = copy.deepcopy(self.fixture['contract'])
        changed['native_sha256'] = '1' * 64
        compiled = self.compile(changed)
        with self.assertRaises(ValueError):
            self.observed([self.report(0, 'KNOWN_TRUE')], compiled)

    def test_citation_source_offset_quote_and_revision_reject(self):
        for key, value in (('source_id', 'MISSING'), ('source_sha256', '0' * 64), ('start', True),
                           ('end', 999999), ('quote', 'wrong exact bytes')):
            report = self.report(0, 'KNOWN_TRUE')
            report['citations'][0][key] = value
            with self.assertRaises(ValueError):
                self.observed([report])

    def test_unsupported_versions_truncation_and_report_values(self):
        for key in ('schema', 'profile'):
            value = copy.deepcopy(self.fixture['contract'])
            value[key] += '-unsupported'
            with self.assertRaises(ValueError):
                self.compile(value)
        for raw in (b'{', b'{}', b'\xff', b'{"schema":1,"schema":2}'):
            with self.assertRaises((ValueError, UnicodeError)):
                contract.compile_contract(raw, self.fixture['decoded'], sha(raw))
        for key, value in (('truth', 'TRUE'), ('provenance', 'AUTHENTICATED'), ('citations', [])):
            report = self.report(0, 'KNOWN_TRUE')
            report[key] = value
            with self.assertRaises(ValueError):
                self.observed([report])
        report = self.report(0, 'KNOWN_TRUE')
        with self.assertRaises(ValueError):
            self.observed([report, report])
        value = fixtures.observations(self.compiled, [])
        value['schema'] = 'transport/bound-observations/999'
        for raw in (canonical(value), b'{', b'[]', b'\xff'):
            with self.assertRaises((ValueError, UnicodeError)):
                lowering.observations(raw, self.compiled, sha(raw))

    def test_explicit_record_and_declaration_bounds(self):
        value = copy.deepcopy(self.fixture['contract'])
        for key, count in (('terms', 65), ('predicates', 33), ('bindings', 65)):
            altered = copy.deepcopy(value)
            altered[key] = [copy.deepcopy(altered[key][0]) for _ in range(count)]
            with self.assertRaises(ValueError):
                self.compile(altered)
        with self.assertRaises(ValueError):
            self.observed([self.report(0, 'KNOWN_TRUE') for _ in range(65)])

    def test_unsupported_operators_are_refused_after_meaning_validation(self):
        fixture = CONFIG['fixtures']['library']
        for op in ('if', 'unless', 'all', 'uncertain', 'attribution'):
            decoded = copy.deepcopy(fixture['decoded'])
            unit = decoded['meaning_units'][0]
            nodes = unit['meaning']['nodes']
            root = nodes[-1]
            root['op'] = op
            root['args'] = {'if': [4, 5], 'unless': [4, 5], 'uncertain': [3, 5],
                            'attribution': [0, 5], 'all': [0, 1, 5]}[op]
            if op == 'all':
                nodes[0] = dict(op='var', name='X')
            value = copy.deepcopy(fixture['contract'])
            value['unit_sha256'] = sha(canonical(unit))
            with self.assertRaisesRegex(ValueError, 'unsupported operator'):
                self.compile(value, decoded)

    def test_nested_must_mixed_fact_norm_and_norm_negation_refused(self):
        for kind in ('nested', 'mixed', 'negation'):
            decoded = copy.deepcopy(self.fixture['decoded'])
            unit = decoded['meaning_units'][0]
            nodes = unit['meaning']['nodes']
            if kind == 'mixed':
                nodes[3]['op'] = 'not'
            elif kind == 'nested':
                nodes.append(dict(op='must', args=[len(nodes) - 1], cue=[0, 0]))
            else:
                nodes.append(dict(op='not', args=[len(nodes) - 1], cue=[0, 0]))
            unit['meaning']['root'] = len(nodes) - 1
            value = copy.deepcopy(self.fixture['contract'])
            value['unit_sha256'] = sha(canonical(unit))
            compiled = self.compile(value, decoded)
            with self.assertRaises(ValueError):
                lowering.lower(compiled, self.observed([], compiled))

    def test_native_output_requires_exact_node_sort_value_and_framing(self):
        lowered = lowering.lower(self.compiled, self.observed([]))
        valid = b'NODE 1 FACT UNRESOLVED\nNODE 2 NORM UNKNOWN\nNODE 3 FACT UNRESOLVED\nNODE 4 NORM UNKNOWN\nNODE 5 NORM UNKNOWN\n'
        self.assertEqual(lowering.native_result(valid, lowered)[-1]['value'], 'UNKNOWN')
        for raw in (valid[:-1], valid + b'EXTRA\n', valid.replace(b'NODE 1', b'NODE 9'),
                    valid.replace(b'FACT', b'NORM', 1), valid.replace(b'UNKNOWN', b'SUCCESS', 1)):
            with self.assertRaises(ValueError):
                lowering.native_result(raw, lowered)

    def test_native_relative_path_rejects_before_read_or_execution(self):
        observed = self.observed([])
        lowered = lowering.lower(self.compiled, observed)
        with patch.object(evaluator, 'held') as read, patch.object(evaluator, 'run_bounded') as spawn:
            for path in (Path('true'), Path('/tmp/../usr/bin/true')):
                with self.assertRaisesRegex(ValueError, 'explicit absolute path'):
                    evaluator.evaluate(self.compiled, observed, lowered, path,
                                       self.compiled['contract']['native_sha256'])
            read.assert_not_called()
            spawn.assert_not_called()

    def test_wrong_verdict_rejects_correct_citation_commentary_ungraded(self):
        evaluation = dict(outcome='VIOLATED', reports=[self.report(1, 'KNOWN_FALSE')], execution_authority='NONE')
        value = dict(schema='transport/evaluation-conclusion/1', evaluation_sha256=sha(canonical(evaluation)),
                     outcome='VIOLATED', commentary='Correct source citation is retained above.')
        for text in ('', 'Unsupported narrative; this commentary is deliberately not graded.'):
            value['commentary'] = text
            answer = lowering.check_conclusion(canonical(value), evaluation)
            self.assertEqual((answer['commentary'], answer['execution_authority']), ('NOT_ASSESSED', 'NONE'))
        value['outcome'] = 'SATISFIED'
        with self.assertRaisesRegex(ValueError, 'contradicts computed outcome'):
            lowering.check_conclusion(canonical(value), evaluation)
        value['outcome'], value['evaluation_sha256'] = 'VIOLATED', '0' * 64
        with self.assertRaises(ValueError):
            lowering.check_conclusion(canonical(value), evaluation)

    def test_native_malformed_frames_refuse(self):
        if not CONFIG['native']:
            self.skipTest('native integration explicitly UNRUN')
        valid = lowering.lower(self.compiled, self.observed([]))['frame']
        for raw in (b'STV2' + valid[4:], valid[:-1], valid + b'\x00', b'STV1\x00\x00',
                    b'STV1\x00\x01' + struct.pack('>BBHH', 4, 0, 1, 0)):
            path = CONFIG['evidence'] / ('bad-frame-%02d.stv' % CONFIG['processes'])
            write_new(path, raw, 1542)
            result = invoke([str(CONFIG['native']), str(path)])
            self.assertNotEqual(result['exit_code'], 0)

    def test_native_nonregular_inputs_refuse_without_blocking(self):
        if not CONFIG['native']:
            self.skipTest('native integration explicitly UNRUN')
        directory = CONFIG['evidence'] / 'nonregular-directory'
        directory.mkdir()
        fifo, link = CONFIG['evidence'] / 'nonregular-fifo', CONFIG['evidence'] / 'nonregular-link'
        regular = CONFIG['evidence'] / 'regular-frame.stv'
        write_new(regular, lowering.lower(self.compiled, self.observed([]))['frame'], 1542)
        os.mkfifo(fifo, mode=0o600)
        try:
            link.symlink_to(regular)
            for path in (fifo, directory, link, Path('/dev/null')):
                result = invoke([str(CONFIG['native']), str(path)], timeout=3)
                self.assertEqual((result['status'], result['exit_code'], result['stdout'], result['stderr']),
                                 ('EXIT_NONZERO', 1, b'', b'REFUSED IO_ERROR\n'))
        finally:
            fifo.unlink()
            link.unlink(missing_ok=True)

    def test_cli_evaluation_pins_and_candidate_verdict(self):
        if not CONFIG['native']:
            self.skipTest('native integration explicitly UNRUN')
        paths = dict(manifest=CONFIG['manifest'], native=CONFIG['native'])
        paths['contract'] = CONFIG['evidence'] / 'evaluation-contract.json'
        paths['observations'] = CONFIG['evidence'] / 'evaluation-observations.json'
        save(paths['contract'], self.fixture['contract'])
        save(paths['observations'], fixtures.observations(self.compiled,
             [self.report(0, 'KNOWN_TRUE'), self.report(1, 'KNOWN_FALSE')]))
        argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(HERE / 'transport_bound_evaluate.py')]
        for key, path in paths.items():
            argv.extend(['--' + key, str(path), '--expect-' + key + '-sha256', sha(read_regular(path))])
        result = invoke(argv)
        self.assertEqual((result['exit_code'], result['stderr']), (0, b''), result['stdout'])
        value = inputs.json_value(result['stdout'])['evaluation']
        self.assertEqual((value['outcome'], value['source_entailment'], value['execution_authority']),
                         ('VIOLATED', 'UNPROVEN', 'NONE'))
        for key in paths:
            wrong = list(argv)
            wrong[wrong.index('--expect-' + key + '-sha256') + 1] = '0' * 64
            failure = invoke(wrong)
            self.assertEqual((failure['exit_code'], inputs.json_value(failure['stdout'])['status']), (1, 'REFUSED'))
        candidate = CONFIG['evidence'] / 'wrong-conclusion.json'
        save(candidate, dict(schema='transport/evaluation-conclusion/1', evaluation_sha256=sha(canonical(value)),
                             outcome='SATISFIED', commentary='The same exact citations do not justify this verdict.'))
        failure = invoke(argv + ['--candidate', str(candidate)])
        self.assertEqual((failure['exit_code'], inputs.json_value(failure['stdout'])['status']), (1, 'REFUSED'))

    def test_function_bounds_and_no_shell(self):
        names = ('bound_evaluation_fixtures.py', 'test_bound_evaluation.py', 'transport_bound_contract.py',
                 'transport_bound_lowering.py', 'transport_bound_evaluate.py', 'transport_bound_inputs.py')
        for name in names:
            for node in ast.walk(ast.parse(read_regular(HERE / name))):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, (name, node.name))
                if isinstance(node, ast.Call):
                    self.assertFalse(any(item.arg == 'shell' for item in node.keywords))


def evidence_size(root):
    pending, count, total = [root], 0, 0
    for _ in range(512):
        if not pending:
            break
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                count += 1
                require(count <= 512 and not entry.is_symlink(), 'evidence tree bound')
                if entry.is_dir(follow_symlinks=False):
                    pending.append(Path(entry.path))
                else:
                    require(entry.is_file(follow_symlinks=False), 'evidence regular file required')
                    total += entry.stat(follow_symlinks=False).st_size
                    require(total < 4194304, 'integration evidence exceeds assigned byte budget')
    require(not pending, 'evidence traversal bound')
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--structure-only', action='store_true')
    parser.add_argument('--native', type=Path)
    parser.add_argument('--prepared-manifest', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    if args.structure_only:
        require(args.bundle is None and args.native is None and args.prepared_manifest is None,
                'synthetic mode refuses bundle, native or prepared manifest')
    else:
        require(args.bundle is not None and args.bundle.is_absolute(), 'absolute installed bundle required')
    require(args.evidence.is_absolute(), 'absolute evidence path required')
    require(args.prepared_manifest is None or (args.native is not None and args.prepared_manifest.is_absolute()),
            'prepared manifest reuse requires native mode and absolute manifest path')
    require(not args.evidence.exists() and not args.evidence.is_symlink(), 'new evidence directory required')
    args.evidence.mkdir(mode=0o700)
    CONFIG.update(bundle=args.bundle, native=args.native, evidence=args.evidence, processes=0,
                  structure_only=args.structure_only, prepared=args.prepared_manifest)
    before = source_freeze()
    CONFIG['before'] = before
    save(args.evidence / 'source-freeze.json', before)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
    require(source_freeze() == before, 'frozen test inputs changed')
    receipt = dict(schema='transport/bound-evaluation-controls/1',
        status='TESTED_SCOPED' if result.wasSuccessful() else 'FAILED', tests_run=result.testsRun,
        failures=[text for _, text in result.failures], errors=[text for _, text in result.errors],
        skipped=[text for _, text in result.skipped], processes=CONFIG['processes'],
        input_freeze_sha256=sha(canonical(before)), output_bytes_before_receipt=evidence_size(args.evidence),
        native_execution='TESTED' if args.native else 'UNRUN', model_execution='UNRUN',
        decoder_execution='UNRUN_SYNTHETIC_VIEW' if args.structure_only else 'ACTUAL_INSTALLED_NATIVE',
        byte_recovery='UNRUN' if args.structure_only else 'EXACT_SOURCE_BYTES_COMPARED',
        source_entailment='UNPROVEN', report_authentication='NOT_AUTHENTICATED', execution_authority='NONE',
        limitations='Named deterministic controls only; no whole-system formal proof or source entailment claim.')
    save(args.evidence / 'receipt.json', receipt)
    evidence_size(args.evidence)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
