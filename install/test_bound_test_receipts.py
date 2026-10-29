#!/usr/bin/env python3
"""Actual decoder/native controls for source-bound, recomputed finite test receipts.

The fixture extends the existing published plan without replacing its detailed
reading, ambiguity records, sources, approval history, or authority boundaries.
"""
import argparse
import ast
import copy
import importlib
import io
import itertools
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import unittest
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_bound_contract as contract
import transport_finite_check as finite
import transport_handoff_inputs as inputs
from test_portable_handoff import bundle_snapshot
from transport_install_support import canonical, read_regular, require, run_bounded, sha, write_new

ROOT = Path(__file__).absolute().parents[1]
HERE = ROOT / 'install'
OLD = ROOT / 'examples/checked-continuation-v1'
PARAMETERS = ('requester_is_keeper', 'recipient_is_keeper', 'seal_ok',
              'repair_mode', 'ticket_ok', 'age_hours')
DOMAINS = {name: {'type': 'boolean'} for name in PARAMETERS[:-1]}
DOMAINS['age_hours'] = {'type': 'integer', 'min': -1, 'max': 13}
CONFIG = {}


def pin(path):
    return dict(path=str(path), **inputs.record(read_regular(path)))


def save(path, value):
    write_new(path, canonical(value), inputs.CAP)


def archived_plan():
    receipt = inputs.json_value(read_regular(ROOT / 'receipts/checked-continuation-1.json'))
    raw = read_regular(OLD / 'evidence.zip', 1048576)
    require(sha(raw) == receipt['archive_sha256'], 'original evidence archive differs from published receipt')
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(len(entries) <= 128 and len({item.filename for item in entries}) == len(entries), 'archive entry bound')
        total = 0
        for entry in entries:
            path = PurePosixPath(entry.filename)
            require(not path.is_absolute() and all(part not in ('', '.', '..') for part in path.parts)
                    and '\\' not in entry.filename and not entry.is_dir(), 'unsafe archive entry')
            mode = entry.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG) and not entry.flag_bits & 1, 'unsupported archive entry')
            require(entry.file_size <= 1048576, 'archive entry size bound')
            total += entry.file_size
            require(total <= 4194304, 'archive expansion bound')
        manifest = inputs.json_value(archive.read('MANIFEST.json'), 1048576)
        require(sha(archive.read('MANIFEST.json')) == receipt['manifest_sha256'], 'original manifest differs')
        target = 'package-01/encoded/plan.json'
        matches = [item for item in manifest['entries'] if item['entry'] == target]
        require(len(matches) == 1, 'original plan entry missing or duplicated')
        plan_raw = archive.read(target)
        require(len(plan_raw) == matches[0]['export_bytes'] and sha(plan_raw) == matches[0]['export_sha256'],
                'original plan bytes differ from original manifest')
    return plan_raw


def span(source, text):
    raw = text.encode('utf-8')
    start = source.index(raw)
    require(source.find(raw, start + 1) == -1, 'ambiguous fixture quotation')
    return [start, start + len(raw)]


def extended_plan(original, data):
    plan = copy.deepcopy(original)
    source = data['RULE']
    phrase = ('return True exactly when requester_is_keeper is True, age_hours is between 0 and 12 inclusive, '
              'and either seal_ok is True or both repair_mode and ticket_ok are True')
    term_span, phrase_span, must_span = span(source, 'allow_demo_route'), span(source, phrase), span(source, 'must')
    nodes = [dict(op='term', symbol='FUNCTION', span=term_span),
             dict(op='text', symbol='COMPLETE_CONDITION', span=phrase_span),
             dict(op='pred', args=[1, 0], cue=phrase_span), dict(op='must', args=[2], cue=must_span)]
    reading = dict(schema='transport/encoding-plan/1',
                   symbols=dict(FUNCTION='allow_demo_route', COMPLETE_CONDITION=phrase),
                   meaning=dict(schema='transport/meaning/1', nodes=nodes, root=3, ambiguities=[]))
    plan['interpretations'].append(dict(id='I_TESTABLE_CORRECTION', label='TESTABLE_CORRECTION', status='proposed',
        text='The whole quoted condition is one named oracle-tested proposition. Its internal English relationships '
             'are not decomposed or proved; the existing detailed reading and uncertainty remain unchanged.',
        provenance='Proposed addition to the original public synthetic plan; no new source claim or authority.',
        anchors=[dict(source='RULE', span=[term_span[0], phrase_span[1]])]))
    plan['meaning_units'].append(dict(id='MU_TESTABLE_CORRECTION', source='RULE',
        interpretation='I_TESTABLE_CORRECTION', kind='instruction',
        context=['MU_INTERFACE', 'MU_CODE', 'MU_CORRECTION'], plan=reading))
    require(plan['meaning_units'][:-1] == original['meaning_units']
            and plan['interpretations'][:-1] == original['interpretations'], 'original readings changed')
    require(all(plan[key] == original[key] for key in ('schema', 'sources', 'relations', 'uncertainties')),
            'original source or historical context changed')
    return plan


def expected(state):
    """Published independent guard-first oracle, retained verbatim in behavior."""
    if not state['requester_is_keeper']:
        return False
    if state['age_hours'] in (-1, 13):
        return False
    if state['seal_ok']:
        return True
    return state['repair_mode'] and state['ticket_ok']


def expected_bits():
    bits = []
    for values in itertools.product((False, True), repeat=5):
        for age in range(-1, 14):
            state = dict(zip(PARAMETERS, (*values, age), strict=True))
            bits.append('1' if expected(state) else '0')
    require(len(bits) == 480, 'declared oracle state count differs')
    return ''.join(bits)


def closure():
    pending = [Path(__file__).name, 'transport_bound_check.py', 'transport_handoff_prepare.py']
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
    files.extend(pin(path) for path in (OLD / 'fixture.json', OLD / 'evidence.zip', OLD / 'check_response.py',
                                       ROOT / 'receipts/checked-continuation-1.json'))
    return dict(schema='transport/bound-test-controls-freeze/1', files=files,
                python=pin(Path(sys.executable).resolve()), bundle=bundle_snapshot(CONFIG['bundle']),
                native=pin(CONFIG['native']), checker=finite.checker_identity())


def invoke(argv):
    number = CONFIG['processes']
    require(number < 48, 'test process count bound')
    CONFIG['processes'] += 1
    result = run_bounded(argv, CONFIG['evidence'], inputs.ENV, timeout=45, cap=131072)
    prefix = 'process-%02d' % number
    for stream in ('stdout', 'stderr'):
        write_new(CONFIG['evidence'] / (prefix + '.' + stream), result[stream], 131072)
    save(CONFIG['evidence'] / (prefix + '.json'),
         {key: item for key, item in result.items() if key not in ('stdout', 'stderr')}
         | {stream: inputs.record(result[stream]) for stream in ('stdout', 'stderr')})
    return result


def encode():
    fixture = inputs.json_value(read_regular(OLD / 'fixture.json'))
    data = {item['id']: item['text'].encode('utf-8') for item in fixture['sources']}
    require(len(data) == 6, 'original fixture source count differs')
    original_raw = archived_plan()
    original = inputs.json_value(original_raw)
    plan = extended_plan(original, data)
    path = CONFIG['evidence'] / 'plan.json'
    save(path, plan)
    write_new(CONFIG['evidence'] / 'original-plan.json', original_raw)
    output = CONFIG['evidence'] / 'encoded'
    argv = [str(CONFIG['bundle'] / 'bin/semantic-transport'), 'encode-plan', str(path), str(output),
            '--budget', '8192', '--reference', 'attached:meaning.zip']
    for key, raw in data.items():
        target = CONFIG['evidence'] / (key + '.txt')
        write_new(target, raw)
        argv.extend(['--source', key + '=' + str(target)])
    result = invoke(argv)
    require(result['status'] == 'SUCCESS' and result['exit_code'] == 0 and not result['stderr'], 'fixture encode refused')
    share = read_regular(output / 'share.txt')
    identity = 'STS1:' + share.decode('utf-8').split('STS1:', 1)[1].split()[0]
    module = importlib.import_module('transport_mcp')
    require(Path(module.__file__).absolute() == CONFIG['bundle'] / 'tools/transport_mcp.py', 'decoder origin differs')
    receiver = module.Receiver(share, read_regular(output / 'meaning.zip'), identity)
    require({item['id']: item['data'] for item in receiver.decoded['sources']} == data, 'source bytes changed')
    CONFIG['codec_verified'] = True
    return dict(data=data, original=original, plan=plan, output=output, decoded=receiver.decoded)


def declared_contract(fixture, unit_id='MU_TESTABLE_CORRECTION'):
    decoded = fixture['decoded']
    unit = next(item for item in decoded['meaning_units'] if item['id'] == unit_id)
    return dict(schema='transport/bound-evaluation-contract/1', profile='transport/ground-obligation-evaluation/1',
        package_identity=decoded['identity'], unit_id=unit_id, unit_sha256=sha(canonical(unit)),
        source_id='RULE', source_sha256=sha(fixture['data']['RULE']), native_sha256=sha(read_regular(CONFIG['native'])),
        terms=[dict(node=0, sort='FUNCTION')],
        predicates=[dict(id='COMPLETE_CORRECTION', name_node=1, argument_sorts=['FUNCTION'])],
        bindings=[dict(node=2, predicate='COMPLETE_CORRECTION', arguments=[0])])


def prepare(fixture):
    task = CONFIG['evidence'] / 'task.txt'
    write_new(task, b'Check proposed function replacement DATA against the declared finite table. No execution authority.\n')
    snapshot, output = CONFIG['before']['bundle'], fixture['output']
    config = dict(schema='transport/handoff-preparation/1', arm='transport', task=pin(task),
        python=pin(Path(sys.executable).resolve()),
        sources=[dict(item, **inputs.record(fixture['data'][item['id']])) for item in fixture['plan']['sources']],
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


def replacement(expression):
    base = CONFIG['fixture']['data']['CODE']
    return dict(schema='transport/function-replacement/1', source_id='CODE', base_sha256=sha(base),
                before=base.decode('utf-8').splitlines(keepends=True)[1], after='    return ' + expression + '\n')


def test_spec(compiled):
    return dict(schema='transport/finite-predicate-test/1', binding_sha256=compiled['bindings'][2]['sha256'],
        checker_sha256=sha(canonical(finite.checker_identity())), base_source_id='CODE',
        base_source_sha256=sha(CONFIG['fixture']['data']['CODE']), function_name='allow_demo_route',
        parameters=list(PARAMETERS), domains=DOMAINS, expected_bits=expected_bits())


def fixtures():
    CONFIG['fixture'] = encode()
    value = declared_contract(CONFIG['fixture'])
    save(CONFIG['evidence'] / 'contract.json', value)
    CONFIG['compiled'] = contract.compile_contract(canonical(value), CONFIG['fixture']['decoded'], sha(canonical(value)))
    save(CONFIG['evidence'] / 'test.json', test_spec(CONFIG['compiled']))
    expressions = dict(correct='requester_is_keeper and 0 <= age_hours <= 12 and (seal_ok or (repair_mode and ticket_ok))',
        swapped_actor='recipient_is_keeper and 0 <= age_hours <= 12 and (seal_ok or (repair_mode and ticket_ok))',
        off_by_one='requester_is_keeper and 0 <= age_hours < 12 and (seal_ok or (repair_mode and ticket_ok))',
        overbroad_exception='(requester_is_keeper and 0 <= age_hours <= 12 and seal_ok) or (repair_mode and ticket_ok)',
        unsafe_call='__import__("os").system("false") == 0')
    for name, expression in expressions.items():
        save(CONFIG['evidence'] / (name + '.json'), replacement(expression))
    CONFIG['manifest'] = prepare(CONFIG['fixture'])


def cli(replacement_name, changes=None, receipt=None):
    paths = dict(manifest=CONFIG['manifest'], contract=CONFIG['evidence'] / 'contract.json',
                 test=CONFIG['evidence'] / 'test.json', native=CONFIG['native'],
                 replacement=CONFIG['evidence'] / (replacement_name + '.json'))
    if changes:
        paths.update(changes)
    if receipt:
        paths['receipt'] = receipt
    argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(HERE / 'transport_bound_check.py')]
    for key, path in paths.items():
        argv.extend(['--' + key, str(path), '--expect-' + key + '-sha256', sha(read_regular(path))])
    return argv


class Controls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(CONFIG['bundle'] / 'tools'))
        fixtures()

    def checked(self, candidate, outcome):
        result = invoke(cli(candidate))
        self.assertEqual((result['exit_code'], result['stderr']), (0, b''), result['stdout'])
        value = inputs.json_value(result['stdout'])
        self.assertEqual(value['status'], 'CHECKED_AND_EVALUATED')
        self.assertEqual(value['evaluation']['outcome'], outcome)
        self.assertEqual(value['execution_authority'], 'NONE')
        self.assertEqual(value['test_receipt']['state_count'], 480)
        CONFIG['native_checks'] += 1
        return value

    def refused(self, argv):
        result = invoke(argv)
        self.assertEqual((result['exit_code'], result['stderr']), (1, b''), result['stdout'])
        value = inputs.json_value(result['stdout'])
        self.assertEqual(value['status'], 'REFUSED')
        return value

    def test_exact_sources_and_additive_plan(self):
        fixture = CONFIG['fixture']
        self.assertEqual({item['id']: item['data'] for item in fixture['decoded']['sources']}, fixture['data'])
        self.assertEqual(fixture['plan']['meaning_units'][:-1], fixture['original']['meaning_units'])
        self.assertEqual(fixture['plan']['interpretations'][:-1], fixture['original']['interpretations'])
        for key in ('sources', 'relations', 'uncertainties'):
            self.assertEqual(fixture['plan'][key], fixture['original'][key])
        self.assertEqual(CONFIG['compiled']['unevaluated_units'], ['MU_INTERFACE', 'MU_CODE', 'MU_CORRECTION'])
        self.assertEqual([unit['id'] for unit in CONFIG['compiled']['context']['units']],
                         ['MU_INTERFACE', 'MU_CODE', 'MU_CORRECTION', 'MU_TESTABLE_CORRECTION'])
        save(CONFIG['evidence'] / 'source-recovery.json', dict(status='EXACT_SOURCE_BYTES_COMPARED',
             sources=[dict(id=key, **inputs.record(raw)) for key, raw in fixture['data'].items()],
             original_plan_entry_sha256=sha(archived_plan()), original_readings_unchanged=True,
             original_relations_uncertainties_unchanged=True))

    def test_correct_replacement_satisfied(self):
        value = self.checked('correct', 'SATISFIED')
        self.assertEqual(value['test_receipt']['failures'], 0)
        self.assertEqual(value['test_receipt']['truth'], 'KNOWN_TRUE')
        save(CONFIG['evidence'] / 'correct-evaluation.json', value)

    def test_bad_candidates_violated(self):
        for name in ('swapped_actor', 'off_by_one', 'overbroad_exception'):
            with self.subTest(candidate=name):
                value = self.checked(name, 'VIOLATED')
                self.assertGreater(value['test_receipt']['failures'], 0)
                self.assertEqual(value['test_receipt']['truth'], 'KNOWN_FALSE')
                save(CONFIG['evidence'] / (name + '-evaluation.json'), value)

    def test_unsafe_call_refused(self):
        self.refused(cli('unsafe_call'))

    def test_imported_receipt_recomputed(self):
        value = self.checked('correct', 'SATISFIED')
        path = CONFIG['evidence'] / 'import-correct.json'
        save(path, value['test_receipt'])
        result = invoke(cli('correct', receipt=path))
        self.assertEqual((result['exit_code'], result['stderr']), (0, b''), result['stdout'])
        checked = inputs.json_value(result['stdout'])['imported_receipt_check']
        self.assertEqual(checked['status'], 'RECOMPUTED_RECEIPT_MATCH')

    def test_forged_passing_receipt_refused(self):
        receipt = self.checked('off_by_one', 'VIOLATED')['test_receipt']
        receipt.update(truth='KNOWN_TRUE', failures=0, first_mismatches=[], mismatches_truncated=False,
                       actual_bits=expected_bits())
        path = CONFIG['evidence'] / 'forged-true.json'
        save(path, receipt)
        self.assertIn('differs from recomputation', self.refused(cli('off_by_one', receipt=path))['reason'])

    def test_receipt_for_other_candidate_refused(self):
        receipt = self.checked('correct', 'SATISFIED')['test_receipt']
        path = CONFIG['evidence'] / 'wrong-candidate-receipt.json'
        save(path, receipt)
        self.assertIn('differs from recomputation', self.refused(cli('swapped_actor', receipt=path))['reason'])

    def test_changed_checker_refused(self):
        value = inputs.json_value(read_regular(CONFIG['evidence'] / 'test.json'))
        value['checker_sha256'] = '0' * 64
        path = CONFIG['evidence'] / 'changed-checker.json'
        save(path, value)
        self.assertIn('checker identity differs', self.refused(cli('correct', {'test': path}))['reason'])

    def test_truncated_receipt_refused(self):
        value = self.checked('correct', 'SATISFIED')['test_receipt']
        path = CONFIG['evidence'] / 'truncated-receipt.json'
        write_new(path, canonical(value)[:-1])
        self.refused(cli('correct', receipt=path))

    def test_held_input_mismatches_refused(self):
        for key in ('manifest', 'contract', 'test', 'replacement', 'native'):
            argv = cli('correct')
            argv[argv.index('--expect-' + key + '-sha256') + 1] = '0' * 64
            with self.subTest(input=key):
                self.refused(argv)

    def test_original_detailed_reading_stays_unevaluable(self):
        value = declared_contract(CONFIG['fixture'], 'MU_CORRECTION')
        path = CONFIG['evidence'] / 'original-detailed-contract.json'
        save(path, value)
        result = self.refused(cli('correct', {'contract': path}))
        self.assertIn('ambiguous reading is not evaluable', result['reason'])
        self.assertTrue(CONFIG['fixture']['original']['meaning_units'][2]['plan']['meaning']['ambiguities'])

    def test_domain_budget_refused(self):
        value = inputs.json_value(read_regular(CONFIG['evidence'] / 'test.json'))
        value['domains']['age_hours']['max'] = 1000000
        path = CONFIG['evidence'] / 'oversized-domain.json'
        save(path, value)
        self.assertIn('finite Cartesian domain exceeds state bound', self.refused(cli('correct', {'test': path}))['reason'])

    def test_function_bounds_and_no_shell(self):
        for name in (Path(__file__).name, 'transport_bound_check.py', 'transport_finite_check.py'):
            for node in ast.walk(ast.parse(read_regular(HERE / name))):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, (name, node.name))
                if isinstance(node, ast.Call):
                    self.assertFalse(any(item.arg == 'shell' for item in node.keywords))


def evidence_size(root):
    pending, count, total = [root], 0, 0
    for _ in range(256):
        if not pending:
            break
        with os.scandir(pending.pop()) as entries:
            for entry in entries:
                count += 1
                require(count <= 256 and not entry.is_symlink(), 'evidence tree bound')
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
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--native', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    require(all(path.is_absolute() for path in (args.bundle, args.native, args.evidence)), 'absolute paths required')
    require(not args.evidence.exists() and not args.evidence.is_symlink(), 'new evidence directory required')
    args.evidence.mkdir(mode=0o700)
    CONFIG.update(bundle=args.bundle, native=args.native, evidence=args.evidence, processes=0, native_checks=0)
    before = source_freeze()
    CONFIG['before'] = before
    save(args.evidence / 'source-freeze.json', before)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
    require(source_freeze() == before, 'frozen test inputs changed')
    receipt = dict(schema='transport/bound-test-controls/1',
        status='TESTED_SCOPED' if result.wasSuccessful() else 'FAILED', tests_run=result.testsRun,
        failures=[text for _, text in result.failures], errors=[text for _, text in result.errors],
        skipped=[text for _, text in result.skipped], processes=CONFIG['processes'],
        input_freeze_sha256=sha(canonical(before)), output_bytes_before_receipt=evidence_size(args.evidence),
        native_execution='TESTED' if CONFIG['native_checks'] else 'UNPERFORMED', model_execution='UNRUN',
        decoder_execution='ACTUAL_INSTALLED_NATIVE' if CONFIG.get('codec_verified') else 'UNPERFORMED',
        byte_recovery='EXACT_SOURCE_BYTES_COMPARED' if CONFIG.get('codec_verified') else 'UNPERFORMED',
        expected_table_entailment='UNPROVEN', whole_source_completeness='UNPROVEN', execution_authority='NONE')
    save(args.evidence / 'receipt.json', receipt)
    evidence_size(args.evidence)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
