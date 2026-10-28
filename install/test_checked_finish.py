#!/usr/bin/env python3
"""Bounded original-reader checked submission controls, no decoder or model."""
import argparse
import ast
import base64
import io
import json
from pathlib import Path
from types import SimpleNamespace
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_checked_finish as checked
import transport_handoff_inputs as inputs
from transport_install_support import canonical, read_regular, require, run_bounded, sha, write_new

HERE = Path(__file__).absolute().parent
CONFIG = {}


def pin(path):
    raw = read_regular(path)
    return dict(path=str(path), bytes=len(raw), sha256=sha(raw))


def frozen(path, held):
    raw = read_regular(path, 32768)
    require(sha(raw) == held, 'held test freeze differs')
    value = inputs.json_value(raw, 32768)
    require(type(value['files']) is list and len(value['files']) == 16, 'test closure count differs')
    names = [item['path'] for item in value['files']]
    require(len(set(names)) == 16, 'duplicate test closure path')
    for item in value['files']:
        require(pin(Path(item['path'])) == item, 'frozen test source changed')
    return raw


def sample():
    return dict(decoder_execution_authority='NONE', source_approval='UNKNOWN', actions=[dict(id='review', status='PENDING')],
                attempt_count=1, note='', is_draft=True, reserved=None)


def fixture(root):
    helpers, content, sessions = root / 'helpers', root / 'content', root / 'sessions'
    for path in (helpers, content, sessions):
        path.mkdir()
    for name in inputs.BOOTSTRAP + ('transport_handoff_client.py',):
        write_new(helpers / name, read_regular(HERE / name))
    marker = root / 'SOURCE_MUST_NOT_EXECUTE'
    raw = ('Synthetic source only. $(touch ' + str(marker) + ')\n').encode()
    source = content / 'source.txt'
    write_new(source, raw)
    python = pin(Path(sys.executable).resolve())
    manifest = dict(schema=inputs.SCHEMA, arm='original', helpers=[pin(helpers / name) for name in inputs.BOOTSTRAP],
                    python=python, content=dict(root=str(content), files=[dict(path='source.txt', bytes=len(raw), sha256=sha(raw))]),
                    sources=[dict(id='SOURCE', label='Synthetic document', media_type='text/plain', provenance='synthetic control',
                                  path='source.txt', bytes=len(raw))], held_source_sha256=dict(SOURCE=sha(raw)))
    write_new(root / 'manifest.json', canonical(manifest))
    binding = dict(schema='transport/handoff-client/1', manifest=pin(root / 'manifest.json'), session=str(sessions / 'recipient'),
                   reader=pin(helpers / 'transport_handoff_reader.py'), python=python, client=pin(helpers / 'transport_handoff_client.py'))
    write_new(root / 'binding.json', canonical(binding))
    write_new(root / 'contract.json', read_regular(HERE / 'response_contract_example.json'))
    write_new(root / 'draft.json', json.dumps(sample(), indent=2, ensure_ascii=False).encode() + b'\n')
    return SimpleNamespace(binding=root / 'binding.json', expect_binding_sha256=pin(root / 'binding.json')['sha256'],
                           contract=root / 'contract.json', expect_contract_sha256=pin(root / 'contract.json')['sha256'],
                           candidate=root / 'draft.json', session=sessions / 'recipient', marker=marker)


def command(args):
    return [str(Path(sys.executable).resolve()), '-I', '-S', '-B', '-Werror', str(HERE / 'transport_checked_finish.py'),
            '--contract', str(args.contract), '--expect-contract-sha256', args.expect_contract_sha256,
            '--candidate', str(args.candidate), '--binding', str(args.binding), '--expect-binding-sha256', args.expect_binding_sha256]


def invoke(argv, cap=131072):
    number = CONFIG['processes']
    require(number < 32, 'bounded test process count')
    CONFIG['processes'] += 1
    result = run_bounded(argv, CONFIG['evidence'], inputs.ENV, timeout=45, cap=cap)
    for stream in ('stdout', 'stderr'):
        write_new(CONFIG['evidence'] / ('process-%02d.%s' % (number, stream)), result[stream], 131072)
    record = {key: value for key, value in result.items() if key not in ('stdout', 'stderr')}
    record.update(argv=argv, stdout=inputs.record(result['stdout']), stderr=inputs.record(result['stderr']))
    write_new(CONFIG['evidence'] / ('process-%02d.json' % number), canonical(record), 131072)
    return result


class Controls(unittest.TestCase):
    def setUp(self):
        self.root = CONFIG['evidence'] / self._testMethodName
        self.root.mkdir()
        self.args = fixture(self.root)

    def call(self):
        result = invoke(command(self.args))
        self.assertEqual(result['stderr'], b'')
        self.assertTrue(result['stdout'].endswith(b'\n'))
        self.assertLessEqual(len(result['stdout']), 131072)
        return result, json.loads(result['stdout'])

    def no_candidate(self, status='REFUSED'):
        result, value = self.call()
        self.assertNotEqual(result['exit_code'], 0)
        self.assertEqual(value['status'], status)
        self.assertFalse(value['client_dispatched'])
        self.assertFalse(self.args.session.exists())
        self.assertFalse(self.args.marker.exists())

    def test_exact_original_reader_save_and_source_inert(self):
        raw = read_regular(self.args.candidate)
        result, value = self.call()
        self.assertEqual((result['status'], result['exit_code']), ('SUCCESS', 0))
        self.assertEqual(value['status'], 'DRAFT_SAVED_STRUCTURALLY_CHECKED')
        self.assertEqual(read_regular(self.args.session / 'candidate.json'), raw)
        self.assertEqual([item['action'] for item in value['calls']], ['describe', 'finish'])
        self.assertEqual(len(list(self.args.session.glob('call-*.json'))), 2)
        self.assertEqual(value['execution_authority'], 'NONE')
        self.assertEqual(value['source_approval'], 'NOT_ASSESSED')
        self.assertFalse(self.args.marker.exists())

    def test_existing_session_uses_only_finish(self):
        value = json.loads(read_regular(self.args.binding))
        argv = [value['python']['path'], '-I', '-S', '-B', '-Werror', value['client']['path'], '--binding',
                str(self.args.binding), '--expect-binding-sha256', self.args.expect_binding_sha256,
                '--request-json', '{"action":"describe"}']
        self.assertEqual(invoke(argv)['exit_code'], 0)
        result, answer = self.call()
        self.assertEqual(result['exit_code'], 0)
        self.assertEqual([item['action'] for item in answer['calls']], ['finish'])

    def test_wrong_contract_pin_no_action(self):
        self.args.expect_contract_sha256 = '0' * 64
        self.no_candidate()

    def test_wrong_binding_pin_no_action(self):
        self.args.expect_binding_sha256 = '0' * 64
        self.no_candidate()

    def test_closed_shape_no_action(self):
        value = sample()
        value['extra'] = 'unrecognized'
        self.args.candidate.write_bytes(canonical(value))
        self.no_candidate('STRUCTURAL_MISMATCH')

    def test_duplicate_ids_no_action(self):
        value = sample()
        value['actions'].append(dict(id='review', status='UNKNOWN'))
        self.args.candidate.write_bytes(canonical(value))
        self.no_candidate('STRUCTURAL_MISMATCH')

    def test_bool_not_integer_no_action(self):
        value = sample()
        value['attempt_count'] = True
        self.args.candidate.write_bytes(canonical(value))
        self.no_candidate('STRUCTURAL_MISMATCH')

    def test_duplicate_json_keys_no_action(self):
        self.args.candidate.write_bytes(b'{"actions":[],"actions":[]}')
        self.no_candidate()

    def test_malformed_candidate_no_action(self):
        self.args.candidate.write_bytes(b'{"actions":[')
        self.no_candidate()

    def test_overbound_candidate_no_action(self):
        self.args.candidate.write_bytes(b' ' * 32769)
        self.no_candidate()

    def test_tampered_client_no_action(self):
        path = self.root / 'helpers' / 'transport_handoff_client.py'
        path.write_bytes(read_regular(path) + b'\n')
        self.no_candidate()

    def test_unexpected_helper_no_action(self):
        write_new(self.root / 'helpers' / 'shadow.py', b'raise RuntimeError("must not execute")\n')
        self.no_candidate()

    def test_held_source_change_no_action(self):
        (self.root / 'content' / 'source.txt').write_bytes(b'changed')
        self.no_candidate()

    def test_finished_session_refuses_without_overwriting(self):
        first, _ = self.call()
        self.assertEqual(first['exit_code'], 0)
        saved = read_regular(self.args.session / 'candidate.json')
        result, value = self.call()
        self.assertNotEqual(result['exit_code'], 0)
        self.assertTrue(value['reader_action_may_be_recorded'])
        self.assertEqual(value['draft_state'], 'UNKNOWN_MAY_BE_SAVED')
        self.assertEqual(read_regular(self.args.session / 'candidate.json'), saved)
        stream = value['calls'][0]['stdout']
        self.assertTrue(stream['capture_complete'])
        self.assertIn('finished', base64.b64decode(stream['base64']).decode())

    def test_real_save_then_input_drift_reports_possible_recording(self):
        original = checked.client_call
        output = io.BytesIO()
        def changing(state, binding, request):
            answer = original(state, binding, request)
            if request['action'] == 'finish':
                self.args.candidate.write_bytes(b'{}')
            return answer
        argv = ['checked'] + command(self.args)[6:]
        with patch.object(checked, 'client_call', changing), patch.object(checked.resource, 'setrlimit'), \
             patch.object(checked.sys, 'argv', argv), patch.object(checked.sys, 'stdout', SimpleNamespace(buffer=output)):
            status = checked.main()
        value = json.loads(output.getvalue())
        self.assertEqual((status, value['status']), (2, 'REFUSED'))
        self.assertTrue(value['reader_action_may_be_recorded'])
        self.assertEqual(value['draft_state'], 'UNKNOWN_MAY_BE_SAVED')
        self.assertNotEqual(read_regular(self.args.session / 'candidate.json'), read_regular(self.args.candidate))

    def test_missing_lock_reason_retained_without_reader_ledger(self):
        self.args.session.mkdir()
        result, value = self.call()
        self.assertNotEqual(result['exit_code'], 0)
        stream = value['calls'][0]['stdout']
        self.assertTrue(stream['capture_complete'])
        self.assertIn('lock', base64.b64decode(stream['base64']).decode())
        self.assertFalse((self.args.session / 'candidate.json').exists())
        self.assertFalse(any(self.args.session.glob('call-*.json')))
        self.assertEqual(value['draft_state'], 'UNKNOWN_MAY_BE_SAVED')

    def test_actual_process_truncated_prefix_retained(self):
        code = 'import os;os.write(1,b"\\xff\\x00"+b"x"*' + str(checked.PROCESS_CAP) + ')'
        process = invoke([str(Path(sys.executable).resolve()), '-I', '-S', '-B', '-Werror', '-c', code], checked.PROCESS_CAP)
        self.assertEqual(process['status'], 'REFUSED_OUTPUT_LIMIT')
        self.assertEqual(len(process['stdout']), checked.PROCESS_CAP)
        self.args.session.mkdir()
        output = io.BytesIO()
        with patch.object(checked, 'run_bounded', return_value=process), patch.object(checked.resource, 'setrlimit'), \
             patch.object(checked.sys, 'argv', ['checked'] + command(self.args)[6:]), \
             patch.object(checked.sys, 'stdout', SimpleNamespace(buffer=output)):
            status = checked.main()
        value = json.loads(output.getvalue())
        self.assertEqual((status, value['status']), (2, 'REFUSED'))
        self.assertEqual(value['draft_state'], 'UNKNOWN_MAY_BE_SAVED')
        self.assertTrue(value['reader_action_may_be_recorded'])
        for name in ('stdout', 'stderr'):
            stream = value['calls'][0][name]
            self.assertFalse(stream['capture_complete'])
            self.assertEqual(stream['extent'], 'PREFIX_OR_INCOMPLETE')
            self.assertEqual(base64.b64decode(stream['base64']), process[name])
            self.assertEqual(stream['sha256'], sha(process[name]))
        self.assertLessEqual(len(output.getvalue()), 131072)

    def test_non_utf8_candidates_refuse_without_action(self):
        raw = json.dumps(sample())
        for encoding in ('utf-16', 'utf-32', 'utf-16-le', 'utf-32-be'):
            self.args.candidate.write_bytes(raw.encode(encoding))
            self.no_candidate()
        for data in (b'\xff{}', b'\xef\xbb\xbf' + raw.encode(), b'{"note":"\xed\xa0\x80"}',
                     raw.replace('"note": ""', '"note": "\\ud800"').encode(),
                     raw.replace('"note": ""', '"note": "\\udfff"').encode()):
            self.args.candidate.write_bytes(data)
            self.no_candidate()

    def test_multibyte_and_escaped_surrogate_pair_saved_exactly(self):
        value = sample()
        value['note'] = 'λ😀'
        raw = json.dumps(value, ensure_ascii=False).replace('😀', r'\ud83d\ude00').encode('utf-8') + b'\n'
        self.args.candidate.write_bytes(raw)
        result, answer = self.call()
        self.assertEqual((result['exit_code'], answer['status']), (0, 'DRAFT_SAVED_STRUCTURALLY_CHECKED'))
        self.assertEqual(read_regular(self.args.session / 'candidate.json'), raw)

    def test_non_utf8_contract_refuses_without_action(self):
        raw = read_regular(self.args.contract).decode()
        for encoding in ('utf-16', 'utf-32'):
            data = raw.encode(encoding)
            self.args.contract.write_bytes(data)
            self.args.expect_contract_sha256 = sha(data)
            self.no_candidate()

    def test_new_functions_short_and_no_recursion(self):
        for name in ('transport_checked_finish.py', 'test_checked_finish.py', 'freeze_response_contract_tests.py'):
            tree = ast.parse(read_regular(HERE / name))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, (name, node.name))
                    calls = [item for item in ast.walk(node) if isinstance(item, ast.Call) and isinstance(item.func, ast.Name)]
                    self.assertFalse(any(item.func.id == node.name for item in calls), (name, node.name))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--freeze', type=Path, required=True)
    parser.add_argument('--expect-freeze-sha256', required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    before = frozen(args.freeze, args.expect_freeze_sha256)
    require(args.evidence.is_absolute() and not args.evidence.exists(), 'new absolute evidence directory required')
    args.evidence.mkdir(mode=0o700)
    CONFIG.update(evidence=args.evidence, processes=0)
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(Controls))
    require(frozen(args.freeze, args.expect_freeze_sha256) == before, 'test source changed')
    value = dict(schema='transport/checked-finish-controls/1', status='TESTED_SCOPED' if result.wasSuccessful() else 'FAILED',
                 tests_run=result.testsRun, processes=CONFIG['processes'], failures=[item for _, item in result.failures],
                 errors=[item for _, item in result.errors], input_freeze_sha256=args.expect_freeze_sha256,
                 models='UNRUN', transport_decoder='UNRUN', scope='STRUCTURAL_CHECK_AND_ORIGINAL_DRAFT_CUSTODY_ONLY')
    write_new(args.evidence / 'receipt.json', canonical(value) + b'\n', 131072)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
