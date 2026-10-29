#!/usr/bin/env python3
"""Bounded public preparation controls using synthetic public source, never models."""

import argparse
import ast
import base64
import copy
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_handoff_inputs as inputs
import transport_handoff_prepare as preparation
import transport_handoff_prepare_inputs as prepare_inputs
from test_portable_handoff import bundle_snapshot
from transport_install_support import canonical, read_regular, require, run_bounded, sha, write_new

ROOT = Path(__file__).absolute().parents[1]
CONFIG = {}


def pin(path):
    return dict(path=str(path), **inputs.record(read_regular(path)))


def save(path, value):
    write_new(path, canonical(value), inputs.CAP)


def invoke(argv):
    number = CONFIG['commands']
    require(number < 96, 'test process count bound')
    CONFIG['commands'] += 1
    result = run_bounded(argv, CONFIG['evidence'], inputs.ENV, timeout=45, cap=inputs.CAP)
    for stream in ('stdout', 'stderr'):
        write_new(CONFIG['evidence'] / ('process-%03d.%s' % (number, stream)), result[stream], inputs.CAP)
    save(CONFIG['evidence'] / ('process-%03d.json' % number),
         {key: value for key, value in result.items() if key not in ('stdout', 'stderr')}
         | {stream: inputs.record(result[stream]) for stream in ('stdout', 'stderr')})
    return result


def fixture():
    source = ROOT / 'examples/handoff-v1'
    plan = inputs.json_value(read_regular(source / 'plan.json'))
    target = CONFIG['evidence'] / 'encoded'
    argv = [str(CONFIG['bundle'] / 'bin/semantic-transport'), 'encode-plan', str(source / 'plan.json'),
            str(target), '--budget', '8192', '--reference', 'attached:meaning.zip']
    entries = []
    for item in plan['sources']:
        path = source / 'source' / (item['id'].lower() + '.txt')
        argv.extend(['--source', item['id'] + '=' + str(path)])
        entries.append(dict(item, **pin(path)))
    result = invoke(argv)
    require(result['status'] == 'SUCCESS' and result['exit_code'] == 0 and result['stderr'] == b'',
            'public synthetic encode refused; outputs retained')
    value = inputs.json_value(result['stdout'])
    share = read_regular(target / 'share.txt')
    identity = 'STS1:' + share.decode().split('STS1:', 1)[1].split()[0]
    task = CONFIG['evidence'] / 'task.txt'
    write_new(task, b'Read task-related records and save one JSON draft with explicit unknowns.\n')
    return dict(sources=entries, package=target, identity=identity, task=pin(task), encoded=value)


class PreparationControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        CONFIG['fixture'] = fixture()

    def setUp(self):
        self.root = CONFIG['evidence'] / self.id().split('.')[-1]
        self.root.mkdir(mode=0o700)
        self.serial = 0

    def config(self, arm):
        source = CONFIG['fixture']
        value = dict(schema=prepare_inputs.SCHEMA, arm=arm, task=source['task'],
                     python=pin(Path(sys.executable).resolve()), sources=copy.deepcopy(source['sources']))
        if arm == 'transport':
            for item in value['sources']:
                del item['path']
            snapshot = bundle_snapshot(CONFIG['bundle'])
            value.update(bundle=dict(path=str(CONFIG['bundle']), install_sha256=snapshot['install_manifest']['sha256'],
                                     snapshot_sha256=sha(canonical(snapshot))),
                         pair=dict(share=pin(source['package'] / 'share.txt'), archive=pin(source['package'] / 'meaning.zip'),
                                   identity=source['identity']))
        return value

    def prepare(self, value, expected=None):
        self.serial += 1
        path = self.root / ('config-%02d.json' % self.serial)
        output = self.root / ('received-%02d' % self.serial)
        save(path, value)
        argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(ROOT / 'install/transport_handoff_prepare.py'),
                '--config', str(path), '--expect-config-sha256', expected or sha(read_regular(path)), '--output', str(output)]
        result = invoke(argv)
        self.assertEqual(result['stderr'], b'')
        self.assertIn(result['status'], ('SUCCESS', 'EXIT_NONZERO'))
        self.assertLessEqual(len(result['stdout']), inputs.CAP)
        return output, inputs.json_value(result['stdout']), result

    def client(self, root, request):
        binding = root / 'client-binding.json'
        argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(root / 'helpers/transport_handoff_client.py'),
                '--binding', str(binding), '--expect-binding-sha256', sha(read_regular(binding)),
                '--request-json', canonical(request).decode()]
        result = invoke(argv)
        self.assertEqual(result['stderr'], b'')
        return inputs.json_value(result['stdout'], inputs.CAP)

    def failed(self, value, partial=False):
        root, answer, result = self.prepare(value)
        self.assertEqual(answer['status'], 'REFUSED')
        self.assertNotEqual(result['exit_code'], 0)
        self.assertFalse((root / 'client-binding.json').exists())
        self.assertFalse((root / 'interface.txt').exists())
        if partial:
            self.assertEqual(inputs.json_value(read_regular(root / 'preparation-failure.json'))['status'], 'FAILED_PARTIAL_RETAINED')
        else:
            self.assertFalse(root.exists())
        return root

    def test_original_exact_bytes_no_decoder_generic_interface_and_finish(self):
        root, answer, result = self.prepare(self.config('original'))
        self.assertEqual((answer['status'], result['exit_code']), ('PREPARED_NOT_DISPATCHED', 0))
        manifest = inputs.json_value(read_regular(root / 'manifest.json'))
        self.assertNotIn('bundle', manifest)
        self.assertFalse((root / 'decoder').exists())
        self.assertFalse((root / 'helpers/test_portable_handoff.py').exists())
        self.assertFalse((root / 'sessions/recipient').exists())
        self.assertEqual(list((root / 'sessions').iterdir()), [])
        self.assertEqual(len(manifest['helpers']), 6)
        text = read_regular(root / 'interface.txt').decode()
        self.assertLess(len(text.encode()), 8192)
        self.assertIn('SOURCE_ID', text)
        self.assertNotIn('U_APPROVAL', text)
        self.assertNotIn('APPROVAL', text)
        for entry, original in zip(manifest['sources'], CONFIG['fixture']['sources'], strict=True):
            self.assertEqual(read_regular(root / 'content' / entry['path']), read_regular(Path(original['path'])))
        self.assertEqual(self.client(root, {'action': 'describe'})['status'], 'OK')
        draft = b'{ "draft": "unreviewed", "unknown": true }\n'
        self.assertEqual(self.client(root, {'action': 'finish', 'candidate_base64': base64.b64encode(draft).decode()})['status'], 'OK')
        self.assertEqual(read_regular(root / 'sessions/recipient/candidate.json'), draft)

    def test_transport_copy_focus_and_identical_catalog(self):
        left, _, _ = self.prepare(self.config('original'))
        right, answer, result = self.prepare(self.config('transport'))
        self.assertEqual((answer['status'], result['exit_code']), ('PREPARED_NOT_DISPATCHED', 0))
        self.assertTrue((right / 'decoder/INSTALL.json').is_file())
        self.assertEqual(bundle_snapshot(right / 'decoder')['files'], bundle_snapshot(CONFIG['bundle'])['files'])
        for root in (left, right):
            self.assertEqual(self.client(root, {'action': 'describe'})['status'], 'OK')
        self.assertEqual(self.client(left, {'action': 'catalog'})['result'], self.client(right, {'action': 'catalog'})['result'])
        page_left = self.client(left, {'action': 'page', 'source': 'WORK', 'offset': 0})
        page_right = self.client(right, {'action': 'page', 'source': 'WORK', 'offset': 0})
        self.assertEqual(page_left['result']['base64'], page_right['result']['base64'])
        unit = page_right['result']['review']['meaning_units'][0]['unit']
        focus = self.client(right, {'action': 'focus', 'unit': unit})
        self.assertEqual(focus['status'], 'OK')
        self.assertEqual(focus['result']['execution_authority'], 'NONE')
        text = read_regular(right / 'interface.txt').decode()
        self.assertIn('result.review.meaning_units[].unit', text)

    def test_wrong_held_config(self):
        root, answer, _ = self.prepare(self.config('original'), '0' * 64)
        self.assertEqual(answer['status'], 'REFUSED')
        self.assertFalse(root.exists())

    def test_changed_source_and_missing_source(self):
        value = self.config('original')
        value['sources'][0]['sha256'] = '0' * 64
        self.failed(value)
        value['sources'][0]['path'] = str(self.root / 'absent.txt')
        self.failed(value)

    def test_source_metadata_ids_duplicates_and_bounds(self):
        for change in ('duplicate', 'id', 'count', 'bytes', 'label'):
            value = self.config('original')
            if change == 'duplicate':
                value['sources'].append(value['sources'][0])
            elif change == 'id':
                value['sources'][0]['id'] = '../bad'
            elif change == 'count':
                value['sources'] = value['sources'] * 4
            elif change == 'bytes':
                value['sources'][0]['bytes'] = True
            else:
                value['sources'][0]['label'] = 'x' * 1025
            self.failed(value)

    def test_wrong_python_task_and_unknown_fields(self):
        value = self.config('original')
        value['python']['sha256'] = '0' * 64
        self.failed(value)
        value = self.config('original')
        value['task']['sha256'] = '0' * 64
        self.failed(value)
        value = self.config('original')
        value['answers'] = {'publication': 'invented'}
        self.failed(value)
        value = self.config('original')
        value['bundle'] = {}
        self.failed(value)

    def test_bundle_pair_held_identity_refusals(self):
        for key in ('install_sha256', 'snapshot_sha256'):
            value = self.config('transport')
            value['bundle'][key] = '0' * 64
            self.failed(value)
        value = self.config('transport')
        value['pair']['archive']['sha256'] = '0' * 64
        self.failed(value)
        value = self.config('transport')
        value['pair']['identity'] = 'STS1:' + '0' * 64
        self.failed(value, partial=True)

    def test_preflight_metadata_mismatch_retains_failure_no_endpoint(self):
        value = self.config('transport')
        value['sources'][0]['provenance'] += ' changed'
        root = self.failed(value, partial=True)
        self.assertTrue((root / 'preflight.stdout').exists())
        self.assertFalse((root / 'preparation.json').exists())

    def test_existing_output_preserved(self):
        value = self.config('original')
        root, answer, _ = self.prepare(value)
        self.assertEqual(answer['status'], 'PREPARED_NOT_DISPATCHED')
        before = read_regular(root / 'manifest.json')
        argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(ROOT / 'install/transport_handoff_prepare.py'),
                '--config', str(self.root / 'config-01.json'), '--expect-config-sha256', sha(read_regular(self.root / 'config-01.json')),
                '--output', str(root)]
        self.assertEqual(inputs.json_value(invoke(argv)['stdout'])['status'], 'REFUSED')
        self.assertEqual(read_regular(root / 'manifest.json'), before)
        self.assertFalse((root / 'preparation-failure.json').exists())

    def test_duplicate_paths_bad_task_and_mutation_recheck(self):
        value = self.config('original')
        value['task'] = {key: value['sources'][0][key] for key in ('path', 'bytes', 'sha256')}
        self.failed(value)
        task = self.root / 'bad-task.txt'
        write_new(task, b'\xff')
        value = self.config('original')
        value['task'] = pin(task)
        self.failed(value)
        path = self.root / 'local.txt'
        write_new(path, b'first')
        state = dict(checks=[(path, b'first')], snapshot=None)
        self.assertIsNone(prepare_inputs.verify(state))
        path.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            prepare_inputs.verify(state)

    def test_function_limits_and_no_shell_subprocess_calls(self):
        for name in ('transport_handoff_prepare.py', 'transport_handoff_prepare_inputs.py', 'test_handoff_prepare.py'):
            tree = ast.parse(read_regular(ROOT / 'install' / name))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, (name, node.name))
                if isinstance(node, ast.Call):
                    self.assertFalse(any(key.arg == 'shell' for key in node.keywords))

    def test_output_bundle_overlap_and_symlink_parent_refused(self):
        value = self.config('transport')
        path = self.root / 'transport.json'
        save(path, value)
        with self.assertRaises(ValueError):
            preparation.prepare(path, sha(read_regular(path)), CONFIG['bundle'] / 'must-not-create')
        self.assertFalse((CONFIG['bundle'] / 'must-not-create').exists())
        target = self.root / 'real-parent'
        target.mkdir()
        link = self.root / 'link-parent'
        link.symlink_to(target, target_is_directory=True)
        value = self.config('original')
        path = self.root / 'original.json'
        save(path, value)
        with self.assertRaises(OSError):
            preparation.prepare(path, sha(read_regular(path)), link / 'must-not-create')
        self.assertFalse((target / 'must-not-create').exists())

    def test_late_publication_failure_is_explicit_partial(self):
        path = self.root / 'config.json'
        save(path, self.config('original'))
        target = self.root / 'received'
        original = preparation.save
        def refuse_success(path, value):
            if path.name == 'preparation.json':
                raise OSError('synthetic late receipt failure')
            original(path, value)
        with patch.object(preparation, 'save', refuse_success), self.assertRaises(OSError):
            preparation.prepare(path, sha(read_regular(path)), target)
        self.assertTrue((target / 'client-binding.json').exists())
        self.assertTrue((target / 'interface.txt').exists())
        self.assertFalse((target / 'preparation.json').exists())
        self.assertEqual(inputs.json_value(read_regular(target / 'preparation-failure.json'))['status'], 'FAILED_PARTIAL_RETAINED')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    require(args.bundle.is_absolute() and args.evidence.is_absolute(), 'absolute bundle/evidence required')
    require(not args.evidence.exists() and not args.evidence.is_symlink(), 'new evidence directory required')
    args.evidence.mkdir(mode=0o700)
    CONFIG.update(bundle=args.bundle, evidence=args.evidence, commands=0)
    before = bundle_snapshot(args.bundle)
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PreparationControls)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    require(bundle_snapshot(args.bundle) == before, 'test input installation changed')
    receipt = dict(schema='transport/handoff-preparation-controls/1', status='TESTED_SCOPED' if result.wasSuccessful() else 'FAILED',
                   tests_run=result.testsRun, commands=CONFIG['commands'], failures=[text for _, text in result.failures],
                   errors=[text for _, text in result.errors], fixture='Public synthetic handoff-v1', model_execution='UNRUN',
                   helpers=[pin(ROOT / 'install' / name) for name in
                            ('transport_handoff_prepare.py', 'transport_handoff_prepare_inputs.py', 'test_handoff_prepare.py')],
                   bundle=before, limitations='Named deterministic controls, not formal proof or comparative model evidence.')
    save(args.evidence / 'receipt.json', receipt)
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
