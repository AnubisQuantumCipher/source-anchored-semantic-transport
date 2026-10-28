#!/usr/bin/env python3
"""Scoped reader controls against an explicit installed bundle; no model trial."""

import argparse
import ast
import base64
import json
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_handoff_inputs as inputs
import transport_handoff_reader as reader
from test_portable_handoff import bundle_snapshot
from transport_install_support import canonical, read_regular, require, run_bounded, sha, write_new

ROOT = Path(__file__).absolute().parents[1]
CONFIG = {}
SOURCE_NAMES = ('APPROVAL', 'CORRECTION', 'REVOCATION', 'WORK', 'UNRELATED')


def pin(path, relative=None):
    raw = read_regular(path)
    return {'path': str(path) if relative is None else relative, 'bytes': len(raw), 'sha256': sha(raw)}


def stored_json(path, value):
    write_new(path, canonical(value), inputs.CAP)


def process_record(number, result):
    root = CONFIG['evidence']
    for stream in ('stdout', 'stderr'):
        write_new(root / ('process-%03d.%s' % (number, stream)), result[stream], inputs.CAP)
    stored_json(root / ('process-%03d.json' % number),
                {key: value for key, value in result.items() if key not in ('stdout', 'stderr')}
                | {stream: inputs.record(result[stream]) for stream in ('stdout', 'stderr')})


def invoke(argv):
    number = CONFIG['commands']
    require(number < 128, 'test command count bound')
    CONFIG['commands'] += 1
    result = run_bounded(argv, CONFIG['evidence'], inputs.ENV, timeout=30, cap=inputs.CAP)
    process_record(number, result)
    return result


def fixture():
    directory = ROOT / 'examples' / 'handoff-v1'
    plan = inputs.json_value(read_regular(directory / 'plan.json'))
    target = CONFIG['evidence'] / 'encoded'
    argv = [str(CONFIG['bundle'] / 'bin' / 'semantic-transport'), 'encode-plan',
            str(directory / 'plan.json'), str(target), '--budget', '8192', '--reference', 'attached:meaning.zip']
    for name in SOURCE_NAMES:
        argv.extend(['--source', name + '=' + str(directory / 'source' / (name.lower() + '.txt'))])
    result = invoke(argv)
    require(result['status'] == 'SUCCESS', 'synthetic fixture encoding refused; outputs retained')
    encoded = inputs.json_value(result['stdout'])
    share = read_regular(target / 'share.txt', inputs.CAP)
    identity = 'STS1:' + share.decode().split('STS1:', 1)[1].split()[0]
    return {'sources': plan['sources'], 'encoded': encoded, 'identity': identity, 'directory': directory}


class ReaderControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        CONFIG['fixture'] = fixture()

    def setUp(self):
        self.root = CONFIG['evidence'] / self.id().split('.')[-1]
        self.root.mkdir(mode=0o700)
        self.serial = 0

    def manifest(self, arm, tag='case', helper_root=None):
        case = self.root / tag
        case.mkdir(mode=0o700)
        content = case / 'content'
        content.mkdir(mode=0o700)
        source = CONFIG['fixture']
        metadata, held = [], {}
        for item in source['sources']:
            raw = read_regular(source['directory'] / 'source' / (item['id'].lower() + '.txt'))
            entry = dict(item, bytes=len(raw))
            held[item['id']] = sha(raw)
            if arm == 'original':
                entry['path'] = item['id'].lower() + '.txt'
                write_new(content / entry['path'], raw)
            metadata.append(entry)
        if arm == 'transport':
            for name in ('share.txt', 'meaning.zip'):
                write_new(content / name, read_regular(CONFIG['evidence'] / 'encoded' / name))
        names = inputs.BOOTSTRAP + (('test_portable_handoff.py',) if arm == 'transport' else ())
        helpers = helper_root or ROOT / 'install'
        value = {'schema': inputs.SCHEMA, 'arm': arm, 'helpers': [pin(helpers / name) for name in names],
                 'python': pin(Path(sys.executable).resolve()),
                 'content': {'root': str(content), 'files': [pin(path, path.name) for path in sorted(content.iterdir())]},
                 'sources': metadata, 'held_source_sha256': held}
        if arm == 'transport':
            bundle = CONFIG['bundle']
            value['bundle'] = {'path': str(bundle), 'install_sha256': sha(read_regular(bundle / 'INSTALL.json')),
                               'snapshot_sha256': sha(canonical(bundle_snapshot(bundle)))}
            value['pair'] = {'share': 'share.txt', 'archive': 'meaning.zip', 'identity': source['identity']}
        path = case / 'manifest.json'
        stored_json(path, value)
        return {'value': value, 'path': path, 'session': case / 'session', 'reader': helpers / 'transport_handoff_reader.py'}

    def rewrite_manifest(self, context, value):
        self.serial += 1
        path = context['path'].parent / ('manifest-%02d.json' % self.serial)
        stored_json(path, value)
        return dict(context, path=path, value=value)

    def call(self, context, request, expected=None, inline=False):
        self.serial += 1
        raw = request if type(request) is bytes else canonical(request)
        path = self.root / ('request-%03d.json' % self.serial)
        write_new(path, raw)
        argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(context['reader']),
                '--manifest', str(context['path']), '--expect-manifest-sha256',
                expected or sha(read_regular(context['path'])), '--session', str(context['session'])]
        argv.extend(['--request-json', raw.decode()] if inline else ['--request', str(path)])
        result = invoke(argv)
        self.assertIn(result['status'], ('SUCCESS', 'EXIT_NONZERO'))
        self.assertEqual(result['stderr'], b'')
        self.assertLessEqual(len(result['stdout']), inputs.CAP)
        self.assertTrue(result['stdout'].endswith(b'\n'))
        return inputs.json_value(result['stdout'], inputs.CAP)

    def start(self, context):
        self.assertEqual(self.call(context, {'action': 'describe'})['status'], 'OK')

    def test_original_pages_catalog_and_exact_unedited_finish(self):
        context = self.manifest('original')
        self.assertNotIn('bundle', context['value'])
        self.start(context)
        catalog = self.call(context, {'action': 'catalog'}, inline=True)['result']
        self.assertEqual([item['id'] for item in catalog['sources']], list(SOURCE_NAMES))
        self.assertNotIn('meaning_units', catalog)
        page = self.call(context, {'action': 'page', 'source': 'APPROVAL', 'offset': 0})['result']
        original = read_regular(CONFIG['fixture']['directory'] / 'source' / 'approval.txt')
        self.assertEqual(base64.b64decode(page['base64']), original)
        self.assertNotIn('review', page)
        draft = b'{ "draft": "unreviewed", "publication": "HOLD" }\n'
        answer = self.call(context, {'action': 'finish', 'candidate_base64': base64.b64encode(draft).decode()})
        self.assertEqual(answer['result']['completeness'], 'NOT_ASSESSED')
        self.assertEqual(read_regular(context['session'] / 'candidate.json'), draft)
        self.assertEqual(self.call(context, {'action': 'catalog'})['status'], 'REFUSED')

    def test_transport_focus_catalog_matches_original_and_pages(self):
        original, transport = self.manifest('original', 'original'), self.manifest('transport', 'transport')
        self.start(original)
        self.start(transport)
        self.assertEqual(self.call(original, {'action': 'catalog'})['result'], self.call(transport, {'action': 'catalog'})['result'])
        focus = self.call(transport, {'action': 'focus', 'unit': 'U_APPROVAL'})['result']
        self.assertEqual([item['id'] for item in focus['meaning_units']], ['U_APPROVAL', 'U_CORRECTION', 'U_REVOKE', 'U_PENDING'])
        self.assertEqual({item['id'] for item in focus['uncertainties']}, {'Q_MISSING', 'Q_CONFLICT'})
        self.assertNotIn('UNRELATED', [item['id'] for item in focus['sources']])
        self.assertEqual(focus['execution_authority'], 'NONE')
        left = self.call(original, {'action': 'page', 'source': 'WORK', 'offset': 0})['result']
        right = self.call(transport, {'action': 'page', 'source': 'WORK', 'offset': 0})['result']
        self.assertEqual(left['base64'], right['base64'])
        self.assertEqual(right['span'], left['span'])

    def test_invalid_requests_are_counted_and_unrelated_is_observed(self):
        context = self.manifest('original')
        self.start(context)
        bad = (b'{"action":"catalog","action":"page"}', b'{"action":',
               {'action': 'catalog', 'extra': True}, {'action': 'focus', 'unit': 'U_APPROVAL'},
               {'action': 'page', 'source': 'MISSING', 'offset': 0},
               {'action': 'page', 'source': 'WORK', 'offset': True}, {'action': 'execute'})
        for number, request in enumerate(bad, 2):
            reply = self.call(context, request)
            self.assertEqual(reply['status'], 'REFUSED')
            self.assertEqual(reply['call'], number)
        reply = self.call(context, {'action': 'page', 'source': 'UNRELATED', 'offset': 0})
        self.assertEqual(reply['status'], 'OK')
        raw = read_regular(context['session'] / ('request-%02d.json' % reply['call']))
        self.assertEqual(inputs.json_value(raw)['source'], 'UNRELATED')

    def test_request_and_candidate_size_refusals_preserve_prefix_and_count(self):
        context = self.manifest('original')
        self.start(context)
        reply = self.call(context, b' ' * (inputs.REQUEST_CAP + 1))
        self.assertEqual(reply['status'], 'REFUSED')
        entry = inputs.json_value(read_regular(context['session'] / 'call-02.json'))
        self.assertFalse(entry['request_complete'])
        self.assertEqual(entry['request']['bytes'], inputs.REQUEST_CAP + 1)
        candidate = canonical({'padding': 'x' * inputs.CANDIDATE_CAP})
        reply = self.call(context, {'action': 'finish', 'candidate_base64': base64.b64encode(candidate).decode()})
        self.assertEqual(reply['status'], 'REFUSED')
        self.assertFalse((context['session'] / 'candidate.json').exists())
        self.assertEqual(self.call(context, {'action': 'finish', 'candidate_base64': '!!'})['status'], 'REFUSED')

    def test_wrong_manifest_and_source_held_digest_refuse(self):
        context = self.manifest('original')
        self.assertEqual(self.call(context, {'action': 'describe'}, '0' * 64)['status'], 'REFUSED')
        changed = dict(context['value'], held_source_sha256=dict(context['value']['held_source_sha256']))
        changed['held_source_sha256']['APPROVAL'] = '0' * 64
        bad = self.rewrite_manifest(context, changed)
        self.assertEqual(self.call(bad, {'action': 'describe'})['status'], 'REFUSED')
        self.assertFalse(context['session'].exists())

    def test_source_mutation_missing_target_and_unexpected_content_refuse(self):
        for tag, mode in (('mutation', 'mutation'), ('missing', 'missing'), ('extra', 'extra')):
            context = self.manifest('original', tag)
            self.start(context)
            root = Path(context['value']['content']['root'])
            if mode == 'mutation':
                (root / 'approval.txt').write_bytes(b'changed')
            elif mode == 'missing':
                (root / 'approval.txt').unlink()
            else:
                write_new(root / 'unexpected.txt', b'unexpected')
            self.assertEqual(self.call(context, {'action': 'catalog'})['status'], 'REFUSED')
            self.assertFalse((context['session'] / 'call-02.json').exists())

    def test_wrong_transport_identity_and_runtime_pin_refuse(self):
        for tag, key in (('pair', 'pair'), ('bundle', 'bundle')):
            context = self.manifest('transport', tag)
            value = dict(context['value'], **{key: dict(context['value'][key])})
            value[key]['identity' if key == 'pair' else 'snapshot_sha256'] = 'STS1:' + '0' * 64 if key == 'pair' else '0' * 64
            altered = self.rewrite_manifest(context, value)
            self.assertEqual(self.call(altered, {'action': 'describe'})['status'], 'REFUSED')
            self.assertFalse(context['session'].exists())

    def test_actual_frozen_bundle_module_mutation_refuses_before_decode(self):
        copied = self.root / 'bundle'
        copied.mkdir(mode=0o700)
        snapshot = bundle_snapshot(CONFIG['bundle'])
        self.assertLessEqual(len(snapshot['files']), 64)
        for name, info in snapshot['files'].items():
            target = copied / name
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            write_new(target, read_regular(CONFIG['bundle'] / name))
            target.chmod(info['mode'])
        context = self.manifest('transport')
        value = dict(context['value'], bundle={'path': str(copied),
                     'install_sha256': sha(read_regular(copied / 'INSTALL.json')),
                     'snapshot_sha256': sha(canonical(bundle_snapshot(copied)))})
        frozen = self.rewrite_manifest(context, value)
        with (copied / 'tools' / 'transport_package.py').open('ab') as stream:
            stream.write(b'\n# changed after freeze\n')
        self.assertEqual(self.call(frozen, {'action': 'describe'})['status'], 'REFUSED')
        self.assertFalse(context['session'].exists())

    def test_exact_page_bytes_split_utf8_and_eof(self):
        context = self.manifest('original')
        data = b'a' * 4095 + '\u00e9'.encode() + b'z'
        root = Path(context['value']['content']['root'])
        (root / 'work.txt').write_bytes(data)
        value = dict(context['value'], sources=[dict(item) for item in context['value']['sources']],
                     held_source_sha256=dict(context['value']['held_source_sha256']),
                     content={'root': str(root), 'files': [pin(path, path.name) for path in sorted(root.iterdir())]})
        for item in value['sources']:
            if item['id'] == 'WORK':
                item['bytes'] = len(data)
        value['held_source_sha256']['WORK'] = sha(data)
        context = self.rewrite_manifest(context, value)
        self.start(context)
        first = self.call(context, {'action': 'page', 'source': 'WORK', 'offset': 0})['result']
        self.assertEqual(base64.b64decode(first['base64']), data[:4096])
        self.assertIsNone(first['utf8'])
        self.assertFalse(first['end'])
        last = self.call(context, {'action': 'page', 'source': 'WORK', 'offset': 4096})['result']
        self.assertEqual(base64.b64decode(last['base64']), data[4096:])
        self.assertTrue(last['end'])
        end = self.call(context, {'action': 'page', 'source': 'WORK', 'offset': len(data)})['result']
        self.assertEqual(end['base64'], '')
        self.assertEqual(self.call(context, {'action': 'page', 'source': 'WORK', 'offset': len(data) + 1})['status'], 'REFUSED')

    def test_helper_mutation_and_missing_dependency_refuse(self):
        helpers = self.root / 'helpers'
        helpers.mkdir(mode=0o700)
        for name in inputs.BOOTSTRAP:
            write_new(helpers / name, read_regular(ROOT / 'install' / name))
        context = self.manifest('original', helper_root=helpers)
        self.start(context)
        with (helpers / 'transport_handoff_inputs.py').open('ab') as stream:
            stream.write(b'\n# altered after freeze\n')
        self.assertEqual(self.call(context, {'action': 'catalog'})['status'], 'REFUSED')
        self.assertFalse((context['session'] / 'call-02.json').exists())
        context = self.manifest('original', 'missing')
        value = dict(context['value'], helpers=context['value']['helpers'][:-1])
        self.assertEqual(self.call(self.rewrite_manifest(context, value), {'action': 'describe'})['status'], 'REFUSED')

    def test_session_hash_chain_unexpected_files_and_partial_logs_refuse(self):
        for tag in ('changed', 'extra', 'partial'):
            context = self.manifest('original', tag)
            self.start(context)
            if tag == 'changed':
                (context['session'] / 'response-01.json').write_bytes(b'{}\n')
            elif tag == 'extra':
                write_new(context['session'] / 'unexpected', b'not a record')
            else:
                write_new(context['session'] / 'request-02.json', b'{}')
            self.assertEqual(self.call(context, {'action': 'catalog'})['status'], 'REFUSED')
            self.assertFalse((context['session'] / 'call-02.json').exists())

    def test_finite_call_limit_includes_describe(self):
        context = self.manifest('original')
        for index in range(1, 33):
            reply = self.call(context, {'action': 'describe'})
            self.assertEqual(reply['status'], 'OK')
            self.assertEqual(reply['call'], index)
        self.assertEqual(self.call(context, {'action': 'catalog'})['status'], 'REFUSED')
        self.assertFalse((context['session'] / 'call-33.json').exists())

    def test_output_cap_includes_newline_and_functions_are_bounded(self):
        base = reader.response('original', 'page', 'OK', {'padding': ''})
        exact = reader.response('original', 'page', 'OK', {'padding': 'x' * (inputs.CAP - len(base))})
        self.assertEqual(len(exact), inputs.CAP)
        with self.assertRaises(ValueError):
            reader.response('original', 'page', 'OK', {'padding': 'x' * (inputs.CAP - len(base) + 1)})
        for name in inputs.BOOTSTRAP[:3] + ('test_handoff_reader.py',):
            tree = ast.parse(read_regular(ROOT / 'install' / name))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self.assertLessEqual(node.end_lineno - node.lineno + 1, 60, name + ':' + node.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    args = parser.parse_args()
    args.evidence.mkdir(mode=0o700)
    CONFIG.update(bundle=args.bundle.absolute(), evidence=args.evidence.absolute(), commands=0)
    result = None
    try:
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(ReaderControls))
    finally:
        stored_json(CONFIG['evidence'] / 'receipt.json',
                    {'schema': 'transport/handoff-reader-controls/1', 'status': 'FAILED' if result is None or not result.wasSuccessful() else 'TESTED_SCOPED',
                     'tests_run': 0 if result is None else result.testsRun, 'commands': CONFIG['commands'],
                     'failures': [] if result is None else [trace for _, trace in result.failures],
                     'errors': [] if result is None else [trace for _, trace in result.errors],
                     'module_pins': [pin(ROOT / 'install' / name) for name in inputs.BOOTSTRAP[:3] + ('test_handoff_reader.py',)],
                     'bundle': str(CONFIG['bundle']), 'model_trial': 'UNRUN', 'baseline_model_trial': 'UNRUN',
                     'limits': 'Scoped synthetic tests; bootstrap/host trust and same-user races remain outside isolation.'})
    return 0 if result is not None and result.wasSuccessful() else 1


if __name__ == '__main__':
    sys.exit(main())
