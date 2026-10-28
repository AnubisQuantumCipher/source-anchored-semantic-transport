#!/usr/bin/env python3
"""Real original-document client controls: no native bundle, model or network."""

import base64
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_handoff_prepare as preparation
import transport_handoff_inputs as inputs
from transport_install_support import canonical, read_regular, run_bounded, sha, write_new

HERE = Path(__file__).absolute().parent
SOURCE = b'All controllers shall log every sample every 100 ms unless maintenance is active.\n'


def pin(path):
    raw = read_regular(path)
    return dict(path=str(path), bytes=len(raw), sha256=sha(raw))


class ClientControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='transport-client-test-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.stdin_calls = 0
        self.prepared = self.root / 'receiving'
        source, task = self.root / 'source.txt', self.root / 'task.txt'
        write_new(source, SOURCE)
        write_new(task, b'Read the supplied source and return an unexecuted draft.\n')
        config = dict(schema='transport/handoff-preparation/1', arm='original', task=pin(task),
                      python=pin(Path(sys.executable).resolve()), sources=[dict(id='SOURCE', label='Source',
                      media_type='text/plain', provenance='Synthetic client control', **pin(source))])
        config_path = self.root / 'config.json'
        write_new(config_path, canonical(config))
        preparation.prepare(config_path, sha(read_regular(config_path)), self.prepared)
        self.binding = self.prepared / 'client-binding.json'
        self.held = sha(read_regular(self.binding))

    def argv(self, *extra):
        return [sys.executable, '-I', '-S', '-B', '-Werror',
                str(self.prepared / 'helpers/transport_handoff_client.py'),
                '--binding', str(self.binding), '--expect-binding-sha256', self.held, *extra]

    def request(self, raw, stdin=False):
        argv = self.argv('--stdin') if stdin else self.argv('--request-json', raw.decode())
        if stdin:
            self.assertLess(self.stdin_calls, 16)
            path = self.root / ('stdin-%02d.bin' % self.stdin_calls)
            self.stdin_calls += 1
            write_new(path, raw)
            bootstrap = ('import os,sys; fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NOFOLLOW); '
                         'os.dup2(fd,0); os.close(fd); os.execv(sys.argv[2],sys.argv[2:])')
            argv = [sys.executable, '-I', '-S', '-B', '-Werror', '-c', bootstrap, str(path)] + argv
        result = run_bounded(argv, self.root, {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8'}, timeout=40, cap=131072)
        self.assertIn(result['status'], ('SUCCESS', 'EXIT_NONZERO'))
        self.assertEqual(result['stderr'], b'')
        self.assertLessEqual(len(result['stdout']), 131072)
        self.assertTrue(result['stdout'].endswith(b'\n'))
        value = json.loads(result['stdout'])
        self.assertEqual(result['exit_code'], 0 if value['status'] == 'OK' else 1)
        return value, result['stdout']

    def start(self):
        value, _ = self.request(b'{"action":"describe"}')
        self.assertEqual(value['status'], 'OK')
        self.assertEqual(value['result']['authority'], 'NONE')

    def file_call(self, path, digest=None, extra=()):
        options = ['--request-file', str(path)]
        if digest is not None:
            options.extend(['--expect-request-sha256', digest])
        result = run_bounded(self.argv(*options, *extra), self.root, inputs.ENV, timeout=40, cap=131072)
        self.assertIn(result['status'], ('SUCCESS', 'EXIT_NONZERO'))
        self.assertEqual(result['stderr'], b'')
        self.assertTrue(result['stdout'].endswith(b'\n'))
        value = json.loads(result['stdout'])
        self.assertEqual(result['exit_code'], 0 if value['status'] == 'OK' else 1)
        return value, result['stdout']

    def file_refused(self, path, digest=None):
        value, _ = self.file_call(path, digest)
        self.assertEqual(value['schema'], 'transport/handoff-client-refusal/1')
        self.assertEqual(value['status'], 'REFUSED')
        self.assertFalse(value['result']['reader_action_may_be_recorded'])
        self.assertFalse((self.prepared / 'sessions/recipient').exists())
        return value

    def recorded(self, number, raw, answer, complete=True, length=None):
        session = self.prepared / 'sessions/recipient'
        item = json.loads(read_regular(session / ('call-%02d.json' % number)))
        self.assertEqual(read_regular(session / ('request-%02d.json' % number)), raw)
        self.assertEqual(read_regular(session / ('response-%02d.json' % number)), answer)
        self.assertEqual(item['request'], dict(bytes=len(raw), sha256=sha(raw)))
        self.assertEqual(item['response'], dict(bytes=len(answer), sha256=sha(answer)))
        self.assertEqual(item['request_complete'], complete)
        self.assertEqual(item['input_bytes'], len(raw) if length is None else length)
        self.assertEqual(item['index'], number)
        self.assertFalse((session / ('call-%02d.json' % (number + 1))).exists())

    def test_actual_source_and_exact_single_submission(self):
        self.start()
        value, _ = self.request(b'{"action":"page","source":"SOURCE","offset":0}', stdin=True)
        self.assertEqual(base64.b64decode(value['result']['base64']), SOURCE)
        self.assertEqual(value['result']['source_sha256'], sha(SOURCE))
        draft = b'{ "draft": "100 ms", "execution": false }\n'
        request = canonical(dict(action='finish', candidate_base64=base64.b64encode(draft).decode()))
        value, _ = self.request(request)
        self.assertEqual(value['status'], 'OK')
        self.assertEqual(read_regular(self.prepared / 'sessions/recipient/candidate.json'), draft)
        second, _ = self.request(request)
        self.assertEqual(second['status'], 'REFUSED')
        self.assertEqual(read_regular(self.prepared / 'sessions/recipient/candidate.json'), draft)

    def test_fixed_session_and_closed_requests(self):
        self.start()
        requests = [b'{"action":"catalog","session":"elsewhere"}', b'{"action":"focus","unit":"U"}',
                    b'{"action":"catalog","action":"describe"}', b'{', b'[]']
        for number, request in enumerate(requests, 2):
            value, answer = self.request(request)
            self.assertEqual(value['status'], 'REFUSED')
            self.recorded(number, request, answer)
        self.assertEqual([path.name for path in (self.prepared / 'sessions').iterdir()], ['recipient'])
        value, _ = self.request(b'{"action":"catalog"}')
        self.assertEqual(value['status'], 'OK')
        self.assertEqual(value['result']['sources'][0]['sha256'], sha(SOURCE))

    def test_overlong_stdin_retains_incomplete_prefix(self):
        self.start()
        raw = b'x' * 65537
        value, answer = self.request(raw, stdin=True)
        self.assertEqual(value['status'], 'REFUSED')
        self.assertIn('total length unknown', value['result']['reason'])
        self.recorded(2, raw, answer, complete=False, length=-1)
        value, _ = self.request(b'{"action":"catalog"}')
        self.assertEqual(value['status'], 'OK')

    def test_binding_drift_refuses_before_dispatch(self):
        write_new(self.root / 'original-binding.json', read_regular(self.binding))
        self.binding.write_bytes(read_regular(self.binding) + b' ')
        value, _ = self.request(b'{"action":"describe"}')
        self.assertEqual(value['schema'], 'transport/handoff-client-refusal/1')
        self.assertFalse(value['result']['reader_action_may_be_recorded'])
        self.assertFalse((self.prepared / 'sessions/recipient').exists())

    def test_pinned_request_file_at_cap_records_exact_bytes(self):
        document = b'{"action":"describe"}'
        raw = document + b' ' * (inputs.REQUEST_CAP - len(document))
        path = self.root / 'request.json'
        write_new(path, raw)
        value, answer = self.file_call(path, sha(raw))
        self.assertEqual(value['status'], 'OK')
        self.recorded(1, raw, answer)

    def test_request_file_missing_wrong_malformed_digest_no_dispatch(self):
        raw, path = b'{"action":"describe"}', self.root / 'request.json'
        write_new(path, raw)
        for digest in (None, '0' * 64, '', sha(raw).upper(), 'x' * 64):
            with self.subTest(digest=digest):
                self.file_refused(path, digest)
        path.write_bytes(raw + b'\n')
        self.file_refused(path, sha(raw))

    def test_request_file_symlink_nonregular_missing_and_overlimit_no_dispatch(self):
        raw, path = b'{"action":"describe"}', self.root / 'request.json'
        write_new(path, raw)
        link = self.root / 'link.json'
        link.symlink_to(path)
        fifo = self.root / 'fifo'
        os.mkfifo(fifo, 0o600)
        for refused in (link, self.root, fifo, self.root / 'missing.json'):
            with self.subTest(path=refused):
                self.file_refused(refused, sha(raw))
        large = raw + b' ' * (inputs.REQUEST_CAP + 1 - len(raw))
        path.write_bytes(large)
        self.file_refused(path, sha(large))

    def test_request_file_option_pairing_and_exclusivity(self):
        for mode in (('--stdin',), ('--request-json', '{"action":"describe"}')):
            result = run_bounded(self.argv(*mode, '--expect-request-sha256', '0' * 64),
                                 self.root, inputs.ENV, timeout=40, cap=131072)
            self.assertEqual(result['stderr'], b'')
            value = json.loads(result['stdout'])
            self.assertEqual(value['status'], 'REFUSED')
            self.assertFalse(value['result']['reader_action_may_be_recorded'])
            result = run_bounded(self.argv(*mode, '--request-file', str(self.root / 'unused')),
                                 self.root, inputs.ENV, timeout=40, cap=131072)
            self.assertEqual(result['exit_code'], 2)
            self.assertIn(b'not allowed with argument', result['stderr'])
        self.assertFalse((self.prepared / 'sessions/recipient').exists())

    def test_source_drift_refuses_without_candidate(self):
        self.start()
        (self.prepared / 'content/source-00.bin').write_bytes(SOURCE.replace(b'100', b'101'))
        value, _ = self.request(b'{"action":"page","source":"SOURCE","offset":0}')
        self.assertEqual(value['status'], 'REFUSED')
        self.assertIn('identity mismatch', value['result']['reason'])
        self.assertFalse((self.prepared / 'sessions/recipient/candidate.json').exists())


if __name__ == '__main__':
    unittest.main()
