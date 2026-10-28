"""Adversarial Source-Anchored Semantic Transport recipient boundary controls."""

import base64
import hashlib
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import transport_recipient_process as process

ROOT = Path(__file__).resolve().parents[1]
HANDOFF = ROOT / 'evidence/semantic-transport-v1/adapter-migration/test-handoff'
RUNNER = ROOT / 'tools/transport_recipient_runner.py'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_environment(root):
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'HOME': str(root), 'TMPDIR': str(root)}


def fixture_process(root, source, wall=None):
    helper = root / 'controlled_fixture.py'
    helper.write_text(source, encoding='utf-8')
    log = root / 'process-log'
    log.mkdir()
    argv = [sys.executable, '-I', '-S', '-B', str(helper)]
    if wall is None:
        result = process.run_process(argv, root, safe_environment(root), log)
    else:
        with patch.object(process, 'WALL_SECONDS', wall):
            result = process.run_process(argv, root, safe_environment(root), log)
    return result, log, helper


def assert_exact_capture(test, result, log):
    for stream in ('stdout', 'stderr'):
        raw = (log / (stream + '.bin')).read_bytes()
        test.assertEqual(base64.b64decode(result[stream + '_base64']), raw)
        test.assertEqual(result[stream + '_bytes'], len(raw))
        test.assertEqual(result[stream + '_sha256'], digest(raw))
        test.assertLessEqual(len(raw), process.STREAM_CAP)


class ProcessBoundaryTests(unittest.TestCase):
    def test_real_generation_caps_stdout_and_stderr_separately(self):
        for descriptor in (1, 2):
            with self.subTest(descriptor=descriptor), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = ('import os\nfor _ in range(4096):\n'
                          '    os.write(' + str(descriptor) + ', b"x" * 4096)\n')
                result, log, _ = fixture_process(root, source)
                assert_exact_capture(self, result, log)
                self.assertTrue(result['stream_cap_hit'])
                self.assertFalse(result['capture_accepted'])
                self.assertNotEqual(result['exit'], 0)
                self.assertFalse(result['wall_timeout'])
                self.assertEqual((log / ('stdout.bin' if descriptor == 1 else 'stderr.bin')).stat().st_size,
                                 process.STREAM_CAP)

    def test_real_interleaved_generation_caps_both_stream_files(self):
        with tempfile.TemporaryDirectory() as directory:
            source = ('import os\nfor _ in range(4096):\n'
                      '    os.write(1, b"o" * 4096)\n    os.write(2, b"e" * 4096)\n')
            result, log, _ = fixture_process(Path(directory), source)
            assert_exact_capture(self, result, log)
            self.assertTrue(result['stream_cap_hit'])
            self.assertFalse(result['capture_accepted'])
            self.assertGreater(result['stdout_bytes'], 0)
            self.assertGreater(result['stderr_bytes'], 0)

    def test_wall_timeout_kills_descendant_and_retains_exact_partial_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = ('import subprocess, sys\n'
                      'child = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", '
                      '"import time; time.sleep(30)"])\n'
                      'print(child.pid, flush=True)\nchild.wait()\n')
            result, log, _ = fixture_process(root, source, wall=0.3)
            assert_exact_capture(self, result, log)
            self.assertTrue(result['wall_timeout'])
            self.assertFalse(result['capture_accepted'])
            pid = int((log / 'stdout.bin').read_text().strip())
            for _ in range(100):
                if not Path('/proc', str(pid)).exists():
                    break
                time.sleep(0.02)
            self.assertFalse(Path('/proc', str(pid)).exists(), 'descendant still exists after process-group kill')
            self.assertEqual(result['limits']['wall_seconds'], 0.3)

    def test_successful_parent_exit_still_kills_background_descendant(self):
        with tempfile.TemporaryDirectory() as directory:
            source = ('import subprocess, sys\n'
                      'child = subprocess.Popen([sys.executable, "-I", "-S", "-B", "-c", '
                      '"import time; time.sleep(30)"])\nprint(child.pid, flush=True)\n')
            result, log, _ = fixture_process(Path(directory), source)
            pid = int((log / 'stdout.bin').read_text().strip())
            for _ in range(100):
                if not Path('/proc', str(pid)).exists():
                    break
                time.sleep(0.02)
            self.assertFalse(Path('/proc', str(pid)).exists(), 'background descendant survives parent exit')
            self.assertEqual(result['exit'], 0)

    def test_resource_limits_stdin_argv_cwd_and_environment_are_observed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = ('import json, os, resource, sys\n'
                      'print(json.dumps({"env": dict(os.environ), "cwd": os.getcwd(), '
                      '"argv": sys.argv, "stdin": sys.stdin.buffer.read().hex(), '
                      '"limits": {name: resource.getrlimit(getattr(resource, name)) '
                      'for name in ("RLIMIT_AS","RLIMIT_CPU","RLIMIT_NOFILE","RLIMIT_FSIZE","RLIMIT_CORE")}}))\n')
            with patch.dict(os.environ, {'TRANSPORT_TEST_SECRET': 'must-not-inherit', 'PYTHONPATH': '/untrusted'}):
                result, log, helper = fixture_process(root, source)
            self.assertTrue(result['capture_accepted'])
            assert_exact_capture(self, result, log)
            observed = json.loads((log / 'stdout.bin').read_bytes())
            self.assertEqual(observed['env'], safe_environment(root))
            self.assertEqual(observed['cwd'], str(root))
            self.assertEqual(observed['argv'], [str(helper)])
            self.assertEqual(observed['stdin'], '')
            self.assertEqual(result['argv'], [sys.executable, '-I', '-S', '-B', str(helper)])
            self.assertEqual(result['cwd'], str(root))
            self.assertEqual(result['env'], safe_environment(root))
            self.assertEqual(result['stdin_base64'], '')
            for name, limit in (('RLIMIT_AS', 'address_bytes'), ('RLIMIT_CPU', 'cpu_seconds'),
                                ('RLIMIT_NOFILE', 'open_files'), ('RLIMIT_FSIZE', 'file_bytes')):
                self.assertEqual(observed['limits'][name], [process.LIMITS[limit]] * 2)
            self.assertEqual(observed['limits']['RLIMIT_CORE'], [0, 0])

    def test_failed_launch_still_has_exact_empty_logs_and_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'logs'
            log.mkdir()
            result = process.run_process([str(root / 'missing-executable')],
                                         root, safe_environment(root), log)
            self.assertFalse(result['capture_accepted'])
            self.assertTrue(result['launch_error'])
            self.assertIsNone(result['exit'])
            assert_exact_capture(self, result, log)
            self.assertEqual(result['stdout_bytes'], 0)
            self.assertEqual(result['stderr_bytes'], 0)

    def test_exact_cap_is_not_accepted_as_complete_success(self):
        with tempfile.TemporaryDirectory() as directory:
            result, log, _ = fixture_process(Path(directory),
                'import os\nos.write(1, b"x" * ' + str(process.STREAM_CAP) + ')\n')
            assert_exact_capture(self, result, log)
            self.assertFalse(result['capture_accepted'])
            self.assertTrue(result['stream_cap_hit'])

    def test_inheritable_parent_file_descriptor_is_not_exposed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            descriptor = os.open(root / 'parent-secret', os.O_CREAT | os.O_RDWR, 0o600)
            try:
                os.set_inheritable(descriptor, True)
                source = ('import os\ntry:\n    os.fstat(' + str(descriptor) + ')\n'
                          '    print("LEAK")\nexcept OSError:\n    print("CLOSED")\n')
                result, log, _ = fixture_process(root, source)
                self.assertTrue(result['capture_accepted'])
                self.assertEqual((log / 'stdout.bin').read_bytes(), b'CLOSED\n')
            finally:
                os.close(descriptor)

    def test_partial_log_collision_preserves_existing_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            log = root / 'logs'
            log.mkdir()
            (log / 'stderr.bin').write_bytes(b'first log')
            with self.assertRaises(FileExistsError):
                process.run_process([sys.executable, '-I', '-S', '-B', '-c', 'print("never")'],
                                    root, safe_environment(root), log)
            self.assertEqual((log / 'stderr.bin').read_bytes(), b'first log')

    def test_symlink_log_and_nonregular_read_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / 'original'
            original.write_bytes(b'preserve')
            link = root / 'link'
            link.symlink_to(original)
            with self.assertRaises(OSError):
                process.read(link)
            with self.assertRaises((ValueError, OSError)):
                process.read(root)
            log = root / 'logs'
            log.mkdir()
            (log / 'stdout.bin').symlink_to(original)
            with self.assertRaises(FileExistsError):
                process.run_process([sys.executable, '-I', '-S', '-B', '-c', 'print("never")'],
                                    root, safe_environment(root), log)
            self.assertEqual(original.read_bytes(), b'preserve')


class RecipientRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.handoff = self.root / 'handoff'
        shutil.copytree(HANDOFF, self.handoff)
        self.session = self.root / 'session'
        self.test_wall = None

    def run_action(self, *arguments, stdin=b'', handoff=None, session=None, environment=None):
        prefix = [sys.executable, '-I', '-S', '-B', '-Werror', str(RUNNER)]
        if self.test_wall is not None:
            shim = ('import sys;sys.path.insert(0,' + repr(str(ROOT / 'tools')) + ');'
                    'import transport_recipient_runner as r;r.LAUNCHER_WALL_SECONDS=' +
                    repr(self.test_wall) + ';sys.exit(r.main())')
            prefix = [sys.executable, '-I', '-S', '-B', '-Werror', '-c', shim]
        argv = prefix + ['--handoff', str(handoff or self.handoff),
                         '--session', str(session or self.session), *arguments]
        env = dict(os.environ)
        env.update(environment or {})
        result = subprocess.run(argv, cwd=self.root, env=env, input=stdin,
                                capture_output=True, timeout=30, check=False)
        if result.returncode == 2:
            return result, {'status': 'ARGUMENT_REFUSAL', 'stderr': result.stderr.decode()}
        self.assertEqual(result.stderr, b'', result.stderr)
        value = json.loads(result.stdout)
        return result, value

    def timed_action(self, mode, *arguments):
        # A test-only shim injects bounded delay. It is not a recipient action.
        helper = self.root / ('timed-' + mode + '.py')
        source = ('import sys, time\nfrom pathlib import Path\n'
            'sys.path.insert(0, ' + repr(str(ROOT / 'tools')) + ')\n'
            'import transport_recipient_runner as runner\n'
            'runner.LAUNCHER_WALL_SECONDS = 0.5\n'
            'mode = ' + repr(mode) + '\n'
            'if mode in ("candidate-write", "record-write"):\n'
            '    original = runner.process.write\n'
            '    def interrupted(path, data, cap=131072):\n'
            '        wanted = "candidate.json" if mode == "candidate-write" else "record.json"\n'
            '        if path.name == wanted:\n'
            '            with path.open("xb") as stream:\n'
            '                stream.write(data[:1]); stream.flush(); time.sleep(2)\n'
            '        else:\n'
            '            return original(path, data, cap)\n'
            '    runner.process.write = interrupted\n'
            'else:\n'
            '    target = {"preflight":"handoff_identity", "describe":"dispatch", '
            '"view":"view", "finish":"finish"}[mode]\n'
            '    original = getattr(runner, target)\n'
            '    def delayed(*args, **kwargs):\n'
            '        time.sleep(2)\n        return original(*args, **kwargs)\n'
            '    setattr(runner, target, delayed)\n'
            'sys.exit(runner.main())\n')
        helper.write_text(source)
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-Werror', str(helper),
            '--handoff', str(self.handoff), '--session', str(self.session), *arguments],
            cwd=self.root, env=safe_environment(self.root), input=b'', capture_output=True,
            timeout=3, check=False)
        self.assertEqual(result.stderr, b'', result.stderr)
        return result, json.loads(result.stdout)

    def start(self):
        result, value = self.run_action('describe')
        self.assertEqual(result.returncode, 0, value)
        return value

    def last_action(self):
        return sorted((self.session / 'actions').iterdir())[-1]

    def test_launcher_wall_bounds_preflight_without_accepted_session(self):
        self.test_wall = 0.5
        result, value = self.timed_action('preflight', 'describe')
        self.assertEqual(result.returncode, 1, value)
        self.assertTrue(value['launcher_wall_timeout'])
        self.assertFalse(self.session.exists())

    def test_launcher_wall_bounds_describe_view_and_finish_and_closes_session(self):
        self.test_wall = 0.5
        for mode in ('describe', 'view', 'finish'):
            with self.subTest(mode=mode):
                self.session = self.root / ('wall-' + mode)
                if mode != 'describe':
                    self.start()
                if mode == 'view':
                    self.assertEqual(self.run_action('recover', 'recipe', 'RECIPE')[0].returncode, 0)
                    args = ('view', 'recipe', 'RECIPE')
                elif mode == 'finish':
                    args = ('finish', '--data-base64', base64.b64encode(
                        b'{"schema":"transport/recipient-narrative/1","narrative":"x"}').decode())
                else:
                    args = ('describe',)
                result, value = self.timed_action(mode, *args)
                self.assertEqual(result.returncode, 1, value)
                record = json.loads((self.last_action() / 'record.json').read_bytes())
                self.assertTrue(record['launcher_wall_timeout'])
                self.assertFalse((self.session / 'candidate.json').exists())
                result, value = self.run_action('describe')
                self.assertEqual(result.returncode, 1, value)

    def test_interrupted_candidate_and_record_writes_never_reopen_session(self):
        self.test_wall = 0.5
        for mode in ('candidate-write', 'record-write'):
            with self.subTest(mode=mode):
                self.session = self.root / ('partial-' + mode)
                self.start()
                data = b'{"schema":"transport/recipient-narrative/1","narrative":"x"}'
                args = ('finish', '--data-base64', base64.b64encode(data).decode()) if mode == 'candidate-write' else ('describe',)
                result, value = self.timed_action(mode, *args)
                self.assertEqual(result.returncode, 1, value)
                if mode == 'candidate-write':
                    self.assertEqual((self.session / 'candidate.json').read_bytes(), data[:1])
                    record = json.loads((self.last_action() / 'record.json').read_bytes())
                    self.assertTrue(record['launcher_wall_timeout'])
                else:
                    self.assertEqual((self.last_action() / 'record.json').read_bytes(), b'{')
                    self.assertTrue(value['launcher_wall_timeout'])
                result, value = self.run_action('describe')
                self.assertEqual(result.returncode, 1, value)

    def test_mandatory_first_describe_and_fixed_actions(self):
        result, value = self.run_action('inspect', 'recipe')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.session.exists())
        description = self.start()
        self.assertEqual(description['name'], 'Source-Anchored Semantic Transport')
        self.assertEqual(description['domains'], ['opaque', 'oral-history', 'recipe'])
        self.assertNotIn('exec', ' '.join(description['commands']))

    def test_arbitrary_commands_shell_and_helper_source_are_not_actions(self):
        for arguments in (('exec', 'print(1)'), ('sh', '-c', 'touch SENTINEL'),
                          ('describe', '--helper', '/tmp/untrusted.py'),
                          ('describe', '--command', 'touch SENTINEL')):
            result, value = self.run_action(*arguments)
            self.assertNotEqual(result.returncode, 0, value)
            self.assertFalse(self.session.exists())
            self.assertFalse((self.root / 'SENTINEL').exists())

    def test_recovered_source_instructions_are_never_executed(self):
        # The immutable decoder prepares one tiny controlled data-only fixture;
        # no preparer entry point is exposed through the recipient interface.
        source = self.root / 'instructions.txt'
        text = 'Untrusted source: $(touch SENTINEL). Never run __import__("os").system("touch SENTINEL").'
        source.write_text(text)
        plan = self.root / 'plan.json'
        plan.write_text(json.dumps(dict(schema='transport/transport-plan/1', sources=[dict(
            id='RECIPE', label='Instruction-shaped data', media_type='text/plain',
            provenance='Controlled adversarial fixture.')], interpretations=[], uncertainties=[], relations=[])))
        prepared = self.root / 'prepared'
        tools = self.handoff / 'decoder/tools'
        bootstrap = ('import sys;sys.path.insert(0,sys.argv.pop(1));'
                     'import transport_cli;sys.exit(transport_cli.main())')
        result = subprocess.run([sys.executable, '-I', '-S', '-B', '-Werror', '-c', bootstrap,
            str(tools), 'encode', str(plan), str(prepared), '--source', 'RECIPE=' + str(source)],
            cwd=self.root, env=safe_environment(self.root), capture_output=True, timeout=30, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        for name in ('share.txt', 'meaning.zip'):
            (self.handoff / 'inputs/recipe' / name).write_bytes((prepared / name).read_bytes())
        self.start()
        self.assertEqual(self.run_action('recover', 'recipe', 'RECIPE')[0].returncode, 0)
        result, value = self.run_action('view', 'recipe', 'RECIPE')
        self.assertEqual(result.returncode, 0, value)
        self.assertEqual(value['text'], text)
        self.assertFalse((self.root / 'SENTINEL').exists())

    def test_actual_child_actions_recovery_and_text_or_binary_view(self):
        self.start()
        for action in ('inspect', 'validate'):
            result, value = self.run_action(action, 'recipe')
            self.assertEqual(result.returncode, 0, value)
            self.assertEqual(value['sources'][0]['id'], 'RECIPE')
            self.assertNotIn('data', value['sources'][0])
        for domain, identifier in (('recipe', 'RECIPE'), ('opaque', 'OPAQUE'), ('opaque', 'EMPTY')):
            result, value = self.run_action('recover', domain, identifier)
            self.assertEqual(result.returncode, 0, value)
            result, viewed = self.run_action('view', domain, identifier)
            self.assertEqual(result.returncode, 0, viewed)
            data = (self.session / 'recovered' / domain / (identifier + '.bin')).read_bytes()
            self.assertEqual(value['sha256'], digest(data))
            self.assertEqual(value['bytes'], len(data))
            self.assertEqual(viewed['source'], identifier)
            self.assertEqual(viewed['opaque'], domain == 'opaque')
            if domain == 'recipe':
                self.assertEqual(viewed['text'].encode(), data)
            else:
                self.assertNotIn('text', viewed)

    def test_every_capture_and_chain_hash_matches_actual_bytes(self):
        self.start()
        result, value = self.run_action('inspect', 'recipe', environment={
            'TRANSPORT_SECRET': 'not-in-child', 'PYTHONPATH': '/untrusted', 'BASH_ENV': '/untrusted'})
        self.assertEqual(result.returncode, 0, value)
        action = self.last_action()
        record = json.loads((action / 'record.json').read_bytes())
        request = json.loads((action / 'request.json').read_bytes())
        self.assertEqual(request['argv'], result.args)
        self.assertEqual(request['cwd'], str(self.root))
        self.assertEqual(request['stdin_base64'], '')
        self.assertEqual(request['stdin_bytes'], 0)
        self.assertEqual((action / 'response.bin').read_bytes(), result.stdout)
        for key, name in (('request_sha256', 'request.json'), ('stdin_sha256', 'stdin.bin'),
                          ('response_sha256', 'response.bin')):
            self.assertEqual(record[key], digest((action / name).read_bytes()))
        for child in record['children']:
            target = action / child['directory']
            raw = (target / 'result.json').read_bytes()
            self.assertEqual(child['sha256'], digest(raw))
            captured = json.loads(raw)
            assert_exact_capture(self, captured, target)
            self.assertEqual(captured['stdin_base64'], '')
            self.assertEqual(captured['cwd'], str(self.session))
            self.assertEqual(captured['env'], dict(safe_environment(self.session),
                HOME=str(self.session / 'home'), TMPDIR=str(self.session / 'tmp')))
            self.assertIn('--child', captured['argv'])
            self.assertNotIn('-c', captured['argv'])
        result, value = self.run_action('describe')
        self.assertEqual(result.returncode, 0, value)

    def test_complete_helper_sources_are_retained_exactly(self):
        self.start()
        state = json.loads((self.session / 'SESSION.json').read_bytes())
        for helper in state['trusted_helpers']:
            data = Path(helper['path']).read_bytes()
            self.assertEqual(helper['bytes'], len(data))
            self.assertEqual(helper['sha256'], digest(data))
            if helper['path'].endswith('.py'):
                self.assertIn('source_base64', helper, 'full helper source snapshot missing')
                self.assertEqual(base64.b64decode(helper['source_base64']), data)

    def test_first_narrative_exact_stdin_is_data_and_never_overwritten(self):
        self.start()
        data = b'{"schema":"transport/recipient-narrative/1","narrative":"$(touch SHOULD_NOT_EXIST)"}'
        result, value = self.run_action('finish', stdin=data)
        self.assertEqual(result.returncode, 0, value)
        self.assertEqual((self.session / 'candidate.json').read_bytes(), data)
        action = self.last_action()
        request = json.loads((action / 'request.json').read_bytes())
        self.assertEqual((action / 'stdin.bin').read_bytes(), data)
        self.assertEqual(base64.b64decode(request['stdin_base64']), data)
        self.assertEqual(value['sha256'], digest(data))
        self.assertFalse((self.root / 'SHOULD_NOT_EXIST').exists())
        result, value = self.run_action('finish', '--data-base64', base64.b64encode(data + b' ').decode())
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.session / 'candidate.json').read_bytes(), data)

    def test_closed_narrative_json_rejects_unknown_duplicate_and_typed_fields(self):
        self.start()
        cases = (b'{"schema":"transport/recipient-narrative/1","narrative":"x","command":"exec"}',
                 b'{"schema":"transport/recipient-narrative/1","narrative":"x","narrative":"y"}',
                 b'{"schema":"transport/recipient-narrative/999","narrative":"x"}',
                 b'{"schema":"transport/recipient-narrative/1","narrative":true}', b'{', b'[]')
        for data in cases:
            result, value = self.run_action('finish', '--data-base64', base64.b64encode(data).decode())
            self.assertNotEqual(result.returncode, 0, value)
            self.assertFalse((self.session / 'candidate.json').exists())

    def test_first_base64_narrative_exact_bytes_and_dual_channel_refusal(self):
        self.start()
        data = b'{"narrative":"Declared reading remains unverified.","schema":"transport/recipient-narrative/1"}'
        encoded = base64.b64encode(data).decode()
        result, value = self.run_action('finish', '--data-base64', encoded, stdin=b'conflict')
        self.assertNotEqual(result.returncode, 0, value)
        self.assertFalse((self.session / 'candidate.json').exists())
        result, value = self.run_action('finish', '--data-base64', encoded)
        self.assertEqual(result.returncode, 0, value)
        self.assertEqual((self.session / 'candidate.json').read_bytes(), data)
        request = json.loads((self.last_action() / 'request.json').read_bytes())
        self.assertEqual(request['stdin_bytes'], 0)
        self.assertIn(encoded, request['argv'])

    def test_unknown_cross_case_and_duplicate_source_ids_refuse(self):
        self.start()
        for domain, identifier in (('recipe', 'HISTORY'), ('opaque', 'RECIPE'), ('recipe', 'MISSING')):
            result, value = self.run_action('recover', domain, identifier)
            self.assertNotEqual(result.returncode, 0, value)
        result, value = self.run_action('recover', 'recipe', 'RECIPE')
        self.assertEqual(result.returncode, 0, value)
        result, value = self.run_action('recover', 'recipe', 'RECIPE')
        self.assertNotEqual(result.returncode, 0, value)
        import transport_recipient_runner as runner
        with self.assertRaises(ValueError):
            runner.selected({'sources': [{'id': 'A'}, {'id': 'A'}]}, 'A')

    def test_changed_input_and_runtime_after_session_start_refuse(self):
        for relative in ('inputs/recipe/share.txt', 'decoder/tools/transport_wire.py'):
            with self.subTest(relative=relative):
                session = self.root / ('session-' + str(len(list(self.root.glob('session-*')))))
                result, value = self.run_action('describe', session=session)
                self.assertEqual(result.returncode, 0, value)
                target = self.handoff / relative
                original = target.read_bytes()
                target.write_bytes(original + b' ')
                result, value = self.run_action('describe', session=session)
                self.assertNotEqual(result.returncode, 0, value)
                target.write_bytes(original)

    def test_tampered_child_stream_request_response_or_record_refuses(self):
        for relative in ('child-01/stdout.bin', 'child-01/result.json', 'request.json', 'response.bin', 'record.json'):
            with self.subTest(relative=relative):
                session = self.root / ('audit-' + str(len(list(self.root.glob('audit-*')))))
                self.assertEqual(self.run_action('describe', session=session)[0].returncode, 0)
                self.assertEqual(self.run_action('inspect', 'recipe', session=session)[0].returncode, 0)
                target = session / 'actions/0002' / relative
                target.write_bytes(target.read_bytes() + b' ')
                result, value = self.run_action('describe', session=session)
                self.assertNotEqual(result.returncode, 0, value)

    def test_external_head_rejects_canonical_last_record_tamper(self):
        self.start()
        import transport_recipient_runner as runner
        checked = runner.verify_session(self.session)
        target = self.last_action() / 'record.json'
        record = json.loads(target.read_bytes())
        record['latency_ns'] += 1
        target.write_bytes(process.canonical(record))
        with self.assertRaisesRegex(ValueError, 'external head'):
            runner.verify_session(self.session, expected_head=checked['head_sha256'])

    def test_orphan_and_nested_empty_child_directories_refuse(self):
        import transport_recipient_runner as runner
        for kind in ('orphan', 'nested'):
            with self.subTest(kind=kind):
                self.session = self.root / ('empty-child-' + kind)
                self.start()
                if kind == 'orphan':
                    unexpected = self.session / 'actions/0001/child-01'
                else:
                    result, value = self.run_action('inspect', 'recipe')
                    self.assertEqual(result.returncode, 0, value)
                    unexpected = self.session / 'actions/0002/child-01/unlogged-empty'
                unexpected.mkdir()
                with self.assertRaises(ValueError):
                    runner.verify_session(self.session)
                result, value = self.run_action('describe')
                self.assertEqual(result.returncode, 1, value)
                next_name = '0002' if kind == 'orphan' else '0003'
                self.assertFalse((self.session / 'actions' / next_name).exists())

    def test_partial_log_directory_and_missing_child_log_fail_closed(self):
        self.start()
        (self.session / 'actions/0002').mkdir()
        result, value = self.run_action('describe')
        self.assertNotEqual(result.returncode, 0, value)
        self.assertFalse((self.session / 'actions/0003').exists())
        session = self.root / 'missing-stream'
        self.assertEqual(self.run_action('describe', session=session)[0].returncode, 0)
        self.assertEqual(self.run_action('inspect', 'recipe', session=session)[0].returncode, 0)
        (session / 'actions/0002/child-01/stderr.bin').unlink()
        result, value = self.run_action('describe', session=session)
        self.assertNotEqual(result.returncode, 0, value)

    def test_handoff_root_and_input_symlinks_refuse(self):
        alias = self.root / 'handoff-alias'
        alias.symlink_to(self.handoff, target_is_directory=True)
        result, value = self.run_action('describe', handoff=alias)
        self.assertNotEqual(result.returncode, 0, value)
        target = self.handoff / 'inputs/recipe/share.txt'
        data = target.read_bytes()
        actual = self.root / 'real-share.txt'
        actual.write_bytes(data)
        target.unlink()
        target.symlink_to(actual)
        result, value = self.run_action('describe')
        self.assertNotEqual(result.returncode, 0, value)

    def test_missing_incompatible_or_duplicate_dependency_refuses(self):
        runtime_path = self.handoff / 'decoder/RUNTIME.json'
        original = runtime_path.read_bytes()
        for alteration in ('duplicate', 'digest', 'missing'):
            state = json.loads(original)
            if alteration == 'duplicate':
                state['files'].append(state['files'][0])
            elif alteration == 'digest':
                state['files'][0]['sha256'] = '0' * 64
            else:
                state['files'] = state['files'][1:]
            runtime_path.write_text(json.dumps(state))
            result, value = self.run_action('describe')
            self.assertNotEqual(result.returncode, 0, value)
            runtime_path.write_bytes(original)

    def test_recovered_byte_and_metadata_binding_tamper_refuses(self):
        self.start()
        self.assertEqual(self.run_action('recover', 'recipe', 'RECIPE')[0].returncode, 0)
        binding = self.session / 'recovered/recipe/RECIPE.json'
        original = binding.read_bytes()
        value = json.loads(original)
        value['metadata']['interpretations'][0]['text'] = 'Changed untrusted declaration.'
        binding.write_text(json.dumps(value))
        result, value = self.run_action('view', 'recipe', 'RECIPE')
        self.assertNotEqual(result.returncode, 0, value)
        binding.write_bytes(original)
        output = self.session / 'recovered/recipe/RECIPE.bin'
        output.write_bytes(output.read_bytes() + b' ')
        result, value = self.run_action('view', 'recipe', 'RECIPE')
        self.assertNotEqual(result.returncode, 0, value)

    def test_invocation_and_aggregate_storage_bounds_fail_closed(self):
        self.start()
        import transport_recipient_runner as runner
        count = runner.MAX_CALLS
        for _ in range(count - 1):
            result, value = self.run_action('describe')
            self.assertEqual(result.returncode, 0, value)
        result, value = self.run_action('describe')
        self.assertNotEqual(result.returncode, 0, value)
        self.assertEqual(len(list((self.session / 'actions').iterdir())), count)
        with patch.object(runner, 'MAX_LEDGER', 1000):
            with self.assertRaises(ValueError):
                runner.check_chain(self.session)

    def test_inventory_bounds_include_directories_special_files_and_file_count(self):
        import transport_recipient_runner as runner
        directory = self.root / 'bounded-inventory'
        directory.mkdir()
        for index in range(5):
            (directory / ('empty-' + str(index))).mkdir()
        with self.assertRaises(ValueError):
            runner.inventory(directory, 1000, 2)
        fifo = self.root / 'fifo-inventory'
        fifo.mkdir()
        os.mkfifo(fifo / 'pipe')
        with self.assertRaises((ValueError, OSError)):
            runner.inventory(fifo, 1000, 10)
        self.start()
        extra = self.session / 'extra'
        extra.mkdir()
        for index in range(runner.MAX_FILES + 1):
            (extra / str(index)).touch()
        result, value = self.run_action('describe')
        self.assertNotEqual(result.returncode, 0, value)

    def test_stalled_stdin_keeps_exact_prefix_and_complete_refusal_audit(self):
        self.start()
        argv = [sys.executable, '-I', '-S', '-B', '-Werror', str(RUNNER),
                '--handoff', str(self.handoff), '--session', str(self.session), 'finish']
        child = subprocess.Popen(argv, cwd=self.root, env=safe_environment(self.root),
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            child.stdin.write(b'{')
            child.stdin.flush()
            child.wait(timeout=3)
            child.stdin.close()
            child.stdin = None
            stdout, stderr = child.communicate(timeout=3)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=3)
        self.assertEqual(child.returncode, 1, stdout)
        self.assertEqual(stderr, b'')
        self.assertFalse((self.session / 'candidate.json').exists())
        action = self.last_action()
        request = json.loads((action / 'request.json').read_bytes())
        self.assertFalse(request['stdin_complete'])
        self.assertIn('timeout', request['stdin_error'])
        self.assertEqual((action / 'stdin.bin').read_bytes(), b'{')
        self.assertEqual((action / 'response.bin').read_bytes(), stdout)
        result, value = self.run_action('describe')
        self.assertEqual(result.returncode, 1, value)

    def test_oversize_stdin_refuses_with_bounded_prefix_and_terminal_refusal(self):
        self.start()
        sent = b'x' * (process.REQUEST_CAP + 1)
        result, value = self.run_action('finish', stdin=sent)
        self.assertNotEqual(result.returncode, 0, value)
        self.assertFalse((self.session / 'candidate.json').exists())
        action = self.last_action()
        request = json.loads((action / 'request.json').read_bytes())
        record = json.loads((action / 'record.json').read_bytes())
        self.assertFalse(request['stdin_complete'])
        self.assertEqual((action / 'stdin.bin').read_bytes(), sent)
        self.assertEqual(base64.b64decode(request['stdin_base64']), sent)
        self.assertEqual(record['launcher_exit'], 1)
        self.assertEqual((action / 'response.bin').read_bytes(), result.stdout)
        result, value = self.run_action('describe')
        self.assertEqual(result.returncode, 1, value)
        self.assertEqual(json.loads((action / 'record.json').read_bytes()), record)


if __name__ == '__main__':
    unittest.main()
