"""Independent process/identity/publication regression controls, separate suite."""
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import io
import json
import os
import types
from pathlib import Path
import resource
import signal
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
SCRATCH = Path(os.environ.get('TRANSPORT_DOCUMENT_TEST_SCRATCH',
                               '/dev/shm/transport-document-tests')) / 'boundaries'
sys.dont_write_bytecode = True
sys.path.insert(0, str(ROOT / 'tools'))
import transport_document as document
import transport_document_cli as cli
import transport_document_io as document_io


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def footprint(root):
    pending, total = [root], 0
    for _ in range(8192):
        if not pending:
            return total
        path = pending.pop()
        info = path.lstat()
        total += max(info.st_size, info.st_blocks * 512)
        if stat.S_ISDIR(info.st_mode):
            with os.scandir(path) as iterator:
                for entry in iterator:
                    if len(pending) >= 8192:
                        raise ValueError('boundary fixture entry bound')
                    pending.append(Path(entry.path))
    raise ValueError('boundary fixture iteration bound')


class BoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = Path(os.environ['TRANSPORT_DOCUMENT_NATIVE'])
        cls.native_pin = os.environ['TRANSPORT_DOCUMENT_NATIVE_SHA256']
        if sha(cls.native.read_bytes()) != cls.native_pin:
            raise ValueError('boundary native pin')
        SCRATCH.mkdir(mode=0o700, parents=True, exist_ok=True)
        if footprint(SCRATCH) + 1048576 > 8388608:
            raise ValueError('boundary initial prebudget')
        cls.arena = Path(tempfile.mkdtemp(prefix='run-', dir=SCRATCH))
        cls.source = cls.arena / 'source.bin'
        cls.source.write_bytes(b'ABC')
        cls.package = cls.arena / 'package'
        document.encode_document(cls.source, cls.package, 'Boundary fixture')

    def setUp(self):
        self.assertLessEqual(footprint(SCRATCH) + 1048576, 8388608)
        self.assertEqual(sha(self.native.read_bytes()), self.native_pin)
        self.case = self.arena / self._testMethodName
        self.case.mkdir(mode=0o700)

    def tearDown(self):
        self.assertEqual(self.source.read_bytes(), b'ABC')
        self.assertEqual(sha(self.native.read_bytes()), self.native_pin)
        self.assertLessEqual(footprint(SCRATCH), 8388608)

    def script(self, name, output):
        path = self.case / name
        raw = b'#!/bin/sh\nprintf ' + output + b'\n'
        path.write_bytes(raw)
        path.chmod(0o700)
        self.assertEqual(path.read_bytes(), raw)
        return path, sha(raw)

    def test_archive_final_identity_precedes_native_and_publication(self):
        archive = self.case / 'meaning.zip'
        archive.write_bytes((self.package / 'meaning.zip').read_bytes())
        original = document.opened

        @contextmanager
        def changed(path):
            with original(path) as opened:
                yield opened
                with archive.open('ab') as stream:
                    stream.write(b'CHANGED')

        output = self.case / 'decoded.bin'
        with patch.object(document, 'opened', changed), \
             patch.object(document, 'run_native') as native, \
             patch.object(document.os, 'link') as publish:
            with self.assertRaisesRegex(ValueError, 'ZIP changed during reading'):
                document.decode_document(archive, self.package / 'share.txt', output, self.native)
        native.assert_not_called()
        publish.assert_not_called()
        self.assertFalse(output.exists())

    def test_native_replacement_restoration_never_executes_replacement(self):
        native, expected = self.script('native', b"'ORIGINAL\\n'")
        replacement, _ = self.script('replacement', b"'REPLACEMENT\\n'")
        saved = self.case / 'saved-original'
        wire = self.case / 'wire'
        wire.write_bytes(b'ignored by trusted fixture')
        recovered = self.case / 'temporary-output'
        real_run = document.supervisor_module.run
        calls = []

        def swapped(descriptor, wire_descriptor, output_descriptor, held, output_limit):
            self.assertEqual(sha(os.pread(descriptor, 4096, 0)), expected)
            self.assertEqual(os.pread(wire_descriptor, 4096, 0), wire.read_bytes())
            self.assertEqual(os.fstat(output_descriptor).st_size, 0)
            self.assertEqual((held, output_limit), (expected, 32))
            calls.append((descriptor, wire_descriptor, output_descriptor))
            native.rename(saved)
            replacement.rename(native)
            try:
                return real_run(descriptor, wire_descriptor, output_descriptor, held, output_limit)
            finally:
                native.rename(replacement)
                saved.rename(native)

        with patch.object(document.supervisor_module, 'run', side_effect=swapped):
            try:
                document.run_native(native, wire, recovered, expected, 32)
            except ValueError as error:
                self.assertIn('native decoder changed during execution', str(error))
        self.assertEqual(len(calls), 1)
        self.assertEqual(recovered.read_bytes(), b'ORIGINAL\n')
        self.assertNotIn(b'REPLACEMENT', recovered.read_bytes())
        self.assertEqual(sha(native.read_bytes()), expected)

    def fake_child(self):
        child = Mock(pid=2000000, returncode=None)
        child.operations = []
        def reaped(timeout):
            child.operations.append("reap")
            return child.wait.return_value
        child.wait.side_effect = reaped
        child.stderr.fileno.return_value = 123
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.select.return_value = [(None, None)]
        return child, selector

    def pidfd_child_result(self, child, selector, read, exit_code, observed=None):
        def waitid(idtype, ident, _options):
            if idtype == os.P_PIDFD:
                self.assertEqual(ident, 77)
                child.operations.append('reap')
                if exit_code < 0:
                    return types.SimpleNamespace(si_pid=child.pid, si_code=os.CLD_KILLED,
                                                 si_status=-exit_code)
                return types.SimpleNamespace(si_pid=child.pid, si_code=os.CLD_EXITED,
                                             si_status=exit_code)
            self.assertEqual((idtype, ident), (os.P_PID, child.pid))
            return types.SimpleNamespace(si_pid=child.pid)

        def send(fd, number, info, flags):
            self.assertEqual((fd, number, info, flags), (77, signal.SIGKILL, None, 4))
            child.operations.append('signal')

        patches = [
            patch.object(document.selectors, 'DefaultSelector', return_value=selector),
            patch.object(document.os, 'read', **read),
            patch.object(document.os, 'waitid', side_effect=waitid),
            patch.object(document.os, 'pidfd_open', return_value=77),
            patch.object(document.os, 'close'),
            patch.object(document.os, 'killpg', side_effect=AssertionError('numeric killpg')),
            patch.object(document.os, 'getpgid', side_effect=AssertionError('numeric getpgid')),
            patch.object(document.os, 'getsid', side_effect=AssertionError('numeric getsid')),
            patch.object(document.signal, 'pidfd_send_signal', side_effect=send),
        ]
        if observed is not None:
            patches.append(patch.object(document, 'child_exit_observed', side_effect=observed))
        return patches

    def test_stderr_4097_kills_reaps_and_closes(self):
        child, selector = self.fake_child()
        patches = self.pidfd_child_result(child, selector, {'return_value': b'x' * 4097}, -9)
        with patches[0], patches[1], patches[2], patches[3], patches[4] as close, \
             patches[5], patches[6], patches[7], patches[8]:
            with self.assertRaisesRegex(ValueError, 'native stderr limit exceeded'):
                document.child_result(child)
        close.assert_called_once_with(77)
        child.wait.assert_not_called()
        self.assertEqual(child.operations, ['signal', 'reap'])
        child.stderr.close.assert_called_once()

    def test_stderr_4096_is_within_bound_but_still_diagnostic_refusal(self):
        child, selector = self.fake_child()
        patches = self.pidfd_child_result(
            child, selector, {'side_effect': [b'x' * 4096, b'']}, 0)
        with patches[0], patches[1], patches[2], patches[3], patches[4] as close, \
             patches[5], patches[6], patches[7], patches[8]:
            with self.assertRaisesRegex(ValueError, 'native document refusal'):
                document.child_result(child)
        close.assert_called_once_with(77)
        # Original refusal purpose retained; the pidfd signal must precede the sole reap.
        child.wait.assert_not_called()
        self.assertEqual(child.operations, ['signal', 'reap'])
        child.stderr.close.assert_called_once()

    def test_timeout_kills_owned_fake_session_and_reaps(self):
        child, selector = self.fake_child()
        patches = self.pidfd_child_result(
            child, selector, {'return_value': b''}, -9,
            observed=subprocess.TimeoutExpired('native', 120))
        with patches[0], patches[1], patches[2], patches[3], patches[4] as close, \
             patches[5], patches[6], patches[7], patches[8], patches[9]:
            with self.assertRaises(subprocess.TimeoutExpired):
                document.child_result(child)
        close.assert_called_once_with(77)
        child.wait.assert_not_called()
        self.assertEqual(child.operations, ['signal', 'reap'])
        child.stderr.close.assert_called_once()

    def test_oversized_stdout_refuses_before_final_publication(self):
        script, expected = self.script('too-much-output', b"'ABCD'")
        real_run = document.run_native

        def overflow(_native, wire, recovered, _expected, limit):
            self.assertEqual(limit, 3)
            return real_run(script, wire, recovered, expected, limit)

        output = self.case / 'decoded.bin'
        with patch.object(document, 'run_native', side_effect=overflow), \
             patch.object(document.os, 'link') as publish:
            with self.assertRaisesRegex(ValueError, 'native document refusal'):
                document.decode_document(self.package / 'meaning.zip',
                                         self.package / 'share.txt', output, self.native)
        publish.assert_not_called()
        self.assertFalse(output.exists())

    def test_tighter_inherited_limits_are_never_relaxed(self):
        inherited = {resource.RLIMIT_AS: (67108864, 134217728),
                     resource.RLIMIT_FSIZE: (7, 9), resource.RLIMIT_NOFILE: (8, 12),
                     resource.RLIMIT_CORE: (0, 0), resource.RLIMIT_CPU: (2, 5)}
        before = {key: resource.getrlimit(key) for key in inherited}
        with patch.object(document.resource, 'getrlimit', side_effect=inherited.__getitem__), \
             patch.object(document.resource, 'setrlimit') as limits:
            document.native_limits(100)
        self.assertEqual(limits.call_count, len(inherited))
        for call in limits.call_args_list:
            key, value = call.args
            self.assertEqual(value, (inherited[key][0], inherited[key][0]))
        self.assertEqual({key: resource.getrlimit(key) for key in inherited}, before)

    def test_unlimited_inheritance_uses_declared_child_limits(self):
        unlimited = (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
        expected = {resource.RLIMIT_AS: 268435456, resource.RLIMIT_FSIZE: 3,
                    resource.RLIMIT_NOFILE: 16, resource.RLIMIT_CORE: 0,
                    resource.RLIMIT_CPU: 120}
        with patch.object(document.resource, 'getrlimit', return_value=unlimited), \
             patch.object(document.resource, 'setrlimit') as limits:
            document.native_limits(3)
        self.assertEqual(limits.call_count, len(expected))
        for call in limits.call_args_list:
            key, value = call.args
            self.assertEqual(value, (expected[key], expected[key]))

    def test_cli_timeout_is_a_refusal_without_traceback(self):
        argv = ['document', 'inspect', '--archive', str(self.package / 'meaning.zip'),
                '--share', str(self.package / 'share.txt'), '--native', str(self.native)]
        output, error = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', argv), \
             patch.object(cli, 'inspect_document', side_effect=subprocess.TimeoutExpired('native', 120)), \
             redirect_stdout(output), redirect_stderr(error):
            status = cli.main()
        self.assertEqual(status, 2)
        self.assertEqual(output.getvalue(), '')
        self.assertIn('DOCUMENT_REFUSED:', error.getvalue())
        self.assertNotIn('Traceback', error.getvalue())

    def test_loaded_code_comparison_rejects_changed_disk_source(self):
        path = self.case / 'trusted-source.py'
        raw = b'def sample():\n    return 1\n'
        path.write_bytes(raw)
        code = compile(raw, str(path), 'exec', dont_inherit=True, optimize=sys.flags.optimize)
        self.assertEqual(document_io.loaded_epoch(str(path), code), sha(raw))
        path.write_bytes(b'def sample():\n    return 2\n')
        with self.assertRaisesRegex(ValueError, 'loaded Python code does not match declared source'):
            document_io.loaded_epoch(str(path), code)

    def test_runtime_rejects_source_drift_after_import(self):
        originals = {}
        for name in document.MODULES:
            raw = (ROOT / 'tools' / name).read_bytes()
            originals[name] = sha(raw)
            (self.case / name).write_bytes(raw)
        with patch.object(document, '__file__', str(self.case / 'transport_document.py')):
            self.assertEqual(document.runtime(self.native)['modules'], originals)
            target = self.case / 'transport_document_io.py'
            with target.open('ab') as stream:
                stream.write(b'\n# independent disk drift fixture\n')
            with self.assertRaisesRegex(ValueError, 'declared Python source changed after import'):
                document.runtime(self.native)
        self.assertEqual({name: sha((ROOT / 'tools' / name).read_bytes())
                          for name in document.MODULES}, originals)


if __name__ == '__main__':
    unittest.main()
