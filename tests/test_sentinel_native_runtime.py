"""Portable lifecycle controls: every process/namespace dispatch is mocked."""
import contextlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from sentinel_v1 import native_runtime as runtime
from sentinel_v1 import native
from sentinel_v1.common import identity


def denied(*_args, **_kwargs):
    raise RuntimeError('real process dispatch forbidden in portable controls')


subprocess.Popen = denied
os.execv = denied


def elf_fixture():
    raw = bytearray(1024)
    raw[:16] = b'\x7fELF\x02\x01' + bytes(10)
    struct.pack_into('<HHIQQQIHHHHHH', raw, 16, 2, 183, 1, 0, 64, 0, 0, 64, 56, 3, 0, 0, 0)
    interpreter = b'/lib/ld-linux-aarch64.so.1\x00'
    strings = b'libc.so.6\x00ld-linux-aarch64.so.1\x00'
    rows = [(1, 5, 0, 0, 0, 1024, 1024, 4096),
            (3, 4, 256, 256, 0, len(interpreter), len(interpreter), 1),
            (2, 4, 320, 320, 0, 80, 80, 8)]
    for index, row in enumerate(rows):
        struct.pack_into('<IIQQQQQQ', raw, 64 + index * 56, *row)
    raw[256:256 + len(interpreter)] = interpreter
    raw[512:512 + len(strings)] = strings
    tags = [(1, 0), (1, len(b'libc.so.6\x00')), (5, 512), (10, len(strings)), (0, 0)]
    for index, row in enumerate(tags):
        struct.pack_into('<QQ', raw, 320 + index * 16, *row)
    return bytes(raw)


class NativeRuntimeControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        (self.work / 'request.stn1').write_bytes(b'input')
        (self.work / 'sentinel-wire').write_bytes(b'binary')
        self.config = {'global_deadline': 500, 'input_pin': identity(b'input'),
                       'binary_pin': identity(b'binary')}

    def test_external_elf_pin_and_dependency_profile(self):
        raw = elf_fixture()
        path = self.work / 'held-elf'
        path.write_bytes(raw)
        self.assertEqual(runtime._binary(path, identity(raw)), (path, raw))
        with self.assertRaises(ValueError):
            runtime._binary(path, identity(raw + b'X'))
        for malformed in (b'', raw[:63], raw[:320], raw.replace(b'libc.so.6', b'libX.so.6')):
            with self.assertRaises((ValueError, struct.error)):
                runtime._elf_dependencies(malformed)

    def test_historical_only_json_preserves_inert_tokens_and_refuses_bad_inputs(self):
        raw = b' { "status": "CHECKED", "elapsed": 0.25, "count": 1 }\n'
        value = native._historical_json(raw)
        self.assertEqual(value['elapsed'], 'HISTORICAL_DIAGNOSTIC_FLOAT:0.25')
        self.assertEqual(type(value['count']), int)
        with self.assertRaises(ValueError):
            native.parse(raw)
        invalid = [b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":Infinity}', b'{"x":-Infinity}',
            b'{"x":1e999999}', b'{"x":' + b'[' * 17 + b'0' + b']' * 17 + b'}',
            b'{"x":1.' + b'0' * 65 + b'}', b'{"x":123456789012345678901}',
            b'{"x":"\xff"}', b'[]', b' ' * 1048577]
        for malformed in invalid:
            with self.assertRaises(ValueError):
                native._historical_json(malformed)

    def test_runtime_roster_drift_refuses(self):
        expected = {'path': '/fixed', 'bytes': 1, 'sha256': '0' * 64}
        with mock.patch.object(runtime, 'pin_regular', return_value=dict(expected, bytes=2)):
            with self.assertRaisesRegex(ValueError, 'runtime identity'):
                runtime._verify_runtime({'/fixed': expected})

    def test_missing_pidfd_or_deadline_refuses_before_input_creation(self):
        out = self.work / 'out'
        out.mkdir()
        with self.assertRaisesRegex(ValueError, 'global admission'):
            runtime._configuration(b'input', self.work / 'none', identity(b'binary'),
                                   out, {}, time.monotonic())
        self.assertFalse((out / 'request.stn1').exists())
        with mock.patch.object(runtime.os, 'pidfd_open', new=None):
            with mock.patch.object(runtime.os, 'pidfd_open', create=True) as unused:
                unused.side_effect = OSError('pidfd unavailable')
                with self.assertRaises(OSError):
                    runtime._configuration(b'input', self.work / 'none', identity(b'binary'),
                                           out, {}, time.monotonic() + 450)

    def test_native_completion_and_owned_cleanup(self):
        fake = mock.Mock()
        fake.wait.return_value = 0
        with mock.patch.object(runtime, 'admit_phase', return_value=500), \
             mock.patch.object(runtime.subprocess, 'Popen', return_value=fake) as dispatch, \
             mock.patch.object(runtime.os, 'waitid', return_value=object()), \
             mock.patch.object(runtime, 'drain_children', return_value={'remaining': 0}) as cleanup, \
             mock.patch.object(runtime.time, 'monotonic', side_effect=[100, 100.1, 100.2]):
            record = runtime._native(self.work, self.config)
        self.assertEqual(record['returncode'], 0)
        cleanup.assert_called_once_with()
        self.assertEqual(dispatch.call_args.args[0], [str(self.work / 'sentinel-wire')])
        self.assertEqual(dispatch.call_args.kwargs['preexec_fn'], runtime._native_limits)

    def test_late_exit_cannot_pass_native_phase(self):
        fake = mock.Mock()
        fake.wait.return_value = 0
        with mock.patch.object(runtime, 'admit_phase', return_value=500), \
             mock.patch.object(runtime.subprocess, 'Popen', return_value=fake), \
             mock.patch.object(runtime.os, 'waitid', return_value=object()), \
             mock.patch.object(runtime, 'drain_children', return_value={'remaining': 0}) as cleanup, \
             mock.patch.object(runtime.time, 'monotonic', side_effect=[100, 103.001]):
            with self.assertRaisesRegex(ValueError, 'late completion'):
                runtime._native(self.work, self.config)
        cleanup.assert_called_once_with()

    def test_timeout_drains_owned_children_and_refuses(self):
        with mock.patch.object(runtime, 'admit_phase', return_value=500), \
             mock.patch.object(runtime.subprocess, 'Popen', return_value=mock.Mock()), \
             mock.patch.object(runtime.os, 'waitid', return_value=None), \
             mock.patch.object(runtime, 'drain_children', return_value={'remaining': 0}) as cleanup, \
             mock.patch.object(runtime.time, 'monotonic', side_effect=[100, 103.001, 103.002]):
            with self.assertRaisesRegex(ValueError, 'timeout'):
                runtime._native(self.work, self.config)
        cleanup.assert_called_once_with()

    def test_failed_remount_captures_writable_quiescent_state_once(self):
        failures = []
        with mock.patch.object(runtime, '_mount', side_effect=ValueError('remount refused')), \
             mock.patch.object(runtime, 'snapshot', return_value={'complete': True}) as capture:
            readonly, _captured = runtime._freeze(self.work, self.work, self.config, failures)
        self.assertFalse(readonly)
        self.assertEqual(len(failures), 1)
        capture.assert_called_once_with(self.work, self.work, False)

    def test_mount_admission_and_late_completion_refuse(self):
        with mock.patch.object(runtime, 'mount_command') as command:
            with mock.patch.object(runtime.time, 'monotonic', return_value=100):
                with self.assertRaisesRegex(ValueError, 'admission'):
                    runtime._mount([], self.work, 109)
            command.assert_not_called()
            with mock.patch.object(runtime.time, 'monotonic', side_effect=[100, 100, 110.001]):
                with self.assertRaisesRegex(ValueError, 'late mount'):
                    runtime._mount([], self.work, 500)

    def test_native_failure_and_incomplete_capture_never_green(self):
        config = dict(self.config, source_root=str(ROOT), source_manifest={}, runtime_roster={},
                      binary_path=str(self.work / 'sentinel-wire'))
        with mock.patch.object(runtime, '_native', side_effect=MemoryError), \
             mock.patch.object(runtime, 'drain_children', return_value={'remaining': 0}), \
             mock.patch.object(runtime, '_source_identity'), \
             mock.patch.object(runtime, '_verify_runtime'), mock.patch.object(runtime, '_binary'), \
             mock.patch.object(runtime, '_freeze', return_value=(False, {'complete': False})), \
             mock.patch.object(runtime, 'usage', return_value=0):
            record = runtime._execute(self.work, self.work, config)
        self.assertEqual(record['status'], 'FAILED')
        self.assertIn('MemoryError', record['failures'][0])

    def test_partial_capture_failure_is_not_retried(self):
        out = self.work / 'out'
        out.mkdir()
        (out / 'private').mkdir()
        (out / 'launch.json').write_text('{}')
        with mock.patch.object(runtime.sys, 'argv', ['runtime', 'tools', str(out)]), \
             mock.patch.object(runtime, 'limits'), mock.patch.object(runtime, '_setup', return_value={}), \
             mock.patch.object(runtime, '_execute', side_effect=ValueError('partial capture collision')), \
             mock.patch.object(runtime, '_freeze') as freeze, \
             mock.patch.object(runtime, 'drain_children', return_value={'remaining': 0}):
            self.assertEqual(runtime.main(), 2)
        freeze.assert_not_called()
        record = json.loads((out / 'namespace-result.json').read_bytes())
        self.assertFalse(record['capture_retry_performed'])
        self.assertEqual(record['failure_stage'], 'EXECUTE_OR_CAPTURE')

    def test_missing_or_tampered_capture_payload_refuses(self):
        folder = self.work / 'capture'
        folder.mkdir()
        payload = folder / 'payload-0000.bin'
        payload.write_bytes(b'x')
        row = {'path': 'native.stdout', 'kind': 'regular', 'bytes': 1,
               'payload': payload.name, 'sha256': identity(b'y')['sha256']}
        record = {'complete_quiescent_census': True, 'readonly_qualified': True,
                  'readonly_observed': True, 'entries': [row]}
        (folder / 'inventory.json').write_text(json.dumps(record))
        with self.assertRaisesRegex(ValueError, 'readback mismatch'):
            runtime._captured_bytes(self.work, {'inventory': 'capture/inventory.json'}, 'native.stdout', 2725)
        with self.assertRaisesRegex(ValueError, 'payload missing'):
            runtime._captured_bytes(self.work, {'inventory': 'capture/inventory.json'}, 'native.stderr', 4096)

    def test_parent_pidfd_failure_closes_pipes_and_reaps(self):
        fake = mock.Mock(stdout=io.BytesIO(), stderr=io.BytesIO())
        with mock.patch.object(runtime.subprocess, 'Popen', return_value=fake), \
             mock.patch.object(runtime.os, 'pidfd_open', side_effect=OSError('pidfd failed')):
            with self.assertRaisesRegex(ValueError, 'namespace failed'):
                runtime._parent(self.work, dict(self.config, source_root=str(ROOT)))
        fake.kill.assert_called_once_with()
        fake.wait.assert_called_once_with(timeout=5)
        self.assertTrue(fake.stdout.closed and fake.stderr.closed)

    def test_parent_stream_allocation_failure_precedes_spawn(self):
        with mock.patch.object(runtime, 'bytearray', side_effect=MemoryError('streams'), create=True), \
             mock.patch.object(runtime.subprocess, 'Popen') as dispatch:
            with self.assertRaises(MemoryError):
                runtime._parent(self.work, dict(self.config, source_root=str(ROOT)))
        dispatch.assert_not_called()

    def test_parent_pidfd_memory_failure_reaps_owned_child(self):
        fake = mock.Mock(stdout=io.BytesIO(), stderr=io.BytesIO())
        with mock.patch.object(runtime.subprocess, 'Popen', return_value=fake), \
             mock.patch.object(runtime.os, 'pidfd_open', side_effect=MemoryError('pidfd')):
            with self.assertRaisesRegex(ValueError, 'namespace failed'):
                runtime._parent(self.work, dict(self.config, source_root=str(ROOT)))
        fake.kill.assert_called_once_with()
        fake.wait.assert_called_once_with(timeout=5)
        self.assertTrue(fake.stdout.closed and fake.stderr.closed)

    def test_parent_precollect_memory_failure_uses_owned_pidfd(self):
        fake = mock.Mock(stdout=io.BytesIO(), stderr=io.BytesIO())
        with mock.patch.object(runtime.subprocess, 'Popen', return_value=fake), \
             mock.patch.object(runtime.os, 'pidfd_open', return_value=123), \
             mock.patch.object(runtime, 'collect', side_effect=MemoryError('precollect')), \
             mock.patch.object(runtime.signal, 'pidfd_send_signal') as kill, \
             mock.patch.object(runtime.os, 'close') as close:
            with self.assertRaisesRegex(ValueError, 'namespace failed'):
                runtime._parent(self.work, dict(self.config, source_root=str(ROOT)))
        kill.assert_called_once_with(123, runtime.signal.SIGKILL, None, 0)
        fake.kill.assert_not_called()
        fake.wait.assert_called_once_with(timeout=5)
        close.assert_called_once_with(123)
        self.assertTrue(fake.stdout.closed and fake.stderr.closed)


if __name__ == '__main__':
    unittest.main()
