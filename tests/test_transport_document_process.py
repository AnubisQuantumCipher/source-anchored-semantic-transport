"""Pure mocked document-process controls; no native, model, fixture or scratch output."""
import contextlib
from pathlib import Path
import signal
import subprocess
import sys
import types
import unittest
from unittest.mock import Mock, patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import transport_document as document
import transport_document_cli as cli


def observation_callbacks(test, child, actions, opened, closed, code, group_error,
                          wait_error, observation_error):
    def send(fd, number, info, flags):
        test.assertIsNone(child.returncode)
        test.assertEqual((fd, number, info, flags), (77, signal.SIGKILL, None, 4))
        actions.append('signal')
        if group_error:
            raise group_error

    def observe(idtype, ident, _options):
        test.assertEqual(ident, child.pid if idtype == document.os.P_PID else 77)
        if idtype == document.os.P_PIDFD:
            actions.append('reap')
            if wait_error:
                raise wait_error
            if code < 0:
                return types.SimpleNamespace(si_pid=child.pid, si_code=document.os.CLD_KILLED,
                                             si_status=-code)
            return types.SimpleNamespace(si_pid=child.pid, si_code=document.os.CLD_EXITED,
                                         si_status=code)
        if observation_error is not None:
            raise observation_error
        test.assertEqual(idtype, document.os.P_PID)
        return types.SimpleNamespace(si_pid=child.pid, si_code=document.os.CLD_EXITED, si_status=0)

    def open_pid(pid, flags=0):
        test.assertEqual((pid, flags), (child.pid, 0))
        opened.append(pid)
        return 77

    def close_fd(fd):
        test.assertEqual(fd, 77)
        closed.append(fd)

    return send, observe, open_pid, close_fd


class ProcessControls(unittest.TestCase):
    def test_fractional_shorter_timer_countdown_is_untouched(self):
        for remaining in (0.125, 0.5, 450):
            with self.subTest(remaining=remaining), \
                 patch.object(cli.resource, 'getrlimit', return_value=(1, 2)), \
                 patch.object(cli.resource, 'setrlimit') as limits, \
                 patch.object(cli.signal, 'signal'), \
                 patch.object(cli.signal, 'getitimer', return_value=(remaining, 0)), \
                 patch.object(cli.signal, 'setitimer') as timer, \
                 patch.object(cli.signal, 'alarm') as alarm:
                cli.cli_limits()
                timer.assert_not_called()
                alarm.assert_not_called()
                self.assertEqual(limits.call_count, 4)
                for call in limits.call_args_list:
                    self.assertLessEqual(call.args[1][0], 1)
                    self.assertLessEqual(call.args[1][1], 2)

    def test_absent_or_longer_timer_receives_command_ceiling(self):
        for remaining in (0, 900):
            with self.subTest(remaining=remaining), \
                 patch.object(cli.resource, 'getrlimit', return_value=(1, 2)), \
                 patch.object(cli.resource, 'setrlimit'), \
                 patch.object(cli.signal, 'signal'), \
                 patch.object(cli.signal, 'getitimer', return_value=(remaining, 0)), \
                 patch.object(cli.signal, 'setitimer') as timer:
                cli.cli_limits()
                timer.assert_called_once_with(signal.ITIMER_REAL, 450)

    def observed_case(self, code=0, data=b'', group_error=None, wait_error=None,
                      observation_error=None):
        actions = []
        child = Mock(pid=2000000, returncode=None)
        child.stderr.fileno.return_value = 123
        child.stderr.close.side_effect = lambda: actions.append('close')
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.select.return_value = [(None, None)]
        opened, closed = [], []
        send, observe, open_pid, close_fd = observation_callbacks(
            self, child, actions, opened, closed, code, group_error, wait_error,
            observation_error)
        with contextlib.ExitStack() as stack:
            for target, name, options in [
                (document.selectors, 'DefaultSelector', {'return_value': selector}),
                (document.os, 'read', {'side_effect': [data, b''] if data else [b'']}),
                (document.os, 'waitid', {'side_effect': observe}),
                (document.os, 'pidfd_open', {'side_effect': open_pid}),
                (document.os, 'close', {'side_effect': close_fd}),
                (document.os, 'getpgid', {'side_effect': AssertionError('numeric getpgid')}),
                (document.os, 'getsid', {'side_effect': AssertionError('numeric getsid')}),
                (document.os, 'killpg', {'side_effect': AssertionError('numeric killpg')}),
                (document.signal, 'pidfd_send_signal', {'side_effect': send}),
                (document.subprocess, 'Popen', {'side_effect': AssertionError('dispatch forbidden')}),
            ]:
                stack.enter_context(patch.object(target, name, **options))
            error = None
            try:
                document.child_result(child)
            except Exception as caught:
                error = caught
        self.assertEqual(actions, ['close'] if observation_error else ['signal', 'reap', 'close'])
        self.assertEqual(opened, [] if observation_error else [child.pid])
        self.assertEqual(closed, [] if observation_error else [77])
        self.assertEqual(child.wait.call_count, 0)
        return error

    def test_lost_or_unverifiable_observation_never_signals_or_reaps(self):
        for error in (ChildProcessError('lost'), PermissionError('denied'), OSError('unknown')):
            with self.subTest(error=type(error).__name__):
                self.assertIs(self.observed_case(observation_error=error), error)

    def test_foreign_reap_between_observations_does_not_signal(self):
        child = Mock(pid=2000000, returncode=None)
        calls = []

        def observe(*_args):
            calls.append('waitid')
            if len(calls) == 2:
                raise ChildProcessError('foreign reap')
            return types.SimpleNamespace(si_pid=child.pid)

        with patch.object(document.os, 'waitid', side_effect=observe), \
             patch.object(document.os, 'getpgid', side_effect=AssertionError('numeric getpgid')), \
             patch.object(document.os, 'getsid', side_effect=AssertionError('numeric getsid')), \
             patch.object(document.os, 'killpg', side_effect=AssertionError('numeric killpg')), \
             patch.object(document.os, 'pidfd_open', side_effect=AssertionError('pidfd open')), \
             patch.object(document.signal, 'pidfd_send_signal', side_effect=AssertionError('pidfd signal')), \
             patch.object(document.os, 'close', side_effect=AssertionError('pidfd close')):
            with self.assertRaises(ChildProcessError):
                document.child_cleanup(child)
        self.assertEqual(calls, ['waitid', 'waitid'])
        child.wait.assert_not_called()

    def test_cleanup_requires_kernel_ownership_before_numeric_operations(self):
        for error in (ChildProcessError('lost'), PermissionError('denied'), OSError('unknown')):
            child = Mock(pid=2000000, returncode=None)
            with self.subTest(error=type(error).__name__), \
                 patch.object(document.os, 'waitid', side_effect=error), \
                 patch.object(document.os, 'getpgid', side_effect=AssertionError('numeric getpgid')), \
                 patch.object(document.os, 'getsid', side_effect=AssertionError('numeric getsid')), \
                 patch.object(document.os, 'killpg', side_effect=AssertionError('numeric killpg')), \
                 patch.object(document.os, 'pidfd_open', side_effect=AssertionError('pidfd open')), \
                 patch.object(document.signal, 'pidfd_send_signal', side_effect=AssertionError('pidfd signal')):
                with self.assertRaises(type(error)):
                    document.child_cleanup(child)
                child.wait.assert_not_called()

    def test_already_reaped_cleanup_does_not_touch_numeric_pid(self):
        child = Mock(pid=2000000, returncode=0)
        with patch.object(document.os, 'waitid', side_effect=AssertionError('waitid')), \
             patch.object(document.os, 'killpg', side_effect=AssertionError('numeric killpg')), \
             patch.object(document.os, 'pidfd_open', side_effect=AssertionError('pidfd open')):
            with self.assertRaisesRegex(ValueError, 'already reaped'):
                document.child_cleanup(child)
            child.wait.assert_not_called()

    def test_lost_ownership_after_open_does_not_signal(self):
        child, calls = Mock(pid=2000000, returncode=None), []

        def observe(idtype, ident, _options):
            self.assertEqual((idtype, ident), (document.os.P_PID, child.pid))
            calls.append('waitid')
            if len(calls) == 3:
                raise ChildProcessError('lost after open')
            return types.SimpleNamespace(si_pid=child.pid)

        with patch.object(document.os, 'waitid', side_effect=observe), \
             patch.object(document.os, 'pidfd_open', return_value=77) as opened, \
             patch.object(document.os, 'close') as close, \
             patch.object(document.os, 'killpg', side_effect=AssertionError('numeric killpg')), \
             patch.object(document.signal, 'pidfd_send_signal', side_effect=AssertionError('pidfd signal')):
            with self.assertRaises(ChildProcessError):
                document.child_cleanup(child)
        self.assertEqual(calls, ['waitid', 'waitid', 'waitid'])
        opened.assert_called_once_with(child.pid)
        close.assert_called_once_with(77)
        child.wait.assert_not_called()
        self.assertIsNone(child.returncode)

    def test_running_owned_child_is_signaled_before_reaping(self):
        child, events = Mock(pid=2000000, returncode=None), []

        def observe(idtype, ident, _options):
            if idtype == document.os.P_PIDFD:
                self.assertEqual(ident, 77)
                events.append('reap')
                return types.SimpleNamespace(si_pid=child.pid, si_code=document.os.CLD_KILLED,
                                             si_status=signal.SIGKILL)
            self.assertEqual((idtype, ident), (document.os.P_PID, child.pid))
            events.append('waitid')
            return types.SimpleNamespace(si_pid=child.pid)

        def send(fd, number, info, flags):
            self.assertEqual((fd, number, info, flags), (77, signal.SIGKILL, None, 4))
            self.assertLess(events.index('waitid'), len(events))
            events.append('signal')

        with patch.object(document.os, 'waitid', side_effect=observe), \
             patch.object(document.os, 'pidfd_open', return_value=77), \
             patch.object(document.os, 'close') as close, \
             patch.object(document.os, 'killpg', side_effect=AssertionError('numeric killpg')), \
             patch.object(document.os, 'getpgid', side_effect=AssertionError('numeric getpgid')), \
             patch.object(document.os, 'getsid', side_effect=AssertionError('numeric getsid')), \
             patch.object(document.signal, 'pidfd_send_signal', side_effect=send):
            self.assertEqual(document.child_cleanup(child), -signal.SIGKILL)
        self.assertEqual(events, ['waitid', 'waitid', 'waitid', 'signal', 'reap'])
        self.assertLess(events.index('signal'), events.index('reap'))
        close.assert_called_once_with(77)
        child.wait.assert_not_called()
        self.assertEqual(child.returncode, -signal.SIGKILL)

    def test_clean_completion_is_observed_before_signal_and_reap(self):
        self.assertIsNone(self.observed_case())

    def test_nonzero_and_diagnostics_preserve_refusal_before_publication(self):
        for code, data in ((7, b''), (0, b'x' * 4096)):
            with self.subTest(code=code, stderr=len(data)):
                self.assertRegex(str(self.observed_case(code, data)), 'native document refusal')

    def test_stderr_overflow_preserves_refusal_and_ordered_cleanup(self):
        self.assertRegex(str(self.observed_case(-9, b'x' * 4097)), 'native stderr limit exceeded')

    def test_signal_error_is_not_success_and_still_reaps_closes(self):
        self.assertIsInstance(self.observed_case(group_error=PermissionError('denied')), PermissionError)

    def test_absent_group_is_benign_while_owned_child_is_reaped(self):
        self.assertIsNone(self.observed_case(group_error=ProcessLookupError('gone')))

    def test_cleanup_wait_timeout_is_not_success_and_closes(self):
        error = subprocess.TimeoutExpired('mock-native', 5)
        self.assertIsInstance(self.observed_case(wait_error=error), subprocess.TimeoutExpired)

    def test_waitid_observes_without_reaping(self):
        child = Mock(pid=2000000)
        with patch.object(document.os, 'waitid', return_value=object()) as observer, \
             patch.object(document.time, 'monotonic', return_value=100):
            document.child_exit_observed(child, 101)
        observer.assert_called_once_with(document.os.P_PID, child.pid,
            document.os.WEXITED | document.os.WNOHANG | document.os.WNOWAIT)
        child.wait.assert_not_called()
        child.poll.assert_not_called()

    def test_completed_observation_after_deadline_is_refused(self):
        child = Mock(pid=2000000)
        with patch.object(document.os, 'waitid', return_value=object()), \
             patch.object(document.time, 'monotonic', side_effect=[100, 102]):
            with self.assertRaisesRegex(ValueError, 'native decoder timed out'):
                document.child_exit_observed(child, 101)
        child.wait.assert_not_called()

    def test_pending_observation_respects_deadline_without_real_sleep(self):
        child = Mock(pid=2000000)
        with patch.object(document.os, 'waitid', return_value=None), \
             patch.object(document.time, 'monotonic', side_effect=[100, 102]), \
             patch.object(document.time, 'sleep') as sleep:
            with self.assertRaisesRegex(ValueError, 'native decoder timed out'):
                document.child_exit_observed(child, 101)
        sleep.assert_called_once_with(0.25)
        child.wait.assert_not_called()


if __name__ == '__main__':
    unittest.main(verbosity=2, failfast=True)
