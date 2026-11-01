"""Real owned Python-child lifecycle evidence, not native decoder acceptance.

Every scenario runs in a fresh single-thread process. The optional counterexample
is reported separately and deliberately prevents an overall qualification claim.
"""
import contextlib
import json
import os
from pathlib import Path
import resource
import select
import signal
import subprocess
import sys
import time
import types
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import transport_document as document

CASES = ('clean', 'diagnostic', 'nonzero', 'timeout', 'interrupt', 'descendant', 'lost_ownership')
COUNTEREXAMPLE = 'foreign_reaper_counterexample'
FLAGS = ['-I', '-B', '-Werror'] + (['-O'] if sys.flags.optimize else [])


def need(condition, reason):
    if condition is not True:
        raise ValueError(reason)


def limits():
    for key, cap in ((resource.RLIMIT_AS, 1073741824), (resource.RLIMIT_CPU, 45),
        (resource.RLIMIT_NOFILE, 64), (resource.RLIMIT_FSIZE, 1048576), (resource.RLIMIT_CORE, 0)):
        previous = resource.getrlimit(key)
        chosen = min([cap] + [value for value in previous if value != resource.RLIM_INFINITY])
        resource.setrlimit(key, (chosen, chosen))
    previous, _interval = signal.getitimer(signal.ITIMER_REAL)
    if previous <= 0 or previous > 20:
        signal.setitimer(signal.ITIMER_REAL, 20)


def process_state(pid):
    try:
        with (Path('/proc') / str(pid) / 'stat').open('rb') as stream:
            raw = stream.read(4097)
    except FileNotFoundError:
        return None
    need(len(raw) <= 4096, 'proc identity bound')
    fields = raw[raw.rfind(b')') + 2:].split()
    need(len(fields) >= 20, 'proc identity fields')
    return {'pid': pid, 'state': fields[0].decode(), 'ppid': int(fields[1]),
        'group': int(fields[2]), 'session': int(fields[3]), 'start': int(fields[19])}


def terminated(pid, original):
    for _ in range(40):
        current = process_state(pid)
        if current is None:
            return 'ABSENT'
        need(current['start'] == original['start'], 'observed identity changed')
        if current['state'] == 'Z':
            return 'ZOMBIE_TERMINATED_NOT_REAPED_BY_HARNESS'
        time.sleep(0.05)
    raise ValueError('owned fixture remains live')


def descendant_handle(pid, leader):
    before = process_state(pid)
    need(before is not None and before['group'] == leader and before['session'] == leader,
         'descendant session before handle acquisition')
    descriptor = os.pidfd_open(pid)
    try:
        after = process_state(pid)
        need(after is not None and all(after[key] == before[key]
            for key in ('pid', 'start', 'group', 'session')),
            'descendant identity changed during handle acquisition')
        return descriptor, after
    except BaseException:
        # An unvalidated handle is never used to signal.
        os.close(descriptor)
        raise


def spawn(case):
    mode = 'waiting' if case in ('timeout', 'interrupt') else 'clean' if case in (
        'lost_ownership', COUNTEREXAMPLE) else case
    path = ROOT / 'tests/transport_process_fixture.py'
    child = subprocess.Popen([sys.executable, *FLAGS, str(path), mode],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        start_new_session=True, close_fds=True, env={'PATH': '/usr/bin:/bin', 'LANG': 'C'})
    descriptor = None
    try:
        descriptor = os.pidfd_open(child.pid)
        ready, _write, _error = select.select([child.stdout], [], [], 3)
        need(bool(ready), 'fixture readiness timed out')
        raw = child.stdout.readline(513)
        need(len(raw) <= 512 and raw.endswith(b'\n'), 'fixture readiness bound')
        value = json.loads(raw)
        need(value.get('pid') == child.pid, 'fixture leader identity')
        identity = process_state(child.pid)
        need(identity is not None and identity['ppid'] == os.getpid()
            and identity['group'] == child.pid and identity['session'] == child.pid,
            'fixture session ownership')
        return child, descriptor, identity, value.get('descendant')
    except BaseException:
        # Without a stable handle, rely on this fixture's own ten-second alarm.
        cleanup(child, descriptor, None, timeout=12 if descriptor is None else 3)
        raise


def cleanup(child, descriptor, descendant_fd, timeout=3):
    errors = []
    for fd in (descendant_fd, descriptor):
        if fd is not None:
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except BaseException as error:
                errors.append(error)
            try:
                os.close(fd)
            except BaseException as error:
                errors.append(error)
    if child.returncode is None:
        try:
            child.wait(timeout=timeout)
        except BaseException as error:
            errors.append(error)
    for stream in (child.stdout, child.stderr):
        try:
            stream.close()
        except BaseException as error:
            errors.append(error)
    if errors:
        raise errors[0]


@contextlib.contextmanager
def audited(child, events):
    original_wait = child.wait
    real_waitid, real_open, real_signal = os.waitid, os.pidfd_open, signal.pidfd_send_signal

    def wait(*args, **kwargs):
        events.append('numeric_reap')
        return original_wait(*args, **kwargs)

    def observe_wait(*args, **kwargs):
        events.append('pidfd_reap' if args and args[0] == os.P_PIDFD else 'waitid')
        return real_waitid(*args, **kwargs)

    def observe_open(pid, flags=0):
        events.append('pidfd_open')
        return real_open(pid, flags)

    def observe_signal(pidfd, sig, siginfo=None, flags=0):
        events.append('pidfd_signal')
        need(sig == signal.SIGKILL and siginfo is None and flags == 4, 'pidfd group signal contract')
        return real_signal(pidfd, sig, siginfo, flags)

    real_kill = os.kill

    def kill(pid, sig):
        if pid == os.getpid():
            return real_kill(pid, sig)
        events.append('numeric_operation')
        raise RuntimeError('numeric pid operation')

    def numeric(*_args, **_kwargs):
        events.append('numeric_operation')
        raise RuntimeError('numeric pid operation')

    with contextlib.ExitStack() as stack:
        stack.enter_context(patch.object(child, 'wait', wait))
        stack.enter_context(patch.object(os, 'waitid', observe_wait))
        stack.enter_context(patch.object(os, 'pidfd_open', observe_open))
        stack.enter_context(patch.object(signal, 'pidfd_send_signal', observe_signal))
        stack.enter_context(patch.object(os, 'kill', kill))
        for name in ('getpgid', 'getsid', 'killpg'):
            stack.enter_context(patch.object(os, name, numeric))
        yield


def exercise_result(case, child):
    if case == 'timeout':
        now, clock, count = time.monotonic(), time.monotonic, [0]
        def deadline_clock():
            count[0] += 1
            return now + 121 if count[0] == 2 else clock()
        replacement = types.SimpleNamespace(monotonic=deadline_clock, sleep=time.sleep)
        with patch.object(document, 'time', replacement):
            document.child_result(child)
    elif case == 'interrupt':
        def interrupt(_process, _deadline):
            os.kill(os.getpid(), signal.SIGINT)
            raise ValueError('real SIGINT did not interrupt')
        with patch.object(document, 'child_exit_observed', interrupt):
            document.child_result(child)
    else:
        document.child_result(child)


def foreign_reap(child, events):
    real_waitid, real_waitpid = os.waitid, os.waitpid
    observed = real_waitid(os.P_PID, child.pid, os.WEXITED | os.WNOWAIT)
    need(observed.si_pid == child.pid, 'fixture exit identity')
    def observe(*args):
        result = real_waitid(*args)
        reaped, _status = real_waitpid(child.pid, 0)
        need(reaped == child.pid, 'foreign reap identity')
        events.append('foreign_reap_after_observation')
        return result
    def forbidden(*_args, **_kwargs):
        events.append('numeric_operation_after_foreign_reap')
        raise RuntimeError('exclusive reaper not enforced')
    try:
        with patch.object(os, 'waitid', observe), patch.object(os, 'getpgid', forbidden), \
                patch.object(os, 'getsid', forbidden), patch.object(os, 'killpg', forbidden), \
                patch.object(os, 'kill', forbidden), patch.object(os, 'pidfd_open', forbidden), \
                patch.object(signal, 'pidfd_send_signal', forbidden):
            document.child_cleanup(child)
    except RuntimeError as error:
        need(str(error) == 'exclusive reaper not enforced', 'unexpected counterexample')
        return 'REPRODUCED_NUMERIC_OPERATION_AFTER_LOST_OWNERSHIP'
    except ChildProcessError:
        need(events == ['foreign_reap_after_observation'], 'foreign reap refused before numeric signal')
        return 'REFUSED_NUMERIC_OPERATION_AFTER_FOREIGN_REAP'
    finally:
        child.returncode = 0
    return 'NOT_REPRODUCED_REQUIRES_REVIEW'


def run_case(case):
    limits()
    need(signal.getsignal(signal.SIGCHLD) == signal.SIG_DFL, 'default SIGCHLD required')
    with os.scandir('/proc/self/task') as tasks:
        need(next(tasks, None) is not None and next(tasks, None) is None,
             'single thread owner required')
    child, descriptor, identity, descendant = spawn(case)
    descendant_fd, descendant_state = None, None
    events, error, result = [], None, None
    try:
        if descendant is not None:
            descendant_fd, descendant_state = descendant_handle(descendant, child.pid)
        if case == COUNTEREXAMPLE:
            result = foreign_reap(child, events)
        elif case == 'lost_ownership':
            child.wait(timeout=3); child.returncode = None
            with audited(child, events):
                try:
                    document.child_cleanup(child)
                except ChildProcessError:
                    error = 'ChildProcessError'
                finally:
                    child.returncode = 0
            need(events == ['waitid'] and error == 'ChildProcessError', 'lost ownership must refuse first')
        else:
            with audited(child, events):
                try:
                    exercise_result(case, child)
                except (ValueError, KeyboardInterrupt) as caught:
                    error = type(caught).__name__ + ':' + str(caught)
            need(child.stderr.closed, 'stderr not closed')
            need('pidfd_signal' in events and 'pidfd_reap' in events and
                 events.index('pidfd_signal') < events.index('pidfd_reap'),
                 'pidfd signal before pidfd reap')
            need('numeric_operation' not in events and 'numeric_reap' not in events,
                 'numeric pid operation after confirmation')
        need(child.returncode is not None, 'direct child not reaped')
        ended = None if descendant is None else terminated(descendant, descendant_state)
        return {'case': case, 'events': events, 'error': error, 'result': result,
            'leader': identity, 'returncode': child.returncode, 'descendant': descendant_state,
            'descendant_terminal_observation': ended,
            'clock': 'INJECTED_DEADLINE_NOT_NATURAL_120_SECONDS' if case == 'timeout' else 'MONOTONIC',
            'exclusive_reaper': 'PIDFD_PROCESS_GROUP_NUMERIC_SIGNAL_ABSENT_KERNEL_ASSUMED',
            'pid_reuse_before_pidfd_open': 'UNPROVEN_USERSPACE_NOT_ATOMIC',
            'native_decoder_executed': False}
    finally:
        cleanup(child, descriptor, descendant_fd)


class LifecycleControls(unittest.TestCase):
    def test_required_cases_in_fresh_owners(self):
        for case in CASES:
            with self.subTest(case=case):
                command = [sys.executable, *FLAGS, str(Path(__file__).resolve()), '--case', case]
                completed = subprocess.run(command, capture_output=True, timeout=18, check=False)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertLessEqual(len(completed.stdout), 8192)
                value = json.loads(completed.stdout)
                self.assertEqual(value['case'], case)
                expected = {'clean': None, 'descendant': None, 'lost_ownership': 'ChildProcessError'}
                if case in expected:
                    self.assertEqual(value['error'], expected[case])
                elif case == 'interrupt':
                    self.assertTrue(value['error'].startswith('KeyboardInterrupt:'))
                elif case == 'timeout':
                    self.assertIn('native decoder timed out', value['error'])
                else:
                    self.assertIn('native document refusal', value['error'])
                codes = {'clean': 0, 'descendant': 0, 'diagnostic': 0, 'nonzero': 7,
                         'timeout': -signal.SIGKILL, 'interrupt': -signal.SIGKILL}
                if case in codes:
                    self.assertEqual(value['returncode'], codes[case])
                if case == 'diagnostic':
                    self.assertIn('bounded diagnostic', value['error'])
                self.assertEqual(value['exclusive_reaper'],
                                 'PIDFD_PROCESS_GROUP_NUMERIC_SIGNAL_ABSENT_KERNEL_ASSUMED')
                self.assertEqual(value['pid_reuse_before_pidfd_open'],
                                 'UNPROVEN_USERSPACE_NOT_ATOMIC')
                self.assertNotIn('numeric_operation', value['events'])
                if case != 'lost_ownership':
                    self.assertLess(value['events'].index('pidfd_signal'),
                                    value['events'].index('pidfd_reap'))

    def test_foreign_reaper_refuses_before_numeric_signal(self):
        command = [sys.executable, *FLAGS, str(Path(__file__).resolve()), '--case', COUNTEREXAMPLE]
        completed = subprocess.run(command, capture_output=True, timeout=18, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertLessEqual(len(completed.stdout), 8192)
        value = json.loads(completed.stdout)
        self.assertEqual(value['case'], COUNTEREXAMPLE)
        self.assertEqual(value['result'], 'REFUSED_NUMERIC_OPERATION_AFTER_FOREIGN_REAP')
        self.assertEqual(value['events'], ['foreign_reap_after_observation'])
        self.assertEqual(value['exclusive_reaper'],
                         'PIDFD_PROCESS_GROUP_NUMERIC_SIGNAL_ABSENT_KERNEL_ASSUMED')
        self.assertEqual(value['pid_reuse_before_pidfd_open'], 'UNPROVEN_USERSPACE_NOT_ATOMIC')
        self.assertFalse(value['native_decoder_executed'])


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--case' and sys.argv[2] in (*CASES, COUNTEREXAMPLE):
        print(json.dumps(run_case(sys.argv[2]), sort_keys=True))
    else:
        limits()
        unittest.main(verbosity=2)
