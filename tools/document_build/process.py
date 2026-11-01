"""Owned private-PID-namespace process lifecycle; no host process-group signals."""
import os
from pathlib import Path
import signal
import subprocess
import resource
import time
from .common import ENTRY_CAP, need


def private_pids():
    need(os.getpid() == 1, 'private PID1 required')
    names = os.listdir('/proc')
    need(len(names) <= 8192, 'private proc bound')
    return sorted(int(name) for name in names if name.isascii() and name.isdigit() and name != '1')


def drain_children():
    need(os.getpid() == 1, 'cleanup requires private PID1')
    for _ in range(501):
        for pid in private_pids():
            try:
                descriptor = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            try:
                signal.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0)
            except ProcessLookupError:
                pass
            finally:
                os.close(descriptor)
        try:
            for _ in range(ENTRY_CAP):
                pid, _status = os.waitpid(-1, os.WNOHANG)
                if pid == 0:
                    break
        except ChildProcessError:
            pass
        if not private_pids():
            return {'remaining': 0, 'ownership': 'private PID namespace'}
        time.sleep(0.01)
    raise ValueError('owned-child cleanup incomplete; capture forbidden')


def phase(argv, seconds, deadline, work, label, env, child_setup=None):
    started = time.monotonic()
    need(started < deadline, 'global deadline before child dispatch')
    code = None
    with (work / (label + '.stdout')).open('xb') as stdout:
        with (work / (label + '.stderr')).open('xb') as stderr:
            proc = subprocess.Popen(argv, cwd=work, env=env, stdin=subprocess.DEVNULL,
                                    stdout=stdout, stderr=stderr, preexec_fn=child_setup)
            for _ in range(seconds * 20 + 2):
                observed = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if observed is not None:
                    code = proc.wait(timeout=1)
                    break
                if time.monotonic() >= min(deadline, started + seconds):
                    break
                time.sleep(0.05)
    cleanup = drain_children()
    return {'argv': argv, 'returncode': code, 'seconds_bound': seconds,
            'elapsed_seconds': time.monotonic() - started, 'cleanup': cleanup}


def mount_command(argv, work, deadline):
    record = phase(argv, 10, deadline, work, 'mount-' + str(time.monotonic_ns()),
                   {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': str(work)}, mount_limits)
    need(record['returncode'] == 0, 'namespace mount refused; bounded logs retained')


def mount_limits():
    soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
    cap = min([65_536] + [value for value in (soft, hard) if value != resource.RLIM_INFINITY])
    resource.setrlimit(resource.RLIMIT_FSIZE, (cap, cap))


def admit_phase(seconds, global_deadline, reserve):
    remaining = global_deadline - reserve - time.monotonic()
    need(seconds > 0 and remaining >= seconds, 'insufficient global phase budget')
    return global_deadline - reserve
