"""Original V1 nested-process ceilings; bounded capture, no inherited escalation."""

import functools
import os
import resource
import subprocess
import time

import transport_install_support as support

LIMITS = ((resource.RLIMIT_AS, 1073741824), (resource.RLIMIT_CPU, 120),
          (resource.RLIMIT_FSIZE, 33554432), (resource.RLIMIT_NOFILE, 128))


def compatible_limits():
    for category, ceiling in LIMITS:
        soft, hard = resource.getrlimit(category)
        if any(v != resource.RLIM_INFINITY and v < ceiling for v in (soft, hard)):
            return False
    return True


def child_limits(directory):
    os.fchdir(directory)
    os.close(directory)
    for category, ceiling in LIMITS:
        soft, hard = resource.getrlimit(category)
        bounded = [ceiling] + [v for v in (soft, hard) if v != resource.RLIM_INFINITY]
        chosen = min(bounded)
        resource.setrlimit(category, (chosen, chosen))


def run_bounded(argv, cwd, environment, timeout=60, cap=131072):
    support._validate_process(argv, environment, timeout, cap)
    if not compatible_limits():
        return dict(status='REFUSED_INHERITED_LIMIT', exit_code=None,
                    stdout=b'', stderr=b'', elapsed_ns=0, argv=list(argv))
    started = time.monotonic_ns()
    directory = support._directory(cwd)
    streams, process, status = {'stdout': bytearray(), 'stderr': bytearray()}, None, 'REFUSED_LAUNCH'
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=dict(environment), close_fds=True,
                                   pass_fds=(directory,), start_new_session=True,
                                   preexec_fn=functools.partial(child_limits, directory))
        status = support._capture(process, streams, started + timeout * 1000000000, cap)
    except (OSError, ValueError, subprocess.SubprocessError, MemoryError):
        status = 'REFUSED_IO' if process is not None else 'REFUSED_LAUNCH'
    except KeyboardInterrupt:
        status = 'REFUSED_INTERRUPTED'
    finally:
        os.close(directory)
        if process is not None:
            descendants, clean = support._kill_group(process)
            if not clean:
                status += '+CLEANUP_UNVERIFIED'
            elif descendants and status == 'SUCCESS':
                status = 'REFUSED_DESCENDANTS'
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
    return dict(status=status, exit_code=None if process is None else process.returncode,
                stdout=bytes(streams['stdout']), stderr=bytes(streams['stderr']),
                elapsed_ns=time.monotonic_ns() - started, argv=list(argv))
