"""Reuse bounded capture/cleanup with limits that never raise inherited ceilings.

Linux single-threaded caller only, same trust boundary as the pinned installer
support module. This is process orchestration, not semantic interpretation.
"""
import functools
import os
import resource
import subprocess
import time

import transport_install_support as support


def limit(category, ceiling):
    soft, hard = resource.getrlimit(category)
    candidates = [ceiling] + [v for v in (soft, hard) if v != resource.RLIM_INFINITY]
    chosen = min(candidates)
    resource.setrlimit(category, (chosen, chosen))


def child_limits(directory):
    os.fchdir(directory)
    for category, ceiling in ((resource.RLIMIT_AS, 536870912),
                              (resource.RLIMIT_CPU, 120),
                              (resource.RLIMIT_FSIZE, 4194304),
                              (resource.RLIMIT_NOFILE, 128)):
        limit(category, ceiling)


def run_bounded(argv, cwd, environment, timeout=60, cap=131072):
    support._validate_process(argv, environment, timeout, cap)
    started = time.monotonic_ns()
    directory = support._directory(cwd)
    process, streams, status = None, {'stdout': bytearray(), 'stderr': bytearray()}, 'REFUSED_LAUNCH'
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=dict(environment), close_fds=True,
                                   pass_fds=(directory,), start_new_session=True,
                                   preexec_fn=functools.partial(child_limits, directory))
        status = support._capture(process, streams, started + int(timeout * 1000000000), cap)
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
    return {'argv': list(argv), 'exit_code': None if process is None else process.returncode,
            'stdout': bytes(streams['stdout']), 'stderr': bytes(streams['stderr']),
            'elapsed_ns': time.monotonic_ns() - started, 'status': status}
