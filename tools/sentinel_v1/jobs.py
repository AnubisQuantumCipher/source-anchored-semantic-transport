"""Two bounded job capabilities in an operator-selected private scheduling root."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
from .common import require

ACTIVE_JOBS = 2


def private_root(path):
    require(type(path) is type(Path('/')) and path.is_absolute()
            and '..' not in path.parts and len(os.fsencode(path)) <= 4096,
            'private job root must be an out-of-band absolute path')
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        value = os.fstat(descriptor)
        require(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700,
                'job root must be private and owned')
        return descriptor
    except (OSError, ValueError):
        os.close(descriptor)
        raise


def slot_descriptor(parent, ordinal):
    descriptor = os.open('slot-%d.lock' % ordinal, os.O_RDWR | os.O_CREAT
                         | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
    try:
        value = os.fstat(descriptor)
        require(stat.S_ISREG(value.st_mode) and value.st_uid == os.geteuid()
                and stat.S_IMODE(value.st_mode) == 0o600 and value.st_size == 0
                and value.st_nlink == 1, 'invalid job capability file')
        return descriptor
    except (OSError, ValueError):
        os.close(descriptor)
        raise


@contextmanager
def job_slot(root):
    """No model dispatch. Every participating process must use the same root."""
    parent, held, ordinal = private_root(root), None, None
    try:
        for candidate in range(ACTIVE_JOBS):
            descriptor = slot_descriptor(parent, candidate)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(descriptor)
                continue
            except OSError:
                os.close(descriptor)
                raise
            held, ordinal = descriptor, candidate
            break
        require(held is not None, 'semantic job concurrency exhausted')
        yield {'slot': ordinal, 'max_active_jobs': ACTIVE_JOBS,
               'scope': 'THIS_OPERATOR_SELECTED_ROOT_ONLY', 'execution_authority': 'NONE'}
    finally:
        if held is not None:
            os.close(held)
        os.close(parent)
