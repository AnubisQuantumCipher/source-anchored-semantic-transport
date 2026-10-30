"""Explicit fixed budgets and checked, bounded local IO."""
import hashlib
import json
import os
from pathlib import Path
import resource
import stat

PRIVATE_CAP = 67_108_864
EXTERNAL_CAP = 100_663_296
META_CAP = 8_388_608
ENTRY_CAP = 4096
FILE_CAP = 8_388_608
OUTER_SECONDS = 450
TERMINAL_RESERVE = 90


def need(test, message):
    if not test:
        raise ValueError(message)


def read_bytes(path, cap=FILE_CAP):
    info = path.lstat()
    need(stat.S_ISREG(info.st_mode) and info.st_size <= cap, 'regular file/read bound: ' + str(path))
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    need(len(raw) == info.st_size and len(raw) <= cap, 'changed/oversized read')
    return raw


def digest(path):
    return hashlib.sha256(read_bytes(path)).hexdigest()


def json_new(path, value, cap=1_048_576):
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()
    need(len(raw) <= cap, 'metadata bound')
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'metadata short write')


def limits():
    for kind, cap in ((resource.RLIMIT_AS, 1_073_741_824),
                      (resource.RLIMIT_FSIZE, FILE_CAP), (resource.RLIMIT_NOFILE, 64),
                      (resource.RLIMIT_CORE, 0)):
        soft, hard = resource.getrlimit(kind)
        bound = min([cap] + [value for value in (soft, hard) if value != resource.RLIM_INFINITY])
        resource.setrlimit(kind, (bound, bound))


def directory(path, owned=False):
    need(path.is_absolute() and '..' not in path.parts, 'canonical absolute directory required')
    for parent in (path, *path.parents):
        info = parent.lstat()
        need(stat.S_ISDIR(info.st_mode), 'symlink/special directory refused')
    if owned:
        info = path.lstat()
        need(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0, 'private owned directory required')
    return path


def usage(folder, excluded=None):
    pending = [folder]
    used = 0
    for _ in range(ENTRY_CAP + 32):
        if not pending:
            return used
        path = pending.pop()
        if path == excluded:
            continue
        info = path.lstat()
        used += max(info.st_size, info.st_blocks * 512)
        need(used <= EXTERNAL_CAP, 'external output allocation bound')
        if stat.S_ISDIR(info.st_mode):
            names = os.listdir(path)
            need(len(pending) + len(names) <= ENTRY_CAP + 32, 'external entry bound')
            pending.extend(path / name for name in names)
    raise ValueError('external traversal bound')


def bounded_names(folder, cap):
    names = []
    with os.scandir(folder) as entries:
        for _ in range(cap + 1):
            entry = next(entries, None)
            if entry is None:
                return names
            need(len(names) < cap, 'directory cardinality bound')
            names.append(Path(entry.path))
    raise ValueError('directory cardinality bound')
