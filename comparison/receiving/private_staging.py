"""Bounded private input staging; no chmod, model calls or execution authority."""
import hashlib
import os
from pathlib import Path
import re
import stat

CAP = 1048576
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\Z')


def need(value, reason):
    if type(value) is not bool or not value:
        raise ValueError(reason)


def parts(relative):
    need(type(relative) is str and 0 < len(relative) <= 1031, 'STAGING_RELATIVE')
    result = relative.split('/')
    need(len(result) <= 8 and all(NAME.fullmatch(p) is not None and p not in ('.', '..')
                                for p in result), 'STAGING_COMPONENTS')
    return result


def private(descriptor):
    value = os.fstat(descriptor)
    need(stat.S_ISDIR(value.st_mode) and value.st_uid == os.geteuid()
         and stat.S_IMODE(value.st_mode) == 0o700, 'STAGING_PARENT_PRIVATE')


def open_chain(anchor, relative, create):
    need(type(create) is bool and isinstance(anchor, Path) and anchor.is_absolute()
         and '..' not in anchor.parts and len(anchor.parts) <= 65
         and len(os.fsencode(anchor)) <= 4096, 'STAGING_ANCHOR')
    names = parts(relative)
    descriptor = os.open(anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        private(descriptor)
        for name in names:
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=descriptor)
            try:
                private(child)
            except (OSError, ValueError):
                os.close(child)
                raise
            os.close(descriptor)
            descriptor = child
        return descriptor
    except (OSError, ValueError):
        os.close(descriptor)
        raise


def chain(anchor, relative, create=True):
    descriptor = open_chain(anchor, relative, create)
    os.close(descriptor)
    return anchor.joinpath(*parts(relative))


def write_new(anchor, relative_dir, name, raw):
    need(type(name) is str and NAME.fullmatch(name) is not None and name not in ('.', '..')
         and type(raw) is bytes and len(raw) <= CAP, 'STAGING_PAYLOAD')
    parent = open_chain(anchor, relative_dir, False)
    descriptor = None
    try:
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        need(stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o600, 'STAGING_PAYLOAD_MODE')
        offset = 0
        for unused in range(65):
            if offset == len(raw):
                break
            written = os.write(descriptor, raw[offset:offset + 16384])
            need(type(written) is int and written > 0, 'STAGING_SHORT_WRITE')
            offset += written
        need(offset == len(raw), 'STAGING_WRITE_BOUND')
        os.fsync(descriptor)
        os.lseek(descriptor, 0, os.SEEK_SET)
        need(os.read(descriptor, CAP + 1) == raw, 'STAGING_READBACK')
        return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)
