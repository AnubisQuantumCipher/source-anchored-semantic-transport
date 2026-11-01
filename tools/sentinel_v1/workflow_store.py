"""Private, create-only storage for the additive workflow profile.

Pins are supplied out of band. This store checks integrity, not authorship.
The lock coordinates this root only; it says nothing about provider liveness.
"""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import re
import stat

from .common import (METADATA, canonical, digest, fields, hash_checked, identity,
                     integer, parse, pin_checked, require)

STORE_BYTES = 536_870_912
STORE_FILES = 131_072
EVENTS = 65_538
AREAS = ('objects', 'inbox', 'events')


def identifier(value):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', value)
            is not None, 'workflow identifier')
    return value


def root_descriptor(path):
    require(type(path) is type(Path('/')) and path.is_absolute()
            and '..' not in path.parts and len(path.parts) <= 256
            and len(os.fsencode(path)) <= 4096, 'workflow root path')
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for component in path.parts[1:]:
            successor = os.open(component, os.O_RDONLY | os.O_DIRECTORY
                | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = successor
        value = os.fstat(descriptor)
        require(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700,
                'workflow root must be owned and private')
        return descriptor
    except (OSError, ValueError):
        os.close(descriptor)
        raise


def file_checked(value, cap):
    require(stat.S_ISREG(value.st_mode) and value.st_uid == os.geteuid()
            and stat.S_IMODE(value.st_mode) == 0o600 and value.st_nlink == 1
            and 0 <= value.st_size <= cap, 'workflow file ownership/type/bound')


def snapshot(value):
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns, value.st_mode, value.st_uid, value.st_nlink)


class Store:
    """One operation owns the directory descriptors and cooperative writer lock."""

    def __init__(self, root):
        self.root = root
        self.parent = None
        self.areas = {}
        self.lock = None
        self.bytes = 0
        self.files = 0

    def _open(self, create):
        self.parent = root_descriptor(self.root)
        self.lock = os.open('workflow.lock', os.O_RDWR | (os.O_CREAT if create else 0) | os.O_NOFOLLOW
            | os.O_CLOEXEC, 0o600, dir_fd=self.parent)
        file_checked(os.fstat(self.lock), 0)
        fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name in AREAS:
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=self.parent)
                except FileExistsError:
                    pass
            descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                | os.O_CLOEXEC, dir_fd=self.parent)
            self.areas[name] = descriptor
            value = os.fstat(descriptor)
            require(value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o700,
                    'workflow area must be owned and private')
        self._account()

    def _account(self):
        self.bytes, self.files = 0, 0
        for descriptor in self.areas.values():
            with os.scandir(descriptor) as entries:
                for entry in entries:
                    self.files += 1
                    require(self.files <= STORE_FILES, 'workflow store file bound')
                    value = entry.stat(follow_symlinks=False)
                    file_checked(value, METADATA)
                    self.bytes += value.st_size
                    require(self.bytes <= STORE_BYTES, 'workflow aggregate byte bound')

    @contextmanager
    def opened(self, create=True):
        try:
            require(type(create) is bool, 'workflow creation policy')
            self._open(create)
            yield self
        finally:
            for descriptor in self.areas.values():
                os.close(descriptor)
            self.areas = {}
            if self.lock is not None:
                os.close(self.lock)
                self.lock = None
            if self.parent is not None:
                os.close(self.parent)
                self.parent = None

    def read(self, area, name):
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                             dir_fd=self.areas[area])
        try:
            before = os.fstat(descriptor)
            file_checked(before, METADATA)
            chunks, count = [], 0
            for _ in range(18):
                chunk = os.read(descriptor, 65_536)
                if not chunk:
                    break
                count += len(chunk)
                require(count <= METADATA, 'workflow read bound')
                chunks.append(chunk)
            require(snapshot(before) == snapshot(os.fstat(descriptor))
                    and count == before.st_size, 'workflow concurrent file mutation')
            return b''.join(chunks)
        finally:
            os.close(descriptor)

    def create(self, area, name, raw):
        require(type(raw) is bytes and len(raw) <= METADATA, 'workflow artifact bound')
        require(self.bytes + len(raw) <= STORE_BYTES and self.files < STORE_FILES,
                'workflow storage admission')
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=self.areas[area])
        try:
            cursor = 0
            for _ in range(METADATA + 1):
                if cursor == len(raw):
                    break
                written = os.write(descriptor, raw[cursor:cursor + 65_536])
                require(written > 0, 'workflow short write')
                cursor += written
            require(cursor == len(raw), 'workflow write work bound')
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(self.areas[area])
        self.bytes += len(raw)
        self.files += 1
        require(self.read(area, name) == raw, 'workflow publication readback')

    def put(self, raw):
        pin = identity(raw)
        try:
            self.create('objects', pin['sha256'], raw)
        except FileExistsError:
            require(self.get(pin) == raw, 'workflow occupied artifact differs')
        return pin

    def get(self, pin):
        pin_checked(pin)
        require(pin['bytes'] <= METADATA, 'workflow object byte bound')
        raw = self.read('objects', pin['sha256'])
        require(identity(raw) == pin, 'workflow artifact pin differs')
        return raw

    def input(self, name, held):
        raw = self.read('inbox', identifier(name) + '.json')
        require(digest(raw) == hash_checked(held), 'workflow input identity differs')
        value = parse(raw)
        fields(value, ('schema', 'kind', 'payload'))
        require(value['schema'] == 'sentinel/workflow-input/1', 'workflow input version')
        return value

    def register(self, name, value, artifacts):
        """Host-only ingestion. Never exposed as a model-callable filesystem tool."""
        identifier(name)
        raw = canonical(value)
        fields(value, ('schema', 'kind', 'payload'))
        require(value['schema'] == 'sentinel/workflow-input/1', 'workflow input version')
        require(type(artifacts) is dict and len(artifacts) <= STORE_FILES,
                'workflow registration artifact count')
        total = len(raw)
        for key, artifact in artifacts.items():
            require(type(artifact) is bytes and len(artifact) <= METADATA
                    and digest(artifact) == hash_checked(key), 'workflow registration pin')
            total += len(artifact)
        require(self.bytes + total <= STORE_BYTES
                and self.files + len(artifacts) + 1 <= STORE_FILES,
                'workflow registration aggregate admission')
        for artifact in artifacts.values():
            self.put(artifact)
        self.create('inbox', name + '.json', raw)
        return identity(raw)

    def chain(self, run_id, held=None):
        prefix = identifier(run_id) + '.'
        names = []
        with os.scandir(self.areas['events']) as entries:
            for index, entry in enumerate(entries):
                require(index < STORE_FILES, 'workflow event scan bound')
                if entry.name.startswith(prefix):
                    names.append(entry.name)
                    require(len(names) <= EVENTS, 'workflow event count bound')
        result, previous = [], None
        for ordinal, name in enumerate(sorted(names)):
            require(name == prefix + '%06d.json' % ordinal, 'workflow missing/reordered event')
            raw = self.read('events', name)
            value = parse(raw)
            fields(value, ('schema', 'run_id', 'ordinal', 'previous', 'runtime', 'kind', 'payload'))
            require(value['schema'] == 'sentinel/workflow-event/1'
                    and value['run_id'] == run_id and value['ordinal'] == ordinal
                    and type(value['ordinal']) is int and value['previous'] == previous,
                    'workflow event chain differs')
            previous = identity(raw)
            result.append(value)
        if held is not None:
            require(previous is not None and previous['sha256'] == hash_checked(held),
                    'workflow latest external pin differs')
        return result, previous

    def event(self, run_id, events, previous, runtime, kind, payload):
        integer(len(events), 0, EVENTS - 1)
        value = {'schema': 'sentinel/workflow-event/1', 'run_id': identifier(run_id),
            'ordinal': len(events), 'previous': previous, 'runtime': runtime,
            'kind': kind, 'payload': payload}
        raw = canonical(value)
        self.create('events', run_id + '.%06d.json' % len(events), raw)
        return identity(raw)
