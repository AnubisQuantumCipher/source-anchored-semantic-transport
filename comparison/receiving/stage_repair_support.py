"""Bounded create-only staging support; inputs remain data, never code."""
import hashlib
import json
import os
from pathlib import Path
import resource
import stat

import private_staging as private

CAP = 1048576
RUN_CAP = 16777216


def need(value, reason):
    if type(value) is not bool or not value:
        raise ValueError(reason)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def raw_json(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def read(path, cap=CAP):
    need(isinstance(path, Path) and path.is_absolute() and '..' not in path.parts
         and len(path.parts) <= 65 and len(os.fsencode(path)) <= 4096, 'INPUT_PATH')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    descriptor = None
    try:
        for component in path.parts[1:-1]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= cap, 'INPUT_BOUND_TYPE')
        raw = bytearray()
        for unused in range(257):
            chunk = os.read(descriptor, min(16384, cap + 1 - len(raw)))
            if not chunk:
                after = os.fstat(descriptor)
                fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                need(all(getattr(before, key) == getattr(after, key) for key in fields)
                     and len(raw) == before.st_size, 'INPUT_CHANGED')
                return bytes(raw)
            raw.extend(chunk)
            need(len(raw) <= cap, 'INPUT_BOUND')
        raise ValueError('INPUT_READ_BOUND')
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def checked(item, cap=CAP):
    need(type(item) is dict and set(item) == {'path', 'bytes', 'sha256'}, 'PIN_SHAPE')
    need(type(item['bytes']) is int and 0 <= item['bytes'] <= cap and
         type(item['sha256']) is str and len(item['sha256']) == 64, 'PIN_TYPE')
    raw = read(Path(item['path']), cap)
    need(len(raw) == item['bytes'] and digest(raw) == item['sha256'], 'INPUT_PIN')
    return raw


def pairs(rows):
    result = {}
    for key, value in rows:
        need(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def invalid_number(unused):
    raise ValueError('NONINTEGER_JSON_NUMBER')


def load(raw):
    need(type(raw) is bytes and len(raw) <= CAP, 'JSON_BOUND')
    depth, quoted, escaped = 0, False, False
    for char in raw.decode('utf-8'):
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            need(depth <= 32, 'JSON_DEPTH')
        elif char in ']}':
            depth -= 1
            need(depth >= 0, 'JSON_STRUCTURE')
    need(depth == 0 and not quoted, 'TRUNCATED_JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_float=invalid_number,
                      parse_constant=invalid_number)


def anchor_descriptor(anchor):
    need(isinstance(anchor, Path) and anchor.is_absolute() and '..' not in anchor.parts
         and len(anchor.parts) <= 65 and len(os.fsencode(anchor)) <= 4096, 'ANCHOR_PATH')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in anchor.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            | os.O_CLOEXEC, dir_fd=parent)
            os.close(parent)
            parent = child
        private.private(parent)
        return parent
    except (OSError, ValueError):
        os.close(parent)
        raise


def new_run(anchor, name):
    need(private.parts(name) == [name], 'RUN_NAME')
    parent = anchor_descriptor(anchor)
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
    finally:
        os.close(parent)
    return private.chain(anchor, name, create=False)


def save(root, relative, raw, records):
    need(type(raw) is bytes and len(raw) <= CAP and len(records) < 128, 'OUTPUT_BOUND')
    need(sum(item['bytes'] for item in records) + len(raw) <= RUN_CAP, 'RUN_BYTE_BOUND')
    parts = private.parts(relative)
    need(len(parts) >= 2, 'PAYLOAD_PARENT_REQUIRED')
    directory = '/'.join(parts[:-1])
    private.chain(root, directory, create=False)
    result = private.write_new(root, directory, parts[-1], raw)
    records.append(dict(path=relative, **result))
    return result


def lower_limit(kind, ceiling):
    soft, hard = resource.getrlimit(kind)
    limits = [ceiling] + [value for value in (soft, hard) if value != resource.RLIM_INFINITY]
    chosen = min(limits)
    resource.setrlimit(kind, (chosen, chosen))
