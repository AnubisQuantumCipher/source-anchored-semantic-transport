"""Bounded filesystem/JSON boundary for the document profile; not a proof."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

MAX_SOURCE = 1_073_741_824
MAX_FRAMES = 16_384
FRAME_SOURCE = 65_536
FRAME_WIRE = 131_072
MAX_META = 8_388_608
MAX_ARCHIVE = 2_147_483_648
MAX_TEMP = 4_294_967_296
MAX_SPAN = 1_048_576
PROFILE = 'transport/document-zip/1'


class DocumentError(ValueError):
    """Explicit refusal; no recovered output is accepted."""


def need(condition, message):
    if not condition:
        raise DocumentError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def fields(value, names):
    need(type(value) is dict and set(value) == set(names), 'unknown or missing fields')


def integer(value, low, high):
    need(type(value) is int and low <= value <= high, 'integer outside document bounds')


def sha(value):
    need(type(value) is str and len(value) == 64 and
         all(c in '0123456789abcdef' for c in value), 'invalid SHA256')


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def no_float(_):
    raise DocumentError('noninteger JSON number is unsupported')


def loads(data):
    need(type(data) is bytes and len(data) <= MAX_META, 'JSON byte limit')
    quoted, escape, depth = False, False, 0
    for byte in data:
        if quoted:
            if escape:
                escape = False
            elif byte == 92:
                escape = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            need(depth <= 32, 'JSON depth limit')
        elif byte in (93, 125):
            depth -= 1
            need(depth >= 0, 'JSON nesting')
    try:
        return json.loads(data, object_pairs_hook=unique_pairs,
                          parse_float=no_float, parse_constant=no_float)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise DocumentError('invalid document JSON: ' + str(error)[:128]) from error


def open_regular(path, cap):
    fd = os.open(Path(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        need(stat.S_ISREG(info.st_mode) and 0 <= info.st_size <= cap,
             'regular file or file byte limit')
        return os.fdopen(fd, 'rb')
    except BaseException:
        os.close(fd)
        raise


def identity(stream):
    info = os.fstat(stream.fileno())
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def read_file(path, cap=MAX_META):
    with open_regular(path, cap) as stream:
        before = identity(stream)
        data = stream.read(cap + 1)
        need(identity(stream) == before and len(data) == before[2], 'file changed or short read')
        return data


def file_digest(path, cap=MAX_SOURCE):
    result, used = hashlib.sha256(), 0
    with open_regular(path, cap) as stream:
        before = identity(stream)
        for _ in range(cap // FRAME_SOURCE + 1):
            block = stream.read(FRAME_SOURCE)
            if not block:
                break
            used += len(block)
            need(used <= cap, 'hash input limit')
            result.update(block)
        need(used == before[2] and identity(stream) == before, 'hash source changed')
    return result.hexdigest(), used


def write_new(path, data):
    need(type(data) is bytes and len(data) <= MAX_META, 'metadata write limit')
    with Path(path).open('xb') as stream:
        need(stream.write(data) == len(data), 'short metadata write')
        stream.flush()
        os.fsync(stream.fileno())


def pin(data):
    return {'bytes': len(data), 'sha256': digest(data)}


def loaded_epoch(path, code):
    raw = read_file(path, MAX_META)
    candidate = compile(raw, path, 'exec', dont_inherit=True, optimize=sys.flags.optimize)
    need(candidate == code, 'loaded Python code does not match declared source')
    return digest(raw)


SOURCE_EPOCH = loaded_epoch(__file__, sys._getframe().f_code)
