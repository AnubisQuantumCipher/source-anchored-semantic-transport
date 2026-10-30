"""Bounded, closed JSON input for informational QUORUM policy version 2."""

import hashlib
import json
import os
import re
import stat

MAX_INPUT = 65536
MAX_OUTPUT = 32768
MAX_DEPTH = 12
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
IDENTIFIER = re.compile(r'[A-Za-z0-9_.:-]+\Z')


class Refusal(ValueError):
    """A complete refusal; never a partial threshold result."""


def need(condition, code):
    if not condition:
        raise Refusal(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def fields(value, names):
    need(type(value) is dict, 'CLOSED_FIELDS')
    need(all(type(key) is str for key in value), 'CLOSED_KEY_TYPE')
    need(set(value) == set(names), 'CLOSED_FIELDS')


def text(value, cap):
    need(type(value) is str, 'TEXT_TYPE')
    try:
        need(len(value.encode('utf-8')) <= cap, 'TEXT_BOUND')
    except UnicodeError as error:
        raise Refusal('TEXT_ENCODING') from error


def identifier(value, cap=32):
    text(value, cap)
    need(IDENTIFIER.fullmatch(value) is not None, 'IDENTIFIER')


def digest(value):
    text(value, 64)
    need(DIGEST.fullmatch(value) is not None, 'DIGEST')


def integer(value, minimum, maximum):
    need(type(value) is int and minimum <= value <= maximum, 'INTEGER_BOUND')


def array(value, minimum, maximum):
    need(type(value) is list and minimum <= len(value) <= maximum, 'ARRAY_BOUND')


def _depth(raw):
    quoted, escaped, depth = False, False, 0
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            need(depth <= MAX_DEPTH, 'JSON_DEPTH')
        elif byte in (93, 125):
            depth -= 1
            need(depth >= 0, 'JSON_DEPTH')
    need(not quoted and depth == 0, 'JSON_DEPTH')


def _pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def _number(token):
    need(len(token) <= 20, 'INTEGER_TOKEN_BOUND')
    return int(token)


def _noninteger(token):
    raise Refusal('NONINTEGER_TOKEN')


def parse(raw, cap=MAX_INPUT):
    need(type(raw) is bytes and 0 < len(raw) <= cap, 'INPUT_BYTE_BOUND')
    _depth(raw)
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_int=_number, parse_float=_noninteger,
                           parse_constant=_noninteger)
        canonical(value)
        return value
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise Refusal('INVALID_JSON') from error


def read_regular(path, cap=MAX_INPUT):
    """Bounded final-component no-follow read; caller owns the parent path."""
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode), 'NOT_REGULAR_FILE')
        need(0 < before.st_size <= cap, 'FILE_BYTE_BOUND')
        with os.fdopen(descriptor, 'rb', closefd=False) as stream:
            raw = stream.read(cap + 1)
        after = os.fstat(descriptor)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        need(identity(before) == identity(after), 'FILE_CHANGED')
        need(len(raw) == before.st_size, 'FILE_LENGTH')
        return raw
    finally:
        os.close(descriptor)


def pin(raw):
    return {'sha256': sha(raw), 'bytes': len(raw)}
