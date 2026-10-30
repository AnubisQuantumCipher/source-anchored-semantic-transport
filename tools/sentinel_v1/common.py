"""Bounded canonical data primitives. None of these functions grants authority."""
import hashlib
import json
import re

JOB_BYTES = 65_536
CLAIMS = 64
PROBES = 256
ROUNDS = 8
LINKS = 16
EDGES = 512
NODES = 256
METADATA = 1_048_576
REGISTRY = 8_388_608


class SentinelError(ValueError):
    """A closed input, evidence or resource contract was not met."""


def require(condition, reason):
    if condition is not True:
        raise SentinelError(reason)


def fields(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'closed record fields')
    return value


def integer(value, low, high):
    require(type(value) is int and low <= value <= high, 'integer type or bound')
    return value


def label(value, cap=64):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:/-]*', value)
            is not None and len(value) <= cap, 'label type or bound')
    return value


def hash_checked(value):
    require(type(value) is str and re.fullmatch(r'[0-9a-f]{64}', value) is not None,
            'SHA256 spelling')
    return value


def digest(raw):
    require(type(raw) is bytes, 'immutable bytes required')
    return hashlib.sha256(raw).hexdigest()


def identity(raw):
    return {'sha256': digest(raw), 'bytes': len(raw)}


def pin_checked(value):
    fields(value, ('sha256', 'bytes'))
    hash_checked(value['sha256'])
    integer(value['bytes'], 0, REGISTRY)
    return value


def string_bytes(value, remaining):
    require(len(value) <= remaining, 'aggregate JSON byte bound')
    count = 2
    for char in value:
        point = ord(char)
        require(not 0xD800 <= point <= 0xDFFF, 'surrogate JSON string')
        if point in (34, 92, 8, 9, 10, 12, 13):
            count += 2
        elif point < 32:
            count += 6
        else:
            count += 1 if point < 128 else 2 if point < 2048 else 3 if point < 65536 else 4
        require(count <= remaining, 'aggregate JSON byte bound')
    return count


def push_children(item, depth, pending, visited):
    require(len(item) + len(pending) + visited <= 262_144, 'JSON node bound')
    try:
        entries = iter(item.items()) if type(item) is dict else iter(item)
        end = object()
        for _ in range(262_145):
            marker = next(entries, end)
            if marker is end:
                return
            if type(item) is dict:
                key, entry = marker
                require(type(key) is str, 'string JSON keys required')
                pending.extend(((key, depth + 1), (entry, depth + 1)))
            else:
                pending.append((marker, depth + 1))
            require(len(pending) + visited <= 262_144, 'JSON node bound')
    except StopIteration:
        return
    except RuntimeError as error:
        raise SentinelError('JSON container mutated during checking') from error
    raise SentinelError('JSON node bound')


def tree_checked(value):
    pending, visited, total = [(value, 0)], 0, 0
    for _ in range(262_144):
        if not pending:
            return
        item, depth = pending.pop()
        visited += 1
        require(depth <= 16, 'JSON nesting bound')
        if type(item) in (dict, list):
            require(depth < 16, 'JSON container nesting bound')
            total += 2 + max(0, len(item) - 1) + (len(item) if type(item) is dict else 0)
            require(total <= METADATA, 'aggregate JSON byte bound')
            push_children(item, depth, pending, visited)
        elif type(item) is str:
            total += string_bytes(item, METADATA - total)
        elif type(item) is int:
            integer(item, -(2 ** 63), 2 ** 63 - 1)
            total += len(str(item))
        else:
            require(item is None or type(item) is bool, 'unsupported JSON value')
            total += 4 if item is None or item is True else 5
        require(total <= METADATA, 'aggregate JSON byte bound')
        require(len(pending) + visited <= 262_144, 'JSON node bound')
    raise SentinelError('JSON node bound')


def scalar_size(item, remaining):
    if type(item) is str:
        return string_bytes(item, remaining)
    if type(item) is int:
        integer(item, -(2 ** 63), 2 ** 63 - 1)
        return len(str(item))
    require(item is None or type(item) is bool, 'unsupported JSON value')
    return 4 if item is None or item is True else 5


def store_copy(item, target, key, depth, stack, budget):
    require(depth <= 16 and budget[1] < 262_144, 'JSON depth or node bound')
    budget[1] += 1
    if type(item) in (dict, list):
        require(depth < 16, 'JSON container nesting bound')
        require(len(item) <= 262_144 - budget[1], 'JSON node bound')
        budget[0] += 2
        target[key] = {} if type(item) is dict else []
        stack.append((iter(item.items()) if type(item) is dict else iter(item), target[key], depth))
    else:
        budget[0] += scalar_size(item, METADATA - budget[0])
        target[key] = item
    require(budget[0] <= METADATA, 'aggregate JSON byte bound')


def private_tree(value):
    holder, stack, budget, end = {}, [], [0, 0], object()
    store_copy(value, holder, 'value', 0, stack, budget)
    try:
        for _ in range(524_289):
            if not stack:
                return holder['value']
            iterator, target, depth = stack[-1]
            entry = next(iterator, end)
            if entry is end:
                stack.pop()
                continue
            budget[0] += bool(target)
            if type(target) is dict:
                key, item = entry
                require(type(key) is str and key not in target, 'JSON key type or duplication')
                budget[0] += 1 + string_bytes(key, METADATA - budget[0])
                budget[1] += 1
            else:
                key, item = len(target), entry
                target.append(None)
            require(budget[0] <= METADATA, 'aggregate JSON byte bound')
            store_copy(item, target, key, depth + 1, stack, budget)
    except RuntimeError as error:
        raise SentinelError('JSON container mutated during snapshot') from error
    raise SentinelError('JSON work bound')


def canonical(value):
    snapshot = private_tree(value)
    tree_checked(snapshot)
    raw = json.dumps(snapshot, ensure_ascii=False, sort_keys=True,
                     separators=(',', ':'), allow_nan=False).encode('utf-8')
    require(len(raw) <= METADATA, 'canonical metadata byte bound')
    return raw


def depth_checked(raw):
    depth, quoted, escaped = 0, False, False
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
            require(depth <= 16, 'JSON nesting bound')
        elif byte in (93, 125):
            depth -= 1
            require(depth >= 0, 'unbalanced JSON')
    require(depth == 0 and not quoted, 'unterminated JSON')


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def no_number(_value):
    raise SentinelError('noninteger JSON number refused')


def parse(raw, cap=METADATA):
    integer(cap, 1, METADATA)
    require(type(raw) is bytes and 0 < len(raw) <= cap <= METADATA, 'JSON byte bound')
    depth_checked(raw)
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_pairs,
                           parse_float=no_number, parse_constant=no_number)
        require(canonical(value) == raw, 'noncanonical JSON')
        return value
    except SentinelError:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise SentinelError('invalid canonical JSON') from error


def capture_registry(registry):
    require(type(registry) is dict and len(registry) <= 256, 'registry entry bound')
    snapshot, total = {}, 0
    try:
        entries = iter(registry.items())
        for index in range(257):
            pair = next(entries, None)
            if pair is None:
                break
            require(index < 256, 'registry entry bound')
            key, raw = pair
            hash_checked(key)
            require(type(raw) is bytes and len(raw) <= METADATA, 'registry immutable entry bound')
            require(digest(raw) == key, 'registry artifact identity mismatch')
            total += len(raw)
            require(total <= REGISTRY, 'registry aggregate byte bound')
            snapshot[key] = raw
    except RuntimeError as error:
        raise SentinelError('registry mutated during snapshot') from error
    return snapshot


def registry_snapshot(registry, held):
    hash_checked(held)
    snapshot = capture_registry(registry)
    require(digest(canonical({key: identity(raw) for key, raw in snapshot.items()})) == held,
            'registry root mismatch')
    return snapshot


def held_record(raw, held, cap=METADATA):
    integer(cap, 1, METADATA)
    require(type(raw) is bytes and 0 < len(raw) <= cap, 'held record byte bound')
    require(digest(raw) == hash_checked(held), 'held record identity mismatch')
    return parse(raw, cap)
