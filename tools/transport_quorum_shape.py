"""Iterative checker for one pinned QUORUM Body schema, not a schema service."""

import hashlib
import os
from pathlib import Path
import re
import stat

from transport_quorum_input import InputError
from transport_schema import canonical, json_value
from transport_wire import TransportError

SCHEMA_SHA256 = 'b6c7cafc1d4f1703188f7bdcb2150316feadc6b870eda9495ee146e2f429f8aa'
SCHEMA_PATH = Path(__file__).with_name('transport_quorum_body.schema.json')
KEYWORDS = frozenset(('$defs', '$id', '$schema', '$ref', 'description', 'title',
    'type', 'properties', 'required', 'additionalProperties', 'items', 'minItems',
    'maxItems', 'uniqueItems', 'minLength', 'maxLength', 'minimum', 'maximum',
    'pattern', 'enum', 'const', 'oneOf', 'allOf', 'contains', 'minContains', 'maxContains'))
PATTERNS = {text: re.compile(text) for text in (
    r'^[A-Za-z][A-Za-z0-9_.:-]{0,31}$', r'^[0-9a-f]{64}$',
    r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$')}
TYPES = {'object': dict, 'array': list, 'string': str, 'integer': int,
         'boolean': bool, 'null': type(None)}
KINDS = ('SOURCE_MEMBERSHIP_V1', 'Q_DECLARATION_IDENTITY_V1',
         'DECLARED_DEPENDENCY_IMPACT_V1', 'RECORDED_STANCE_COUNTS_V1')
RECORD_ARRAYS = ('sources', 'rules', 'tasks', 'claims', 'selectors', 'dependencies',
    'input_manifests', 'blobs', 'provenance', 'run_evidence', 'readings',
    'challenges', 'reading_withdrawals', 'updates', 'history')


class Budget:
    """Per-invocation counters; quotas are charged before work."""

    def __init__(self, stage: str) -> None:
        self.steps = 1048576
        self.bytes = 1048576
        self.stage = stage

    def step(self, count: int = 1) -> None:
        if count < 0 or count > self.steps:
            raise InputError('INPUT_WORK_BOUND', self.stage)
        self.steps -= count

    def byte(self, count: int) -> None:
        if count < 0 or count > self.bytes:
            raise InputError('INPUT_WORK_BOUND', self.stage)
        self.bytes -= count


def _schema_children(node: dict) -> list[dict]:
    children = list(node.get('$defs', {}).values())
    children.extend(node.get('properties', {}).values())
    children.extend(node.get('oneOf', ()))
    children.extend(node.get('allOf', ()))
    for key in ('items', 'contains'):
        if key in node:
            children.append(node[key])
    return children


def _schema_inventory(schema: dict, budget: Budget) -> None:
    pending, count = [schema], 0
    for _ in range(519):
        if not pending:
            return
        budget.step()
        node = pending.pop()
        count += 1
        if type(node) is not dict or not set(node) <= KEYWORDS:
            raise InputError('INPUT_SCHEMA_UNSUPPORTED', 'BOOTSTRAP')
        if 'pattern' in node and node['pattern'] not in PATTERNS:
            raise InputError('INPUT_SCHEMA_UNSUPPORTED', 'BOOTSTRAP')
        if '$ref' in node:
            ref = node['$ref']
            if not ref.startswith('#/$defs/') or ref[8:] not in schema['$defs']:
                raise InputError('INPUT_SCHEMA_UNSUPPORTED', 'BOOTSTRAP')
        children = _schema_children(node)
        budget.step(len(children))
        if len(children) + count + len(pending) > 519:
            raise InputError('INPUT_SCHEMA_UNSUPPORTED', 'BOOTSTRAP')
        pending.extend(children)
    if pending:
        raise InputError('INPUT_SCHEMA_UNSUPPORTED', 'BOOTSTRAP')


def _schema_acyclic(schema: dict, budget: Budget) -> None:
    # Fixed pinned definitions; Kahn elimination admits no recursive reference.
    definitions, dependencies = schema['$defs'], {}
    for name, root in definitions.items():
        pending, refs = [root], set()
        for _ in range(519):
            if not pending:
                break
            budget.step()
            node = pending.pop()
            if '$ref' in node:
                refs.add(node['$ref'][8:])
            pending.extend(_schema_children(node))
        if pending:
            raise InputError('INPUT_SCHEMA_UNSUPPORTED', 'BOOTSTRAP')
        dependencies[name] = refs
    done = set()
    for _ in range(49):
        for name, refs in dependencies.items():
            budget.step(len(refs) + 1)
            if refs <= done:
                done.add(name)
    if len(done) != len(definitions):
        raise InputError('INPUT_SCHEMA_UNSUPPORTED', 'BOOTSTRAP')


def load_schema() -> dict:
    try:
        descriptor = os.open(SCHEMA_PATH, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 32768:
                raise OSError('schema must be a bounded regular file')
            with os.fdopen(descriptor, 'rb', closefd=False) as stream:
                raw = stream.read(32769)
        finally:
            os.close(descriptor)
        if len(raw) > 32768 or hashlib.sha256(raw).hexdigest() != SCHEMA_SHA256:
            raise OSError('schema identity mismatch')
        schema = json_value(raw, 32768)
    except (OSError, TransportError) as error:
        raise InputError('INPUT_SCHEMA_UNSUPPORTED', 'BOOTSTRAP') from error
    budget = Budget('BOOTSTRAP')
    _schema_inventory(schema, budget)
    _schema_acyclic(schema, budget)
    return schema


def _text_limit(node: dict, value: str, budget: Budget) -> None:
    if node.get('pattern') == next(reversed(PATTERNS)):
        return  # Encoded base64; decoded-byte checks belong to W04.
    limit = 1024 if node.get('maxLength') in (64, 1024) else 4096
    if node.get('pattern') == next(iter(PATTERNS)):
        limit = 32
    size = 0
    for character in value:
        budget.step()
        size += _utf8_width(ord(character))
        if size > limit:
            raise InputError('INPUT_BYTE_FIELD_BOUND', 'BOUNDS')


def _limits(node: dict, value: object, budget: Budget) -> None:
    if type(value) is list and 'maxItems' in node:
        if len(value) > node['maxItems']:
            raise InputError('INPUT_RECORD_BOUND', 'BOUNDS')
    if type(value) is str and (node.get('type') == 'string' or
            type(node.get('const')) is str or 'enum' in node):
        _text_limit(node, value, budget)


def _scalar_equal(left: object, right: object) -> bool:
    return type(left) is type(right) and type(left) in (str, int, bool, type(None)) and left == right


def _utf8_width(point: int) -> int:
    if point <= 127:
        return 1
    if point <= 2047:
        return 2
    if point <= 65535:
        return 3
    return 4


def _string_size(value: str, budget: Budget) -> int:
    budget.byte(2)
    size = 2
    for character in value:
        budget.step()
        point = ord(character)
        if character in '\"\\\b\t\n\f\r':
            width = 2
        elif point < 32:
            width = 6
        else:
            width = _utf8_width(point)
        budget.byte(width)
        size += width
    return size


def _integer_size(value: int) -> int:
    for digits in range(1, 21):
        value //= 10
        if value == 0:
            return digits
    raise InputError('INPUT_INTEGER_BOUND', 'SCHEMA')


def _canonical_size(value: object, budget: Budget) -> int:
    total, stack = 0, [iter((value,))]
    for _ in range(65536):
        if not stack:
            return total
        budget.step()
        item = next(stack[-1], StopIteration)
        size = 0
        if item is StopIteration:
            stack.pop()
        elif type(item) is str:
            total += _string_size(item, budget)
        elif type(item) in (dict, list):
            size = 2 + max(0, len(item) - 1)
            if type(item) is dict:
                size += len(item)
                stack.append(iter(item.items()))
            else:
                stack.append(iter(item))
        elif type(item) is tuple:
            stack.append(iter(item))
        elif type(item) is int:
            size = _integer_size(item)
        elif type(item) is bool:
            size = 4 if item else 5
        elif item is None:
            size = 4
        else:
            raise InputError('INPUT_CLOSED_SCHEMA', budget.stage)
        budget.byte(size)
        total += size
        if len(stack) > 128 or total > 131072:
            raise InputError('INPUT_WORK_BOUND', budget.stage)
    raise InputError('INPUT_WORK_BOUND', budget.stage)


def _unique(values: list, budget: Budget) -> bool:
    keys, scratch = set(), 0
    for item in values:
        budget.step()
        size = _canonical_size(item, budget)
        if scratch + size > 131072:
            raise InputError('INPUT_WORK_BOUND', budget.stage)
        budget.byte(size)
        key = canonical(item)
        if len(key) != size:
            raise InputError('INPUT_WORK_BOUND', budget.stage)
        budget.step()
        if key in keys:
            return False
        keys.add(key)
        scratch += size
    return True


def _object(node: dict, value: dict, budget: Budget) -> bool:
    properties = node.get('properties', {})
    for key in node.get('required', ()):
        budget.step()
        if key not in value:
            return False
    if node.get('additionalProperties') is False:
        for key in value:
            budget.step()
            if key not in properties:
                return False
    return True


def _basic(node: dict, value: object, budget: Budget) -> bool:
    budget.step()
    if 'type' in node and type(value) is not TYPES[node['type']]:
        return False
    if 'const' in node and not _scalar_equal(value, node['const']):
        return False
    if 'enum' in node:
        budget.step(len(node['enum']))
        if not any(_scalar_equal(value, item) for item in node['enum']):
            return False
    if type(value) is dict and not _object(node, value, budget):
        return False
    if type(value) is str:
        if not node.get('minLength', 0) <= len(value) <= node.get('maxLength', 65536):
            return False
        if 'pattern' in node:
            budget.step(len(value))
            if PATTERNS[node['pattern']].search(value) is None:
                return False
    if type(value) is int:
        if not node.get('minimum', 0) <= value <= node.get('maximum', 10 ** 20):
            return False
    if type(value) is list:
        if not node.get('minItems', 0) <= len(value) <= node.get('maxItems', 65536):
            return False
        if node.get('uniqueItems') and not _unique(value, budget):
            return False
    if 'contains' in node:
        if type(value) is not list:
            return True
        kind = node['contains']['properties']['kind']['const']
        count = 0
        for item in value:
            budget.step()
            if type(item) is dict and item.get('kind') == kind:
                count += 1
        if count != 1:
            return False
    return True


def _children(node: dict, value: object, definitions: dict, budget: Budget):
    if '$ref' in node:
        budget.step()
        yield 'all', definitions[node['$ref'][8:]], value
    for key in ('allOf', 'oneOf'):
        for child in node.get(key, ()):
            budget.step()
            yield key, child, value
    if type(value) is dict:
        for key, child in node.get('properties', {}).items():
            budget.step()
            if key in value:
                yield 'all', child, value[key]
    if type(value) is list and 'items' in node:
        for item in value:
            budget.step()
            yield 'all', node['items'], item


class Frame:
    """One bounded schema continuation; only one active child at any time."""

    def __init__(self, node: dict, value: object, definitions: dict,
                 budget: Budget, bounds: bool) -> None:
        if bounds:
            _limits(node, value, budget)
        self.ok = True if bounds else _basic(node, value, budget)
        self.children = _children(node, value, definitions, budget)
        self.has_one = 'oneOf' in node and not bounds
        self.ones = 0
        self.waiting = 'all'


def _evaluate_stack(stack: list[Frame], definitions: dict,
                    budget: Budget, bounds: bool) -> bool:
    for _ in range(1048576):
        budget.step()
        frame = stack[-1]
        child = next(frame.children, None) if frame.ok else None
        if child is not None:
            if len(stack) >= 128:
                raise InputError('INPUT_WORK_BOUND', budget.stage)
            mode, node, item = child
            frame.waiting = 'all' if bounds else mode
            stack.append(Frame(node, item, definitions, budget, bounds))
        else:
            result = frame.ok and (not frame.has_one or frame.ones == 1)
            stack.pop()
            if not stack:
                return result
            parent = stack[-1]
            if parent.waiting == 'oneOf':
                parent.ones += int(result)
            else:
                parent.ok = parent.ok and result
    raise InputError('INPUT_WORK_BOUND', budget.stage)


def _evaluate(value: object, schema: dict, budget: Budget, bounds: bool) -> bool:
    definitions = schema['$defs']
    frame = Frame(definitions['ReplayBody'], value, definitions, budget, bounds)
    return _evaluate_stack([frame], definitions, budget, bounds)


def _declaration_shape(value: object, schema: dict) -> None:
    """Fixed private declaration root; schema comes only from the owned bundle."""
    definitions = schema['$defs']
    budget = Budget('DECLARATION_INPUT')
    frame = Frame(definitions['DeclarationSource'], value, definitions, budget, True)
    _evaluate_stack([frame], definitions, budget, True)
    frame = Frame(definitions['DeclarationSource'], value, definitions, budget, False)
    if not _evaluate_stack([frame], definitions, budget, False):
        raise InputError('INPUT_CLOSED_SCHEMA', 'DECLARATION_INPUT')


def _record_count(body: object) -> None:
    if type(body) is not dict or type(body.get('registry')) is not dict:
        return  # Closed-shape validation must reject these later.
    seats = body['registry'].get('seats')
    if type(seats) is not list:
        return
    total = 2 + len(seats)
    for key in RECORD_ARRAYS:
        if type(body.get(key)) is not list:
            return
        total += len(body[key])
    for manifest in body['input_manifests']:
        if type(manifest) is not dict or type(manifest.get('registry_snapshot')) is not dict:
            return
        seats = manifest['registry_snapshot'].get('seats')
        if type(seats) is not list:
            return
        total += 1 + len(seats)
    if total > 96:
        raise InputError('INPUT_RECORD_BOUND', 'BOUNDS')


def _version(record: object) -> None:
    if type(record) is dict and type(record.get('version')) is str:
        if record['version'] != 'V1':
            raise InputError('INPUT_UNADMITTED', 'SCHEMA')


def _admission(body: object) -> None:
    if type(body) is not dict:
        return
    if type(body.get('schema')) is str and body['schema'] != 'quorum/replay-body/1':
        raise InputError('INPUT_UNADMITTED', 'SCHEMA')
    for key in ('registry', 'policy'):
        _version(body.get(key))
    for key in ('rules', 'tasks'):
        if type(body.get(key)) is list:
            for record in body[key]:
                _version(record)
    if type(body.get('input_manifests')) is list:
        for manifest in body['input_manifests']:
            if type(manifest) is dict:
                _version(manifest.get('registry_snapshot'))
    rules = body.get('rules')
    if type(rules) is list:
        kinds = []
        for rule in rules:
            if type(rule) is not dict or type(rule.get('kind')) is not str:
                return  # A malformed kind must be a closed-shape refusal.
            kinds.append(rule['kind'])
        if len(kinds) != 4 or set(kinds) != set(KINDS):
            raise InputError('INPUT_UNADMITTED', 'SCHEMA')


def check_shape(value: object, schema: dict) -> None:
    """Private post-parser stage; callers supply only this module's pinned schema."""
    budget = Budget('BOUNDS')
    _evaluate(value, schema, budget, True)
    _record_count(value)
    budget.stage = 'SCHEMA'
    _admission(value)
    if not _evaluate(value, schema, budget, False):
        raise InputError('INPUT_CLOSED_SCHEMA', 'SCHEMA')
