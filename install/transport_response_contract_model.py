"""Small declarative response contracts; bounded structure only, never semantics.

Flat nodes reference only earlier nodes. Every object field is required and
closed. Descriptions are inert documentation. No source approval or executable
policy follows from compiling a contract or accepting a response shape.
"""

import re

from transport_install_layout import checked_json
from transport_install_support import require

SCHEMA = 'transport/response-contract/1'
CONTRACT_BYTES, CANDIDATE_BYTES = 65536, 32768
MAX_NODES, MAX_DEPTH, MAX_VALUES = 64, 8, 1024
NODE_ID = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
FIELD = re.compile(r'[a-z][a-z0-9_]{0,63}\Z')
COMMON = {'id', 'type', 'description'}


def safe_json(raw, cap, values):
    require(type(raw) is bytes and 0 < len(raw) <= cap, 'JSON byte bound')
    text = raw.decode('utf-8', errors='strict')
    require(not text.startswith('\ufeff') and '\x00' not in text, 'UTF-8 JSON without BOM or literal NUL required')
    value = checked_json(raw)
    pending, seen = [value], 0
    for _ in range(values):
        if not pending:
            break
        item = pending.pop()
        seen += 1
        if type(item) is dict:
            require(len(item) <= 128 and all(len(key.encode('utf-8')) <= 128 for key in item), 'JSON object bound')
            pending.extend(item.values())
        elif type(item) is list:
            require(len(item) <= 128, 'JSON array bound')
            pending.extend(item)
        elif type(item) is str:
            require(len(item.encode('utf-8')) <= 4096, 'JSON string byte bound')
        elif type(item) is int:
            require(-(2 ** 63) <= item < 2 ** 63, 'JSON integer range')
        else:
            require(item is None or type(item) is bool, 'only finite safe literals; floating point unsupported')
        require(seen + len(pending) <= values, 'JSON value count bound')
    require(not pending, 'JSON traversal bound')
    return value


def fields(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'unsupported/missing contract keywords')


def integer(value, minimum, maximum, label):
    require(type(value) is int and minimum <= value <= maximum, label + ' requires bounded integer')
    return value


def reference(value, names):
    require(type(value) is str and value in names, 'node reference must name an earlier node')
    return names[value]


def string_node(node):
    allowed = COMMON | {'min_bytes', 'max_bytes'} | ({'enum'} if 'enum' in node else set())
    fields(node, allowed)
    low = integer(node['min_bytes'], 0, 4096, 'string minimum')
    high = integer(node['max_bytes'], low, 4096, 'string maximum')
    if 'enum' in node:
        values = node['enum']
        require(type(values) is list and 1 <= len(values) <= 64, 'string enum count bound')
        require(all(type(value) is str and low <= len(value.encode('utf-8')) <= high for value in values), 'string enum value bound')
        require(len(set(values)) == len(values), 'duplicate string enum')
    return dict(min_bytes=low, max_bytes=high, enum=tuple(node['enum']) if 'enum' in node else None), ()


def object_node(node, names):
    fields(node, COMMON | {'fields'})
    entries = node['fields']
    require(type(entries) is dict and len(entries) <= 32, 'object field count bound')
    require(all(type(name) is str and FIELD.fullmatch(name) is not None for name in entries), 'object field name')
    values = tuple((name, reference(value, names)) for name, value in entries.items())
    return dict(fields=values), tuple(value for _, value in values)


def array_node(node, names, compiled):
    fields(node, COMMON | {'items', 'min_items', 'max_items', 'unique', 'unique_by'})
    low = integer(node['min_items'], 0, 64, 'array minimum')
    high = integer(node['max_items'], low, 64, 'array maximum')
    item = reference(node['items'], names)
    require(type(node['unique']) is bool, 'array unique requires boolean')
    key = node['unique_by']
    if key is not None:
        require(type(key) is str and FIELD.fullmatch(key) is not None and node['unique'] is True, 'unique ID field declaration')
        require(compiled[item]['type'] == 'object', 'unique_by requires object items')
        entries = dict(compiled[item]['fields'])
        require(key in entries and compiled[entries[key]]['type'] == 'string'
                and compiled[entries[key]]['min_bytes'] >= 1, 'unique_by requires a nonempty string field')
    elif node['unique']:
        require(compiled[item]['type'] in ('string', 'integer', 'boolean', 'null'), 'value uniqueness requires scalar items')
    return dict(items=item, min_items=low, max_items=high, unique=node['unique'], unique_by=key), (item,)


def compile_node(node, names, compiled):
    require(type(node) is dict and COMMON.issubset(node), 'contract node shape')
    name, kind = node['id'], node['type']
    require(type(name) is str and NODE_ID.fullmatch(name) is not None and name not in names, 'node ID invalid/duplicate')
    require(type(kind) is str, 'node type requires string')
    description = node['description']
    require(type(description) is str and 1 <= len(description.encode('utf-8')) <= 1024, 'node description bound')
    if kind == 'string':
        attributes, refs = string_node(node)
    elif kind == 'object':
        attributes, refs = object_node(node, names)
    elif kind == 'array':
        attributes, refs = array_node(node, names, compiled)
    elif kind == 'integer':
        fields(node, COMMON | {'min', 'max'})
        low = integer(node['min'], -(2 ** 63), 2 ** 63 - 1, 'integer minimum')
        attributes, refs = dict(min=low, max=integer(node['max'], low, 2 ** 63 - 1, 'integer maximum')), ()
    else:
        require(kind in ('boolean', 'null'), 'unsupported field type')
        fields(node, COMMON)
        attributes, refs = {}, ()
    depth = 1 + max((compiled[index]['depth'] for index in refs), default=0)
    require(depth <= MAX_DEPTH, 'contract value depth bound')
    return dict(id=name, type=kind, description=description, depth=depth, refs=refs, **attributes)


def compile_contract(raw):
    value = safe_json(raw, CONTRACT_BYTES, 4096)
    fields(value, ('schema', 'description', 'root', 'nodes'))
    require(value['schema'] == SCHEMA, 'unsupported response-contract schema')
    require(type(value['description']) is str and 1 <= len(value['description'].encode('utf-8')) <= 1024, 'contract description bound')
    entries = value['nodes']
    require(type(entries) is list and 1 <= len(entries) <= MAX_NODES, 'instruction node count bound')
    names, compiled = {}, []
    for node in entries:
        result = compile_node(node, names, compiled)
        names[result['id']] = len(compiled)
        compiled.append(result)
    root = reference(value['root'], names)
    require(root == len(compiled) - 1 and compiled[root]['type'] == 'object', 'root must be final object node')
    pending, used = [root], set()
    for _ in range(MAX_NODES * 33):
        if not pending:
            break
        index = pending.pop()
        if index not in used:
            used.add(index)
            pending.extend(compiled[index]['refs'])
    require(not pending and len(used) == len(compiled), 'unreachable nodes or traversal bound')
    return tuple(compiled), root
