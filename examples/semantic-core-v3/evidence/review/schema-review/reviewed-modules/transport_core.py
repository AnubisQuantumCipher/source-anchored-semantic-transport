"""Closed grammar 3 validation and STC3 serialization; no Python denotation.

The supplied finite model is data, not the world. Legacy grammars are untouched.
"""
import re
import struct

from transport_schema import canonical, fields, json_value, require, sha

GRAMMAR = 'transport/meaning/3'
PLAN = 'transport/core-plan/3'
MODEL = 'transport/finite-model/1'
MAX_NODES = 256
MAX_SYMBOLS = 64
MAX_TUPLES = 256
IDENT = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,47}\Z', re.ASCII)
TRUTHS = ('UNRESOLVED', 'KNOWN_FALSE', 'KNOWN_TRUE')
OPS = ('pred', 'not', 'and', 'if', 'all', 'some', 'must')
DEFINITIONS = {
    'pred': 'Fact: exact ordered tuple lookup. Missing, conflicting, or explicitly unresolved reports yield Unresolved.',
    'not': 'Fact to Fact: strong Kleene negation; Unresolved remains Unresolved.',
    'and': 'Fact x Fact to Fact: False if either False; True if both True; otherwise Unresolved.',
    'if': 'Fact x Fact to Fact: strong Kleene material implication; False only for True then False.',
    'all': 'Unary predicate and explicit finite domain to Fact: False if any False, True if all True, otherwise Unresolved. Empty domain True.',
    'some': 'Unary predicate and explicit finite domain to Fact: True if any True, False if all False, otherwise Unresolved. Empty domain False.',
    'must': 'Fact to Norm: True maps Satisfied, False Violated, Unresolved Unknown. Norm Truth always Unresolved; no authority.',
}
OPERATORS = {'schema': 'transport/core-operators/3', 'entries': DEFINITIONS}


def identifier(value):
    require(type(value) is str and IDENT.fullmatch(value) is not None, 'CORE_IDENTIFIER')
    return value


def records(value, cap, minimum=0):
    require(type(value) is list and minimum <= len(value) <= cap, 'CORE_COUNT')
    return value


def binding(value, source):
    require(type(value) is dict, 'CORE_BINDING')
    if value.get('kind') == 'name':
        fields(value, {'kind', 'name'})
        name = value['name']
        require(type(name) is str and 1 <= len(name.encode('utf-8')) <= 255,
                'CORE_BOUND_NAME')
        require(all(c.isprintable() for c in name), 'CORE_BOUND_NAME_CONTROL')
        return
    fields(value, {'kind', 'span', 'quote'})
    require(value['kind'] == 'span', 'CORE_BINDING_KIND')
    pair = records(value['span'], 2, 2)
    require(all(type(i) is int for i in pair), 'CORE_SPAN_INTEGER')
    begin, end = pair
    require(0 <= begin < end <= len(source), 'CORE_SPAN_RANGE')
    require(type(value['quote']) is str and 1 <= len(value['quote'].encode('utf-8')) <= 255,
            'CORE_QUOTE_BOUND')
    require(source[begin:end] == value['quote'].encode('utf-8'), 'CORE_QUOTE_MISMATCH')
    source[:begin].decode('utf-8')
    source[:end].decode('utf-8')


def symbols(value, source):
    result = {}
    for item in records(value, MAX_SYMBOLS, 1):
        require(type(item) is dict, 'CORE_SYMBOL')
        kind = item.get('kind')
        require(type(kind) is str and kind in ('term', 'predicate', 'domain'), 'CORE_SYMBOL_KIND')
        fields(item, {'id', 'kind', 'binding'} | ({'arity'} if kind == 'predicate' else
                                               {'members'} if kind == 'domain' else set()))
        name = identifier(item['id'])
        require(name not in result, 'CORE_DUPLICATE_SYMBOL')
        binding(item['binding'], source)
        if kind == 'predicate':
            require(type(item['arity']) is int and 0 <= item['arity'] <= 2, 'CORE_ARITY')
        result[name] = item
    for item in value:
        if item['kind'] == 'domain':
            members = records(item['members'], MAX_SYMBOLS)
            require(all(identifier(n) in result and result[n]['kind'] == 'term' for n in members),
                    'CORE_DOMAIN_MEMBER')
            require(len(set(members)) == len(members), 'CORE_DUPLICATE_MEMBER')
    return result


def predicate(name, terms, declared):
    require(identifier(name) in declared and declared[name]['kind'] == 'predicate',
            'CORE_PREDICATE')
    records(terms, 2)
    require(len(terms) == declared[name]['arity'], 'CORE_PREDICATE_ARITY')
    require(all(identifier(t) in declared and declared[t]['kind'] == 'term' for t in terms),
            'CORE_PREDICATE_TERM')


def node_kind(node, kinds, declared):
    require(type(node) is dict and type(node.get('op')) is str, 'CORE_NODE')
    op = node['op']
    require(op in OPS, 'CORE_UNSUPPORTED_OPERATOR')
    if op == 'pred':
        fields(node, {'op', 'predicate', 'terms'})
        predicate(node['predicate'], node['terms'], declared)
        return 'FACT'
    if op in ('all', 'some'):
        fields(node, {'op', 'predicate', 'domain'})
        p, d = identifier(node['predicate']), identifier(node['domain'])
        require(p in declared and declared[p]['kind'] == 'predicate'
                and declared[p]['arity'] == 1, 'CORE_QUANTIFIER_PREDICATE')
        require(d in declared and declared[d]['kind'] == 'domain', 'CORE_QUANTIFIER_DOMAIN')
        return 'FACT'
    fields(node, {'op', 'args'})
    count = 1 if op in ('not', 'must') else 2
    args = records(node['args'], count, count)
    require(all(type(a) is int and 0 <= a < len(kinds) for a in args), 'CORE_NODE_ORDER')
    require(all(kinds[a] == 'FACT' for a in args), 'CORE_FACT_REQUIRED')
    return 'NORM' if op == 'must' else 'FACT'


def tree(value, declared):
    fields(value, {'schema', 'nodes', 'root'})
    require(value['schema'] == GRAMMAR, 'CORE_GRAMMAR')
    nodes = records(value['nodes'], MAX_NODES, 1)
    kinds = []
    for node in nodes:
        kinds.append(node_kind(node, kinds, declared))
    root = value['root']
    require(type(root) is int and root == len(nodes) - 1, 'CORE_ROOT')
    seen = {root}
    for i in range(root, -1, -1):
        if i in seen:
            seen.update(nodes[i].get('args', []))
    require(len(seen) == len(nodes), 'CORE_UNREACHABLE_NODE')
    return kinds


def plan(raw, source):
    require(type(source) is bytes and len(source) <= 65536, 'CORE_SOURCE_BOUND')
    value = json_value(raw, 65536)
    fields(value, {'schema', 'symbols', 'tree', 'translation'})
    require(value['schema'] == PLAN, 'CORE_PLAN_VERSION')
    require(value['translation'] in ('declared', 'requirement'), 'CORE_TRANSLATION_MODE')
    declared = symbols(value['symbols'], source)
    tree(value['tree'], declared)
    return value


def model(raw, declarations, source):
    value = json_value(raw, 65536)
    fields(value, {'schema', 'symbols', 'tuples'})
    require(value['schema'] == MODEL, 'CORE_MODEL_VERSION')
    require(canonical(value['symbols']) == canonical(declarations), 'CORE_MODEL_SYMBOLS')
    declared = symbols(value['symbols'], source)
    seen = set()
    for row in records(value['tuples'], MAX_TUPLES):
        fields(row, {'predicate', 'terms', 'truth'})
        predicate(row['predicate'], row['terms'], declared)
        require(type(row['truth']) is str and row['truth'] in TRUTHS, 'CORE_MODEL_TRUTH')
        key = (row['predicate'], tuple(row['terms']), row['truth'])
        require(key not in seen, 'CORE_DUPLICATE_TUPLE_REPORT')
        seen.add(key)
    return value


def symbol_wire(item, indices):
    kind = ('term', 'predicate', 'domain').index(item['kind']) + 1
    members = set(item.get('members', []))
    mask = bytes(int(name in members) for name in indices)
    return bytes((kind, item.get('arity', 0))) + mask + bytes(MAX_SYMBOLS - len(mask))


def node_wire(node, indices):
    op = node['op']
    p = indices[node['predicate']] if 'predicate' in node else 0
    terms = [indices[t] for t in node.get('terms', [])] + [0, 0]
    domain = indices[node['domain']] if 'domain' in node else 0
    refs = [a + 1 for a in node.get('args', [])] + [0, 0]
    return struct.pack('>5B2H', OPS.index(op), p, terms[0], terms[1], domain, refs[0], refs[1])


def wire(value, finite_model, source):
    declared = symbols(value['symbols'], source)
    tree(value['tree'], declared)
    checked = model(canonical(finite_model), value['symbols'], source)
    indices = {s['id']: i + 1 for i, s in enumerate(value['symbols'])}
    nodes, tuples = value['tree']['nodes'], checked['tuples']
    data = bytearray(b'STC3' + struct.pack('>BBHH', len(indices), 0, len(tuples), len(nodes)))
    for item in value['symbols']:
        data.extend(symbol_wire(item, indices))
    for row in tuples:
        args = [indices[t] for t in row['terms']] + [0, 0]
        data.extend(bytes((indices[row['predicate']], args[0], args[1], TRUTHS.index(row['truth']))))
    for node in nodes:
        data.extend(node_wire(node, indices))
    require(len(data) <= 8192, 'CORE_WIRE_BOUND')
    return bytes(data)


def display(value):
    lines = []
    for i, node in enumerate(value['tree']['nodes']):
        op = node['op']
        if op == 'pred':
            text = node['predicate'] + '(' + ','.join(node['terms']) + ')'
        elif op in ('all', 'some'):
            text = op + '(' + node['predicate'] + ',' + node['domain'] + ')'
        else:
            text = op + '(' + ','.join('n' + str(a) for a in node['args']) + ')'
        lines.append('n' + str(i) + '=' + text)
    return '; '.join(lines)


def native_values(raw, value):
    require(type(raw) is bytes and 0 < len(raw) <= 32768 and raw.endswith(b'\n'), 'CORE_OUTPUT_BOUND')
    kinds = tree(value['tree'], {s['id']: s for s in value['symbols']})
    lines = raw.decode('ascii').splitlines()
    require(len(lines) == len(kinds) + 1 and lines[0] == 'OK CORE3 ' + kinds[-1], 'CORE_OUTPUT_HEADER')
    result = []
    for i, (line, kind) in enumerate(zip(lines[1:], kinds, strict=True)):
        parts = line.split()
        require(len(parts) == 5 and parts[:3] == ['NODE', str(i + 1), kind], 'CORE_OUTPUT_NODE')
        require(parts[3] in TRUTHS and parts[4] in ('UNKNOWN', 'SATISFIED', 'VIOLATED'), 'CORE_OUTPUT_VALUE')
        require((kind == 'FACT' and parts[4] == 'UNKNOWN') or
                (kind == 'NORM' and parts[3] == 'UNRESOLVED'), 'CORE_OUTPUT_SORT')
        result.append({'node': i, 'sort': kind, 'truth': parts[3], 'outcome': parts[4]})
    return result
