"""Typed documentary meaning graph and native-checked structural compaction.

Typing/source interpretation and this projection are TESTED, not SPARK-proved.
Native comparison treats projected labels and edges as documentary graph data.
"""

from transport_schema import (GRAMMAR, IDENT, LEAVES, MAX_NODES, SIGNATURES,
                              canonical, fields, require)
from transport_structure import graph_bytes, map_bytes, verify_structure
from transport_operators import EXTENSIONS, GRAMMAR_V2
from transport_references import check_groups, check_ownership, reference_node


def span(value: object, source: bytes, empty: bool = False) -> tuple[int, int]:
    require(type(value) is list and len(value) == 2, 'invalid source span')
    begin, end = value
    require(type(begin) is int and type(end) is int, 'span must use integer metadata')
    require(0 <= begin <= end <= len(source) and (empty or begin < end), 'source span out of bounds')
    try:
        source[:begin].decode('utf-8')
        source[begin:end].decode('utf-8')
    except UnicodeError as error:
        raise ValueError('span splits a UTF-8 character') from error
    return begin, end


def leaf(node: dict, source: bytes, symbols: dict, index: int) -> tuple[str, frozenset]:
    op = node['op']
    if op == 'var':
        fields(node, {'op', 'name'})
        require(type(node['name']) is str and IDENT.fullmatch(node['name']) is not None, 'invalid bound variable')
        return 'var', frozenset((index,))
    fields(node, {'op', 'symbol', 'span'})
    require(type(node['symbol']) is str and node['symbol'] in symbols, 'undefined symbol')
    begin, end = span(node['span'], source)
    require(source[begin:end] == symbols[node['symbol']].encode('utf-8'), 'symbol occurrence mismatch')
    return LEAVES[op], frozenset()


def relation(node: dict, kinds: list, frees: list, source: bytes, grammar: str) -> tuple[str, frozenset]:
    special = grammar == GRAMMAR_V2 and node['op'] == 'copy_unchanged'
    fields(node, {'op', 'args', 'cue', 'comparison'} if special else {'op', 'args', 'cue'})
    if special:
        require(node['comparison'] == 'unspecified', 'copy comparison domain must remain explicitly unspecified')
    args, op = node['args'], node['op']
    require(type(args) is list and 1 <= len(args) <= 7, 'relation arity budget exceeded')
    require(all(type(arg) is int and 0 <= arg < len(kinds) for arg in args), 'forward, cyclic or absent reference')
    span(node['cue'], source, empty=True)
    actual = tuple(kinds[arg] for arg in args)
    if op == 'pred':
        require(actual[0] == 'text' and all(k in ('term', 'var') for k in actual[1:]), 'predicate type mismatch')
        kind = 'prop'
    else:
        signatures = SIGNATURES | EXTENSIONS if grammar == GRAMMAR_V2 else SIGNATURES
        require(op in signatures and actual == signatures[op][0], 'unknown relation or type mismatch')
        kind = signatures[op][1]
    free = frozenset().union(*(frees[arg] for arg in args))
    if op in ('all', 'some'):
        require(args[0] in frees[args[2]], 'vacuous quantifier or wrong variable binding')
        free = frees[args[1]] | frees[args[2]].difference((args[0],))
    return kind, free


def reachable(nodes: list, root: int) -> None:
    found = {root}
    for index in range(root, -1, -1):
        if index in found:
            found.update(nodes[index].get('args', []))
    require(len(found) == len(nodes), 'unreachable meaning nodes are not silently ignored')


def check_meaning(value: object, source: bytes, symbols: dict) -> dict:
    fields(value, {'schema', 'nodes', 'root', 'ambiguities'})
    require(value['schema'] in (GRAMMAR, GRAMMAR_V2), 'incompatible meaning grammar')
    nodes = value['nodes']
    require(type(nodes) is list and 1 <= len(nodes) <= MAX_NODES, 'meaning node budget exceeded')
    kinds, frees, names = [], [], set()
    for index, node in enumerate(nodes):
        require(type(node) is dict and type(node.get('op')) is str, 'invalid meaning node')
        op = node['op']
        if op == 'reference' and value['schema'] == GRAMMAR_V2:
            kind, free = reference_node(node, source, symbols, nodes, index, kinds, frees)
        elif op in LEAVES or op == 'var':
            kind, free = leaf(node, source, symbols, index)
        else:
            kind, free = relation(node, kinds, frees, source, value['schema'])
            if value['schema'] == GRAMMAR_V2:
                check_ownership(node, nodes)
        if op == 'var':
            require(node['name'] not in names, 'duplicate variable declaration')
            names.add(node['name'])
        if op == 'within':
            require(nodes[node['args'][1]]['op'] == 'quantity', 'deadline requires an explicit quantity')
        kinds.append(kind)
        frees.append(free)
    root = value['root']
    require(type(root) is int and root == len(nodes) - 1, 'root must identify final node')
    require(kinds[root] == 'prop' and not frees[root], 'meaning root must be a closed proposition')
    reachable(nodes, root)
    if value['schema'] == GRAMMAR_V2:
        check_groups(nodes)
    ambiguities = value['ambiguities']
    require(type(ambiguities) is list and len(ambiguities) <= 16, 'ambiguity budget exceeded')
    for item in ambiguities:
        fields(item, {'span', 'note'})
        span(item['span'], source)
        require(type(item['note']) is str and 1 <= len(item['note'].encode('utf-8')) <= 1024,
                'ambiguity note budget exceeded')
    return value


def projection(value: dict, symbols: dict) -> tuple[bytes, list[int]]:
    records, roots = [], []
    for node in value['nodes']:
        metadata = {key: item for key, item in node.items() if key != 'args'}
        if 'symbol' in node:
            metadata['literal'] = symbols[node['symbol']]
        if 'mentions' in node:
            metadata['mention_literals'] = [symbols[item['symbol']] for item in node['mentions']]
        literal = canonical(metadata)
        records.append(('text', literal, ()))
        label = len(records) - 1
        children = tuple(roots[arg] for arg in node.get('args', []))
        records.append(('bundle', b'', (label,) + children))
        roots.append(len(records) - 1)
    return graph_bytes(records, roots[value['root']]), roots


def compact(value: dict, source: bytes, symbols: dict) -> dict:
    check_meaning(value, source, symbols)
    nodes, mapping, seen = [], [], {}
    for node in value['nodes']:
        item = dict(node)
        if 'args' in item:
            item['args'] = [mapping[arg] for arg in item['args']]
        key = canonical(item)
        if key not in seen:
            seen[key] = len(nodes)
            nodes.append(item)
        mapping.append(seen[key])
    result = dict(value, nodes=nodes, root=mapping[value['root']])
    check_meaning(result, source, symbols)
    before, _ = projection(value, symbols)
    after, _ = projection(result, symbols)
    projected_map = []
    for target in mapping:
        projected_map.extend((target * 2, target * 2 + 1))
    verify_structure(before, after, map_bytes(projected_map))
    require(result['ambiguities'] == value['ambiguities'], 'ambiguity changed in compaction')
    return result


def residuals(value: dict, source: bytes) -> list:
    intervals = []
    for node in value['nodes']:
        interval = node.get('span', node.get('cue', [0, 0]))
        if interval[0] < interval[1]:
            intervals.append(tuple(interval))
        intervals.extend(tuple(item['span']) for item in node.get('mentions', []))
    result, cursor = [], 0
    for begin, end in sorted(set(intervals)):
        if begin > cursor:
            result.append({'span': [cursor, begin], 'text': source[cursor:begin].decode('utf-8')})
        cursor = max(cursor, end)
    if cursor < len(source):
        result.append({'span': [cursor, len(source)], 'text': source[cursor:].decode('utf-8')})
    return result


def display(value: dict) -> str:
    lines = []
    for index, node in enumerate(value['nodes']):
        if node['op'] == 'var':
            text = 'var(' + node['name'] + ')'
        elif node['op'] == 'reference':
            scope = ', '.join('n' + str(arg) for arg in node['args']) or 'document'
            mentions = ', '.join(item['symbol'] for item in node['mentions'])
            text = 'reference(' + node['id'] + ', ' + node['relationship'] + ', ' + scope + ', [' + mentions + '])'
        elif 'symbol' in node:
            text = node['op'] + '(' + node['symbol'] + ')'
        else:
            text = node['op'] + '(' + ', '.join('n' + str(arg) for arg in node['args']) + ')'
            if node['op'] == 'copy_unchanged':
                text += ' [comparison=unspecified]'
        lines.append('n' + str(index) + ' = ' + text)
    lines.append('root n' + str(value['root']))
    return '\n'.join(lines)
