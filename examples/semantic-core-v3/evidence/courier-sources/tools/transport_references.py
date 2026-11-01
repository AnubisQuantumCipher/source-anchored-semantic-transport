"""Bounded declared reference groups; checks syntax, spans and lexical scope."""

from transport_operators import MAX_MENTIONS
from transport_schema import IDENT, fields, require


def occurrence(item: dict, source: bytes, symbols: dict) -> None:
    fields(item, {'symbol', 'span'})
    require(type(item['symbol']) is str and item['symbol'] in symbols, 'undefined reference symbol')
    interval = item['span']
    require(type(interval) is list and len(interval) == 2, 'invalid reference occurrence')
    begin, end = interval
    require(type(begin) is int and type(end) is int and 0 <= begin < end <= len(source),
            'reference occurrence out of bounds')
    require(source[begin:end] == symbols[item['symbol']].encode('utf-8'), 'reference quotation mismatch')
    try:
        source[:begin].decode('utf-8')
        source[begin:end].decode('utf-8')
    except UnicodeError as error:
        raise ValueError('reference span splits UTF-8') from error


def reference_node(node: dict, source: bytes, symbols: dict, nodes: list,
                   index: int, kinds: list, frees: list) -> tuple[str, frozenset]:
    fields(node, {'op', 'id', 'relationship', 'args', 'mentions'})
    require(type(node['id']) is str and IDENT.fullmatch(node['id']) is not None, 'invalid reference id')
    args, mode = node['args'], node['relationship']
    require(mode in ('document', 'bound-variable', 'dependent'), 'unknown reference relationship')
    require(type(args) is list and len(args) == (0 if mode == 'document' else 1), 'reference scope arity mismatch')
    for arg in args:
        require(type(arg) is int and 0 <= arg < index and kinds[arg] == 'var' and nodes[arg]['op'] == 'var',
                'reference scope must name an earlier variable declaration')
    mentions = node['mentions']
    require(type(mentions) is list and 1 <= len(mentions) <= MAX_MENTIONS, 'reference mention budget exceeded')
    seen = set()
    for mention in mentions:
        occurrence(mention, source, symbols)
        identity = tuple(mention['span'])
        require(identity not in seen, 'duplicate reference occurrence')
        seen.add(identity)
    return 'term', frees[args[0]] if args else frozenset()


def check_ownership(node: dict, nodes: list) -> None:
    if node['op'] in ('part_of', 'value_of'):
        require(nodes[node['args'][0]]['op'] in ('reference', 'part_of'),
                'owned term/value requires an explicit reference owner')
    elif node['op'] == 'copy_unchanged':
        require(nodes[node['args'][0]]['op'] in ('reference', 'part_of'),
                'copy destination requires an explicit reference')
        require(nodes[node['args'][1]]['op'] == 'value_of', 'copy source requires a named owned value')


def check_groups(nodes: list) -> None:
    names, mentions, bound = set(), {}, set()
    for node in nodes:
        if node['op'] != 'reference':
            continue
        require(node['id'] not in names, 'duplicate reference id')
        names.add(node['id'])
        for item in node['mentions']:
            key = tuple(item['span'])
            require(key not in mentions, 'one source occurrence assigned to multiple reference groups')
            mentions[key] = node['id']
        if node['relationship'] == 'bound-variable':
            require(node['args'][0] not in bound, 'multiple reference groups denote one bound variable')
            bound.add(node['args'][0])
