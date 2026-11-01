"""Bounded grammar-3 requirement translation; role labels stay opaque.

Only the complete controlled surface and its explicit role bindings are checked.
The model supplies predicate interpretation. This parser does not evaluate truth,
infer English meaning, establish model adequacy, or grant execution authority.
"""

import hashlib
import re

from transport_requirement_language import MAX_LINE_BYTES, parse_requirement
from transport_schema import canonical
from transport_wire import TransportError

PROFILE = 'transport/requirements-core/1'
GRAMMAR = 'transport/meaning/3'
MAX_SOURCE_BYTES = MAX_LINE_BYTES + 1
PHRASE = re.compile(r'[A-Za-z]+(?:[ -][A-Za-z]+)*\Z')
RESERVED = frozenset((
    'when shall should may within unless not all some every each any none no '
    'if then before after during until since cause causes caused causing because '
    'therefore thus imply implies implication belief believes believe believed '
    'attribution according says said reported reports might can could would must '
    'permission permitted allowed'
).split())
ROLES = ('ID', 'WHEN', 'ACTOR', 'MODAL', 'ACTION', 'UNLESS')


def outside(source: object, reason: str) -> dict:
    bounded = type(source) is bytes and len(source) <= MAX_SOURCE_BYTES
    return {'status': 'NOT_IN_FRAGMENT', 'profile': PROFILE, 'reason': reason,
            'source_sha256': hashlib.sha256(source).hexdigest() if bounded else None,
            'lexical_interpretation': 'OPAQUE_MODEL_LABELS', 'tree': None,
            'symbols': [], 'requirement_id': None}


def role_symbols(fields: dict) -> list:
    specifications = (('EVENT', 'WHEN', 5, 'predicate', 0),
                      ('ACTOR', 'ACTOR', 0, 'term', None),
                      ('ACTION', 'ACTION', 0, 'predicate', 1),
                      ('EXCEPTION', 'UNLESS', 7, 'predicate', 0))
    symbols = []
    for name, role, prefix, kind, arity in specifications:
        if role not in fields:
            continue
        item = fields[role]
        quote = item.value[prefix:]
        words = quote.lower().replace('-', ' ').split(' ')
        if PHRASE.fullmatch(quote) is None or any(word in RESERVED for word in words):
            raise TransportError('unsupported controlled role label')
        symbol = {'id': name, 'kind': kind, 'binding': {
            'kind': 'span', 'span': [item.begin + prefix, item.end], 'quote': quote}}
        if arity is not None:
            symbol['arity'] = arity
        symbols.append(symbol)
    return symbols


def expected_tree(exception: bool) -> dict:
    nodes = [{'op': 'pred', 'predicate': 'EVENT', 'terms': []},
             {'op': 'pred', 'predicate': 'ACTION', 'terms': ['ACTOR']}]
    trigger = 0
    if exception:
        nodes.extend(({'op': 'pred', 'predicate': 'EXCEPTION', 'terms': []},
                      {'op': 'not', 'args': [2]}, {'op': 'and', 'args': [0, 3]}))
        trigger = 4
    nodes.append({'op': 'if', 'args': [trigger, 1]})
    nodes.append({'op': 'must', 'args': [len(nodes) - 1]})
    return {'schema': GRAMMAR, 'nodes': nodes, 'root': len(nodes) - 1}


def canonical_sentence(fields: dict) -> bytes:
    text = (fields['ID'].value + ': ' + fields['WHEN'].value + ', ' +
            fields['ACTOR'].value + ' shall ' + fields['ACTION'].value)
    if 'UNLESS' in fields:
        text += ', ' + fields['UNLESS'].value
    return (text + '.').encode('ascii')


def parse_fragment(source: object) -> dict:
    """Return NOT_IN_FRAGMENT for every unsupported complete bounded input."""
    if type(source) is not bytes or not 1 <= len(source) <= MAX_SOURCE_BYTES:
        return outside(source, 'INPUT_TYPE_OR_BYTE_BOUND')
    line = source.removesuffix(b'\n')
    try:
        line.decode('ascii')
        record = parse_requirement(line, 0)
        fields = {item.role: item for item in record}
        expected = ROLES if 'UNLESS' in fields else ROLES[:-1]
        if tuple(fields) != expected or fields['MODAL'].value != 'shall':
            return outside(source, 'UNSUPPORTED_REQUIREMENT_SHAPE')
        symbols = role_symbols(fields)
        if canonical_sentence(fields) != line:
            return outside(source, 'NONCANONICAL_COMPLETE_SENTENCE')
    except (TransportError, UnicodeError):
        return outside(source, 'UNSUPPORTED_REQUIREMENT_SHAPE_OR_LABEL')
    identity = fields['ID']
    return {'status': 'IN_FRAGMENT', 'profile': PROFILE, 'reason': None,
            'source_sha256': hashlib.sha256(source).hexdigest(),
            'lexical_interpretation': 'OPAQUE_MODEL_LABELS',
            'tree': expected_tree('UNLESS' in fields), 'symbols': symbols,
            'requirement_id': {'value': identity.value,
                               'span': [identity.begin, identity.end]}}


def bounded_canonical(value: object) -> bytes:
    pending = [(value, 0)]
    for _ in range(128):
        if not pending:
            return canonical(value)
        item, depth = pending.pop()
        if depth > 6:
            raise TransportError('controlled translation nesting bound exceeded')
        if type(item) is dict:
            if len(item) > 8 or any(type(key) is not str or len(key) > 64 for key in item):
                raise TransportError('controlled translation object bound exceeded')
            pending.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            if len(item) > 8:
                raise TransportError('controlled translation list bound exceeded')
            pending.extend((child, depth + 1) for child in item)
        elif type(item) is str:
            if len(item) > MAX_LINE_BYTES:
                raise TransportError('controlled translation string bound exceeded')
        elif type(item) is int:
            if not 0 <= item <= MAX_SOURCE_BYTES:
                raise TransportError('controlled translation integer bound exceeded')
        elif type(item) not in (bool, type(None)):
            raise TransportError('controlled translation scalar type is unsupported')
    raise TransportError('controlled translation object count bound exceeded')


def validate_translation(source: object, authored_tree: object,
                         authored_symbols: object) -> dict:
    """Exact tree and role-binding equality, never a lexical entailment claim."""
    result = parse_fragment(source)
    if result['status'] == 'NOT_IN_FRAGMENT':
        return result
    if type(authored_tree) is not dict or type(authored_symbols) is not list:
        raise TransportError('controlled translation needs a tree and role symbols')
    if (bounded_canonical(authored_tree) != canonical(result['tree']) or
            bounded_canonical(authored_symbols) != canonical(result['symbols'])):
        raise TransportError('controlled translation differs from the complete source')
    return dict(result, status='CHECKED_CONTROLLED_TRANSLATION')
