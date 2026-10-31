"""Closed, versioned knowledge-codec schema; documentary semantics, no authority."""

import hashlib
import json
import re

from transport_wire import MAX_SOURCE, MAX_WIRE, TransportError
from transport_operators import EXTENSIONS, REFERENCE_DEFINITION

SCHEMA = 'transport/package/1'
GRAMMAR = 'transport/meaning/1'
DICTIONARY = 'transport/dictionary/1'
MAX_NODES = 256
MAX_SYMBOLS = 64
MAX_LITERAL = 4096
IDENT = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,47}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
SIGNATURES = {
    'not': (('prop',), 'prop', 'Negate the enclosed proposition.'),
    'and': (('prop', 'prop'), 'prop', 'Both propositions hold in the declared reading.'),
    'sequence': (('prop', 'prop'), 'prop', 'First operand precedes the second; no causation implied.'),
    'parallel': (('prop', 'prop'), 'prop', 'Tracks proceed in parallel; no interaction or completion rule implied.'),
    'cause': (('prop', 'prop'), 'prop', 'Declared causal claim from first operand to second; not verified causality.'),
    'if': (('prop', 'prop'), 'prop', 'First operand is a sufficient condition for the second in the declared reading.'),
    'unless': (('prop', 'prop'), 'prop', 'Second operand is an exception to the first; no converse obligation implied.'),
    'requires': (('prop', 'prop'), 'prop', 'Second operand is necessary for the first; does not authorize execution.'),
    'only_after': (('prop', 'prop'), 'prop', 'First operand may occur only after the second is complete; no occurrence is promised or authorized.'),
    'attribution': (('term', 'prop'), 'prop', 'First operand is the source of the claim; no narrator endorsement.'),
    'belief': (('term', 'prop'), 'prop', 'First operand believes the proposition; not asserted as fact.'),
    'uncertain': (('text', 'prop'), 'prop', 'Retain the exact uncertainty qualification on this proposition.'),
    'all': (('var', 'term', 'prop'), 'prop', 'Bind the first variable universally over the declared domain in the body.'),
    'some': (('var', 'term', 'prop'), 'prop', 'Bind the first variable existentially over the declared domain in the body.'),
    'must': (('prop',), 'prop', 'Declared obligation; no satisfaction or authority verdict.'),
    'may': (('prop',), 'prop', 'Declared permission; no obligation to perform it.'),
    'should': (('prop',), 'prop', 'Declared recommendation, distinct from an obligation.'),
    'quantity': (('text', 'text'), 'term', 'Exact amount spelling and unit spelling; no evaluation or conversion.'),
    'within': (('prop', 'term'), 'prop', 'Declared inclusive deadline quantity for this proposition; origin must be explicit or ambiguous.'),
}
LEAVES = {'text': 'text', 'term': 'term', 'atom': 'prop'}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TransportError(message)


def fields(value: object, expected: set[str]) -> None:
    require(type(value) is dict and set(value) == expected, 'unknown or missing schema fields')


def canonical(value: object) -> bytes:
    try:
        data = json.dumps(value, ensure_ascii=False, sort_keys=True,
                          separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (ValueError, UnicodeError, TypeError, RecursionError) as error:
        raise TransportError('invalid canonical JSON value') from error
    require(len(data) <= MAX_WIRE, 'canonical output budget exceeded')
    return data


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def unique(pairs: list) -> dict:
    require(len(pairs) <= MAX_NODES, 'object field budget exceeded')
    require(len({key for key, _ in pairs}) == len(pairs), 'duplicate JSON field')
    return dict(pairs)


def refuse_number(value: str) -> None:
    raise TransportError('only integer metadata is admitted; source numbers must be strings')


def json_value(data: bytes, cap: int = MAX_WIRE) -> object:
    require(type(data) is bytes and 0 < len(data) <= cap, 'JSON byte budget or immutable input failure')
    quoted, escaped, depth = False, False, 0
    for value in data:
        if quoted:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                quoted = False
        elif value == 34:
            quoted = True
        elif value in (91, 123):
            depth += 1
            require(depth <= 12, 'JSON nesting budget exceeded')
        elif value in (93, 125):
            depth -= 1
            require(depth >= 0, 'malformed JSON nesting')
    require(not quoted and depth == 0, 'truncated JSON')
    try:
        return json.loads(data.decode('utf-8'), object_pairs_hook=unique,
                          parse_float=refuse_number, parse_constant=refuse_number)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise TransportError('malformed codec JSON') from error


def operator_dictionary(version: str = '1') -> dict:
    require(version in ('1', '2'), 'incompatible operator version')
    signatures = SIGNATURES if version == '1' else SIGNATURES | EXTENSIONS
    entries = {name: {'args': list(args), 'result': kind, 'definition': definition}
               for name, (args, kind, definition) in signatures.items()}
    entries['pred'] = {'args': ['text', 'term-or-var...'], 'result': 'prop',
                       'definition': 'Source predicate applied to ordered explicit terms or bound variables; interpretation is declared.'}
    if version == '2':
        entries['reference'] = dict(REFERENCE_DEFINITION, args=list(REFERENCE_DEFINITION['args']))
    return {'schema': DICTIONARY, 'id': 'transport-operators', 'version': version,
            'role': 'operators', 'entries': entries}


def check_dictionary(value: object) -> dict:
    fields(value, {'schema', 'id', 'version', 'role', 'entries'})
    require(value['schema'] == DICTIONARY and value['version'] in ('1', '2'), 'incompatible dictionary version')
    require(type(value['id']) is str and IDENT.fullmatch(value['id']) is not None, 'invalid dictionary id')
    if value['role'] == 'operators':
        require(value == operator_dictionary(value['version']), 'unknown operator dictionary or altered definitions')
    else:
        require(value['role'] == 'symbols' and value['version'] == '1', 'unknown symbol dictionary role/version')
        entries = value['entries']
        require(type(entries) is dict and 1 <= len(entries) <= MAX_SYMBOLS, 'symbol dictionary budget exceeded')
        for name, text in entries.items():
            require(IDENT.fullmatch(name) is not None and type(text) is str, 'invalid symbol definition')
            try:
                size = len(text.encode('utf-8'))
            except UnicodeError as error:
                raise TransportError('invalid symbol Unicode') from error
            require(1 <= size <= MAX_LITERAL, 'symbol literal budget exceeded')
    require(len(canonical(value)) <= MAX_SOURCE, 'dictionary byte budget exceeded')
    return value


def reference(value: dict, embedded: bool) -> dict:
    check_dictionary(value)
    return {key: value[key] for key in ('id', 'version', 'role')} | {
        'sha256': sha(canonical(value)), 'content': value if embedded else None}


def resolve(references: object, supplied: tuple[bytes, ...]) -> dict:
    require(type(references) is list and len(references) == 2, 'exactly two dictionaries required')
    require(type(supplied) is tuple and len(supplied) <= 2, 'dependency budget exceeded')
    available = {}
    for data in supplied:
        value = check_dictionary(json_value(data, MAX_SOURCE))
        digest = sha(canonical(value))
        require(digest not in available, 'duplicate supplied dictionary')
        available[digest] = value
    found, used = {}, set()
    for item in references:
        fields(item, {'id', 'version', 'role', 'sha256', 'content'})
        require(type(item['sha256']) is str and DIGEST.fullmatch(item['sha256']) is not None, 'invalid dictionary digest')
        content = item['content']
        if content is None:
            require(item['sha256'] in available, 'missing declared dictionary: ' + item['sha256'])
            content = available[item['sha256']]
            used.add(item['sha256'])
        value = check_dictionary(content)
        require(reference(value, item['content'] is not None) == item, 'dictionary identity mismatch')
        require(value['role'] not in found, 'duplicate dictionary role')
        found[value['role']] = value
    require(set(found) == {'operators', 'symbols'} and used == set(available), 'unused or missing dependency')
    return found
