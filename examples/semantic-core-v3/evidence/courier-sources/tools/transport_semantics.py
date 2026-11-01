"""Typed meaning units over preserved source frames; interpretation is unproved.

This composes the existing typed codec, not a second grammar or decoder. Context
edges are declared dependencies. Their presence never proves context adequacy.
"""

import re

from transport_meaning import check_meaning, compact, display, residuals
from transport_operators import GRAMMAR_V2, PLAN_V2
from transport_schema import (DICTIONARY, GRAMMAR, canonical, check_dictionary,
                              fields, operator_dictionary, reference, require, resolve, sha)

KINDS = ('source_claim', 'goal', 'instruction', 'historical_approval', 'revocation',
         'pending_action')
UNIT_KEYS = {'id', 'source', 'interpretation', 'kind', 'context'}
MAX_UNITS = 16
MAX_BYTES = 65_536
IDENTIFIER = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
BOUNDARY = {'typing': 'TESTED_NOT_FORMALLY_PROVED',
            'interpretation_entailment': 'UNPROVEN', 'semantic_completeness': 'UNPROVEN',
            'context_adequacy': 'UNPROVEN', 'execution_authority': 'NONE'}


def identifier(value: object) -> str:
    require(type(value) is str and IDENTIFIER.fullmatch(value) is not None,
            'invalid typed meaning unit identifier')
    return value


def dictionary_pair(plan: dict) -> tuple[str, list, dict]:
    fields(plan, {'schema', 'symbols', 'meaning'})
    require(plan['schema'] in ('transport/encoding-plan/1', PLAN_V2),
            'incompatible typed encoding plan')
    grammar = GRAMMAR_V2 if plan['schema'] == PLAN_V2 else GRAMMAR
    require(type(plan['meaning']) is dict and plan['meaning'].get('schema') == grammar,
            'typed unit plan/grammar mismatch')
    symbols = check_dictionary({'schema': DICTIONARY, 'id': 'document-symbols',
                                'version': '1', 'role': 'symbols', 'entries': plan['symbols']})
    operators = operator_dictionary('2' if grammar == GRAMMAR_V2 else '1')
    return grammar, [reference(item, True) for item in (operators, symbols)], symbols


def checked_payload(item: dict, source: bytes, stored: bool) -> dict:
    require(type(source) is bytes, 'typed source requires immutable bytes')
    try:
        source.decode('utf-8')
    except UnicodeError as error:
        raise ValueError('typed semantic payload requires a UTF-8 source') from error
    if not stored:
        grammar, dictionaries, symbols = dictionary_pair(item['plan'])
        meaning = compact(item['plan']['meaning'], source, symbols['entries'])
    else:
        grammar, dictionaries, meaning = item['grammar'], item['dictionaries'], item['meaning']
        require(grammar in (GRAMMAR, GRAMMAR_V2), 'incompatible typed unit grammar')
        require(type(dictionaries) is list and len(dictionaries) == 2,
                'typed unit requires two declared dictionaries')
        require(all(type(entry) is dict and entry.get('content') is not None
                    for entry in dictionaries), 'typed unit dictionaries must be self-contained')
        resolved = resolve(dictionaries, ())
        symbols = resolved['symbols']
        expected = '2' if grammar == GRAMMAR_V2 else '1'
        require(resolved['operators']['version'] == expected, 'typed grammar/dictionary mismatch')
    require(type(meaning) is dict and meaning.get('schema') == grammar,
            'typed unit grammar/meaning mismatch')
    check_meaning(meaning, source, symbols['entries'])
    used = set()
    for node in meaning['nodes']:
        if 'symbol' in node:
            used.add(node['symbol'])
        used.update(mention['symbol'] for mention in node.get('mentions', []))
    require(used == set(symbols['entries']), 'unused typed unit symbol has no checked source occurrence')
    return {'grammar': grammar, 'dictionaries': dictionaries, 'meaning': meaning}


def anchored_payload(meaning: dict, anchors: list, source: str) -> None:
    declared = sorted(tuple(anchor['span']) for anchor in anchors if anchor['source'] == source)
    require(bool(declared), 'typed unit interpretation must anchor its source')
    selected = [item['span'] for item in meaning['ambiguities']]
    for node in meaning['nodes']:
        selected.append(node.get('span', node.get('cue', [0, 0])))
        selected.extend(mention['span'] for mention in node.get('mentions', []))
    for begin, end in selected:
        if begin == end:
            continue
        cursor = begin
        for left, right in declared:
            if left <= cursor <= right:
                cursor = max(cursor, right)
        require(cursor >= end, 'typed unit occurrence outside its interpretation anchors')


def check_units(value: object, plan: dict, sources: dict, stored: bool = False) -> list:
    require(type(value) is list and 1 <= len(value) <= MAX_UNITS, 'typed meaning unit count budget exceeded')
    interpretations = {item['id']: item for item in plan['interpretations']}
    seen, result = set(), []
    for item in value:
        fields(item, UNIT_KEYS | ({'grammar', 'dictionaries', 'meaning'} if stored else {'plan'}))
        name = identifier(item['id'])
        require(name not in seen, 'duplicate typed meaning unit identifier')
        require(identifier(item['source']) in sources, 'typed unit references missing source')
        require(identifier(item['interpretation']) in interpretations,
                'typed unit references missing interpretation')
        require(type(item['kind']) is str and item['kind'] in KINDS, 'unknown typed meaning unit kind')
        context = item['context']
        require(type(context) is list and len(context) <= MAX_UNITS,
                'typed context dependency count budget exceeded')
        require(all(identifier(entry) in seen for entry in context),
                'typed context must reference earlier declared units; no missing or cyclic dependency')
        require(len(set(context)) == len(context), 'duplicate typed context dependency')
        payload = checked_payload(item, sources[item['source']], stored)
        anchored_payload(payload['meaning'], interpretations[item['interpretation']]['anchors'], item['source'])
        result.append({key: item[key] for key in UNIT_KEYS} | payload)
        seen.add(name)
    require(len(canonical(result)) <= MAX_BYTES, 'typed meaning payload byte budget exceeded')
    return result


def unit_view(unit: dict, source: bytes) -> dict:
    dictionaries = resolve(unit['dictionaries'], ())
    meaning = unit['meaning']
    gaps = residuals(meaning, source)
    locations = [{'span': gap['span'], 'bytes': gap['span'][1] - gap['span'][0],
                  'sha256': sha(source[gap['span'][0]:gap['span'][1]]),
                  'text_location': 'explicit recover of source ' + unit['source']} for gap in gaps]
    opaque = [node['span'] for node in meaning['nodes'] if node['op'] == 'atom']
    metadata = {key: unit[key] for key in UNIT_KEYS | {'grammar', 'meaning'}}
    references = [{key: value for key, value in item.items() if key != 'content'}
                  for item in unit['dictionaries']]
    return dict(metadata, dictionaries=references,
                formula=display(meaning), lexicon=dictionaries['symbols']['entries'],
                operator_definitions=dictionaries['operators']['entries'],
                residuals=locations, opaque_propositions=opaque,
                representation='INCOMPLETE' if gaps or opaque else 'PROPOSED_STRUCTURED_READING',
                assurance=dict(BOUNDARY))


def display_units(units: list) -> str:
    parts = []
    for unit in units:
        parts.append(unit['id'] + ':' + unit['kind'] + '{' +
                     display(unit['meaning']).replace('\n', '; ') + '}')
    value = ' M[' + ' | '.join(parts) + ']'
    require(len(value.encode('utf-8')) <= MAX_BYTES, 'typed formula display byte budget exceeded')
    return value


def dependency_closure(units: list, selected: str) -> list:
    names = {unit['id'] for unit in units}
    require(selected in names, 'requested typed meaning unit not found')
    needed = {selected}
    for unit in reversed(units):
        if unit['id'] in needed:
            needed.update(unit['context'])
    return [unit for unit in units if unit['id'] in needed]
