"""One reusable knowledge-codec API: encode, validate, decode, inspect.

Exact source equality uses the existing native core. Meaning typing, dependency
resolution and projection remain TESTED; source interpretation stays UNPROVEN.
"""

from dataclasses import dataclass

from transport_meaning import check_meaning, compact, display, residuals
from transport_schema import (DICTIONARY, DIGEST, GRAMMAR, MAX_LITERAL, MAX_NODES,
                              SCHEMA, canonical, check_dictionary, fields,
                              json_value, operator_dictionary, reference, require,
                              resolve, sha)
from transport_readable import compare_source
from transport_wire import MAX_SOURCE, MAX_WIRE, encode as encode_frame, unpack
from transport_operators import GRAMMAR_V2, PLAN_V2


@dataclass(frozen=True)
class Encoded:
    package: bytes
    dependencies: tuple[bytes, ...]


def source_text(source: bytes) -> str:
    require(type(source) is bytes and 0 < len(source) <= MAX_SOURCE, 'source byte budget or immutable input failure')
    try:
        return source.decode('utf-8')
    except UnicodeError as error:
        raise ValueError('knowledge source must be UTF-8') from error


def literal_plan(source: bytes) -> dict:
    text = source_text(source)
    require(len(source) <= MAX_LITERAL, 'automatic opaque input limit; supply an explicit bounded meaning plan')
    return {'schema': 'transport/encoding-plan/1', 'symbols': {'SOURCE': text},
            'meaning': {'schema': GRAMMAR, 'nodes': [{'op': 'atom', 'symbol': 'SOURCE',
                                                    'span': [0, len(source)]}],
                        'root': 0, 'ambiguities': []}}


def encode(source: bytes, plan: bytes | None = None, profile: str = 'self-contained') -> Encoded:
    source_text(source)
    require(profile in ('self-contained', 'shared'), 'unknown package profile')
    value = literal_plan(source) if plan is None else json_value(plan, MAX_SOURCE)
    fields(value, {'schema', 'symbols', 'meaning'})
    require(value['schema'] in ('transport/encoding-plan/1', PLAN_V2), 'incompatible encoding plan')
    grammar = GRAMMAR_V2 if value['schema'] == PLAN_V2 else GRAMMAR
    require(type(value['meaning']) is dict and value['meaning'].get('schema') == grammar, 'plan/grammar mismatch')
    symbols = check_dictionary({'schema': DICTIONARY, 'id': 'document-symbols', 'version': '1',
                                'role': 'symbols', 'entries': value['symbols']})
    meaning = compact(value['meaning'], source, symbols['entries'])
    words = [text.encode('utf-8') for text in symbols['entries'].values()
             if len(text.encode('utf-8')) <= 255]
    frame = encode_frame(source, words)
    compare_source(frame, source)
    dictionaries = (operator_dictionary('2' if grammar == GRAMMAR_V2 else '1'), symbols)
    body = {'schema': SCHEMA, 'grammar': grammar, 'profile': profile,
            'dictionaries': [reference(item, profile == 'self-contained') for item in dictionaries],
            'source': {'sha256': sha(source), 'frame_hex': frame.hex()}, 'meaning': meaning}
    package = canonical(dict(body, integrity_sha256=sha(canonical(body))))
    dependencies = tuple(canonical(item) for item in dictionaries) if profile == 'shared' else ()
    validate(package, dependencies, canonical_source=source)
    return Encoded(package, dependencies)


def opened(package: bytes, dependencies: tuple[bytes, ...], expected_sha256: str | None,
           canonical_source: bytes | None) -> tuple[dict, dict, bytes]:
    require(type(package) is bytes and len(package) <= MAX_WIRE, 'package byte budget exceeded')
    if expected_sha256 is not None:
        require(type(expected_sha256) is str and DIGEST.fullmatch(expected_sha256) is not None,
                'invalid expected package digest')
        require(sha(package) == expected_sha256, 'package differs from separately expected identity')
    item = json_value(package)
    fields(item, {'schema', 'grammar', 'profile', 'dictionaries', 'source', 'meaning', 'integrity_sha256'})
    require(item['schema'] == SCHEMA and item['grammar'] in (GRAMMAR, GRAMMAR_V2), 'incompatible package or grammar')
    require(item['profile'] in ('self-contained', 'shared'), 'unknown package profile')
    body = {key: value for key, value in item.items() if key != 'integrity_sha256'}
    require(item['integrity_sha256'] == sha(canonical(body)), 'package integrity mismatch')
    dictionaries = resolve(item['dictionaries'], dependencies)
    version = '2' if item['grammar'] == GRAMMAR_V2 else '1'
    require(dictionaries['operators']['version'] == version, 'grammar/operator dictionary mismatch')
    require(type(item['meaning']) is dict and item['meaning'].get('schema') == item['grammar'], 'envelope/meaning grammar mismatch')
    embedded = [entry['content'] is not None for entry in item['dictionaries']]
    require(all(embedded) if item['profile'] == 'self-contained' else not any(embedded), 'profile/dependency mismatch')
    record = item['source']
    fields(record, {'sha256', 'frame_hex'})
    require(type(record['frame_hex']) is str, 'source frame must be hexadecimal text')
    try:
        frame = bytes.fromhex(record['frame_hex'])
    except ValueError as error:
        raise ValueError('malformed source frame') from error
    require(frame.hex() == record['frame_hex'], 'noncanonical source frame spelling')
    source = unpack(frame)
    source_text(source)
    require(record['sha256'] == sha(source), 'source identity mismatch')
    check_meaning(item['meaning'], source, dictionaries['symbols']['entries'])
    if canonical_source is not None:
        compare_source(frame, canonical_source)
    return item, dictionaries, source


def validate(package: bytes, dependencies: tuple[bytes, ...] = (),
             expected_sha256: str | None = None, canonical_source: bytes | None = None) -> dict:
    item, _, source = opened(package, dependencies, expected_sha256, canonical_source)
    gaps = residuals(item['meaning'], source)
    opaque = [node['span'] for node in item['meaning']['nodes'] if node['op'] == 'atom']
    return {'status': 'TESTED_VALID', 'schema': SCHEMA, 'package_sha256': sha(package),
            'source_sha256': sha(source), 'structure': 'TESTED',
            'canonical_source_comparison': 'NATIVE_CHECKED' if canonical_source is not None else 'NOT_SUPPLIED',
            'representation': 'INCOMPLETE' if gaps or opaque else 'PROPOSED_STRUCTURED_READING',
            'semantic_completeness': 'UNPROVEN', 'evidence_authentication': 'NOT_AUTHENTICATED',
            'residuals': gaps, 'opaque_propositions': opaque,
            'ambiguities': item['meaning']['ambiguities']}


def decode(package: bytes, dependencies: tuple[bytes, ...] = (),
           expected_sha256: str | None = None, canonical_source: bytes | None = None,
           source_only: bool = False, meaning_only: bool = False) -> dict | bytes:
    item, dictionaries, source = opened(package, dependencies, expected_sha256, canonical_source)
    require(type(source_only) is bool and type(meaning_only) is bool, 'decode view options must be Boolean')
    require(not (source_only and meaning_only), 'decode views are mutually exclusive')
    if source_only:
        return source
    result = validate(package, dependencies, expected_sha256, canonical_source)
    location = 'decode --source-only UTF-8 bytes' if meaning_only else 'source_text UTF-8 bytes'
    result['residuals'] = [{'span': gap['span'], 'text_location': location}
                           for gap in result['residuals']]
    result.update({'formula': display(item['meaning']), 'meaning': item['meaning'],
                   'lexicon': dictionaries['symbols']['entries'],
                   'operator_definitions': dictionaries['operators']['entries'],
                   'source_text': source.decode('utf-8'), 'commentary': None})
    if meaning_only:
        del result['source_text']
        result['view'] = 'DECLARED_MEANING_SOURCE_FRAME_OMITTED'
    canonical(result)
    return result


def export_dictionary(package: bytes, role: str, dependencies: tuple[bytes, ...] = ()) -> bytes:
    require(role in ('operators', 'symbols'), 'unknown dictionary role')
    _, dictionaries, _ = opened(package, dependencies, None, None)
    return canonical(dictionaries[role])


def inspect(package: bytes, dependencies: tuple[bytes, ...] = (),
            expected_sha256: str | None = None) -> dict:
    item, _, source = opened(package, dependencies, expected_sha256, None)
    return {'schema': SCHEMA, 'grammar': item['grammar'], 'profile': item['profile'],
            'package_bytes': len(package), 'source_bytes': len(source),
            'formula': display(item['meaning']),
            'dependencies': [{key: value for key, value in ref.items() if key != 'content'}
                             for ref in item['dictionaries']],
            'validation': validate(package, dependencies, expected_sha256)}
