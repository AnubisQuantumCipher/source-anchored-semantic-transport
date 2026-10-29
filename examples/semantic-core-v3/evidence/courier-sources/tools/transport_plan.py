"""Bounded Source-Anchored Semantic Transport declarations: byte references do not establish semantic truth."""

import html
import re

from transport_schema import canonical, fields, json_value, reference, require, sha
from transport_wire import MAX_SOURCE, TransportError
import transport_semantics as semantics

PLAN = 'transport/transport-plan/1'
PLAN_V2 = 'transport/transport-plan/2'
MAX_METADATA = 65_536
IDENT = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
STATUSES = ('proposed', 'disputed', 'withdrawn')
RELATIONS = {
    'supports': 'Declared support from the first record to the second; no entailment or truth is verified.',
    'contradicts': 'Declared conflict between the first record and the second; no inconsistency is proved.',
    'qualifies': 'The first record declares a qualification on the second; no scope or adequacy is verified.',
    'derived_from': 'The first record is declared derived from the second; no derivation is checked.',
    'supersedes': 'The first record is declared to replace the second in this reading; no authority is granted.',
}
DISPLAY = {
    'Σ': 'Documentary source group only; not an arithmetic sum, universal quantifier or completeness claim.',
    'I': 'Ordered declared interpretation IDs and statuses; none means no interpretation was supplied.',
    'U': 'Ordered uncertainty IDs; none means no uncertainty record was supplied, not absence of uncertainty.',
    'R': 'Ordered declared relations, written first kind second; no causality, execution or authority is implied.',
    'anchor': 'Half-open offsets [begin,end) in exact original bytes with SHA-256 of the selected bytes; a reference only, not entailment.',
    'M': 'Typed meaning units with indexed operator trees, fixed dictionary identities and declared context dependencies; interpretation and adequacy remain unproved.',
}
ASSURANCE = {
    'source_bytes': 'NATIVE_DECODED_AND_HASH_CHECKED',
    'declarations': 'UNVERIFIED',
    'interpretation_entailment': 'UNPROVEN',
    'semantic_completeness': 'NOT_CLAIMED',
    'media_understanding': 'UNPROVEN',
    'author_authentication': 'NOT_AUTHENTICATED',
    'confidentiality': 'NOT_PROVIDED',
    'runtime_boundary': 'External trusted runtime; hash-then-use does not isolate hostile concurrent same-user mutation.',
}


def text(value: object) -> str:
    require(type(value) is str, 'Transport text must be a string')
    try:
        encoded = value.encode('utf-8')
    except UnicodeError as error:
        raise TransportError('Transport invalid Unicode') from error
    require(len(encoded) <= MAX_METADATA, 'Transport text byte budget exceeded')
    return value


def identifier(value: object) -> str:
    require(type(value) is str and IDENT.fullmatch(value) is not None, 'Transport invalid identifier')
    return value


def records(value: object, cap: int, minimum: int = 0) -> list:
    require(type(value) is list and minimum <= len(value) <= cap, 'Transport record count budget exceeded')
    return value


def check_sources(value: object, sources: tuple[bytes, ...]) -> dict:
    records(value, 16, 1)
    require(len(value) == len(sources), 'Transport source metadata/data count mismatch')
    result = {}
    for item, data in zip(value, sources, strict=True):
        fields(item, {'id', 'label', 'media_type', 'provenance'})
        name = identifier(item['id'])
        require(name not in result, 'Transport duplicate source identifier')
        for key in ('label', 'media_type', 'provenance'):
            text(item[key])
        require(item['media_type'] != '', 'Transport media type declaration must be explicit')
        result[name] = data
    return result


def check_anchors(value: object, sources: dict, stored: bool) -> list:
    records(value, 16, 1)
    result = []
    for item in value:
        fields(item, {'source', 'span', 'sha256'} if stored else {'source', 'span'})
        name = identifier(item['source'])
        require(name in sources, 'Transport anchor references missing source')
        span = item['span']
        require(type(span) is list and len(span) == 2, 'Transport anchor requires two offsets')
        begin, end = span
        require(type(begin) is int and type(end) is int, 'Transport offsets must be integers')
        data = sources[name]
        require(0 <= begin <= end <= len(data), 'Transport anchor offset outside source bytes')
        require(begin < end or (len(data) == 0 and begin == end == 0),
                'Transport empty anchor allowed only for empty source')
        checked = {'source': name, 'span': [begin, end], 'sha256': sha(data[begin:end])}
        require(not stored or checked == item, 'Transport anchor digest mismatch')
        result.append(checked)
    return result


def collect_ids(plan: dict) -> set:
    names = set()
    groups = ('sources', 'interpretations', 'uncertainties')
    for group in groups + (('meaning_units',) if plan['schema'] == PLAN_V2 else ()):
        for item in plan[group]:
            require(type(item) is dict and 'id' in item, 'Transport record identifier missing')
            name = identifier(item['id'])
            require(name not in names, 'Transport globally duplicate identifier')
            names.add(name)
    return names


def check_interpretations(value: object, sources: dict, stored: bool) -> list:
    result = []
    for item in records(value, 32):
        fields(item, {'id', 'label', 'text', 'status', 'provenance', 'anchors'})
        identifier(item['id'])
        for key in ('label', 'text', 'provenance'):
            text(item[key])
        require(type(item['status']) is str and item['status'] in STATUSES,
                'Transport interpretation status must be proposed/disputed/withdrawn')
        result.append(dict(item, anchors=check_anchors(item['anchors'], sources, stored)))
    return result


def checked_references(value: object, names: set) -> list:
    records(value, 80)
    require(len(set(identifier(item) for item in value)) == len(value), 'Transport duplicate affected ID')
    require(all(item in names for item in value), 'Transport uncertainty references missing record')
    return value


def check_uncertainties(value: object, sources: dict, names: set, stored: bool) -> list:
    result = []
    for item in records(value, 32):
        fields(item, {'id', 'text', 'anchors', 'affects'})
        identifier(item['id'])
        text(item['text'])
        checked_references(item['affects'], names)
        result.append(dict(item, anchors=check_anchors(item['anchors'], sources, stored)))
    return result


def check_relations(value: object, sources: dict, names: set, stored: bool) -> list:
    result = []
    for item in records(value, 64):
        fields(item, {'kind', 'from', 'to', 'note', 'anchors'})
        require(type(item['kind']) is str and item['kind'] in RELATIONS, 'Transport unknown relation kind')
        require(identifier(item['from']) in names and identifier(item['to']) in names,
                'Transport relation references missing record')
        text(item['note'])
        result.append(dict(item, anchors=check_anchors(item['anchors'], sources, stored)))
    return result


def check_plan(data: bytes, sources: tuple[bytes, ...], stored: bool = False) -> dict:
    require(type(sources) is tuple and 1 <= len(sources) <= 16, 'Transport source tuple budget exceeded')
    require(all(type(item) is bytes for item in sources), 'Transport immutable original bytes required')
    require(sum(len(item) for item in sources) <= MAX_SOURCE, 'Transport aggregate source byte budget exceeded')
    plan = json_value(data, MAX_METADATA)
    require(type(plan) is dict and plan.get('schema') in (PLAN, PLAN_V2), 'Transport incompatible plan schema')
    fields(plan, {'schema', 'sources', 'interpretations', 'uncertainties', 'relations'} |
           ({'meaning_units'} if plan['schema'] == PLAN_V2 else set()))
    source_map = check_sources(plan['sources'], sources)
    records(plan['interpretations'], 32)
    records(plan['uncertainties'], 32)
    if plan['schema'] == PLAN_V2:
        records(plan['meaning_units'], semantics.MAX_UNITS, 1)
    names = collect_ids(plan)
    result = dict(plan)
    result['interpretations'] = check_interpretations(plan['interpretations'], source_map, stored)
    result['uncertainties'] = check_uncertainties(plan['uncertainties'], source_map, names, stored)
    result['relations'] = check_relations(plan['relations'], source_map, names, stored)
    if plan['schema'] == PLAN_V2:
        result['meaning_units'] = semantics.check_units(plan['meaning_units'], result, source_map, stored)
    require(len(canonical(result)) <= MAX_METADATA, 'Transport stored metadata byte budget exceeded')
    return result


def formula(plan: dict) -> bytes:
    groups = [','.join(item['id'] for item in plan['sources']),
              ','.join(item['id'] + ':' + item['status'] for item in plan['interpretations']),
              ','.join(item['id'] for item in plan['uncertainties']),
              ';'.join(item['from'] + ' ' + item['kind'] + ' ' + item['to'] for item in plan['relations'])]
    value = ' '.join(mark + '[' + (group or 'none') + ']'
                     for mark, group in zip(('Σ', 'I', 'U', 'R'), groups, strict=True))
    if plan['schema'] == PLAN_V2:
        value += semantics.display_units(plan['meaning_units'])
    return value.encode('utf-8')


def escaped(value: str) -> str:
    result = []
    for char in value:
        if not char.isprintable():
            result.append(('\\u' if ord(char) <= 0xffff else '\\U') + format(ord(char), '04x' if ord(char) <= 0xffff else '08x'))
        elif char in '`*_[]()#!|~':
            result.append('&#' + str(ord(char)) + ';')
        else:
            result.append(html.escape(char, quote=True))
    return ''.join(result)


def lexicon_lines(plan: dict) -> list[str]:
    lines = ['# Source-Anchored Semantic Transport lexicon.md', '', 'All metadata below are unverified declarations.',
             'Original bytes are retained. Binary media are retained, not understood.',
             'Anchors prove references to selected bytes only; they do not prove a reading.', '', '<pre>']
    for group in ('sources', 'interpretations', 'uncertainties', 'relations'):
        lines.append(group.upper())
        for item in plan[group]:
            for key in sorted(item):
                value = item[key]
                rendered = value if type(value) is str else canonical(value).decode('utf-8')
                lines.append(key + ': ' + html.escape(rendered, quote=False))
            lines.append('')
    lines += ['</pre>', '', 'Interpretation supplied: ' + ('YES' if plan['interpretations'] else 'NO'),
              'Coverage is a byte-reference report; no semantic completeness is claimed.', '', '## Fixed definitions', '']
    for mark, definition in DISPLAY.items():
        lines.append('- ' + mark + ': ' + definition)
    for kind, definition in RELATIONS.items():
        lines.append('- ' + kind + ': ' + definition)
    return lines


def lexicon(plan: dict) -> bytes:
    lines = lexicon_lines(plan)
    if plan['schema'] == PLAN_V2:
        lines += semantic_lines(plan['meaning_units'])
    lines += ['', '## Decoder and boundary', '',
              'Use the separately supplied Transport decoder and matching runtime; never execute archive content.',
              'This ZIP has exactly manifest.json, codec.json, index.json, formula.txt, README.md.',
              'README.md is this lexicon.md document; the separately returned lexicon bytes are identical.',
              'STS1 binds bytes and declarations, not author identity, truth, confidentiality or authority.',
              'No reference is fetched. Missing or incompatible external dependencies refuse before reconstruction.',
              ASSURANCE['runtime_boundary'], '']
    data = '\n'.join(lines).encode('utf-8')
    require(len(data) <= MAX_METADATA, 'Transport lexicon byte budget exceeded')
    return data


def dictionary_registry(units: list) -> tuple[dict, list]:
    require(type(units) is list and 1 <= len(units) <= 16, 'readable unit count bound')
    registry, projected = {}, []
    for unit in units:
        dictionaries = unit['dictionaries']
        require(type(dictionaries) is list and len(dictionaries) == 2, 'readable dictionary count bound')
        references = []
        for item in dictionaries:
            content = item['content']
            require(content is not None and reference(content, True) == item,
                    'readable dictionary reference differs from content')
            digest, raw = item['sha256'], canonical(content)
            require(digest not in registry or canonical(registry[digest]) == raw,
                    'conflicting readable dictionary content')
            registry[digest] = content
            references.append(reference(content, False))
        require(len(registry) <= 32, 'readable dictionary registry bound')
        projected.append(dict(unit, dictionaries=references))
    return registry, projected


def dictionary_lines(digest: str, content: dict) -> list[str]:
    if content['role'] == 'symbols':
        return symbol_dictionary_lines(digest, content)
    lines = ['### Dictionary SHA-256 ' + digest, '',
             'Role: ' + escaped(content['role']) + '; id: ' + escaped(content['id'])
             + '; version: ' + escaped(content['version']), '',
             '<pre data-transport-dictionary-sha256="' + digest + '">'
             + html.escape(canonical(content).decode('utf-8'), quote=False) + '</pre>', '']
    lines += ['| Operator | Argument types | Result | Exact definition |', '|---|---|---|---|']
    for name in sorted(content['entries']):
        definition = content['entries'][name]
        lines.append('| ' + ' | '.join(escaped(item) for item in
                     (name, ', '.join(definition['args']), definition['result'], definition['definition'])) + ' |')
    return lines + ['']


def symbol_dictionary_lines(digest: str, content: dict) -> list[str]:
    require(type(content['entries']) is dict and 1 <= len(content['entries']) <= 64,
            'readable symbol table count bound')
    attributes = [('data-transport-symbol-dictionary', digest), ('data-dictionary-schema', content['schema']),
                  ('data-dictionary-id', content['id']), ('data-dictionary-version', content['version'])]
    opening = '<table ' + ' '.join(key + '="' + html.escape(value, quote=True) + '"'
                                  for key, value in attributes) + '>'
    lines = ['### Symbol dictionary ' + escaped(content['id']) + '@' + escaped(content['version']), '', opening,
             '<tr><th>Symbol</th><th>Exact source literal (canonical JSON string)</th></tr>']
    for name in sorted(content['entries']):
        literal = canonical(content['entries'][name]).decode('utf-8')
        lines.append('<tr><td>' + html.escape(name, quote=False) + '</td><td><pre>'
                     + html.escape(literal, quote=False) + '</pre></td></tr>')
    return lines + ['</table>', '']


def semantic_lines(units: list) -> list[str]:
    registry, projected = dictionary_registry(units)
    lines = ['', '## Shared exact dictionary registry', '',
        'Each dictionary is indexed by the SHA-256 of its canonical UTF-8 JSON and appears once.',
        'Recovery: HTML-unescape marked operator pre blocks. For each marked symbol table, reconstruct',
        'schema/id/version from its exact attributes, role=symbols, and entries from its unique symbol rows;',
        'each row pre is one canonical JSON string literal. Reject unknown shape, duplicates, truncation or over 64 rows.',
        'Canonicalize each reconstructed dictionary and verify its SHA-256,',
        'then replace each unit dictionary reference content:null with the matching verified content.',
        'Check every reference id, version and role against that content. Missing, conflicting or altered entries refuse.',
        'Canonical serialization then recovers every original complete stored unit byte-for-byte.', '']
    for digest in sorted(registry):
        lines += dictionary_lines(digest, registry[digest])
    lines += ['', '## Typed meaning units', '',
        'Types and source occurrences are checked. Interpretation, completeness and context adequacy remain UNPROVEN.',
        'Historical approvals are evidence only. No unit grants current execution authority.', '']
    for unit in projected:
        lines += ['### ' + escaped(unit['id']) + ' / ' + escaped(unit['kind']), '',
            'Source: ' + escaped(unit['source']) + '; interpretation: ' + escaped(unit['interpretation']),
            'Declared context units: ' + ', '.join(escaped(name) for name in unit['context']), '',
            '<pre>', html.escape(semantics.display(unit['meaning']), quote=False), '</pre>', '',
            '<pre data-transport-unit="' + html.escape(unit['id'], quote=True) + '">'
            + html.escape(canonical(unit).decode('utf-8'), quote=False) + '</pre>', '']
    return lines


def coverage(plan: dict) -> dict:
    result = {item['id']: {'interpretation_spans': [], 'all_record_spans': []}
              for item in plan['sources']}
    for group in ('interpretations', 'uncertainties', 'relations'):
        for item in plan[group]:
            for anchor in item['anchors']:
                selected = result[anchor['source']]
                selected['all_record_spans'].append(anchor['span'])
                if group == 'interpretations':
                    selected['interpretation_spans'].append(anchor['span'])
    for selected in result.values():
        selected['interpretation_coverage'] = ('DECLARED_SPANS_ONLY' if selected['interpretation_spans'] else 'ABSENT')
        selected['reference_coverage'] = ('DECLARED_SPANS_ONLY' if selected['all_record_spans'] else 'ABSENT')
    report = {'interpretation_supplied': bool(plan['interpretations']), 'sources': result,
              'meaning': 'Declared spans only; overlaps retained; uncovered bytes and semantic completeness are not inferred.'}
    if plan['schema'] == PLAN_V2:
        report['typed_units'] = [{key: unit[key] for key in semantics.UNIT_KEYS}
                                 for unit in plan['meaning_units']]
        report['typed_assurance'] = dict(semantics.BOUNDARY)
    return report
