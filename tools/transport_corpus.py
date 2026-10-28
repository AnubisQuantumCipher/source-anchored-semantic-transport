"""Inspect bounded, source-linked requirement proposals without semantic acceptance."""

import hashlib
import json
import os
import re
import stat
from pathlib import Path

from transport_graph import TIME_UNITS, inspect_path, parse
from transport_wire import MAX_SOURCE, TransportError

MAX_DOCUMENT = 1_048_576
KEYWORDS = {'MUST': 'shall', 'MUST NOT': 'shall_not', 'RECOMMENDED': 'should', 'MAY': 'may'}
FIELDS = ('identifier', 'actor', 'trigger', 'action', 'deadline', 'exception',
          'domain', 'time', 'assumptions', 'source')
PATHS = ('1', '2', '3', '4', '5', '6', '7.1', '7.2', '7.3', '8')
OPERATORS = ('text', 'name', 'atom', 'atom', 'timing', 'atom', 'text', 'text', 'text', 'text')


def exact_keys(value: object, keys: tuple[str, ...]) -> dict:
    if not isinstance(value, dict) or set(value) != set(keys):
        raise TransportError('corpus object fields do not match its schema')
    return value


def string(value: object, cap: int = 4096) -> str:
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > cap:
        raise TransportError('invalid or oversized corpus string')
    return value


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    if len(pairs) > 32:
        raise TransportError('corpus object field budget exceeded')
    result = {}
    for key, value in pairs:
        if key in result:
            raise TransportError('duplicate corpus object key')
        result[key] = value
    return result


def source_record(value: object) -> dict:
    source = exact_keys(value, ('document', 'url', 'file', 'sha256', 'bytes',
                                'retrieved_utc', 'section'))
    for key in ('document', 'url', 'file', 'sha256', 'retrieved_utc', 'section'):
        string(source[key], 2048)
    if re.fullmatch(r'RFC[1-9][0-9]{0,4}', source['document']) is None:
        raise TransportError('this corpus profile requires an explicit RFC identity')
    expected = 'rfc' + source['document'][3:] + '.txt'
    if source['file'] != expected or source['url'] != 'https://www.rfc-editor.org/rfc/' + expected:
        raise TransportError('RFC source location/identity mismatch')
    if re.fullmatch(r'[0-9a-f]{64}', source['sha256']) is None:
        raise TransportError('invalid document hash')
    if type(source['bytes']) is not int or not 0 < source['bytes'] <= MAX_DOCUMENT:
        raise TransportError('document budget exceeded')
    return source


def span_record(value: object, size: int) -> dict:
    span = exact_keys(value, ('start', 'text'))
    text = string(span['text'])
    start = span['start']
    if type(start) is not int or not 0 <= start <= size:
        raise TransportError('invalid source span start')
    if len(text.encode('utf-8')) > size - start:
        raise TransportError('source span exceeds document')
    return span


def read_document(path: Path) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise TransportError('source snapshot must be a regular file')
        data = stream.read(MAX_DOCUMENT + 1)
    if len(data) > MAX_DOCUMENT:
        raise TransportError('source snapshot budget exceeded')
    return data


def verify_source(source: dict, spans: tuple[dict, ...], directory: Path | None) -> str:
    if directory is None:
        return 'NOT_CHECKED'
    data = read_document(directory / source['file'])
    if len(data) != source['bytes'] or hashlib.sha256(data).hexdigest() != source['sha256']:
        raise TransportError('source snapshot identity mismatch')
    for span in spans:
        start, expected = span['start'], span['text'].encode('utf-8')
        if data[start:start + len(expected)] != expected:
            raise TransportError('source span does not match snapshot bytes')
    return 'SNAPSHOT_BYTES_CHECKED'


def inspect_proposal(case: dict, quote: str, keyword: str) -> dict:
    mapping = exact_keys(case['mapping'], FIELDS)
    for value in mapping.values():
        string(value)
    if mapping['identifier'] != case['id'] or mapping['source'] != quote:
        raise TransportError('proposal identifier or source binding mismatch')
    if mapping['deadline'] != 'unspecified':
        raise TransportError('this corpus proposal lane has no executable timing semantics')
    data = string(case['graph'], MAX_SOURCE).encode('utf-8')
    nodes, root = parse(data)
    if nodes[root].op != KEYWORDS[keyword]:
        raise TransportError('proposed modality disagrees with declared source keyword')
    observations = {}
    for field, path, operator in zip(FIELDS, PATHS, OPERATORS, strict=True):
        found = inspect_path(data, path)
        if not found['present'] or found['operator'] != operator or found['literal'] != mapping[field]:
            raise TransportError('proposal field binding mismatch: ' + field)
        observations[field] = {'path': path, 'operator': operator, 'literal': found['literal']}
    return {'profile_status': 'PROPOSAL_BINDINGS_CHECKED', 'modality': nodes[root].op,
            'graph_sha256': hashlib.sha256(data).hexdigest(), 'fields': observations}


def inspect_residual(case: dict) -> dict:
    if case['graph'] is not None or case['mapping'] is not None:
        raise TransportError('residual-only case cannot carry an interpreted requirement graph')
    timing = exact_keys(case['timing'], ('relation', 'amount', 'unit'))
    relation = string(timing['relation'], 16)
    amount = string(timing['amount'], 20)
    unit = string(timing['unit'], 8)
    if relation not in ('lt', 'le', 'eq', 'gt', 'ge') or unit not in TIME_UNITS:
        raise TransportError('unrecognized residual timing relation/unit')
    if re.fullmatch(r'(0|[1-9][0-9]{0,8})(\.[0-9]{1,9})?', amount) is None:
        raise TransportError('invalid residual timing amount spelling')
    return {'profile_status': 'RESIDUAL_ONLY', 'reason': 'TIMING_INTERPRETATION_UNAVAILABLE',
            'retained_timing': timing}


def inspect_case(value: object, directory: Path | None) -> dict:
    case = exact_keys(value, ('id', 'source', 'quote', 'keyword', 'context', 'disposition',
                              'mapping', 'graph', 'timing', 'residuals'))
    if re.fullmatch(r'[A-Z][A-Z0-9_-]{0,63}', string(case['id'], 64)) is None:
        raise TransportError('invalid corpus case identifier')
    source = source_record(case['source'])
    quote = span_record(case['quote'], source['bytes'])
    keyword = span_record(case['keyword'], source['bytes'])
    if keyword['text'] not in KEYWORDS:
        raise TransportError('unrecognized declared normative keyword')
    string(case['context'])
    residuals = case['residuals']
    if not isinstance(residuals, list) or not 1 <= len(residuals) <= 8:
        raise TransportError('explicit residuals are required within the corpus budget')
    for residual in residuals:
        string(residual)
    binding = verify_source(source, (quote, keyword), directory)
    if case['disposition'] == 'proposal':
        if case['timing'] != {'relation': 'unspecified'}:
            raise TransportError('unsupported timing must remain residual-only')
        result = inspect_proposal(case, quote['text'], keyword['text'])
    elif case['disposition'] == 'residual':
        result = inspect_residual(case)
    else:
        raise TransportError('unrecognized corpus disposition')
    result.update(id=case['id'], source=source, source_binding=binding,
                  context=case['context'], residuals=residuals,
                  source_excerpt=quote['text'], semantic_acceptance='UNPROVEN')
    return result


def inspect_corpus(data: bytes, directory: Path | None = None) -> dict:
    if len(data) > MAX_SOURCE:
        raise TransportError('corpus frame budget exceeded')
    try:
        document = json.loads(data.decode('utf-8'), object_pairs_hook=unique_object)
        document = exact_keys(document, ('schema', 'cases'))
        cases = document['cases']
        if document['schema'] != 'transport-requirements-corpus/1' or not isinstance(cases, list):
            raise TransportError('invalid corpus schema')
        if not 1 <= len(cases) <= 8:
            raise TransportError('corpus case budget exceeded')
        results, identifiers = [], set()
        for case in cases:
            result = inspect_case(case, directory)
            if result['id'] in identifiers:
                raise TransportError('duplicate corpus requirement identifier')
            identifiers.add(result['id'])
            results.append(result)
        return {'status': 'CORPUS_INSPECTED', 'semantic_acceptance': 'UNPROVEN',
                'corpus_sha256': hashlib.sha256(data).hexdigest(), 'cases': results}
    except (UnicodeError, ValueError, TypeError, RecursionError) as error:
        raise TransportError('malformed corpus: ' + str(error)[:160]) from error
