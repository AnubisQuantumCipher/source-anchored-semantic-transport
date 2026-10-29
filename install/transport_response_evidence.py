"""Bounded source-byte citation checks; no entailment, authority or context inference.

The caller establishes ``held`` independently and binds the declared structural
contract digest to the structural contract it actually validates. This module
only checks data. The host, Python parser and imported helpers remain trusted.
"""

import re

from transport_handoff_inputs import ID, CANDIDATE_CAP, digest, fields, json_value
from transport_install_support import canonical, require, sha

SCHEMA = 'transport/response-evidence-contract/1'
CONTRACT_CAP, MAX_VALUES, MAX_DEPTH = 8192, 1024, 8
CONTRACT_BYTES = CONTRACT_CAP
MAX_SELECTORS, MAX_TOKENS, MAX_SELECTED, MAX_WORK = 16, 8, 64, 1024
MAX_SOURCES, SOURCE_BYTES, QUOTE_BYTES = 16, 65536, 4096
FIELD = re.compile(r'[a-z][a-z0-9_]{0,63}\Z')
CITATION_FIELDS = ('source_id', 'source_sha256', 'start', 'end', 'quote')


def safe_json(raw, cap):
    require(type(raw) is bytes and 0 < len(raw) <= cap, 'JSON byte bound')
    text = raw.decode('utf-8', errors='strict')
    require(not text.startswith('\ufeff') and '\0' not in text, 'UTF-8 JSON without BOM or NUL required')
    value = json_value(raw, cap)
    pending, visited = [(value, 1)], 0
    for _ in range(MAX_VALUES):
        if not pending:
            break
        item, depth = pending.pop()
        visited += 1
        require(depth <= MAX_DEPTH, 'JSON value depth bound')
        if type(item) in (dict, list):
            require(len(item) <= 128, 'JSON container bound')
            if type(item) is dict:
                require(all('\0' not in key and len(key.encode('utf-8')) <= 128 for key in item), 'JSON key bound')
            children = item.values() if type(item) is dict else item
            require(visited + len(pending) + len(item) <= MAX_VALUES, 'JSON value count bound')
            pending.extend((child, depth + 1) for child in children)
        elif type(item) is str:
            require('\0' not in item and len(item.encode('utf-8')) <= QUOTE_BYTES, 'JSON string bound')
        elif type(item) is int:
            require(-(2 ** 63) <= item < 2 ** 63, 'JSON integer bound')
        else:
            require(item is None or type(item) is bool, 'finite safe JSON scalar required')
    require(not pending, 'JSON traversal bound')
    return value


def compile_contract(raw):
    value = safe_json(raw, CONTRACT_CAP)
    fields(value, ('schema', 'description', 'response_contract_sha256', 'selectors'))
    require(value['schema'] == SCHEMA, 'unsupported evidence-contract schema')
    require(type(value['description']) is str and 1 <= len(value['description'].encode('utf-8')) <= 1024,
            'evidence-contract description bound')
    digest(value['response_contract_sha256'])
    selectors, seen = value['selectors'], set()
    require(type(selectors) is list and 1 <= len(selectors) <= MAX_SELECTORS, 'selector count bound')
    for selector in selectors:
        require(type(selector) is list and 1 <= len(selector) <= MAX_TOKENS, 'selector token count bound')
        require(all(type(token) is str and (token == '*' or FIELD.fullmatch(token) is not None)
                    for token in selector), 'unsupported selector token')
        path = tuple(selector)
        require(path not in seen, 'duplicate evidence selector')
        seen.add(path)
    return value


def source_pins(sources, held):
    require(type(sources) is dict and 1 <= len(sources) <= MAX_SOURCES, 'source count bound')
    require(type(held) is dict and len(held) == len(sources) and set(held) == set(sources),
            'held source identifiers differ')
    pins, total = {}, 0
    for name, raw in sources.items():
        require(type(name) is str and ID.fullmatch(name) is not None, 'invalid source identifier')
        require(type(raw) is bytes and len(raw) <= SOURCE_BYTES, 'source byte bound')
        total += len(raw)
        require(total <= SOURCE_BYTES, 'aggregate source byte bound')
        expected = digest(held[name])
        require(sha(raw) == expected, 'source differs from externally held digest')
        pins[name] = expected
    return pins


def selected(value, selectors):
    """Visit at most MAX_WORK selector states, retaining at most MAX_SELECTED paths."""
    results, seen, work = [], set(), 0
    for selector in selectors:
        pending, matches = [(value, (), 0)], 0
        for _ in range(MAX_WORK):
            if not pending:
                break
            item, path, position = pending.pop()
            work += 1
            require(work <= MAX_WORK, 'selector work bound')
            if position == len(selector):
                require(type(item) is dict, 'selector must resolve to citation object')
                require(path not in seen, 'duplicate selected candidate path')
                require(len(results) < MAX_SELECTED, 'selected citation count bound')
                seen.add(path)
                results.append((path, item))
                matches += 1
            else:
                token = selector[position]
                if token == '*':
                    require(type(item) is list and 1 <= len(item) <= MAX_SELECTED, 'wildcard requires bounded nonempty list')
                    more = [(child, path + (index,), position + 1) for index, child in enumerate(item)]
                else:
                    require(type(item) is dict and token in item, 'selector field missing or not an object')
                    more = [(item[token], path + (token,), position + 1)]
                require(work + len(pending) + len(more) <= MAX_WORK, 'selector pending work bound')
                pending.extend(reversed(more))
        require(not pending and matches > 0, 'unused selector or traversal bound')
    return results


def link(path, citation, sources, pins):
    fields(citation, CITATION_FIELDS)
    name = citation['source_id']
    require(type(name) is str and ID.fullmatch(name) is not None and name in sources, 'citation source missing or invalid')
    require(digest(citation['source_sha256']) == pins[name], 'citation source revision differs')
    start, end = citation['start'], citation['end']
    require(type(start) is int and type(end) is int and 0 <= start < end <= len(sources[name]),
            'citation requires nonempty half-open byte span')
    quote = citation['quote']
    require(type(quote) is str, 'citation quote requires UTF-8 text')
    raw = quote.encode('utf-8', errors='strict')
    require(1 <= len(raw) <= QUOTE_BYTES, 'citation quote byte bound')
    require(raw == sources[name][start:end], 'citation quote differs from source byte span')
    return dict(candidate_path=list(path), source_id=name, source_sha256=pins[name],
                start=start, end=end, quote_sha256=sha(raw))


def validate(candidate: bytes, contract_raw: bytes, sources: dict[str, bytes], held: dict[str, str]) -> dict:
    contract = compile_contract(contract_raw)
    value = safe_json(candidate, CANDIDATE_CAP)
    pins = source_pins(sources, held)
    records = [link(path, citation, sources, pins) for path, citation in selected(value, contract['selectors'])]
    return dict(status='SOURCE_SPANS_MATCH', candidate_sha256=sha(candidate),
                evidence_contract_sha256=sha(contract_raw), response_contract_sha256=contract['response_contract_sha256'],
                selected_records=len(records), links_sha256=sha(canonical(dict(records=records))),
                scope='DECLARED_CANDIDATE_CITATIONS_ONLY', semantics='NOT_ASSESSED',
                context_adequacy='UNPROVEN', execution_authority='NONE')
