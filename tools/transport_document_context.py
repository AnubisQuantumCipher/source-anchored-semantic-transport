"""Separate source spans for bounded semantic intake; no interpretation authority.

The existing raw read_section concatenation contract is unchanged. This API
exposes boundaries rather than inserting separators into arbitrary source bytes.
"""
import transport_document as document
from transport_document_io import (MAX_SOURCE, canonical, identity, integer, need,
                                   open_regular, sha)

MAX_CONTEXT = 65_536
MAX_PARTS = 64
MAX_CONTEXT_META = 32_768


def checked_spans(sections, selected, source_bytes):
    need(type(selected) is str, 'context section identifier required')
    need(type(sections) is list and len(sections) <= MAX_PARTS, 'context section count')
    clean = [{key: value for key, value in row.items() if key != 'sha256'}
             for row in sections]
    document.sections_checked(clean, source_bytes)
    spans = document.dependency_spans(clean, selected)
    need(1 <= len(spans) <= MAX_PARTS, 'context part count')
    total = 0
    for start, end in spans:
        integer(start, 0, source_bytes)
        integer(end, start + 1, source_bytes)
        total += end - start
    need(total <= MAX_CONTEXT, 'semantic intake exceeds 65536-byte context bound')
    return spans


def read_parts(recovered, spans, source_bytes):
    parts, offset = [], 0
    with open_regular(recovered, MAX_SOURCE) as stream:
        before = identity(stream)
        need(before[2] == source_bytes, 'context source size changed')
        for start, end in spans:
            stream.seek(start)
            data = stream.read(end - start)
            need(len(data) == end - start, 'context part truncated')
            parts.append({'source_span': [start, end],
                          'output_span': [offset, offset + len(data)], 'data': data})
            offset += len(data)
        need(identity(stream) == before, 'context source descriptor changed')
    return parts


def context_result(parts, body, package_id, selected):
    sha(package_id)
    sha(body['source']['sha256'])
    gaps = [[left['source_span'][1], right['source_span'][0]]
            for left, right in zip(parts, parts[1:])]
    result = {'schema': 'transport/document-section-context/1',
              'package_id': package_id, 'source_sha256': body['source']['sha256'],
              'source_bytes': body['source']['bytes'], 'selected_section': selected,
              'selected_bytes': sum(len(part['data']) for part in parts),
              'parts': parts, 'gaps': gaps, 'gap_scope': 'BETWEEN_RETURNED_PARTS_ONLY',
              'interpretation': 'SOURCE_BYTES_ONLY_INTERPRETATION_UNPROVEN',
              'execution_authority': 'NONE'}
    metadata = dict(result, parts=[{key: value for key, value in part.items()
                                   if key != 'data'} for part in parts])
    need(len(canonical(metadata)) <= MAX_CONTEXT_META, 'context metadata bound')
    return result


def read_section_context(archive, share, section, native=None):
    """Recover verified context parts; output spans never imply source adjacency.

    Existing validated() reconstructs and checks the whole source first. Labels,
    share display suffixes and retrieval hints are not returned or interpreted.
    Hostile concurrent host control is not attested by descriptor-change checks.
    """
    with document.validated(archive, share, native) as (recovered, body, package_id, sections):
        integer(body['source']['bytes'], 0, MAX_SOURCE)
        spans = checked_spans(sections, section, body['source']['bytes'])
        parts = read_parts(recovered, spans, body['source']['bytes'])
        return context_result(parts, body, package_id, section)
