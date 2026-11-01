"""Bounded paragraph anchors for a complete admitted generation application.

Anchors locate source bytes; they assert neither interpretation nor authority.
The historical host catalogs retain their original versioned contracts.
"""
from sentinel_v1 import document_analysis as document
from sentinel_v1.common import JOB_BYTES, canonical, digest, parse, require

PROFILE = 'sentinel/source-anchor-catalog/1'
CATALOG_BYTES = 10000


def build(request, prompt, reading):
    """Derive all anchors, or refuse before publishing an incomplete catalog."""
    require(all(type(raw) is bytes and 0 < len(raw) <= JOB_BYTES
                for raw in (request, prompt, reading)), 'catalog application byte bound')
    document.generation_message({'request': request, 'prompt': prompt, 'reading': reading})
    value = parse(request, JOB_BYTES)
    sources = value['source_set']
    require(len(sources) == 1, 'catalog requires one declared reading window')
    window = sources[0]['window']
    left, right = window['start'], window['end']
    require(type(left) is int and type(right) is int and 0 <= left < right
            and right - left == len(reading) and window['sha256'] == digest(reading),
            'catalog reading window differs')
    identifiers = value['paragraph_ids']
    require(len(set(identifiers)) == len(identifiers), 'catalog duplicate paragraph identity')
    spans = document.paragraph_spans(reading)
    require(len(spans) == len(identifiers), 'catalog paragraph accounting differs')
    result = {'schema': PROFILE, 'job_id': value['job_id'],
        'coordinate_system': 'FULL_READING_UTF8_BYTES', 'window': [left, right],
        'reading': value['reading_pin'], 'anchors': []}
    used = len(canonical(result))
    require(used <= CATALOG_BYTES, 'catalog metadata byte bound')
    for ordinal, (start, end) in enumerate(spans):
        row = {'id': identifiers[ordinal], 'start': left + start, 'end': left + end,
               'quote_sha256': digest(reading[start:end])}
        used += len(canonical(row)) + (1 if ordinal else 0)
        require(used <= CATALOG_BYTES, 'complete catalog byte bound; no partial output')
        result['anchors'].append(row)
    raw = canonical(result)
    require(len(raw) == used and len(raw) <= CATALOG_BYTES, 'catalog serialization bound')
    return raw


def checked(raw, request, prompt, reading):
    """Reject any changed roster, coordinates, quote, profile or representation."""
    require(type(raw) is bytes and 0 < len(raw) <= CATALOG_BYTES,
            'catalog immutable byte bound')
    require(raw == build(request, prompt, reading), 'catalog differs from complete application')
    return raw
