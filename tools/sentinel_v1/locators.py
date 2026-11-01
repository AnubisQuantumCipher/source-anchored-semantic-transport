"""Package-bound byte locators. Documentary coordinates never grant authority."""
from pathlib import Path
import transport_document as document
import transport_document_context as context
import transport_document_reading as reading
from transport_document_io import identity as file_identity, open_regular, read_file
from .common import (EDGES, JOB_BYTES, METADATA, REGISTRY, SentinelError, canonical,
                     digest, fields, hash_checked, integer, label, parse, require,
                     registry_snapshot)

__all__ = ('resolve_locator',)

LOCATOR_CAP = 64
REVISION_CAP = 8
LOCATOR_BYTES = 32_768
REVISION_BYTES = 4_096


def source_checked(value):
    fields(value, ('sha256', 'bytes', 'package_id'))
    hash_checked(value['sha256']); hash_checked(value['package_id'])
    integer(value['bytes'], 0, document.MAX_SOURCE)


def representation_checked(value):
    fields(value, ('kind', 'sha256', 'bytes', 'record_sha256'))
    require(value['kind'] in ('ORIGINAL', 'DERIVED_UTF8'), 'representation kind')
    hash_checked(value['sha256'])
    integer(value['bytes'], 0, document.MAX_SOURCE)
    if value['kind'] == 'ORIGINAL':
        require(value['record_sha256'] is None, 'original has no reading record')
    else:
        integer(value['bytes'], 0, reading.MAX_READING)
        hash_checked(value['record_sha256'])


def revision_checked(value):
    fields(value, ('id', 'artifact_sha256', 'previous_sha256'))
    label(value['id']); hash_checked(value['artifact_sha256'])
    if value['previous_sha256'] is not None:
        hash_checked(value['previous_sha256'])


def locator_checked(raw):
    value = parse(raw, LOCATOR_BYTES)
    fields(value, ('schema', 'id', 'source', 'representation', 'selector',
                   'dependencies', 'revision'))
    require(value['schema'] == 'sentinel/evidence-locator/1', 'locator schema')
    label(value['id']); source_checked(value['source'])
    representation_checked(value['representation']); revision_checked(value['revision'])
    deps = value['dependencies']
    require(type(deps) is list and len(deps) <= LOCATOR_CAP, 'dependency count/type')
    for key in deps:
        hash_checked(key)
    require(len(set(deps)) == len(deps), 'duplicate dependency')
    return value


def snapshots(locator_raw, expected, locators, held_locators, revisions, held_revisions):
    hash_checked(expected)
    require(type(locator_raw) is bytes and 0 < len(locator_raw) <= LOCATOR_BYTES,
            'locator byte bound')
    require(digest(locator_raw) == expected, 'locator pin')
    left = registry_snapshot(locators, held_locators)
    right = registry_snapshot(revisions, held_revisions)
    require(1 <= len(left) <= LOCATOR_CAP and 1 <= len(right) <= REVISION_CAP,
            'locator/revision registry count')
    require(sum(len(raw) for raw in left.values()) + sum(len(raw) for raw in right.values())
            <= REGISTRY, 'combined registry byte bound')
    require(left.get(expected) == locator_raw, 'root locator absent/different')
    require(all(len(raw) <= LOCATOR_BYTES for raw in left.values()), 'locator byte bound')
    require(all(len(raw) <= REVISION_BYTES for raw in right.values()), 'revision byte bound')
    return left, right


def revision_records(registry, root):
    records = {}
    for key, raw in registry.items():
        value = parse(raw, REVISION_BYTES)
        fields(value, ('schema', 'id', 'source_sha256', 'source_bytes', 'previous_sha256'))
        require(value['schema'] == 'sentinel/source-revision/1', 'revision schema')
        label(value['id']); hash_checked(value['source_sha256'])
        integer(value['source_bytes'], 0, document.MAX_SOURCE)
        if value['previous_sha256'] is not None:
            hash_checked(value['previous_sha256'])
        records[key] = value
    selected = root['revision']
    require(selected['artifact_sha256'] in records, 'missing selected revision')
    current = records[selected['artifact_sha256']]
    require(all(current[key] == selected[key] for key in ('id', 'previous_sha256')),
            'locator revision binding')
    require((current['source_sha256'], current['source_bytes']) ==
            (root['source']['sha256'], root['source']['bytes']), 'revision source binding')
    key, seen = selected['artifact_sha256'], set()
    for _ in range(REVISION_CAP):
        if key is None:
            break
        require(key in records and key not in seen, 'missing/cyclic revision predecessor')
        seen.add(key); key = records[key]['previous_sha256']
    require(key is None and seen == set(records), 'revision closure/overflow/extra')


def locator_records(registry, selected):
    records = {key: locator_checked(raw) for key, raw in registry.items()}
    root = records[selected]
    edges = 0
    for value in records.values():
        require(all(value[key] == root[key] for key in ('source', 'representation', 'revision')),
                'mixed source/representation/revision dependency')
        require(all(key in records for key in value['dependencies']), 'missing locator dependency')
        edges += len(value['dependencies'])
    require(edges <= EDGES, 'dependency edge bound')
    reached, pending = set(), [selected]
    for _ in range(LOCATOR_CAP):
        if not pending:
            break
        key = pending.pop(); reached.add(key)
        pending = sorted((set(pending) | set(records[key]['dependencies'])) - reached)
    require(not pending and reached == set(records), 'locator closure/unused artifact')
    done = set()
    for _ in range(LOCATOR_CAP):
        done.update(key for key, value in records.items() if set(value['dependencies']) <= done)
    require(done == set(records), 'cyclic locator dependencies')
    return records


def reading_metadata(recovered, body):
    require(body['reading'] is not None, 'reading representation absent')
    pin = body['entries']['reading.json']
    integer(pin['bytes'], 1, METADATA)
    raw = read_file(recovered.parent / 'reading.json', METADATA)
    require({'sha256': digest(raw), 'bytes': len(raw)} == pin, 'reading metadata entry binding')
    value = reading.record_checked(document.loads(raw), body['source']['sha256'])
    require((value['text_sha256'], value['text_bytes']) ==
            (body['reading']['sha256'], body['reading']['bytes']), 'reading text binding')
    return value


def package_binding(root, recovered, body, package_id):
    source = {'sha256': body['source']['sha256'], 'bytes': body['source']['bytes'],
              'package_id': package_id}
    source_checked(source)
    require(root['source'] == source, 'locator/package source mismatch')
    rep = root['representation']
    if rep['kind'] == 'ORIGINAL':
        expected = {'kind': 'ORIGINAL', 'sha256': source['sha256'],
                    'bytes': source['bytes'], 'record_sha256': None}
        path, record = recovered, None
    else:
        record = reading_metadata(recovered, body)
        expected = {'kind': 'DERIVED_UTF8', 'sha256': record['text_sha256'],
                    'bytes': record['text_bytes'],
                    'record_sha256': body['entries']['reading.json']['sha256']}
        path = recovered.parent / 'reading.txt'
    require(rep == expected, 'locator/package representation mismatch')
    return path, record


def byte_span(selector, size):
    start = integer(selector['start'], 0, size)
    end = integer(selector['end'], start + 1, size)
    require(end - start <= JOB_BYTES, 'selected span bound')
    hash_checked(selector['quote_sha256'])
    return start, end


def unsupported_selector(selector):
    kind = selector['kind']
    if kind == 'PAGE_REGION':
        fields(selector, ('kind', 'page', 'coordinate_system', 'box', 'mapping_sha256'))
        integer(selector['page'], 1, 16_384)
        require(selector['coordinate_system'] in ('PIXELS_TOP_LEFT', 'POINTS_TOP_LEFT'),
                'spatial coordinate system')
        box = selector['box']
        require(type(box) is list and len(box) == 4, 'spatial box shape')
        for coordinate in box:
            integer(coordinate, 0, 2 ** 31 - 1)
        require(box[0] < box[2] and box[1] < box[3], 'spatial box order')
    else:
        fields(selector, ('kind', 'object_id', 'mapping_sha256'))
        label(selector['object_id'])
    hash_checked(selector['mapping_sha256'])


def page_span(selector, record, size):
    fields(selector, ('kind', 'segment_id', 'page', 'start', 'end', 'quote_sha256'))
    label(selector['segment_id']); integer(selector['page'], 1, 16_384)
    span = byte_span(selector, size)
    matches = [s for s in record['segments'] if s['id'] == selector['segment_id']]
    require(len(matches) == 1, 'unknown page segment')
    row = matches[0]
    require(row['kind'] == 'page' and row['source_locator'] == {'page': selector['page']},
            'declared page identity')
    require(row['start'] <= span[0] < span[1] <= row['end'], 'page segment extent')
    return span


def selector_spans(node, sections, record):
    selector, rep = node['selector'], node['representation']
    require(type(selector) is dict and type(selector.get('kind')) is str, 'selector shape')
    kind = selector['kind']
    if kind in ('PAGE_REGION', 'TABLE', 'FIGURE'):
        unsupported_selector(selector)
        return None
    if kind == 'SECTION':
        fields(selector, ('kind', 'section_id')); label(selector['section_id'])
        require(rep['kind'] == 'ORIGINAL', 'section representation')
        return context.checked_spans(sections, selector['section_id'], node['source']['bytes'])
    if kind == 'PAGE_TEXT':
        require(rep['kind'] == 'DERIVED_UTF8', 'page representation')
        return [page_span(selector, record, rep['bytes'])]
    require(kind in ('SOURCE_BYTES', 'DERIVED_UTF8', 'CODE_BYTES'), 'unsupported selector tag')
    names = ('kind', 'start', 'end', 'quote_sha256')
    fields(selector, names + (('language',) if kind == 'CODE_BYTES' else ()))
    if kind == 'CODE_BYTES':
        label(selector['language'])
    expected = 'DERIVED_UTF8' if kind == 'DERIVED_UTF8' else 'ORIGINAL'
    require(rep['kind'] == expected, 'selector representation')
    return [byte_span(selector, rep['bytes'])]


def selected_spans(records, sections, record):
    spans, selections, unsupported = set(), [], False
    for key in sorted(records):
        node = records[key]
        selected = selector_spans(node, sections, record)
        unsupported = unsupported or selected is None
        selections.append((key, node['selector'], selected))
        for span in selected or ():
            spans.add(tuple(span))
            require(len(spans) <= LOCATOR_CAP, 'distinct selected interval bound')
    merged = []
    for start, end in sorted(spans):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    require(sum(end - start for start, end in merged) <= JOB_BYTES, 'aggregate selected byte bound')
    return merged, selections, unsupported


def selected_parts(path, spans, size, derived):
    parts = []
    with open_regular(path, document.MAX_SOURCE) as stream:
        before = file_identity(stream)
        require(before[2] == size, 'representation file size changed')
        for start, end in spans:
            stream.seek(start); data = stream.read(end - start)
            require(len(data) == end - start, 'selected part truncated')
            if derived:
                data.decode('utf-8', errors='strict')
            parts.append({'span': [start, end], 'data': data, 'sha256': digest(data)})
        require(file_identity(stream) == before, 'representation descriptor changed')
    return parts


def checked_quotes(parts, selections, derived):
    for _key, selector, spans in selections:
        if 'quote_sha256' not in selector:
            continue
        start, end = spans[0]
        containing = [p for p in parts if p['span'][0] <= start and end <= p['span'][1]]
        require(len(containing) == 1, 'selected quote not in final parts')
        part = containing[0]
        data = part['data'][start - part['span'][0]:end - part['span'][0]]
        require(digest(data) == selector['quote_sha256'], 'selected quote mismatch')
        if derived:
            data.decode('utf-8', errors='strict')


def result_for(root, expected, records, parts, unsupported):
    metadata = []
    for key in sorted(records):
        node = records[key]; selector = node['selector']
        row = {'locator_sha256': key, 'id': node['id'], 'kind': selector['kind']}
        if selector['kind'] == 'PAGE_TEXT':
            row.update(page=selector['page'], segment_id=selector['segment_id'])
        metadata.append(row)
    result = {'schema': 'sentinel/evidence-resolution/1',
        'status': 'UNSUPPORTED' if unsupported else 'RESOLVED_BYTES',
        'locator_sha256': expected, 'package_id': root['source']['package_id'],
        'source': root['source'], 'representation': root['representation'],
        'coordinate_kind': 'SOURCE_BYTE' if root['representation']['kind'] == 'ORIGINAL'
                           else 'DERIVED_UTF8_BYTE', 'revision': root['revision'],
        'dependency_locator_sha256s': sorted(set(records) - {expected}), 'parts': parts,
        'gaps': [[a['span'][1], b['span'][0]] for a, b in zip(parts, parts[1:])],
        'gap_scope': 'BETWEEN_RETURNED_PARTS_ONLY',
        'selected_bytes': sum(len(p['data']) for p in parts), 'selector_metadata': metadata,
        'execution_authority': 'NONE', 'qualification': 'NOT_QUALIFIED',
        'interpretation': 'UNPROVEN', 'OCR_accuracy': 'UNPROVEN',
        'semantic_completeness': 'UNPROVEN', 'context_adequacy': 'UNPROVEN'}
    if any(row['kind'] == 'PAGE_TEXT' for row in metadata):
        result['page_mapping'] = 'DECLARED_PAGE_TEXT_NOT_VISUALLY_ADJUDICATED'
    clean = dict(result, parts=[{k: v for k, v in p.items() if k != 'data'} for p in parts])
    require(len(canonical(clean)) <= METADATA, 'result metadata bound')
    return result


def _resolve_bound(recovered, body, package_id, sections, expected, left, right):
    records = locator_records(left, expected)
    root = records[expected]
    revision_records(right, root)
    path, record = package_binding(root, Path(recovered), body, package_id)
    spans, selections, unsupported = selected_spans(records, sections, record)
    parts = []
    if not unsupported:
        derived = root['representation']['kind'] == 'DERIVED_UTF8'
        parts = selected_parts(path, spans, root['representation']['bytes'], derived)
        checked_quotes(parts, selections, derived)
    return result_for(root, expected, records, parts, unsupported)


def resolve_locator(archive, share, locator_raw, expected_locator_sha256, locator_registry,
                    expected_locator_registry_sha256, revision_registry,
                    expected_revision_registry_sha256, native=None):
    """Resolve complete same-space dependency closure through validated package bytes."""
    try:
        left, right = snapshots(locator_raw, expected_locator_sha256, locator_registry,
                                expected_locator_registry_sha256, revision_registry,
                                expected_revision_registry_sha256)
        with document.validated(archive, share, native) as (recovered, body, package_id, sections):
            return _resolve_bound(recovered, body, package_id, sections,
                                  expected_locator_sha256, left, right)
    except (ValueError, OSError, UnicodeError, KeyError, TypeError) as error:
        if isinstance(error, SentinelError):
            raise
        raise SentinelError('locator evidence refused: ' + str(error)[:256]) from error
