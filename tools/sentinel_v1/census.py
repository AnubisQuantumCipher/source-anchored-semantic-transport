"""Bounded, paragraph-preserving operational census; never semantic acceptance."""
from .common import (EDGES, JOB_BYTES, METADATA, NODES, SentinelError, canonical, digest, fields,
                     hash_checked, identity, integer, label, parse, require)

MAX_READING = 33_554_432
MAX_PARAGRAPHS = 4096
MAX_SHARDS = 512
MAX_SOURCE = 1_073_741_824


def binding_checked(value):
    fields(value, ('source', 'revision', 'representation'))
    source, revision, representation = (value[key] for key in
                                         ('source', 'revision', 'representation'))
    fields(source, ('sha256', 'bytes', 'package_id'))
    hash_checked(source['sha256']); hash_checked(source['package_id'])
    integer(source['bytes'], 0, MAX_SOURCE)
    fields(revision, ('id', 'artifact_sha256', 'previous_sha256'))
    label(revision['id']); hash_checked(revision['artifact_sha256'])
    if revision['previous_sha256'] is not None:
        hash_checked(revision['previous_sha256'])
    fields(representation, ('kind', 'sha256', 'bytes', 'record_sha256'))
    hash_checked(representation['sha256'])
    integer(representation['bytes'], 0, MAX_SOURCE)
    require(representation['kind'] in ('ORIGINAL', 'DERIVED_UTF8'), 'representation kind')
    if representation['kind'] == 'ORIGINAL':
        require(representation['sha256'] == source['sha256']
                and representation['bytes'] == source['bytes']
                and representation['record_sha256'] is None, 'original identity mismatch')
    else:
        hash_checked(representation['record_sha256'])
        integer(representation['bytes'], 0, MAX_READING)
    return value


def paragraphs(reading):
    """Partition all bytes at literal blank lines; keep each delimiter intact."""
    result, cursor = [], 0
    lf, crlf = reading.find(b'\n\n'), reading.find(b'\r\n\r\n')
    for _ in range(MAX_PARAGRAPHS):
        if cursor == len(reading):
            return result
        choices = [(position, width) for position, width in ((lf, 2), (crlf, 4))
                   if position >= 0]
        end = min(choices)[0] + min(choices)[1] if choices else len(reading)
        result.append((cursor, end))
        cursor = end
        if 0 <= lf < cursor:
            lf = reading.find(b'\n\n', cursor)
        if 0 <= crlf < cursor:
            crlf = reading.find(b'\r\n\r\n', cursor)
    require(cursor == len(reading), 'paragraph count bound')
    return result


def acyclic(names, edges):
    require(len(names) <= MAX_PARAGRAPHS and len(edges) <= EDGES, 'DAG bound')
    pending = set(names)
    for _ in range(len(names)):
        ready = {name for name in pending if not any(
            left == name and right in pending for left, right in edges)}
        if not pending:
            return
        require(bool(ready), 'cyclic dependency')
        pending.difference_update(ready)
    require(not pending, 'cyclic dependency')


def hierarchy_checked(raw, size, spans):
    value = ([{'id': 'DOCUMENT', 'parent': None, 'kind': 'DOCUMENT', 'start': 0, 'end': size}]
             if raw is None else parse(raw))
    require(type(value) is list and 1 <= len(value) <= NODES, 'hierarchy region bound')
    boundaries = {0, size} | {point for span in spans for point in span}
    seen, levels, siblings = {}, {}, {}
    for index, row in enumerate(value):
        fields(row, ('id', 'parent', 'kind', 'start', 'end'))
        name = label(row['id'])
        require(name not in seen, 'duplicate region')
        integer(row['start'], 0, size); integer(row['end'], row['start'], size)
        require(row['start'] in boundaries and row['end'] in boundaries,
                'hierarchy splits intact paragraph')
        if index == 0:
            require(row == {'id': name, 'parent': None, 'kind': 'DOCUMENT',
                            'start': 0, 'end': size}, 'document root must cover reading')
            levels[name] = 0
        else:
            require(row['kind'] in ('CHAPTER', 'SECTION', 'DIVISION'), 'hierarchy kind')
            parent = label(row['parent'])
            require(parent in seen and row['start'] < row['end'], 'missing parent or empty region')
            require(seen[parent]['start'] <= row['start'] < row['end'] <= seen[parent]['end'],
                    'region outside parent')
            require(all(row['end'] <= old['start'] or old['end'] <= row['start']
                        for old in siblings.get(parent, [])), 'overlapping sibling regions')
            siblings.setdefault(parent, []).append(row)
            levels[name] = levels[parent] + 1
        seen[name] = row
    return value, levels


def dependencies_checked(raw, regions):
    value = [] if raw is None else parse(raw)
    require(type(value) is list and len(value) <= EDGES, 'context dependency bound')
    names, seen = {row['id'] for row in regions}, set()
    for row in value:
        fields(row, ('from', 'to'))
        left, right = label(row['from']), label(row['to'])
        require(left in names and right in names and left != right, 'context dependency target')
        require((left, right) not in seen, 'duplicate context dependency')
        seen.add((left, right))
    acyclic(names, seen)
    return value


def paragraph_units(reading, spans, regions, levels):
    units = []
    for index, (start, end) in enumerate(spans):
        containers = [row['id'] for row in regions
                      if row['start'] <= start and end <= row['end']]
        region = max(containers, key=lambda name: levels[name])
        units.append({'id': 'P%04d' % (index + 1), 'span': [start, end],
                      'sha256': digest(reading[start:end]), 'region_id': region,
                      'status': 'PENDING' if end - start <= JOB_BYTES else 'OPAQUE'})
    return units


def dependency_regions(selected, dependencies, regions):
    parents = {row['id']: row['parent'] for row in regions}
    reached, pending = set(), {selected}
    for _ in range(NODES):
        if not pending:
            return sorted(reached - {selected})
        current = pending.pop()
        reached.add(current)
        next_names = {row['to'] for row in dependencies if row['from'] == current}
        if parents[current] is not None:
            next_names.add(parents[current])
        pending.update(next_names - reached)
    require(not pending, 'context closure region bound')
    return sorted(reached - {selected})


def shard_record(reading, units, dependencies, regions, binding_sha256, index):
    start, end = units[0]['span'][0], units[-1]['span'][1]
    record = {'id': 'SHARD%04d' % index, 'span': [start, end],
              'binding_sha256': binding_sha256,
              'context_sha256': digest(canonical({'regions': regions, 'dependencies': dependencies})),
              'identity': identity(reading[start:end]),
              'paragraph_ids': [row['id'] for row in units],
              'region_id': units[0]['region_id'], 'status': 'PENDING',
              'dependency_regions': dependency_regions(units[0]['region_id'], dependencies, regions)}
    record['receipt_sha256'] = digest(canonical(record))
    return record


def shards(reading, units, dependencies, regions, binding_sha256):
    result, group = [], []
    for unit in units:
        if group and (unit['status'] != 'PENDING' or unit['region_id'] != group[0]['region_id']
                      or unit['span'][1] - group[0]['span'][0] > JOB_BYTES):
            require(len(result) < MAX_SHARDS, 'shard count bound')
            result.append(shard_record(reading, group, dependencies, regions, binding_sha256,
                                       len(result) + 1))
            group = []
        if unit['status'] == 'PENDING':
            group.append(unit)
    if group:
        require(len(result) < MAX_SHARDS, 'shard count bound')
        result.append(shard_record(reading, group, dependencies, regions, binding_sha256,
                                   len(result) + 1))
    return result


def build_census(reading, binding_raw, hierarchy_raw=None, dependencies_raw=None):
    require(type(reading) is bytes and len(reading) <= MAX_READING, 'immutable reading byte bound')
    try:
        reading.decode('utf-8')
    except UnicodeError as error:
        raise SentinelError('census reading requires UTF8') from error
    binding = binding_checked(parse(binding_raw))
    representation = binding['representation']
    require(identity(reading) == {'sha256': representation['sha256'],
                                 'bytes': representation['bytes']}, 'reading identity mismatch')
    spans = paragraphs(reading)
    regions, levels = hierarchy_checked(hierarchy_raw, len(reading), spans)
    dependencies = dependencies_checked(dependencies_raw, regions)
    units = paragraph_units(reading, spans, regions, levels)
    jobs = shards(reading, units, dependencies, regions, digest(binding_raw))
    result = {'schema': 'sentinel/semantic-census/1', 'binding': binding,
              'regions': regions, 'dependencies': dependencies, 'paragraphs': units, 'shards': jobs,
              'coverage': {'source': 'EXACT_REPRESENTATION_IDENTITY_ONLY' if representation['kind']
                           == 'ORIGINAL' else 'EXTRACTION_FIDELITY_UNPROVEN',
                           'reading': 'ALL_BYTES_OPERATIONALLY_ACCOUNTED',
                           'candidate_propositions': 'UNPERFORMED', 'context': 'UNPROVEN',
                           'semantic_tests': 'UNPERFORMED', 'unknown_meaning': 'UNPROVEN'},
              'potential_claims': [], 'relationships': dependencies,
              'uncertainty': ['MEANING_UNASSESSED', 'EXTRACTION_NOT_INDEPENDENTLY_CHECKED'],
              'unprocessed': [{'span': row['span'], 'status': row['status']} for row in units],
              'processing': 'NO_PENDING_JOBS' if not units else 'PENDING_OR_OPAQUE',
              'semantic_completeness': 'UNPROVEN', 'execution_authority': 'NONE'}
    require(len(canonical(result)) <= METADATA, 'census metadata bound')
    return result
