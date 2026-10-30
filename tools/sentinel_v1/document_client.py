"""Explicit bounded logical client envelopes over the unchanged document profile.

Provider framing and actual tool delivery require separate recorded evidence.
This planner never grants semantic qualification or execution authority.
"""
from . import census, document_analysis as document
from .common import (JOB_BYTES, METADATA, SentinelError, canonical, digest, fields, held_record,
    identity, integer, require)

PROFILE = 'sentinel/document-client-plan/1'
TARGETED = 'sentinel/document-client-plan/2'


def dispatch_bytes(dispatch):
    require(type(dispatch) is str, 'client dispatch must be UTF8 text')
    integer(len(dispatch), 1, 4096)
    try:
        raw = dispatch.encode('utf-8')
    except UnicodeError as error:
        raise SentinelError('client dispatch invalid UTF8') from error
    integer(len(raw), 1, 4096)
    return raw


def frame_bytes(dispatch, prompt):
    raw = dispatch_bytes(dispatch)
    require(type(prompt) is bytes, 'client application must be immutable bytes')
    require(8 + len(raw) + len(prompt) <= JOB_BYTES, 'complete client frame exceeds job bound')
    return b'SPG1' + len(raw).to_bytes(4, 'big') + raw + prompt


def best_group(reading, binding, units, start, end, deps, regions, number, overhead, target=JOB_BYTES):
    low, high, best = start + 1, end, None
    for _ in range(17):
        if low > high: break
        middle = (low + high) // 2
        row = document.group_row(reading, binding, units[start:middle], deps, regions, number)
        fits = row['status'] == 'ADMITTED' and row['prompt_pin']['bytes'] + overhead <= target
        if fits: best, low = (middle, row), middle + 1
        else: high = middle - 1
    return best if best is not None else (start + 1, document.group_row(
        reading, binding, units[start:start + 1], deps, regions, number))


def groups(reading, binding, units, dependencies, regions, overhead, target=JOB_BYTES):
    result, cursor, admitted = [], 0, 0
    for _ in range(document.MAX_PARAGRAPHS):
        if cursor == len(units): return result
        first = units[cursor]; end = cursor + 1
        if first['status'] == 'PENDING':
            for index in range(cursor + 1, len(units)):
                row = units[index]
                if row['status'] != 'PENDING' or row['region_id'] != first['region_id'] \
                        or row['span'][1] - first['span'][0] > JOB_BYTES: break
                end = index + 1
        cursor, row = best_group(reading, binding, units, cursor, end, dependencies,
            regions, len(result) + 1, overhead, target)
        admitted += row['status'] == 'ADMITTED'
        require(admitted <= document.MAX_JOBS, 'document job count bound')
        result.append(row)
    require(cursor == len(units), 'client group work bound')
    return result


def index_bytes(reading, binding, units, rows, regions, dependencies):
    context = digest(canonical({'regions': regions, 'dependencies': dependencies})); store = {}
    paragraphs = document.store_blocks(document.CENSUS_BLOCK, units, binding, context, store)
    jobs = document.store_blocks(document.JOB_BLOCK, rows, binding, context, store)
    raw = canonical({'schema': document.INDEX, 'binding': binding, 'regions': regions,
        'dependencies': dependencies, 'context_sha256': context, 'paragraph_blocks': paragraphs,
        'job_blocks': jobs, 'paragraph_count': len(units),
        'job_count': sum(row['status'] == 'ADMITTED' for row in rows), 'group_count': len(rows),
        'coverage': 'ALL_READING_INTERVALS_ACCOUNTED_NOT_MEANING',
        'semantic_completeness': 'UNPROVEN', 'execution_authority': 'NONE'})
    require(len(raw) + sum(map(len, store.values())) + METADATA <= document.TOTAL_METADATA,
        'client plan aggregate metadata bound with client manifest reserve')
    return raw, store


def client_rows(reading, binding, rows, dispatch):
    result = []
    overhead = 8 + len(dispatch_bytes(dispatch))
    for row in rows:
        fits = row['status'] == 'ADMITTED' and row['prompt_pin']['bytes'] + overhead <= JOB_BYTES
        pin = None
        if fits:
            start, end = row['span']
            pin = identity(frame_bytes(dispatch, document.complete_prompt(binding, row, reading[start:end])))
        result.append({'id': row['id'], 'status': 'FRAME_ADMITTED' if fits else 'FRAME_UNADMITTED',
            'application_pin': row['prompt_pin'], 'frame_pin': pin})
        require(len(canonical(result)) + len(dispatch_bytes(dispatch)) + 2048 <= METADATA,
            'client manifest byte bound before next insertion')
    return result


def manifest_bytes(index_raw, dispatch, rows, target=None):
    value = {'schema': PROFILE, 'index_pin': identity(index_raw), 'dispatch': dispatch,
        'frame_profile': 'SPG1', 'frame_limit_bytes': JOB_BYTES, 'jobs': rows,
        'delivery_status': 'NOT_OBSERVED', 'semantic_completeness': 'UNPROVEN',
        'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE'}
    if target is not None:
        integer(target, 1, JOB_BYTES)
        value.update(schema=TARGETED, packing_target_bytes=target)
        value['jobs'] = [dict(row, packing_target_met=row['frame_pin'] is not None
            and row['frame_pin']['bytes'] <= target) for row in rows]
    raw = canonical(value)
    require(len(raw) <= METADATA, 'client manifest bound')
    return raw


def planned(reading, binding_raw, dispatch, hierarchy_raw, dependencies_raw, target):
    if target is not None: integer(target, 1, JOB_BYTES)
    overhead = 8 + len(dispatch_bytes(dispatch))
    binding = document.reading_checked(reading, binding_raw); spans = document.paragraph_spans(reading)
    regions, levels = census.hierarchy_checked(hierarchy_raw, len(reading), spans)
    dependencies = census.dependencies_checked(dependencies_raw, regions)
    units = document.document_units(reading, regions, levels, spans)
    rows = groups(reading, binding, units, dependencies, regions, overhead,
        JOB_BYTES if target is None else target)
    index_raw, store = index_bytes(reading, binding, units, rows, regions, dependencies)
    manifest = manifest_bytes(index_raw, dispatch, client_rows(reading, binding, rows, dispatch), target)
    return {'index': index_raw, 'blocks': store, 'client': manifest}


def plan(reading, binding_raw, dispatch, hierarchy_raw=None, dependencies_raw=None):
    return planned(reading, binding_raw, dispatch, hierarchy_raw, dependencies_raw, None)


def plan_targeted(reading, binding_raw, dispatch, packing_target_bytes,
                  hierarchy_raw=None, dependencies_raw=None):
    integer(packing_target_bytes, 1, JOB_BYTES)
    return planned(reading, binding_raw, dispatch, hierarchy_raw, dependencies_raw, packing_target_bytes)


def checked(raw, held, reading, binding_raw, index_raw, index_held, blocks):
    value = held_record(raw, held)
    require(type(value) is dict and value.get('schema') in (PROFILE, TARGETED), 'client plan version')
    target = value.get('packing_target_bytes') if value['schema'] == TARGETED else None
    if value['schema'] == TARGETED: integer(target, 1, JOB_BYTES)
    fields(value, ('schema', 'index_pin', 'dispatch', 'frame_profile', 'frame_limit_bytes',
        'jobs', 'delivery_status', 'semantic_completeness', 'qualification', 'execution_authority')
        + (('packing_target_bytes',) if value['schema'] == TARGETED else ()))
    require(type(index_raw) is bytes and len(index_raw) <= METADATA, 'client index immutable bound')
    snapshot = document.blocks_snapshot(blocks)
    require(len(index_raw) + sum(map(len, snapshot.values())) + METADATA <= document.TOTAL_METADATA,
        'client checker aggregate metadata bound with client manifest reserve')
    index, rows = document.document_checked(reading, binding_raw, index_raw, index_held, snapshot)
    if target is not None:
        overhead = 8 + len(dispatch_bytes(value['dispatch']))
        for row in rows:
            require(len(row['paragraph_ids']) == 1 or row['prompt_pin'] is not None
                and row['prompt_pin']['bytes'] + overhead <= target,
                'target miss requires one indivisible paragraph')
    expected = manifest_bytes(index_raw, value['dispatch'],
        client_rows(reading, index['binding'], rows, value['dispatch']), target)
    require(raw == expected, 'client manifest/index/frame differs')
    return value


def prepare(raw, held, reading, binding_raw, index_raw, index_held, blocks, job_id):
    value = checked(raw, held, reading, binding_raw, index_raw, index_held, blocks)
    matches = [row for row in value['jobs'] if row['id'] == job_id]
    require(len(matches) == 1 and matches[0]['status'] == 'FRAME_ADMITTED', 'client frame not admitted')
    prepared = document.prepare_document_job(reading, binding_raw, index_raw, index_held, blocks, job_id)
    frame = frame_bytes(value['dispatch'], document.generation_message(prepared))
    require(identity(frame) == matches[0]['frame_pin'], 'prepared client frame differs')
    return {**prepared, 'frame': frame, 'dispatch': value['dispatch']}
