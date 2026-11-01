"""Versioned whole-reading operational planning; no semantic or execution authority."""
from .common import (JOB_BYTES, METADATA, ROUNDS, SentinelError, canonical, digest, fields,
    hash_checked, held_record, identity, integer, label, parse, pin_checked, registry_snapshot, require)
from . import census, graph
from .analysis import PROMPT
from .assessments import artifact, reviewer_checked
from .bindings import graph_from_registry

INDEX = 'sentinel/document-census-index/1'
CENSUS_BLOCK = 'sentinel/document-census-block/1'
JOB_BLOCK = 'sentinel/document-job-block/1'
REQUEST = 'sentinel/document-analysis-request/1'
MAX_PARAGRAPHS = 65536
MAX_JOBS = 4096
MAX_BLOCKS = 128
TOTAL_METADATA = 16777216
MAX_READING = census.MAX_READING


def reading_checked(reading, binding_raw):
    require(type(reading) is bytes and len(reading) <= MAX_READING, 'document immutable reading bound')
    binding = census.binding_checked(parse(binding_raw))
    require(identity(reading) == {key: binding['representation'][key] for key in ('sha256', 'bytes')},
            'document full reading identity mismatch')
    try:
        reading.decode('utf-8')
    except UnicodeError as error:
        raise SentinelError('document reading UTF8 required') from error
    return binding


def paragraph_spans(reading):
    result, cursor = [], 0
    lf, crlf = reading.find(b'\n\n'), reading.find(b'\r\n\r\n')
    for _ in range(MAX_PARAGRAPHS):
        if cursor == len(reading): return result
        choices = [(p, w) for p, w in ((lf, 2), (crlf, 4)) if p >= 0]
        end = min(choices)[0] + min(choices)[1] if choices else len(reading)
        result.append((cursor, end)); cursor = end
        if 0 <= lf < cursor: lf = reading.find(b'\n\n', cursor)
        if 0 <= crlf < cursor: crlf = reading.find(b'\r\n\r\n', cursor)
    require(cursor == len(reading), 'document paragraph count bound')
    return result


def document_units(reading, regions, levels, spans):
    units = census.paragraph_units(reading, spans, regions, levels)
    for index, row in enumerate(units, 1): row['id'] = f'P{index:05d}'
    return units


def source_record(binding, row):
    return {'id': 'S1', **binding, 'window': {'start': row['span'][0],
        'end': row['span'][1], 'sha256': row['identity']['sha256']}}


def output_template(source, raw):
    first = raw.decode('utf-8')[0].encode('utf-8')
    evidence = {'source_id': 'S1', 'start': source['window']['start'],
        'end': source['window']['start'] + len(first), 'quote_sha256': digest(first)}
    node = {'id': 'C1', 'kind': 'PROPOSITION', 'origin': 'SOURCE_OCCURRENCE',
        'text': 'Replace with a source-grounded proposed reading; this template is not an analysis.',
        'evidence': [evidence], 'documentary_state': 'NEITHER', 'support_records': [],
        'refutation_records': [], 'assurance': dict(graph.ASSURANCE)}
    return {'schema': graph.PROFILE, 'source_set': [source], 'nodes': [node],
            'edges': [], 'assurance': dict(graph.ASSURANCE)}


def complete_prompt(binding, row, raw):
    require(type(raw) is bytes and 0 < len(raw) <= JOB_BYTES, 'document prompt reading bound')
    source = source_record(binding, row)
    constraints = {'nodes': [1, 256], 'propositions_max': 64, 'edges_max': 512,
        'evidence_per_node': [1, 16], 'text_utf8_bytes_max': 4096, 'response_bytes_max': JOB_BYTES,
        'labels': '[A-Za-z0-9][A-Za-z0-9_.:/-]*, at most 64 characters',
        'evidence': 'Absolute UTF8 byte offsets inside supplied window; nonempty complete codepoints. '
            'quote_sha256 is SHA256 of exact selected UTF8 bytes. Every supplied source must be used.',
        'documentary_records': 'Use NEITHER and empty support_records/refutation_records; no invented authority.',
        'edges': 'Closed keys from,to,kind; existing distinct node IDs, no duplicates; endpoint types below. '
            'DEPENDS_ON, REVISES, TEMPORALLY_BEFORE must each be acyclic.',
        'serialization': 'Return ONLY UTF8 JSON, sorted object keys, separators comma/colon, no whitespace '
            'outside strings, no floats, duplicate keys, Markdown fences, extra fields or trailing newline.',
        'interpretation': 'Template is shape only. Propose all evidenced entities/relations/conditions and '
            'exceptions within bounds; unsupported or omitted meaning remains UNPROVEN, never invent facts.'}
    return canonical({'instructions': PROMPT, 'output_template': output_template(source, raw),
        'critical_constraints': constraints, 'node_kinds': list(graph.KINDS),
        'origins': list(graph.ORIGINS), 'relations': list(graph.RELATIONS),
        'relation_endpoint_kinds': {key: [list(left), list(right)]
                                    for key, (left, right) in graph.EDGE_TYPES.items()},
        'source_set': [source], 'SOURCE_DATA': raw.decode('utf-8'),
        'required_context_regions_not_supplied': row['dependency_regions'],
        'operational_job': {'id': row['id'], 'paragraph_ids': row['paragraph_ids'],
            'region_id': row['region_id']}, 'context_adequacy': 'UNPROVEN',
        'semantic_completeness': 'UNPROVEN', 'execution_authority': 'NONE'})


def group_row(reading, binding, selected, dependencies, regions, number):
    start, end = selected[0]['span'][0], selected[-1]['span'][1]
    row = {'id': f'JOB{number:05d}', 'paragraph_ids': [p['id'] for p in selected],
        'span': [start, end], 'identity': identity(reading[start:end]),
        'region_id': selected[0]['region_id'], 'dependency_regions': census.dependency_regions(
            selected[0]['region_id'], dependencies, regions), 'status': 'OPAQUE', 'prompt_pin': None}
    if end - start <= JOB_BYTES:
        prompt = complete_prompt(binding, row, reading[start:end])
        row['prompt_pin'] = identity(prompt)
        row['status'] = 'ADMITTED' if len(prompt) <= JOB_BYTES else 'PROMPT_BUDGET_UNADMITTED'
    return row


def best_group(reading, binding, units, start, end, dependencies, regions, number):
    low, high, best = start + 1, end, None
    for _ in range(17):
        if low > high: break
        middle = (low + high) // 2
        row = group_row(reading, binding, units[start:middle], dependencies, regions, number)
        if row['status'] == 'ADMITTED': best, low = (middle, row), middle + 1
        else: high = middle - 1
    return best if best is not None else (start + 1, group_row(
        reading, binding, units[start:start + 1], dependencies, regions, number))


def planned_groups(reading, binding, units, dependencies, regions):
    result, cursor, admitted = [], 0, 0
    for _ in range(MAX_PARAGRAPHS):
        if cursor == len(units): return result
        first = units[cursor]; end = cursor + 1
        if first['status'] == 'PENDING':
            for index in range(cursor + 1, len(units)):
                row = units[index]
                if row['status'] != 'PENDING' or row['region_id'] != first['region_id'] \
                        or row['span'][1] - first['span'][0] > JOB_BYTES: break
                end = index + 1
        cursor, row = best_group(reading, binding, units, cursor, end, dependencies, regions, len(result) + 1)
        admitted += row['status'] == 'ADMITTED'
        require(admitted <= MAX_JOBS, 'document admitted job count bound')
        result.append(row)
    require(cursor == len(units), 'document group count bound')
    return result


def block_bytes(schema, ordinal, binding, context, rows):
    return canonical({'schema': schema, 'ordinal': ordinal, 'binding': binding,
                      'context_sha256': context, 'rows': rows})


def admit_block(store, raw):
    require(type(raw) is bytes and 0 < len(raw) <= METADATA, 'document block byte bound')
    require(len(store) < MAX_BLOCKS, 'document block count before insertion')
    require(sum(map(len, store.values())) + len(raw) + METADATA <= TOTAL_METADATA,
            'document block cumulative bound with full index reserve before insertion')
    key = digest(raw); require(key not in store, 'duplicate document block content')
    store[key] = raw
    return identity(raw)


def store_blocks(schema, rows, binding, context, store):
    refs, group, used = [], [], 0
    overhead = len(block_bytes(schema, 1, binding, context, [])) + 16
    for row in rows:
        amount = len(canonical(row)) + 1
        require(amount + overhead <= METADATA, 'one document metadata row exceeds block bound')
        if group and (len(group) == 4096 or used + amount + overhead > METADATA):
            raw = block_bytes(schema, len(refs) + 1, binding, context, group)
            refs.append(admit_block(store, raw)); group, used = [], 0
        group.append(row); used += amount
    if group:
        raw = block_bytes(schema, len(refs) + 1, binding, context, group)
        refs.append(admit_block(store, raw))
    require(len(store) <= MAX_BLOCKS and sum(map(len, store.values())) <= TOTAL_METADATA,
            'document block aggregate bound')
    return refs


def plan_document_jobs(reading, binding_raw, hierarchy_raw=None, dependencies_raw=None):
    binding = reading_checked(reading, binding_raw); spans = paragraph_spans(reading)
    regions, levels = census.hierarchy_checked(hierarchy_raw, len(reading), spans)
    dependencies = census.dependencies_checked(dependencies_raw, regions)
    units = document_units(reading, regions, levels, spans)
    groups = planned_groups(reading, binding, units, dependencies, regions)
    context = digest(canonical({'regions': regions, 'dependencies': dependencies})); store = {}
    paragraph_blocks = store_blocks(CENSUS_BLOCK, units, binding, context, store)
    job_blocks = store_blocks(JOB_BLOCK, groups, binding, context, store)
    index = {'schema': INDEX, 'binding': binding, 'regions': regions, 'dependencies': dependencies,
        'context_sha256': context, 'paragraph_blocks': paragraph_blocks, 'job_blocks': job_blocks,
        'paragraph_count': len(units), 'job_count': sum(row['status'] == 'ADMITTED' for row in groups),
        'group_count': len(groups), 'coverage': 'ALL_READING_INTERVALS_ACCOUNTED_NOT_MEANING',
        'semantic_completeness': 'UNPROVEN', 'execution_authority': 'NONE'}
    raw = canonical(index)
    require(len(raw) + sum(map(len, store.values())) <= TOTAL_METADATA, 'document aggregate metadata bound')
    return {'index': raw, 'blocks': store}


def blocks_snapshot(blocks):
    require(type(blocks) is dict and len(blocks) <= MAX_BLOCKS, 'document block store bound')
    snapshot, total = {}, 0
    try:
        for position, (key, raw) in enumerate(blocks.items()):
            require(position < MAX_BLOCKS, 'document block iterator bound')
            hash_checked(key)
            require(type(raw) is bytes and len(raw) <= METADATA, 'document block byte bound')
            total += len(raw); require(total <= TOTAL_METADATA, 'document block aggregate bound')
            snapshot[key] = raw
    except RuntimeError as error: raise SentinelError('document block store mutated') from error
    for key, raw in snapshot.items(): require(digest(raw) == key, 'document block hash mismatch')
    return snapshot


def load_rows(refs, schema, binding, context, snapshot, used, maximum):
    require(type(refs) is list and len(refs) <= MAX_BLOCKS, 'document block reference bound')
    rows = []
    for ordinal, pin in enumerate(refs, 1):
        pin_checked(pin); integer(pin['bytes'], 1, METADATA)
        key = pin['sha256']; require(key not in used, 'duplicate document block')
        raw = snapshot.get(key); require(type(raw) is bytes and identity(raw) == pin, 'missing document block')
        value = parse(raw); fields(value, ('schema', 'ordinal', 'binding', 'context_sha256', 'rows'))
        integer(value['ordinal'], ordinal, ordinal)
        require(value['schema'] == schema and canonical(value['binding']) == canonical(binding)
                and value['context_sha256'] == context, 'document block binding/order/context mismatch')
        require(type(value['rows']) is list and 1 <= len(value['rows']) <= 4096, 'document block rows')
        require(len(rows) + len(value['rows']) <= maximum, 'document row aggregate bound')
        rows.extend(value['rows']); used.add(key)
    return rows


def index_checked(raw, held, binding, snapshot):
    value = held_record(raw, held)
    fields(value, ('schema', 'binding', 'regions', 'dependencies', 'context_sha256',
        'paragraph_blocks', 'job_blocks', 'paragraph_count', 'job_count', 'group_count',
        'coverage', 'semantic_completeness', 'execution_authority'))
    require(value['schema'] == INDEX and canonical(value['binding']) == canonical(binding), 'document index binding')
    integer(value['paragraph_count'], 0, MAX_PARAGRAPHS); integer(value['job_count'], 0, MAX_JOBS)
    integer(value['group_count'], 0, MAX_PARAGRAPHS)
    require(value['coverage'] == 'ALL_READING_INTERVALS_ACCOUNTED_NOT_MEANING'
        and value['semantic_completeness'] == 'UNPROVEN' and value['execution_authority'] == 'NONE',
        'document index cannot promote meaning/authority')
    context = digest(canonical({'regions': value['regions'], 'dependencies': value['dependencies']}))
    require(context == value['context_sha256'], 'document context mismatch')
    require(len(raw) + sum(map(len, snapshot.values())) <= TOTAL_METADATA, 'document metadata aggregate')
    return value


def units_checked(reading, index, rows):
    require(len(rows) == index['paragraph_count'], 'document paragraph count changed')
    spans = paragraph_spans(reading)
    regions, levels = census.hierarchy_checked(canonical(index['regions']), len(reading), spans)
    census.dependencies_checked(canonical(index['dependencies']), regions)
    expected = document_units(reading, regions, levels, spans)
    require(len(rows) == len(expected), 'document missing paragraph')
    for row, original in zip(rows, expected):
        fields(row, ('id', 'span', 'sha256', 'region_id', 'status'))
        require(type(row['span']) is list and len(row['span']) == 2, 'document paragraph span')
        integer(row['span'][0], 0, len(reading)); integer(row['span'][1], row['span'][0] + 1, len(reading))
        require(row == original, 'document paragraph reordered/changed')
    return rows


def groups_checked(reading, index, rows, units):
    require(len(rows) == index['group_count'], 'document group count changed')
    cursor, admitted = 0, 0
    for ordinal, row in enumerate(rows, 1):
        fields(row, ('id', 'paragraph_ids', 'span', 'identity', 'region_id', 'dependency_regions', 'status', 'prompt_pin'))
        require(row['id'] == f'JOB{ordinal:05d}', 'document job order/ID changed')
        ids = row['paragraph_ids']
        require(type(ids) is list and 1 <= len(ids) <= MAX_PARAGRAPHS, 'document group paragraph count')
        selected = units[cursor:cursor + len(ids)]
        require(len(selected) == len(ids) and ids == [p['id'] for p in selected], 'document paragraph partition changed')
        require(type(row['span']) is list and len(row['span']) == 2, 'document group span')
        integer(row['span'][0], 0, len(reading)); integer(row['span'][1], row['span'][0] + 1, len(reading))
        require(row['span'] == [selected[0]['span'][0], selected[-1]['span'][1]], 'document absolute span changed')
        require(all(p['region_id'] == row['region_id'] for p in selected), 'document group crosses region')
        deps = census.dependency_regions(row['region_id'], index['dependencies'], index['regions'])
        require(row['dependency_regions'] == deps, 'document group context changed')
        fields(row['identity'], ('sha256', 'bytes')); hash_checked(row['identity']['sha256'])
        integer(row['identity']['bytes'], 1, MAX_READING)
        start, end = row['span']; require(row['identity'] == identity(reading[start:end]), 'document group source changed')
        if end - start > JOB_BYTES:
            require(len(ids) == 1 and row['status'] == 'OPAQUE' and row['prompt_pin'] is None, 'opaque group mismatch')
        else:
            pin_checked(row['prompt_pin']); integer(row['prompt_pin']['bytes'], 1, METADATA)
            prompt = complete_prompt(index['binding'], row, reading[start:end])
            require(identity(prompt) == row['prompt_pin'], 'document group exact prompt changed')
            status = 'ADMITTED' if len(prompt) <= JOB_BYTES else 'PROMPT_BUDGET_UNADMITTED'
            require(row['status'] == status and (status == 'ADMITTED' or len(ids) == 1), 'document prompt admission mismatch')
            admitted += status == 'ADMITTED'
        cursor += len(ids)
    require(cursor == len(units) and admitted == index['job_count'], 'document incomplete partition/job count')
    return rows


def document_checked(reading, binding_raw, index_raw, index_held, blocks):
    binding = reading_checked(reading, binding_raw); snapshot = blocks_snapshot(blocks)
    index = index_checked(index_raw, index_held, binding, snapshot); used = set()
    units = load_rows(index['paragraph_blocks'], CENSUS_BLOCK, binding, index['context_sha256'], snapshot, used, MAX_PARAGRAPHS)
    groups = load_rows(index['job_blocks'], JOB_BLOCK, binding, index['context_sha256'], snapshot, used, MAX_PARAGRAPHS)
    require(used == set(snapshot), 'unused document block')
    units_checked(reading, index, units); groups_checked(reading, index, groups, units)
    return index, groups


def selected_job(index, groups, reading, job_id):
    label(job_id); selected = [row for row in groups if row['id'] == job_id]
    require(len(selected) == 1 and selected[0]['status'] == 'ADMITTED', 'document admitted job absent')
    row = selected[0]; start, end = row['span']; raw = reading[start:end]
    prompt = complete_prompt(index['binding'], row, raw)
    require(identity(prompt) == row['prompt_pin'] and len(prompt) <= JOB_BYTES, 'document exact prompt changed/unbounded')
    return row, raw, prompt


def request_bytes(index, index_held, row, raw, prompt):
    return canonical({'schema': REQUEST, 'index_sha256': index_held, 'job_id': row['id'],
        'binding': index['binding'], 'source_set': [source_record(index['binding'], row)],
        'context_sha256': index['context_sha256'], 'paragraph_ids': row['paragraph_ids'],
        'reading_pin': identity(raw), 'prompt_pin': identity(prompt), 'max_response_bytes': JOB_BYTES,
        'required_context_regions': row['dependency_regions'], 'qualification': 'NOT_QUALIFIED',
        'semantic_completeness': 'UNPROVEN', 'execution_authority': 'NONE'})


def prepare_document_job(reading, binding_raw, index_raw, index_held, blocks, job_id):
    index, groups = document_checked(reading, binding_raw, index_raw, index_held, blocks)
    return _prepare_checked(reading, index, index_held, groups, job_id)


def _prepare_checked(reading, index, index_held, groups, job_id):
    """Use only an owned document_checked result within the current call."""
    row, raw, prompt = selected_job(index, groups, reading, job_id)
    return {'request': request_bytes(index, index_held, row, raw, prompt), 'prompt': prompt, 'reading': raw}


def request_checked(request_raw, request_held, reading, binding_raw, index_raw, index_held, blocks, registry):
    index, groups = document_checked(reading, binding_raw, index_raw, index_held, blocks)
    return _request_checked(request_raw, request_held, reading, index, index_held, groups, registry)


def _request_checked(request_raw, request_held, reading, index, index_held, groups, registry):
    value = held_record(request_raw, request_held)
    fields(value, ('schema', 'index_sha256', 'job_id', 'binding', 'source_set', 'context_sha256',
        'paragraph_ids', 'reading_pin', 'prompt_pin', 'max_response_bytes', 'required_context_regions',
        'qualification', 'semantic_completeness', 'execution_authority'))
    prepared = _prepare_checked(reading, index, index_held, groups, value['job_id'])
    require(prepared['request'] == request_raw, 'document request differs from held full source/index')
    require(artifact(value['reading_pin'], registry, JOB_BYTES) == prepared['reading']
            and artifact(value['prompt_pin'], registry, JOB_BYTES) == prepared['prompt'], 'document request artifacts changed')
    return value


def import_candidate(request_raw, request_held, graph_raw, graph_held, reading, binding_raw,
                     index_raw, index_held, blocks, registry, registry_held, provenance_raw, provenance_held):
    snapshot = registry_snapshot(registry, registry_held)
    request = request_checked(request_raw, request_held, reading, binding_raw, index_raw, index_held, blocks, snapshot)
    return _import_checked(request, request_held, graph_raw, graph_held, index_held,
                           snapshot, provenance_raw, provenance_held)


def _import_checked(request, request_held, graph_raw, graph_held, index_held,
                    snapshot, provenance_raw, provenance_held):
    require(type(graph_raw) is bytes and len(graph_raw) <= JOB_BYTES, 'document response bound')
    proposal = graph_from_registry(graph_held, snapshot)
    require(snapshot.get(graph_held) == graph_raw and canonical(proposal['source_set']) == canonical(request['source_set']),
            'document graph source differs')
    provenance = held_record(provenance_raw, provenance_held); observed = reviewer_checked(provenance, snapshot)
    require(provenance['prompt_pin'] == request['prompt_pin'] and provenance['raw_response_pin'] == identity(graph_raw),
            'document generation provenance differs')
    return canonical({'schema': 'sentinel/document-candidate-import/1', 'index_sha256': index_held,
        'job_id': request['job_id'], 'request_sha256': request_held, 'graph_sha256': graph_held,
        'provenance_sha256': provenance_held, 'observed_provenance': observed,
        'scope': 'STRUCTURAL_PROPOSAL_ONLY', 'assurance': dict(graph.ASSURANCE)})


def admission_checked(raw, held, index_held, job_id):
    value = held_record(raw, held)
    fields(value, ('schema', 'index_sha256', 'job_id', 'entries', 'authority'))
    require(value['schema'] == 'sentinel/document-generation-admission/1'
        and value['index_sha256'] == index_held and value['job_id'] == job_id
        and value['authority'] == 'OPERATOR_HELD_RECORDED_EVIDENCE_NOT_PROVIDER_AUTHENTICATION',
        'independently held generation admission required')
    require(type(value['entries']) is list and len(value['entries']) <= ROUNDS, 'generation admission rounds')
    result = {}
    for row in value['entries']:
        fields(row, ('ordinal', 'request_pin', 'prompt_pin', 'response_pin', 'provenance_pin',
                     'import_pin', 'invocation_pin', 'observed_identity_pin'))
        integer(row['ordinal'], 1, ROUNDS); require(row['ordinal'] not in result, 'duplicate generation admission')
        for key in set(row) - {'ordinal'}: pin_checked(row[key]); integer(row[key]['bytes'], 1, JOB_BYTES)
        result[row['ordinal']] = row
    return result


def replay_attempt(row, document, registry, registry_held, admitted):
    reading, binding_raw, index_raw, index_held, blocks, job_id = document
    index, groups = document_checked(reading, binding_raw, index_raw, index_held, blocks)
    snapshot = registry_snapshot(registry, registry_held)
    _replay_checked(row, reading, index, index_held, groups, job_id, snapshot, admitted)


def _replay_checked(row, reading, index, index_held, groups, job_id, registry, admitted):
    fields(row, ('ordinal', 'status', 'request_sha256', 'graph_sha256', 'provenance_sha256', 'result_pin'))
    integer(row['ordinal'], 1, ROUNDS)
    key = hash_checked(row['request_sha256']); request_raw = registry.get(key)
    request = _request_checked(request_raw, key, reading, index, index_held, groups, registry)
    require(request['job_id'] == job_id, 'attempt job differs')
    result = artifact(row['result_pin'], registry, JOB_BYTES)
    require(row['status'] in ('FAILED', 'INTERRUPTED', 'ANALYZED_PROPOSED'), 'document attempt status')
    if row['status'] != 'ANALYZED_PROPOSED':
        require(row['graph_sha256'] is None and row['provenance_sha256'] is None and len(result) > 0,
                'document failure evidence missing')
        require(row['ordinal'] not in admitted, 'generation admission cannot bless failed attempt')
        return
    graph_key, provenance_key = hash_checked(row['graph_sha256']), hash_checked(row['provenance_sha256'])
    graph_raw, provenance_raw = registry.get(graph_key), registry.get(provenance_key)
    provenance = held_record(provenance_raw, provenance_key); reviewer_checked(provenance, registry)
    require(provenance['origin'] == 'RECORDED_EXTERNAL_RUN' and provenance['observed_identity_pin'] is not None,
            'manual fixture cannot count as recorded generation')
    expected = _import_checked(request, key, graph_raw, graph_key, index_held,
                               registry, provenance_raw, provenance_key)
    require(result == expected and row['ordinal'] in admitted, 'generation import/admission missing')
    actual = {'ordinal': row['ordinal'], 'request_pin': identity(request_raw), 'prompt_pin': request['prompt_pin'],
        'response_pin': identity(graph_raw), 'provenance_pin': identity(provenance_raw), 'import_pin': identity(result),
        'invocation_pin': provenance['invocation_pin'], 'observed_identity_pin': provenance['observed_identity_pin']}
    require(admitted[row['ordinal']] == actual, 'generation admission differs from replayed evidence')


def reconcile_job(reading, binding_raw, index_raw, index_held, blocks, job_id, records_raw,
                  records_held, registry, registry_held, admission_raw, admission_held):
    index, groups = document_checked(reading, binding_raw, index_raw, index_held, blocks)
    return _reconcile_checked(reading, index, index_held, groups, job_id, records_raw,
        records_held, registry, registry_held, admission_raw, admission_held)


def _reconcile_checked(reading, index, index_held, groups, job_id, records_raw,
                       records_held, registry, registry_held, admission_raw, admission_held):
    selected_job(index, groups, reading, job_id)
    records = held_record(records_raw, records_held)
    fields(records, ('schema', 'index_sha256', 'job_id', 'attempts'))
    require(records['schema'] == 'sentinel/document-job-attempts/1' and records['index_sha256'] == index_held
            and records['job_id'] == job_id, 'document attempts binding')
    require(type(records['attempts']) is list and len(records['attempts']) <= ROUNDS, 'document attempt round bound')
    admitted = admission_checked(admission_raw, admission_held, index_held, job_id)
    snapshot = registry_snapshot(registry, registry_held); successes = set()
    for ordinal, row in enumerate(records['attempts'], 1):
        fields(row, ('ordinal', 'status', 'request_sha256', 'graph_sha256', 'provenance_sha256', 'result_pin'))
        integer(row['ordinal'], ordinal, ordinal)
        _replay_checked(row, reading, index, index_held, groups, job_id, snapshot, admitted)
        if row['status'] == 'ANALYZED_PROPOSED': successes.add(ordinal)
    require(successes == set(admitted), 'unused generation admission')
    status = 'PENDING' if not records['attempts'] else ('RECORDED_GENERATION_IMPORTED'
        if records['attempts'][-1]['status'] == 'ANALYZED_PROPOSED' else 'ACCOUNTED_WITH_FAILURES')
    return canonical({'schema': 'sentinel/document-job-reconciliation/1', 'index_sha256': index_held,
        'job_id': job_id, 'status': status, 'records_pin': identity(records_raw),
        'admission_pin': identity(admission_raw), 'history': records['attempts'],
        'execution_evidence': 'REPLAYED_OPERATOR_HELD_RECORDED_BYTES' if successes else 'NO_SUCCESSFUL_GENERATION_RECORDED',
        'provider_authentication': 'UNVERIFIED', 'semantic_completeness': 'UNPROVEN',
        'context_adequacy': 'UNPROVEN', 'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE'})



def reconciliation_inputs(value):
    require(type(value) is dict and len(value) == 6, 'document replay input field count before checking')
    fields(value, ('records_raw', 'records_held', 'registry', 'registry_held', 'admission_raw', 'admission_held'))
    require(type(value['registry']) is dict and len(value['registry']) <= 256, 'document job registry bound')
    metadata, payload = 0, 0
    for key in ('records_raw', 'admission_raw'):
        require(type(value[key]) is bytes and len(value[key]) <= METADATA, 'document replay metadata bound')
        metadata += len(value[key])
    for raw in value['registry'].values():
        require(type(raw) is bytes and len(raw) <= METADATA, 'document replay artifact bound')
        payload += len(raw)
    require(payload <= 8388608, 'document per-job replay registry bound')
    return metadata, payload



def job_inputs_snapshot(job_inputs):
    require(type(job_inputs) is dict and len(job_inputs) <= MAX_JOBS, 'document replay roster bound')
    result, metadata, payload = {}, 0, 0
    try:
        for position, (job_id, supplied) in enumerate(job_inputs.items()):
            require(position < MAX_JOBS, 'document replay iterator bound'); label(job_id)
            reconciliation_inputs(supplied); value = dict(supplied)
            value['registry'] = registry_snapshot(value['registry'], value['registry_held'])
            more_metadata, more_payload = reconciliation_inputs(value)
            metadata += more_metadata; payload += more_payload
            require(metadata <= TOTAL_METADATA and payload <= 268435456, 'document replay aggregate bound')
            result[job_id] = value
    except RuntimeError as error: raise SentinelError('document replay inputs mutated') from error
    return result, metadata


def reconcile_document(reading, binding_raw, index_raw, index_held, blocks, job_inputs):
    index, groups = document_checked(reading, binding_raw, index_raw, index_held, blocks)
    inputs, metadata = job_inputs_snapshot(job_inputs)
    required = {row['id'] for row in groups if row['status'] == 'ADMITTED'}
    require(set(inputs) == required, 'missing/extra job reconciliation evidence')
    statuses, receipts = {}, {}
    for job_id, value in inputs.items():
        raw = _reconcile_checked(reading, index, index_held, groups, job_id,
            value['records_raw'], value['records_held'], value['registry'], value['registry_held'],
            value['admission_raw'], value['admission_held'])
        metadata += len(raw); require(metadata <= TOTAL_METADATA, 'document replay receipts bound')
        statuses[job_id] = parse(raw)['status']; receipts[job_id] = identity(raw)
    incomplete = any(row['status'] != 'ADMITTED' for row in groups)
    status = 'EMPTY_READING' if not groups else 'INCOMPLETE_UNADMITTED_OR_OPAQUE' if incomplete else (
        'RECORDED_GENERATION_IMPORTS_REPLAYED' if all(s == 'RECORDED_GENERATION_IMPORTED'
        for s in statuses.values()) else 'INCOMPLETE_GENERATION')
    return canonical({'schema': 'sentinel/document-analysis-accounting/1', 'index_sha256': index_held,
        'status': status, 'job_count': index['job_count'], 'paragraph_count': index['paragraph_count'],
        'replayed_job_receipts': receipts, 'provider_authentication': 'UNVERIFIED',
        'semantic_completeness': 'UNPROVEN', 'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE'})



def generation_message(prepared):
    """Exact self-contained application bytes; full-source authentication is separate."""
    require(type(prepared) is dict and len(prepared) == 3, 'generation packet field count before checking')
    fields(prepared, ('request', 'prompt', 'reading'))
    request = parse(prepared['request'])
    fields(request, ('schema', 'index_sha256', 'job_id', 'binding', 'source_set', 'context_sha256',
        'paragraph_ids', 'reading_pin', 'prompt_pin', 'max_response_bytes', 'required_context_regions',
        'qualification', 'semantic_completeness', 'execution_authority'))
    require(request['schema'] == REQUEST, 'document generation request version')
    raw, message = prepared['reading'], prepared['prompt']
    require(type(raw) is bytes and 0 < len(raw) <= JOB_BYTES and type(message) is bytes
            and len(message) <= JOB_BYTES, 'generation application byte bounds')
    require(identity(raw) == request['reading_pin'] and identity(message) == request['prompt_pin'],
            'generation artifact identity differs')
    binding = census.binding_checked(request['binding'])
    integer(binding['representation']['bytes'], 1, MAX_READING)
    require(type(request['source_set']) is list and len(request['source_set']) == 1, 'generation source count')
    source = request['source_set'][0]
    fields(source, ('id', 'source', 'revision', 'representation', 'window'))
    fields(source['window'], ('start', 'end', 'sha256')); window = source['window']
    integer(window['start'], 0, binding['representation']['bytes'])
    integer(window['end'], window['start'] + 1, binding['representation']['bytes'])
    require(window['end'] - window['start'] == len(raw), 'generation absolute span differs')
    prompt = parse(message)
    fields(prompt, ('instructions', 'output_template', 'critical_constraints', 'node_kinds', 'origins',
        'relations', 'relation_endpoint_kinds', 'source_set', 'SOURCE_DATA',
        'required_context_regions_not_supplied', 'operational_job', 'context_adequacy',
        'semantic_completeness', 'execution_authority'))
    operation = fields(prompt['operational_job'], ('id', 'paragraph_ids', 'region_id'))
    label(operation['id']); label(operation['region_id'])
    ids, deps = operation['paragraph_ids'], request['required_context_regions']
    require(type(ids) is list and 1 <= len(ids) <= MAX_PARAGRAPHS
        and type(deps) is list and len(deps) <= 256, 'generation paragraph/context bounds')
    for name in ids: label(name)
    for name in deps: label(name)
    row = {'id': operation['id'], 'paragraph_ids': ids, 'region_id': operation['region_id'],
        'span': [window['start'], window['end']], 'identity': identity(raw), 'dependency_regions': deps}
    expected = complete_prompt(binding, row, raw)
    require(expected == message, 'generation message is not exact complete application prompt')
    index = {'binding': binding, 'context_sha256': hash_checked(request['context_sha256'])}
    require(request_bytes(index, hash_checked(request['index_sha256']), row, raw, message)
            == prepared['request'], 'generation complete request differs')
    return message
