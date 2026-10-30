"""Matched four-arm data preparation and recorded observations; no dispatch."""
from contextlib import contextmanager
import hashlib
from pathlib import Path
from transport_document_io import identity as fd_identity, open_regular
from .common import (JOB_BYTES, METADATA, canonical, digest, fields, hash_checked,
                     held_record, identity, integer, parse, pin_checked,
                     registry_snapshot, require)
from .assessments import artifact, legacy_entry, reviewer_checked
from .bindings import graph_from_registry

ARMS = ('A', 'B', 'C', 'D')
MAX_ACTIVE_JOBS = 2
MAX_ORIGINAL = 1_073_741_824
MAX_STAGING = 33_554_432
METRICS = ('consequential_errors', 'material_omissions', 'unsupported_additions',
           'conditions_exceptions_lost', 'attribution_errors', 'numerical_temporal_errors',
           'contradiction_errors', 'uncertainty_errors', 'tokens', 'latency_ns',
           'disk_bytes', 'memory_bytes', 'cost_microunits', 'human_effort_seconds')
CAPABILITIES = {'A': ['SEARCH', 'READ_ORIGINAL', 'NEIGHBOR_CONTEXT'],
                'B': ['VERIFY_PACKAGE', 'SEARCH_VERIFIED_SOURCE', 'READ_SECTION'],
                'D': ['VERIFY_PACKAGE', 'SEARCH_VERIFIED_SOURCE', 'READ_SECTION']}


def oracle_checked(raw, held, snapshot, task):
    value = held_record(raw, held)
    fields(value, ('schema', 'task_pin', 'expected_answer_pin', 'criteria_pin', 'adjudication_pin'))
    require(value['schema'] == 'sentinel/comparison-oracle/1' and value['task_pin'] == task,
            'comparison oracle task/version')
    artifact(value['task_pin'], snapshot, JOB_BYTES)
    for key in ('expected_answer_pin', 'criteria_pin', 'adjudication_pin'):
        artifact(value[key], snapshot, JOB_BYTES)
    return value


def graph_view(graph):
    keys = ('id', 'kind', 'origin', 'text', 'documentary_state', 'assurance')
    return canonical({'schema': 'sentinel/graph-only-view/1',
        'graph_sha256': graph['graph_sha256'], 'source_set_sha256': graph['source_set_sha256'],
        'nodes': [{key: node[key] for key in keys} for node in graph['nodes']],
        'edges': graph['edges'], 'assurance': graph['assurance']})


def source_pin(pin):
    fields(pin, ('sha256', 'bytes'))
    hash_checked(pin['sha256']); integer(pin['bytes'], 0, MAX_ORIGINAL)
    return pin


def original_pins_checked(pins, graph):
    require(type(pins) is list and 1 <= len(pins) <= 16, 'complete original count')
    seen = {}
    for pin in pins:
        source_pin(pin)
        require(pin['sha256'] not in seen, 'duplicate complete original')
        seen[pin['sha256']] = pin
    expected = {}
    for row in graph['source_set']:
        pin = {'sha256': row['source']['sha256'], 'bytes': row['source']['bytes']}
        require(pin['sha256'] not in expected or expected[pin['sha256']] == pin,
                'conflicting whole-source identities')
        expected[pin['sha256']] = pin
    require(seen == expected, 'ArmA requires every complete original, never snippets')
    return seen


def _inputs(plan_raw, held, registry, root, oracle_raw, oracle_held):
    plan = held_record(plan_raw, held)
    fields(plan, ('schema', 'task_pin', 'graph_pin', 'original_pins', 'sast',
                  'retrieval_pin', 'oracle_pin'))
    require(plan['schema'] == 'sentinel/four-arm-plan/1', 'four-arm plan version')
    snapshot = registry_snapshot(registry, root)
    graph_raw = artifact(plan['graph_pin'], snapshot)
    graph = graph_from_registry(digest(graph_raw), snapshot)
    originals = original_pins_checked(plan['original_pins'], graph)
    task = artifact(plan['task_pin'], snapshot, JOB_BYTES)
    oracle = oracle_checked(oracle_raw, oracle_held, snapshot, plan['task_pin'])
    pin_checked(plan['oracle_pin'])
    require(plan['oracle_pin'] == identity(oracle_raw), 'plan private oracle commitment')
    retrieval = parse(artifact(plan['retrieval_pin'], snapshot, JOB_BYTES))
    require(retrieval == {'schema': 'sentinel/retrieval-capabilities/1', **CAPABILITIES},
            'strong matched retrieval baseline required')
    fields(plan['sast'], ('share_pin', 'archive_pin', 'lexicon_pin'))
    sast = {name: artifact(plan['sast'][key], snapshot) for name, key in
            (('share.txt', 'share_pin'), ('meaning.zip', 'archive_pin'), ('lexicon.md', 'lexicon_pin'))}
    return plan, snapshot, graph, originals, task, oracle, retrieval, sast


def _prepared(inputs, original_data, registered):
    plan, snapshot, graph, originals, task, oracle, retrieval, sast = inputs
    projection = graph_view(graph)
    views = {arm: {'task.txt': task} for arm in ARMS}
    views['A'].update(original_data)
    for arm in ('A', 'B', 'D'):
        views[arm]['capabilities.json'] = canonical({'capabilities': retrieval[arm]})
    views['C']['capabilities.json'] = canonical({'capabilities': ['GRAPH_ONLY']})
    views['C']['graph.json'] = projection
    views['D']['graph.json'] = projection
    views['B'].update(sast); views['D'].update(sast)
    evaluator = {'oracle.json': canonical(oracle), 'expected-answer.bin':
        artifact(oracle['expected_answer_pin'], snapshot, JOB_BYTES),
        'criteria.bin': artifact(oracle['criteria_pin'], snapshot, JOB_BYTES),
        'adjudication.bin': artifact(oracle['adjudication_pin'], snapshot, JOB_BYTES)}
    require(all(raw != evaluator['oracle.json'] for files in views.values() for raw in files.values()),
            'private oracle present in receiver view')
    manifest = {'schema': 'sentinel/four-arm-preparation/1', 'task_pin': plan['task_pin'],
        'graph_sha256': graph['graph_sha256'], 'source_set_sha256': graph['source_set_sha256'],
        'oracle_pin': plan['oracle_pin'], 'models': 'NOT_DISPATCHED',
        'max_concurrent_jobs': MAX_ACTIVE_JOBS, 'isolation': 'NOT_ESTABLISHED',
        'source_profile': 'REGISTERED_HANDLES' if registered else 'BOUNDED_IN_MEMORY',
        'arms': {arm: {'inventory': {name: identity(raw) for name, raw in files.items()},
                      'registered_sources': list(originals.values()) if registered and arm in ('A', 'D')
                                            else []} for arm, files in views.items()},
        'evaluator_inventory': {name: identity(raw) for name, raw in evaluator.items()}}
    canonical(manifest)
    return {'manifest': manifest, 'views': views, 'evaluator': evaluator}


def prepare_four_arms(plan_raw, held, registry, root, oracle_raw, oracle_held):
    inputs = _inputs(plan_raw, held, registry, root, oracle_raw, oracle_held)
    originals, snapshot = inputs[3], inputs[1]
    raw = {'original-' + key + '.bin': artifact(pin, snapshot) for key, pin in originals.items()}
    return _prepared(inputs, raw, False)


def stream_hash(stream):
    before, total, result = fd_identity(stream), 0, hashlib.sha256()
    stream.seek(0)
    for _ in range(MAX_ORIGINAL // JOB_BYTES + 1):
        block = stream.read(JOB_BYTES)
        if not block:
            break
        total += len(block)
        require(total <= MAX_ORIGINAL, 'registered original byte bound')
        result.update(block)
    require(total == before[2] and fd_identity(stream) == before, 'registered original changed')
    stream.seek(0)
    return {'sha256': result.hexdigest(), 'bytes': total}, before


@contextmanager
def registered_sources(paths, expected):
    require(type(paths) is dict and len(paths) <= 16 and set(paths) == set(expected),
            'registered path set')
    handles = {}
    try:
        for key in sorted(paths):
            require(type(paths[key]) is type(Path('/')) and paths[key].is_absolute(),
                    'out-of-band absolute Path required')
            stream = open_regular(paths[key], MAX_ORIGINAL)
            handles[key] = {'stream': stream}
            pin, before = stream_hash(stream)
            require(pin == expected[key], 'registered complete original mismatch')
            handles[key].update(pin=pin, before=before)
        yield handles
        require(all(fd_identity(row['stream']) == row['before'] for row in handles.values()),
                'registered source changed during use')
    finally:
        for row in handles.values():
            row['stream'].close()


@contextmanager
def prepare_four_arms_handles(plan_raw, held, registry, root, oracle_raw, oracle_held, registered_paths):
    """Whole-file capabilities remain private, single-owner and live only in this context."""
    inputs = _inputs(plan_raw, held, registry, root, oracle_raw, oracle_held)
    with registered_sources(registered_paths, inputs[3]) as handles:
        yield _prepared(inputs, {}, True), handles


def read_registered(handles, source_sha256, start, end):
    require(source_sha256 in handles, 'registered source absent')
    row = handles[source_sha256]
    integer(start, 0, row['pin']['bytes']); integer(end, start, row['pin']['bytes'])
    require(end - start <= JOB_BYTES, 'registered read job bound')
    stream = row['stream']
    require(fd_identity(stream) == row['before'], 'registered descriptor changed')
    stream.seek(start); raw = stream.read(end - start)
    require(len(raw) == end - start and fd_identity(stream) == row['before'], 'registered short/change read')
    return raw


def search_registered(handles, source_sha256, needle, maximum=256):
    require(type(needle) is bytes and 1 <= len(needle) <= 4096, 'search needle bound')
    integer(maximum, 1, 256)
    require(source_sha256 in handles, 'registered source absent')
    row, found, carry, offset = handles[source_sha256], [], b'', 0
    stream = row['stream']
    require(fd_identity(stream) == row['before'], 'registered descriptor changed')
    stream.seek(0)
    for _ in range(MAX_ORIGINAL // JOB_BYTES + 1):
        block = stream.read(JOB_BYTES)
        if not block:
            break
        data, cursor = carry + block, 0
        for _ in range(len(data) + 1):
            position = data.find(needle, cursor)
            if position < 0:
                break
            absolute = offset - len(carry) + position
            if absolute >= 0 and (not found or absolute > found[-1]):
                require(len(found) < maximum, 'search match bound; no silent truncation')
                found.append(absolute)
            cursor = position + 1
        offset += len(block)
        carry = data[-(len(needle) - 1):] if len(needle) > 1 else b''
    require(offset == row['pin']['bytes'] and fd_identity(stream) == row['before'],
            'registered search changed or incomplete')
    return found


def _files_snapshot(prepared, held):
    fields(prepared, ('manifest', 'views', 'evaluator'))
    manifest = parse(canonical(prepared['manifest']))
    require(digest(canonical(manifest)) == hash_checked(held), 'preparation manifest mismatch')
    manifest_checked(manifest)
    fields(prepared['views'], ARMS)
    result, total = {}, 0
    for arm in (*ARMS, 'evaluator'):
        files = prepared['evaluator'] if arm == 'evaluator' else prepared['views'][arm]
        inventory = manifest['evaluator_inventory'] if arm == 'evaluator' else manifest['arms'][arm]['inventory']
        require(type(files) is dict and len(files) <= 36 and set(files) == set(inventory), 'staging file set')
        private = {}
        for name, raw in files.items():
            require(type(raw) is bytes and len(raw) <= METADATA, 'staging immutable file bound')
            require(identity(raw) == inventory[name], 'staging file identity mismatch')
            total += len(raw)
            require(total <= MAX_STAGING, 'whole staged packet byte bound')
            private[name] = raw
        result[arm] = private
    return manifest, result


def views_checked(manifest, files):
    if manifest['schema'] == 'sentinel/four-arm-preparation/2':
        return streaming_views_checked(manifest, files)
    fixed = {'A': {'task.txt', 'capabilities.json'},
             'B': {'task.txt', 'capabilities.json', 'share.txt', 'meaning.zip', 'lexicon.md'},
             'C': {'task.txt', 'capabilities.json', 'graph.json'},
             'D': {'task.txt', 'capabilities.json', 'graph.json', 'share.txt', 'meaning.zip', 'lexicon.md'}}
    originals = set(files['A']) - fixed['A']
    if manifest['source_profile'] == 'BOUNDED_IN_MEMORY':
        require(1 <= len(originals) <= 16, 'ArmA complete originals missing')
        for name in originals:
            require(name == 'original-' + digest(files['A'][name]) + '.bin', 'ArmA original filename pin')
    else:
        require(not originals and bool(manifest['arms']['A']['registered_sources']), 'registered ArmA handles missing')
    for arm in ARMS:
        require(set(files[arm]) == fixed[arm] | (originals if arm == 'A' else set()), 'arm view file template')
        require(identity(files[arm]['task.txt']) == manifest['task_pin'], 'matched task changed')
        expected = ['GRAPH_ONLY'] if arm == 'C' else CAPABILITIES[arm]
        require(parse(files[arm]['capabilities.json']) == {'capabilities': expected}, 'arm capability template')
    require(files['C']['graph.json'] == files['D']['graph.json'], 'C/D graph projection differs')
    for name in ('share.txt', 'meaning.zip', 'lexicon.md'):
        require(files['B'][name] == files['D'][name], 'B/D SAST baseline differs')
    fields(files['evaluator'], ('oracle.json', 'expected-answer.bin', 'criteria.bin', 'adjudication.bin'))
    require(identity(files['evaluator']['oracle.json']) == manifest['oracle_pin'], 'evaluator oracle changed')


def manifest_checked(manifest):
    if type(manifest) is dict and manifest.get('schema') == 'sentinel/four-arm-preparation/2':
        return streaming_manifest_checked(manifest)
    fields(manifest, ('schema', 'task_pin', 'graph_sha256', 'source_set_sha256', 'oracle_pin',
                      'models', 'max_concurrent_jobs', 'isolation', 'source_profile', 'arms',
                      'evaluator_inventory'))
    require(manifest['schema'] == 'sentinel/four-arm-preparation/1', 'preparation schema')
    require(manifest['models'] == 'NOT_DISPATCHED' and manifest['max_concurrent_jobs'] == 2
            and manifest['isolation'] == 'NOT_ESTABLISHED', 'preparation cannot claim execution')
    require(manifest['source_profile'] in ('BOUNDED_IN_MEMORY', 'REGISTERED_HANDLES'), 'source profile')
    pin_checked(manifest['task_pin']); pin_checked(manifest['oracle_pin'])
    hash_checked(manifest['graph_sha256']); hash_checked(manifest['source_set_sha256'])
    fields(manifest['arms'], ARMS)
    for arm in ARMS:
        fields(manifest['arms'][arm], ('inventory', 'registered_sources'))
        require(type(manifest['arms'][arm]['registered_sources']) is list
                and len(manifest['arms'][arm]['registered_sources']) <= 16, 'registered inventory bound')
        for pin in manifest['arms'][arm]['registered_sources']:
            source_pin(pin)
        require(arm in ('A', 'D') and manifest['source_profile'] == 'REGISTERED_HANDLES'
                or not manifest['arms'][arm]['registered_sources'], 'source handle role mismatch')
    require(manifest['arms']['A']['registered_sources'] == manifest['arms']['D']['registered_sources'],
            'matched original/fallback handle set')
    for inventory in [manifest['evaluator_inventory']] + [manifest['arms'][arm]['inventory'] for arm in ARMS]:
        require(type(inventory) is dict and len(inventory) <= 36, 'artifact inventory bound')
        for pin in inventory.values():
            pin_checked(pin)
    return manifest


def stage_four_arms(prepared, manifest_held, anchor, staging_sha256):
    manifest, files = _files_snapshot(prepared, manifest_held)
    views_checked(manifest, files)
    chain = legacy_entry('comparison.receiving.private_staging', 'chain', staging_sha256)
    write = legacy_entry('comparison.receiving.private_staging', 'write_new', staging_sha256)
    staged = {}
    for arm in (*ARMS, 'evaluator'):
        relative = 'evaluation/input' if arm == 'evaluator' else 'receivers/' + arm + '/input'
        chain(anchor, relative)
        staged[arm] = {name: write(anchor, relative, name, raw) for name, raw in files[arm].items()}
    return {'manifest_sha256': manifest_held, 'staged': staged, 'models': 'NOT_DISPATCHED',
            'isolation': 'PRIVATE_INPUT_DIRECTORIES_ONLY_NOT_FRESH_RECEIVER_ATTESTATION',
            'sast_package_verification': 'REGISTERED_BASES_CHECKED_AT_PREPARATION_NOT_STAGING'
                if manifest['schema'] == 'sentinel/four-arm-preparation/2' else 'UNPERFORMED',
            'execution_authority': 'NONE'}


def metrics_checked(value, pin, snapshot):
    fields(value, METRICS)
    measured = False
    for item in value.values():
        if item is not None:
            integer(item, 0, 2 ** 63 - 1); measured = True
    if not measured:
        require(pin is None, 'empty measurement pin')
        return 'NOT_MEASURED'
    require(pin is not None, 'measurement evidence missing')
    record = parse(artifact(pin, snapshot, JOB_BYTES))
    fields(record, ('schema', 'metrics', 'method', 'provenance_pin'))
    require(record['schema'] == 'sentinel/measurement/1'
            and canonical(record['metrics']) == canonical(value),
            'measurement record mismatch')
    from .common import label
    label(record['method']); artifact(record['provenance_pin'], snapshot, JOB_BYTES)
    return 'RECORDED_BYTES_UNVERIFIED'


def submission_checked(row, snapshot, expected):
    fields(row, ('arm', 'status', 'answer_pin', 'provenance', 'metrics', 'measurement_pin'))
    require(row['arm'] in ARMS and row['status'] in ('UNRUN', 'RECORDED', 'TOOL_PROCESS_FAILURE'),
            'submission arm/status')
    measurement = metrics_checked(row['metrics'], row['measurement_pin'], snapshot)
    if row['status'] == 'UNRUN':
        require(row['answer_pin'] is None and row['provenance'] is None
                and measurement == 'NOT_MEASURED', 'UNRUN cannot contain fabricated observations')
        status, provenance = 'UNRUN', None
    else:
        provenance = reviewer_checked(row['provenance'], snapshot, row['status'] == 'TOOL_PROCESS_FAILURE')
        if row['status'] == 'RECORDED':
            answer = artifact(row['answer_pin'], snapshot, JOB_BYTES)
            require(row['provenance']['raw_response_pin'] == row['answer_pin'], 'submission differs from response')
            status = 'MATCH_REFERENCE' if answer == expected else 'MISMATCH_REFERENCE'
        else:
            require(row['answer_pin'] is None, 'process failure cannot publish a successful answer')
            status = 'TOOL_PROCESS_FAILURE'
    return {'arm': row['arm'], 'status': status, 'answer_pin': row['answer_pin'],
            'provenance': provenance, 'metrics': row['metrics'], 'measurement': measurement}


def comparisons(rows):
    statuses, result = {row['arm']: row['status'] for row in rows}, []
    for index, left in enumerate(ARMS):
        for right in ARMS[index + 1:]:
            a, b = statuses[left], statuses[right]
            if a not in ('MATCH_REFERENCE', 'MISMATCH_REFERENCE') or b not in ('MATCH_REFERENCE', 'MISMATCH_REFERENCE'):
                relation = 'UNCOMPARABLE'
            elif a == b:
                relation = 'TIE_REFERENCE_MATCH' if a == 'MATCH_REFERENCE' else 'TIE_REFERENCE_MISMATCH'
            else:
                relation = left + '_REFERENCE_LOSS' if a == 'MISMATCH_REFERENCE' else right + '_REFERENCE_LOSS'
            result.append({'left': left, 'right': right, 'relation': relation})
    return result


def record_results(manifest_raw, manifest_held, submissions_raw, submissions_held,
                   registry, root, oracle_raw, oracle_held):
    manifest, submissions = held_record(manifest_raw, manifest_held), held_record(submissions_raw, submissions_held)
    manifest_checked(manifest)
    snapshot = registry_snapshot(registry, root)
    oracle = oracle_checked(oracle_raw, oracle_held, snapshot, manifest['task_pin'])
    require(manifest['oracle_pin'] == identity(oracle_raw), 'frozen evaluator oracle changed')
    fields(submissions, ('schema', 'manifest_sha256', 'records'))
    require(submissions['schema'] == 'sentinel/four-arm-submissions/1'
            and submissions['manifest_sha256'] == manifest_held, 'submission preparation mismatch')
    require(type(submissions['records']) is list and len(submissions['records']) == 4, 'four submission arms required')
    expected = artifact(oracle['expected_answer_pin'], snapshot, JOB_BYTES)
    rows = [submission_checked(row, snapshot, expected) for row in submissions['records']]
    require({row['arm'] for row in rows} == set(ARMS), 'duplicate or missing submission arm')
    result = {'schema': 'sentinel/four-arm-observations/1', 'manifest_sha256': manifest_held,
        'submissions_sha256': submissions_held, 'oracle_sha256': oracle_held,
        'results': rows, 'ties_and_losses': comparisons(rows), 'superiority': 'NOT_ESTABLISHED',
        'statistical_analysis': 'UNPERFORMED', 'semantic_completeness': 'UNPROVEN',
        'execution_authority': 'NONE', 'model_dispatch': 'NOT_PERFORMED_BY_THIS_TOOL'}
    canonical(result)
    return result


def check_source_handoff(answer_raw, oracle_raw, oracle_held, checker_sha256):
    require(type(answer_raw) is bytes and len(answer_raw) <= JOB_BYTES, 'handoff answer bound')
    require(type(oracle_raw) is bytes and len(oracle_raw) <= 131072
            and digest(oracle_raw) == hash_checked(oracle_held), 'handoff oracle pin/bound')
    checker = legacy_entry('comparison.receiving.check_answer', 'validate', checker_sha256)
    return checker(answer_raw, oracle_raw)


def streaming_inputs(plan_raw, held, registry, root, oracle_raw, oracle_held):
    plan = held_record(plan_raw, held)
    fields(plan, ('schema', 'task_pin', 'graph_pin', 'original_pins', 'sast_bases',
                  'retrieval_pin', 'oracle_pin'))
    require(plan['schema'] == 'sentinel/four-arm-streaming-plan/1', 'streaming plan version')
    snapshot = registry_snapshot(registry, root)
    graph = graph_from_registry(digest(artifact(plan['graph_pin'], snapshot)), snapshot)
    originals = original_pins_checked(plan['original_pins'], graph)
    task = artifact(plan['task_pin'], snapshot, JOB_BYTES)
    oracle = oracle_checked(oracle_raw, oracle_held, snapshot, plan['task_pin'])
    require(canonical(plan['oracle_pin']) == canonical(identity(oracle_raw)), 'streaming private oracle commitment')
    retrieval = parse(artifact(plan['retrieval_pin'], snapshot, JOB_BYTES))
    require(retrieval == {'schema': 'sentinel/retrieval-capabilities/1', **CAPABILITIES},
            'strong streaming retrieval baseline required')
    from .bundle import base_checked
    bases = plan['sast_bases']
    require(type(bases) is list and 1 <= len(bases) <= 16, 'registered SAST count')
    for base in bases:
        base_checked(base)
    expected = {}
    for row in graph['source_set']:
        key, value = row['source']['package_id'], (row['source']['sha256'], row['source']['bytes'])
        require(key not in expected or expected[key] == value, 'conflicting SAST package original identity')
        expected[key] = value
    actual = {row['package_id']: (row['source_sha256'], row['source_bytes']) for row in bases}
    require(len(actual) == len(bases) and actual == expected, 'complete SAST source set required')
    return {'plan': plan, 'snapshot': snapshot, 'graph': graph, 'originals': originals,
            'task': task, 'oracle': oracle, 'retrieval': retrieval, 'bases': bases}


@contextmanager
def verified_sast(handle):
    import transport_document as document
    from .bundle import register_bases
    require(type(handle) is dict and handle.get('active') is True, 'registered SAST handle closed')
    base, config = handle['base'], handle['config']
    key = base['package_id']
    root = digest(canonical({key: base}))
    registered = {key: config}
    declaration = {'index': {'bases': [base]}}
    register_bases(declaration, registered, root)
    with document.validated(config['archive'], config['share'], config['native']) as result:
        source, body, package_id, _sections = result
        require(package_id == key and (body['source']['sha256'], body['source']['bytes']) ==
                (base['source_sha256'], base['source_bytes']), 'registered recovered source/package mismatch')
        require(document.file_digest(source, MAX_ORIGINAL) ==
                (base['source_sha256'], base['source_bytes']), 'registered whole recovery mismatch')
        yield result
    register_bases(declaration, registered, root)


def sast_display(handle):
    import transport_document as document
    from transport_document_io import read_file
    with verified_sast(handle) as (source, body, package_id, sections):
        record = document.loads(read_file(source.parent / 'reading.json', document.MAX_META))
        entries = document.metadata(body['title'], sections, record)
        for name in ('formula.txt', 'lexicon.md'):
            require(identity(entries[name]) == body['entries'][name], 'registered SAST display metadata mismatch')
        share = read_file(handle['config']['share'], METADATA)
        document.share_checked(share, entries['formula.txt'].decode('utf-8'), package_id)
        require(len(entries['lexicon.md']) <= METADATA, 'registered SAST lexicon display bound')
        return {'share-' + package_id + '.txt': share,
                'lexicon-' + package_id + '.md': entries['lexicon.md']}


@contextmanager
def registered_sast_packages(registrations, bases, held_root):
    from .bundle import register_bases
    bases = parse(canonical(bases))
    configs = register_bases({'index': {'bases': bases}}, registrations, held_root)
    handles = {base['package_id']: {'base': base, 'config': configs[base['package_id']], 'active': True}
               for base in bases}
    try:
        display = {}
        for handle in handles.values():
            display.update(sast_display(handle))
        yield handles, display
        register_bases({'index': {'bases': bases}}, configs, held_root)
    finally:
        for handle in handles.values():
            handle['active'] = False


def streaming_prepared(inputs, display):
    plan, graph = inputs['plan'], inputs['graph']
    projection, task = graph_view(graph), inputs['task']
    views = {arm: {'task.txt': task} for arm in ARMS}
    for arm in ARMS:
        views[arm]['capabilities.json'] = canonical({'capabilities': ['GRAPH_ONLY'] if arm == 'C'
                                                   else inputs['retrieval'][arm]})
    views['C']['graph.json'] = projection; views['D']['graph.json'] = projection
    for arm in ('B', 'D'):
        views[arm].update(display)
        views[arm]['registered-sast.json'] = canonical({'schema': 'sentinel/registered-sast-view/1',
            'bases': inputs['bases'], 'retrieval': 'THROUGH_VALIDATED_SAST_ONLY'})
    oracle, snapshot = inputs['oracle'], inputs['snapshot']
    evaluator = {'oracle.json': canonical(oracle), 'expected-answer.bin':
        artifact(oracle['expected_answer_pin'], snapshot, JOB_BYTES),
        'criteria.bin': artifact(oracle['criteria_pin'], snapshot, JOB_BYTES),
        'adjudication.bin': artifact(oracle['adjudication_pin'], snapshot, JOB_BYTES)}
    manifest = {'schema': 'sentinel/four-arm-preparation/2', 'task_pin': plan['task_pin'],
        'graph_sha256': graph['graph_sha256'], 'source_set_sha256': graph['source_set_sha256'],
        'oracle_pin': plan['oracle_pin'], 'models': 'NOT_DISPATCHED',
        'max_concurrent_jobs': 2, 'isolation': 'NOT_ESTABLISHED', 'source_profile': 'REGISTERED_SAST_HANDLES',
        'arms': {arm: {'inventory': {name: identity(raw) for name, raw in files.items()},
            'registered_sources': list(inputs['originals'].values()) if arm == 'A' else [],
            'registered_sast': inputs['bases'] if arm in ('B', 'D') else []} for arm, files in views.items()},
        'evaluator_inventory': {name: identity(raw) for name, raw in evaluator.items()}}
    streaming_manifest_checked(manifest)
    streaming_views_checked(manifest, dict(views, evaluator=evaluator))
    return {'manifest': manifest, 'views': views, 'evaluator': evaluator}


@contextmanager
def prepare_four_arms_streaming(plan_raw, held, registry, root, oracle_raw, oracle_held,
                                original_paths, sast_registrations, held_base_root):
    inputs = streaming_inputs(plan_raw, held, registry, root, oracle_raw, oracle_held)
    with registered_sources(original_paths, inputs['originals']) as originals:
        with registered_sast_packages(sast_registrations, inputs['bases'], held_base_root) as (sast, display):
            prepared = streaming_prepared(inputs, display)
            yield prepared, {'A': originals, 'B': sast, 'C': {}, 'D': sast}


@contextmanager
def decoded_sast_stream(handles, package_id, reading=False):
    require(type(handles) is dict and package_id in handles and type(reading) is bool,
            'registered SAST package/coordinate missing')
    with verified_sast(handles[package_id]) as (source, body, _package_id, _sections):
        path, pin = source, {'sha256': body['source']['sha256'], 'bytes': body['source']['bytes']}
        if reading:
            require(body['reading'] is not None, 'registered SAST reading absent')
            integer(body['reading']['bytes'], 0, 33_554_432)
            path = source.parent / 'reading.txt'
            pin = {'sha256': body['reading']['sha256'], 'bytes': body['reading']['bytes']}
        with registered_sources({pin['sha256']: path}, {pin['sha256']: pin}) as streams:
            yield streams, pin['sha256']


def read_sast_registered(handles, package_id, start, end, reading=False):
    with decoded_sast_stream(handles, package_id, reading) as (streams, key):
        return read_registered(streams, key, start, end)


def search_sast_registered(handles, package_id, needle, maximum=256, reading=False):
    with decoded_sast_stream(handles, package_id, reading) as (streams, key):
        return search_registered(streams, key, needle, maximum)


def resolve_sast_registered(handles, package_id, locator_raw, locator_held,
                            locator_registry, locator_root, revision_registry, revision_root):
    from .locators import resolve_locator
    require(type(handles) is dict and package_id in handles, 'registered SAST package missing')
    handle = handles[package_id]
    with verified_sast(handle):
        config = handle['config']
        result = resolve_locator(config['archive'], config['share'], locator_raw, locator_held,
            locator_registry, locator_root, revision_registry, revision_root, config['native'])
        require(result['package_id'] == package_id, 'fallback locator wrong package')
        return result


def streaming_manifest_checked(manifest):
    fields(manifest, ('schema', 'task_pin', 'graph_sha256', 'source_set_sha256', 'oracle_pin',
        'models', 'max_concurrent_jobs', 'isolation', 'source_profile', 'arms', 'evaluator_inventory'))
    require(manifest['schema'] == 'sentinel/four-arm-preparation/2'
        and manifest['source_profile'] == 'REGISTERED_SAST_HANDLES'
        and manifest['models'] == 'NOT_DISPATCHED' and type(manifest['max_concurrent_jobs']) is int
        and manifest['max_concurrent_jobs'] == 2 and manifest['isolation'] == 'NOT_ESTABLISHED',
        'streaming preparation cannot grant execution')
    pin_checked(manifest['task_pin']); pin_checked(manifest['oracle_pin'])
    hash_checked(manifest['graph_sha256']); hash_checked(manifest['source_set_sha256'])
    fields(manifest['arms'], ARMS)
    from .bundle import base_checked
    for arm in ARMS:
        row = manifest['arms'][arm]
        fields(row, ('inventory', 'registered_sources', 'registered_sast'))
        require(type(row['registered_sources']) is list and len(row['registered_sources']) <= 16,
                'streaming original inventory bound')
        for pin in row['registered_sources']:
            source_pin(pin)
        require(type(row['registered_sast']) is list and len(row['registered_sast']) <= 16,
                'streaming SAST inventory bound')
        for base in row['registered_sast']:
            base_checked(base)
        require(arm == 'A' or not row['registered_sources'], 'only ArmA receives raw original handles')
        require(arm in ('B', 'D') or not row['registered_sast'], 'only B/D receive SAST handles')
    left, right = manifest['arms']['B']['registered_sast'], manifest['arms']['D']['registered_sast']
    require(bool(manifest['arms']['A']['registered_sources']) and bool(left)
            and canonical(left) == canonical(right), 'complete matched streaming handles required')
    expected = {row['source_sha256']: row['source_bytes'] for row in left}
    originals = {row['sha256']: row['bytes'] for row in manifest['arms']['A']['registered_sources']}
    require(expected == originals, 'registered original/SAST source set differs')
    for inventory in [manifest['evaluator_inventory']] + [manifest['arms'][arm]['inventory'] for arm in ARMS]:
        require(type(inventory) is dict and len(inventory) <= 36, 'streaming inventory bound')
        for pin in inventory.values():
            pin_checked(pin); require(pin['bytes'] <= METADATA, 'streaming display file bound')
    return manifest


def streaming_views_checked(manifest, files):
    display = set()
    for base in manifest['arms']['B']['registered_sast']:
        display.update(('share-' + base['package_id'] + '.txt', 'lexicon-' + base['package_id'] + '.md'))
    templates = {'A': {'task.txt', 'capabilities.json'}, 'C': {'task.txt', 'capabilities.json', 'graph.json'},
        'B': {'task.txt', 'capabilities.json', 'registered-sast.json'} | display,
        'D': {'task.txt', 'capabilities.json', 'registered-sast.json', 'graph.json'} | display}
    for arm in ARMS:
        require(set(files[arm]) == templates[arm], 'streaming role file template')
        require(identity(files[arm]['task.txt']) == manifest['task_pin'], 'streaming matched task changed')
        expected = ['GRAPH_ONLY'] if arm == 'C' else CAPABILITIES[arm]
        require(parse(files[arm]['capabilities.json']) == {'capabilities': expected}, 'streaming capability template')
    for name in templates['B'] - {'task.txt', 'capabilities.json'}:
        require(files['B'][name] == files['D'][name], 'streaming B/D SAST baseline differs')
    declared = {'schema': 'sentinel/registered-sast-view/1',
        'bases': manifest['arms']['B']['registered_sast'], 'retrieval': 'THROUGH_VALIDATED_SAST_ONLY'}
    require(files['B']['registered-sast.json'] == canonical(declared), 'registered SAST view mismatch')
    require(files['C']['graph.json'] == files['D']['graph.json'], 'streaming C/D graph differs')
    fields(files['evaluator'], ('oracle.json', 'expected-answer.bin', 'criteria.bin', 'adjudication.bin'))
    require(identity(files['evaluator']['oracle.json']) == manifest['oracle_pin'], 'streaming evaluator changed')
    require(all(raw != files['evaluator']['oracle.json'] for arm in ARMS for raw in files[arm].values()),
            'streaming private oracle in receiver view')
