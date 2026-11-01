"""Versioned host terminal journal; recorded failures are never success authority.

Uses the original Store and document reconciler. The legacy workflow runtime is
unchanged. Hosts supply terminal observations and externally held latest pins;
this adapter neither observes processes nor dispatches or authenticates models.
"""
from pathlib import Path

import transport_workflow_capture as capture
from sentinel_v1 import document_analysis as document, workflow
from sentinel_v1.common import (METADATA, ROUNDS, canonical, digest, fields,
    hash_checked, identity, parse, require)
from sentinel_v1.workflow_store import STORE_BYTES, STORE_FILES, Store, identifier

PROFILE = 'sentinel/workflow-terminal-history/1'
INPUTS = ('records_raw', 'records_held', 'registry', 'registry_held',
          'admission_raw', 'admission_held')


def journal_id(run_id, job_id):
    identifier(run_id); identifier(job_id)
    return digest(canonical({'schema': PROFILE, 'run_id': run_id, 'job_id': job_id}))


def adapter_identity():
    with Path(__file__).open('rb') as stream:
        raw = stream.read(METADATA + 1)
    require(len(raw) <= METADATA, 'terminal adapter source bound')
    return digest(raw)


# Predecessor of this migration only. Not a parameter and not a successor identity.
HISTORICAL_ADAPTER_IDENTITY = '276c0ec782e3007714984ba9044dd99280bca06c99dfb630efda626629a3941a'


def admitted_journal_runtime(events):
    """Admit this adapter or the one named predecessor. Do not rewrite the journal."""
    if not events:
        return adapter_identity()
    stored = hash_checked(events[0]['runtime'])
    current = adapter_identity()
    for event in events:
        require(event['runtime'] == stored, 'terminal journal profile/runtime differs')
    if stored != current:
        require(stored == HISTORICAL_ADAPTER_IDENTITY,
                'terminal journal runtime is not the admitted historical identity')
    return stored


def require_current_journal_publication(events, runtime):
    """Refuse to extend a historical journal or to publish as the predecessor."""
    require(runtime == adapter_identity(), 'terminal caller runtime is not this source')
    require(runtime != HISTORICAL_ADAPTER_IDENTITY,
            'historical adapter identity is not a publication identity')
    if events:
        require(events[0]['runtime'] == runtime, 'terminal historical identity is not extended')


def context(store, run_id, held, job_id, ancestor=False):
    events, head = store.chain(run_id, None if ancestor else held)
    if ancestor:
        matches = [index for index, row in enumerate(events)
                   if digest(canonical(row)) == held]
        require(len(matches) == 1, 'terminal workflow ancestor absent')
        events = events[:matches[0] + 1]
        head = identity(canonical(events[-1]))
    runtime = workflow.runtime_identity()
    plan, completed, _, status = workflow.checked_history(store, events, runtime)
    require(status == 'OPEN', 'terminal workflow must be ready for capture')
    pending = [row['id'] for row in parse(plan['client'])['jobs']
               if row['status'] == 'FRAME_ADMITTED' and row['id'] not in completed]
    require(pending and pending[0] == job_id, 'terminal next job differs')
    binding = {'run_id': run_id, 'job_id': job_id, 'base_head': head,
        'kernel_runtime': events[0]['runtime'], 'index': identity(plan['index']),
        'reading': identity(plan['reading']), 'binding': identity(plan['binding'])}
    return plan, binding, events, completed


def replay(plan, job_id, inputs):
    fields(inputs, INPUTS)
    document.reconciliation_inputs(inputs)
    raw = document.reconcile_job(plan['reading'], plan['binding'], plan['index'],
        digest(plan['index']), plan['blocks'], job_id, **inputs)
    return raw, parse(raw)


def prefix(rows, previous, successful):
    require(len(rows) == len(previous) + 1 and rows[:-1] == previous,
            'terminal exact prior prefix plus one attempt required')
    expected = ('ANALYZED_PROPOSED',) if successful else ('FAILED', 'INTERRUPTED')
    require(rows[-1]['status'] in expected, 'terminal attempt class differs')


def failure_closure(inputs, rows):
    require(parse(inputs['admission_raw'])['entries'] == [], 'terminal failure admission must be empty')
    used = set()
    for row in rows:
        require(row['status'] in ('FAILED', 'INTERRUPTED'), 'terminal history only records failures')
        key = row['request_sha256']; used.add(key); used.add(row['result_pin']['sha256'])
        request = parse(inputs['registry'][key])
        used.update((request['prompt_pin']['sha256'], request['reading_pin']['sha256']))
    require(used == set(inputs['registry']), 'terminal failure registry closure differs')


def stored_inputs(store, payload):
    return {'records_raw': store.get(payload['records']),
        'records_held': payload['records']['sha256'],
        'registry': workflow.registry_input(store, payload['registry']),
        'registry_held': payload['registry']['sha256'],
        'admission_raw': store.get(payload['admission']),
        'admission_held': payload['admission']['sha256']}


def checked_journal(store, plan, binding, held):
    name = journal_id(binding['run_id'], binding['job_id'])
    try:
        store.read('inbox', '@' + name)
    except FileNotFoundError:
        pass
    else:
        raise ValueError('terminal journal collides with workflow reservation')
    events, head = store.chain(name, held)
    require(held is not None or not events, 'terminal existing journal requires held latest pin')
    require(len(events) <= ROUNDS, 'terminal journal round bound')
    previous = []; runtime = admitted_journal_runtime(events)
    for event in events:
        require(event['runtime'] == runtime and event['kind'] == 'FAILURE_RECORDED',
                'terminal journal profile/runtime differs')
        payload = fields(event['payload'], ('schema', 'binding', 'records',
            'registry', 'admission', 'reconciliation'))
        require(payload['schema'] == PROFILE and payload['binding'] == binding,
                'terminal journal source/context binding differs')
        inputs = stored_inputs(store, payload)
        raw, result = replay(plan, binding['job_id'], inputs)
        require(raw == store.get(payload['reconciliation']), 'terminal replay differs')
        prefix(result['history'], previous, False); failure_closure(inputs, result['history'])
        previous = result['history']
    return events, head, previous


def publication(store, binding, events, head, inputs, reconciled):
    registry, manifest = capture.registry_manifest(inputs['registry'], inputs['registry_held'])
    objects = dict(registry)
    for raw in (manifest, inputs['records_raw'], inputs['admission_raw'], reconciled):
        objects[digest(raw)] = raw
    payload = {'schema': PROFILE, 'binding': binding,
        'records': identity(inputs['records_raw']), 'registry': identity(manifest),
        'admission': identity(inputs['admission_raw']), 'reconciliation': identity(reconciled)}
    name = journal_id(binding['run_id'], binding['job_id']); runtime = adapter_identity()
    require_current_journal_publication(events, runtime)
    expected = canonical({'schema': 'sentinel/workflow-event/1', 'run_id': name,
        'ordinal': len(events), 'previous': head, 'runtime': runtime,
        'kind': 'FAILURE_RECORDED', 'payload': payload})
    require(len(events) < ROUNDS and len(expected) <= METADATA, 'terminal publication bound')
    require(store.bytes + len(expected) + sum(map(len, objects.values())) <= STORE_BYTES
        and store.files + len(objects) + 1 <= STORE_FILES, 'terminal prospective store bound')
    for raw in objects.values():
        store.put(raw)
    published = store.event(name, events, head, runtime, 'FAILURE_RECORDED', payload)
    require(published == identity(expected), 'terminal event publication differs')
    return published


def outcome(binding, head, phase):
    return {'schema': PROFILE, 'phase': phase, 'binding': binding, 'journal_head': head,
        'provider_authentication': 'UNVERIFIED', 'qualification': 'NOT_QUALIFIED',
        'semantic_completeness': 'UNPROVEN', 'execution_authority': 'NONE'}


def capture_inputs(raw, held, artifacts):
    payload, snapshot = capture.packet_checked(raw, held, artifacts)
    require(payload['terminal_state'] == 'TERMINAL_RECORDED'
        and payload['admission'] is not None, 'terminal retry requires supplied success admission')
    manifest = parse(snapshot[payload['registry']['sha256']])
    inputs = {'records_raw': snapshot[payload['records']['sha256']],
        'records_held': payload['records']['sha256'],
        'registry': {key: snapshot[key] for key in manifest},
        'registry_held': payload['registry']['sha256'],
        'admission_raw': snapshot[payload['admission']['sha256']],
        'admission_held': payload['admission_sha256']}
    return payload, snapshot, inputs


def success_checked(plan, job_id, inputs, previous, payload):
    raw, result = replay(plan, job_id, inputs)
    require(result['status'] == 'RECORDED_GENERATION_IMPORTED', 'terminal retry did not reconcile')
    prefix(result['history'], previous, True)
    last = result['history'][-1]
    require(payload['job_id'] == job_id and last['request_sha256'] == payload['request']['sha256']
        and last['graph_sha256'] == payload['graph']['sha256']
        and last['provenance_sha256'] == payload['provenance']['sha256'], 'terminal candidate differs')
    return raw


def finish_generation(root, run_id, workflow_held, job_id, journal_held, terminal):
    """One host entry point for observed failure or externally admitted capture.

The caller must reconcile unknown process/publication state before calling.
No missing observation, successful provenance or admission is manufactured.
"""
    fields(terminal, ('inputs', 'capture', 'submission_id'))
    with Store(root).opened(create=False) as store:
        plan, binding, _, _ = context(store, run_id, workflow_held, job_id)
        events, head, previous = checked_journal(store, plan, binding, journal_held)
        if terminal['capture'] is None:
            require(terminal['submission_id'] is None, 'terminal failure has no submission')
            inputs = terminal['inputs']; raw, result = replay(plan, job_id, inputs)
            prefix(result['history'], previous, False); failure_closure(inputs, result['history'])
            head = publication(store, binding, events, head, inputs, raw)
            return outcome(binding, head, 'FAILURE_RECORDED_NOT_DISPATCHED')
        require(terminal['inputs'] is None, 'terminal success uses capture-bound inputs')
        packet = fields(terminal['capture'], ('raw', 'held', 'artifacts'))
        payload, artifacts, inputs = capture_inputs(**packet)
        success_checked(plan, job_id, inputs, previous, payload)
        pin = store.register(terminal['submission_id'], parse(packet['raw']), artifacts)
        result = outcome(binding, head, 'CAPTURE_REGISTERED_NOT_ADVANCED')
        result.update(submission_id=terminal['submission_id'], submission=pin)
        return result


def inspect_history(root, run_id, workflow_held, job_id, journal_held):
    with Store(root).opened(create=False) as store:
        plan, binding, _, _ = context(store, run_id, workflow_held, job_id, ancestor=True)
        _, head, previous = checked_journal(store, plan, binding, journal_held)
        result = outcome(binding, head, 'RECORDED_FAILURE_HISTORY')
        result['attempts'] = previous
        return result


def advance_retry(root, run_id, workflow_held, job_id, journal_held, submission_id, submission_held):
    """Check the failure prefix under the same lock as the legacy advancement.

Return a new head only; a fresh inspect must establish completed readback.
"""
    with Store(root).opened(create=False) as store:
        plan, binding, events, completed = context(store, run_id, workflow_held, job_id)
        _, journal_head, previous = checked_journal(store, plan, binding, journal_held)
        value = store.input(submission_id, submission_held)
        require(value['kind'] == 'capture', 'terminal retry input kind')
        payload = workflow.submission_input(store, submission_id, submission_held)
        inputs = stored_inputs(store, payload)
        success_checked(plan, job_id, inputs, previous, payload)
        args = {'run_id': run_id, 'expected_sha256': workflow_held,
            'submission_id': submission_id, 'submission_sha256': submission_held}
        head = workflow.Workflow(root)._advance(store, args, events, binding['base_head'],
            binding['kernel_runtime'], plan, completed)
        terminal = parse(store.read('events', run_id + '.%06d.json' % (len(events) + 1)))
        phase = 'ADVANCED_READBACK_PENDING' if terminal['kind'] == 'ADVANCED' else 'RETAINED_REFUSAL'
        result = outcome(binding, journal_head, phase)
        result.update(workflow_head=head, workflow_terminal=terminal['payload'])
        return result
