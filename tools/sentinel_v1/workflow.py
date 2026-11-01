"""Resumable, source-bound document preparation and recorded-evidence replay.

This additive workflow does not launch providers, qualify meaning, sign packages,
or grant action authority. Existing SAST interfaces remain normative. A host
registers inputs; tools use identifiers and independently held pins, never paths.
"""
import base64
from pathlib import Path

from . import document_analysis as document, document_client as client
from .common import (METADATA, SentinelError, canonical, digest, fields, hash_checked,
                     identity, parse, pin_checked, registry_snapshot, require)
from .workflow_store import Store, identifier

PROFILE = 'sentinel/automatic-workflow/1'
OPERATIONS = {
    'prepare': ('run_id', 'input_id', 'input_sha256'),
    'inspect': ('run_id', 'expected_sha256'),
    'advance': ('run_id', 'expected_sha256', 'submission_id', 'submission_sha256'),
    'receive': ('input_id', 'input_sha256'),
}


def runtime_identity():
    """Source identity, not a proof or executable authentication mechanism."""
    paths = sorted(Path(__file__).parent.glob('*.py'))
    require(0 < len(paths) <= 64, 'workflow source inventory bound')
    inventory = {}
    for path in paths:
        with path.open('rb') as stream:
            raw = stream.read(METADATA + 1)
        require(len(raw) <= METADATA, 'workflow source module bound')
        inventory[path.name] = identity(raw)
    return digest(canonical(inventory))


# Predecessor of this migration only. Not a parameter and not a successor identity.
HISTORICAL_WORKFLOW_RUNTIME = 'c2bd5ef4737183bde8eb787dc7035cbb6eaa05938a93797636bd63b45b6575b8'


def admitted_event_runtime(events, runtime):
    """Admit this source or the one named predecessor. Historical events stay historical."""
    require(runtime == runtime_identity(), 'workflow caller runtime is not this source')
    require(len(events) >= 1, 'workflow missing origin')
    stored = hash_checked(events[0]['runtime'])
    for event in events:
        require(event['runtime'] == stored, 'workflow runtime source identity differs')
    if stored != runtime:
        require(stored == HISTORICAL_WORKFLOW_RUNTIME,
                'workflow runtime is not the admitted historical identity')
    return stored


def require_current_publication(events, runtime):
    """Refuse to extend a historical chain or to publish as the predecessor."""
    require(runtime == runtime_identity(), 'workflow caller runtime is not this source')
    require(runtime != HISTORICAL_WORKFLOW_RUNTIME,
            'historical workflow identity is not a publication identity')
    if events:
        require(events[0]['runtime'] == runtime, 'workflow historical identity is not extended')


def reading_bytes(store, pins):
    require(type(pins) is list and len(pins) <= 32, 'workflow reading chunk bound')
    total = 0
    for pin in pins:
        pin_checked(pin)
        require(pin['bytes'] <= METADATA, 'workflow reading chunk byte bound')
        total += pin['bytes']
    require(total <= document.MAX_READING, 'workflow reading aggregate bound')
    return b''.join(store.get(pin) for pin in pins)


def document_input(store, name, held):
    envelope = store.input(name, held)
    require(envelope['kind'] == 'document', 'workflow document input required')
    value = envelope['payload']
    fields(value, ('reading', 'binding', 'hierarchy', 'dependencies', 'dispatch', 'packing_target'))
    reading = reading_bytes(store, value['reading'])
    binding = store.get(value['binding'])
    hierarchy = None if value['hierarchy'] is None else store.get(value['hierarchy'])
    dependencies = None if value['dependencies'] is None else store.get(value['dependencies'])
    if value['packing_target'] is None:
        plan = client.plan(reading, binding, value['dispatch'], hierarchy, dependencies)
    else:
        plan = client.plan_targeted(reading, binding, value['dispatch'],
            value['packing_target'], hierarchy, dependencies)
    return {'reading': reading, 'binding': binding, **plan}


def plan_pins(plan):
    return {'index': identity(plan['index']), 'client': identity(plan['client']),
            'blocks': {key: identity(raw) for key, raw in plan['blocks'].items()}}


def plan_artifacts(plan):
    return [plan['index'], plan['client'], *plan['blocks'].values()]


def registry_input(store, pin):
    raw = store.get(pin)
    value = parse(raw)
    require(type(value) is dict and len(value) <= 256, 'workflow capture registry bound')
    total = 0
    for key, item in value.items():
        pin_checked(item)
        require(item['sha256'] == key and item['bytes'] <= METADATA, 'workflow registry pin')
        total += item['bytes']
    require(total <= 8_388_608, 'workflow capture aggregate bound')
    registry = {key: store.get(item) for key, item in value.items()}
    return registry_snapshot(registry, digest(raw))


def submission_input(store, name, held):
    envelope = store.input(name, held)
    require(envelope['kind'] == 'capture', 'workflow capture input required')
    value = envelope['payload']
    fields(value, ('job_id', 'terminal_state', 'request', 'graph', 'provenance',
                  'registry', 'records', 'admission', 'admission_sha256'))
    identifier(value['job_id'])
    require(value['terminal_state'] in ('LIVE_OR_UNKNOWN', 'TERMINAL_RECORDED'),
            'workflow capture terminal state')
    return value


def evaluated_submission(store, plan, value):
    job_id = value['job_id']
    rows = parse(plan['client'])['jobs']
    require(any(row['id'] == job_id and row['status'] == 'FRAME_ADMITTED' for row in rows),
            'workflow capture job not frame admitted')
    result = {'job_id': job_id, 'status': 'BLOCKED_PENDING_EXTERNAL_CONTEXT',
              'import': None, 'reconciliation': None}
    if value['terminal_state'] != 'TERMINAL_RECORDED':
        return result, {}, None
    request, graph, provenance = [store.get(value[key]) for key in ('request', 'graph', 'provenance')]
    registry = registry_input(store, value['registry'])
    imported = document.import_candidate(request, digest(request), graph, digest(graph),
        plan['reading'], plan['binding'], plan['index'], digest(plan['index']),
        plan['blocks'], registry, value['registry']['sha256'], provenance, digest(provenance))
    require(parse(imported)['job_id'] == job_id, 'workflow imported job differs')
    result.update(status='WAITING_HELD_ADMISSION', **{'import': identity(imported)})
    outputs = {digest(imported): imported}
    if value['admission'] is None:
        require(value['admission_sha256'] is None, 'workflow missing admission pin')
        return result, outputs, None
    admission = store.get(value['admission'])
    require(digest(admission) == value['admission_sha256'], 'workflow admission held pin differs')
    records = store.get(value['records'])
    inputs = {'records_raw': records, 'records_held': digest(records), 'registry': registry,
        'registry_held': value['registry']['sha256'], 'admission_raw': admission,
        'admission_held': value['admission_sha256']}
    reconciled = document.reconcile_job(plan['reading'], plan['binding'], plan['index'],
        digest(plan['index']), plan['blocks'], job_id, **inputs)
    if parse(reconciled)['status'] == 'RECORDED_GENERATION_IMPORTED':
        latest = parse(records)['attempts'][-1]
        require(latest['request_sha256'] == digest(request)
            and latest['graph_sha256'] == digest(graph)
            and latest['provenance_sha256'] == digest(provenance)
            and latest['result_pin'] == identity(imported),
            'workflow reconciled attempt differs from supplied candidate')
    result.update(status=parse(reconciled)['status'], reconciliation=identity(reconciled))
    outputs[digest(reconciled)] = reconciled
    return result, outputs, inputs


def retained_outputs(store, artifacts):
    for raw in artifacts:
        require(store.get(identity(raw)) == raw, 'workflow completed output differs')


def checked_history(store, events, runtime):
    stored = admitted_event_runtime(events, runtime)
    require(events[0]['kind'] == 'PREPARE_INTENT', 'workflow missing origin')
    origin = fields(events[0]['payload'], ('input_id', 'input_sha256'))
    require(store.read('inbox', '@' + events[0]['run_id']) == canonical({
        'schema': 'sentinel/workflow-reservation/1', 'run_id': events[0]['run_id'],
        'runtime': stored, 'origin': origin}), 'workflow run reservation differs')
    plan = document_input(store, origin['input_id'], origin['input_sha256'])
    if len(events) == 1:
        return plan, {}, {}, 'INTERRUPTED_PREPARATION'
    require(events[1]['kind'] == 'PREPARED' and events[1]['payload'] == plan_pins(plan),
            'workflow prepared output differs')
    retained_outputs(store, plan_artifacts(plan))
    completed, inputs, previous_records = {}, {}, {}
    for offset in range(2, len(events), 2):
        intent = events[offset]
        require(intent['kind'] == 'ADVANCE_INTENT', 'workflow unexpected transition')
        fields(intent['payload'], ('submission_id', 'submission_sha256'))
        value = store_submission(store, intent['payload'])
        require(value['job_id'] not in completed, 'workflow completed job resubmission')
        if offset + 1 == len(events):
            return plan, completed, inputs, 'INTERRUPTED_ADVANCEMENT'
        terminal = events[offset + 1]
        if terminal['kind'] == 'REFUSED':
            fields(terminal['payload'], ('reason', 'message'))
            require(offset + 2 == len(events), 'workflow failure cannot be skipped')
            try:
                evaluated_submission(store, plan, value)
            except (SentinelError, OSError) as error:
                require(terminal['payload'] == failure_detail(error), 'workflow failure evidence differs')
            else:
                raise SentinelError('workflow claimed failure not reproduced')
            return plan, completed, inputs, 'RETAINED_FAILURE_REQUIRES_REVIEW'
        require(terminal['kind'] == 'ADVANCED', 'workflow terminal transition missing')
        result, outputs, job_inputs = evaluated_submission(store, plan, value)
        require(terminal['payload'] == result, 'workflow recorded result differs')
        retained_outputs(store, outputs.values())
        check_attempt_prefix(value, job_inputs, previous_records)
        if result['status'] == 'RECORDED_GENERATION_IMPORTED':
            completed[value['job_id']] = result
            inputs[value['job_id']] = job_inputs
    status = 'OPEN'
    if len(events) > 2:
        latest = events[-1]['payload']['status']
        if latest != 'RECORDED_GENERATION_IMPORTED':
            status = latest
    return plan, completed, inputs, status


def store_submission(store, value):
    return submission_input(store, value['submission_id'], value['submission_sha256'])


def failure_detail(error):
    message = str(error)
    require(len(message.encode('utf-8')) <= 65_536, 'workflow failure artifact bound')
    return {'reason': type(error).__name__, 'message': message}


def check_attempt_prefix(value, inputs, previous):
    if inputs is None:
        return
    attempts = parse(inputs['records_raw'])['attempts']
    old = previous.get(value['job_id'], [])
    require(attempts[:len(old)] == old, 'workflow removed previous attempt evidence')
    previous[value['job_id']] = attempts


class Workflow:
    """Durable orchestration; external evidence and native qualification stay separate."""

    def __init__(self, root):
        self.root = root

    def call(self, operation, args):
        require(type(operation) is str and operation in OPERATIONS, 'workflow operation')
        fields(args, OPERATIONS[operation])
        with Store(self.root).opened(create=operation == 'prepare') as store:
            if operation == 'prepare':
                result = self._prepare(store, args)
            elif operation == 'receive':
                result = self._receive(store, args)
            else:
                events, head = store.chain(args['run_id'], args['expected_sha256'])
                runtime = runtime_identity()
                plan, completed, inputs, status = checked_history(store, events, runtime)
                if operation == 'advance':
                    require(status in ('OPEN', 'WAITING_HELD_ADMISSION',
                        'BLOCKED_PENDING_EXTERNAL_CONTEXT'), 'workflow interrupted/failed state requires review')
                    head = self._advance(store, args, events, head, runtime, plan, completed)
                    events, head = store.chain(args['run_id'], head['sha256'])
                    plan, completed, inputs, status = checked_history(store, events, runtime)
                result = self._view(store, args['run_id'], head, plan, completed, inputs, status)
        canonical(result)
        return result

    def _prepare(self, store, args):
        identifier(args['run_id'])
        events, previous = store.chain(args['run_id'])
        require(not events, 'workflow occupied run; inspect with externally held pin')
        runtime = runtime_identity()
        origin = {'input_id': args['input_id'], 'input_sha256': args['input_sha256']}
        plan = document_input(store, args['input_id'], args['input_sha256'])
        store.create('inbox', '@' + args['run_id'], canonical({
            'schema': 'sentinel/workflow-reservation/1', 'run_id': args['run_id'],
            'runtime': runtime, 'origin': origin}))
        first = store.event(args['run_id'], [], None, runtime, 'PREPARE_INTENT', origin)
        for raw in plan_artifacts(plan):
            store.put(raw)
        events, previous = store.chain(args['run_id'], first['sha256'])
        head = store.event(args['run_id'], events, previous, runtime, 'PREPARED', plan_pins(plan))
        return self._view(store, args['run_id'], head, plan, {}, {}, 'OPEN')

    def _advance(self, store, args, events, head, runtime, plan, completed):
        require_current_publication(events, runtime)
        source = {'submission_id': args['submission_id'], 'submission_sha256': args['submission_sha256']}
        value = store_submission(store, source)
        require(value['job_id'] not in completed, 'workflow completed job resubmission')
        if len(events) > 2 and events[-1]['payload']['status'] != 'RECORDED_GENERATION_IMPORTED':
            require(events[-1]['payload']['job_id'] == value['job_id'],
                    'workflow unresolved capture must be reconciled first')
        for offset in range(2, len(events), 2):
            old = store_submission(store, events[offset]['payload'])
            if old['job_id'] == value['job_id'] and old['terminal_state'] == 'TERMINAL_RECORDED':
                require(all(old[key] == value[key] for key in old
                    if key not in ('admission', 'admission_sha256')),
                    'workflow captured evidence changed; use a separately reviewed refinement')
        intent = store.event(args['run_id'], events, head, runtime, 'ADVANCE_INTENT', source)
        events, previous = store.chain(args['run_id'], intent['sha256'])
        try:
            result, outputs, _ = evaluated_submission(store, plan, value)
            for raw in outputs.values():
                store.put(raw)
        except (SentinelError, OSError) as error:
            return store.event(args['run_id'], events, previous, runtime, 'REFUSED', failure_detail(error))
        return store.event(args['run_id'], events, previous, runtime, 'ADVANCED', result)

    def _view(self, store, run_id, head, plan, completed, inputs, status):
        index, manifest = parse(plan['index']), parse(plan['client'])
        pending = [row for row in manifest['jobs']
                   if row['status'] == 'FRAME_ADMITTED' and row['id'] not in completed]
        unadmitted = sum(row['status'] != 'FRAME_ADMITTED' for row in manifest['jobs'])
        result = {'schema': PROFILE, 'run_id': run_id, 'head': head, 'status': status,
            'index': identity(plan['index']), 'client': identity(plan['client']),
            'reading': identity(plan['reading']), 'paragraph_count': index['paragraph_count'],
            'group_count': index['group_count'], 'job_count': index['job_count'],
            'completed_jobs': len(completed), 'pending_jobs': len(pending),
            'frame_unadmitted_groups': unadmitted,
            'coverage': index['coverage'], 'next_action': None,
            'source_authentication': 'HOST_HELD_BINDING_NOT_NATIVE_PACKAGE_VERIFICATION',
            'native_qualification': 'NOT_PERFORMED', 'qualification': 'NOT_QUALIFIED',
            'semantic_completeness': 'UNPROVEN', 'context_adequacy': 'UNPROVEN',
            'execution_authority': 'NONE'}
        if status != 'OPEN':
            return result
        if pending:
            row = pending[0]
            prepared = client.prepare(plan['client'], digest(plan['client']), plan['reading'],
                plan['binding'], plan['index'], digest(plan['index']), plan['blocks'], row['id'])
            result['status'] = 'WAITING_EXTERNAL_CAPTURE'
            result['next_action'] = {'kind': 'CAPTURE_REQUIRED', 'job_id': row['id'],
                'request': parse(prepared['request']), 'prompt': prepared['prompt'].decode('utf-8'),
                'frame_pin': identity(prepared['frame']),
                'frame_base64': base64.b64encode(prepared['frame']).decode('ascii')}
        elif unadmitted:
            result['status'] = 'INCOMPLETE_FRAME_UNADMITTED_OR_OPAQUE'
        elif index['job_count'] == len(completed):
            raw = document.reconcile_document(plan['reading'], plan['binding'], plan['index'],
                digest(plan['index']), plan['blocks'], inputs)
            result['document_reconciliation'] = parse(raw)
            result['status'] = 'WAITING_NATIVE_QUALIFICATION' if parse(raw)['status'] == \
                'RECORDED_GENERATION_IMPORTS_REPLAYED' else parse(raw)['status']
        return result

    def _receive(self, store, args):
        envelope = store.input(args['input_id'], args['input_sha256'])
        require(envelope['kind'] == 'received-package', 'workflow received package required')
        payload = fields(envelope['payload'], ('share', 'archive_chunks', 'archive_sha256',
                                              'decoder_identity'))
        share = store.get(payload['share'])
        archive = reading_bytes(store, payload['archive_chunks'])
        require(digest(archive) == payload['archive_sha256'], 'workflow archive identity differs')
        require(type(payload['decoder_identity']) is str, 'workflow declared decoder identity')
        return {'schema': PROFILE, 'status': 'WAITING_NATIVE_VERIFICATION',
            'share': identity(share), 'archive': identity(archive),
            'verification': 'NOT_PERFORMED', 'explanation': None,
            'qualification': 'NOT_QUALIFIED', 'semantic_completeness': 'UNPROVEN',
            'context_adequacy': 'UNPROVEN', 'execution_authority': 'NONE'}
