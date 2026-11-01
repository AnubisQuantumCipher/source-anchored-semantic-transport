"""Host-only generation handoff and recorded-capture submission.

Provider calls, terminal observations and generation admission are supplied by
the host. This module never creates them, executes source instructions or grants
qualification. Existing workflow and document checks remain normative.
"""
import base64

from sentinel_v1 import assessments, document_analysis as document, document_client, locators
from sentinel_v1.common import (JOB_BYTES, METADATA, REGISTRY, SentinelError, canonical, digest,
    fields, hash_checked, held_record, identity, integer, label, parse, registry_snapshot, require)
from transport_document_io import MAX_SOURCE
from sentinel_v1.workflow import Workflow
from sentinel_v1.workflow_store import Store, identifier

PROFILE = 'sentinel/workflow-capture-host/1'
CAPTURE_FIELDS = ('job_id', 'terminal_state', 'request', 'graph', 'provenance',
                  'registry', 'records', 'admission', 'admission_sha256')


def artifact(raw, cap=JOB_BYTES):
    require(type(raw) is bytes and 0 < len(raw) <= cap, 'capture immutable artifact bound')
    return raw


def _install_unsplit():
    """Seal reader bytes where ordinary construction and assignment cannot replace them."""
    bound = {}

    class UnsplitGeneration(object):
        __slots__ = ()

        def __init__(self, *_args):
            raise SentinelError('sliced prefix is not the complete generation')

        def __setattr__(self, _name, _value):
            raise SentinelError('sliced prefix is not the complete generation')

        @property
        def raw(self):
            value = bound.get(self)
            if type(value) is not bytes or len(value) == 0 or len(value) > JOB_BYTES:
                raise SentinelError('sliced prefix is not the complete generation')
            return value

    def seal(raw):
        require(type(raw) is bytes and 0 < len(raw) <= JOB_BYTES,
                'sliced prefix is not the complete generation')
        held = UnsplitGeneration.__new__(UnsplitGeneration)
        bound[held] = bytes(raw)
        return held

    return UnsplitGeneration, seal


UnsplitGeneration, _seal_unsplit = _install_unsplit()


def read_unsplit(stream):
    """Read until EOF or the job cap. A short read is not treated as the end."""
    parts = []
    total = 0
    saw_end = False
    for _offset in range(JOB_BYTES + 1):
        piece = stream.read(JOB_BYTES + 1 - total)
        require(type(piece) is bytes and len(piece) <= JOB_BYTES + 1 - total,
                'generation intake requires bytes')
        if piece == b'':
            saw_end = True
            break
        total += len(piece)
        if total > JOB_BYTES:
            raise SentinelError('output exceeds job bound; not partitioned into an accepted graph')
        parts.append(piece)
    require(saw_end, 'output exceeds job bound; not partitioned into an accepted graph')
    require(0 < total, 'host receiver requires the complete generation')
    return _seal_unsplit(b''.join(parts))


def _generation_bytes(complete_response):
    """Accept only a full read. Raw bytes can be a substituted prefix."""
    if complete_response is None:
        raise SentinelError('host receiver requires the complete generation')
    if type(complete_response) is bytes and len(complete_response) > JOB_BYTES:
        raise SentinelError('output exceeds job bound; not partitioned into an accepted graph')
    require(type(complete_response) is UnsplitGeneration,
            'sliced prefix is not the complete generation')
    return complete_response.raw


PACKAGE_PROFILE = 'sast/automatic-file-package/1'
UNSIGNED_ENVELOPE = 'sast/unsigned-source-envelope/1'
KEY_ADMISSION_REFUSAL = 'sast/production-key-admission-refusal/1'
DEPENDENCY_INVALIDATION = 'sast/source-dependency-invalidation/1'


def _install_source():
    """Seal source bytes where ordinary construction and assignment cannot replace them."""
    bound = {}

    class SealedSource(object):
        __slots__ = ()

        def __init__(self, *_args):
            raise SentinelError('sliced prefix is not the complete source')

        def __setattr__(self, _name, _value):
            raise SentinelError('sliced prefix is not the complete source')

        @property
        def raw(self):
            value = bound.get(self)
            if type(value) is not bytes or len(value) == 0 or len(value) > METADATA:
                raise SentinelError('sliced prefix is not the complete source')
            return value

    def seal(raw):
        require(type(raw) is bytes and 0 < len(raw) <= METADATA,
                'sliced prefix is not the complete source')
        held = SealedSource.__new__(SealedSource)
        bound[held] = bytes(raw)
        return held

    return SealedSource, seal


SealedSource, _seal_source = _install_source()


def read_source(stream):
    """Read one source until EOF or the metadata bound. A short read is not the end."""
    parts = []
    total = 0
    saw_end = False
    for _offset in range(METADATA + 1):
        piece = stream.read(METADATA + 1 - total)
        require(type(piece) is bytes and len(piece) <= METADATA + 1 - total,
                'source intake requires bytes')
        if piece == b'':
            saw_end = True
            break
        total += len(piece)
        if total > METADATA:
            raise SentinelError('source exceeds metadata bound; not accepted as a package')
        parts.append(piece)
    require(saw_end, 'source exceeds metadata bound; not accepted as a package')
    require(0 < total, 'automatic package requires the complete source')
    return _seal_source(b''.join(parts))


def _source_bytes(source):
    """Accept only a full source read. Raw bytes can be a substituted prefix."""
    if source is None:
        raise SentinelError('automatic package requires the complete source')
    if type(source) is bytes and len(source) > METADATA:
        raise SentinelError('source exceeds metadata bound; not accepted as a package')
    require(type(source) is SealedSource, 'sliced prefix is not the complete source')
    return source.raw


def unsigned_source_envelope(source):
    """Canonical unsigned record of one preserved source. Not a signature or a ZIP."""
    raw = _source_bytes(source)
    return canonical({'schema': UNSIGNED_ENVELOPE, 'source_sha256': digest(raw),
        'source_bytes': len(raw), 'signature': None,
        'production_key_admission': 'ABSENT', 'zip_written': False,
        'qualification': 'NOT_QUALIFIED', 'semantic_completeness': 'UNPROVEN',
        'execution_authority': 'NONE'})


def production_signing_refusal(source, offered=None):
    """Name the absent signing inputs. A supplied key is not admission.

    No key is generated. No provider is called. The offered value is not echoed.
    """
    raw = _source_bytes(source)
    require(offered is None, 'production signing is not admitted')
    return canonical({'schema': KEY_ADMISSION_REFUSAL, 'status': 'REFUSED',
        'reason': 'production signing is not admitted', 'source_sha256': digest(raw),
        'source_bytes': len(raw), 'production_key_admission': 'ABSENT',
        'trust_distribution': 'ABSENT', 'current_revocation': 'NOT_RECHECKED',
        'signature': None, 'zip_written': False, 'provider_called': False,
        'key_generated': False, 'qualification': 'NOT_QUALIFIED',
        'semantic_completeness': 'UNPROVEN', 'execution_authority': 'NONE'})


def source_package_gate(source):
    """Preserve one complete source and refuse production signing.

    No ZIP is written. No provider is called. The digest is not qualification.
    The envelope binds the source hash. The refusal names the absent signing inputs.
    """
    raw = _source_bytes(source)
    envelope = unsigned_source_envelope(source)
    refusal = production_signing_refusal(source)
    return {'schema': PACKAGE_PROFILE, 'status': 'REFUSED',
            'reason': 'production signing is not admitted',
            'phase': 'SOURCE_PRESERVED_NOT_SIGNED', 'source_bytes': len(raw),
            'source_sha256': digest(raw), 'signed_export': 'NOT_PERFORMED',
            'production_key_admission': 'ABSENT', 'trust_distribution': 'ABSENT',
            'current_revocation': 'NOT_RECHECKED', 'key_generated': False,
            'provider_called': False, 'zip_written': False,
            'envelope_schema': UNSIGNED_ENVELOPE, 'envelope_sha256': digest(envelope),
            'envelope_bytes': len(envelope), 'refusal_schema': KEY_ADMISSION_REFUSAL,
            'refusal_sha256': digest(refusal), 'refusal_bytes': len(refusal),
            'graph_import': 'NOT_PERFORMED', 'registered': False,
            'qualification': 'NOT_QUALIFIED', 'semantic_completeness': 'UNPROVEN',
            'context_adequacy': 'UNPROVEN', 'execution_authority': 'NONE'}


def _prior_envelope(previous):
    """Require one canonical unsigned envelope. Do not echo its bytes."""
    require(type(previous) is bytes, 'prior envelope must be the unsigned source record')
    try:
        parsed = parse(previous)
        require(previous == canonical(parsed),
                'prior envelope must be the unsigned source record')
    except SentinelError:
        raise SentinelError('prior envelope must be the unsigned source record') from None
    fields = {'schema', 'source_sha256', 'source_bytes', 'signature',
              'production_key_admission', 'zip_written', 'qualification',
              'semantic_completeness', 'execution_authority'}
    require(type(parsed) is dict and set(parsed) == fields,
            'prior envelope must be the unsigned source record')
    require(parsed['schema'] == UNSIGNED_ENVELOPE
            and parsed['signature'] is None and parsed['zip_written'] is False
            and parsed['qualification'] == 'NOT_QUALIFIED'
            and parsed['production_key_admission'] == 'ABSENT'
            and parsed['semantic_completeness'] == 'UNPROVEN'
            and parsed['execution_authority'] == 'NONE',
            'prior envelope must be the unsigned source record')
    try:
        prior = hash_checked(parsed['source_sha256'])
    except SentinelError:
        raise SentinelError('prior envelope must be the unsigned source record') from None
    require(type(parsed['source_bytes']) is int and parsed['source_bytes'] > 0,
            'prior envelope must be the unsigned source record')
    return prior, parsed['source_bytes']


def source_dependency_invalidation(previous, source):
    """Invalidate carried dependencies when the source identity changes.

    A matching hash does not revalidate context. No key, ZIP, or provider call.
    The prior bytes are not copied into the result.
    """
    raw = _source_bytes(source)
    prior, prior_bytes = _prior_envelope(previous)
    current = digest(raw)
    if prior == current:
        require(prior_bytes == len(raw), 'prior envelope must be the unsigned source record')
    changed = prior != current
    envelope = unsigned_source_envelope(source)
    refusal = production_signing_refusal(source)
    return canonical({'schema': DEPENDENCY_INVALIDATION,
        'status': 'INVALIDATED' if changed else 'UNCHANGED',
        'reason': 'source identity changed' if changed else 'source identity matches the prior envelope',
        'previous_source_sha256': prior, 'source_sha256': current,
        'source_bytes': len(raw),
        'prior_context': 'INVALIDATED' if changed else 'NOT_REVALIDATED',
        'prior_qualification': 'INVALIDATED' if changed else 'NOT_REVALIDATED',
        'prior_envelope': 'NOT_CARRIED' if changed else 'SAME_SOURCE',
        'envelope_sha256': digest(envelope), 'refusal_sha256': digest(refusal),
        'production_key_admission': 'ABSENT', 'trust_distribution': 'ABSENT',
        'current_revocation': 'NOT_RECHECKED', 'signature': None,
        'zip_written': False, 'key_generated': False, 'provider_called': False,
        'qualification': 'NOT_QUALIFIED', 'semantic_completeness': 'UNPROVEN',
        'context_adequacy': 'UNPROVEN', 'execution_authority': 'NONE'})


LINEAGE_CHECK = 'sast/manifest-lineage-check/1'
_REVISION_FIELDS = ('schema', 'id', 'source_sha256', 'source_bytes', 'previous_sha256')
_REVISION_MESSAGE = 'revision registry must be the held source-revision records'
_PACKAGE_MESSAGE = 'package identity must be the existing source pin'


def _revision_value(raw):
    """Parse one revision record or refuse without echoing it."""
    try:
        value = parse(raw, locators.REVISION_BYTES)
        fields(value, _REVISION_FIELDS)
        require(value['schema'] == 'sentinel/source-revision/1', _REVISION_MESSAGE)
        label(value['id'])
        hash_checked(value['source_sha256'])
        integer(value['source_bytes'], 0, MAX_SOURCE)
        if value['previous_sha256'] is not None:
            hash_checked(value['previous_sha256'])
        require(raw == canonical(value), _REVISION_MESSAGE)
    except SentinelError:
        raise SentinelError(_REVISION_MESSAGE) from None
    return value


def _held_revisions(revisions, selected):
    """Require content-addressed revision bytes. Do not echo them."""
    require(type(revisions) is dict and 0 < len(revisions) <= locators.REVISION_CAP,
            _REVISION_MESSAGE)
    require(type(selected) is str, _REVISION_MESSAGE)
    try:
        hash_checked(selected)
    except SentinelError:
        raise SentinelError(_REVISION_MESSAGE) from None
    require(selected in revisions, _REVISION_MESSAGE)
    items = tuple(revisions.items())
    require(len(items) == len(revisions), _REVISION_MESSAGE)
    checked, current = {}, None
    for key, raw in items:
        try:
            hash_checked(key)
        except SentinelError:
            raise SentinelError(_REVISION_MESSAGE) from None
        require(type(raw) is bytes and 0 < len(raw) <= locators.REVISION_BYTES
                and digest(raw) == key, _REVISION_MESSAGE)
        value = _revision_value(raw)
        checked[key] = raw
        if key == selected:
            current = value
    require(current is not None, _REVISION_MESSAGE)
    root = {'revision': {'id': current['id'], 'artifact_sha256': selected,
                         'previous_sha256': current['previous_sha256']},
            'source': {'sha256': current['source_sha256'],
                       'bytes': current['source_bytes']}}
    return checked, root, current


def _package_relations(packages, source_sha256, source_bytes):
    """Name package identity against one revision source. Do not reject repackaging."""
    require(type(packages) is tuple and 1 <= len(packages) <= locators.REVISION_CAP,
            _PACKAGE_MESSAGE)
    prepared, matching = [], []
    for item in packages:
        locators.source_checked(item)
        prepared.append((item['package_id'], item['sha256'], item['bytes']))
        if item['sha256'] == source_sha256 and item['bytes'] == source_bytes:
            matching.append(item['package_id'])
    repack = len(set(matching)) > 1
    rows = []
    for package_id, sha256, size in prepared:
        same = sha256 == source_sha256 and size == source_bytes
        if not same:
            relation = 'DIFFERENT_SOURCE'
        elif repack:
            relation = 'REPACKAGED_SAME_SOURCE'
        else:
            relation = 'SAME_PACKAGE'
        rows.append({'package_id': package_id, 'source_sha256': sha256,
                     'source_bytes': size, 'relation': relation})
    return rows, repack


def manifest_lineage_check(revisions, selected, packages):
    """Close one supplied revision registry and name package repackaging.

    The existing source-revision checker is authoritative for closure.
    A closed chain is not a canonical document. No key, ZIP, or provider call.
    Frozen manifest profiles are not redefined.
    """
    checked, root, current = _held_revisions(revisions, selected)
    locators.revision_records(checked, root)
    rows, repack = _package_relations(packages, current['source_sha256'], current['source_bytes'])
    return canonical({'schema': LINEAGE_CHECK,
        'status': 'CLOSED_RELATIVE_TO_SUPPLIED_REGISTRY',
        'selected_revision_sha256': selected, 'selected_id': current['id'],
        'source_sha256': current['source_sha256'], 'source_bytes': current['source_bytes'],
        'previous_sha256': current['previous_sha256'],
        'genesis': current['previous_sha256'] is None,
        'chain_records': len(checked), 'packages': rows,
        'repackaging': 'DETECTED' if repack else 'NOT_OBSERVED',
        'repackaging_rejected': False, 'canonical_document': 'NOT_ESTABLISHED',
        'fresh_genesis_prohibited': False, 'continuity_policy': 'ABSENT',
        'production_key_admission': 'ABSENT', 'trust_distribution': 'ABSENT',
        'current_revocation': 'NOT_RECHECKED', 'signature': None,
        'zip_written': False, 'key_generated': False, 'provider_called': False,
        'frozen_manifest_redefined': False, 'qualification': 'NOT_QUALIFIED',
        'semantic_completeness': 'UNPROVEN', 'context_adequacy': 'UNPROVEN',
        'execution_authority': 'NONE'})


LINEAGE_REQUEST = 'sast/manifest-lineage-request/1'
_REQUEST_FIELDS = ('schema', 'selected', 'revisions', 'packages')
_REQUEST_MESSAGE = 'lineage request must be the supplied revision registry'


def read_lineage_request(stream):
    """Read one lineage request until EOF or the metadata bound."""
    parts = []
    total = 0
    saw_end = False
    for _offset in range(METADATA + 1):
        piece = stream.read(METADATA + 1 - total)
        require(type(piece) is bytes and len(piece) <= METADATA + 1 - total,
                _REQUEST_MESSAGE)
        if piece == b'':
            saw_end = True
            break
        total += len(piece)
        if total > METADATA:
            raise SentinelError(_REQUEST_MESSAGE)
        parts.append(piece)
    require(saw_end and 0 < total <= METADATA, _REQUEST_MESSAGE)
    return b''.join(parts)


def _decode_revisions(revisions):
    """Decode exact revision bytes. Do not canonicalize or echo them."""
    require(type(revisions) is dict, _REQUEST_MESSAGE)
    checked = {}
    for key, encoded in revisions.items():
        try:
            hash_checked(key)
            require(type(encoded) is str, _REQUEST_MESSAGE)
            raw = base64.b64decode(encoded, validate=True)
        except (SentinelError, ValueError):
            raise SentinelError(_REQUEST_MESSAGE) from None
        checked[key] = raw
    return checked


def _request_packages(packages):
    """JSON supplies a list. The shipped check requires a tuple."""
    require(type(packages) is list, _REQUEST_MESSAGE)
    return tuple(packages)


def manifest_lineage_invocation(raw):
    """Call manifest_lineage_check for one canonical host request.

    No workflow root is opened. No key, ZIP, or provider call is made.
    Frozen manifest profiles are not redefined. Closure errors are unchanged.
    """
    require(type(raw) is bytes and 0 < len(raw) <= METADATA, _REQUEST_MESSAGE)
    try:
        value = parse(raw, METADATA)
        fields(value, _REQUEST_FIELDS)
        require(value['schema'] == LINEAGE_REQUEST, _REQUEST_MESSAGE)
        records = _decode_revisions(value['revisions'])
        packages = _request_packages(value['packages'])
        selected = value['selected']
        hash_checked(selected)
    except SentinelError:
        raise SentinelError(_REQUEST_MESSAGE) from None
    result = manifest_lineage_check(records, selected, packages)
    parsed = parse(result)
    require(parsed['schema'] == LINEAGE_CHECK and result == canonical(parsed),
            _REQUEST_MESSAGE)
    return parsed


def output_partition(response, proposed=None):
    """Refuse one complete generation that does not fit the fixed job cap.

    JOB_BYTES is the cap. An over-cap response is not truncated, split into
    accepted graphs, imported, or resampled. A fitting response is not a grant.
    """
    require(type(response) is bytes and 0 < len(response),
            'output partition requires the complete response')
    require(proposed is None or type(proposed) is bytes, 'proposed graph must be bytes')
    if len(response) > JOB_BYTES:
        raise SentinelError('output exceeds job bound; not partitioned into an accepted graph')
    if proposed is not None and proposed != response:
        raise SentinelError('proposed graph is not the complete response')
    return {'schema': PROFILE, 'phase': 'OUTPUT_WITHIN_CAP_NOT_IMPORTED',
        'response_bytes': len(response), 'cap_bytes': JOB_BYTES, 'part_count': 1,
        'accepted_graph': None, 'truncated': False, 'cap_raised': False,
        'graph_import': 'NOT_PERFORMED', 'qualification': 'NOT_QUALIFIED',
        'semantic_completeness': 'UNPROVEN', 'execution_authority': 'NONE'}


def registry_manifest(registry, held):
    require(type(registry) is dict and len(registry) <= 256, 'capture registry count')
    snapshot = registry_snapshot(registry, held)
    manifest = canonical({key: identity(raw) for key, raw in snapshot.items()})
    return snapshot, manifest


def capture_packet(job_id, terminal_state, request, graph, provenance, registry, registry_held,
                   records, admission=None, admission_held=None, *, complete_response=None):
    """Assemble unchanged captured bytes; an external admission is never inferred.

    complete_response is optional and is not stored. When supplied, it is the
    generation before any host slice. When omitted, only graph is classified.
    """
    response = graph if complete_response is None else complete_response
    output_partition(response, graph)
    identifier(job_id)
    require(terminal_state == 'TERMINAL_RECORDED', 'explicit host terminal declaration required')
    snapshot, manifest = registry_manifest(registry, registry_held)
    for raw in (request, graph, provenance):
        artifact(raw)
        require(snapshot.get(digest(raw)) == raw, 'capture artifact absent from registry')
    observed = parse(provenance, JOB_BYTES)
    assessments.reviewer_checked(observed, snapshot)
    require(observed['raw_response_pin'] == identity(graph), 'capture response differs')
    requested = parse(request, JOB_BYTES)
    require(type(requested) is dict and requested.get('job_id') == job_id
            and 'reading_pin' in requested, 'capture request job or reading differs')
    prompt = assessments.artifact(observed['prompt_pin'], snapshot, JOB_BYTES)
    reading = assessments.artifact(requested['reading_pin'], snapshot, JOB_BYTES)
    document.generation_message({'request': request, 'prompt': prompt, 'reading': reading})
    artifact(records, METADATA)
    if admission is None:
        require(admission_held is None, 'capture absent admission has held pin')
    else:
        artifact(admission, METADATA)
        require(digest(admission) == hash_checked(admission_held), 'capture admission differs')
    payload = {'job_id': job_id, 'terminal_state': terminal_state,
        'request': identity(request), 'graph': identity(graph), 'provenance': identity(provenance),
        'registry': identity(manifest), 'records': identity(records),
        'admission': None if admission is None else identity(admission),
        'admission_sha256': admission_held}
    artifacts = dict(snapshot)
    for raw in (manifest, records, admission):
        if raw is not None:
            artifacts[digest(raw)] = raw
    envelope = canonical({'schema': 'sentinel/workflow-input/1', 'kind': 'capture',
                          'payload': payload})
    return envelope, artifacts


def receive_complete(job_id, terminal_state, request, graph, provenance, registry, registry_held,
                     records, complete_response, admission=None, admission_held=None):
    """Pass one complete generation into capture_packet.

    complete_response is required. It is not stored, sliced, resampled, or
    imported. A returned envelope is not registration and not qualification.
    """
    require(type(complete_response) is bytes and len(complete_response) > 0,
            'host receiver requires the complete generation')
    envelope, artifacts = capture_packet(
        job_id, terminal_state, request, graph, provenance, registry, registry_held,
        records, admission, admission_held, complete_response=complete_response)
    return {'schema': PROFILE, 'phase': 'COMPLETE_RECEIVED_NOT_QUALIFIED',
        'envelope': envelope, 'artifacts': artifacts,
        'response_bytes': len(complete_response), 'cap_bytes': JOB_BYTES,
        'accepted_graph': None, 'truncated': False, 'cap_raised': False,
        'graph_import': 'NOT_PERFORMED', 'registered': False,
        'qualification': 'NOT_QUALIFIED', 'semantic_completeness': 'UNPROVEN',
        'execution_authority': 'NONE'}


def pending_packet(job_id):
    """Retain unknown external execution; this blocks another capture action."""
    identifier(job_id)
    value = {key: None for key in CAPTURE_FIELDS}
    value.update(job_id=job_id, terminal_state='LIVE_OR_UNKNOWN')
    return canonical({'schema': 'sentinel/workflow-input/1', 'kind': 'capture',
                      'payload': value}), {}


def packet_checked(raw, held, artifacts):
    value = held_record(raw, held)
    fields(value, ('schema', 'kind', 'payload'))
    require(value['schema'] == 'sentinel/workflow-input/1' and value['kind'] == 'capture',
            'capture envelope profile')
    payload = fields(value['payload'], CAPTURE_FIELDS)
    require(type(artifacts) is dict and len(artifacts) <= 259, 'capture packet artifact count')
    total = 0
    for key, item in artifacts.items():
        artifact(item, METADATA)
        require(digest(item) == hash_checked(key), 'capture packet artifact pin')
        total += len(item)
        require(total <= REGISTRY + 3 * METADATA, 'capture packet aggregate bound')
    if payload['terminal_state'] == 'LIVE_OR_UNKNOWN':
        expected, snapshot = pending_packet(payload['job_id'])
    else:
        require(payload['terminal_state'] == 'TERMINAL_RECORDED', 'capture terminal state')
        reg_raw = assessments.artifact(payload['registry'], artifacts)
        reg = parse(reg_raw)
        require(type(reg) is dict and len(reg) <= 256, 'capture registry count')
        registry = {key: assessments.artifact(pin, artifacts) for key, pin in reg.items()}
        values = [assessments.artifact(payload[key], artifacts)
                  for key in ('request', 'graph', 'provenance', 'records')]
        admission = None if payload['admission'] is None else assessments.artifact(
            payload['admission'], artifacts)
        expected, snapshot = capture_packet(payload['job_id'], payload['terminal_state'], *values[:3], registry,
            payload['registry']['sha256'], values[3], admission, payload['admission_sha256'])
    require(raw == expected and artifacts == snapshot, 'capture packet closure differs')
    return payload, snapshot


def recorded_terminal(root, run_id, expected_sha256, job_id):
    """Replay a failure journal. No journal means no recorded terminal.

The returned history is a failure. It is not a graph import or a completion.
"""
    from transport_workflow_attempts import inspect_history, journal_id
    with Store(root).opened(create=False) as store:
        _events, head = store.chain(journal_id(run_id, job_id))
    if head is None:
        return None
    history = inspect_history(root, run_id, expected_sha256, job_id, head['sha256'])
    require(history['phase'] == 'RECORDED_FAILURE_HISTORY'
            and history['qualification'] == 'NOT_QUALIFIED'
            and history['execution_authority'] == 'NONE',
            'recorded terminal is not a qualified success')
    require(history['attempts'] and all(row['graph_sha256'] is None
            and row['status'] in ('FAILED', 'INTERRUPTED') for row in history['attempts']),
            'recorded terminal contains an importable graph')
    return history


def inspect_terminal(root, run_id, expected_sha256, job_id):
    """Report a recorded failure without dispatching, importing, or completing."""
    view = Workflow(root).call('inspect', {'run_id': run_id, 'expected_sha256': expected_sha256})
    history = recorded_terminal(root, run_id, expected_sha256, job_id)
    if history is None:
        return {'schema': PROFILE, 'phase': 'NO_RECORDED_TERMINAL', 'job_id': job_id,
            'completed_jobs': view['completed_jobs'], 'qualification': 'NOT_QUALIFIED',
            'execution_authority': 'NONE'}
    return {'schema': PROFILE, 'phase': 'RECORDED_FAILURE_NOT_DISPATCHED', 'job_id': job_id,
        'journal_head': history['journal_head'], 'attempt_count': len(history['attempts']),
        'completed_jobs': view['completed_jobs'], 'workflow_status': view['status'],
        'graph_import': 'NOT_PERFORMED', 'dispatch': 'REFUSED_RECORDED_FAILURE',
        'qualification': 'NOT_QUALIFIED', 'semantic_completeness': 'UNPROVEN',
        'execution_authority': 'NONE'}


def prepare_generation(root, run_id, expected_sha256, dispatch):
    """Return the next checked application with an explicit host-selected frame.

Changing dispatch does not rewrite the retained client plan or application. The
complete new frame must fit JOB_BYTES. Actual delivery remains unobserved.
A recorded failure journal refuses another automatic frame.
"""
    view = Workflow(root).call('inspect', {'run_id': run_id, 'expected_sha256': expected_sha256})
    require(view['status'] == 'WAITING_EXTERNAL_CAPTURE' and view['next_action'] is not None,
            'capture generation is not pending')
    action = view['next_action']
    require(recorded_terminal(root, run_id, expected_sha256, action['job_id']) is None,
            'recorded failure is not a new capture')
    request = canonical(action['request'])
    prompt = action['prompt'].encode('utf-8')
    reading = parse(prompt, JOB_BYTES)['SOURCE_DATA'].encode('utf-8')
    document.generation_message({'request': request, 'prompt': prompt, 'reading': reading})
    original_frame = base64.b64decode(action['frame_base64'], validate=True)
    require(identity(original_frame) == action['frame_pin'], 'capture original frame differs')
    frame = document_client.frame_bytes(dispatch, prompt)
    return {'schema': PROFILE, 'run_id': run_id, 'head': view['head'], 'index': view['index'],
        'job_id': action['job_id'], 'request': request, 'prompt': prompt, 'reading': reading,
        'frame': frame, 'original_frame_pin': action['frame_pin'], 'dispatch': dispatch,
        'delivery': 'NOT_OBSERVED', 'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE'}


def entry_checked(root, run_id, expected_sha256, job_id):
    view = Workflow(root).call('inspect', {'run_id': run_id, 'expected_sha256': expected_sha256})
    if view['status'] == 'WAITING_EXTERNAL_CAPTURE':
        require(view['next_action']['job_id'] == job_id, 'capture next job differs')
    else:
        require(view['status'] in ('WAITING_HELD_ADMISSION', 'BLOCKED_PENDING_EXTERNAL_CONTEXT'),
                'capture workflow cannot accept submission')
    return view


def register_capture(root, run_id, expected_sha256, submission_id, raw, held, artifacts):
    """Registration only. Partial IO failures retain files; no rollback is claimed."""
    payload, snapshot = packet_checked(raw, held, artifacts)
    entry_checked(root, run_id, expected_sha256, payload['job_id'])
    identifier(submission_id)
    with Store(root).opened(create=False) as store:
        store.chain(run_id, expected_sha256)
        pin = store.register(submission_id, parse(raw), snapshot)
    return {'schema': PROFILE, 'phase': 'CAPTURE_REGISTERED_NOT_ADVANCED',
        'submission_id': submission_id, 'submission': pin, 'previous_head': expected_sha256,
        'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE'}


def advance_registered(root, run_id, expected_sha256, submission_id, submission_sha256):
    """Resume a retained registration; never dispatch a provider or overwrite it."""
    result = Workflow(root).call('advance', {'run_id': run_id, 'expected_sha256': expected_sha256,
        'submission_id': submission_id, 'submission_sha256': submission_sha256})
    return {'schema': PROFILE, 'phase': 'WORKFLOW_REPLAY_RETURNED', 'workflow': result}


def _received_unsplit(packet, complete_response):
    """Classify the unsplit generation before any terminal registration."""
    payload, snapshot = packet_checked(packet['raw'], packet['held'], packet['artifacts'])
    manifest = parse(snapshot[payload['registry']['sha256']])
    registry = {key: snapshot[key] for key in manifest}
    admission = None if payload['admission'] is None else snapshot[payload['admission']['sha256']]
    return receive_complete(
        payload['job_id'], payload['terminal_state'], snapshot[payload['request']['sha256']],
        snapshot[payload['graph']['sha256']], snapshot[payload['provenance']['sha256']],
        registry, payload['registry']['sha256'], snapshot[payload['records']['sha256']],
        complete_response, admission, payload['admission_sha256'])


def finish_generation(root, run_id, expected_sha256, job_id, journal_sha256, terminal, *,
                      complete_response=None):
    """Bind the unsplit generation, then retain the attempts terminal result.

    A success capture must carry the complete buffer. The receive_complete
    envelope is checked and discarded. It is not the returned result and it is
    not qualification. Failure terminals have no generation.
    """
    from transport_workflow_attempts import finish_generation as finish
    fields(terminal, ('inputs', 'capture', 'submission_id'))
    if terminal['capture'] is None:
        require(complete_response is None, 'failure terminal has no generation')
    else:
        raw_response = _generation_bytes(complete_response)
        packet = fields(terminal['capture'], ('raw', 'held', 'artifacts'))
        bound = _received_unsplit(packet, raw_response)
        require(bound['phase'] == 'COMPLETE_RECEIVED_NOT_QUALIFIED'
                and bound['qualification'] == 'NOT_QUALIFIED'
                and bound['registered'] is False and bound['accepted_graph'] is None
                and bound['graph_import'] == 'NOT_PERFORMED',
                'complete generation is not qualification')
        require(bound['envelope'] == packet['raw'] and bound['artifacts'] == packet['artifacts'],
                'complete generation packet differs')
    return finish(root, run_id, expected_sha256, job_id, journal_sha256, terminal)
