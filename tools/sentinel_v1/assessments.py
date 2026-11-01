"""Recorded source-relative assessments, never votes converted into truth."""
import importlib
from pathlib import Path
import sys
import types
from transport_document_io import read_file
from .common import (CLAIMS, JOB_BYTES, LINKS, METADATA, canonical, digest, fields,
                     hash_checked, held_record, identity, label, parse, pin_checked,
                     registry_snapshot, require)
from .bindings import bind_graph, graph_from_registry
from .graph import evidence_checked

CATEGORIES = ('CONFIRMED_MISMATCH', 'SUPPORTED_ALTERNATIVE', 'UNRESOLVED_AMBIGUITY',
              'UNSUPPORTED_CHALLENGE', 'MISSING_REFERENCE_EVIDENCE', 'TOOL_OR_PROCESS_FAILURE')
REVIEWER_FIELDS = ('origin', 'declared_identity', 'observed_identity_pin', 'invocation_pin',
                   'settings_pin', 'prompt_pin', 'raw_response_pin')


def artifact(pin, snapshot, cap=METADATA):
    pin_checked(pin)
    require(pin['bytes'] <= cap and pin['sha256'] in snapshot, 'assessment artifact missing/bound')
    raw = snapshot[pin['sha256']]
    require(identity(raw) == pin, 'assessment artifact identity')
    return raw


def reviewer_checked(value, snapshot, allow_missing=False):
    fields(value, REVIEWER_FIELDS)
    require(value['origin'] in ('MANUAL_FIXTURE', 'RECORDED_EXTERNAL_RUN'), 'reviewer origin')
    name = value['declared_identity']
    require(name is None or type(name) is str and len(name.encode('utf-8')) <= 256,
            'declared reviewer identity bound')
    for key in ('settings_pin', 'prompt_pin'):
        artifact(value[key], snapshot, JOB_BYTES)
    for key in ('observed_identity_pin', 'invocation_pin', 'raw_response_pin'):
        if value[key] is not None:
            artifact(value[key], snapshot, JOB_BYTES)
    if value['origin'] == 'MANUAL_FIXTURE':
        require(value['observed_identity_pin'] is None and value['invocation_pin'] is None,
                'manual fixture cannot mint observed invocation identity')
    else:
        require(value['invocation_pin'] is not None, 'external invocation evidence missing')
    require(allow_missing or value['raw_response_pin'] is not None, 'review response missing')
    return {'declared_identity': name, 'origin': value['origin'],
            'observed_identity': 'NOT_RECORDED' if value['observed_identity_pin'] is None
                                 else 'RECORDED_BYTES_UNVERIFIED',
            'independence': 'UNPROVEN', 'provider_identity': 'UNVERIFIED'}


def assessment_graph(value, snapshot):
    graph = graph_from_registry(hash_checked(value['graph_sha256']), snapshot)
    key = hash_checked(value['source_set_sha256'])
    require(key in snapshot and graph['source_set_sha256'] == key
            and canonical(graph['source_set']) == snapshot[key], 'assessment source set mismatch')
    artifact(value['task_pin'], snapshot, JOB_BYTES)
    return graph


def adjudication_checked(value, admission, graph, snapshot):
    fields(admission, ('schema', 'graph_sha256', 'source_set_sha256', 'task_pin', 'adjudications'))
    require(admission['schema'] == 'sentinel/assessment-admission/1', 'assessment admission version')
    require(all(admission[key] == value[key] for key in
                ('graph_sha256', 'source_set_sha256', 'task_pin')), 'assessment admission target')
    artifact(admission['task_pin'], snapshot, JOB_BYTES)
    records = admission['adjudications']
    require(type(records) is dict and len(records) <= CLAIMS, 'adjudication count')
    for name, row in records.items():
        label(name)
        fields(row, ('record_sha256', 'category', 'adjudication_pin'))
        hash_checked(row['record_sha256'])
        require(row['category'] in CATEGORIES, 'adjudication category')
        artifact(row['adjudication_pin'], snapshot, JOB_BYTES)
    return records


def assessment_record(row, graph, snapshot, admissions):
    fields(row, ('id', 'claim_id', 'category', 'evidence', 'explanation_pin', 'reviewer'))
    name, claim = label(row['id']), label(row['claim_id'])
    require(claim in {node['id'] for node in graph['nodes']}, 'assessment claim missing')
    require(row['category'] in CATEGORIES, 'assessment category')
    artifact(row['explanation_pin'], snapshot, JOB_BYTES)
    evidence = row['evidence']
    require(type(evidence) is list and len(evidence) <= LINKS, 'assessment evidence count')
    if evidence:
        sources = {source['id']: source for source in graph['source_set']}
        evidence_checked(evidence, sources, snapshot)
    strong = row['category'] in ('CONFIRMED_MISMATCH', 'SUPPORTED_ALTERNATIVE')
    require(not strong or bool(evidence), 'confirmed assessment requires source quotes')
    admitted = admissions.get(name)
    require(not strong or admitted is not None, 'confirmed assessment lacks held adjudication')
    if admitted is not None:
        require(admitted['record_sha256'] == digest(canonical(row))
                and admitted['category'] == row['category'], 'adjudication record mismatch')
    reviewer = reviewer_checked(row['reviewer'], snapshot, row['category'] in
                               ('TOOL_OR_PROCESS_FAILURE', 'MISSING_REFERENCE_EVIDENCE'))
    return {'id': name, 'claim_id': claim, 'category': row['category'],
            'record_sha256': digest(canonical(row)), 'reviewer': reviewer,
            'adjudication': 'HELD_PIN_MATCH_ONLY' if admitted is not None else 'UNADMITTED',
            'interpretation_entailment': 'UNPROVEN', 'execution_authority': 'NONE'}


def _checked(raw, held, registry, registry_root, admission_raw, admission_held):
    value = held_record(raw, held)
    snapshot = registry_snapshot(registry, registry_root)
    fields(value, ('schema', 'graph_sha256', 'source_set_sha256', 'task_pin', 'records'))
    require(value['schema'] == 'sentinel/assessments/1', 'assessment schema')
    graph = assessment_graph(value, snapshot)
    admission = held_record(admission_raw, admission_held)
    admitted = adjudication_checked(value, admission, graph, snapshot)
    require(type(value['records']) is list and len(value['records']) <= CLAIMS, 'assessment count')
    rows, seen = [], set()
    for row in value['records']:
        checked = assessment_record(row, graph, snapshot, admitted)
        require(checked['id'] not in seen, 'duplicate assessment')
        seen.add(checked['id']); rows.append(checked)
    require(set(admitted) <= seen, 'unknown admitted assessment')
    result = {'schema': 'sentinel/assessment-check/1', 'assessment_sha256': held,
              'admission_sha256': admission_held, 'graph_sha256': value['graph_sha256'],
              'source_set_sha256': value['source_set_sha256'], 'task_pin': value['task_pin'],
              'records': rows, 'source_binding': 'SUPPLIED_WINDOW_BYTES_ONLY',
              'semantic_completeness': 'UNPROVEN', 'qualification': 'NOT_QUALIFIED',
              'execution_authority': 'NONE', 'independent_review': 'UNPROVEN'}
    canonical(result)
    return result, graph


def checked_assessments(raw, held, registry, registry_root, admission_raw, admission_held):
    return _checked(raw, held, registry, registry_root, admission_raw, admission_held)[0]


def check_source_assessments(raw, held, registry, registry_root, admission_raw, admission_held,
                             archive, share, locator_raw, locator_held, locators, locators_held,
                             revisions, revisions_held, native=None):
    from .locators import resolve_locator
    result, graph = _checked(raw, held, registry, registry_root, admission_raw, admission_held)
    resolution = resolve_locator(archive, share, locator_raw, locator_held, locators,
                                  locators_held, revisions, revisions_held, native)
    result['source_evidence'] = bind_graph(graph, resolution)
    canonical(result)
    return result


def legacy_entry(module_name, function_name, expected_sha256):
    allowed = {'transport_quorum_reading': ('tools/transport_quorum_reading.py',
                                           ('check_reading_aggregation',)),
        'comparison.receiving.private_staging': ('comparison/receiving/private_staging.py',
                                               ('chain', 'write_new')),
        'comparison.receiving.check_answer': ('comparison/receiving/check_answer.py', ('validate',))}
    require(module_name in allowed and function_name in allowed[module_name][1], 'legacy entry allowlist')
    root = Path(__file__).resolve().parents[2]
    path = root / allowed[module_name][0]
    raw = read_file(path, METADATA)
    require(digest(raw) == hash_checked(expected_sha256), 'legacy source pin mismatch')
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    module = importlib.import_module(module_name)
    require(Path(module.__file__).resolve() == path, 'legacy module path mismatch')
    code = compile(raw, str(path), 'exec', dont_inherit=True, optimize=sys.flags.optimize)
    entries = [item for item in code.co_consts if type(item) is types.CodeType
               and item.co_name == function_name]
    function = module.__dict__.get(function_name)
    require(len(entries) == 1 and type(function) is types.FunctionType
            and function.__code__ == entries[0], 'loaded legacy entry differs from source')
    return function


def quorum_aggregate(body_raw, originals, held_updates, held_withdrawals, expected_checker_sha256):
    checker = legacy_entry('transport_quorum_reading', 'check_reading_aggregation',
                           expected_checker_sha256)
    result = checker(body_raw, originals, held_updates, held_withdrawals)
    canonical(result)
    return {'legacy_result': result, 'checker_sha256': expected_checker_sha256,
            'scope': 'UNCHANGED_RECORDED_READING_ADMISSIBILITY_NOT_SOURCE_TRUTH',
            'dependency_provenance': 'INHERITED_TRUSTED_BASELINE', 'execution_authority': 'NONE'}
