"""Staging manifest for a future reviewed native adapter; never a native wire."""
import sys
from transport_document_io import canonical, digest, loaded_epoch, need
from transport_sentinel import CAP, checked_sidecar, record_index, target


def probe_inputs(document, context):
    oracles = record_index(document['oracles'])
    output = []
    for ordinal, row in enumerate(document['probes']):
        oracle = target(row['oracle_pin'], oracles, context)
        output.append({'ordinal': ordinal, 'id': row['id'], 'claim_id': row['claim_id'],
                       'probe_sha256': digest(canonical(row)),
                       'question_sha256': row['question_pin']['sha256'],
                       'scenario_sha256': row['scenario_pin']['sha256'],
                       'oracle_sha256': row['oracle_pin']['sha256'],
                       'expected_answer_sha256': oracle['answer_pin']['sha256'],
                       'checker_sha256': row['checker_pin']['sha256'],
                       'materiality_sha256': row['materiality_pin']['sha256'],
                       'relation': 'EXACT_ANSWER_DIGEST'})
    return output


def result_inputs(document):
    candidates = {row['id']: index for index, row in enumerate(document['candidates'])}
    probes = {row['id']: index for index, row in enumerate(document['probes'])}
    output = []
    for row in document['results']:
        blocker = row['status'] if row['status'] in ('UNRUN', 'REFUSED') else 'NONE'
        output.append({'candidate_ordinal': candidates[row['candidate_pin']['id']],
                       'probe_ordinal': probes[row['probe_pin']['id']],
                       'actual_answer_sha256': row['answer_pin']['sha256'],
                       'evidence_sha256': row['run_evidence_pin']['sha256'],
                       'input_manifest_sha256': row['input_manifest_pin']['sha256'],
                       'evaluator_sha256': row['evaluator_pin']['sha256'],
                       'comparison_evidence_sha256': row['comparison_receipt_pin']['sha256'],
                       'result_record_sha256': digest(canonical(row)), 'blocker': blocker})
    return sorted(output, key=lambda row: (row['candidate_ordinal'], row['probe_ordinal']))


def claim_inputs(document, context):
    output = []
    for ordinal, candidate in enumerate(document['candidates']):
        claims = []
        for claim in candidate['claims']:
            spans = []
            for locator in claim['evidence']:
                selector = context['parsed'][locator['selector_pin']['id']]
                spans.append({'source_sha256': locator['source_pin']['sha256'],
                              'start': selector['start'], 'end': selector['end'],
                              'quote_sha256': locator['quote_pin']['sha256']})
            claims.append({'id': claim['id'], 'text_sha256': claim['claim_text_pin']['sha256'],
                           'source_spans': spans,
                           'required_context_sha256': [pin['sha256'] for pin in claim['required_context']]})
        output.append({'ordinal': ordinal, 'id': candidate['id'],
                       'candidate_sha256': digest(canonical(candidate)), 'claims': claims,
                       'dependency_graph_sha256': candidate['dependency_graph_pin']['sha256'],
                       'unknown_regions_sha256': candidate['unknown_regions_pin']['sha256']})
    return output


def export_policy_inputs(raw, artifacts, expected_sha256, expected_registry_sha256,
                         previous_raw=None, expected_previous_sha256=None):
    document, context, repairs = checked_sidecar(raw, artifacts, expected_sha256,
        expected_registry_sha256, previous_raw, expected_previous_sha256)
    output = {'schema': 'sentinel/policy-inputs-exact/1',
              'sidecar_sha256': digest(raw), 'registry_sha256': expected_registry_sha256,
              'source_set_sha256': document['source_set_pin']['sha256'],
              'q_set_sha256': document['q_set_pin']['sha256'],
              'oracle_set_sha256': document['oracle_set_pin']['sha256'],
              'policy_sha256': document['policy_pin']['sha256'],
              'history_sha256': document['qualification']['failure_history_pin']['sha256'],
              'candidates': claim_inputs(document, context),
              'probes': probe_inputs(document, context), 'results': result_inputs(document),
              'repair_links': [list(pair) for pair in sorted(repairs)],
              'status': 'NOT_QUALIFIED', 'ceiling': 'EXACT_BYTES_AND_STRUCTURE_ONLY',
              'semantic_completeness': 'UNPROVEN', 'execution_authority': 'NONE'}
    encoded = canonical(output)
    need(len(encoded) <= CAP, 'SENTINEL export bound')
    return encoded


SOURCE_EPOCH = loaded_epoch(__file__, sys._getframe().f_code)
