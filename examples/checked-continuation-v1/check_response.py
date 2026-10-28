"""Source-bound finite-fixture checks. Never execute candidate Python code.

The predicate below implements the independently authored fixture oracle, not a
general natural-language interpreter. Narrative fidelity needs separate review.
"""
import argparse
import itertools
import json
from pathlib import Path
import resource
import sys

ROOT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(ROOT / 'install'))
from transport_install_support import canonical, read_regular, require, sha
from transport_response_contract import validate
from transport_response_contract_model import compile_contract, safe_json
from transport_fixture_expression import apply_replacement, parse_function, evaluate

PARAMETERS = ('requester_is_keeper', 'recipient_is_keeper', 'seal_ok',
              'repair_mode', 'ticket_ok', 'age_hours')
DOMAINS = {name: {'type': 'boolean'} for name in PARAMETERS[:-1]}
DOMAINS['age_hours'] = {'type': 'integer', 'min': -1, 'max': 13}


def expected(state):
    """Finite source specification; reject guards first, independent of AST form."""
    if not state['requester_is_keeper']:
        return False
    if state['age_hours'] in (-1, 13):
        return False
    if state['seal_ok']:
        return True
    return state['repair_mode'] and state['ticket_ok']


def behavior(source):
    program = parse_function(source, 'allow_demo_route', PARAMETERS, DOMAINS)
    rows, differences = [], []
    failures = 0
    for values in itertools.product((False, True), repeat=5):
        for age in range(-1, 14):
            state = dict(zip(PARAMETERS, (*values, age), strict=True))
            wanted, actual = expected(state), evaluate(program, state)
            require(type(actual) is bool, 'interpreter returned a non-Boolean')
            row = dict(state=state, expected=wanted, actual=actual)
            rows.append(row)
            if wanted != actual:
                failures += 1
                if len(differences) < 16:
                    differences.append(row)
    require(len(rows) == 480, 'incomplete declared domain enumeration')
    return dict(status='PASS' if failures == 0 else 'FAIL', states=len(rows),
                failures=failures, table_sha256=sha(canonical(dict(rows=rows))),
                first_differences=differences, differences_truncated=failures > len(differences),
                scope='FINITE_DECLARED_DOMAIN_ONLY; empirical interpreter checks, not formal proof')


def check_equal(checks, name, observed, wanted):
    checks.append(dict(check=name, passed=observed == wanted,
                       observed=observed, expected=wanted))


def anchors(candidate, sources, checks):
    records = candidate['evidence'] + candidate['historical_approvals']
    records += candidate['historical_reports'] + candidate['source_actions']
    require(len(records) <= 80, 'anchor record count bound')
    for index, record in enumerate(records):
        source = sources.get(record['source_id'], '')
        quote = record['quote']
        offset = source.find(quote)
        unique = offset >= 0 and source.find(quote, offset + 1) < 0
        check_equal(checks, 'exact_unique_quote_' + str(index), unique, True)
    check_equal(checks, 'evidence_source_order',
                [item['source_id'] for item in candidate['evidence']], list(sources))


def source_records(candidate, checks):
    approvals = [[item['id'], item['status'], item['source_id']]
                 for item in candidate['historical_approvals']]
    check_equal(checks, 'historical_approvals', approvals, [['HAPP-01', 'REVOKED', 'HISTORY']])
    reports = [[item['id'], item['claimed_result'], item['source_id']]
               for item in candidate['historical_reports']]
    check_equal(checks, 'historical_report_claims', reports,
                [['TR-A', 'PASS', 'CHECKS'], ['TR-B', 'FAIL', 'CHECKS']])
    actions = [[item['id'], item['state'], item['source_id']]
               for item in candidate['source_actions']]
    wanted = [['ACT-01', 'COMPLETED', 'ACTIONS'], ['ACT-02', 'COMPLETED', 'ACTIONS'],
              ['ACT-03', 'PENDING', 'ACTIONS'], ['ACT-04', 'PENDING', 'ACTIONS'],
              ['ACT-05', 'PENDING', 'ACTIONS']]
    check_equal(checks, 'source_snapshot_actions', actions, wanted)
    for key, value in (('reports_conflict', True), ('current_replacement_verification', 'UNKNOWN'),
                       ('supplied_current_publication_approval', 'ABSENT'),
                       ('decoder_execution_authority', 'NONE')):
        check_equal(checks, key, candidate[key], value)


def patch(candidate, sources):
    item = candidate['patch']
    require(item['source_id'] == 'CODE' and item['path'] == 'decision.py', 'wrong patch target')
    base = sources['CODE'].encode('utf-8')
    require(item['base_sha256'] == sha(base), 'candidate base identity mismatch')
    result, receipt = apply_replacement(base, sha(base), item['before'].encode('utf-8'),
                                        item['after'].encode('utf-8'))
    header = base.split(b'\n', 1)[0] + b'\n'
    require(receipt['byte_offset'] >= len(header), 'edit touches fixed signature')
    require(result.startswith(header), 'preserve exact header bytes')
    return receipt, behavior(result)


def assess(fixture_raw, contract_raw, candidate_raw):
    fixture = safe_json(fixture_raw, 65536, 4096)
    require(fixture['schema'] == 'transport/coding-continuation-fixture/1', 'fixture version')
    shape = validate(candidate_raw, compile_contract(contract_raw))
    result = dict(schema='transport/checked-continuation-assessment/1', structure=shape,
                  status='FAIL', narrative_fidelity='NOT_ASSESSED', authority='NONE',
                  interpretation_entailment='UNPROVEN', source_checks=[])
    if shape['status'] != 'STRUCTURALLY_CONFORMANT':
        return result
    candidate = safe_json(candidate_raw, 32768, 1024)
    require(len(fixture['sources']) == 6, 'fixed fixture source count')
    sources = {item['id']: item['text'] for item in fixture['sources']}
    anchors(candidate, sources, result['source_checks'])
    source_records(candidate, result['source_checks'])
    try:
        result['patch'], result['behavior'] = patch(candidate, sources)
    except (ValueError, UnicodeError) as error:
        result['patch'] = dict(status='REFUSED', reason=str(error)[:256])
        return result
    if all(item['passed'] for item in result['source_checks']) and result['behavior']['status'] == 'PASS':
        result['status'] = 'DETERMINISTIC_CHECKS_PASSED'
    return result


def pinned(path, held, cap):
    raw = read_regular(path, cap)
    require(sha(raw) == held, 'input identity mismatch: ' + path.name)
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fixture', 'contract', 'candidate'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (131072, 131072))
    try:
        raw = {name: pinned(getattr(args, name), getattr(args, name + '_sha256'),
                            32768 if name == 'candidate' else 65536)
               for name in ('fixture', 'contract', 'candidate')}
        result = assess(raw['fixture'], raw['contract'], raw['candidate'])
        for name in raw:
            require(read_regular(getattr(args, name)) == raw[name], 'input changed during assessment')
        result['inputs'] = {name: dict(bytes=len(value), sha256=sha(value)) for name, value in raw.items()}
        output = canonical(result) + b'\n'
        require(len(output) <= 131072, 'assessment output bound')
        sys.stdout.buffer.write(output)
        return 0 if result['status'] == 'DETERMINISTIC_CHECKS_PASSED' else 1
    except (ValueError, KeyError, TypeError, OSError, UnicodeError, MemoryError) as error:
        sys.stdout.buffer.write(canonical(dict(status='REFUSED', reason=str(error)[:256])) + b'\n')
        return 2


if __name__ == '__main__':
    sys.exit(main())
