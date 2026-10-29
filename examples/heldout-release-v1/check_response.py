"""Bounded structural and finite-table checks; supplied code is never executed.

Narrative meaning, historical authentication and task-only access need separate
independent evaluation. Passing this checker supplies no action authority.
"""
import argparse
import io
from pathlib import Path
import resource
import sys
import tokenize

sys.dont_write_bytecode = True
ROOT = Path(__file__).absolute().parents[2]
sys.path.insert(0, str(ROOT / 'install'))
from transport_fixture_expression import apply_replacement, parse_function
from transport_finite_check import _cardinality, _table, checker_identity
from transport_install_support import canonical, read_regular, require, sha
from transport_response_contract_model import fields, safe_json

CAP = 32768
PARAMETERS = ('rights_review_complete', 'curatorial_review_complete',
              'publication_hold', 'maintenance_replacement', 'age_days')
DOMAINS = {name: {'type': 'boolean'} for name in PARAMETERS[:-1]}
DOMAINS['age_days'] = {'type': 'integer', 'min': -1, 'max': 3}
FUNCTION = 'may_queue_museum_preview'
CODE_SHA256 = 'dea6f6d6748168a0fba870efb6e7c53b4c1ce56fe75773aa380e49b19aac65b4'
BITS = '00000000000000000000000000000000000000000000000000000000000001110011100000001110'
SOURCE_IDS = {'CODE', 'RULE', 'HISTORY', 'REPORTS', 'ACTIONS', 'UNRELATED'}
LEDGER = {'M-ACT-01': 'COMPLETED', 'M-ACT-02': 'PENDING',
          'M-ACT-03': 'PENDING', 'M-ACT-04': 'PENDING'}
TOP = ('schema', 'replacement', 'current_rule', 'historical_authority',
       'historical_verification', 'actions', 'unresolved', 'source_citations')


def case_identity():
    """Add the case adapter and its extra import to the finite checker closure."""
    identity = checker_identity()
    paths = (Path(__file__).absolute(), ROOT / 'install/transport_response_contract_model.py')
    entries = []
    for path in paths:
        raw = read_regular(path, 131072)
        entries.append(dict(path=str(path.relative_to(ROOT)), bytes=len(raw), sha256=sha(raw)))
    return dict(finite_checker=identity, case_adapter=entries,
                bootstrap='Already imported code, standard library and host are trusted.')


def string(value, label):
    require(type(value) is str and len(value.encode('utf-8')) <= 4096,
            label + ': bounded string required')
    return value


def records(value, maximum, label):
    require(type(value) is list and len(value) <= maximum, label + ': array bound/type')
    return value


def fixture_inputs(fixture_raw, criteria_raw):
    fixture = safe_json(fixture_raw, 65536, 4096)
    criteria = safe_json(criteria_raw, 65536, 4096)
    require(type(fixture) is dict and type(criteria) is dict, 'fixture/criteria objects')
    require(fixture['function_name'] == FUNCTION and fixture['parameters'] == list(PARAMETERS)
            and fixture['domains'] == DOMAINS, 'frozen function/domain specification differs')
    require(criteria['schema'] == 'transport/heldout-continuation-criteria/1'
            and criteria['fixture_id'] == 'fictional-museum-preview-rule-r3', 'criteria identity')
    oracle = criteria['oracle']
    require(oracle['function_name'] == FUNCTION and oracle['parameters'] == list(PARAMETERS)
            and oracle['domains'] == DOMAINS, 'frozen oracle signature/domain differs')
    require(type(oracle['state_count']) is int and oracle['state_count'] == 80
            and oracle['expected_bits'] == BITS, 'frozen oracle table differs')
    source_list = records(fixture['sources'], 6, 'fixture sources')
    require(len(source_list) == 6, 'fixture source count')
    sources = {}
    for item in source_list:
        require(type(item) is dict and type(item['id']) is str
                and item['id'] in SOURCE_IDS and item['id'] not in sources, 'source identity')
        sources[item['id']] = string(item['text'], 'source text')
    require(set(sources) == SOURCE_IDS and sha(sources['CODE'].encode()) == CODE_SHA256,
            'frozen CODE source differs')
    parse_function(sources['CODE'].encode(), FUNCTION, PARAMETERS, DOMAINS)
    return sources


def response_shape(candidate):
    fields(candidate, TOP)
    require(candidate['schema'] == 'transport/heldout-release-response/1', 'response schema')
    for name in ('current_rule', 'historical_authority', 'historical_verification'):
        string(candidate[name], name)
    for item in records(candidate['unresolved'], 64, 'unresolved'):
        string(item, 'unresolved item')
    replacement = candidate['replacement']
    fields(replacement, ('schema', 'source_id', 'base_sha256', 'before', 'after'))
    for name in replacement:
        string(replacement[name], 'replacement ' + name)
    require(replacement['schema'] == 'transport/function-replacement/1'
            and replacement['source_id'] == 'CODE', 'replacement schema/target')


def action_records(candidate):
    actions = records(candidate['actions'], 4, 'actions')
    require(len(actions) == len(LEDGER), 'complete frozen ledger required')
    observed = {}
    for item in actions:
        fields(item, ('id', 'state'))
        identifier = string(item['id'], 'action id')
        state = string(item['state'], 'action state')
        require(identifier not in observed, 'duplicate action id')
        observed[identifier] = state
    require(observed == LEDGER, 'frozen action identifiers/states differ')
    return dict(status='EXACT_SNAPSHOT_MATCH', ordering='UNSPECIFIED_BY_TASK')


def citation_records(candidate, sources):
    citations = records(candidate['source_citations'], 64, 'source citations')
    covered = set()
    for item in citations:
        fields(item, ('source', 'quote'))
        source = string(item['source'], 'citation source')
        quote = string(item['quote'], 'citation quote')
        require(source in sources and bool(quote) and quote in sources[source],
                'citation must be nonempty exact contiguous source text')
        covered.add(source)
    require({'RULE', 'HISTORY', 'REPORTS', 'ACTIONS'} <= covered,
            'required citation source coverage incomplete')
    return dict(status='EXACT_CONTIGUOUS_QUOTES_AND_SOURCE_COVERAGE', count=len(citations),
                covered=sorted(covered), narrative_support='NOT_ASSESSED')


def expression_tokens(after):
    require(bool(after.strip()), 'empty replacement expression')
    tokens = tokenize.generate_tokens(io.StringIO(after).readline)
    try:
        for _ in range(1024):
            token = next(tokens, None)
            require(token is not None, 'incomplete replacement token stream')
            require(token.type != tokenize.COMMENT, 'comments are not expression grammar')
            if token.type == tokenize.OP:
                require(token.string in ('(', ')', '==', '!=', '<', '<=', '>', '>=', '+', '-'),
                        'replacement token outside expression grammar')
            if token.type == tokenize.ENDMARKER:
                return
    except (tokenize.TokenError, IndentationError) as error:
        raise ValueError('replacement tokenization refused') from error
    raise ValueError('replacement token count bound')


def patch(candidate, sources):
    item = candidate['replacement']
    base = sources['CODE'].encode('utf-8')
    require(item['base_sha256'] == CODE_SHA256, 'candidate base identity mismatch')
    lines = base.splitlines(keepends=True)
    require(len(lines) == 2 and lines[1].startswith(b'    return ')
            and lines[1].endswith(b'\n'), 'frozen CODE layout differs')
    before = lines[1][len(b'    return '):-1].decode('utf-8').strip()
    require(item['before'] == before, 'before must equal complete original return expression')
    expression_tokens(item['after'])
    result, receipt = apply_replacement(base, CODE_SHA256, before.encode(), item['after'].encode())
    require(receipt['byte_offset'] == len(lines[0]) + len(b'    return ')
            and result == lines[0] + b'    return ' + item['after'].encode() + b'\n',
            'bytes outside complete return expression changed')
    program = parse_function(result, FUNCTION, PARAMETERS, DOMAINS)
    count = _cardinality(program)
    require(count == 80, 'frozen declared-domain state count differs')
    return receipt, _table(program, BITS, count)


def assess(fixture_raw, criteria_raw, candidate_raw):
    result = dict(schema='transport/heldout-release-assessment/1', status='REFUSED',
                  narrative_fidelity='NOT_ASSESSED', historical_authentication='NOT_ASSESSED',
                  authority_meaning='NOT_ASSESSED', uncertainty_meaning='NOT_ASSESSED',
                  task_only_access='NOT_ASSESSED', interpretation_entailment='UNPROVEN',
                  execution_authority='NONE')
    try:
        identity = case_identity()
        sources = fixture_inputs(fixture_raw, criteria_raw)
        candidate = safe_json(candidate_raw, CAP, 1024)
        response_shape(candidate)
        result['actions'] = action_records(candidate)
        result['citations'] = citation_records(candidate, sources)
        result['patch'], result['behavior'] = patch(candidate, sources)
        require(case_identity() == identity, 'helper identity changed during check')
        result['checker_identity'] = identity
        result['status'] = ('DETERMINISTIC_CHECKS_PASSED' if result['behavior']['failures'] == 0
                            else 'FINITE_TABLE_FAILED')
    except (ValueError, KeyError, TypeError, UnicodeError, OSError,
            MemoryError, RecursionError, OverflowError) as error:
        result['reason'] = str(error)[:256]
    return result


def pinned(path, expected, cap):
    raw = read_regular(path, cap)
    require(sha(raw) == expected, 'input identity mismatch: ' + path.name)
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('fixture', 'criteria', 'candidate'):
        parser.add_argument('--' + name, type=Path, required=True)
        parser.add_argument('--' + name + '-sha256', required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_CPU, (20, 20))
    resource.setrlimit(resource.RLIMIT_FSIZE, (131072, 131072))
    try:
        raw = {name: pinned(getattr(args, name), getattr(args, name + '_sha256'),
                            CAP if name == 'candidate' else 65536)
               for name in ('fixture', 'criteria', 'candidate')}
        result = assess(raw['fixture'], raw['criteria'], raw['candidate'])
        for name in raw:
            require(read_regular(getattr(args, name)) == raw[name], 'input changed during check')
        result['inputs'] = {name: dict(bytes=len(value), sha256=sha(value))
                            for name, value in raw.items()}
        encoded = canonical(result) + b'\n'
        require(len(encoded) <= 131072, 'assessment output bound')
        sys.stdout.buffer.write(encoded)
        return 0 if result['status'] == 'DETERMINISTIC_CHECKS_PASSED' else 1
    except (ValueError, KeyError, TypeError, UnicodeError, OSError,
            MemoryError, RecursionError, OverflowError) as error:
        sys.stdout.buffer.write(canonical(dict(status='REFUSED', reason=str(error)[:256],
                                               execution_authority='NONE')) + b'\n')
        return 2


if __name__ == '__main__':
    sys.exit(main())
