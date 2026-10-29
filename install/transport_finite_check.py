"""Bounded, data-only finite tests bound to an existing predicate occurrence.

The expected table is an externally pinned interpretation, not a proof of English
meaning. Supplied function text is parsed by a closed whitelist and never run as
Python. Local helper bytes and the resolved interpreter are pinned before/after;
the imported host, standard library, loader and OS remain trusted dependencies.
"""
import io
from pathlib import Path
import sys
import tokenize

from transport_fixture_expression import apply_replacement, parse_function, evaluate
from transport_handoff_inputs import ID, digest, fields
from transport_install_support import canonical, read_regular, require, sha
from transport_response_evidence import safe_json, source_pins

CAP, MAX_STATES, MAX_MISMATCHES = 32768, 512, 16
SCHEMA = 'transport/finite-predicate-test/1'
RECEIPT_SCHEMA = 'transport/finite-predicate-receipt/1'
DEPENDENCIES = ('transport_finite_check.py', 'transport_fixture_expression.py',
                'transport_handoff_inputs.py', 'transport_install_layout.py',
                'transport_install_support.py', 'transport_response_evidence.py')


def checker_identity():
    """Describe local implementation bytes; this is not host authentication."""
    root = Path(__file__).absolute().parent
    dependencies = []
    for name in DEPENDENCIES:
        raw = read_regular(root / name, 131072)
        dependencies.append(dict(path=name, bytes=len(raw), sha256=sha(raw)))
    executable = Path(sys.executable).resolve(strict=True)
    raw = read_regular(executable, 4194304)
    return dict(schema='transport/finite-checker-identity/1', dependencies=dependencies,
                python=dict(path=str(executable), bytes=len(raw), sha256=sha(raw),
                            version=sys.version, implementation=sys.implementation.name),
                profile='PURE_BOOLEAN_EXPRESSION_FINITE_DOMAIN',
                max_input_bytes=CAP, max_program_bytes=4096, max_states=MAX_STATES,
                state_order='PARAMETER_ORDER; BOOLEAN_FALSE_TRUE; INTEGER_ASCENDING',
                host_trust='IMPORTED_CODE_STANDARD_LIBRARY_LOADER_AND_OS_ASSUMED',
                formal_proof='NOT_CLAIMED', execution_authority='NONE')


def _pinned_json(raw, expected):
    require(type(raw) is bytes and 0 < len(raw) <= CAP, 'finite input byte bound')
    require(sha(raw) == digest(expected), 'finite input differs from held digest')
    return safe_json(raw, CAP)


def _test(raw, expected, compiled, identity):
    value = _pinned_json(raw, expected)
    fields(value, ('schema', 'binding_sha256', 'checker_sha256', 'base_source_id',
                   'base_source_sha256', 'function_name', 'parameters', 'domains', 'expected_bits'))
    require(value['schema'] == SCHEMA, 'unsupported finite test schema')
    require(digest(value['checker_sha256']) == sha(canonical(identity)), 'checker identity differs')
    binding = digest(value['binding_sha256'])
    bindings = compiled['bindings']
    require(type(bindings) is dict and 1 <= len(bindings) <= 64, 'compiled binding count bound')
    require(sum(item['sha256'] == binding for item in bindings.values()) == 1,
            'finite test requires exactly one matching predicate binding')
    name = value['base_source_id']
    require(type(name) is str and ID.fullmatch(name) is not None, 'invalid finite source identifier')
    pins = source_pins(compiled['sources'], compiled['source_pins'])
    require(name in pins and digest(value['base_source_sha256']) == pins[name], 'base source revision differs')
    return value, compiled['sources'][name]


def _replacement(raw, expected, test, base):
    value = _pinned_json(raw, expected)
    fields(value, ('schema', 'source_id', 'base_sha256', 'before', 'after'))
    require(value['schema'] == 'transport/function-replacement/1', 'unsupported replacement schema')
    require(value['source_id'] == test['base_source_id'], 'replacement source identifier differs')
    require(digest(value['base_sha256']) == test['base_source_sha256'], 'replacement base differs')
    require(type(value['before']) is str and type(value['after']) is str, 'replacement text types')
    before, after = value['before'].encode('utf-8'), value['after'].encode('utf-8')
    return apply_replacement(base, value['base_sha256'], before, after)


def _header(raw):
    """Preserve exact bytes through the parsed function's signature colon."""
    text, depth = raw.decode('utf-8'), 0
    lines = text.splitlines(keepends=True)
    tokens = tokenize.generate_tokens(io.StringIO(text).readline)
    for _ in range(1024):
        token = next(tokens, None)
        require(token is not None, 'function header missing')
        if token.type == tokenize.OP:
            if token.string == '(':
                depth += 1
            elif token.string == ')':
                depth -= 1
            elif token.string == ':' and depth == 0:
                row, column = token.end
                return (''.join(lines[:row - 1]) + lines[row - 1][:column]).encode('utf-8')
    raise ValueError('function header token bound')


def _cardinality(program):
    count = 1
    for domain in program.domains:
        width = 2 if domain.kind == 'boolean' else domain.upper - domain.lower + 1
        require(0 < width <= MAX_STATES and count <= MAX_STATES // width,
                'finite Cartesian domain exceeds state bound')
        count *= width
    return count


def _state(program, ordinal):
    state = {}
    for name, domain in reversed(tuple(zip(program.parameters, program.domains, strict=True))):
        width = 2 if domain.kind == 'boolean' else domain.upper - domain.lower + 1
        offset, ordinal = ordinal % width, ordinal // width
        state[name] = bool(offset) if domain.kind == 'boolean' else domain.lower + offset
    require(ordinal == 0, 'finite state index outside domain')
    return {name: state[name] for name in program.parameters}


def _table(program, expected, count):
    require(type(expected) is str and len(expected) == count
            and all(bit in '01' for bit in expected), 'expected bit table shape')
    actual, mismatches, failures = [], [], 0
    for ordinal in range(count):
        state = _state(program, ordinal)
        value = evaluate(program, state)
        require(type(value) is bool, 'finite result must be exact Boolean')
        bit = '1' if value else '0'
        actual.append(bit)
        if bit != expected[ordinal]:
            failures += 1
            if len(mismatches) < MAX_MISMATCHES:
                mismatches.append(dict(index=ordinal, state=state,
                                       expected=expected[ordinal] == '1', actual=value))
    return dict(actual_bits=''.join(actual), expected_bits_sha256=sha(expected.encode('ascii')),
                state_count=count, failures=failures, first_mismatches=mismatches,
                mismatches_truncated=failures > len(mismatches))


def run_check(test_raw, replacement_raw, compiled, expected_test, expected_replacement):
    """Recompute a finite receipt from held data; no stored claim supplies truth."""
    identity = checker_identity()
    test, base = _test(test_raw, expected_test, compiled, identity)
    original = parse_function(base, test['function_name'], test['parameters'], test['domains'])
    count = _cardinality(original)
    result, replacement = _replacement(replacement_raw, expected_replacement, test, base)
    program = parse_function(result, test['function_name'], test['parameters'], test['domains'])
    require(_header(base) == _header(result), 'function header bytes changed')
    table = _table(program, test['expected_bits'], count)
    require(checker_identity() == identity, 'checker dependency changed during evaluation')
    source_pins(compiled['sources'], compiled['source_pins'])
    receipt = dict(schema=RECEIPT_SCHEMA, status='TESTED_FINITE_DOMAIN',
                test_sha256=sha(test_raw), replacement_sha256=sha(replacement_raw),
                checker_sha256=sha(canonical(identity)), checker_identity=identity,
                binding_sha256=test['binding_sha256'], base_source_id=test['base_source_id'],
                base_source_sha256=sha(base), result_sha256=sha(result), replacement=replacement,
                truth='KNOWN_TRUE' if table['failures'] == 0 else 'KNOWN_FALSE', **table,
                expected_interpretation='UNPROVEN', scope='DECLARED_FINITE_TABLE_ONLY',
                authentication='NOT_AUTHENTICATED', execution_authority='NONE')
    require(len(canonical(receipt)) <= CAP, 'finite receipt byte bound')
    return receipt


def validate_receipt(raw, computed, expected_receipt):
    """Accept only exact canonical bytes of the freshly recomputed receipt."""
    value = _pinned_json(raw, expected_receipt)
    require(type(computed) is dict and computed.get('schema') == RECEIPT_SCHEMA,
            'fresh finite receipt required')
    require(value == computed and raw == canonical(computed), 'finite receipt differs from recomputation')
    return dict(status='RECOMPUTED_RECEIPT_MATCH', receipt_sha256=sha(raw),
                scope='EXACT_CANONICAL_RECOMPUTATION', execution_authority='NONE')
