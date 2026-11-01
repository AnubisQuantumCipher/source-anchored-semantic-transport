#!/usr/bin/env python3
"""Literal source-checker controls with create-only first-output retention.

Expected dispositions are authored constants, never derived from the checker.
Synthetic source facts below are independent of product decoder behavior.
"""

import argparse
import ast
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
CHECKER = HERE / 'check_answer.py'
SUPPORT = HERE / 'trace_support.py'
ORACLE_SHA = 'd4ff2d766bdd32c9d0016eedd84433b7a1bc69f202c6533572b93684449d5375'
CAP, TOTAL_CAP = 4194304, 16777216


def need(condition, reason):
    if type(condition) is not bool or not condition:
        raise ValueError(reason)


def encode(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('ascii')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path, cap=CAP):
    need(path.is_file() and not path.is_symlink(), 'regular nonsymlink test input')
    with path.open('rb') as stream:
        raw = stream.read(cap + 1)
    need(len(raw) <= cap, 'test input cap')
    return raw


def save(path, raw):
    data = raw if type(raw) is bytes else encode(raw)
    need(len(data) <= CAP, 'test output cap')
    with path.open('xb') as stream:
        need(stream.write(data) == len(data), 'short test output')
    need(read(path) == data, 'test output readback')
    return dict(bytes=len(data), sha256=sha(data))


def source(name, revision, raw):
    return dict(id=name, revision=revision, raw_base64=base64.b64encode(raw).decode('ascii'),
                sha256=sha(raw))


def cite(name, revision, raw, begin, end, quote):
    return dict(source=name, revision=revision, source_sha256=sha(raw),
                begin=begin, end=end, quote=quote)


def fixture():
    oracle = dict(schema='transport/source-handoff-oracle/1', sources=[
        source('OLD', 'r1', b'ABCDE\n'), source('NEW', 'r2', b'ABCDE\n'),
        source('NUM', 'n1', b'12 L')], required_spans=[
        dict(source='OLD', begin=0, end=6), dict(source='NEW', begin=0, end=6),
        dict(source='NUM', begin=0, end=4)], obligations=[dict(instruction='DATA_ONLY_NOT_EXECUTED')])
    answer = dict(schema='transport/source-handoff-answer/1', narrative='Synthetic account.',
        evidence=[cite('OLD', 'r1', b'ABCDE\n', 0, 6, 'ABCDE\n'),
                  cite('NEW', 'r2', b'ABCDE\n', 0, 6, 'ABCDE\n'),
                  cite('NUM', 'n1', b'12 L', 0, 4, '12 L')])
    return answer, oracle


def changed(value, path, replacement):
    need(1 <= len(path) <= 4, 'fixed mutation path bound')
    result = json.loads(encode(value))
    target = result
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = replacement
    return result


def add(cases, name, answer, oracle, status, missing=None):
    need(len(cases) < 128, 'case count cap')
    cases.append(dict(name=name, answer=answer if type(answer) is bytes else encode(answer),
        oracle=oracle if type(oracle) is bytes else encode(oracle), expected_status=status,
        expected_missing=missing))


def answer_cases(cases, answer, oracle):
    add(cases, 'exact-distinct-identical-byte-sources', answer, oracle, 'PASS', [])
    variants = [
        ('mutated-number', ['evidence', 2, 'quote'], '13 L'),
        ('same-hash-swapped-source-wrong-revision', ['evidence', 0, 'source'], 'NEW'),
        ('revision-mismatch', ['evidence', 0, 'revision'], 'r2'),
        ('digest-mismatch', ['evidence', 0, 'source_sha256'], '0' * 64),
        ('unknown-source', ['evidence', 0, 'source'], 'ABSENT'),
        ('boolean-begin', ['evidence', 0, 'begin'], False),
        ('boolean-end', ['evidence', 0, 'end'], True),
        ('negative-begin', ['evidence', 0, 'begin'], -1),
        ('floating-end', ['evidence', 0, 'end'], 6.0),
        ('empty-span', ['evidence', 0, 'end'], 0),
        ('span-past-source', ['evidence', 0, 'end'], 7),
        ('quote-boolean', ['evidence', 0, 'quote'], True),
        ('quote-empty', ['evidence', 0, 'quote'], ''),
        ('quote-normalization', ['evidence', 0, 'quote'], 'ABCDE\r\n'),
        ('empty-narrative', ['narrative'], ''),
        ('boolean-narrative', ['narrative'], True),
        ('narrative-over-cap', ['narrative'], 'n' * 16385),
        ('wrong-schema', ['schema'], 'transport/source-handoff-answer/2'),
        ('empty-evidence', ['evidence'], []),
        ('evidence-over-count', ['evidence'], answer['evidence'][:1] * 17)]
    for name, path, replacement in variants:
        add(cases, name, changed(answer, path, replacement), oracle, 'REFUSED')
    extra = dict(answer, extra='not admitted')
    add(cases, 'answer-unknown-key', extra, oracle, 'REFUSED')
    extra_cite = changed(answer, ['evidence', 0], dict(answer['evidence'][0], extra='no'))
    add(cases, 'citation-unknown-key', extra_cite, oracle, 'REFUSED')
    duplicate = dict(answer, evidence=answer['evidence'] + answer['evidence'][:1])
    add(cases, 'duplicate-citation', duplicate, oracle, 'REFUSED')
    semantic = dict(answer, narrative='Unsupported statement: every release is authorized.')
    add(cases, 'semantic-falsehood-not-assessed', semantic, oracle, 'PASS', [])
    hostile = dict(answer, narrative='$(touch NEVER_EXECUTE_THIS_DATA)')
    add(cases, 'narrative-source-data-not-executed', hostile, oracle, 'PASS', [])


def coverage_cases(cases, answer, oracle):
    old_missing = [dict(source='OLD', revision='r1', begin=0, end=6)]
    no_old = dict(answer, evidence=answer['evidence'][1:])
    add(cases, 'same-hash-other-identity-is-not-coverage', no_old, oracle,
        'MISSING_REQUIRED_EVIDENCE', old_missing)
    no_num = dict(answer, evidence=answer['evidence'][:2])
    add(cases, 'missing-required-source', no_num, oracle, 'MISSING_REQUIRED_EVIDENCE',
        [dict(source='NUM', revision='n1', begin=0, end=4)])
    fragments = [cite('OLD', 'r1', b'ABCDE\n', 0, 3, 'ABC'),
                 cite('OLD', 'r1', b'ABCDE\n', 3, 6, 'DE\n')]
    add(cases, 'contiguous-fragments-not-one-containing-citation',
        dict(answer, evidence=fragments + answer['evidence'][1:]), oracle,
        'MISSING_REQUIRED_EVIDENCE', old_missing)
    gaps = [cite('OLD', 'r1', b'ABCDE\n', 0, 2, 'AB'),
            cite('OLD', 'r1', b'ABCDE\n', 3, 6, 'DE\n')]
    add(cases, 'gapped-fragments-not-coverage',
        dict(answer, evidence=gaps + answer['evidence'][1:]), oracle,
        'MISSING_REQUIRED_EVIDENCE', old_missing)
    narrower = changed(oracle, ['required_spans', 0], dict(source='OLD', begin=1, end=5))
    add(cases, 'whole-source-citation-contains-required-span', answer, narrower, 'PASS', [])
    duplicate_identity = changed(answer, ['evidence', 0, 'source'], 'NEW')
    duplicate_identity = changed(duplicate_identity, ['evidence', 0, 'revision'], 'r2')
    add(cases, 'same-hash-swapped-id-and-revision-duplicates-new',
        duplicate_identity, oracle, 'REFUSED')


def unicode_cases(cases):
    raw = b'\xc3\xa9Z'
    oracle = dict(schema='transport/source-handoff-oracle/1',
        sources=[source('UNI', 'u1', raw)],
        required_spans=[dict(source='UNI', begin=0, end=2)], obligations=[])
    answer = dict(schema='transport/source-handoff-answer/1', narrative='Unicode data.',
                  evidence=[cite('UNI', 'u1', raw, 0, 2, '\u00e9')])
    add(cases, 'utf8-byte-span', answer, oracle, 'PASS', [])
    add(cases, 'character-offset-is-not-byte-offset',
        changed(answer, ['evidence', 0, 'end'], 1), oracle, 'REFUSED')
    add(cases, 'unicode-normalization-not-allowed',
        changed(answer, ['evidence', 0, 'quote'], 'e\u0301'), oracle, 'REFUSED')
    add(cases, 'oracle-required-splits-utf8', answer,
        changed(oracle, ['required_spans', 0, 'end'], 1), 'REFUSED')
    opaque = dict(schema='transport/source-handoff-oracle/1',
        sources=[source('OPAQUE', 'o1', b'\xff')], required_spans=[], obligations=[])
    bad_answer = dict(schema='transport/source-handoff-answer/1', narrative='Opaque.',
        evidence=[cite('OPAQUE', 'o1', b'\xff', 0, 1, 'x')])
    add(cases, 'opaque-bytes-cannot-be-text-citation', bad_answer, opaque, 'REFUSED')
    combined_answer, combined_oracle = fixture()
    combined_oracle['sources'].append(source('OPAQUE', 'o1', b'\x00\xff'))
    add(cases, 'unselected-opaque-source-remains-allowed',
        combined_answer, combined_oracle, 'PASS', [])


def oracle_cases(cases, answer, oracle):
    variants = [
        ('oracle-source-hash-mismatch', ['sources', 0, 'sha256'], '0' * 64),
        ('oracle-invalid-base64', ['sources', 0, 'raw_base64'], '%%%'),
        ('oracle-noncanonical-base64', ['sources', 2, 'raw_base64'], 'MTIgTB=='),
        ('oracle-empty-revision', ['sources', 0, 'revision'], ''),
        ('oracle-boolean-revision', ['sources', 0, 'revision'], True),
        ('oracle-source-count-over', ['sources'], oracle['sources'][:1] * 17),
        ('oracle-required-count-over', ['required_spans'], oracle['required_spans'][:1] * 17),
        ('oracle-required-boolean', ['required_spans', 0, 'begin'], False),
        ('oracle-required-float', ['required_spans', 0, 'end'], 6.0),
        ('oracle-required-past-end', ['required_spans', 0, 'end'], 7),
        ('oracle-required-unknown-source', ['required_spans', 0, 'source'], 'ABSENT'),
        ('oracle-obligations-not-data-list', ['obligations'], {'execute': 'FORBIDDEN'}),
        ('oracle-source-empty', ['sources'], []),
        ('oracle-schema', ['schema'], 'transport/source-handoff-oracle/2')]
    for name, path, replacement in variants:
        add(cases, name, answer, changed(oracle, path, replacement), 'REFUSED')
    add(cases, 'oracle-duplicate-source-id', answer,
        dict(oracle, sources=oracle['sources'] + oracle['sources'][:1]), 'REFUSED')
    add(cases, 'oracle-duplicate-required-span', answer,
        dict(oracle, required_spans=oracle['required_spans'] + oracle['required_spans'][:1]), 'REFUSED')
    extra = changed(oracle, ['sources', 0], dict(oracle['sources'][0], extra='no'))
    add(cases, 'oracle-unknown-source-key', answer, extra, 'REFUSED')
    add(cases, 'oracle-unknown-root-key', answer, dict(oracle, extra='no'), 'REFUSED')
    data = dict(oracle, obligations=[dict(instruction='$(touch NEVER_EXECUTE_ORACLE_DATA)')])
    add(cases, 'oracle-obligations-are-inert-data', answer, data, 'PASS', [])


def budget_cases(cases, answer, oracle):
    add(cases, 'answer-byte-budget', b' ' * 32769, oracle, 'REFUSED')
    add(cases, 'oracle-byte-budget', answer, b' ' * 131073, 'REFUSED')
    add(cases, 'answer-duplicate-json-key',
        b'{"schema":"transport/source-handoff-answer/1","schema":"duplicate"}', oracle, 'REFUSED')
    duplicate_oracle = b'{"schema":"a","schema":"b"}'
    add(cases, 'oracle-duplicate-json-key', answer, duplicate_oracle, 'REFUSED')
    add(cases, 'answer-nonfinite-json',
        b'{"schema":"x","narrative":NaN,"evidence":[]}', oracle, 'REFUSED')
    add(cases, 'answer-deep-json', b'[' * 65 + b'0' + b']' * 65, oracle, 'REFUSED')
    large = dict(schema='transport/source-handoff-oracle/1',
        sources=[source('LARGE', 'l1', b'A' * 65536)], required_spans=[], obligations=[])
    one = dict(schema='transport/source-handoff-answer/1', narrative='Bounded.',
        evidence=[cite('LARGE', 'l1', b'A' * 65536, 0, 1, 'A')])
    add(cases, 'source-budget-exact-bound', one, large, 'PASS', [])
    add(cases, 'source-over-budget', one,
        dict(large, sources=[source('LARGE', 'l1', b'A' * 65537)]), 'REFUSED')
    aggregate = dict(large, sources=[source('LARGE', 'l1', b'A' * 32769),
                                   source('OTHER', 'l2', b'B' * 32769)])
    add(cases, 'aggregate-source-over-budget', one, aggregate, 'REFUSED')


def admitted_fixture(cases):
    raw = read(HERE / 'oracle.json', 131072)
    need(sha(raw) == ORACLE_SHA, 'admitted source oracle changed')
    value, evidence = json.loads(raw), []
    required = {item['source'] for item in value['required_spans']}
    for item in value['sources']:
        if item['id'] in required:
            data = base64.b64decode(item['raw_base64'], validate=True)
            evidence.append(cite(item['id'], item['revision'], data, 0, len(data), data.decode('utf-8')))
    answer = dict(schema='transport/source-handoff-answer/1',
                  narrative='Synthetic plumbing candidate; narrative semantics not assessed.', evidence=evidence)
    add(cases, 'admitted-oracle-full-required-sources', answer, raw, 'PASS', [])


def load(path, name):
    specification = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def static_controls():
    result = {}
    for path in (CHECKER, Path(__file__).resolve()):
        tree = ast.parse(read(path))
        functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
        need(all(node.end_lineno - node.lineno + 1 <= 60 for node in functions), 'function size limit')
        need(not any(isinstance(node, (ast.While, ast.AsyncFor, ast.Assert)) for node in ast.walk(tree)),
             'unbounded explicit loop or assertion-only enforcement')
        for function in functions:
            need(not any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                         and node.func.id == function.name for node in ast.walk(function)), 'direct recursion')
        result[path.name] = dict(max_function_lines=max(n.end_lineno - n.lineno + 1 for n in functions),
                                functions=len(functions), explicit_while=False, assertions=False)
    return result


def api_control(module, case):
    try:
        result = module.validate(case['answer'], case['oracle'])
        observed = dict(status=result['status'], result=result)
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError,
            OverflowError, RecursionError) as error:
        observed = dict(status='REFUSED', reason=str(error)[:256])
    passed = observed['status'] == case['expected_status']
    if observed['status'] != 'REFUSED':
        result = observed['result']
        passed = passed and result['source_membership'] == 'PASS'
        passed = passed and result['interpretation'] == 'NOT_ASSESSED' and result['authority'] == 'NONE'
        passed = passed and result['missing_spans'] == case['expected_missing']
        passed = passed and result['required_evidence'] == ('COMPLETE' if case['expected_status'] == 'PASS' else 'MISSING')
        passed = passed and result['oracle_sha256'] == sha(case['oracle'])
        passed = passed and result['answer_sha256'] == sha(case['answer'])
    else:
        passed = passed and bool(observed.get('reason'))
    return dict(name=case['name'], passed=passed, expected_status=case['expected_status'], observed=observed)


def child_limits():
    for kind, bound in ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_CPU, 30),
                        (resource.RLIMIT_FSIZE, CAP), (resource.RLIMIT_NOFILE, 64)):
        resource.setrlimit(kind, (bound, bound))


def cli_control(root, name, case, pin_override=None, file_kind='regular'):
    directory = root / ('cli-' + name)
    directory.mkdir(mode=0o700)
    save(directory / 'answer.json', case['answer'])
    save(directory / 'oracle.json', case['oracle'])
    answer = directory / 'answer.json'
    if file_kind == 'symlink':
        answer = directory / 'alias.json'
        answer.symlink_to(directory / 'answer.json')
    elif file_kind == 'missing':
        answer = directory / 'missing.json'
    elif file_kind == 'directory':
        answer = directory
    command = [sys.executable, '-I', '-S', '-B'] + (['-O'] if sys.flags.optimize else [])
    command += ['-Werror', str(CHECKER), '--answer', str(answer), '--oracle', str(directory / 'oracle.json'),
                '--expect-oracle-sha256', pin_override or sha(case['oracle'])]
    save(directory / 'command.json', dict(argv=command, cwd=str(directory), stdin='DEVNULL',
        wall_seconds=30, child_address_bytes=268435456, child_cpu_seconds=30, child_file_bytes=CAP))
    timeout = False
    with (directory / 'stdout').open('xb') as out, (directory / 'stderr').open('xb') as err:
        try:
            result = subprocess.run(command, cwd=directory, env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                'LC_ALL': 'C.UTF-8'}, stdin=subprocess.DEVNULL, stdout=out, stderr=err,
                timeout=30, check=False, close_fds=True, preexec_fn=child_limits)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code, timeout = None, True
    stdout, stderr = read(directory / 'stdout'), read(directory / 'stderr')
    observed = json.loads(stdout) if stdout else {}
    expected = 'REFUSED' if pin_override or file_kind != 'regular' else case['expected_status']
    passed = (not timeout and not stderr and stdout.endswith(b'\n')
              and stdout == encode(observed) + b'\n' and observed.get('status') == expected
              and code == (0 if expected == 'PASS' else 1))
    result = dict(name=name, passed=passed, expected_status=expected, observed=observed,
                  exit_code=code, wall_timeout=timeout, stdout_pin=dict(bytes=len(stdout), sha256=sha(stdout)),
                  stderr_pin=dict(bytes=len(stderr), sha256=sha(stderr)))
    save(directory / 'result.json', result)
    return result


def pin_inputs(root, args):
    paths = (CHECKER, SUPPORT, Path(__file__).resolve(), HERE / 'oracle.json',
             HERE / 'contract.json', HERE / 'contract-addendum.json', Path(sys.executable).resolve())
    pins = {}
    for index, path in enumerate(paths):
        raw = read(path)
        pins[str(path)] = dict(bytes=len(raw), sha256=sha(raw))
        save(root / ('source-%02d.bin' % index), raw)
    need(pins[str(CHECKER)]['sha256'] == args.expect_checker_sha256, 'held checker changed')
    need(pins[str(SUPPORT)]['sha256'] == args.expect_support_sha256, 'held support changed')
    need(pins[str(HERE / 'oracle.json')]['sha256'] == ORACLE_SHA, 'held source oracle changed')
    save(root / 'source-pins.json', pins)
    return pins


def verify_pins(pins):
    for path, pin in pins.items():
        raw = read(Path(path))
        need(dict(bytes=len(raw), sha256=sha(raw)) == pin, 'source changed during controls')


def run(root, args):
    need(root.is_absolute() and root.parent.is_dir() and not root.exists() and not root.is_symlink(),
         'new evidence directory with existing parent required')
    root.mkdir(mode=0o700)
    pins = pin_inputs(root, args)
    static = static_controls()
    save(root / 'static-controls.json', static)
    cases, pair = [], fixture()
    answer_cases(cases, *pair)
    coverage_cases(cases, *pair)
    unicode_cases(cases)
    oracle_cases(cases, *pair)
    budget_cases(cases, *pair)
    admitted_fixture(cases)
    need(len({case['name'] for case in cases}) == len(cases), 'unique cases')
    save(root / 'literal-case-expectations.json', [dict(name=c['name'], answer_base64=base64.b64encode(c['answer']).decode(),
        oracle_base64=base64.b64encode(c['oracle']).decode(), expected_status=c['expected_status'],
        expected_missing=c['expected_missing']) for c in cases])
    module, results = load(CHECKER, 'receiving_checker_under_test'), []
    for case in cases:
        results.append(api_control(module, case))
    save(root / 'api-results.json', results)
    selected = ('exact-distinct-identical-byte-sources', 'missing-required-source', 'mutated-number',
                'answer-duplicate-json-key', 'admitted-oracle-full-required-sources', 'source-budget-exact-bound')
    by_name = {case['name']: case for case in cases}
    cli = [cli_control(root, name, by_name[name]) for name in selected]
    valid = cases[0]
    cli.append(cli_control(root, 'held-oracle-mismatch', valid, '0' * 64))
    cli.append(cli_control(root, 'malformed-held-pin', valid, 'NOT_A_DIGEST'))
    for kind in ('symlink', 'missing', 'directory'):
        cli.append(cli_control(root, 'answer-' + kind, valid, file_kind=kind))
    verify_pins(pins)
    files = list(root.rglob('*'))
    need(len(files) <= 256, 'evidence member cap')
    for path in files:
        if path.is_symlink():
            need(path == root / 'cli-answer-symlink/alias.json'
                 and os.readlink(path) == str(root / 'cli-answer-symlink/answer.json'),
                 'only the deliberate negative-control symlink is allowed')
    total = sum(p.stat().st_size for p in files if p.is_file() and not p.is_symlink())
    need(total <= TOTAL_CAP, 'aggregate evidence budget')
    failed = [r['name'] for r in results + cli if not r['passed']]
    receipt = dict(schema='transport/source-handoff-checker-controls/1',
        status='PASS' if not failed else 'FAILED', optimized=bool(sys.flags.optimize),
        api_cases=len(results), cli_cases=len(cli), failed_cases=failed, code_pins=pins,
        actual_evidence_bytes_before_receipt=total, interpretation='NOT_ASSESSED', authority='NONE', models='UNRUN')
    save(root / 'receipt.json', receipt)
    print(encode(receipt).decode('ascii'))
    return 0 if not failed else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--expect-checker-sha256', required=True)
    parser.add_argument('--expect-support-sha256', required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_AS, (536870912, 536870912))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (CAP, CAP))
    return run(args.evidence, args)


if __name__ == '__main__':
    sys.exit(main())
