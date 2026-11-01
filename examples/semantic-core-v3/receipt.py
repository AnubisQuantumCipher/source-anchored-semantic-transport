"""Check frozen evidence and exact current sources without executing packages.

This is a bounded receipt checker, not a proof checker or an authenticator.
The retained prover output records the stated SPARK contracts only.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import sys
import zlib

CAP = 1048576
FILE_CAP = 512
TOTAL_CAP = 4194304
RUNTIME = {'install/transport_install_support.py', 'transport_core.py',
           'transport_core_bridge.py', 'transport_core_cli.py',
           'transport_core_language.py', 'transport_core_process.py',
           'transport_operators.py', 'transport_requirement_language.py',
           'transport_schema.py', 'transport_wire.py'}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def integer(value, expected_value):
    return type(value) is int and value == expected_value


def read(base, name):
    parts = Path(name).parts
    require(parts and not Path(name).is_absolute(), 'absolute evidence path')
    require(all(p not in ('.', '..', '') for p in parts), 'unsafe path')
    target = base
    for part in parts:
        target = target / part
        require(not target.is_symlink(), 'symlink refused')
    info = target.stat()
    require(stat.S_ISREG(info.st_mode) and info.st_size <= CAP, 'file cap/type')
    with target.open('rb') as stream:
        raw = stream.read(CAP + 1)
    require(len(raw) == info.st_size and len(raw) <= CAP, 'file changed/cap')
    return raw


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def pin(base, name):
    raw = read(base, name)
    return {'path': name, 'bytes': len(raw), 'sha256': digest(raw)}


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def finite_float(token):
    value = float(token)
    require(math.isfinite(value), 'nonfinite JSON number')
    return value


def json_bytes(raw):
    require(type(raw) is bytes and len(raw) <= CAP, 'JSON byte cap/type')
    depth = 0
    quoted = escaped = False
    for char in raw.decode('utf-8'):
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            require(depth <= 48, 'JSON depth cap')
        elif char in ']}':
            depth -= 1
            require(depth >= 0, 'JSON structure')
    require(depth == 0 and not quoted, 'truncated JSON')
    return json.loads(raw, object_pairs_hook=pairs,
                      parse_constant=lambda unused: require(False, 'nonfinite'),
                      parse_float=finite_float)


def load(base, name):
    raw = read(base, name)
    if name.endswith('.gz'):
        raw = expand(raw)
    return json_bytes(raw)


def expand(raw):
    decoder = zlib.decompressobj(31)
    raw = decoder.decompress(raw, CAP + 1)
    require(len(raw) <= CAP and decoder.eof and not decoder.unused_data,
            'gzip expansion/truncation/trailing data')
    return raw


def inventory(base):
    found = []
    pending = [('', 0)]
    total = 0
    for unused in range(FILE_CAP):
        if not pending:
            break
        prefix, depth = pending.pop()
        require(depth <= 10, 'directory depth cap')
        with os.scandir(base / prefix) as iterator:
            entries = []
            for entry in iterator:
                require(len(entries) < FILE_CAP, 'directory entry cap')
                entries.append(entry)
        for entry in sorted(entries, key=lambda item: item.name):
            name = str(Path(prefix) / entry.name)
            require(not entry.is_symlink(), 'symlink refused')
            if entry.is_dir(follow_symlinks=False):
                pending.append((name, depth + 1))
            elif name != 'receipt.json':
                item = pin(base, name)
                found.append(item)
                total += item['bytes']
                require(len(found) <= FILE_CAP and total <= TOTAL_CAP,
                        'evidence inventory cap')
    require(not pending, 'directory traversal cap')
    return sorted(found, key=lambda item: item['path'])


def check_pin(base, item):
    got = pin(base, item['path'])
    require(got['sha256'] == item['sha256'], 'pin mismatch: ' + item['path'])
    if 'bytes' in item:
        require(integer(item['bytes'], got['bytes']), 'size mismatch: ' + item['path'])


def summary(base, name, expected_unproved):
    text = read(base, name).decode()
    rows = re.findall(r'^Total\s+.*$', text, re.MULTILINE)
    require(len(rows) == 1, 'proof Total coverage')
    cells = re.sub(r'\([^)]*\)', '', rows[0]).split()
    require(len(cells) == 6 and cells[0] == 'Total', 'proof Total format')
    numbers = [0 if cell == '.' else int(cell) for cell in cells[1:]]
    require(all(number >= 0 for number in numbers) and
            numbers[0] == sum(numbers[1:]), 'proof totals disagree')
    require(numbers[0] > 0 and numbers[-2:] == [0, expected_unproved],
            'proof contains unproved/justified checks')
    if expected_unproved == 0:
        require('not proved' not in text.lower(), 'contradictory detailed proof')
    units = re.findall(r'^in unit (\w+), (\d+) subprograms and packages '
                       r'out of (\d+) analyzed$', text, re.MULTILINE)
    require(units and all(done == all_ for _, done, all_ in units),
            'partial proof unit')
    require(not re.search(r'[1-9]\d* (?:errors|warnings|pragma Assume)', text),
            'proof warnings/errors/assumptions')
    return numbers, {unit for unit, _, _ in units}


def native_sources(root, example):
    base = example / 'evidence/native'
    native = load(base, 'receipt.json')
    manifest = load(base, 'proof-source-manifest-04.json')
    require(integer(native['proof']['process_exit'], 0) and
            native['proof']['all_project_units'] is True, 'native proof scope')
    require('-U' in native['proof']['command'], 'all-unit command required')
    items = manifest['items']
    expected = {'evaluation/transport_core.gpr'}
    for directory in ('src', 'evaluation/src'):
        for child in (root / directory).iterdir():
            if child.suffix in ('.ads', '.adb'):
                expected.add(str(child.relative_to(root)))
    require({item['path'] for item in items} == expected,
            'proof source inventory coverage')
    for item in items:
        check_pin(root, item)
        check_pin(base / 'proof-04-sources', item)
    counts, units = summary(base, 'proof-04-summary.out', 0)
    require(units == {Path(p).stem for p in expected if p.endswith(('.ads', '.adb'))},
            'proof analyzed unit coverage')
    summary(base, 'proof-03-summary.out', 5)
    for item in native['sources']:
        check_pin(root, item)
    for item in native['artifacts']:
        if not item['name'].endswith('.tar.gz'):
            check_pin(base, dict(item, path=item['name']))
    require(read(base, 'checks-03.stdout') == b'PASS CORE_CHECKS\n' and
            read(base, 'checks-03.stderr') == b'', 'native checks failed')
    require(integer(native['tests']['exit'], 0), 'native check exit')
    return native, expected | {item['path'] for item in native['sources']}, counts


def legacy_sources(root, example):
    base = example / 'evidence/native'
    receipt = load(base, 'legacy-receipt.json')
    require(receipt['status'] == 'PASS' and integer(receipt['build']['exit'], 0),
            'legacy regression failed')
    require(len(receipt['tests']) == 2 and all(
        all(integer(row[key], 0) for key in ('exit', 'stdout_bytes', 'stderr_bytes'))
        for row in receipt['tests']), 'legacy test results')
    for item in receipt['unchanged_files']:
        check_pin(root, item)
        require(item['byte_identical_to_head'] is True, 'legacy changed')
    for item in receipt['artifacts']:
        check_pin(base, dict(item, path=item['name']))
    for suffix in ('ads', 'adb'):
        name = 'transport_eval.' + suffix
        old = read(example / 'evidence/legacy-original', name)
        prefix = old.split(b'end Transport_Eval;', 1)[0]
        require(prefix and read(root, 'evaluation/src/' + name).startswith(prefix),
                'legacy evaluator prefix changed')
        require(digest(read(root, 'evaluation/src/' + name)) ==
                receipt['additive_evaluator_sha256'][name], 'legacy evaluator pin')
    return {item['path'] for item in receipt['unchanged_files']}


def test_log(base, name, count):
    text = read(base, name).decode()
    require(re.search(r'\nRan ' + str(count) + r' tests in [0-9.]+s\n\nOK\n$', text)
            is not None, 'test log not complete pass: ' + name)
    require('skipped' not in text.lower() and 'warning' not in text.lower(),
            'test warning/skip')


def python_tests(root, example, native):
    base = example / 'evidence/integration'
    frozen = load(base, 'test-oracle-04.json')
    for item in frozen['files']:
        check_pin(root, item)
    for mode in ('normal', 'optimized'):
        name = 'test-' + mode + '-04'
        run = load(base, name + '.run.json')
        require(integer(run['exit_code'], 0), 'integration failed')
        require(run['environment']['TRANSPORT_CORE_NATIVE_SHA256'] == native,
                'integration native pin')
        for suffix, item in run['logs'].items():
            check_pin(base, dict(item, path=name + '.' + suffix))
        test_log(base, name + '.stderr', 12)
    language = load(example / 'evidence/language', 'receipt.json')
    for item in language['source']:
        check_pin(root, item)
    for row in language['runs']:
        require(integer(row['exit_code'], 0), 'language test failed')
        for item in row['logs']:
            check_pin(example / 'evidence/language', item)
        test_log(example / 'evidence/language', row['mode'] + '.stderr', 15)
    return {item['path'] for item in frozen['files'] + language['source']}


def independent_controls(root, example, native):
    base = example / 'evidence'
    for mode in ('normal', 'optimized'):
        name = 'final-controls-' + mode
        report = load(base, name + '.json.gz')
        require(report['successful'] is True and integer(report['test_groups'], 3) and
                all(integer(report[key], 0) for key in ('skips', 'errors', 'failures')),
                'independent groups failed/skipped')
        require(len(report['cases']) == 139 and all(
            row['pass'] is True for row in report['cases']), 'independent controls')
        require(len({row['id'] for row in report['cases']}) == 139,
                'duplicate independent control')
        require(report['native_sha256'] == native, 'independent native pin')
        require(digest(read(root, 'tests/test_transport_core.py')) ==
                report['test_source_sha256'], 'independent oracle source pin')
        require(digest(read(example, 'run_controls.py')) == report['capture_sha256'],
                'independent capture source pin')
        test_log(base, name + '.stderr', 3)
        require(integer(load(base, name + '.run.json')['exit_code'], 0), 'control exit')
    review = load(base / 'review/delta-review', 'public-review-receipt-final-02.json')
    require(review['status'] == 'REVIEWED_SCOPED_EVIDENCE_PASS' and
            review['native_sha256'] == native, 'independent review status/pin')
    for name, sha in review['source_pins'].items():
        require(digest(read(root, name)) == sha, 'review source pin: ' + name)
    return set(review['source_pins']) | {'tests/test_transport_core.py'}


def retained_controls(root, example):
    base = example / 'evidence'
    original = load(base, 'review/schema-review/results.json.gz')['cases']
    failed = {row['id'] for row in original if row['pass'] is False}
    require(failed == {'wire_bad_plan_version', 'wire_unknown_translation',
                       'wire_extra_field'}, 'original schema failures lost')
    original = load(base, 'review/process-review/results01.json')['cases']
    require([r['case']['id'] for r in original if r['pass'] is False] ==
            ['directory_fd_closed'], 'original descriptor failure lost')
    checked = {}
    for name, field, count in (
        ('review/process-review/results02/results01.json', 'cases', 12),
        ('review/process-review/error-results.json', 'cases', 4),
        ('review/delta-review/replay-results.json', 'results', 6)):
        rows = load(base, name)[field]
        require(len(rows) == count and all(row['pass'] is True for row in rows),
                'error/replay control failed: ' + name)
        checked[name] = [row.get('id', row.get('case', {}).get('id')) for row in rows]
    source = read(root, 'tests/test_transport_core.py').decode()
    matches = re.findall(r"FROZEN = json.loads\(r'''(.*?)'''\)", source, re.DOTALL)
    require(len(matches) == 1, 'frozen oracle declaration changed')
    frozen = json_bytes(matches[0].encode())
    original = load(base, 'contract/oracle.json')
    require(frozen and all(original[key] == value for key, value in frozen.items()),
            'preimplementation oracle changed')
    failure = load(base, 'historical-on-current.json')
    require(integer(failure['exit_code'], 1) and b'source inventory coverage mismatch' in
            read(base, 'historical-on-current.stderr'), 'historical refusal lost')
    review = load(base / 'review/delta-review', 'public-review-receipt-final-02.json')
    paths = {'SCHEMA-01': 'review/schema-review/results.json.gz',
             'PROCESS-01': 'review/process-review/results01.json',
             'PROOF-03': 'native/proof-03-summary.out'}
    require({row['id'] for row in review['retained_failures']} == set(paths),
            'review retained failure coverage')
    for row in review['retained_failures']:
        name = paths[row['id']]
        raw = read(base, name)
        require(digest(expand(raw) if name.endswith('.gz') else raw) == row['sha256'],
                'review retained raw failure pin')
    for row in review['prior_revisions'] + [review['provenance_correction']]:
        name = 'review/delta-review/' + Path(row['artifact']).name
        require(digest(read(base, name)) == row['sha256'], 'review provenance pin')
    return checked


def held_product(example):
    report = load(example / 'evidence/integration', 'receipt-04.json')
    files = {'share': 'share.txt', 'archive': 'meaning.zip', 'lexicon': 'lexicon.md',
             'recipient_result': 'recipient-result.json', 'replay': 'replay.json',
             'recovered_source': 'source.txt', 'recovered_model': 'model.json',
             'recovered_payload': 'core-envelope.json'}
    require(set(report['held_fixture']) == set(files), 'held fixture coverage')
    for field, name in files.items():
        check_pin(example, dict(report['held_fixture'][field], path=name))
    base = example / 'evidence/integration'
    check_pin(base, report['source_snapshot'])
    for run in report['runs']:
        check_pin(base, run)


def relocated(example):
    base = example / 'evidence/relocated-recipient'
    result = load(base, 'receipt.json')
    require(integer(result['exit_code'], 0) and result['result_exact_comparison'] == 'PASS'
            and result['source_model_core_byte_comparison'] == 'PASS',
            'relocated recovery failed')
    for suffix in ('stdout', 'stderr'):
        require(digest(read(base, suffix)) == result[suffix + '_sha256'],
                'relocated log pin')
    decoded = json_bytes(read(base, 'stdout'))
    require(decoded == load(example, 'recipient-result.json'),
            'relocated recipient result differs')
    for name in ('share.txt', 'meaning.zip'):
        pins = [sha for path, sha in result['held_inputs'].items()
                if Path(path).name == name]
        require(pins == [digest(read(example, name))], 'relocated input pin')


def product(example, native):
    result = load(example, 'recipient-result.json')
    replay = load(example, 'replay.json')
    for source, recovered, key in (
        ('source.txt', 'source-recovered.txt', 'source_sha256'),
        ('model.json', 'model-recovered.json', 'model_sha256'),
        ('original.stc3', 'recovered.stc3', 'frame_sha256')):
        require(read(example, source) == read(example, recovered), 'recovery differs')
        require(digest(read(example, source)) == result[key], 'result digest differs')
    require(result['payload_sha256'] == digest(read(example, 'core-envelope.json')),
            'payload digest differs')
    require(result['native_sha256'] == native and replay['native_sha256'] == native,
            'product native pin')
    require(replay['original'] == replay['recovered'] and
            replay['status'] == 'ORIGINAL_RECOVERED_VALUES_MATCH', 'replay mismatch')
    require(result['nodes'] == replay['original']['nodes'] and
            result['result'] == replay['original']['result'], 'recipient differs')
    require(result['result'] == {'node': 6, 'outcome': 'VIOLATED',
                               'sort': 'NORM', 'truth': 'UNRESOLVED'}, 'norm boundary')
    require(result['semantic_scope'] == 'CLOSED_FORMULA_IN_SUPPLIED_FINITE_MODEL' and
            result['reading_status'] == 'PROPOSED_STRUCTURED_READING', 'scope')
    require(result['semantic_completeness'] == 'UNPROVEN' and
            result['execution_authority'] == 'NONE', 'claim inflation')
    share = read(example, 'share.txt').decode()
    require(result['package_identity'] in share and
            replay['package_identity'] == result['package_identity'], 'pair identity')
    absent = load(example / 'evidence/no-model', 'roundtrip-result.json')
    require(absent['status'] == 'NOT_EVALUATED' and absent['nodes'] == [] and
            absent['result'] is None and absent['model_sha256'] is None and
            absent['semantic_scope'] == 'NONE_NO_MODEL' and
            absent['reading_status'] == 'PROPOSED_STRUCTURED_READING', 'no-model scope')
    return {'identity': result['package_identity'], 'share_codepoints': len(share),
            'archive_bytes': len(read(example, 'meaning.zip')),
            'source_bytes': len(read(example, 'source.txt')),
            'model_bytes': len(read(example, 'model.json')),
            'result': result['result'], 'ai_recipient': 'UNPERFORMED'}


def runtime_sources(root, example, native):
    runtime = load(example, 'core-envelope.json')['runtime']
    require(set(runtime['files']) == RUNTIME, 'runtime dependency coverage')
    require(runtime['native_sha256'] == native, 'runtime native pin')
    names = set()
    for name, sha in runtime['files'].items():
        path = name if name.startswith('install/') else 'tools/' + name
        require(digest(read(root, path)) == sha, 'runtime source pin: ' + path)
        names.add(path)
    account = load(example / 'evidence/integration', 'dependency-accounting-04.json')
    require(account['native']['sha256'] == native, 'dependency native pin')
    declared = {}
    for item in account['grammar_runtime_files']:
        require(item['path'] not in declared, 'duplicate runtime dependency')
        declared[item['path']] = item['sha256']
    require(declared == runtime['files'], 'dependency accounting coverage')
    courier = account['qualified_courier_bundle_files']
    require(len(courier) <= 64 and len({item['path'] for item in courier}) == len(courier),
            'courier dependency count/duplicates')
    for item in courier:
        if item['path'] != 'bin/transport_native':
            check_pin(example / 'evidence/courier-sources', item)
    launcher = [item for item in courier if item['path'] == 'bin/semantic-transport']
    require(len(launcher) == 1 and launcher[0]['sha256'] ==
            runtime['decoder_launcher_sha256'], 'courier launcher accounting pin')
    return names


def expected(root, example):
    native, sources, counts = native_sources(root, example)
    native_pin = native['binary']['sha256']
    sources |= legacy_sources(root, example)
    sources |= python_tests(root, example, native_pin)
    sources |= independent_controls(root, example, native_pin)
    sources |= runtime_sources(root, example, native_pin)
    metrics = product(example, native_pin)
    held_product(example)
    controls = retained_controls(root, example)
    relocated(example)
    return {'schema': 'transport/semantic-core-evidence/1',
            'status': 'CHECKED_SOURCE_BOUND_SCOPED_EVIDENCE',
            'source_files': [pin(root, name) for name in sorted(sources)],
            'frozen_courier_files': inventory(example / 'evidence/courier-sources'),
            'artifacts': inventory(example), 'native_sha256': native_pin,
            'proof': {'total': counts[0], 'flow': counts[1], 'prover': counts[2],
                      'justified': counts[3], 'unproved': counts[4],
                      'scope': native['proof']['properties'],
                      'exclusions': native['proof']['exclusions']},
            'tests': {'language_methods_per_mode': 15,
                      'integration_methods_per_mode': 12,
                      'independent_controls_per_mode': 139,
                      'error_controls': controls,
                      'modes': ['normal', 'optimized'],
                      'retained_failed_attempts': True},
            'metrics': metrics, 'authentication': 'NOT_AUTHENTICATED',
            'english_entailment': 'UNPROVEN', 'world_truth': 'NOT_CERTIFIED'}


def canonical(value):
    return json.dumps(value, sort_keys=True, indent=2).encode() + b'\n'


def check(root, example):
    observed = expected(root, example)
    require(read(example, 'receipt.json') == canonical(observed),
            'receipt differs from current source/evidence inventory')
    return observed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    example = Path(__file__).resolve().parent
    root = example.parents[1]
    try:
        value = check(root, example) if args.check else expected(root, example)
        if not args.check:
            with (example / 'receipt.json').open('xb') as stream:
                stream.write(canonical(value))
        print(value['status'])
        return 0
    except (ValueError, OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        print('REFUSED: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
