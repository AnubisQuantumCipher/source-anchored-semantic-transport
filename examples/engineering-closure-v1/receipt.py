#!/usr/bin/env python3
"""Recheck source-bound native and installed observations; never execute evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import stat

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CAP = 1048576
STRICT = ['-U', '--level=2', '--report=all', '--warnings=error',
          '--checks-as-errors=on', '--proof-warnings=on', '-j1']
COMMANDS = ('core-build', 'evaluation-build', 'eval-checks-build',
    'bound-checks-build', 'bound-runtime-build', 'eval-tests', 'bound-tests',
    'core-proof-03', 'evaluation-proof-03', 'bound-proof', 'first-install',
    'second-install', 'current-regression', 'current-product', 'current-portable',
    'bound-native-integration', 'bound-test-receipts', 'legacy-recipient',
    'legacy-mcp', 'current-export-encode', 'current-export-inspect',
    'current-export-render', 'current-export-verify', 'current-independent-inspect',
    'current-independent-recover', 'current-independent-metadata',
    'current-handoff/test_handoff_prepare', 'current-handoff/test_handoff_reader',
    'current-handoff/test_evidence_finish')
TIMEOUTS = ('core-proof', 'evaluation-proof', 'core-proof-02', 'evaluation-proof-02')
PROOFS = (('core', 'core-proof-03', 'transport.gpr'),
    ('evaluation', 'evaluation-proof-03', 'evaluation/transport_eval.gpr'),
    ('bound', 'bound-proof', 'evaluation/transport_bound_eval_proof.gpr'))
SUITES = {'product':9, 'bound-native-integration':22, 'bound-test-receipts':13,
          'test_handoff_prepare':13, 'test_handoff_reader':13, 'test_evidence_finish':14}


def need(value, message):
    if not value:
        raise ValueError(message)


def read(path):
    try:
        need(stat.S_ISREG(path.lstat().st_mode), 'regular receipt input required')
        with path.open('rb') as stream:
            raw = stream.read(CAP + 1)
    except OSError as error:
        raise ValueError('missing or unreadable receipt input: ' + str(path)) from error
    need(len(raw) <= CAP, 'receipt input byte bound')
    return raw


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def pairs(items):
    need(len(items) <= 512, 'JSON object bound')
    result = {}
    for name, value in items:
        need(name not in result, 'duplicate JSON key')
        result[name] = value
    return result


def load(path):
    try:
        return json.loads(read(path), object_pairs_hook=pairs,
                          parse_constant=lambda value: need(False, 'nonfinite JSON'))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('missing or malformed receipt input: ' + str(path)) from error


def relative(value):
    path = Path(value)
    need(type(value) is str and not path.is_absolute() and '..' not in path.parts
         and path.as_posix() == value and 1 <= len(path.parts) <= 10,
         'unsafe receipt path')
    return path


def source_names(root, python=False):
    folders = ('install', 'tests') if python else ('src', 'evaluation/src', 'evaluation/tests', 'evaluation')
    result, visited = set(), 0
    for folder in folders:
        for path in (root / folder).iterdir():
            visited += 1
            need(visited <= 512, 'source directory bound')
            suffixes = ('.py',) if python else ('.ads', '.adb', '.c', '.gpr')
            if path.suffix in suffixes:
                result.add(path.relative_to(root).as_posix())
    if not python:
        result.add('transport.gpr')
    need(0 < len(result) <= 256, 'source coverage bound')
    return result


def source_checks(root, evidence):
    before = load(evidence / 'source-before.json')
    for name in ('source-after.json', 'source-after-continuation.json',
                 'source-after-full-proof.json', 'copied-source-after.json',
                 'copied-source-after-full-proof.json'):
        need(load(evidence / name) == before, 'proof source changed')
    extra = load(evidence / 'python-sources.json')
    need(len(before) <= 128 and len(extra) <= 256, 'source inventory bound')
    need(set(before) == source_names(root) and set(extra) == source_names(root, True),
         'source inventory coverage mismatch')
    for inventory in (before, extra):
        for name, expected_pin in inventory.items():
            data = read(root / relative(name))
            need(pin(data) == expected_pin, 'current source mismatch: ' + name)
            if name.endswith(('.ads', '.adb')):
                pattern = rb'\bpragma\s+(Assume|Suppress|Annotate)\b|Skip_Proof'
                need(re.search(pattern, data, re.I) is None, 'proof bypass marker')
    need(read(root / 'install/SOURCE.json') == read(evidence / 'current-SOURCE.json'),
         'installed source manifest changed')
    manifest = load(evidence / 'current-SOURCE.json')
    need(len(manifest['files']) <= 256, 'installed source count bound')
    for row in manifest['files']:
        need(pin(read(root / relative(row['path']))) ==
             {key: row[key] for key in ('bytes', 'sha256')}, 'installed source mismatch')
    return pin(read(evidence / 'source-before.json'))


def process(evidence, stem, status='SUCCESS', code=0):
    result = load(evidence / (stem + '.json'))
    need(result['status'] == status and type(result['exit_code']) is int
         and result['exit_code'] == code, 'process result: ' + stem)
    for name in ('stdout', 'stderr'):
        actual = pin(read(evidence / (stem + '.' + name)))
        held = result[name]
        need(actual == {key: held[key] for key in ('bytes', 'sha256')},
             'process stream mismatch: ' + stem)
    return result


def proof_checks(evidence, contract):
    rows = []
    identities = [(item['label'], item['stem'], item['project']) for item in contract['proofs']]
    need(identities == list(PROOFS), 'proof project scope mismatch')
    for spec in contract['proofs']:
        execution = process(evidence, spec['stem'])
        need(execution['argv'][1:] == ['-P', spec['project']] + STRICT,
             'proof command weakened')
        report = read(evidence / 'proofs' / (spec['label'] + '.out')).decode('utf-8')
        totals = re.findall(r'^Total\s+.+$', report, re.M)
        need(totals == [spec['total_row']], 'proof total mismatch')
        cleaned = re.sub(r'\([^)]*\)', '', totals[0]).split()[1:]
        need(len(cleaned) == 5 and cleaned[-2:] == ['.', '.'], 'unclosed proof')
        need(all(value.isdigit() and int(value) > 0 for value in cleaned[:3]),
             'empty proof scope')
        units = re.findall(r'^in unit .+$', report, re.M)
        need(units == spec['unit_rows'], 'proof unit coverage mismatch')
        for line in units:
            match = re.fullmatch(r'in unit (\w+), (\d+) subprograms and packages out of (\d+) analyzed', line)
            need(match is not None and match[2] == match[3], 'incomplete proof unit')
        need(re.search(r'\b[1-9]\d* pragma Assume statements', report) is None,
             'proof assumption observed')
        rows.append({'project':spec['project'], 'total':int(cleaned[0]),
            'flow':int(cleaned[1]), 'provers':int(cleaned[2]), 'justified':0,
            'unproved':0, 'unit_rows':units, 'report':pin(report.encode())})
    return rows


def unittest_log(path, count):
    log = read(path).decode('utf-8')
    need(re.search(r'^Ran ' + str(count) + r' tests? in [\d.]+s$', log, re.M)
         is not None and re.search(r'^OK$', log, re.M) is not None,
         'unittest summary missing')
    need(re.search(r'\b(skipped|FAILED|ERROR|FAIL:|ResourceWarning)\b', log) is None,
         'failed, warned or skipped unittest')


def suite_checks(evidence, contract):
    suites = {}
    need(contract['suite_counts'] == SUITES, 'required suite scope mismatch')
    for name, count in contract['suite_counts'].items():
        stem = ('current-handoff/' + name if name.startswith('test_') else
                'install-current/' + name if name == 'product' else name)
        result = load(evidence / stem / 'receipt.json')
        need(result['status'] == 'TESTED_SCOPED' and
             type(result['tests_run']) is int and result['tests_run'] == count,
             'suite result mismatch: ' + name)
        need(result['errors'] in (0, []) and result['failures'] in (0, [])
             and result.get('skipped', []) == [], 'suite failed or skipped: ' + name)
        log_stem = 'current-product' if name == 'product' else stem
        unittest_log(evidence / (log_stem + '.stderr'), count)
        suites[name] = count
    unittest_log(evidence / 'install-current/regression/regression.stderr', 118)
    need(load(evidence / 'install-current/regression/receipt.json')['status'] == 'PASS',
         'installed regression failed')
    for stem, count in (('legacy-recipient',54), ('legacy-mcp',10)):
        unittest_log(evidence / (stem + '.stderr'), count)
        suites[stem] = count
    return dict(suites, installed_regression=118)


def install_checks(evidence):
    source = pin(read(evidence / 'current-SOURCE.json'))['sha256']
    first = load(evidence / 'install-current/first-bundle-inventory.json')
    second = load(evidence / 'install-current/second-bundle-inventory.json')
    review = load(evidence / 'reviews/native-closure-review-20261029.json')
    need(first == second == review['paired_complete_inventory'] and
         review['paired_complete_inventory_match'] is True, 'paired installation differs')
    original = load(evidence / 'installed-before.json')
    for name in ('installed-after.json', 'installed-after-continuation.json',
                 'installed-after-full-proof.json'):
        need(load(evidence / name) == original, 'original installation changed')
    need(load(evidence / 'historical-before.json') == load(evidence / 'historical-after.json'),
         'original historical fixture/runtime changed')
    for label in ('first', 'second'):
        receipt = load(evidence / 'install-current' / (label + '-build/receipt.json'))
        install = read(evidence / 'install-current' / (label + '-INSTALL.json'))
        runtime = read(evidence / 'install-current' / (label + '-RUNTIME.json'))
        need(receipt['status'] == 'INSTALLED_BUILD_SPECIFIC_BUNDLE' and
             receipt['source_manifest_sha256'] == source and
             receipt['install_manifest_sha256'] == pin(install)['sha256'],
             'build/source binding mismatch')
        for name, data in (('INSTALL.json',install),('RUNTIME.json',runtime)):
            need(pin(data) == {key:first[name][key] for key in ('bytes','sha256')},
                 'installed manifest identity mismatch')
    export = load(evidence / 'current-export/receipt.json')
    need(export['status'] == 'TESTED_CURRENT_PRODUCER_INDEPENDENT_READER' and
         export['source_byte_equal'] is True and export['metadata_byte_equal'] is True,
         'independent export recovery failed')
    return {'source_manifest_sha256':source, 'complete_inventory_match':True,
            'launcher':first['bin/semantic-transport'], 'native':first['bin/transport_native'],
            'export_manifest_sha256':export['export_manifest_sha256']}


def portable_checks(evidence):
    value = load(evidence / 'install-current/portable/receipt.json')
    need(value['status'] == 'TESTED_SCOPED' and value['failure'] is None and
         value['final_check_errors'] == [], 'portable inner failure')
    for key in ('bundles_unchanged', 'implementation_files_unchanged', 'original_fixture_files_unchanged'):
        flags = value[key]
        need(0 < len(flags) <= 128 and all(flag is True for flag in flags.values()),
             'portable input changed')
    names = ('attributed', 'controller', 'emotion', 'opaque', 'publication', 'recipe')
    need(tuple(value['handoffs']) == names, 'portable fixture scope mismatch')
    for name, handoff in value['handoffs'].items():
        need(handoff['declarations'] == 'MATCHED_RETAINED_FIXTURE_DECLARATIONS' and
             handoff['original_chat_supplied'] is False and
             handoff['original_source_files_supplied'] is False, 'portable declarations')
        recovery = handoff['recovery']
        need(0 < len(recovery) <= 16, 'portable recovery coverage')
        for row in recovery:
            need(row['byte_for_byte_equal'] is True and row['original'] == row['recovered'],
                 'portable recovery differs')
        typed = name not in ('opaque', 'recipe')
        focus = ('DECLARED_DEPENDENCIES_AND_SOURCE_EXCERPTS_MATCH' if typed
                 else 'REFUSED_NO_TYPED_MEANING_UNITS')
        need(handoff['focus'] == focus and bool(handoff['typed_structure']) == typed,
             'portable focus/structure scope')
        for row in handoff['typed_structure']:
            need(row['expected'] == row['received'] and
                 row['status'] == 'DECLARED_STRUCTURE_AND_LITERAL_VALUES_MATCH',
                 'portable typed structure differs')
    negatives = value['negative_controls']
    for name in ('changed-value', 'invalid-share', 'missing-archive',
                 'mismatched-runtime', 'swapped-archive'):
        need(negatives[name]['status'] == 'REFUSED_AS_REQUIRED', 'portable negative failed')
    return {'handoffs':list(names), 'status':'TESTED_SCOPED'}


def inventory(here):
    pending, result, total = [here], [], 0
    for unused in range(128):
        if not pending:
            break
        for path in sorted(pending.pop().iterdir()):
            need(not path.is_symlink(), 'evidence symlink')
            if path.is_dir():
                need(len(path.relative_to(here).parts) <= 6, 'evidence depth bound')
                pending.append(path)
            elif path.name != 'receipt.json' or path.parent != here:
                data = read(path)
                total += len(data)
                result.append(dict(path=path.relative_to(here).as_posix(), **pin(data)))
            need(len(result) <= 512 and len(pending) <= 128 and total <= 8388608,
                 'evidence inventory bound')
    need(not pending, 'evidence traversal bound')
    return sorted(result, key=lambda row:row['path'])


def expected(root=ROOT, here=HERE):
    evidence = here / 'evidence'
    contract = load(here / 'contract.json')
    source = source_checks(root, evidence)
    for stem in COMMANDS:
        process(evidence, stem)
    for stem in TIMEOUTS:
        process(evidence, stem, 'REFUSED_TIMEOUT', -9)
    proofs = proof_checks(evidence, contract)
    suites = suite_checks(evidence, contract)
    installation = install_checks(evidence)
    portable = portable_checks(evidence)
    return {'schema':'transport/engineering-closure-receipt/1', 'files':inventory(here),
        'proof_source_inventory':source, 'proofs':proofs, 'suites':suites,
        'installation':installation, 'portable':portable, 'retained_timeout_attempts':list(TIMEOUTS),
        'scope':'Rechecked retained command/test/proof observations, with current source identity.',
        'claims':{'native_components':'PROVED_WITH_DECLARED_PRECONDITIONS_AND_EXCLUSIONS',
          'installed_workflows':'TESTED_SCOPED', 'same_host_double_build':'OBSERVED_BYTE_IDENTICAL',
          'independent_standard_export_reader':'TESTED_SCOPED',
          'all_inherited_engineering_gates':'NOT_ESTABLISHED', 'whole_system_proof':'UNPROVEN',
          'semantic_completeness':'UNPROVEN', 'behavioral_advantage':'NOT_ESTABLISHED',
          'external_human_validation':'NOT_PERFORMED', 'product_acceptance':'NOT_ESTABLISHED'}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    data = (json.dumps(expected(), sort_keys=True, separators=(',',':')) + '\n').encode()
    need(len(data) <= 262144, 'derived receipt byte bound')
    path = HERE / 'receipt.json'
    if args.check:
        need(read(path) == data, 'closure receipt mismatch')
        print('PASS: source, proof coverage, installed results and retained failures match.')
    else:
        with path.open('xb') as stream:
            need(stream.write(data) == len(data), 'receipt short write')
        print('Created source-bound engineering receipt.')


if __name__ == '__main__':
    main()
