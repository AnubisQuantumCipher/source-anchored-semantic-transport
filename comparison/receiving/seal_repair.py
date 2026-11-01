"""Freeze/check source-bound prelaunch evidence; never authorize or dispatch a model."""
import argparse
import base64
import json
import os
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import stage_repair as staging
import stage_repair_support as safe

SOURCE_NAMES = ('stage_repair.py', 'stage_repair_support.py', 'private_staging.py',
                'test_stage_repair.py', 'seal_repair.py', 'repair-verification-contract-02.json',
                'repair-staging-oracle-02.json', 'capture_trace.py', 'trace_support.py',
                'check_answer.py', 'test_capture.py', 'test_check_answer.py',
                'trace-oracle.json', 'trace-lifecycle-integer-oracle.json')


def sources(root):
    result = []
    for name in SOURCE_NAMES:
        path = Path(__file__).resolve().parent / name
        raw = safe.read(path)
        result.append({'path': str(path), 'bytes': len(raw), 'sha256': safe.digest(raw)})
    return result


def recovered(root, oracle):
    folder = root / 'preflight/native-02/source-workspace/sources'
    rows = []
    safe.need(type(oracle['sources']) is list and len(oracle['sources']) <= 32, 'SOURCE_BOUND')
    seen = set()
    for item in oracle['sources']:
        name = item['id']
        safe.need(type(name) is str and name.isascii() and name.replace('_', '').isalnum()
                  and name not in seen and len(name) <= 32, 'SOURCE_ID')
        seen.add(name)
        original = base64.b64decode(item['raw_base64'], validate=True)
        raw = safe.read(folder / (name + '.bin'))
        safe.need(raw == original and safe.digest(raw) == item['sha256'], 'EXACT_RECOVERY')
        rows.append({'id': name, 'bytes': len(raw), 'sha256': safe.digest(raw),
                     'byte_comparison': 'IDENTICAL'})
    return rows


def native_result(root):
    result = safe.load(safe.read(root / 'preflight/native-02/run.json'))
    safe.need(result['status'] == 'SUCCESS' and type(result['exit_code']) is int
              and result['exit_code'] == 0, 'NATIVE_PREFLIGHT')
    for name in ('stdout', 'stderr'):
        raw = safe.read(root / ('preflight/native-02/' + name), 8192)
        safe.need(safe.digest(raw) == result[name + '_sha256'], 'NATIVE_CAPTURE_PIN')
    output = safe.load(safe.read(root / 'preflight/native-02/stdout', 8192))
    safe.need(output['status'] == 'PREPARED_VERIFIED_NATIVE_FILES' and output['authority'] == 'NONE', 'NATIVE_STATUS')
    failure = safe.load(safe.read(root / 'preflight/native.stdout', 8192))
    safe.need(failure['status'] == 'REFUSED' and failure['reason'] == 'WORKFLOW_VALIDATION_OR_IO',
              'RETAINED_PROFILE_FAILURE')
    profile = safe.load(safe.read(root / 'preflight/native-02/profile.json'))
    safe.need(profile['limits_raised'] is False and profile['profile_status'] ==
              'ORIGINAL_QUALIFIED_BOUND', 'NATIVE_PROFILE')
    return {'status': 'PASS', 'initial_lower_profile': 'RETAINED_REFUSAL',
            'native_profile': profile, 'result': result}


def inventory(root):
    queue, result, total = [root], [], 0
    for unused in range(128):
        if not queue:
            return sorted(result, key=lambda item: item['path'])
        directory = queue.pop(0)
        with os.scandir(directory) as entries:
            for count, entry in enumerate(entries):
                safe.need(count < 128 and len(queue) + len(result) < 256, 'ENTRY_BOUND')
                path = Path(entry.path)
                if path == root / 'preflight/prelaunch-seal.json':
                    continue
                meta = entry.stat(follow_symlinks=False)
                safe.need(meta.st_uid == os.geteuid(), 'ENTRY_OWNER')
                relative = str(path.relative_to(root))
                mode = stat.S_IMODE(meta.st_mode)
                if stat.S_ISDIR(meta.st_mode):
                    safe.need(mode in (0o700, 0o500), 'DIRECTORY_MODE')
                    queue.append(path)
                    result.append({'path': relative, 'type': 'directory', 'mode': format(mode, '04o')})
                else:
                    safe.need(stat.S_ISREG(meta.st_mode) and mode in (0o600, 0o400), 'FILE_TYPE_MODE')
                    raw = safe.read(path)
                    total += len(raw)
                    safe.need(total <= safe.RUN_CAP, 'RUN_BOUND')
                    result.append({'path': relative, 'type': 'file', 'mode': format(mode, '04o'),
                                   'bytes': len(raw), 'sha256': safe.digest(raw)})
    raise ValueError('DIRECTORY_BOUND')


def controls(root):
    held = safe.load(safe.read(root / 'preflight/staging-controls.json'))
    safe.need(type(held['runs']) is list and len(held['runs']) == 2, 'CONTROL_RUNS')
    for item in held['runs']:
        run = json.loads(safe.checked(item['record']), object_pairs_hook=safe.pairs,
                         parse_constant=safe.invalid_number)
        safe.need(type(run['exit_code']) is int and run['exit_code'] == 0, 'CONTROL_FAILURE')
        safe.checked(item['stdout'])
        stderr = safe.checked(item['stderr']).decode('utf-8')
        safe.need('Ran 16 tests in ' in stderr and stderr.endswith('\nOK\n'), 'CONTROL_RESULT')
        for name, pin in run['source_pins'].items():
            safe.need(name in SOURCE_NAMES and safe.digest(safe.read(
                Path(__file__).resolve().parent / name)) == pin, 'CONTROL_SOURCE_PIN')
        safe.need(set(run['source_pins']) == {'private_staging.py', 'stage_repair.py',
                  'stage_repair_support.py', 'test_stage_repair.py'}, 'CONTROL_SOURCE_SET')
    return held


def qualifications(root):
    held = safe.load(safe.read(root / 'preflight/qualified-controls.json'))
    safe.need(type(held['runs']) is list and len(held['runs']) == 4, 'QUALIFICATION_RUNS')
    for item in held['runs']:
        receipt = safe.load(safe.checked(item['receipt']))
        safe.need(receipt['status'] == 'PASS' and receipt['failed_cases'] == []
                  and receipt.get('unperformed', []) == [], 'QUALIFICATION_FAILURE')
        exit_record = safe.load(safe.checked(item['exit']))
        safe.need(type(exit_record['exit_code']) is int and exit_record['exit_code'] == 0,
                  'QUALIFICATION_EXIT')
        for name, pin in receipt['code_pins'].items():
            path = Path(name) if name.startswith('/') else Path(__file__).resolve().parent / name
            safe.checked(dict(pin, path=str(path)))
        rows = safe.load(safe.checked(item['results']))
        count = 182 if receipt['schema'] == 'transport/receiving-capture-controls/1' else 67
        safe.need(type(rows) is list and len(rows) == count and
                  all(row['passed'] is True for row in rows), 'QUALIFICATION_ROWS')
        if count == 182:
            safe.need(type(receipt['controls']) is int and receipt['controls'] == count,
                      'CAPTURE_CONTROLS')
        else:
            safe.need(type(receipt['api_cases']) is int and receipt['api_cases'] == count
                      and type(receipt['cli_cases']) is int and receipt['cli_cases'] == 11
                      and len(item['cli']) == 11, 'CHECKER_CONTROLS')
            for command in item['cli']:
                observed = safe.load(safe.checked(command['result']))
                safe.need(observed['passed'] is True, 'CLI_CONTROL_FAILURE')
                for stream in ('stdout', 'stderr'):
                    raw = safe.checked(command[stream])
                    safe.need(observed[stream + '_pin'] ==
                              {'bytes': len(raw), 'sha256': safe.digest(raw)}, 'CLI_STREAM_PIN')
    return held


def expected(root, config_pin):
    descriptor = safe.anchor_descriptor(root)
    os.close(descriptor)
    config, data, unused = staging.configuration(root / 'preflight/config.json', config_pin)
    manifest = staging.sealed_inputs(config, data)
    staging.declared_dependencies(config, manifest)
    staged = safe.load(safe.read(root / 'preflight/staged-inputs.json'))
    for item in staged['files']:
        safe.checked(dict(item, path=str(root / item['path'])))
    safe.need(not (root / 'receivers/transport/answer.json').exists() and
              not (root / 'receivers/transport/source-workspace').exists(), 'RECEIVER_ALREADY_USED')
    current = safe.load(safe.read(root / 'receivers/transport/input/manifest.json'))
    manifest['content']['root'] = current['content']['root']
    safe.need(current == manifest, 'ONLY_CONTENT_ROOT_RELOCATED')
    source_rows = recovered(root, safe.load(data['oracle']))
    checks = controls(root)
    return {'schema': 'transport/public-repair-prelaunch-seal/2', 'root': str(root),
            'status': 'READY_FOR_INDEPENDENT_REVIEW', 'authority': 'NONE', 'model_calls': 0,
            'config_sha256': config_pin, 'source_files': sources(root),
            'first_trial': 'RETAINED_FAILED_UNCHANGED_PINS', 'exact_recovery': source_rows,
            'native_preflight': native_result(root), 'staging_controls': checks,
            'capture_and_evaluator_qualification': qualifications(root),
            'files': inventory(root), 'independent_review': 'REQUIRED',
            'acceptance': 'PUBLIC_REPAIR_ONLY_NOT_COMPARATIVE_BENEFIT'}


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--expect-config-sha256', required=True)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = expected(args.root, args.expect_config_sha256)
    raw = safe.raw_json(result)
    if args.check:
        safe.need(safe.read(args.root / 'preflight/prelaunch-seal.json') == raw, 'SEAL_MISMATCH')
    else:
        safe.save(args.root, 'preflight/prelaunch-seal.json', raw, [])
    print(safe.raw_json({'status': 'PASS', 'seal_sha256': safe.digest(raw),
                         'source_entries': len(result['exact_recovery']), 'model_calls': 0}).decode())


if __name__ == '__main__':
    main()
