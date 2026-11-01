#!/usr/bin/env python3
"""Derive a source-bound inventory from retained observations; do not rerun them."""

import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
LIMIT = 33554432


def read(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Receipt input must be a regular file')
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    if len(raw) > 1048576:
        raise ValueError('Receipt input byte bound')
    return raw


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def relative(root, name):
    path = Path(name)
    if path.is_absolute() or not path.parts or any(p in ('.', '..') for p in path.parts):
        raise ValueError('Receipt relative path')
    target = root / path
    for parent in (target, *target.parents):
        if parent == root:
            return target
        if parent.is_symlink():
            raise ValueError('Receipt symlink')
    raise ValueError('Receipt path escaped root')


def evidence():
    root = HERE / 'evidence'
    inventory = json.loads(read(root / 'inventory.json'))
    items, found, by_path = inventory['items'], {}, {}
    aliases = inventory.get('aliases', [])
    if len(items) > 1024 or len(aliases) > 4096:
        raise ValueError('Evidence count bound')
    for row in items:
        raw = read(relative(root, row['path']))
        if pin(raw) != dict(bytes=row['bytes'], sha256=row['sha256']):
            raise ValueError('Retained evidence changed')
        if row['source_path'] in found:
            raise ValueError('Duplicate original evidence path')
        found[row['source_path']] = raw
        if row['path'] in by_path:
            raise ValueError('Duplicate retained evidence path')
        by_path[row['path']] = raw
    for row in aliases:
        if set(row) != {'source_path', 'path'} or row['source_path'] in found:
            raise ValueError('Conflicting evidence alias')
        found[row['source_path']] = by_path[row['path']]
    return found


def document(found, suffix):
    matches = [raw for name, raw in found.items() if name.endswith(suffix)]
    if len(matches) != 1:
        raise ValueError('Missing or ambiguous retained evidence: ' + suffix)
    return json.loads(matches[0])


def verify_source(found):
    frozen = document(found, '/source-freeze-03.json')['sourcepins_verified_before_run']
    for name, expected in frozen.items():
        if pin(read(relative(ROOT, name))) != dict(bytes=expected['bytes'], sha256=expected['sha256']):
            raise ValueError('Current source differs from qualified source')
    public = document(found, '/public-reproducer-01/final-freeze.json')['installed_preparer']
    if pin(read(ROOT / 'install/prepare_quorum_replay.py')) != dict(bytes=public['bytes'], sha256=public['sha256']):
        raise ValueError('Current preparer differs from tested source')
    return tuple(sorted(frozen))


def verify_tests(found):
    first = document(found, '/portable-core-tests-03/normal.json')
    optimized = document(found, '/portable-core-tests-03/optimized.json')
    other = document(found, '/code-review-01/final-core-normal-results.json')
    for result in (first, optimized, other):
        if result['passed'] is not True or result['outputs'] != first['outputs']:
            raise ValueError('Retained complete core observations differ')
        for name, expected in result['source_pins'].items():
            if pin(read(relative(ROOT, name))) != expected:
                raise ValueError('Core observations do not cover current source')
    review = document(found, '/code-review-01/final-independent-full-replay-review.json')
    for row in review['product_pins']:
        path = Path(row['path'])
        name = path.parent.name + '/' + path.name
        if pin(read(relative(ROOT, name))) != dict(bytes=row['bytes'], sha256=row['sha256']):
            raise ValueError('Independent review covers different source')
    return len(first['outputs'])


def retained(found, row):
    raw = found[row['path']]
    if pin(raw) != dict(bytes=row['bytes'], sha256=row['sha256']):
        raise ValueError('Referenced evidence pin differs')
    return raw


def verify_run(found, report):
    if report['failures'] or report['unrun']:
        raise ValueError('Qualified run contains failures or unrun cases')
    manifest = json.loads(retained(found, report['manifest']))
    expected = {row['id']: row for row in manifest['cases']}
    observed = {row['id']: row for row in report['cases']}
    if (len(expected) != len(manifest['cases']) or len(observed) != len(report['cases'])
            or set(expected) != set(observed)):
        raise ValueError('Run case set differs')
    for name, actual in observed.items():
        target = expected[name]
        if actual['execution']['exit_code'] != target['expected_exit_code']:
            raise ValueError('Observed exit differs')
        for stream in ('stdout', 'stderr'):
            if retained(found, actual['first_' + stream]) != retained(found, target['expected_' + stream]):
                raise ValueError('Complete observed stream differs')
        if actual['inputs_unchanged'] is not True or actual['file_metadata_unchanged'] is not True:
            raise ValueError('Observed inputs changed')
        absent_count = len(target.get('absent_paths', []))
        if (len(actual['absent_before']) != absent_count or
                len(actual['absent_after']) != absent_count or
                not all(actual['absent_before']) or not all(actual['absent_after'])):
            raise ValueError('Required absent sidecar was present')
    return len(observed)


def verify_cli(found):
    review = document(found, '/code-review-01/final-independent-full-replay-review.json')
    counts = []
    for run in review['runs']:
        if run['group'] != 'pure_core_synthetic_host':
            report = json.loads(retained(found, run['report']))
            count = verify_run(found, report)
            if count != run['cases']:
                raise ValueError('Independent case count differs')
            counts.append(dict(group=run['group'], lane=run['lane'], cases=count))
    public = document(found, '/public-reproducer-01/bootstrap-two-first-runs/first-run.json')
    return counts, verify_run(found, public)


def files(source):
    paths = {ROOT / name for name in source}
    paths.update(ROOT / name for name in ('install/prepare_quorum_replay.py',
        'install/test_quorum_replay.py', '.github/workflows/quorum-replay.yml', 'README.md'))
    pending = [HERE]
    for unused in range(2048):
        if not pending:
            break
        directory = pending.pop()
        for path in directory.iterdir():
            if path.is_symlink():
                raise ValueError('Receipt tree symlink')
            if path.is_dir():
                pending.append(path)
            elif path.is_file() and path != HERE / 'receipt.json':
                paths.add(path)
            else:
                if path != HERE / 'receipt.json':
                    raise ValueError('Unsupported receipt entry')
            if len(pending) + len(paths) > 2048:
                raise ValueError('Receipt tree count bound')
    if pending:
        raise ValueError('Receipt directory work bound')
    result, total = [], 0
    for path in sorted(paths):
        raw = read(path)
        total += len(raw)
        if total > LIMIT:
            raise ValueError('Receipt aggregate byte bound')
        result.append(dict(path=str(path.relative_to(ROOT)), **pin(raw)))
    return result


def derived():
    retained = evidence()
    source = verify_source(retained)
    outputs = verify_tests(retained)
    runs, public = verify_cli(retained)
    value = dict(schema='quorum/full-replay-checkpoint-receipt/1', status='TESTED',
        files=files(source), portable_core_output_records=outputs,
        independent_run_groups=runs, public_recipient_runs=public,
        scope='Frozen development replay, qualified local CLI and separately labeled probes',
        external_validation='EXTERNAL_VALIDATION_PENDING', formal_proof='UNPROVEN',
        semantic_completeness='UNPROVEN', current_authority='NONE',
        benefit='NOT_MEASURED; matched annotations and checker demonstrate finite parity',
        product_acceptance=False)
    raw = (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')
    if len(raw) > 1048576:
        raise ValueError('Receipt output bound')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw, target = derived(), HERE / 'receipt.json'
    if args.check:
        if read(target) != raw:
            raise ValueError('Receipt differs from retained inputs')
    else:
        with target.open('xb') as stream:
            if stream.write(raw) != len(raw):
                raise OSError('Short receipt write')
    print('REPLAY_RECEIPT_CHECKED' if args.check else 'REPLAY_RECEIPT_WRITTEN')


if __name__ == '__main__':
    main()
