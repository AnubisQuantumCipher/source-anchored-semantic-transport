#!/usr/bin/env python3
"""Derive a source-bound public checkpoint from retained owner evidence.

No private attachment, book, meaning ZIP, executable or model output is copied.
--check verifies the derived source/artifact pins without executing an artifact.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ('tools/build_sentinel_policy.py', 'tools/transport_document_context.py',
    'tools/transport_sentinel.py', 'tools/transport_sentinel_export.py',
    'tools/transport_sentinel_package.py', 'sentinel_native/sentinel_policy.ads',
    'sentinel_native/sentinel_policy.adb', 'sentinel_native/sentinel_policy.gpr',
    'sentinel_native/sentinel_policy_proof.gpr', 'sentinel_native/sentinel_policy_checks.adb',
    'sentinel_native/sentinel_policy_fixtures.ads', 'sentinel_native/sentinel_policy_fixtures.adb',
    'sentinel_native/sentinel_build_profile.py', 'sentinel_native/sentinel_qualification.py',
    'tests/test_sentinel_qualification.py', 'tests/test_transport_document_context.py',
    'tests/test_transport_sentinel.py', 'tests/test_transport_sentinel_package.py',
    'tests/check_sentinel_profile.py', 'docs/SENTINEL.md', '.github/workflows/document-profile.yml',
    'examples/sentinel-exact-v1/create_fixture.py', 'examples/sentinel-exact-v1/freeze_receipt.py',
    'tests/test_sentinel_checkpoint.py')
ARTIFACTS = ('build-runs/attempt01/receipt.json', 'build-runs/attempt01/namespace-result.json',
    'build-runs/attempt02/receipt.json', 'build-runs/attempt02/namespace-result.json',
    'build-runs/attempt03/receipt.json', 'build-runs/attempt03/namespace-result.json',
    'build-runs/attempt04/receipt.json', 'build-runs/attempt04/namespace-result.json',
    'build-runs/attempt04-admission.json', 'build-input-04.json',
    'build-oracle/policy-source05-roster.json', 'build-oracle/policy-source05-roster-review.json',
    'build-oracle/roster-omission-correction-01.json',
    'build-oracle/machine-independent-review-01/review.json',
    'build-oracle/machine-diagnostics-01/CONTRACT.md', 'build-oracle/machine-diagnostics-01/STATUS.md',
    'build-oracle/mixed-annotations-01/concurrency-failure.json',
    'native-proof-readback-01/readback.json', 'native-proof-readback-source05/readback.json',
    'native-proof-readback-source05/roster-provenance-supplement.json',
    'foundation-publication-review-01/source05-retained-evidence-readback.json',
    'graph-build-01/valid-append-first-counterexample.json',
    'graph-build-01/spurious-label-self-review-counterexample.json',
    'graph-independent-review-01/registry-interleaving-counterexample-01.json',
    'graph-independent-review-01/source03-review-01.json',
    'graph-independent-review-01/source04-review-02.json',
    'context-review/review.json', 'package-independent-review-01/controls.json',
    'package-independent-review-02/review.json', 'package-build-01/failed-source01/receipt.json',
    'package-build-01/tests-normal-01.stderr', 'cli-integration-01/receipt.json',
    'cli-integration-01/package/report.json', 'package-oracle-01/CONTRACT.md',
    'foundation-tests-mission-01/receipt.json',
    'foundation-publication-review-01/generator-boundary-first/counterexample.json',
    'checkpoint-controls-independent-readback-01/review.json')


def read(path, cap=1_048_576):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 <= before.st_size <= cap:
            raise ValueError('checkpoint regular file or input byte bound')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(cap + 1)
        after = os.fstat(fd)
        keys = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key) for key in keys):
            raise ValueError('checkpoint file changed or truncated')
        return raw
    finally:
        os.close(fd)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def source_pins():
    return {name: pin(read(ROOT / name, 131072)) for name in SOURCES}


def selected_artifacts(base):
    result = {name: read(base / name) for name in ARTIFACTS}
    for attempt in ('attempt01', 'attempt02', 'attempt03', 'attempt04'):
        folder = base / 'build-runs' / attempt / 'capture'
        inventory = json.loads(read(folder / 'inventory.json'))
        wanted = {'proof.stderr', 'proof/gnatprove/gnatprove.out', 'checks.stdout', 'checks.stderr'}
        if attempt == 'attempt04':
            wanted.add('proof/gnatprove/sentinel_policy.spark')
        rows = [row for row in inventory['entries'] if row.get('path') in wanted]
        if len(rows) != len(wanted) or {row['path'] for row in rows} != wanted:
            raise ValueError('missing captured raw proof artifact')
        for row in rows:
            if row.get('kind') != 'regular' or type(row.get('payload')) is not str:
                raise ValueError('capture payload must be a regular file')
            if re.fullmatch(r'payload-[0-9]{4}\.bin', row['payload']) is None:
                raise ValueError('capture payload basename refused')
            if type(row.get('bytes')) is not int or not 0 <= row['bytes'] <= 1048576:
                raise ValueError('capture declared size bound')
            raw = read(folder / row['payload'])
            if pin(raw) != {'bytes': row['bytes'], 'sha256': row['sha256']}:
                raise ValueError('captured payload identity mismatch')
            result['raw/' + attempt + '/' + row['path']] = raw
    if len(result) > 64 or sum(len(raw) for raw in result.values()) > 524288:
        raise ValueError('checkpoint artifact retention bound')
    return result


def receipt(base, artifacts):
    terminal = json.loads(artifacts['build-runs/attempt04/namespace-result.json'])
    worker = terminal['worker']
    machine = worker['machine_diagnostics']
    if terminal['status'] != 'SENTINEL_POLICY_BUILD_TEST_PROOF_CHECKED' or terminal['failures']:
        raise ValueError('native policy not qualified')
    if not terminal['capture']['complete'] or not terminal['readonly_qualified']:
        raise ValueError('incomplete native evidence capture')
    if machine['warn_error_records'] != 0 or worker['proof']['unproved'] != 0:
        raise ValueError('unclean native report')
    launch = json.loads(read(base / 'build-runs/attempt04/launch.json', 8388608))
    held = pin(artifacts['build-oracle/policy-source05-roster.json'])
    if launch['runtime_pins']['caller-held-proof-roster']['sha256'] != held['sha256']:
        raise ValueError('actual dispatched roster mismatch')
    current = source_pins()
    for name, expected in launch['proof_roster']['sources'].items():
        if current[name]['sha256'] != expected:
            raise ValueError('current proof source drift')
    private = read(base / 'source-package-01/recovered-original.txt', 65536)
    return {'schema': 'sentinel/source-checkpoint/1', 'status': 'DEVELOPMENT_CHECKPOINT',
        'source': current, 'artifacts': {name: pin(raw) for name, raw in artifacts.items()},
        'native_proof': worker['proof'], 'machine_diagnostics': machine,
        'native_scope': worker['scope'], 'native_driver_sha256': worker['checks_binary_sha256'],
        'actual_dispatched_roster': held, 'private_attachment_recovered': pin(private),
        'private_payload_publication': 'NOT_PUBLISHED', 'python_tests': {
            'context_normal_and_optimized': 14, 'graph_normal_and_optimized': 25,
            'container_normal_and_optimized': 17, 'builder_normal_and_optimized': 23,
            'checkpoint_normal_and_optimized': 4},
        'cli': json.loads(artifacts['cli-integration-01/receipt.json']),
        'semantic_completeness': 'UNPROVEN', 'world_truth': 'NOT_CERTIFIED',
        'fresh_Sentinel_agent': 'NOT_PERFORMED', 'comparative_benefit': 'NOT_PERFORMED',
        'external_human_validation': 'NOT_PERFORMED', 'execution_authority': 'NONE',
        'native_parser_and_live_bridge': 'NOT_SUPPLIED_BY_THIS_CHECKPOINT',
        'model_tokens_and_cost': 'NOT_MEASURED', 'source_setup_bytes': sum(v['bytes'] for v in current.values())}


def check(out):
    value = json.loads(read(out / 'receipt.json'))
    if value['source'] != source_pins():
        raise ValueError('checkpoint source no longer matches')
    allowed = set(ARTIFACTS)
    for attempt in ('attempt01', 'attempt02', 'attempt03', 'attempt04'):
        for name in ('proof.stderr', 'proof/gnatprove/gnatprove.out', 'checks.stdout', 'checks.stderr'):
            allowed.add('raw/' + attempt + '/' + name)
    allowed.add('raw/attempt04/proof/gnatprove/sentinel_policy.spark')
    if type(value['artifacts']) is not dict or set(value['artifacts']) != allowed:
        raise ValueError('unknown or missing checkpoint artifact')
    for name, expected in value['artifacts'].items():
        if type(expected) is not dict or set(expected) != {'bytes', 'sha256'}:
            raise ValueError('checkpoint pin fields')
        if type(expected['bytes']) is not int or not 0 <= expected['bytes'] <= 1048576:
            raise ValueError('checkpoint pin byte type or bound')
        if pin(read(out / 'artifacts' / name)) != expected:
            raise ValueError('checkpoint artifact mismatch')
    print('CHECKED: source and retained artifact bytes; no new proof or semantic evaluation')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root', type=Path)
    parser.add_argument('--out', type=Path, default=Path(__file__).resolve().parent / 'evidence')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.check:
        check(args.out)
        return
    if args.evidence_root is None:
        raise ValueError('evidence root required for initial derivation')
    artifacts = selected_artifacts(args.evidence_root)
    value = receipt(args.evidence_root, artifacts)
    args.out.mkdir(mode=0o700)
    for name, raw in artifacts.items():
        path = args.out / 'artifacts' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open('xb') as stream:
            stream.write(raw)
    with (args.out / 'receipt.json').open('x') as stream:
        json.dump(value, stream, sort_keys=True, indent=2); stream.write('\n')
    check(args.out)


if __name__ == '__main__':
    main()
