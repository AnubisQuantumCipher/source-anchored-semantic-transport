#!/usr/bin/env python3
"""Derive this component receipt from retained bytes; --check never rewrites it."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FILES = ('tools/transport_quorum_graph.py', 'install/test_quorum_graph.py',
         'install/check_source.py', '.github/workflows/source.yml')
LOCAL = ('contract.json', 'oracle.json', 'oracle-addendum.json', 'review.json',
         'README.md', 'prepare_receipt.py', 'evidence/graph-first-results.json',
         'evidence/independent-test-results.json', 'evidence/code-review.json',
         'evidence/command-results-01.json', 'evidence/development-baseline.json')


def read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError('receipt input must be a regular file')
    with path.open('rb') as stream:
        value = stream.read(131073)
    if len(value) > 131072:
        raise ValueError('receipt input bound exceeded')
    return value


def receipt() -> bytes:
    paths = [ROOT / name for name in FILES] + [HERE / name for name in LOCAL]
    records = []
    for path in paths:
        raw = read(path)
        records.append(dict(path=str(path.relative_to(ROOT)), bytes=len(raw),
                            sha256=hashlib.sha256(raw).hexdigest()))
    first = json.loads(read(HERE / 'evidence/graph-first-results.json'))
    other = json.loads(read(HERE / 'evidence/independent-test-results.json'))
    source = hashlib.sha256(read(ROOT / FILES[0])).hexdigest()
    if first['source_sha256'] != source or other['source_sha256'] != source:
        raise ValueError('retained results do not cover current component')
    if not first['passed'] or not other['passed']:
        raise ValueError('retained component tests did not pass')
    if first['case_arm_outputs'] != other['case_arm_outputs']:
        raise ValueError('independent outputs differ')
    value = dict(schema='quorum/graph-component-receipt/1', status='TESTED',
                 files=sorted(records, key=lambda item: item['path']),
                 literal_case_ids=sorted({item['case'] for item in first['case_arm_outputs']}),
                 development_arm_outputs=len(first['case_arm_outputs']),
                 formal_proof='UNPROVEN', full_replay='UNRUN',
                 installed_decoder='UNCHANGED_NOT_INTEGRATED',
                 external_validation='EXTERNAL_VALIDATION_PENDING',
                 product_acceptance=False, benefit='NOT_MEASURED')
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    data = receipt()
    target = HERE / 'receipt.json'
    if args.check:
        if read(target) != data:
            raise ValueError('receipt differs from retained inputs')
    else:
        with target.open('xb') as stream:
            if stream.write(data) != len(data):
                raise OSError('short receipt write')
    print('COMPONENT_RECEIPT_CHECKED' if args.check else 'COMPONENT_RECEIPT_WRITTEN')


if __name__ == '__main__':
    main()
