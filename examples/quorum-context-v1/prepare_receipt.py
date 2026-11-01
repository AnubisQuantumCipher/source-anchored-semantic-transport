#!/usr/bin/env python3
"""Derive component evidence from retained files; never replace a receipt."""

import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ('tools/transport_quorum_context.py', 'tools/transport_quorum_impact.py',
          'tools/transport_quorum_graph.py',
          'tools/transport_quorum_claim.py', 'tools/transport_quorum_source.py',
          'tools/transport_quorum_input.py', 'tools/transport_quorum_shape.py',
          'tools/transport_quorum_body.schema.json', 'tools/transport_schema.py',
          'tools/transport_wire.py', 'install/test_quorum_context.py',
          'install/check_source.py', '.github/workflows/source.yml')
RESULTS = ('evidence/reading-integration-root-results.json',
           'evidence/reading-integration-independent-results.json')


def read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError('receipt input must be a regular file')
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    if len(raw) > 1048576:
        raise ValueError('receipt input byte bound exceeded')
    return raw


def records() -> list:
    paths = [ROOT / name for name in SOURCE]
    for path in HERE.rglob('*'):
        if path.is_file() and path.name != 'receipt.json':
            if len(paths) >= 512:
                raise ValueError('receipt input count exceeded')
            paths.append(path)
    result, total = [], 0
    for path in sorted(paths):
        raw = read(path)
        total += len(raw)
        if total > 8388608:
            raise ValueError('receipt total byte bound exceeded')
        result.append(dict(path=str(path.relative_to(ROOT)), bytes=len(raw),
                           sha256=hashlib.sha256(raw).hexdigest()))
    return result


def derived() -> bytes:
    first, other = (json.loads(read(HERE / name)) for name in RESULTS)
    required = set(SOURCE[:11])
    for result in (first, other):
        if not result['passed'] or set(result['source_pins']) != required:
            raise ValueError('retained tests missing required coverage')
        for name, digest in result['source_pins'].items():
            if hashlib.sha256(read(ROOT / name)).hexdigest() != digest:
                raise ValueError('tests do not cover current component')
    if first['outputs'] != other['outputs']:
        raise ValueError('independent observed outputs differ')
    value = dict(schema='quorum/context-component-receipt/1', status='TESTED',
        files=records(), observed_test_methods=first['test_methods'],
        observed_output_records=len(first['outputs']), full_replay='UNRUN',
        installed_decoder='UNCHANGED_NOT_INTEGRATED', formal_proof='UNPROVEN',
        external_validation='EXTERNAL_VALIDATION_PENDING', product_acceptance=False,
        benefit='NOT_MEASURED; identical checker and annotation development parity only')
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode('utf-8')


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw = derived()
    target = HERE / 'receipt.json'
    if args.check:
        if read(target) != raw:
            raise ValueError('receipt differs from retained inputs')
    else:
        with target.open('xb') as stream:
            if stream.write(raw) != len(raw):
                raise OSError('short receipt write')
    print('CONTEXT_RECEIPT_CHECKED' if args.check else 'CONTEXT_RECEIPT_WRITTEN')


if __name__ == '__main__':
    main()
