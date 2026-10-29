#!/usr/bin/env python3
"""Reproduce source/evidence identities; does not rerun or approve observations."""
import argparse
import ast
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE = ('README.md', 'transfer.py', 'test_transfer.py', 'oracle.json',
          'bridge.py', 'receipt.py')
WORKFLOW = '.github/workflows/conventional-transfer.yml'


def read(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('Expected regular receipt input')
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    if len(raw) > 1048576:
        raise ValueError('Receipt input bound exceeded')
    return raw


def pin(path):
    raw = read(path)
    return {'path':path.relative_to(ROOT).as_posix(), 'bytes':len(raw),
            'sha256':hashlib.sha256(raw).hexdigest()}


def prepare():
    paths = [HERE/name for name in SOURCE] + [ROOT/WORKFLOW]
    for path in paths:
        if path.suffix == '.py':
            tree = ast.parse(read(path))
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.end_lineno-node.lineno+1 > 60:
                        raise ValueError(str(path)+':'+node.name+': exceeds 60 lines')
    evidence = []
    for path in (HERE/'evidence').iterdir():
        if len(evidence) >= 128:
            raise ValueError('Evidence file count bound exceeded')
        evidence.append(pin(path))
    if not evidence:
        raise ValueError('Missing retained observations')
    return {'schema':'transport/conventional-transfer-receipt/1',
            'scope':'SOURCE_BOUND_RETAINED_OBSERVATIONS_NOT_ACCEPTANCE',
            'source':[pin(path) for path in paths],
            'observations':sorted(evidence,key=lambda row:row['path']),
            'limits':'Identities bind retained files, not authenticity, semantic '
                     'adequacy, human benefit, external validation or whole-system proof.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    raw = (json.dumps(prepare(),sort_keys=True,separators=(',',':'),
                      ensure_ascii=False,allow_nan=False)+'\n').encode('utf-8')
    path = HERE/'receipt.json'
    if args.check:
        if read(path) != raw:
            raise ValueError('Conventional transfer receipt does not reproduce')
        print('Conventional transfer source and observation receipt matches')
    else:
        with path.open('xb') as stream:
            if stream.write(raw) != len(raw):
                raise OSError('Incomplete receipt write')
        print('Created conventional transfer source and observation receipt')


if __name__ == '__main__':
    main()
