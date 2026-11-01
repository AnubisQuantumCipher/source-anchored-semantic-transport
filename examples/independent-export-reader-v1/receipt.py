#!/usr/bin/env python3
"""Bind exact consumer, controls and retained evidence; no semantic certification."""
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCE_NAMES = ('install/read_transport_export.py', 'install/test_export_reader.py',
                'install/export_reader_test_fixtures.py', 'docs/EXPORT_READER.md',
                '.github/workflows/export-reader.yml')
OMIT = {'receipt.json'}


def need(value, message):
    if not value:
        raise ValueError(message)


def pin(path):
    need(path.is_file() and not path.is_symlink(), 'regular receipt input required')
    with path.open('rb') as stream:
        raw = stream.read(1048577)
    need(len(raw) <= 1048576, 'receipt input byte limit')
    return {'path':path.relative_to(ROOT).as_posix(),'bytes':len(raw),
            'sha256':hashlib.sha256(raw).hexdigest()}


def inventory():
    selected = [ROOT / name for name in SOURCE_NAMES]
    pending = [HERE]
    for unused in range(128):
        if not pending:
            break
        for path in sorted(pending.pop().iterdir()):
            need(not path.is_symlink(), 'receipt symlink')
            if path.is_dir():
                need(len(path.relative_to(HERE).parts) <= 5, 'receipt directory depth')
                pending.append(path)
            elif path.relative_to(HERE).as_posix() not in OMIT:
                selected.append(path)
            need(len(selected) <= 512 and len(pending) <= 128, 'receipt inventory bound')
    need(not pending, 'receipt traversal bound')
    return [pin(path) for path in sorted(selected)]


def expected():
    result_path = HERE / 'evidence/owner-checks.json'
    with result_path.open('rb') as stream:
        raw = stream.read(131073)
    need(len(raw) <= 131072, 'owner receipt bound')
    observations = json.loads(raw)
    need(observations['status'] == 'PASS_FOR_FROZEN_DEVELOPMENT_CONTROLS', 'owner observations incomplete')
    return {'schema':'transport/independent-export-reader-receipt/1','files':inventory(),
        'observations':observations,'scope':'Standalone standard-export reader and frozen development comparisons.',
        'claims':{'exact_selected_export_recovery':'TESTED','whole_system_proof':'UNPROVEN',
          'semantic_fidelity':'NOT_ASSESSED','source_authentication':'NOT_PROVIDED',
          'external_human_validation':'NOT_PERFORMED','behavioral_advantage':'NOT_ESTABLISHED',
          'product_acceptance':'NOT_ESTABLISHED'}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args = parser.parse_args()
    raw = (json.dumps(expected(),sort_keys=True,separators=(',',':')) + '\n').encode()
    need(len(raw) <= 131072, 'receipt byte limit')
    path = HERE / 'receipt.json'
    if args.check:
        need(path.read_bytes() == raw, 'reader receipt mismatch')
        print('PASS: independent reader source and retained observations match receipt.')
    else:
        with path.open('xb') as stream:
            need(stream.write(raw) == len(raw), 'receipt short write')
        print('Created independent reader source-bound receipt.')


if __name__ == '__main__':
    main()
