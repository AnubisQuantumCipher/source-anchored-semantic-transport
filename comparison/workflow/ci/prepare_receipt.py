#!/usr/bin/env python3
"""Check one CI inventory delta without rewriting the sealed parent receipt."""
import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import zipfile
import zlib

HERE = Path(__file__).absolute().parent
PARENT = HERE.parent
ROOT = PARENT.parents[1]
READER_SHA = 'fed2ceb65a2d55ba9f856b7bf92fc1c9157c64f44e5049e0dd0bd67d1e53d8dc'
RECEIPT_SHA = '139d903318428502b481880a3284ea7e7d7e55997fbb22b1e9716f8fbcd0dfd2'
WORKFLOW_SHA = '7a5d8a3db2e6cda61d3f6b812c89a832fae8c18676386fbc31ed3f6675b260d4'
CONTRACT_SHA = '65cedf7aec64371babfd26664985c1aef37fb476f9de06edb4a26e6f5d327a14'
KEY = 'ci/native-source-workflow.yml'
FILES = ('prepare_receipt.py', 'test_delta.py', 'contract.json', 'README.md',
         'parent-workflow.yml', 'failed-job.log')


def need(value, reason):
    if type(value) is not bool or not value:
        raise ValueError(reason)


def read(path, maximum=262144):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        item = os.fstat(descriptor)
        need(stat.S_ISREG(item.st_mode) and item.st_size <= maximum, 'CI evidence file bound/type')
        with os.fdopen(os.dup(descriptor), 'rb') as stream:
            raw = stream.read(maximum + 1)
        need(len(raw) == item.st_size, 'CI evidence read length')
        return raw
    finally:
        os.close(descriptor)


def pinned(path, digest):
    raw = read(path)
    need(hashlib.sha256(raw).hexdigest() == digest, 'CI parent or contract pin differs')
    return raw


def parent_reader():
    path = PARENT / 'prepare_receipt.py'
    raw = pinned(path, READER_SHA)
    specification = importlib.util.spec_from_file_location('_sealed_native_receipt', path)
    module = importlib.util.module_from_spec(specification)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def compare(parent, current, old_pin, new_pin):
    need(type(parent) is dict and type(current) is dict, 'CI receipt object')
    need(type(parent.get('files')) is dict and type(current.get('files')) is dict,
         'CI receipt file inventory')
    need(parent['files'].get(KEY) == old_pin and current['files'].get(KEY) == new_pin,
         'CI workflow pin differs')
    need(old_pin != new_pin, 'CI workflow delta absent')
    restored = copy.deepcopy(current)
    restored['files'][KEY] = old_pin
    options = dict(sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    need(json.dumps(restored, **options) == json.dumps(parent, **options),
         'CI delta changes more than the workflow pin')


def derived():
    reader = parent_reader()
    checked = reader.utility()
    parent_raw = pinned(PARENT / 'receipt.json', RECEIPT_SHA)
    contract_raw = pinned(HERE / 'contract.json', CONTRACT_SHA)
    old_raw = pinned(HERE / 'parent-workflow.yml', WORKFLOW_SHA)
    new_raw = read(ROOT / '.github/workflows/native-source-workflow.yml')
    current_raw = reader.derived(checked)
    compare(checked.json_value(parent_raw), checked.json_value(current_raw),
            checked.pin(old_raw), checked.pin(new_raw))
    files = {name: checked.pin(read(HERE / name)) for name in FILES}
    return checked.canonical({
        'schema': 'transport/native-workflow-ci-delta-receipt/1',
        'status': 'TESTED_DEVELOPMENT_NOT_ACCEPTED',
        'parent_commit': 'e0d3175a0292f1661a165ad149ee310799a3a143',
        'parent_reader': checked.pin(read(PARENT / 'prepare_receipt.py')),
        'parent_receipt': checked.pin(parent_raw), 'contract': checked.pin(contract_raw),
        'old_workflow': checked.pin(old_raw), 'new_workflow': checked.pin(new_raw),
        'current_parent_inventory': checked.pin(current_raw), 'files': files,
        'claims': 'Full sealed parent inventory equality except the declared CI workflow pin. '
                  'Retained failure is dependency setup, not product execution. '
                  'No semantic, benefit, proof or hosted-success claim is inferred.'})


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw = derived()
    if args.check:
        need(read(HERE / 'receipt.json') == raw, 'CI delta receipt does not reproduce')
    else:
        with (HERE / 'receipt.json').open('xb') as stream:
            need(stream.write(raw) == len(raw), 'short CI delta receipt write')
    print('CI delta matches; sealed parent inventory preserved except declared workflow pin')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile,
            zipfile.LargeZipFile, zlib.error, NotImplementedError, RecursionError) as error:
        print('REFUSED: ' + str(error), file=sys.stderr)
        sys.exit(1)
