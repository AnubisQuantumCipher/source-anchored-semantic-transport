#!/usr/bin/env python3
"""Reuse the sealed CI delta checker for the corrected harness invocation."""
import argparse
import hashlib
import importlib.util
import os
from pathlib import Path
import stat
import sys
import zipfile
import zlib

HERE = Path(__file__).absolute().parent
PREVIOUS = HERE.parent / 'ci'
READER_SHA = '63a1c21ef1241b1419fb4711b312d39fc8c9c3cb68c91f6cfa8d6192f1d6914c'
RECEIPT_SHA = '0f9be203f4adb7c94cdb93bcd25cf8faba07fecc0b778d10fb5084c01cbf60aa'
CONTRACT_SHA = 'e4f9064dfc91c57247c636b9f9a4905cd4c2b25d930cf3e89b0b6a1bccc7a523'


def previous_reader():
    path = PREVIOUS / 'prepare_receipt.py'
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        item = os.fstat(descriptor)
        if not stat.S_ISREG(item.st_mode) or item.st_size > 65536:
            raise ValueError('sealed CI reader type or size')
        with os.fdopen(os.dup(descriptor), 'rb') as stream:
            raw = stream.read(65537)
        if len(raw) != item.st_size:
            raise ValueError('sealed CI reader read length')
    finally:
        os.close(descriptor)
    if hashlib.sha256(raw).hexdigest() != READER_SHA:
        raise ValueError('sealed CI delta reader differs')
    specification = importlib.util.spec_from_file_location('_sealed_ci_delta', path)
    module = importlib.util.module_from_spec(specification)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def derived():
    previous = previous_reader()
    reader = previous.parent_reader()
    checked = reader.utility()
    held = previous.pinned(PREVIOUS / 'receipt.json', RECEIPT_SHA)
    previous.pinned(HERE / 'contract.json', CONTRACT_SHA)
    current = previous.derived()
    files = {name: checked.pin(previous.read(HERE / name))
             for name in ('prepare_receipt.py', 'contract.json', 'README.md', 'failed-job.log')}
    return checked.canonical({
        'schema': 'transport/native-workflow-ci-path-receipt/1',
        'status': 'TESTED_DEVELOPMENT_NOT_ACCEPTED',
        'parent_commit': 'c13b9a8a8dd1f6d3d2811705ab52ea9b85b1f303',
        'previous_delta_reader': checked.pin(previous.read(PREVIOUS / 'prepare_receipt.py')),
        'previous_delta_receipt': checked.pin(held),
        'current_checked_delta': checked.json_value(current), 'files': files,
        'claims': 'Pinned previous checker enforces complete base inventory continuity. '
                  'New workflow supplies the unchanged test harness required private tmpfs path. '
                  'Hosted success requires a separate completed run; no semantic or benefit claim.'})


def main():
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw = derived()
    if args.check:
        previous = previous_reader()
        previous.need(previous.read(HERE / 'receipt.json') == raw,
                      'CI path receipt does not reproduce')
    else:
        with (HERE / 'receipt.json').open('xb') as stream:
            if stream.write(raw) != len(raw):
                raise ValueError('short CI path receipt write')
    print('CI harness path correction matches the sealed parent inventory')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile,
            zipfile.LargeZipFile, zlib.error, NotImplementedError, RecursionError) as error:
        print('REFUSED: ' + str(error), file=sys.stderr)
        sys.exit(1)
