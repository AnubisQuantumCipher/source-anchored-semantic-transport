#!/usr/bin/env python3
"""Derive a bounded source/observation inventory; --check never edits it."""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import stat
import sys

HERE = Path(__file__).resolve().parent
SOURCES = ('retrieval.py', 'adapter.py', 'test_adapter.py', 'test_retrieval.py',
           'test_fts_capability.py', 'run_tests.py', 'prepare_receipt.py',
           'oracle.json', 'contract.json', 'response-contract.json', 'README.md')
MAX_FILE, MAX_TOTAL, MAX_ENTRIES = 2097152, 8388608, 256


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE, 'file bound/type')
        raw = bytearray()
        for unused in range(MAX_FILE // 16384 + 2):
            chunk = os.read(descriptor, min(16384, MAX_FILE + 1 - len(raw)))
            if not chunk:
                after = os.fstat(descriptor)
                fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                need(all(getattr(before, n) == getattr(after, n) for n in fields)
                     and len(raw) == after.st_size, 'changed file')
                return bytes(raw)
            raw.extend(chunk)
            need(len(raw) <= MAX_FILE, 'file bound')
        raise ValueError('iteration bound')
    finally:
        os.close(descriptor)


def inventory():
    directory = HERE / 'evidence'
    need(directory.is_dir() and not directory.is_symlink(), 'evidence directory')
    entries = list(itertools.islice(directory.iterdir(), MAX_ENTRIES + 1))
    need(1 <= len(entries) <= MAX_ENTRIES, 'evidence entry bound')
    paths = [HERE / name for name in SOURCES]
    for path in entries:
        need(path.name.isascii() and len(path.name) <= 128 and path.is_file()
             and not path.is_symlink(), 'evidence entry type/name')
        paths.append(path)
    result, total = {}, 0
    for path in sorted(paths):
        raw = read(path)
        total += len(raw)
        need(total <= MAX_TOTAL, 'inventory byte bound')
        result[path.relative_to(HERE).as_posix()] = {
            'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
    return result, total


def derived():
    records, total = inventory()
    return canonical({'schema': 'transport/matched-retrieval-receipt/1',
        'status': 'TESTED_DEVELOPMENT_NOT_ACCEPTED', 'files': records,
        'inventory_bytes': total,
        'claims': {'portable_controls': '71 normal and71 optimized local; strict FTS positive cases included',
                   'actual_codec_integration': 'Two frozen scenarios, canonical arm equality plus full-source payload oracles',
                   'negative_controls': 'Five adapter pin/code-selection refusals',
                   'proof_scope': 'Python/SQLite tests and structural AST checks; native source unchanged'},
        'open': ['strongest native workflow qualification', 'human total-work benefit',
                 'external reproduction', 'semantic adequacy', 'formal integration proof']})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw = derived()
    target = HERE / 'receipt.json'
    if args.check:
        need(read(target) == raw, 'receipt does not reproduce')
    else:
        with target.open('xb') as stream:
            need(stream.write(raw) == len(raw), 'short receipt write')
    print('Matched retrieval source and observation inventory matches')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError) as error:
        print('REFUSED: ' + str(error), file=sys.stderr)
        sys.exit(1)
