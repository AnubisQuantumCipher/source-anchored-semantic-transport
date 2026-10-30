#!/usr/bin/env python3
"""Check sealed QUORUM inputs and the narrowly versioned documentary transition."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
V1 = 'examples/quorum-replay-v1'
V2 = 'examples/quorum-replay-continuity-v2'
RECEIPT = V1 + '/receipt.json'
MANIFEST = V2 + '/manifest.json'
CHECKER = V2 + '/check_continuity.py'
HISTORICAL = '3e0d8602353e42a772927c8adaa32a73e7cc3b0a'
MANIFEST_SHA256 = '2e3c222d0c82b40c75e3c448e115fbeeef8f0d946f437e87a0518cc60b0918ac'
FILE_LIMIT = 1048576
TOTAL_LIMIT = 33554432
ENTRY_LIMIT = 2048


def require(condition, message):
    if not condition:
        raise ValueError(message)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def relative(root, name):
    require(type(name) is str and 0 < len(name) <= 512, 'Relative path bound')
    path = Path(name)
    require(not path.is_absolute() and path.as_posix() == name, 'Relative path form')
    require(all(part not in ('.', '..') for part in path.parts), 'Relative path escape')
    target = root / path
    for parent in (target, *target.parents):
        require(not parent.is_symlink(), 'Symlink in checked path')
        if parent == root:
            return target
    raise ValueError('Path outside checked root')


class Reader:
    def __init__(self):
        self.total = 0

    def read(self, root, name):
        target = relative(root, name)
        info = target.lstat()
        require(stat.S_ISREG(info.st_mode), 'Checked input is not a regular file')
        require(info.st_size <= FILE_LIMIT, 'Input byte bound')
        with target.open('rb') as stream:
            raw = stream.read(FILE_LIMIT + 1)
        require(len(raw) <= FILE_LIMIT, 'Input grew past byte bound')
        self.total += len(raw)
        require(self.total <= TOTAL_LIMIT, 'Aggregate input byte bound')
        return raw


def tree_paths(root, name):
    pending, files, entries = [relative(root, name)], set(), 0
    for unused in range(ENTRY_LIMIT):
        if not pending:
            return files
        directory = pending.pop()
        seen = False
        with os.scandir(directory) as children:
            for entry in children:
                seen = True
                entries += 1
                require(entries <= ENTRY_LIMIT, 'Tree entry bound')
                path, info = Path(entry.path), entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    pending.append(path)
                else:
                    require(stat.S_ISREG(info.st_mode), 'Unsupported tree entry')
                    files.add(path.relative_to(root).as_posix())
        require(seen, 'Empty directory outside sealed tree')
    raise ValueError('Tree work bound')


def owned_sources(root, separate):
    result = set()
    for directory in ('tools', 'install'):
        with os.scandir(root / directory) as children:
            for count, entry in enumerate(children, 1):
                require(count <= ENTRY_LIMIT, 'Source directory entry bound')
                owned = (entry.name.startswith('transport_quorum') if directory == 'tools'
                         else 'quorum' in entry.name)
                if owned and directory + '/' + entry.name not in separate:
                    info = entry.stat(follow_symlinks=False)
                    require(stat.S_ISREG(info.st_mode), 'Unsupported QUORUM source')
                    result.add(directory + '/' + entry.name)
    return result


def load_manifest(reader, root):
    raw = reader.read(root, MANIFEST)
    require(hashlib.sha256(raw).hexdigest() == MANIFEST_SHA256, 'Manifest pin differs')
    manifest = json.loads(raw)
    require(manifest['schema'] == 'quorum/source-continuity/2', 'Manifest schema')
    require(manifest['historical_commit'] == HISTORICAL, 'Historical source epoch')
    require(set(manifest['intentional_mismatches']) ==
            {'README.md', '.github/workflows/quorum-replay.yml'}, 'Transition roster')
    return manifest


def receipt_rows(reader, root, manifest):
    raw = reader.read(root, RECEIPT)
    require(pin(raw) == manifest['historical_receipt'], 'Sealed receipt pin differs')
    receipt = json.loads(raw)
    rows = receipt['files']
    require(len(rows) == manifest['historical_file_count'] == 701, 'Receipt file count')
    names = [row['path'] for row in rows]
    require(names == sorted(set(names), key=Path), 'Receipt roster order or duplicates')
    require(sum(row['bytes'] for row in rows) <= TOTAL_LIMIT, 'Receipt aggregate bound')
    return rows


def check_historical(reader, historical, rows, manifest):
    require(pin(reader.read(historical, RECEIPT)) == manifest['historical_receipt'],
            'Historical receipt differs')
    for row in rows:
        require(pin(reader.read(historical, row['path'])) ==
                {'bytes': row['bytes'], 'sha256': row['sha256']},
                'Historical input differs: ' + row['path'])
    expected = {row['path'] for row in rows if row['path'].startswith(V1 + '/')}
    require(tree_paths(historical, V1) == expected | {RECEIPT}, 'Historical archive roster')


def check_transition(name, raw, expected, transition):
    require(transition['historical'] == expected, 'Transition historical pin')
    require(pin(raw) == transition['current'], 'Current transition pin: ' + name)
    if name == 'README.md':
        require(transition['replacement'] == 'exact-dated-section-insertion',
                'README replacement contract')
        start, size = transition['insertion_offset'], transition['insertion']['bytes']
        require(type(start) is int and type(size) is int and 0 <= start < len(raw)
                and 0 < size <= len(raw) - start, 'README insertion bounds')
        require(pin(raw[start:start + size]) == transition['insertion'], 'README insertion')
        require(pin(raw[:start] + raw[start + size:]) == expected, 'README original body')
    else:
        require(transition['replacement'] == 'historical-replay-and-current-continuity',
                'Workflow replacement contract')


def check_current(reader, root, rows, manifest):
    mismatches = set()
    transitions = manifest['intentional_mismatches']
    for row in rows:
        name, expected = row['path'], {'bytes': row['bytes'], 'sha256': row['sha256']}
        raw = reader.read(root, name)
        if pin(raw) != expected:
            require(name in transitions, 'Current sealed input differs: ' + name)
            check_transition(name, raw, expected, transitions[name])
            mismatches.add(name)
    require(mismatches == set(transitions), 'Required documentary mismatches differ')
    expected = {row['path'] for row in rows if row['path'].startswith(V1 + '/')}
    require(tree_paths(root, V1) == expected | {RECEIPT}, 'Current archive roster')
    sources = {row['path'] for row in rows if row['path'].startswith(('tools/', 'install/'))
               and ('quorum' in Path(row['path']).name)}
    require(owned_sources(root, manifest['separate_source_names']) == sources,
            'QUORUM source roster differs')


def check_v2(reader, root, manifest):
    expected = {CHECKER, MANIFEST, V2 + '/test_continuity.py', V2 + '/README.md'}
    require(tree_paths(root, V2) == expected, 'Continuity archive roster differs')
    require(set(manifest['continuity_files']) == expected - {MANIFEST}, 'V2 pin roster')
    for name, expected_pin in manifest['continuity_files'].items():
        raw = reader.read(root, name)
        if name == CHECKER:
            field = "MANIFEST_SHA256 = '" + MANIFEST_SHA256 + "'"
            require(raw.count(field.encode()) == 1, 'Checker manifest anchor')
            raw = raw.replace(field.encode(), ("MANIFEST_SHA256 = '" + '0' * 64 + "'").encode())
        require(pin(raw) == expected_pin, 'Continuity input differs: ' + name)


def check(root, historical):
    root, historical = root.resolve(), historical.resolve()
    require(root != historical, 'Separate historical source view required')
    reader = Reader()
    manifest = load_manifest(reader, root)
    rows = receipt_rows(reader, root, manifest)
    check_historical(reader, historical, rows, manifest)
    check_current(reader, root, rows, manifest)
    check_v2(reader, root, manifest)
    return {'status': 'CHECKED', 'historical_files': len(rows),
            'intentional_mismatches': sorted(manifest['intentional_mismatches']),
            'scope': 'Sealed QUORUM inputs and exact documentary transition',
            'formal_proof': 'UNPROVEN', 'product_acceptance': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--historical-root', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = check(ROOT, args.historical_root)
    except (OSError, ValueError, TypeError, KeyError) as error:
        print('REFUSED: ' + str(error)[:240], file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
