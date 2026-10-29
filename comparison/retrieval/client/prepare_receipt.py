#!/usr/bin/env python3
"""Inventory this development checkpoint and read retained observations safely.

This checks recorded bytes, not fresh product behavior or semantic adequacy.
Archive entries are read under explicit bounds and are never extracted or run.
"""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import zipfile

HERE = Path(__file__).absolute().parent
SOURCES = ('entry.py', 'test_client.py', 'test_postdispatch.py', 'test_inventory.py', 'contract.json',
           'oracle.json', 'review.json', 'inventory-review.json', 'README.md', 'prepare_receipt.py')
EVIDENCE = ('observations.zip', 'origins.json')
MAX_FILE, MAX_TOTAL, MAX_MEMBERS = 4194304, 8388608, 2048


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def read(path):
    need(path.is_absolute() and len(path.parts) <= 65 and '..' not in path.parts, 'read path')
    parent = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    descriptor = None
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= MAX_FILE, 'file type/bound')
        raw = bytearray()
        for unused in range(MAX_FILE // 16384 + 2):
            chunk = os.read(descriptor, min(16384, MAX_FILE + 1 - len(raw)))
            if not chunk:
                after = os.fstat(descriptor)
                keys = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                need(all(getattr(before, n) == getattr(after, n) for n in keys)
                     and len(raw) == after.st_size, 'changed file')
                return bytes(raw)
            raw.extend(chunk)
            need(len(raw) <= MAX_FILE, 'read byte bound')
        raise ValueError('read iteration bound')
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def pairs(items):
    need(len(items) <= MAX_MEMBERS, 'JSON object bound')
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def json_value(raw):
    need(len(raw) <= MAX_FILE, 'JSON byte bound')
    depth, nodes, quoted, escaped = 0, 0, False, False
    for token in raw:
        if quoted:
            if escaped:
                escaped = False
            elif token == 92:
                escaped = True
            elif token == 34:
                quoted = False
        elif token == 34:
            quoted = True
        elif token in (91, 123):
            depth += 1
            nodes += 1
            need(depth <= 16 and nodes <= 65536, 'JSON structural bound')
        elif token in (93, 125):
            depth -= 1
            need(depth >= 0, 'JSON depth')
        elif token in (44, 58):
            nodes += 1
            need(nodes <= 65536, 'JSON node bound')
    need(not quoted and depth == 0, 'JSON framing')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs,
                      parse_float=lambda unused: need(False, 'JSON fractional value'),
                      parse_constant=lambda unused: need(False, 'JSON non-finite value'))


def member_name(value):
    path = PurePosixPath(value)
    need(value.isascii() and 0 < len(value) <= 256 and '\\' not in value
         and not path.is_absolute() and path.as_posix() == value
         and 1 <= len(path.parts) <= 6 and '..' not in path.parts
         and all(part not in ('.', '..') and all(c.isalnum() or c in '._-' for c in part)
                 for part in path.parts), 'archive name')


def observations():
    archive_raw = read(HERE / 'evidence' / 'observations.zip')
    origins_raw = read(HERE / 'evidence' / 'origins.json')
    origins = json_value(origins_raw)
    need(type(origins) is dict and set(origins) == {'schema', 'members'}
         and origins['schema'] == 'transport/adaptive-client-observation-origins/1', 'origins schema')
    expected = origins['members']
    need(type(expected) is dict and 1 <= len(expected) <= MAX_MEMBERS, 'origin count')
    contents, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(archive_raw), 'r') as archive:
        entries = archive.infolist()
        need(1 <= len(entries) <= MAX_MEMBERS, 'archive count')
        for item in entries:
            member_name(item.filename)
            need(not item.is_dir() and item.filename not in contents
                 and item.orig_filename == item.filename and item.flag_bits == 0
                 and item.compress_type == zipfile.ZIP_STORED
                 and stat.S_ISREG(item.external_attr >> 16)
                 and item.compress_size == item.file_size and item.file_size <= 131072,
                 'archive entry type/bound')
            total += item.file_size
            need(total <= MAX_TOTAL, 'archive aggregate bound')
            with archive.open(item, 'r') as stream:
                raw = stream.read(item.file_size + 1)
            need(len(raw) == item.file_size and item.filename in expected, 'archive entry size/name')
            record = expected[item.filename]
            need(type(record) is dict and set(record) == {'path', 'bytes', 'sha256'}
                 and type(record['path']) is str and len(record['path']) <= 4096
                 and type(record['bytes']) is int and type(record['sha256']) is str
                 and pin(raw) == {key: record[key] for key in ('bytes', 'sha256')}, 'origin bytes differ')
            contents[item.filename] = raw
    need(set(contents) == set(expected), 'missing archive entry')
    return contents, total, {'evidence/observations.zip': archive_raw,
                             'evidence/origins.json': origins_raw}


def process_records(contents):
    counts = {'client-02': 0, 'client-03': 0, 'postdispatch-01': 0}
    for name, raw in sorted(contents.items()):
        parts = PurePosixPath(name).parts
        if len(parts) != 2 or parts[0] not in counts or not name.endswith('.json'):
            continue
        value = json_value(raw)
        if type(value) is not dict or not {'argv', 'stdout', 'stderr', 'exit_code'} <= set(value):
            continue
        for stream in ('stdout', 'stderr'):
            path = name[:-5] + '.' + stream
            need(path in contents and value[stream] == pin(contents[path]), 'process stream pin differs')
        counts[parts[0]] += 1
    need(all(counts[key] > 0 for key in counts), 'missing retained process records')
    return counts


def derived():
    contents, expanded, checked = observations()
    files, total = {}, 0
    for name in SOURCES + tuple('evidence/' + name for name in EVIDENCE):
        raw = checked[name] if name in checked else read(HERE / name)
        total += len(raw)
        need(total <= MAX_TOTAL, 'checkpoint inventory bound')
        files[name] = pin(raw)
    return canonical({'schema': 'transport/adaptive-client-development-receipt/1',
        'status': 'TESTED_DEVELOPMENT_NOT_ACCEPTED', 'files': files,
        'inventory_bytes': total, 'observation_members': len(contents),
        'observation_expanded_bytes': expanded, 'retained_process_records': process_records(contents),
        'claims': {'adaptive_integration': 'Local actual original and qualified decoder paths; frozen literal expectations',
                   'controlled_faults': 'Four original-arm real commits and one prelaunch no-commit case',
                   'artifact_check': 'Every retained member and process stream checked; no extraction or execution',
                   'proof_scope': 'Python development tests and GPT-6.1 engineering review; native source unchanged'},
        'open': ['external reproduction', 'strongest native workflow qualification',
                 'human or model benefit', 'semantic adequacy', 'formal integration proof',
                 'hostile concurrency', 'crash and power-failure durability']})


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
    print('Adaptive client source and retained observation inventory matches')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, UnicodeError, KeyError, TypeError, RecursionError,
            NotImplementedError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        print('REFUSED: ' + str(error), file=sys.stderr)
        sys.exit(1)
