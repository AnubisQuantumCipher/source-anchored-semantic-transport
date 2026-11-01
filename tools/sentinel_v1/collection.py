"""Inert document evidence collection, carried by the unchanged SAST codec.

This is an indexed source file, not another ZIP codec. No item names a command,
module, network address or extraction path. Integrity is not authentication.
"""
from contextlib import contextmanager
import hashlib
import os
import re
from pathlib import Path
from transport_document_io import (open_regular, identity as file_identity,
    file_digest, MAX_SOURCE, FRAME_SOURCE)
from .common import (JOB_BYTES, METADATA, canonical, digest, fields, hash_checked,
    identity, integer, parse, require)

PROFILE = 'sentinel/document-evidence-collection/1'
MAX_ITEMS = 24576
KINDS = ('BASE_ARCHIVE', 'BASE_SHARE', 'DOCUMENT_INDEX', 'CENSUS_BLOCK', 'JOB_REQUEST',
    'JOB_GRAPH', 'GENERATION_PROVENANCE', 'IMPORT_RECEIPT', 'ASSESSMENTS', 'NATIVE_SCOPE',
    'DICTIONARY', 'INSTRUCTIONS', 'RECEIVING_EXPLANATION', 'ATTEMPT_HISTORY', 'REVISION')
MANDATORY = {'BASE_ARCHIVE', 'BASE_SHARE', 'DOCUMENT_INDEX', 'DICTIONARY', 'INSTRUCTIONS', 'REVISION'}


def identifier(value):
    require(type(value) is str and re.fullmatch(r'[A-Za-z0-9_-]{1,64}', value) is not None,
            'collection ID is data, never an archive path')
    return value


def kind_cap(kind):
    require(kind in KINDS, 'unsupported collection entry kind')
    return MAX_SOURCE if kind == 'BASE_ARCHIVE' else JOB_BYTES if kind == 'JOB_GRAPH' else METADATA


def file_pin(path, cap):
    key, size = file_digest(path, cap)
    return {'sha256': key, 'bytes': size}


def input_rows(entries):
    require(type(entries) is list and 1 <= len(entries) <= MAX_ITEMS, 'collection entry count bound')
    rows, paths, names, kinds, offset = [], [], set(), set(), 0
    for position, item in enumerate(entries):
        require(position < MAX_ITEMS, 'collection entry mutation exceeds count bound')
        fields(item, ('id', 'kind', 'path', 'pin'))
        name = identifier(item['id']); cap = kind_cap(item['kind'])
        fields(item['pin'], ('sha256', 'bytes')); hash_checked(item['pin']['sha256'])
        require(name not in names, 'duplicate collection item')
        integer(item['pin']['bytes'], 0, cap)
        require(file_pin(item['path'], cap) == item['pin'], 'collection input differs from held pin')
        rows.append({'id': name, 'kind': item['kind'], 'offset': offset, **item['pin']})
        paths.append(Path(item['path'])); names.add(name); kinds.add(item['kind'])
        offset += item['pin']['bytes']; require(offset <= MAX_SOURCE - METADATA - 8, 'collection payload bound')
    require(MANDATORY <= kinds and all(sum(row['kind'] == kind for row in rows) == 1
            for kind in MANDATORY), 'required unique collection entries missing')
    return rows, paths, offset


def index_bytes(binding, rows, total, decoder_root):
    from .census import binding_checked
    binding_checked(binding); hash_checked(decoder_root)
    return canonical({'schema': PROFILE, 'binding': binding, 'items': rows, 'payload_bytes': total,
        'decoder_root_sha256': decoder_root, 'authentication': 'UNAUTHENTICATED',
        'qualification': 'NOT_QUALIFIED', 'semantic_completeness': 'UNPROVEN',
        'execution_authority': 'NONE'})


def copy_exact(source, destination, count):
    result, used = hashlib.sha256(), 0
    for _ in range(count // FRAME_SOURCE + 1):
        if used == count: return result.hexdigest()
        block = source.read(min(FRAME_SOURCE, count - used))
        require(bool(block), 'truncated collection entry')
        require(destination.write(block) == len(block), 'short collection write')
        result.update(block); used += len(block)
    require(used == count, 'collection copy bound')
    return result.hexdigest()


def pack_file(entries, binding, decoder_root, output):
    rows, paths, total = input_rows(entries)
    header = index_bytes(binding, rows, total, decoder_root)
    require(len(header) <= METADATA and 8 + len(header) + total <= MAX_SOURCE, 'complete collection bound')
    with Path(output).open('xb') as destination:
        prefix = b'SNC1' + len(header).to_bytes(4, 'big') + header
        require(destination.write(prefix) == len(prefix), 'short collection header write')
        for row, path in zip(rows, paths):
            with open_regular(path, kind_cap(row['kind'])) as source:
                before = file_identity(source)
                require(copy_exact(source, destination, row['bytes']) == row['sha256']
                    and not source.read(1) and file_identity(source) == before, 'collection input changed')
        destination.flush(); os.fsync(destination.fileno())
    return file_pin(output, MAX_SOURCE)


def header_checked(stream, file_bytes, decoder_root):
    raw = stream.read(8)
    require(len(raw) == 8 and raw[:4] == b'SNC1', 'collection magic or truncated header')
    size = int.from_bytes(raw[4:8], 'big'); integer(size, 1, METADATA)
    require(8 + size <= file_bytes, 'collection header outside source')
    header = stream.read(size); require(len(header) == size, 'truncated collection index')
    value = parse(header)
    fields(value, ('schema', 'binding', 'items', 'payload_bytes', 'decoder_root_sha256',
        'authentication', 'qualification', 'semantic_completeness', 'execution_authority'))
    require(value['schema'] == PROFILE and value['decoder_root_sha256'] == hash_checked(decoder_root),
            'collection version or independently held decoder mismatch')
    require(header == index_bytes(value['binding'], value['items'], value['payload_bytes'], decoder_root),
            'collection assurance/index differs from canonical contract')
    integer(value['payload_bytes'], 0, MAX_SOURCE)
    require(8 + size + value['payload_bytes'] == file_bytes, 'collection trailing/truncated payload')
    return value, 8 + size


def hash_entry(stream, count, whole):
    result, used = hashlib.sha256(), 0
    for _ in range(count // FRAME_SOURCE + 1):
        if used == count: return result.hexdigest()
        raw = stream.read(min(FRAME_SOURCE, count - used))
        require(bool(raw), 'truncated collection payload')
        result.update(raw); whole.update(raw); used += len(raw)
    require(used == count, 'collection hash work bound')
    return result.hexdigest()


def rows_checked(value, stream, whole):
    rows = value['items']
    require(type(rows) is list and 1 <= len(rows) <= MAX_ITEMS, 'collection item roster bound')
    offset, names, kinds = 0, set(), set()
    for row in rows:
        fields(row, ('id', 'kind', 'offset', 'sha256', 'bytes'))
        name = identifier(row['id']); cap = kind_cap(row['kind'])
        require(name not in names, 'duplicate collection ID')
        integer(row['offset'], offset, offset); integer(row['bytes'], 0, cap); hash_checked(row['sha256'])
        require(offset + row['bytes'] <= value['payload_bytes'], 'collection entry outside payload')
        require(hash_entry(stream, row['bytes'], whole) == row['sha256'], 'collection entry digest mismatch')
        names.add(name); kinds.add(row['kind']); offset += row['bytes']
    require(offset == value['payload_bytes'] and MANDATORY <= kinds and
        all(sum(row['kind'] == kind for row in rows) == 1 for kind in MANDATORY), 'collection missing entries')


@contextmanager
def verified_file(path, held, decoder_root):
    hash_checked(held)
    with open_regular(path, MAX_SOURCE) as stream:
        before = file_identity(stream)
        index, body = header_checked(stream, before[2], decoder_root)
        stream.seek(0); prefix = stream.read(body); whole = hashlib.sha256(prefix)
        require(len(prefix) == body, 'short collection header reread')
        rows_checked(index, stream, whole)
        require(not stream.read(1) and file_identity(stream) == before
            and whole.hexdigest() == held, 'collection whole identity changed')
        yield stream, index, body
        require(file_identity(stream) == before, 'collection changed during retrieval')


def find_entry(index, name):
    identifier(name)
    rows = [row for row in index['items'] if row['id'] == name]
    require(len(rows) == 1, 'collection item absent')
    return rows[0]


def entry_bytes(stream, index, body, name, cap=METADATA):
    row = find_entry(index, name)
    integer(row['bytes'], 0, min(cap, kind_cap(row['kind'])))
    stream.seek(body + row['offset']); raw = stream.read(row['bytes'])
    require(identity(raw) == {'sha256': row['sha256'], 'bytes': row['bytes']}, 'collection selected item changed')
    return raw


def export_entry(stream, index, body, name, output):
    row = find_entry(index, name)
    stream.seek(body + row['offset'])
    with Path(output).open('xb') as destination:
        require(copy_exact(stream, destination, row['bytes']) == row['sha256'], 'collection export changed')
        destination.flush(); os.fsync(destination.fileno())
    return {'bytes': row['bytes'], 'sha256': row['sha256']}
