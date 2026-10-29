#!/usr/bin/env python3
"""Distribute the unchanged pinned installer source; never execute archive code."""
import argparse
import io
import os
from pathlib import Path
import resource
import shutil
import struct
import sys
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
from transport_install_layout import DIGEST, checked_json, input_names, source_inputs
from transport_install_support import canonical, confined, read_regular, require, sha, write_new

MAX_ARCHIVE, MAX_ENTRIES, MAX_ENTRY, MAX_EXPANDED = 1048576, 128, 131072, 4194304
RESERVE = 10000000000
MANIFEST = 'DISTRIBUTION.json'
SOURCE = 'install/SOURCE.json'
DEMO = ('examples/authoring-v1/controller/authoring.json',
        'examples/authoring-v1/controller/source.txt')
README = 'README-DISTRIBUTION.md'
SCOPE = 'PINNED_CODEC_INSTALLER_SOURCE_AND_CONTROLLER_DEMO'


def instructions(source_sha):
    return ('''# Source-Anchored Semantic Transport: codec source distribution

This archive contains the exact pinned codec build inputs, their SOURCE.json,
and a controller authoring example. It is an installer source distribution, not
the full development repository, evaluator extensions, test or evidence corpus.
Those remain in https://github.com/AnubisQuantumCipher/source-anchored-semantic-transport

No imported source was executed by the distribution verifier. Authenticate your
source and separately held archive/source digests before building. Hashes detect
changes; they do not establish authorship, truth, safety or execution authority.
The manifest excludes itself and identifies every other member. All extracted
files are non-executable data with private permissions.

The exercised build environment is Linux aarch64, Python 3.14.7, GNAT/GCC 16.1.0,
GPRbuild 26.0.0 and readelf 2.46.1. Supply an existing trusted toolchain; this
archive installs no prerequisites or services. Other hosts are not certified by
this source distribution. The installer enforces its existing resource bounds.

From this directory, after the source trust decision:

```sh
python3 -I -S -B -Werror install/prepare_source.py --check
python3 -I -S -B -Werror install/transport_install.py build /absolute/new/runtime \\
  --expect-source SOURCE_DIGEST --receipt /absolute/new/build-receipt \\
  --gprbuild /absolute/trusted/gprbuild --compiler-bin /absolute/trusted/gnat/bin
/absolute/new/runtime/bin/semantic-transport encode \\
  examples/authoring-v1/controller/authoring.json /absolute/new/encoded \\
  --source SOURCE=examples/authoring-v1/controller/source.txt \\
  --budget 1024 --reference attached:meaning.zip
/absolute/new/runtime/bin/semantic-transport validate /absolute/new/encoded/share.txt \\
  --archive /absolute/new/encoded/meaning.zip
/absolute/new/runtime/bin/semantic-transport recover /absolute/new/encoded/share.txt \\
  /absolute/new/recovered.txt --archive /absolute/new/encoded/meaning.zip --source SOURCE
cmp examples/authoring-v1/controller/source.txt /absolute/new/recovered.txt
```

Use real absolute paths whose parent directories already exist, are owned by you
and are not writable by other users. All output targets must be new. The decoder
identity is derived from the actual build. A source rebuild does not promise the
same runtime identity on another host. Keep exact old runtimes for old packages;
incompatible identities must refuse, not silently migrate. Full semantic capture
and the correctness of an author's interpretation are not established by this
archive or a source byte comparison.
'''.replace('SOURCE_DIGEST', source_sha)).encode('utf-8')


def allowed_names():
    return input_names() | {SOURCE, README, *DEMO}


def bounded_entries(entries):
    require(type(entries) is dict and 1 <= len(entries) <= MAX_ENTRIES, 'distribution entry count')
    total = 0
    for name, raw in entries.items():
        require(type(name) is str and 0 < len(name) <= 4096, 'entry path bound')
        require(type(raw) is bytes and 0 < len(raw) <= MAX_ENTRY, 'entry byte bound')
        total += len(raw)
        require(total <= MAX_EXPANDED, 'distribution expansion bound')


def source_check(entries, expected_source):
    bounded_entries(entries)
    require(type(expected_source) is str and DIGEST.fullmatch(expected_source) is not None,
            'independently held source digest required')
    require(set(entries) == allowed_names(), 'distribution source closure differs')
    require(sha(entries[SOURCE]) == expected_source, 'held source digest mismatch')
    source = checked_json(entries[SOURCE])
    require(set(source) == {'schema', 'files', 'excluded', 'product'}, 'source manifest fields')
    require(source['schema'] == 'transport/install-source/1'
            and source['excluded'] == [SOURCE], 'source manifest version or exclusions')
    require(source['product'] == 'Source-Anchored Semantic Transport', 'source product identity')
    records = source['files']
    require(type(records) is list and 1 <= len(records) <= 128, 'source record bound')
    seen = set()
    for item in records:
        require(type(item) is dict and set(item) == {'path', 'bytes', 'sha256'}, 'source record fields')
        name = item['path']
        require(type(name) is str and name in input_names() and name not in seen, 'source record path')
        require(type(item['bytes']) is int and item['bytes'] == len(entries[name])
                and type(item['sha256']) is str and item['sha256'] == sha(entries[name]), 'source record mismatch')
        seen.add(name)
    require(seen == input_names(), 'missing declared installer input')
    require(entries[README] == instructions(expected_source), 'distribution instructions differ')


def collect(root, expected_source):
    _, entries = source_inputs(root, expected_source)
    entries[SOURCE] = read_regular(confined(root, SOURCE), MAX_ENTRY)
    for name in DEMO:
        entries[name] = read_regular(confined(root, name), MAX_ENTRY)
    entries[README] = instructions(expected_source)
    source_check(entries, expected_source)
    for name, raw in entries.items():
        if name != README:
            require(read_regular(confined(root, name), MAX_ENTRY) == raw, 'source changed during collection')
    return entries


def manifest(entries):
    bounded_entries(entries)
    return canonical(dict(schema='transport/source-distribution/1', scope=SCOPE,
        source_manifest_sha256=sha(entries[SOURCE]), excluded=[MANIFEST],
        files=[dict(path=name, bytes=len(raw), sha256=sha(raw)) for name, raw in sorted(entries.items())]))


def _zip(entries):
    bounded_entries(entries)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_STORED, allowZip64=False) as archive:
        for name, raw in sorted(entries.items()):
            require(name in allowed_names() | {MANIFEST}, 'unsupported distribution path')
            info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
            info.create_system, info.external_attr = 3, 0o100644 << 16
            archive.writestr(info, raw)
    raw = buffer.getvalue()
    require(len(raw) <= MAX_ARCHIVE, 'distribution archive byte bound')
    return raw


def pack(entries):
    bounded_entries(entries)
    require(SOURCE in entries, 'source payload required')
    source_check(entries, sha(entries[SOURCE]))
    return _zip(entries | {MANIFEST: manifest(entries)})


def _directory(raw):
    require(type(raw) is bytes and 22 <= len(raw) <= MAX_ARCHIVE, 'archive byte bound or truncation')
    end = struct.unpack('<4s4H2IH', raw[-22:])
    require(end[0] == b'PK\x05\x06' and end[1:3] == (0, 0) and end[7] == 0,
            'single disk without trailing data or comment required')
    require(1 <= end[3] == end[4] <= MAX_ENTRIES, 'archive entry count bound')
    require(end[5] + end[6] == len(raw) - 22, 'archive central extent')


def _read_zip(raw):
    _directory(raw)
    entries, total = {}, 0
    try:
        with zipfile.ZipFile(io.BytesIO(raw), 'r', allowZip64=False) as archive:
            infos = archive.infolist()
            require(1 <= len(infos) <= MAX_ENTRIES, 'archive directory entry bound')
            for info in infos:
                name = info.filename
                require(name == info.orig_filename and name in allowed_names() | {MANIFEST}
                        and name not in entries, 'unsafe, unsupported or duplicate archive path')
                require(info.create_system == 3 and info.external_attr == 0o100644 << 16,
                        'regular archive file required')
                require(info.compress_type == zipfile.ZIP_STORED and info.flag_bits == 0,
                        'compressed, encrypted or descriptor entries refused')
                require(info.extra == info.comment == b'' and 0 < info.file_size <= MAX_ENTRY
                        and info.file_size == info.compress_size, 'entry metadata or byte bound')
                total += info.file_size
                require(total <= MAX_EXPANDED, 'archive expansion bound')
                with archive.open(info) as stream:
                    value = stream.read(info.file_size + 1)
                require(len(value) == info.file_size, 'truncated archive entry')
                entries[name] = value
    except (zipfile.BadZipFile, RuntimeError, EOFError, NotImplementedError) as error:
        raise ValueError('invalid source archive') from error
    return entries


def inspect_archive(raw, expected_archive, expected_source):
    require(type(expected_archive) is str and DIGEST.fullmatch(expected_archive) is not None,
            'held archive digest required')
    require(type(raw) is bytes and len(raw) <= MAX_ARCHIVE and sha(raw) == expected_archive,
            'held archive digest mismatch or byte bound')
    entries = _read_zip(raw)
    require(MANIFEST in entries, 'distribution manifest missing')
    declared = entries.pop(MANIFEST)
    source_check(entries, expected_source)
    require(declared == manifest(entries), 'manifest version, scope, inventory or integrity differs')
    require(raw == pack(entries), 'noncanonical archive layout, metadata or ordering')
    return entries


def _headroom(parent, sizes, directories=0):
    """Observed allocation allowance, not a reservation against concurrent writers."""
    require(type(sizes) is list and 1 <= len(sizes) <= MAX_ENTRIES, 'output file count bound')
    require(all(type(size) is int and 0 <= size <= MAX_ARCHIVE for size in sizes), 'output byte bounds')
    require(type(directories) is int and 0 <= directories <= MAX_ENTRIES, 'directory bound')
    block = os.statvfs(parent).f_frsize
    require(0 < block <= MAX_ARCHIVE, 'filesystem allocation unit bound')
    allowance = sum(((size + block - 1) // block) * block for size in sizes) + directories * block
    require(shutil.disk_usage(parent).free >= RESERVE + 2 * allowance,
            'insufficient free space for output, full comparison allowance and reserve')


def new_target(path):
    require(isinstance(path, Path) and path.is_absolute(), 'absolute output path required')
    confined(path.parent, path.name)
    parent = path.parent.stat()
    require(parent.st_uid == os.geteuid() and parent.st_mode & 0o022 == 0,
            'output parent must be owned and not group/world writable')
    require(not path.exists() and not path.is_symlink(), 'output target must be new')


def publish(archive, archive_path, receipt_path, expected_source):
    require(type(archive) is bytes and len(archive) <= MAX_ARCHIVE, 'archive byte bound')
    entries = inspect_archive(archive, sha(archive), expected_source)
    require(archive_path.absolute() != receipt_path.absolute(), 'archive and receipt targets alias')
    for path in (archive_path, receipt_path):
        new_target(path)
    value = dict(schema='transport/source-distribution-receipt/1', status='SOURCE_ARCHIVE_VERIFIED',
                 archive_sha256=sha(archive), archive_bytes=len(archive), entry_count=len(entries) + 1,
                 source_manifest_sha256=expected_source, manifest_sha256=sha(manifest(entries)),
                 scope=SCOPE, authentication='NOT_PROVIDED', build_execution='UNPERFORMED',
                 publication='CREATE_ONLY_FILES; a later failure retains earlier outputs')
    receipt = canonical(value)
    _headroom(archive_path.parent, [len(archive), len(receipt)])
    _headroom(receipt_path.parent, [len(archive), len(receipt)])
    write_new(archive_path, archive, MAX_ARCHIVE)
    write_new(receipt_path, receipt, MAX_ENTRY)
    require(read_regular(archive_path, MAX_ARCHIVE) == archive
            and read_regular(receipt_path, MAX_ENTRY) == receipt, 'publication readback mismatch')
    return value


def unpack(raw, expected_archive, expected_source, output):
    entries = inspect_archive(raw, expected_archive, expected_source)
    entries[MANIFEST] = manifest(entries)
    new_target(output)
    target = output
    directories = {str(parent) for name in entries for parent in Path(name).parents}
    _headroom(target.parent, [len(value) for value in entries.values()], len(directories))
    target.mkdir(mode=0o700)
    for name, value in sorted(entries.items()):
        path = target / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_new(confined(target, name), value, MAX_ENTRY)
    for name, value in entries.items():
        require(read_regular(confined(target, name), MAX_ENTRY) == value, 'extraction readback differs')
    source_inputs(target, expected_source)
    return dict(status='SOURCE_EXTRACTED_BYTE_CHECKED', archive_sha256=expected_archive,
                source_manifest_sha256=expected_source, entry_count=len(entries),
                code_execution='NONE', scope=SCOPE, partial_failure='RETAIN_OUTPUT; never use a failed extraction')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    export = sub.add_parser('pack')
    export.add_argument('--source-root', type=Path, required=True)
    export.add_argument('--archive', type=Path, required=True)
    export.add_argument('--receipt', type=Path, required=True)
    export.add_argument('--expect-source', required=True)
    for action in ('inspect', 'unpack'):
        command = sub.add_parser(action)
        command.add_argument('--archive', type=Path, required=True)
        command.add_argument('--expect-archive', required=True)
        command.add_argument('--expect-source', required=True)
        if action == 'unpack':
            command.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.action == 'pack':
        raw = pack(collect(args.source_root, args.expect_source))
        return publish(raw, args.archive, args.receipt, args.expect_source)
    raw = read_regular(args.archive, MAX_ARCHIVE)
    if args.action == 'unpack':
        return unpack(raw, args.expect_archive, args.expect_source, args.output)
    entries = inspect_archive(raw, args.expect_archive, args.expect_source)
    return dict(status='SOURCE_ARCHIVE_VERIFIED', files=len(entries), scope=SCOPE, code_execution='NONE')


if __name__ == '__main__':
    try:
        resource.setrlimit(resource.RLIMIT_AS, (268435456, 1073741824))
        resource.setrlimit(resource.RLIMIT_CPU, (20, 120))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARCHIVE, 33554432))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 128))
        print(canonical(main()).decode('utf-8'))
    except (ValueError, OSError, TypeError, KeyError, UnicodeError, MemoryError) as error:
        print(canonical(dict(status='REFUSED', reason=str(error)[:512], code_execution='NONE')).decode())
        raise SystemExit(1)
