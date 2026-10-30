#!/usr/bin/env python3
"""Local byte transport with declared interpretations; no fetching or execution."""

import argparse
import ctypes
import errno
import os
import re
import resource
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

import transport_package
from transport_schema import canonical, json_value, require, sha
from transport_wire import MAX_SOURCE, MAX_WIRE, read_bounded, write_new

ID = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
NAMES = ('share.txt', 'meaning.zip', 'lexicon.md')


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    encode = commands.add_parser('encode')
    encode.add_argument('plan', type=Path)
    encode.add_argument('output', type=Path)
    encode.add_argument('--source', action='append', required=True, default=[])
    encode.add_argument('--budget', type=int, default=512,
                        help='Complete share budget in Unicode code points, including identity and reference')
    encode.add_argument('--reference', default='attached:meaning.zip')
    for action in ('inspect', 'decode', 'validate', 'recover', 'focus'):
        command = commands.add_parser(action)
        command.add_argument('share', type=Path)
        command.add_argument('--archive', type=Path, required=True)
        if action == 'focus':
            command.add_argument('--unit', required=True)
        if action == 'recover':
            command.add_argument('output', type=Path)
            command.add_argument('--source', required=True)
    return parser.parse_args()


def source_bytes(plan_data: bytes, supplied: list[str]) -> tuple[bytes, ...]:
    require(1 <= len(supplied) <= 16, 'source argument count must be 1..16')
    plan = json_value(plan_data, MAX_SOURCE)
    require(type(plan) is dict and type(plan.get('sources')) is list,
            'plan must declare sources')
    metadata = plan['sources']
    require(1 <= len(metadata) <= 16, 'source metadata count must be 1..16')
    paths = {}
    for entry in supplied:
        identifier, separator, path = entry.partition('=')
        require(separator == '=' and ID.fullmatch(identifier) is not None and bool(path),
                'source argument must be ID=PATH')
        require(identifier not in paths, 'duplicate source argument ID')
        paths[identifier] = Path(path)
    ids = [item.get('id') if type(item) is dict else None for item in metadata]
    require(all(type(item) is str and ID.fullmatch(item) is not None for item in ids),
            'invalid source metadata ID')
    require(len(set(ids)) == len(ids) and set(ids) == set(paths),
            'source arguments must match declared source IDs exactly')
    sources, used = [], 0
    for identifier in ids:
        data = read_bounded(paths[identifier], MAX_SOURCE - used)
        sources.append(data)
        used += len(data)
    return tuple(sources)


def rename_new(source: Path, destination: Path) -> None:
    """Linux atomic directory publication; reject every preexisting destination."""
    paths = (os.fsencode(source), os.fsencode(destination))
    require(all(0 < len(path) < 4096 and b'\0' not in path for path in paths),
            'publication path byte budget or NUL failure')
    library = ctypes.CDLL(None, use_errno=True)
    try:
        rename = library.renameat2
    except AttributeError as error:
        raise OSError(errno.ENOSYS, 'atomic create-only rename unavailable') from error
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(-100, paths[0], -100, paths[1], 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))


def publish(directory: Path, files: dict[str, bytes]) -> None:
    require(set(files) == set(NAMES), 'complete product output required')
    require(all(type(value) is bytes and len(value) <= MAX_WIRE
                for value in files.values()), 'product output budget exceeded')
    stage = Path(tempfile.mkdtemp(prefix='.transport-stage-', dir=directory.parent))
    identity = stage.lstat()
    require(stat.S_ISDIR(identity.st_mode) and identity.st_uid == os.geteuid()
            and stat.S_IMODE(identity.st_mode) == 0o700, 'stage ownership mismatch')
    published = False
    try:
        for name in NAMES:
            warning = write_new(stage / name, files[name])
            require(not warning, 'output cleanup warning: ' + warning)
            require(read_bounded(stage / name, MAX_WIRE) == files[name],
                    'product readback mismatch')
        rename_new(stage, directory)
        published = True
    finally:
        if not published:
            current = stage.lstat()
            require((current.st_dev, current.st_ino, current.st_uid) ==
                    (identity.st_dev, identity.st_ino, identity.st_uid),
                    'stage identity changed; cleanup refused')
            for name in NAMES:
                (stage / name).unlink(missing_ok=True)
            stage.rmdir()


def encoded(args: argparse.Namespace) -> dict:
    plan = read_bounded(args.plan, MAX_SOURCE)
    sources = source_bytes(plan, args.source)
    pair = transport_package.encode(sources, plan, args.reference, args.budget)
    publish(args.output, dict(zip(NAMES, (pair.text, pair.archive, pair.lexicon))))
    return dict(status='MATCHED_PAIR_WRITTEN', share_characters=len(pair.text.decode('utf-8')),
                share_bytes=len(pair.text), counting='Unicode code points including identity, reference and newlines',
                archive_bytes=len(pair.archive), archive_sha256=sha(pair.archive),
                source_count=len(sources), source_bytes=sum(map(len, sources)),
                authentication='NOT_AUTHENTICATED', semantic_completeness='UNPROVEN')


def opened(args: argparse.Namespace) -> dict:
    text = read_bounded(args.share, MAX_WIRE)
    archive = read_bounded(args.archive, MAX_WIRE)
    if args.action == 'focus':
        return transport_package.focus(text, archive, args.unit)
    if args.action == 'validate':
        return transport_package.validate(text, archive)
    if args.action in ('inspect', 'decode'):
        # Both are metadata views: raw source bytes need explicit recover.
        return transport_package.inspect(text, archive)
    value = transport_package.decode(text, archive)
    require(ID.fullmatch(args.source) is not None, 'invalid requested source ID')
    selected = [item for item in value['sources'] if item['id'] == args.source]
    require(len(selected) == 1, 'requested source ID not found')
    data = selected[0]['data']
    warning = write_new(args.output, data)
    require(not warning, 'recovery cleanup warning: ' + warning)
    require(read_bounded(args.output, MAX_SOURCE) == data, 'recovery readback mismatch')
    return dict(status='EXACT_OPAQUE_BYTES_RECOVERED', source=args.source,
                bytes=len(data), sha256=sha(data), interpretation='NOT_PERFORMED')


def main() -> int:
    resource.setrlimit(resource.RLIMIT_AS, (268_435_456, 268_435_456))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_FSIZE, (131_072, 131_072))
    args = arguments()
    try:
        result = encoded(args) if args.action == 'encode' else opened(args)
        sys.stdout.buffer.write(canonical(result) + b'\n')
        return 0
    except (ValueError, OSError, MemoryError, UnicodeError, subprocess.TimeoutExpired) as error:
        print('REFUSED: ' + str(error)[:256], file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
