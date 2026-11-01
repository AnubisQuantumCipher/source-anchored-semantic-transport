"""Presentation-only CRED companion; canonical codec artifacts are never edited."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

CAP = 131072
TOKEN = re.compile(br'STS1:[0-9a-f]{64}\Z')
REFERENCE = re.compile(br'https://[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&\x27()*+,;=%-]{0,247}\Z')


class PublicShareError(ValueError):
    """Named fail-closed presentation refusal, never an authority verdict."""


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise PublicShareError('PUBLIC_SHARE_ARGUMENTS')


def _need(condition, reason):
    if not condition:
        raise PublicShareError(reason)


def _pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def _formatted(raw, budget):
    _need(type(raw) is bytes and type(budget) is int and 1 <= budget <= CAP,
          'PUBLIC_SHARE_ARGUMENTS')
    _need(len(raw) <= CAP, 'PUBLIC_SHARE_INPUT_BOUND')
    try:
        raw.decode('utf-8', errors='strict')
    except UnicodeError as error:
        raise PublicShareError('PUBLIC_SHARE_UTF8') from error
    parts = raw.rsplit(b'\n', 2)
    _need(len(parts) == 3 and bool(parts[0]) and bool(parts[2]),
          'PUBLIC_SHARE_LAYOUT')
    display, token, reference = parts
    _need(TOKEN.fullmatch(token) is not None, 'PUBLIC_SHARE_TOKEN')
    _need(reference == b'attached:meaning.zip' or
          REFERENCE.fullmatch(reference) is not None, 'PUBLIC_SHARE_REFERENCE')
    cred = b'CRED:' + hashlib.sha256(token).hexdigest().encode('ascii')
    result = display + b'\n' + token + b'\n' + cred + b'\n' + reference
    _need(len(result) <= CAP, 'PUBLIC_SHARE_BYTE_BOUND')
    characters = len(result.decode('utf-8', errors='strict'))
    _need(characters <= budget, 'PUBLIC_SHARE_BUDGET')
    return result, cred.decode('ascii'), characters


def public_text(raw, budget):
    """Return the complete companion or raise a named presentation refusal."""
    return _formatted(raw, budget)[0]


def _path(value):
    _need(type(value) is str and '\x00' not in value, 'PUBLIC_SHARE_PATH')
    try:
        encoded = value.encode('utf-8', errors='strict')
    except UnicodeError as error:
        raise PublicShareError('PUBLIC_SHARE_PATH') from error
    _need(0 < len(encoded) <= 4096, 'PUBLIC_SHARE_PATH')
    path = Path(os.path.abspath(value))
    _need(len(os.fsencode(path)) <= 4096 and len(path.parts) <= 65,
          'PUBLIC_SHARE_PATH')
    return path


def _parent(path):
    descriptor = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for part in path.parts[1:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                          os.O_CLOEXEC, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = nxt
        return descriptor
    except OSError:
        os.close(descriptor)
        raise


def _read(path):
    parent = _parent(path)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK |
                             os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(descriptor)
        _need(stat.S_ISREG(before.st_mode), 'PUBLIC_SHARE_IO')
        _need(before.st_size <= CAP, 'PUBLIC_SHARE_INPUT_BOUND')
        raw = bytearray()
        for unused in range(CAP + 1):
            block = os.read(descriptor, min(16384, CAP + 1 - len(raw)))
            if not block:
                after = os.fstat(descriptor)
                names = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                _need(all(getattr(before, n) == getattr(after, n) for n in names)
                      and len(raw) == after.st_size, 'PUBLIC_SHARE_CHANGED')
                return bytes(raw)
            raw.extend(block)
            _need(len(raw) <= CAP, 'PUBLIC_SHARE_INPUT_BOUND')
        raise PublicShareError('PUBLIC_SHARE_IO')
    finally:
        os.close(descriptor)


def _outside(root, output):
    _need(output != root and root not in output.parents,
          'PUBLIC_SHARE_CANONICAL_DESTINATION')


def _write(descriptor, raw):
    offset = 0
    for unused in range(CAP + 1):
        if offset == len(raw):
            return
        count = os.write(descriptor, raw[offset:offset + 16384])
        _need(type(count) is int and count > 0, 'PUBLIC_SHARE_IO')
        offset += count
    raise PublicShareError('PUBLIC_SHARE_IO')


def _remove_owned(parent, name, identity):
    try:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (current.st_dev, current.st_ino) == identity:
            os.unlink(name, dir_fd=parent)
    except OSError:
        return


def _publish(path, raw):
    parent = _parent(path)
    descriptor = None
    identity = None
    try:
        try:
            descriptor = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=parent)
        except FileExistsError as error:
            raise PublicShareError('PUBLIC_SHARE_EXISTS') from error
        created = os.fstat(descriptor)
        identity = (created.st_dev, created.st_ino)
        _write(descriptor, raw)
    except (OSError, PublicShareError):
        if identity is not None:
            _remove_owned(parent, path.name, identity)
        raise
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _budget(value):
    _need(type(value) is str and value.isascii() and value.isdigit()
          and 1 <= len(value) <= 6, 'PUBLIC_SHARE_ARGUMENTS')
    result = int(value)
    _need(1 <= result <= CAP, 'PUBLIC_SHARE_ARGUMENTS')
    return result


def _format_file(source, output, budget):
    _outside(source.parent, output)
    raw = _read(source)
    result, cred, characters = _formatted(raw, budget)
    _publish(output, result)
    return {'schema': 'transport/public-share-format/1', 'status': 'FORMATTED_COMPANION',
            'input': _pin(raw), 'output': _pin(result), 'cred': cred,
            'characters': characters, 'budget': budget}


def main():
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    formatter = commands.add_parser('format')
    formatter.add_argument('input')
    formatter.add_argument('output')
    formatter.add_argument('--budget', required=True)
    args = parser.parse_args()
    budget = _budget(args.budget)
    source, output = _path(args.input), _path(args.output)
    return _format_file(source, output, budget)


def _entry():
    try:
        result = main()
    except PublicShareError as error:
        result = {'schema': 'transport/public-share-refusal/1',
                  'status': 'REFUSED_PUBLIC_SHARE', 'reason': str(error)}
        sys.stdout.buffer.write(_canonical(result) + b'\n')
        return 2
    except OSError:
        result = {'schema': 'transport/public-share-refusal/1',
                  'status': 'REFUSED_PUBLIC_SHARE', 'reason': 'PUBLIC_SHARE_IO'}
        sys.stdout.buffer.write(_canonical(result) + b'\n')
        return 2
    sys.stdout.buffer.write(_canonical(result) + b'\n')
    return 0


if __name__ == '__main__':
    raise SystemExit(_entry())
