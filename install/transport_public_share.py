"""Presentation-only CRED companion; canonical codec artifacts are never edited."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import signal
import stat
import subprocess
import sys
import tempfile

CAP = 131072
RESPONSE_CAP = 1048576
ENCODER_SHA256 = '7366d0bc297e782dfc48593befe57828165f3a671c78bc75296a3e837a15a5e9'
SOURCE_ID = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
TOKEN = re.compile(br'STS1:[0-9a-f]{64}\Z')
REFERENCE = re.compile(br'https://[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&\x27()*+,;=%-]{0,247}\Z')


class PublicShareError(ValueError):
    """Named fail-closed presentation refusal, never an authority verdict."""

    def __init__(self, reason):
        super().__init__(reason)
        self.encoder = None
        self.canonical_files = None


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
    _need(len(raw) + len(b'\n') + len(cred) <= CAP, 'PUBLIC_SHARE_BYTE_BOUND')
    result = display + b'\n' + token + b'\n' + cred + b'\n' + reference
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


def _read(path, cap=CAP):
    _need(type(cap) is int and 1 <= cap <= CAP, 'PUBLIC_SHARE_ARGUMENTS')
    parent = _parent(path)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NONBLOCK |
                             os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        before = os.fstat(descriptor)
        _need(stat.S_ISREG(before.st_mode), 'PUBLIC_SHARE_IO')
        _need(before.st_size <= cap, 'PUBLIC_SHARE_INPUT_BOUND')
        raw = bytearray()
        for unused in range(cap + 1):
            block = os.read(descriptor, min(16384, cap + 1 - len(raw)))
            if not block:
                after = os.fstat(descriptor)
                names = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
                _need(all(getattr(before, n) == getattr(after, n) for n in names)
                      and len(raw) == after.st_size, 'PUBLIC_SHARE_CHANGED')
                return bytes(raw)
            raw.extend(block)
            _need(len(raw) <= cap, 'PUBLIC_SHARE_INPUT_BOUND')
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
        return identity
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


def _format_owned(source, output, budget):
    _outside(source.parent, output)
    raw = _read(source)
    result, cred, characters = _formatted(raw, budget)
    identity = _publish(output, result)
    return {'schema': 'transport/public-share-format/1', 'status': 'FORMATTED_COMPANION',
            'input': _pin(raw), 'output': _pin(result), 'cred': cred,
            'characters': characters, 'budget': budget}, identity


def _format_file(source, output, budget):
    return _format_owned(source, output, budget)[0]


def _absent(path, reason):
    parent = _parent(path)
    try:
        try:
            os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise PublicShareError(reason)
    finally:
        os.close(parent)


def _sources(values):
    _need(type(values) is list and 1 <= len(values) <= 16,
          'PUBLIC_SHARE_ENCODER_ARGUMENTS')
    result, names = [], set()
    for value in values:
        _need(type(value) is str and len(value) <= 4130,
              'PUBLIC_SHARE_ENCODER_ARGUMENTS')
        name, separator, filename = value.partition('=')
        _need(separator == '=' and SOURCE_ID.fullmatch(name) is not None
              and name not in names, 'PUBLIC_SHARE_ENCODER_ARGUMENTS')
        names.add(name)
        result.append((name, _path(filename)))
    return result


def _limits():
    result = []
    items = ((resource.RLIMIT_CPU, 60, 60),
             (resource.RLIMIT_AS, 1073741824, 268435456),
             (resource.RLIMIT_FSIZE, CAP, CAP))
    for kind, ceiling, required in items:
        unused, hard = resource.getrlimit(kind)
        _need(hard == resource.RLIM_INFINITY or hard >= required,
              'PUBLIC_SHARE_ENCODER_RESOURCE')
        result.append((kind, ceiling if hard == resource.RLIM_INFINITY
                       else min(ceiling, hard)))
    return tuple(result)


def _child_limits(limits):
    for kind, ceiling in limits:
        resource.setrlimit(kind, (ceiling, ceiling))


def _stream(raw):
    _need(len(raw) <= CAP, 'PUBLIC_SHARE_ENCODER_OUTPUT')
    return dict(_pin(raw), base64=base64.b64encode(raw).decode('ascii'))


def _stop(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        return process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        return None


def _run_encoder(command, limits):
    environment = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                   'LC_ALL': 'C.UTF-8', 'PYTHONDONTWRITEBYTECODE': '1'}
    timed_out = False
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        try:
            process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                stdout=stdout, stderr=stderr, env=environment, shell=False,
                start_new_session=True, preexec_fn=lambda: _child_limits(limits))
        except subprocess.SubprocessError as error:
            raise PublicShareError('PUBLIC_SHARE_ENCODER_RESOURCE') from error
        try:
            code = process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            timed_out = True
            code = _stop(process)
        stdout.seek(0)
        stderr.seek(0)
        first, second = stdout.read(CAP + 1), stderr.read(CAP + 1)
    _need(len(first) + len(second) <= 2 * CAP, 'PUBLIC_SHARE_ENCODER_OUTPUT')
    return {'exit_code': code, 'stdout': _stream(first), 'stderr': _stream(second)}, timed_out


def _canonical_snapshot(root, action):
    names = ('lexicon.md', 'meaning.zip', 'share.txt')
    if action == 'encode':
        names = ('lexicon.md', 'meaning.zip', 'plan.json', 'review.json', 'share.txt')
    parent, descriptor = _parent(root), None
    try:
        descriptor = os.open(root.name, os.O_RDONLY | os.O_DIRECTORY |
                             os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        found = set()
        with os.scandir(descriptor) as entries:
            for unused in range(6):
                entry = next(entries, None)
                if entry is None:
                    break
                _need(entry.name in names and entry.is_file(follow_symlinks=False),
                      'PUBLIC_SHARE_ENCODER_ARTIFACTS')
                found.add(entry.name)
        _need(found == set(names), 'PUBLIC_SHARE_ENCODER_ARTIFACTS')
        return {name: _read(root / name) for name in names}
    except (OSError, PublicShareError) as error:
        raise PublicShareError('PUBLIC_SHARE_ENCODER_ARTIFACTS') from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def _canonical_rows(snapshot):
    return [dict(name=name, **_pin(raw)) for name, raw in snapshot.items()]


def _encoder_inputs(args, budget):
    expected = args.expect_encoder_sha256
    _need(type(expected) is str and DIGEST.fullmatch(expected) is not None,
          'PUBLIC_SHARE_ENCODER_ARGUMENTS')
    _need(expected == ENCODER_SHA256, 'PUBLIC_SHARE_ENCODER_UNSUPPORTED')
    _need(args.encoder.startswith('/'), 'PUBLIC_SHARE_ENCODER_ARGUMENTS')
    encoder, document = _path(args.encoder), _path(args.document)
    encoded, public = _path(args.encoded_dir), _path(args.public_output)
    _need(encoder.name == 'semantic-transport' and encoder.parent.name == 'bin',
          'PUBLIC_SHARE_ENCODER_UNSUPPORTED')
    _outside(encoded, public)
    _absent(encoded, 'PUBLIC_SHARE_ENCODED_EXISTS')
    _absent(public, 'PUBLIC_SHARE_EXISTS')
    launcher = _read(encoder)
    _need(_pin(launcher)['sha256'] == expected, 'PUBLIC_SHARE_ENCODER_PIN')
    observed = [(encoder, launcher), (document, _read(document, 65536))]
    sources, total = _sources(args.source), 0
    for unused, path in sources:
        raw = _read(path, 65536)
        total += len(raw)
        _need(total <= 65536, 'PUBLIC_SHARE_INPUT_BOUND')
        observed.append((path, raw))
    try:
        reference = args.reference.encode('ascii', errors='strict')
    except UnicodeError as error:
        raise PublicShareError('PUBLIC_SHARE_REFERENCE') from error
    _need(reference == b'attached:meaning.zip' or
          REFERENCE.fullmatch(reference) is not None, 'PUBLIC_SHARE_REFERENCE')
    command = [str(encoder), args.command, str(document), str(encoded)]
    for name, path in sources:
        command.extend(('--source', name + '=' + str(path)))
    command.extend(('--budget', str(budget), '--reference', args.reference))
    _need(len(command) <= 64 and sum(len(a.encode('utf-8')) for a in command) <= 32768,
          'PUBLIC_SHARE_ENCODER_ARGUMENTS')
    return command, observed, encoded, public


def _unchanged(observed):
    for path, raw in observed:
        try:
            _need(_read(path) == raw, 'PUBLIC_SHARE_CHANGED')
        except (OSError, PublicShareError) as error:
            raise PublicShareError('PUBLIC_SHARE_CHANGED') from error


def _encode_workflow(args, budget):
    command, observed, encoded, public = _encoder_inputs(args, budget)
    execution, timed_out = _run_encoder(command, _limits())
    rows, identity = None, None
    try:
        _need(not timed_out, 'PUBLIC_SHARE_ENCODER_TIMEOUT')
        _need(execution['exit_code'] == 0, 'PUBLIC_SHARE_ENCODER_FAILED')
        _unchanged(observed)
        before = _canonical_snapshot(encoded, args.command)
        rows = _canonical_rows(before)
        formatted, identity = _format_owned(encoded / 'share.txt', public, budget)
        _need(_canonical_snapshot(encoded, args.command) == before,
              'PUBLIC_SHARE_CANONICAL_CHANGED')
    except (PublicShareError, OSError) as failure:
        if identity is not None:
            parent = _parent(public)
            try:
                _remove_owned(parent, public.name, identity)
            finally:
                os.close(parent)
        error = failure if isinstance(failure, PublicShareError) else PublicShareError('PUBLIC_SHARE_IO')
        error.encoder, error.canonical_files = execution, rows
        raise error
    return {'schema': 'transport/public-share-encode/1', 'status': 'ENCODED_PUBLIC_COMPANION',
            'format': formatted, 'canonical_files': rows, 'encoder': execution}


def _output_refusal(result):
    refusal = {'schema': 'transport/public-share-refusal/1',
               'status': 'REFUSED_PUBLIC_SHARE', 'reason': 'PUBLIC_SHARE_ENCODER_OUTPUT',
               'diagnostics_unavailable': 'RESPONSE_BOUND'}
    if 'encoder' in result:
        encoder = result['encoder']
        refusal['encoder'] = {'exit_code': encoder['exit_code'],
            'stdout': {k: encoder['stdout'][k] for k in ('bytes', 'sha256')},
            'stderr': {k: encoder['stderr'][k] for k in ('bytes', 'sha256')}}
        refusal['canonical_files'] = result.get('canonical_files')
    return refusal


def _emit(result):
    retained = True
    metadata = dict(result)
    if 'encoder' in metadata:
        encoder = dict(metadata['encoder'])
        encoder['stdout'] = dict(encoder['stdout'], base64='')
        encoder['stderr'] = dict(encoder['stderr'], base64='')
        metadata['encoder'] = encoder
    if len(_canonical(metadata)) > 65536:
        retained = False
        result = _output_refusal(result)
    raw = _canonical(result) + b'\n'
    if len(raw) > RESPONSE_CAP:
        retained = False
        raw = _canonical(_output_refusal(result)) + b'\n'
    sys.stdout.buffer.write(raw)
    return retained


def _argv_bound(argv):
    _need(type(argv) is list and 1 <= len(argv) <= 64, 'PUBLIC_SHARE_ARGUMENTS')
    total = 0
    for value in argv:
        _need(type(value) is str and len(value) <= 32768, 'PUBLIC_SHARE_ARGUMENTS')
        try:
            total += len(value.encode('utf-8', errors='strict'))
        except UnicodeError as error:
            raise PublicShareError('PUBLIC_SHARE_ARGUMENTS') from error
        _need(total <= 32768, 'PUBLIC_SHARE_ARGUMENTS')


def main():
    _argv_bound(sys.argv)
    parser = Parser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    formatter = commands.add_parser('format')
    formatter.add_argument('input')
    formatter.add_argument('output')
    formatter.add_argument('--budget', required=True)
    for action in ('encode', 'encode-plan'):
        encoder = commands.add_parser(action)
        encoder.add_argument('--encoder', required=True)
        encoder.add_argument('--expect-encoder-sha256', required=True)
        encoder.add_argument('document')
        encoder.add_argument('encoded_dir')
        encoder.add_argument('public_output')
        encoder.add_argument('--source', action='append', required=True)
        encoder.add_argument('--budget', required=True)
        encoder.add_argument('--reference', default='attached:meaning.zip')
    args = parser.parse_args()
    budget = _budget(args.budget)
    if args.command == 'format':
        return _format_file(_path(args.input), _path(args.output), budget)
    return _encode_workflow(args, budget)


def _entry():
    try:
        result = main()
    except PublicShareError as error:
        result = {'schema': 'transport/public-share-refusal/1',
                  'status': 'REFUSED_PUBLIC_SHARE', 'reason': str(error)}
        if error.encoder is not None:
            result.update(encoder=error.encoder, canonical_files=error.canonical_files)
        _emit(result)
        return 2
    except OSError:
        result = {'schema': 'transport/public-share-refusal/1',
                  'status': 'REFUSED_PUBLIC_SHARE', 'reason': 'PUBLIC_SHARE_IO'}
        _emit(result)
        return 2
    return 0 if _emit(result) else 2


if __name__ == '__main__':
    raise SystemExit(_entry())
