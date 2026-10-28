"""Bounded Linux installer mechanics; observations, not authorization or proof.

Call from a single-threaded bootstrap with trusted tools that do not escape their
process group. SUCCESS records complete direct output, direct exit zero and an
observed absent original process group; it is not general descendant containment.
Resource limits are per process, not aggregate descendant limits. Same-UID hostile
processes and kernel failure are outside this scope. Refusal output retains only
the captured prefix and must never be presented as a complete transcript.
"""

import ctypes
import errno
import functools
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import resource
import selectors
import signal
import stat
import subprocess
import threading
import time

MAX_FILE = 4_194_304
MAX_JSON = 2_097_152
MAX_OUTPUT = 1_048_576
CHUNK = 16_384
MAX_STEPS = 32_768
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def require(condition: bool, message: str) -> None:
    if type(condition) is not bool or not condition:
        raise ValueError(message)


def sha(data: bytes) -> str:
    require(type(data) is bytes, 'hash input must be bytes')
    return hashlib.sha256(data).hexdigest()


def _path_parts(path: Path) -> tuple[str, ...]:
    require(isinstance(path, Path), 'path must be a Path')
    require('..' not in path.parts, 'parent path traversal refused')
    absolute = path.absolute()
    require(len(str(absolute)) < 4096, 'path character budget exceeded')
    encoded = os.fsencode(absolute)
    require(0 < len(encoded) < 4096 and b'\0' not in encoded,
            'path exceeds byte budget or contains NUL')
    require(absolute.anchor == '/' and 1 <= len(absolute.parts) <= 65,
            'path component budget exceeded')
    return absolute.parts[1:]


def _parent(path: Path) -> tuple[int, str]:
    parts = _path_parts(path)
    require(bool(parts), 'filesystem root is not a file target')
    descriptor = os.open('/', DIRECTORY_FLAGS)
    try:
        for component in parts[:-1]:
            next_descriptor = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, parts[-1]
    except BaseException:
        os.close(descriptor)
        raise


def _directory(path: Path) -> int:
    if not _path_parts(path):
        return os.open('/', DIRECTORY_FLAGS)
    parent, name = _parent(path)
    try:
        return os.open(name, DIRECTORY_FLAGS, dir_fd=parent)
    finally:
        os.close(parent)


def _identity(metadata: os.stat_result) -> tuple[int, int, int, int]:
    return metadata.st_dev, metadata.st_ino, metadata.st_uid, metadata.st_mode


def confined(root: Path, name: str) -> Path:
    require(type(name) is str and 0 < len(name) < 4096,
            'relative name exceeds character budget or is empty')
    require(not name.startswith('/') and '\\' not in name and '\0' not in name,
            'relative POSIX name required')
    parts = name.split('/')
    require(len(parts) <= 64 and all(part not in ('', '.', '..') for part in parts)
            and str(PurePosixPath(name)) == name, 'noncanonical relative name')
    descriptor = _directory(root)
    try:
        for component in parts[:-1]:
            next_descriptor = os.open(component, DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        try:
            metadata = os.stat(parts[-1], dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            metadata = None
        require(metadata is None or stat.S_ISREG(metadata.st_mode),
                'existing confined target must be a regular file')
    finally:
        os.close(descriptor)
    return root / name


def _read_fd(descriptor: int, cap: int) -> bytes:
    initial = os.fstat(descriptor)
    require(stat.S_ISREG(initial.st_mode) and initial.st_size <= cap,
            'regular file required within byte budget')
    output = bytearray()
    for _ in range(cap // CHUNK + 2):
        block = os.read(descriptor, min(CHUNK, cap + 1 - len(output)))
        if not block:
            final = os.fstat(descriptor)
            require(_identity(initial) == _identity(final)
                    and (initial.st_size, initial.st_mtime_ns, initial.st_ctime_ns) ==
                    (final.st_size, final.st_mtime_ns, final.st_ctime_ns)
                    and len(output) == final.st_size, 'file changed during read')
            return bytes(output)
        output.extend(block)
        require(len(output) <= cap, 'file exceeds byte budget')
    raise ValueError('file read iteration budget exceeded')


def read_regular(path: Path, cap: int = MAX_FILE) -> bytes:
    require(type(cap) is int and 0 <= cap <= MAX_FILE, 'invalid file byte budget')
    parent, name = _parent(path)
    try:
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                             | os.O_CLOEXEC, dir_fd=parent)
        try:
            return _read_fd(descriptor, cap)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent)


def _write_fd(descriptor: int, data: bytes) -> None:
    offset = 0
    for _ in range(MAX_STEPS):
        if offset == len(data):
            os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            require(_read_fd(descriptor, len(data)) == data, 'write readback mismatch')
            return
        written = os.write(descriptor, data[offset:offset + CHUNK])
        require(0 < written <= min(CHUNK, len(data) - offset), 'invalid write result')
        offset += written
    raise ValueError('file write iteration budget exceeded')


def _remove_created(parent: int, name: str, identity: tuple) -> None:
    try:
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    require(_identity(current)[:3] == identity[:3] and stat.S_ISREG(current.st_mode),
            'created file changed; cleanup refused')
    os.unlink(name, dir_fd=parent)
    os.fsync(parent)


def _finish_write(parent: int, name: str, descriptor: int | None,
                  identity: tuple | None, complete: bool) -> None:
    if descriptor is None:
        return
    try:
        if identity is None:
            try:
                identity = _identity(os.fstat(descriptor))
            except OSError as error:
                raise ValueError('created file identity unavailable; cleanup refused') from error
    finally:
        os.close(descriptor)
    if not complete:
        _remove_created(parent, name, identity)


def write_new(path: Path, data: bytes, maxbytes: int = MAX_FILE) -> None:
    """Create and verify, removing only identified failed writes; otherwise refuse cleanup."""
    require(type(maxbytes) is int and 0 <= maxbytes <= MAX_FILE,
            'invalid write byte budget')
    require(type(data) is bytes and len(data) <= maxbytes, 'write byte budget exceeded')
    parent, name = _parent(path)
    descriptor, identity, complete = None, None, False
    try:
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL
                             | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             0o600, dir_fd=parent)
        identity = _identity(os.fstat(descriptor))
        os.fchmod(descriptor, 0o600)
        identity = _identity(os.fstat(descriptor))
        _write_fd(descriptor, data)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        require(_identity(current) == identity, 'created file identity changed')
        os.fsync(parent)
        complete = True
    finally:
        try:
            _finish_write(parent, name, descriptor, identity, complete)
        finally:
            os.close(parent)


def _json_shape(value: dict) -> None:
    stack, scalar_bytes = [(value, 0)], 0
    for _ in range(MAX_STEPS):
        if not stack:
            return
        item, depth = stack.pop()
        require(depth <= 32, 'JSON nesting budget exceeded')
        kind = type(item)
        if kind in (dict, list):
            require(len(item) <= 4096, 'JSON container budget exceeded')
            children = list(item.items()) if kind is dict else list(enumerate(item))
            require(len(stack) + len(children) * 2 <= MAX_STEPS,
                    'JSON pending node budget exceeded')
            for key, child in children:
                if kind is dict:
                    require(type(key) is str, 'JSON object keys must be strings')
                    stack.append((key, depth + 1))
                stack.append((child, depth + 1))
        else:
            require(kind in (str, int, bool, type(None)), 'unsupported JSON scalar')
            require(kind is not int or item.bit_length() <= 4096, 'JSON integer budget')
            require(kind is not str or len(item) <= MAX_JSON, 'JSON string budget')
            scalar_bytes += len(json.dumps(item, ensure_ascii=False).encode('utf-8'))
            require(scalar_bytes <= MAX_JSON, 'JSON scalar byte budget exceeded')
    require(not stack, 'JSON node budget exceeded')


def canonical(value: dict) -> bytes:
    require(type(value) is dict, 'canonical JSON root must be an object')
    _json_shape(value)
    data = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                      allow_nan=False).encode('utf-8')
    require(len(data) <= MAX_JSON, 'canonical JSON byte budget exceeded')
    return data


def _validate_process(argv: list[str], environment: dict, timeout: float, cap: int) -> None:
    require(type(argv) is list and 1 <= len(argv) <= 32, 'argv count budget exceeded')
    require(all(type(arg) is str and len(arg) <= 4096 and '\0' not in arg
                and len(os.fsencode(arg)) <= 4096
                for arg in argv), 'invalid argv value')
    require(bool(argv[0]) and sum(len(os.fsencode(arg)) for arg in argv) <= 32768,
            'argv byte budget exceeded')
    require(type(environment) is dict and len(environment) <= 64,
            'environment entry budget exceeded')
    total = 0
    for key, value in environment.items():
        require(type(key) is str and type(value) is str and bool(key)
                and len(key) <= 4096 and len(value) <= 4096
                and '=' not in key and '\0' not in key + value, 'invalid environment')
        size = len(os.fsencode(key)) + len(os.fsencode(value))
        require(size <= 4096, 'environment value budget exceeded')
        total += size
    require(total <= 32768, 'environment byte budget exceeded')
    require(type(timeout) in (float, int) and 0 < timeout <= 120 and math.isfinite(timeout),
            'invalid subprocess wall budget')
    require(type(cap) is int and 0 <= cap <= MAX_OUTPUT, 'invalid subprocess output budget')
    require(threading.active_count() == 1, 'single-threaded bootstrap required')


def _child_limits(directory: int) -> None:
    os.fchdir(directory)
    os.close(directory)
    for category, limit in ((resource.RLIMIT_AS, 1_073_741_824),
                            (resource.RLIMIT_CPU, 120),
                            (resource.RLIMIT_FSIZE, 33_554_432),
                            (resource.RLIMIT_NOFILE, 128)):
        resource.setrlimit(category, (limit, limit))


def _capture(process: subprocess.Popen, streams: dict, deadline: int, cap: int) -> str:
    with selectors.DefaultSelector() as selector:
        for stream, name in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        for _ in range(MAX_STEPS):
            remaining = deadline - time.monotonic_ns()
            if remaining <= 0:
                return 'REFUSED_TIMEOUT'
            if not selector.get_map() and process.poll() is not None:
                return 'SUCCESS' if process.returncode == 0 else 'EXIT_NONZERO'
            events = selector.select(min(0.05, remaining / 1_000_000_000))
            for key, _ in events:
                target = streams[key.data]
                try:
                    block = os.read(key.fd, min(CHUNK, cap + 1 - len(target)))
                except BlockingIOError:
                    continue
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                room = cap - len(target)
                target.extend(block[:room])
                if len(block) > room:
                    return 'REFUSED_OUTPUT_LIMIT'
        return 'REFUSED_ITERATION_LIMIT'


def _kill_group(process: subprocess.Popen) -> tuple[bool, bool]:
    try:
        os.killpg(process.pid, signal.SIGKILL)
        existed = True
    except ProcessLookupError:
        existed = False
    except OSError:
        try:
            process.kill()
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return False, False
    try:
        process.wait(timeout=2)
    except (OSError, subprocess.TimeoutExpired):
        return existed, False
    for _ in range(50):
        try:
            os.killpg(process.pid, 0)
        except ProcessLookupError:
            return existed, True
        except OSError:
            return existed, False
        time.sleep(0.01)
    return existed, False


def run_bounded(argv: list[str], cwd: Path, environment: dict,
                timeout: float = 120, cap: int = MAX_OUTPUT) -> dict:
    _validate_process(argv, environment, timeout, cap)
    started = time.monotonic_ns()
    directory = _directory(cwd)
    process, streams, status = None, {'stdout': bytearray(), 'stderr': bytearray()}, 'REFUSED_LAUNCH'
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=dict(environment), close_fds=True,
                                   pass_fds=(directory,), start_new_session=True,
                                   preexec_fn=functools.partial(_child_limits, directory))
        status = _capture(process, streams, started + int(timeout * 1_000_000_000), cap)
    except (OSError, ValueError, subprocess.SubprocessError, MemoryError):
        status = 'REFUSED_IO' if process is not None else 'REFUSED_LAUNCH'
    except KeyboardInterrupt:
        status = 'REFUSED_INTERRUPTED'
    finally:
        os.close(directory)
        if process is not None:
            descendants, clean = _kill_group(process)
            if not clean:
                status += '+CLEANUP_UNVERIFIED'
            elif descendants and status == 'SUCCESS':
                status = 'REFUSED_DESCENDANTS'
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
    return {'argv': list(argv), 'exit_code': None if process is None else process.returncode,
            'stdout': bytes(streams['stdout']), 'stderr': bytes(streams['stderr']),
            'elapsed_ns': time.monotonic_ns() - started, 'status': status}


def _rename_new(parent: int, stage: str, destination: str) -> None:
    library = ctypes.CDLL(None, use_errno=True)
    try:
        rename = library.renameat2
    except AttributeError as error:
        raise OSError(errno.ENOSYS, 'atomic create-only rename unavailable') from error
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                       ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(parent, os.fsencode(stage), parent, os.fsencode(destination), 1) != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), destination)


def atomic_publish(stage: Path, destination: Path) -> None:
    require(stage.absolute().parent == destination.absolute().parent,
            'stage and destination must share their parent')
    parent, stage_name = _parent(stage)
    stage_fd = None
    try:
        destination_name = _path_parts(destination)[-1]
        parent_meta = os.fstat(parent)
        require(parent_meta.st_uid == os.geteuid() and parent_meta.st_mode & 0o022 == 0,
                'publication parent must be owned and not group/world writable')
        stage_fd = os.open(stage_name, DIRECTORY_FLAGS, dir_fd=parent)
        initial = os.fstat(stage_fd)
        require(initial.st_uid == os.geteuid() and stat.S_IMODE(initial.st_mode) == 0o700,
                'stage must be privately owned with mode 0700')
        os.fsync(stage_fd)
        current = os.stat(stage_name, dir_fd=parent, follow_symlinks=False)
        require(_identity(current) == _identity(initial), 'stage identity changed')
        _rename_new(parent, stage_name, destination_name)
        final = os.stat(destination_name, dir_fd=parent, follow_symlinks=False)
        require(_identity(final) == _identity(initial), 'published stage identity mismatch')
        os.fsync(parent)
    finally:
        if stage_fd is not None:
            os.close(stage_fd)
        os.close(parent)
