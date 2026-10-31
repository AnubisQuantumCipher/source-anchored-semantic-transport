"""Bounded process boundary for Source-Anchored Semantic Transport recipients."""

import base64
import hashlib
import json
import os
import resource
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

STREAM_CAP = 131_072
REQUEST_CAP = 65_536
WALL_SECONDS = 10
LIMITS = {'address_bytes': 268_435_456, 'cpu_seconds': 60,
          'open_files': 32, 'file_bytes': STREAM_CAP, 'wall_seconds': WALL_SECONDS}
FROZEN_RUNTIME_SHA256 = '683527cac47425759c750cbc5190acbd249fcec43a79b3bea99727fb51688819'


class RequestError(ValueError):
    """Bounded prefix retained when a request cannot be read completely."""

    def __init__(self, message: str, data: bytes):
        super().__init__(message)
        self.data = data


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(path: Path, cap: int = STREAM_CAP) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, 'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode), 'regular file required')
        value = stream.read(cap + 1)
    require(len(value) <= cap, 'read byte budget exceeded')
    return value


def write(path: Path, data: bytes, cap: int = STREAM_CAP) -> None:
    require(type(data) is bytes and len(data) <= cap, 'write byte budget exceeded')
    with path.open('xb') as stream:
        require(stream.write(data) == len(data), 'short log write')
        stream.flush()
        os.fsync(stream.fileno())
    require(read(path, cap) == data, 'log readback mismatch')


def canonical(value: object) -> bytes:
    value = json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(',', ':'), allow_nan=False).encode('ascii')
    require(len(value) <= 1_048_576, 'JSON output budget exceeded')
    return value


def unique(pairs: list) -> dict:
    require(len(pairs) <= 256 and len(dict(pairs)) == len(pairs), 'duplicate or excess JSON fields')
    return dict(pairs)


def json_value(data: bytes, cap: int = STREAM_CAP) -> object:
    require(type(data) is bytes and 0 < len(data) <= cap, 'JSON input budget exceeded')
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            require(depth <= 12, 'JSON depth exceeded')
        elif byte in (93, 125):
            depth -= 1
            require(depth >= 0, 'malformed JSON')
    require(not quoted and depth == 0, 'truncated JSON')
    return json.loads(data.decode('utf-8'), object_pairs_hook=unique)


def stdin_bytes(cap: int) -> bytes:
    if sys.stdin.isatty():
        return b''
    selector = selectors.PollSelector()
    selector.register(0, selectors.EVENT_READ)
    result = bytearray()
    deadline = time.monotonic() + 1
    try:
        for _ in range(REQUEST_CAP + 2):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(max(0, remaining)):
                raise RequestError('request stdin timeout', bytes(result))
            chunk = os.read(0, min(4096, cap + 1 - len(result)))
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            if len(result) > cap:
                raise RequestError('request stdin byte budget exceeded', bytes(result))
    finally:
        selector.close()
    raise RequestError('request stdin progress budget exceeded', bytes(result))


def child_limits() -> None:
    resource.setrlimit(resource.RLIMIT_AS, (LIMITS['address_bytes'],) * 2)
    resource.setrlimit(resource.RLIMIT_CPU, (LIMITS['cpu_seconds'],) * 2)
    resource.setrlimit(resource.RLIMIT_NOFILE, (LIMITS['open_files'],) * 2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (LIMITS['file_bytes'],) * 2)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def terminate_group(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=2)


def run_process(argv: list[str], cwd: Path, env: dict, log_directory: Path) -> dict:
    """Internal process seam; recipient callers cannot supply argv through CLI."""
    stdout_path, stderr_path = log_directory / 'stdout.bin', log_directory / 'stderr.bin'
    started, timed_out = time.perf_counter_ns(), False
    deadline = time.monotonic() + WALL_SECONDS
    failure = ''
    with stdout_path.open('xb') as stdout, stderr_path.open('xb') as stderr:
        try:
            process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                       stdout=stdout, stderr=stderr, start_new_session=True,
                                       preexec_fn=child_limits, close_fds=True)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, WALL_SECONDS)
            code = process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            timed_out = True
            terminate_group(process)
            code = process.returncode
        except TimeoutError:
            raise
        except (OSError, subprocess.SubprocessError) as error:
            failure, code = str(error), None
        finally:
            if 'process' in locals():
                terminate_group(process)
    out, err = read(stdout_path), read(stderr_path)
    cap_hit = len(out) >= STREAM_CAP or len(err) >= STREAM_CAP
    return {'argv': argv, 'cwd': str(cwd), 'env': env, 'stdin_base64': '', 'stdin_bytes': 0,
            'stdout_base64': base64.b64encode(out).decode('ascii'),
            'stderr_base64': base64.b64encode(err).decode('ascii'),
            'stdout_sha256': sha(out), 'stderr_sha256': sha(err),
            'stdout_bytes': len(out), 'stderr_bytes': len(err), 'exit': code,
            'launch_error': failure,
            'wall_timeout': timed_out, 'stream_cap_hit': cap_hit,
            'capture_accepted': code == 0 and not timed_out and not cap_hit,
            'latency_ns': time.perf_counter_ns() - started,
            'limits': dict(LIMITS, wall_seconds=WALL_SECONDS),
            'process_tree_policy': 'SIGKILL entire new process group after exit, timeout or refusal.'}


def compatibility_runtime(tools: Path) -> dict:
    """Accept only the explicitly pinned current decoder runtime closure."""
    data = read(tools.parent / 'RUNTIME.json')
    require(sha(data) == FROZEN_RUNTIME_SHA256, 'unrecognized trusted decoder runtime')
    runtime = json_value(data)
    files = runtime['files']
    require(type(files) is list and len(files) == 22, 'invalid fixed runtime file count')
    names = set()
    for item in files:
        require(type(item) is dict and set(item) == {'path', 'bytes', 'sha256'}, 'invalid runtime fields')
        path = Path(item['path'])
        require(not path.is_absolute() and '..' not in path.parts, 'unsafe runtime path')
        require(item['path'] not in names, 'duplicate runtime path')
        names.add(item['path'])
        value = read(tools.parent / path, 4_194_304)
        require(len(value) == item['bytes'] and sha(value) == item['sha256'], 'trusted decoder source mismatch')
    return runtime


def compatibility_child(arguments: list[str]) -> int:
    """Pinned compatibility boundary for the declared current decoder."""
    require(len(arguments) in (5, 8), 'invalid fixed child argument count')
    tools, action = arguments[:2]
    require(action in ('inspect', 'validate', 'recover'), 'unsupported fixed child action')
    require((action == 'recover') == (len(arguments) == 8), 'fixed child shape mismatch')
    child_limits()
    compatibility_runtime(Path(tools))
    sys.path.insert(0, tools)
    import transport_cli
    sys.argv = ['trusted-transport-decoder'] + arguments[1:]
    return transport_cli.main()


if __name__ == '__main__':
    require(len(sys.argv) >= 3 and sys.argv[1] == '--child', 'only fixed child entry is available')
    sys.exit(compatibility_child(sys.argv[2:]))
