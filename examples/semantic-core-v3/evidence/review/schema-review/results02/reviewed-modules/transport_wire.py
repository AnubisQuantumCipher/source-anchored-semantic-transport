"""Bounded, untrusted candidate encoder. SPARK decides source equality."""

import re
import os
import stat
import subprocess
import tempfile
from collections import Counter
from pathlib import Path

MAX_SOURCE = 65_536
MAX_WIRE = 131_072
MAX_SYMBOLS = 64
MAX_TOKEN = 255
MAX_CANDIDATES = 256
CORE = Path(__file__).resolve().parents[1] / "bin" / "transport_native"
WORD = re.compile(rb"[A-Za-z_][A-Za-z_0-9:/.-]{3,254}")


class TransportError(ValueError):
    """Explicit refusal: no accepted artifact may be emitted."""


def read_bounded(path: Path, cap: int) -> bytes:
    """Read at most cap plus one byte; reject before parsing or allocation."""
    if not 0 <= cap <= MAX_WIRE:
        raise TransportError("invalid read budget")
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise TransportError("input must be a regular file, not a pipe or device")
        data = stream.read(cap + 1)
    if len(data) > cap:
        raise TransportError("input limit exceeded")
    return data


def write_new(path: Path, data: bytes) -> str:
    """Publish atomically; return any post-publication cleanup warning."""
    if len(data) > MAX_WIRE:
        raise TransportError("output limit exceeded")
    stage: Path | None = None
    published = False
    warning = ''
    try:
        with tempfile.NamedTemporaryFile(prefix=".transport-stage-", dir=path.parent,
                                         delete=False) as stream:
            stage = Path(stream.name)
            if stream.write(data) != len(data):
                raise TransportError("short write")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(stage, path, follow_symlinks=False)
        published = True
    finally:
        if stage is not None:
            try:
                stage.unlink(missing_ok=True)
            except OSError as error:
                if not published:
                    raise TransportError('unpublished stage cleanup failed: ' + str(stage)) from error
                warning = 'published; stage cleanup failed: ' + str(stage) + ': ' + str(error)
    return warning


def remember(counts: Counter[bytes], token: bytes) -> None:
    if not 4 <= len(token) <= MAX_TOKEN:
        return
    if token in counts or len(counts) < MAX_CANDIDATES:
        counts[token] += 1


def dictionary(data: bytes) -> list[bytes]:
    if len(data) > MAX_SOURCE:
        raise TransportError("source limit exceeded")
    counts: Counter[bytes] = Counter()
    for line in data.splitlines(keepends=True):
        remember(counts, line)
    for match in WORD.finditer(data):
        remember(counts, match.group())
    scored = [(count * (len(word) - 2) - len(word) - 3, word)
              for word, count in counts.items()]
    scored.sort(key=lambda pair: (-pair[0], pair[1]))
    return [word for score, word in scored[:MAX_SYMBOLS] if score > 0]


def flush_literal(wire: bytearray, literal: bytearray) -> None:
    if not 0 <= len(literal) <= MAX_TOKEN:
        raise TransportError("internal literal budget exceeded")
    if literal:
        wire.extend(bytes((0, len(literal))))
        wire.extend(literal)
        literal.clear()
    if len(wire) > MAX_WIRE - 1:
        raise TransportError("wire limit exceeded")


def encode(data: bytes, symbols: list[bytes]) -> bytes:
    if len(data) > MAX_SOURCE or len(symbols) > MAX_SYMBOLS:
        raise TransportError("encoding budget exceeded")
    wire = bytearray(b"STB1")
    for index, word in enumerate(symbols):
        if not 1 <= len(word) <= MAX_TOKEN:
            raise TransportError("invalid symbol length")
        wire.extend(bytes((1, index, len(word))))
        wire.extend(word)
    order = sorted(range(len(symbols)), key=lambda i: (-len(symbols[i]), i))
    literal = bytearray()
    pos = 0
    for _ in range(MAX_SOURCE):
        if pos == len(data):
            break
        found = -1
        for index in order:
            if data.startswith(symbols[index], pos):
                found = index
                break
        if found >= 0:
            flush_literal(wire, literal)
            wire.extend(bytes((2, found)))
            pos += len(symbols[found])
        else:
            literal.append(data[pos])
            pos += 1
            if len(literal) == MAX_TOKEN:
                flush_literal(wire, literal)
    if pos != len(data):
        raise TransportError("encoding progress budget exceeded")
    flush_literal(wire, literal)
    wire.append(255)
    if len(wire) > MAX_WIRE:
        raise TransportError("wire limit exceeded")
    return bytes(wire)


def run_core(mode: str, wire: Path, target: Path | None = None) -> bytes:
    if mode not in ("decode", "check"):
        raise TransportError("unsupported core command")
    command = [str(CORE), mode, str(wire)]
    if mode == "check":
        if target is None:
            raise TransportError("source comparison requires a source")
        command.append(str(target))
    result = subprocess.run(command, capture_output=True, timeout=10, check=False)
    if result.returncode != 0:
        message = result.stderr.decode("ascii", errors="replace").strip()
        raise TransportError("core refused: " + message[:256])
    if mode == "check" and not result.stdout.startswith(b"OK "):
        raise TransportError("unrecognized core response")
    if len(result.stdout) > MAX_SOURCE:
        raise TransportError("core output limit exceeded")
    return result.stdout


def pack(data: bytes) -> bytes:
    """Candidates never certify themselves; invoke Check against source bytes."""
    if len(data) > MAX_SOURCE:
        raise TransportError("source limit exceeded")
    raw = encode(data, [])
    candidate = encode(data, dictionary(data))
    selected = candidate if len(candidate) < len(raw) else raw
    with tempfile.TemporaryDirectory(prefix="transport-check-") as scratch:
        source = Path(scratch) / "source"
        wire = Path(scratch) / "wire"
        if write_new(source, data) or write_new(wire, selected):
            raise TransportError('private comparison staging cleanup failed')
        run_core("check", wire, source)
    return selected


def unpack(data: bytes) -> bytes:
    if len(data) > MAX_WIRE:
        raise TransportError("wire limit exceeded")
    with tempfile.TemporaryDirectory(prefix="transport-decode-") as scratch:
        wire = Path(scratch) / "wire"
        if write_new(wire, data):
            raise TransportError('private decoding staging cleanup failed')
        return run_core("decode", wire)
