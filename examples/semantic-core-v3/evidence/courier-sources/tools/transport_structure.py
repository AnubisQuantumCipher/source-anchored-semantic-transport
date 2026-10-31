"""Bounded projection transport for the native binary-graph correspondence check.

This bridge is TESTED, not formally proved. It grants no meaning/type authority.
"""

import struct
import re
import subprocess
import tempfile
from pathlib import Path

from transport_wire import CORE, MAX_WIRE, TransportError, write_new

MAX_NODES = 1024
MAX_ARITY = 8
MAX_LITERAL = 4096
MAX_LITERAL_TOTAL = 65_536
OPERATORS = ('name', 'var', 'text', 'atom', 'bool', 'timing', 'pred', 'not',
             'and', 'or', 'implies', 'iff', 'forall', 'exists', 'context',
             'claim', 'within', 'shall', 'shall_not', 'should', 'may', 'bundle')
OPCODES = {name: index + 1 for index, name in enumerate(OPERATORS)}
GraphRecord = tuple[str, bytes, tuple[int, ...]]


def graph_bytes(records: list[GraphRecord], root: int) -> bytes:
    if not 0 <= root < len(records) <= MAX_NODES:
        raise TransportError('projection node/root budget exceeded')
    output = bytearray(b'STG1' + struct.pack('>HH', len(records), root + 1))
    used = 0
    for index, (operator, literal, children) in enumerate(records):
        if operator not in OPCODES or len(children) > MAX_ARITY:
            raise TransportError('invalid projected operator/arity')
        if len(literal) > MAX_LITERAL or any(child < 0 or child >= index for child in children):
            raise TransportError('invalid projected literal/child')
        used += len(literal)
        if used > MAX_LITERAL_TOTAL:
            raise TransportError('projection literal budget exceeded')
        tag = OPCODES[operator]
        if (tag <= 6 and children) or (tag > 6 and (literal or not children)):
            raise TransportError('invalid projected node shape')
        output.extend(struct.pack('>BBH', tag, len(children), len(literal)))
        for child in children:
            output.extend(struct.pack('>H', child + 1))
        output.extend(literal)
        if len(output) > MAX_WIRE:
            raise TransportError('projection wire budget exceeded')
    return bytes(output)


def map_bytes(mapping: list[int]) -> bytes:
    if not 1 <= len(mapping) <= MAX_NODES:
        raise TransportError('mapping budget exceeded')
    output = bytearray(b'STM1' + struct.pack('>H', len(mapping)))
    for target in mapping:
        if not 0 <= target < MAX_NODES:
            raise TransportError('invalid mapping target')
        output.extend(struct.pack('>H', target + 1))
    return bytes(output)


def verify_structure(original: bytes, candidate: bytes, mapping: bytes) -> None:
    if any(len(item) > MAX_WIRE for item in (original, candidate, mapping)):
        raise TransportError('structural input budget exceeded')
    with tempfile.TemporaryDirectory(prefix='transport-structure-') as scratch:
        paths = [Path(scratch) / name for name in ('original', 'candidate', 'mapping')]
        for path, data in zip(paths, (original, candidate, mapping), strict=True):
            if write_new(path, data):
                raise TransportError('private structural staging cleanup failed')
        command = [str(CORE), 'graph-check', *(str(path) for path in paths)]
        result = subprocess.run(command, capture_output=True, timeout=10, check=False)
        if result.returncode != 0:
            detail = (result.stderr + result.stdout).decode('ascii', errors='replace')
            raise TransportError('structure core refused: ' + detail.strip()[:256])
        if result.stdout != b'OK GRAPH\n' or result.stderr:
            raise TransportError('unrecognized structure core response')


def follow_path(graph: bytes, positions: tuple[int, ...]) -> int | None:
    if len(graph) > MAX_WIRE or len(positions) > MAX_NODES:
        raise TransportError('path input budget exceeded')
    if any(type(position) is not int or not 1 <= position <= MAX_ARITY for position in positions):
        raise TransportError('invalid child position')
    choices = b'STP1' + struct.pack('>H', len(positions)) + bytes(positions)
    with tempfile.TemporaryDirectory(prefix='transport-path-') as scratch:
        paths = [Path(scratch) / name for name in ('graph', 'choices')]
        for path, data in zip(paths, (graph, choices), strict=True):
            if write_new(path, data):
                raise TransportError('private path staging cleanup failed')
        command = [str(CORE), 'path', *(str(path) for path in paths)]
        result = subprocess.run(command, capture_output=True, timeout=10, check=False)
        if result.returncode != 0:
            detail = (result.stderr + result.stdout).decode('ascii', errors='replace')
            raise TransportError('path core refused: ' + detail.strip()[:256])
        match = re.fullmatch(rb'OK PATH (0|[1-9][0-9]{0,3})\n', result.stdout)
        if match is None or result.stderr:
            raise TransportError('unrecognized path core response')
        found = int(match.group(1))
        if found > MAX_NODES:
            raise TransportError('path core result exceeds node budget')
        return None if found == 0 else found - 1
