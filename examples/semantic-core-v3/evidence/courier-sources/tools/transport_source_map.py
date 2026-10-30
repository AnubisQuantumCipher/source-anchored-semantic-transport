"""Source-mapped documentary readings: checked links, not semantic approval."""

import hashlib
import json
import re
from dataclasses import dataclass

from transport_corpus import MAX_DOCUMENT
from transport_formula import IDENT, MAX_NODES, parse_formula
from transport_wire import MAX_SOURCE, TransportError

HEADER = 'transport/readable-plan/3'
PROFILE = 'source-map/1'
MAX_QUOTES = 32
MAX_QUOTE = 4096
PATH = re.compile(r'r(?:\.[1-9][0-9]?){0,32}\Z')
POSITION = re.compile(r'(?:0|[1-9][0-9]{0,4})\Z')
DOCUMENT_POSITION = re.compile(r'(?:0|[1-9][0-9]{0,6})\Z')
SOURCE_URL = re.compile(r'https://[A-Za-z0-9.-]+(?:/[A-Za-z0-9/._~%?=&+#-]*)?\Z')


@dataclass(frozen=True)
class Origin:
    url: str
    digest: str
    begin: int
    end: int


def parse_origin(payload: str) -> Origin:
    parts = payload.split(' ')
    if len(parts) != 4 or len(parts[0]) > 2048 or SOURCE_URL.fullmatch(parts[0]) is None:
        raise TransportError('origin requires a bounded HTTPS URL, document digest and byte interval')
    if re.fullmatch(r'[0-9a-f]{64}', parts[1]) is None or not all(
            DOCUMENT_POSITION.fullmatch(value) for value in parts[2:]):
        raise TransportError('invalid origin digest or byte positions')
    begin, end = int(parts[2]), int(parts[3])
    if not 0 <= begin < end <= MAX_DOCUMENT or end - begin > MAX_SOURCE:
        raise TransportError('origin source or document budget exceeded')
    return Origin(parts[0], parts[1], begin, end)


def check_document(origin: Origin | None, source: bytes, document: bytes) -> None:
    if origin is None:
        raise TransportError('a supplied source document requires an origin declaration')
    if not isinstance(document, bytes) or not 1 <= len(document) <= MAX_DOCUMENT:
        raise TransportError('source document must be a bounded immutable byte snapshot')
    if hashlib.sha256(document).hexdigest() != origin.digest:
        raise TransportError('origin document identity mismatch')
    if document[origin.begin:origin.end] != source:
        raise TransportError('retained source differs from the declared document occurrence')


@dataclass(frozen=True)
class Passage:
    key: str
    begin: int
    end: int
    value: str


@dataclass(frozen=True)
class Support:
    passage: Passage
    operator: str
    sense: str


def passage(parts: list[str], kind: str) -> Passage:
    if len(parts) != 4 or not all(POSITION.fullmatch(item) for item in parts[1:3]):
        raise TransportError('source passage requires a key, START END and exact quotation')
    key, begin, end, quoted = parts[0], int(parts[1]), int(parts[2]), parts[3]
    if not (PATH if kind == 'support' else IDENT).fullmatch(key):
        raise TransportError('invalid source passage key')
    if not 0 <= begin < end <= MAX_SOURCE or end - begin > MAX_QUOTE:
        raise TransportError('source passage span budget exceeded')
    try:
        value = json.loads(quoted)
        if not isinstance(value, str) or len(value.encode('utf-8')) != end - begin:
            raise TransportError('source passage quotation length differs from its byte span')
    except (ValueError, UnicodeError, RecursionError) as error:
        raise TransportError('invalid source passage quotation') from error
    return Passage(key, begin, end, value)


def parse_support(payload: str) -> Support:
    parts = payload.split(' ', 5)
    if len(parts) != 6:
        raise TransportError('support requires PATH OPERATOR SENSE START END QUOTATION')
    return Support(passage([parts[0], *parts[3:]], 'support'), parts[1], parts[2])


def add_passage(value: Passage | Support, values: list) -> None:
    key = value.passage.key if isinstance(value, Support) else value.key
    keys = [item.passage.key if isinstance(item, Support) else item.key for item in values]
    if len(values) == MAX_QUOTES or key in keys:
        raise TransportError('duplicate or excessive source passages')
    values.append(value)


def operator_paths(nodes: tuple, root: int) -> dict:
    pending, paths = [(root, 'r')], {}
    for _ in range(MAX_NODES):
        if not pending:
            break
        index, path = pending.pop()
        node = nodes[index]
        if node.operator and node.operator != 'Σ':
            if PATH.fullmatch(path) is None:
                raise TransportError('source-map relation path budget exceeded')
            paths[path] = index
        pending.extend((child, path + '.' + str(position + 1))
                       for position, child in enumerate(node.children))
    if pending:
        raise TransportError('source-map traversal budget exceeded')
    return paths


def node_spans(nodes: tuple, bindings: tuple) -> list[tuple[int, int]]:
    lookup = {name: (begin, end) for name, begin, end in bindings}
    spans = []
    for node in nodes:
        if node.symbol:
            spans.append(lookup[node.symbol])
        else:
            spans.append((min(spans[child][0] for child in node.children),
                          max(spans[child][1] for child in node.children)))
    return spans


def bind_passage(item: Passage, source: bytes) -> None:
    if source[item.begin:item.end] != item.value.encode('utf-8'):
        raise TransportError('source passage occurrence mismatch: ' + item.key)


def bind_mapping(source: bytes, formula: str, senses: tuple, bindings: tuple,
                 supports: tuple[Support, ...], contexts: tuple[Passage, ...]) -> None:
    nodes, root = parse_formula(formula)
    paths = operator_paths(nodes, root)
    supplied = {item.passage.key: item for item in supports}
    if set(paths) != set(supplied):
        raise TransportError('every relational operator requires one source support; unused support is refused')
    spans, meanings = node_spans(nodes, bindings), dict(senses)
    for path, index in paths.items():
        item, node = supplied[path], nodes[index]
        bind_passage(item.passage, source)
        if (item.operator, item.sense) != (node.operator, meanings[node.operator]):
            raise TransportError('source support operator or sense differs from formula')
        begin, end = spans[index]
        if begin < item.passage.begin or end > item.passage.end:
            raise TransportError('source support does not contain every operand occurrence')
    for item in contexts:
        bind_passage(item, source)


def unrepresented(source: bytes, bindings: tuple) -> tuple[tuple[int, int], ...]:
    """Return source byte intervals outside formula leaves, not semantic coverage."""
    cursor, result = 0, []
    for _, begin, end in sorted(bindings, key=lambda item: (item[1], item[2])):
        if begin > cursor:
            result.append((cursor, begin))
        cursor = max(cursor, end)
    if cursor < len(source):
        result.append((cursor, len(source)))
    return tuple(result)
