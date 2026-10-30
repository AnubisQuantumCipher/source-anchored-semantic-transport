"""Source-Anchored Semantic Transport graph notation: typed, ordered syntax; no truth or authority decisions.

This prototype is TESTED rather than formally proved. Every reference points
backward. Nodes are immutable tuples. No recursive parser or expansion routine.
"""

import hashlib
import json
import re
from dataclasses import dataclass

from transport_wire import MAX_SOURCE, TransportError
from transport_structure import follow_path, graph_bytes, map_bytes, verify_structure

MAX_NODES = 1024
MAX_ARITY = 8
MAX_LITERAL = 4096
MAX_EXPANDED = 65_536
IDENT = re.compile(r"n(0|[1-9][0-9]{0,3})\Z")
LEAVES = {"name": "term", "var": "term", "text": "text", "atom": "prop",
          "bool": "prop", "timing": "deadline"}
BINARY = {"and", "or", "implies", "iff"}
MODALITIES = {'shall', 'shall_not', 'should', 'may'}
TIME_UNITS = {'ns', 'us', 'ms', 's', 'min', 'h'}


@dataclass(frozen=True)
class Node:
    op: str
    literal: str
    args: tuple[int, ...]
    kind: str
    free: frozenset[str]


def reference(token: str, count: int) -> int:
    match = IDENT.fullmatch(token)
    if match is None:
        raise TransportError("invalid reference")
    index = int(match.group(1))
    if index >= count:
        raise TransportError("forward, cyclic, or missing reference")
    return index


def leaf(op: str, payload: str) -> Node:
    if len(payload.encode("utf-8")) > MAX_LITERAL:
        raise TransportError("literal limit exceeded")
    if not payload.startswith('"'):
        raise TransportError("a leaf requires a JSON string")
    try:
        value = json.loads(payload)
        if not isinstance(value, str):
            raise TransportError("a leaf requires a string")
        value.encode("utf-8")
    except (ValueError, UnicodeError, RecursionError) as error:
        raise TransportError("invalid Unicode string literal") from error
    if op in ("name", "var", "atom") and not value:
        raise TransportError("empty identifier")
    if op == "var" and re.fullmatch(r"[a-z][a-z0-9_]{0,31}", value) is None:
        raise TransportError("invalid variable name")
    if op == 'bool' and value not in ('true', 'false'):
        raise TransportError('invalid Boolean literal')
    if op == 'timing' and value != 'unspecified':
        raise TransportError('invalid timing marker')
    free = frozenset((value,)) if op == "var" else frozenset()
    return Node(op, value, (), LEAVES[op], free)


def requirement_shape(op: str, children: tuple[Node, ...]) -> str:
    kinds = tuple(node.kind for node in children)
    if op not in MODALITIES or kinds != (
            'text', 'term', 'prop', 'prop', 'deadline', 'prop', 'context', 'text'):
        raise TransportError('invalid requirement fields')
    if re.fullmatch(r'[A-Z][A-Z0-9_-]{0,63}', children[0].literal) is None:
        raise TransportError('invalid requirement identifier')
    if children[1].op != 'name' or any(node.free for node in children):
        raise TransportError('requirement must be closed with a named actor')
    if not children[7].literal:
        raise TransportError('requirement must retain its source wording')
    return 'requirement'


def shape(op: str, children: tuple[Node, ...]) -> str:
    kinds = tuple(node.kind for node in children)
    if op in MODALITIES:
        return requirement_shape(op, children)
    if op == 'within' and kinds == ('text', 'text'):
        amount, unit = (node.literal for node in children)
        if re.fullmatch(r'(0|[1-9][0-9]{0,8})(\.[0-9]{1,9})?', amount) is None:
            raise TransportError('deadline requires an unsigned bounded decimal spelling')
        if unit not in TIME_UNITS:
            raise TransportError('unknown deadline time unit')
        return 'deadline'
    if op == "pred" and 1 <= len(kinds) <= MAX_ARITY:
        if children[0].op == "name" and all(k == "term" for k in kinds):
            return "prop"
    if (op in BINARY and kinds == ("prop", "prop")) or (
            op == "not" and kinds == ("prop",)):
        return "prop"
    if op in ("forall", "exists") and kinds == ("term", "prop"):
        if children[0].op == "var":
            return "prop"
    if op == "context" and kinds == ("text", "text", "text"):
        return "context"
    if op == "claim" and kinds == ("prop", "context", "text", "text"):
        if children[0].free:
            raise TransportError("claim contains free variables")
        return "claim"
    if op == "bundle" and 1 <= len(kinds) <= MAX_ARITY:
        if all(k in ('claim', 'requirement') for k in kinds):
            return "bundle"
    raise TransportError("unknown operator, arity, or type mismatch: " + op)


def composite(op: str, payload: str, nodes: list[Node]) -> Node:
    tokens = payload.split()
    if not 1 <= len(tokens) <= MAX_ARITY:
        raise TransportError("arity budget exceeded")
    args = tuple(reference(token, len(nodes)) for token in tokens)
    children = tuple(nodes[index] for index in args)
    kind = shape(op, children)
    free: frozenset[str] = frozenset()
    for node in children:
        free = free.union(node.free)
    if op in ("forall", "exists"):
        free = children[1].free.difference((children[0].literal,))
    return Node(op, "", args, kind, free)


def parse(data: bytes) -> tuple[list[Node], int]:
    if len(data) > MAX_SOURCE:
        raise TransportError("graph input limit exceeded")
    try:
        lines = data.decode("utf-8").split("\n")
    except UnicodeError as error:
        raise TransportError("graph must be UTF-8") from error
    if lines[-1] == "":
        lines.pop()
    lines = [line[:-1] if line.endswith("\r") else line for line in lines]
    if not lines or lines[0] != "transport/1" or len(lines) > MAX_NODES + 2:
        raise TransportError("invalid graph header or node budget")
    nodes: list[Node] = []
    requirement_ids: set[str] = set()
    root = -1
    for line in lines[1:]:
        if root >= 0:
            raise TransportError("content after root")
        if line.startswith("root "):
            root = reference(line[5:], len(nodes))
            continue
        if len(nodes) >= MAX_NODES:
            raise TransportError("node limit exceeded")
        prefix = f"n{len(nodes)}="
        if not line.startswith(prefix):
            raise TransportError("nodes must be sequential and unique")
        parts = line[len(prefix):].split(" ", 1)
        if len(parts) != 2:
            raise TransportError("missing node payload")
        op, payload = parts
        node = leaf(op, payload) if op in LEAVES else composite(op, payload, nodes)
        if node.kind == 'requirement':
            identity = nodes[node.args[0]].literal
            if identity in requirement_ids:
                raise TransportError('duplicate requirement identifier')
            requirement_ids.add(identity)
        nodes.append(node)
    if root < 0:
        raise TransportError("missing root")
    return nodes, root


def render(nodes: list[Node], root: int) -> bytes:
    if not 0 <= root < len(nodes) <= MAX_NODES:
        raise TransportError("invalid graph size or root")
    lines = ["transport/1"]
    for index, node in enumerate(nodes):
        payload = (json.dumps(node.literal, ensure_ascii=False)
                   if node.op in LEAVES else
                   " ".join(f"n{arg}" for arg in node.args))
        lines.append(f"n{index}={node.op} {payload}")
    lines.append(f"root n{root}")
    output = ("\n".join(lines) + "\n").encode("utf-8")
    if len(output) > MAX_SOURCE:
        raise TransportError("canonical graph limit exceeded")
    return output


def compaction_candidate(data: bytes) -> tuple[bytes, list[int]]:
    nodes, root = parse(data)
    unique: list[Node] = []
    indexes: dict[tuple[str, str, tuple[int, ...]], int] = {}
    remap: list[int] = []
    for node in nodes:
        args = tuple(remap[arg] for arg in node.args)
        key = (node.op, node.literal, args)
        if key not in indexes:
            indexes[key] = len(unique)
            unique.append(Node(node.op, node.literal, args, node.kind, node.free))
        remap.append(indexes[key])
    return render(unique, remap[root]), remap


def check_compaction(original: bytes, candidate: bytes, mapping: list[int]) -> None:
    """Project immutable input and emitted bytes; native acceptance is mandatory."""
    before, before_root = parse(original)
    after, after_root = parse(candidate)
    before_records = [(n.op, n.literal.encode('utf-8'), n.args) for n in before]
    after_records = [(n.op, n.literal.encode('utf-8'), n.args) for n in after]
    verify_structure(graph_bytes(before_records, before_root),
                     graph_bytes(after_records, after_root), map_bytes(mapping))


def compact(data: bytes) -> bytes:
    candidate, mapping = compaction_candidate(data)
    check_compaction(data, candidate, mapping)
    return candidate


def expand(data: bytes) -> bytes:
    nodes, root = parse(data)
    lengths: list[int] = []
    heads: list[str] = []
    for node in nodes:
        head = "(" + node.op
        if node.op in LEAVES:
            head += " " + json.dumps(node.literal, ensure_ascii=False)
        heads.append(head)
        size = len(head.encode("utf-8")) + 1
        for arg in node.args:
            size += 1 + lengths[arg]
        lengths.append(min(size, MAX_EXPANDED + 1))
    if lengths[root] > MAX_EXPANDED:
        raise TransportError("expanded expression limit exceeded")
    stack: list[int | str] = [root]
    pieces: list[str] = []
    for _ in range(MAX_EXPANDED * 2):
        if not stack:
            break
        item = stack.pop()
        if isinstance(item, str):
            pieces.append(item)
            continue
        node = nodes[item]
        pieces.append(heads[item])
        stack.append(")")
        for arg in reversed(node.args):
            stack.append(arg)
            stack.append(" ")
    if stack:
        raise TransportError("expansion step limit exceeded")
    result = "".join(pieces).encode("utf-8")
    if len(result) != lengths[root]:
        raise TransportError("expansion length invariant failed")
    return result


def inspect_path(data: bytes, path: str = '') -> dict[str, object]:
    if len(path) > MAX_NODES * 2 - 1:
        raise TransportError('path length budget exceeded')
    if path and re.fullmatch(r'[1-8](?:\.[1-8])*', path) is None:
        raise TransportError('path requires dot-separated child positions 1 through 8')
    positions = tuple(int(item) for item in path.split('.')) if path else ()
    nodes, root = parse(data)
    records = [(node.op, node.literal.encode('utf-8'), node.args) for node in nodes]
    found = follow_path(graph_bytes(records, root), positions)
    result: dict[str, object] = {'present': found is not None, 'path': list(positions),
                                'source_sha256': hashlib.sha256(data).hexdigest()}
    if found is not None:
        if not 0 <= found < len(nodes):
            raise TransportError('path result outside source graph')
        node = nodes[found]
        result.update(node=found, operator=node.op, literal=node.literal,
                      children=list(node.args))
    return result


def find_records(data: bytes, needle: str) -> list[dict[str, str | int]]:
    nodes, root = parse(data)
    if not needle or len(needle.encode("utf-8")) > MAX_LITERAL:
        raise TransportError("empty or oversized search")
    matched: list[bool] = []
    results: list[dict[str, str | int]] = []
    live = [False] * len(nodes)
    live[root] = True
    for index in range(len(nodes) - 1, -1, -1):
        if live[index]:
            for arg in nodes[index].args:
                live[arg] = True
    for index, node in enumerate(nodes):
        hit = needle in node.literal or any(matched[arg] for arg in node.args)
        matched.append(hit)
        if node.op == "claim" and hit and live[index]:
            results.append({"node": index, "declared_status": nodes[node.args[2]].literal,
                            "source": nodes[node.args[3]].literal})
        if node.kind == 'requirement' and hit and live[index]:
            results.append({'node': index, 'requirement_id': nodes[node.args[0]].literal,
                            'modality': node.op, 'source': nodes[node.args[7]].literal})
    return results
