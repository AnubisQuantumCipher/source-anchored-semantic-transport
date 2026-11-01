"""Bounded informational graph checks for QUORUM.

This internal component accepts decoded, caller-owned builtin values. It is not
a raw-byte parser, source-identity verifier, public replay result or authority
decision. Do not mutate inputs concurrently with a call. See the pinned
development contract in examples/quorum-graph-v1/contract.json.
"""

MAX_NODES = 32
MAX_EDGES = 64
MAX_PREDECESSORS = 8
GRAPH_SCHEMA = 'quorum/graph-development/1'
GRAPH_FIELDS = ('schema', 'node_count', 'edges', 'changed_nodes')


def _error(code: str) -> dict[str, object]:
    return {'status': 'error', 'error': code}


def _header_error(graph: object) -> str:
    if type(graph) is not dict:
        return 'G_OBJECT'
    # Constant probes preserve missing-before-unknown precedence without walking
    # arbitrary extra keys or copying an unbounded caller dictionary.
    for field in GRAPH_FIELDS:
        if field not in graph:
            return 'G_MISSING_FIELD'
    if len(graph) != len(GRAPH_FIELDS):
        return 'G_UNKNOWN_FIELD'
    if type(graph['schema']) is not str or graph['schema'] != GRAPH_SCHEMA:
        return 'G_SCHEMA'
    if type(graph['node_count']) is not int:
        return 'G_NODE_COUNT_TYPE'
    if not 0 <= graph['node_count'] <= MAX_NODES:
        return 'G_NODE_COUNT_RANGE'
    return ''


def _index_error(index: object, count: int, prefix: str) -> str:
    if type(index) is not int:
        return prefix + '_INDEX_TYPE'
    if not 0 <= index < count:
        return prefix + '_INDEX_RANGE'
    return ''


def _edges_error(edges: object, count: int) -> str:
    if type(edges) is not list:
        return 'G_EDGES_TYPE'
    if len(edges) > MAX_EDGES:
        return 'G_EDGE_LIMIT'
    seen = []
    for edge in edges:  # At most MAX_EDGES, each edge checked before access.
        if type(edge) is not list or len(edge) != 2:
            return 'G_EDGE_SHAPE'
        for index in edge:
            error = _index_error(index, count, 'G')
            if error:
                return error
        pair = (edge[0], edge[1])
        if pair in seen:
            return 'G_DUPLICATE_EDGE'
        seen.append(pair)
    return ''


def _changes_error(changes: object, count: int) -> str:
    if type(changes) is not list:
        return 'G_CHANGED_TYPE'
    if len(changes) > MAX_NODES:
        return 'G_CHANGED_LIMIT'
    seen = [False] * MAX_NODES
    for index in changes:
        error = _index_error(index, count, 'G')
        if error:
            return error
        if seen[index]:
            return 'G_DUPLICATE_CHANGED'
        seen[index] = True
    return ''


def _topological_order(count: int, edges: tuple) -> list[int] | None:
    """Private helper: callers have validated all indices and fixed bounds."""
    assert 0 <= count <= MAX_NODES and len(edges) <= MAX_EDGES
    pending = [0] * MAX_NODES
    emitted = [False] * MAX_NODES
    for dependent, _ in edges:
        pending[dependent] += 1
    order = []
    for _ in range(count):
        ready = None
        for index in range(count):
            if not emitted[index] and pending[index] == 0:
                ready = index
                break
        if ready is None:
            return None
        emitted[ready] = True
        order.append(ready)
        for dependent, required in edges:
            if required == ready:
                assert pending[dependent] > 0
                pending[dependent] -= 1
    assert len(order) == count
    return order


def reverse_reachable(graph: object) -> dict[str, object]:
    """Return seeds and their declared dependents, or an explicit refusal.

Every component is checked for cycles, even when it has no changed node.
No result here establishes source applicability, truth or current authority.
"""
    error = _header_error(graph)
    if error:
        return _error(error)
    count = graph['node_count']
    error = _edges_error(graph['edges'], count)
    if error:
        return _error(error)
    error = _changes_error(graph['changed_nodes'], count)
    if error:
        return _error(error)
    edges = tuple((edge[0], edge[1]) for edge in graph['edges'])
    changes = tuple(graph['changed_nodes'])
    order = _topological_order(count, edges)
    if order is None:
        return _error('G_CYCLE')
    affected = [False] * MAX_NODES
    for index in changes:
        affected[index] = True
    # All requirements precede each dependent in order, so no recursive walk
    # or input-order-dependent single edge scan is needed.
    for node in order:
        for dependent, required in edges:
            if dependent == node and affected[required]:
                affected[node] = True
    return {'status': 'ok', 'nodes': [i for i in range(count) if affected[i]]}


def predecessor_order(predecessors: object) -> dict[str, object]:
    """Return the smallest-ready-first event order; it is not version currency."""
    if type(predecessors) is not list:
        return _error('P_ARRAY')
    if len(predecessors) > MAX_PREDECESSORS:
        return _error('P_LIMIT')
    count = len(predecessors)
    for predecessor in predecessors:
        if predecessor is not None:
            error = _index_error(predecessor, count, 'P')
            if error:
                return _error(error)
    edges = tuple((i, predecessor) for i, predecessor in enumerate(predecessors)
                  if predecessor is not None)
    order = _topological_order(count, edges)
    if order is None:
        return _error('P_CYCLE')
    return {'status': 'ok', 'order': order}
