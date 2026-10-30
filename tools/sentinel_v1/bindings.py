"""Bind proposed graph windows to verified SAST locator output, without authority."""
from .common import (CLAIMS, LINKS, NODES, canonical, capture_registry, digest, fields,
                     hash_checked, identity, integer, label, parse, require)


def registry_root(registry):
    snapshot = capture_registry(registry)
    return digest(canonical({key: identity(raw) for key, raw in snapshot.items()}))


def graph_from_registry(key, snapshot):
    from .graph import validate_graph
    hash_checked(key)
    require(key in snapshot, 'meaning graph dependency missing')
    graph = parse(snapshot[key])
    fields(graph, ('schema', 'source_set', 'nodes', 'edges', 'assurance'))
    require(type(graph['source_set']) is list and len(graph['source_set']) <= CLAIMS,
            'graph source count')
    require(type(graph['nodes']) is list and len(graph['nodes']) <= NODES, 'graph node count')
    keys = set()
    for source in graph['source_set']:
        fields(source, ('id', 'source', 'revision', 'representation', 'window'))
        fields(source['window'], ('start', 'end', 'sha256'))
        keys.add(hash_checked(source['window']['sha256']))
    for node in graph['nodes']:
        require(type(node) is dict, 'graph node record type')
        for field in ('support_records', 'refutation_records'):
            require(type(node.get(field)) is list and len(node[field]) <= LINKS,
                    'documentary record list')
            for pin in node[field]:
                keys.add(hash_checked(pin))
    require(keys <= set(snapshot), 'graph evidence artifact missing')
    artifacts = {pin: snapshot[pin] for pin in keys}
    return validate_graph(snapshot[key], artifacts, registry_root(artifacts), key)


def contiguous_part(parts, start, end):
    for part in parts:
        first, last = part['span']
        if first <= start < end <= last:
            return part['data'][start - first:end - first]
    raise ValueError('required window missing or disjoint in resolved context')


def bind_graph(graph, resolution):
    require(resolution['status'] == 'RESOLVED_BYTES', 'graph evidence unsupported')
    for source in graph['source_set']:
        require(all(source[key] == resolution[key] for key in ('source', 'representation', 'revision')),
                'graph source, revision or coordinate identity differs from package')
        window = source['window']
        raw = contiguous_part(resolution['parts'], window['start'], window['end'])
        require(digest(raw) == window['sha256'], 'graph window differs from resolved source')
    return {'schema': 'sentinel/graph-source-binding/1',
        'graph_sha256': graph['graph_sha256'], 'source_set_sha256': graph['source_set_sha256'],
        'locator_sha256': resolution['locator_sha256'], 'package_id': resolution['package_id'],
        'source': resolution['source'], 'coordinate_kind': resolution['coordinate_kind'],
        'status': 'CHECKED_WINDOW_BYTES_TO_VALIDATED_PACKAGE',
        'interpretation_entailment': 'UNPROVEN', 'context_adequacy': 'UNPROVEN',
        'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE'}


def structural_locator(raw):
    from .locators import locator_checked, byte_span
    node = locator_checked(raw)
    selector = node['selector']
    require(type(selector) is dict, 'target selector record')
    kind = selector.get('kind')
    require(kind in ('SOURCE_BYTES', 'DERIVED_UTF8', 'CODE_BYTES', 'PAGE_TEXT'),
            'contiguous target selector required')
    names = ('kind', 'start', 'end', 'quote_sha256')
    extra = ('segment_id', 'page') if kind == 'PAGE_TEXT' else ('language',) if kind == 'CODE_BYTES' else ()
    fields(selector, names + extra)
    expected = 'DERIVED_UTF8' if kind in ('DERIVED_UTF8', 'PAGE_TEXT') else 'ORIGINAL'
    require(node['representation']['kind'] == expected, 'target coordinate kind')
    byte_span(selector, node['representation']['bytes'])
    if kind == 'PAGE_TEXT':
        label(selector['segment_id']); integer(selector['page'], 1, 16_384)
    if kind == 'CODE_BYTES':
        label(selector['language'])
    return node


def target_in_graph(graph, node_id, locator):
    locator = structural_locator(canonical(locator))
    nodes = [row for row in graph['nodes'] if row['id'] == node_id]
    require(len(nodes) == 1, 'challenge target node missing')
    sources = {row['id']: row for row in graph['source_set']}
    selector = locator.get('selector', {})
    require(type(selector) is dict and selector.get('kind') in
            ('SOURCE_BYTES', 'DERIVED_UTF8', 'CODE_BYTES', 'PAGE_TEXT'), 'target selector')
    for evidence in nodes[0]['evidence']:
        source = sources[evidence['source_id']]
        if all(source[key] == locator.get(key) for key in ('source', 'representation', 'revision')):
            if (evidence['start'], evidence['end'], evidence['quote_sha256']) == (
                    selector.get('start'), selector.get('end'), selector.get('quote_sha256')):
                return
    raise ValueError('challenge locator not bound to the target node evidence')
