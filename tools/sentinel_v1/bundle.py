"""Versioned semantic evidence document, carried by the existing SAST codec.

SNE1 is inert indexed data, not an alternative ZIP/transport implementation.
Base packages are explicit dependencies supplied out of band; no fetching or
execution is selected by this document. The underlying SAST whole-source hash
binds header, index and every raw entry without a circular self-hash.
"""
from pathlib import Path
import os
import tempfile
from .common import (METADATA, REGISTRY, canonical, capture_registry, digest, fields,
                     hash_checked, identity, integer, label, parse, require)
from .bindings import graph_from_registry, registry_root

PROFILE = 'sentinel/semantic-evidence-document/1'
PAYLOAD_CAP = 20_971_520
INDEX_CAP = 65_536
RECORDS = ('GRAPH', 'CENSUS', 'CHALLENGES', 'ADMISSION', 'REFINEMENT',
           'ASSESSMENTS', 'ASSESSMENT_ADMISSION', 'FORMAL', 'LOCATORS', 'REVISIONS', 'NATIVE_RECEIPT')


def base_checked(row):
    fields(row, ('package_id', 'source_sha256', 'source_bytes', 'archive_sha256',
                 'archive_bytes', 'decoder_identity_sha256', 'decoder_source_sha256'))
    for key in ('package_id', 'source_sha256', 'archive_sha256', 'decoder_identity_sha256',
                'decoder_source_sha256'):
        hash_checked(row[key])
    integer(row['source_bytes'], 0, 1_073_741_824)
    integer(row['archive_bytes'], 1, 2_147_483_648)


def records_snapshot(records):
    require(type(records) is dict and 1 <= len(records) <= len(RECORDS), 'semantic record count')
    snapshot = {}
    try:
        entries = iter(records.items())
        for index in range(len(RECORDS) + 1):
            pair = next(entries, None)
            if pair is None:
                require('GRAPH' in snapshot, 'meaning graph required')
                return snapshot
            require(index < len(RECORDS), 'semantic record count')
            name, raw = pair
            require(name in RECORDS and type(raw) is bytes and 0 < len(raw) <= METADATA,
                    'semantic record name or immutable byte bound')
            snapshot[name] = raw
    except RuntimeError as error:
        raise ValueError('semantic records mutated during snapshot') from error
    raise ValueError('semantic record count bound')


def content_checked(records, artifacts, bases):
    require(type(bases) is list and 1 <= len(bases) <= 64, 'base dependency count')
    seen = set()
    for row in bases:
        base_checked(row)
        require(row['package_id'] not in seen, 'duplicate base dependency')
        seen.add(row['package_id'])
    graph_key = digest(records['GRAPH'])
    require(graph_key in artifacts or len(artifacts) < 256, 'graph consumes registry capacity')
    graph_bytes = 0 if graph_key in artifacts else len(records['GRAPH'])
    require(sum(len(raw) for raw in artifacts.values()) + graph_bytes <= REGISTRY, 'graph consumes registry bytes')
    combined = dict(artifacts)
    require(graph_key not in combined or combined[graph_key] == records['GRAPH'], 'graph artifact conflict')
    combined[graph_key] = records['GRAPH']
    graph = graph_from_registry(graph_key, combined)
    used = set()
    for source in graph['source_set']:
        matches = [row for row in bases if row['package_id'] == source['source']['package_id']
            and row['source_sha256'] == source['source']['sha256']
            and row['source_bytes'] == source['source']['bytes']]
        require(len(matches) == 1, 'graph source has no declared base package')
        used.add(matches[0]['package_id'])
    require(used == seen, 'undeclared or unused base package dependency')
    optional_checked(records, combined, graph)
    return graph


def optional_checked(records, combined, graph):
    challenge_value = None
    if 'CHALLENGES' in records or 'ADMISSION' in records:
        require('CHALLENGES' in records and 'ADMISSION' in records, 'paired challenge admission required')
        from .challenges import checked_set
        challenge_value, _snapshot, _oracles = checked_set(records['CHALLENGES'],
            digest(records['CHALLENGES']), combined, registry_root(combined),
            records['ADMISSION'], digest(records['ADMISSION']))
        current_graph_record(challenge_value, graph)
    if 'REFINEMENT' in records:
        replay_history(records, combined, graph, challenge_value)
    if 'ASSESSMENTS' in records or 'ASSESSMENT_ADMISSION' in records:
        require('ASSESSMENTS' in records and 'ASSESSMENT_ADMISSION' in records, 'paired assessment admission')
        from .assessments import checked_assessments
        checked_assessments(records['ASSESSMENTS'], digest(records['ASSESSMENTS']), combined,
            registry_root(combined), records['ASSESSMENT_ADMISSION'], digest(records['ASSESSMENT_ADMISSION']))
        current_graph_record(parse(records['ASSESSMENTS']), graph)
    if 'CENSUS' in records:
        from .census import build_census
        value = parse(records['CENSUS'])
        require(type(value) is dict and value.get('schema') == 'sentinel/semantic-census/1', 'census schema')
        binding = value.get('binding')
        require(type(binding) is dict and type(binding.get('representation')) is dict, 'census binding')
        key = hash_checked(binding['representation'].get('sha256'))
        require(key in combined, 'complete census reading unavailable')
        expected = build_census(combined[key], canonical(binding), canonical(value.get('regions')),
                                canonical(value.get('dependencies')))
        require(canonical(expected) == records['CENSUS'], 'census recomputation differs')
    pointer_or_formal(records, combined)
    if 'LOCATORS' in records or 'REVISIONS' in records:
        locator_sets(records, combined)


def pointer_or_formal(records, artifacts):
    from .assessments import artifact
    if 'FORMAL' in records:
        from .graph import checked_formal_fragment
        value = parse(records['FORMAL'])
        fields(value, ('schema', 'source_pin', 'plan_pin', 'result'))
        require(value['schema'] == 'sentinel/formal-fragment/1', 'formal record schema')
        expected = checked_formal_fragment(artifact(value['source_pin'], artifacts, 65536),
                                           artifact(value['plan_pin'], artifacts, 65536))
        require(canonical(expected) == canonical(value['result']), 'formal record result mismatch')
    if 'NATIVE_RECEIPT' in records:
        value = parse(records['NATIVE_RECEIPT'])
        fields(value, ('schema', 'receipt_pin', 'source_pins_pin', 'scope_pin'))
        require(value['schema'] == 'sentinel/native-evidence-pointer/1', 'native pointer schema')
        for key in ('receipt_pin', 'source_pins_pin', 'scope_pin'):
            artifact(value[key], artifacts)


def selector_structure(node):
    from .locators import unsupported_selector, byte_span
    selector = node['selector']
    require(type(selector) is dict, 'locator selector shape')
    kind = selector.get('kind')
    if kind in ('PAGE_REGION', 'TABLE', 'FIGURE'):
        unsupported_selector(selector)
    elif kind == 'SECTION':
        fields(selector, ('kind', 'section_id')); label(selector['section_id'])
        require(node['representation']['kind'] == 'ORIGINAL', 'section coordinate kind')
    else:
        from .bindings import structural_locator
        structural_locator(canonical(node))


def locator_sets(records, artifacts):
    from .locators import locator_records, revision_records
    require('LOCATORS' in records and 'REVISIONS' in records, 'paired locator revision registries')
    value, revisions = parse(records['LOCATORS']), parse(records['REVISIONS'])
    fields(value, ('schema', 'sets')); fields(revisions, ('schema', 'keys'))
    require(value['schema'] == 'sentinel/locator-sets/1'
            and revisions['schema'] == 'sentinel/revision-pins/1', 'locator registry record version')
    require(type(value['sets']) is list and 1 <= len(value['sets']) <= 64, 'locator set bound')
    all_revisions, seen = set(), set()
    for row in value['sets']:
        fields(row, ('root', 'locator_keys', 'revision_keys'))
        root = hash_checked(row['root'])
        require(root not in seen, 'duplicate locator root'); seen.add(root)
        left = artifact_subset(row['locator_keys'], artifacts, 64)
        right = artifact_subset(row['revision_keys'], artifacts, 8)
        require(root in left, 'locator root unavailable')
        nodes = locator_records(left, root)
        revision_records(right, nodes[root])
        for node in nodes.values():
            selector_structure(node)
        all_revisions.update(right)
    require(revisions['keys'] == sorted(all_revisions), 'revision pin closure differs')
    return value['sets']


def artifact_subset(keys, artifacts, cap):
    require(type(keys) is list and 1 <= len(keys) <= cap, 'artifact subset count')
    require(keys == sorted(set(hash_checked(key) for key in keys)), 'artifact subset order/duplicate')
    require(set(keys) <= set(artifacts), 'artifact subset missing')
    return {key: artifacts[key] for key in keys}


def pack(records, artifacts, artifacts_held, bases, decoder_identity):
    records = records_snapshot(records)
    from .common import registry_snapshot
    artifacts = registry_snapshot(artifacts, artifacts_held)
    bases = parse(canonical(bases))
    graph = content_checked(records, artifacts, bases)
    entries = [(name, 'RECORD', raw) for name, raw in sorted(records.items())]
    entries += [(key, 'ARTIFACT', raw) for key, raw in sorted(artifacts.items())]
    require(len(entries) <= 256 + len(RECORDS), 'semantic item count')
    total, rows = 0, []
    for name, kind, raw in entries:
        rows.append({'id': name, 'kind': kind, 'offset': total, **identity(raw)})
        total += len(raw)
        require(total <= PAYLOAD_CAP - INDEX_CAP - 8, 'semantic payload aggregate bound')
    index = canonical({'schema': PROFILE, 'bases': bases, 'items': rows,
        'decoder_identity_sha256': hash_checked(decoder_identity),
        'graph_sha256': graph['graph_sha256'], 'registry_sha256': artifacts_held,
        'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE',
        'semantic_completeness': 'UNPROVEN', 'authentication': 'UNAUTHENTICATED'})
    require(len(index) <= INDEX_CAP, 'semantic index bound')
    return b'SNE1' + len(index).to_bytes(4, 'big') + index + b''.join(raw for _name, _kind, raw in entries)


def unpack(raw, held, decoder_identity):
    require(type(raw) is bytes and 8 < len(raw) <= PAYLOAD_CAP, 'semantic document byte bound')
    require(digest(raw) == hash_checked(held), 'semantic document identity mismatch')
    require(raw[:4] == b'SNE1', 'unsupported semantic document magic')
    size = int.from_bytes(raw[4:8], 'big')
    integer(size, 1, INDEX_CAP)
    require(8 + size <= len(raw), 'truncated semantic index')
    index = parse(raw[8:8 + size], INDEX_CAP)
    fields(index, ('schema', 'bases', 'items', 'decoder_identity_sha256', 'graph_sha256',
                   'registry_sha256', 'qualification', 'execution_authority',
                   'semantic_completeness', 'authentication'))
    require(index['schema'] == PROFILE and index['decoder_identity_sha256'] == hash_checked(decoder_identity),
            'semantic profile or decoder identity mismatch')
    require(index['qualification'] == 'NOT_QUALIFIED' and index['execution_authority'] == 'NONE'
        and index['semantic_completeness'] == 'UNPROVEN' and index['authentication'] == 'UNAUTHENTICATED',
        'semantic index assurance cannot grant qualification or authority')
    require(type(index['items']) is list and 1 <= len(index['items']) <= 256 + len(RECORDS), 'semantic item count')
    records, artifacts, cursor = {}, {}, 8 + size
    seen = set()
    for row in index['items']:
        fields(row, ('id', 'kind', 'offset', 'sha256', 'bytes'))
        name = label(row['id'])
        require(name not in seen, 'duplicate semantic item')
        seen.add(name)
        integer(row['offset'], cursor - 8 - size, cursor - 8 - size)
        integer(row['bytes'], 0, METADATA); hash_checked(row['sha256'])
        require(cursor + row['bytes'] <= len(raw), 'truncated semantic item')
        item = raw[cursor:cursor + row['bytes']]
        require(identity(item) == {'sha256': row['sha256'], 'bytes': row['bytes']}, 'semantic item altered')
        cursor += row['bytes']
        require(row['kind'] in ('RECORD', 'ARTIFACT'), 'semantic item kind')
        if row['kind'] == 'RECORD': records[name] = item
        else:
            require(len(artifacts) < 256, 'semantic registry count')
            require(name == digest(item), 'artifact item ID mismatch')
            artifacts[name] = item
    require(cursor == len(raw), 'trailing semantic document bytes')
    require(registry_root(artifacts) == index['registry_sha256'], 'semantic registry root mismatch')
    graph = content_checked(records_snapshot(records), capture_registry(artifacts), index['bases'])
    require(graph['graph_sha256'] == index['graph_sha256'], 'semantic graph substitution')
    return index, records, artifacts


def encode_with_sast(payload_path, out, title, reference, budget, native, expected_payload_sha256,
                     display_profile='COMPLETE', semantic_root=None):
    """Use SAST unchanged; its one-source hash verifies the entire evidence document."""
    from transport_document import encode_document
    from transport_document_io import read_file
    raw = read_file(Path(payload_path), PAYLOAD_CAP)
    require(digest(raw) == hash_checked(expected_payload_sha256), 'held encoder payload mismatch')
    index_size = int.from_bytes(raw[4:8], 'big')
    require(8 < len(raw) and index_size <= INDEX_CAP, 'presentation payload header')
    declared = parse(raw[8:8 + index_size], INDEX_CAP)['decoder_identity_sha256']
    require(decoder_pins(native)[1] == declared, 'SAST runtime differs from semantic declaration')
    index, records, artifacts = decode_payload(raw, digest(raw), declared, semantic_root)
    sections, lexicon, visible = presentation(index, records, artifacts, title, display_profile)
    readable = graph_lexicon(records, artifacts)
    with tempfile.TemporaryDirectory(prefix='.semantic-source-', dir=Path(out).parent) as folder:
        source = Path(folder) / 'semantic.sne1'
        write_payload(source, raw)
        result = encode_document(source, Path(out), visible, reference, budget,
                                 sections=sections, native=native)
        write_payload(Path(out) / 'semantic-graph.md', readable)
        return dict(result, semantic_display_profile=display_profile,
                    semantic_graph_lexicon=identity(readable))


def decode_with_sast(archive, share, decoder_identity, native=None, semantic_root=None):
    from transport_document import validated
    from transport_document_io import read_file
    require(decoder_pins(native)[1] == decoder_identity, 'registered SAST decoder identity mismatch')
    with validated(archive, share, native) as (path, body, package_id, _sections):
        require(body['source']['bytes'] <= PAYLOAD_CAP, 'semantic evidence document bound')
        raw = read_file(path, PAYLOAD_CAP)
        index, records, artifacts = decode_payload(raw, body['source']['sha256'], decoder_identity, semantic_root)
        return {'package_id': package_id, 'source_sha256': body['source']['sha256'],
                'index': index, 'records': records, 'artifacts': artifacts,
                'execution_authority': 'NONE', 'qualification': 'NOT_QUALIFIED',
                'admission_scope': 'BUNDLED_PINS_NOT_INDEPENDENTLY_HELD',
                'native_receipts': 'POINTERS_NOT_PROOF_VERIFICATION',
                'base_resolution': 'NOT_PERFORMED_GRAPH_ONLY'}


def presentation(index, records, artifacts, title='SENTINEL proposed graph', display_profile='COMPLETE'):
    require(type(title) is str and display_profile in ('COMPLETE', 'OVERVIEW'), 'visible display profile/type')
    graph = graph_from_registry(digest(records['GRAPH']), dict(artifacts, **{digest(records['GRAPH']): records['GRAPH']}))
    nodes = graph['nodes']
    require(any(row['kind'] == 'PROPOSITION' for row in nodes), 'visible proposition required')
    symbols = {node['id']: ('P' if node['kind'] == 'PROPOSITION' else 'N') + str(i)
               for i, node in enumerate(nodes, 1)}
    selected = nodes if display_profile == 'COMPLETE' else [node for node in nodes if node['kind'] == 'PROPOSITION']
    require(1 <= len(selected) <= 64, 'complete visible graph node bound')
    row = next(row for row in index['items'] if row['id'] == 'GRAPH' and row['kind'] == 'RECORD')
    first = 8 + len(canonical(index)) + row['offset']
    sections = display_sections(selected, symbols, first, row['bytes'], display_profile)
    if display_profile == 'COMPLETE':
        relations = [symbols[row['from']] + ':' + row['kind'] + ':' + symbols[row['to']] for row in graph['edges']]
        visible = title + ' ' + ';'.join(relations or list(symbols.values()))
        lexicon = {symbols[node['id']]: node['text'] for node in nodes}
    else:
        visible = title + ' [OVERVIEW: ' + str(len(nodes)) + ' nodes, ' + str(len(graph['edges'])) + ' relations]'
        lexicon = {'scope': 'OVERVIEW_MAIN_PROPOSITIONS_ONLY_RELATION_DETAILS_IN_GRAPH',
            'nodes': [dict(node, symbol=symbols[node['id']]) for node in nodes], 'relations': graph['edges']}
    require(0 < len(visible.encode('utf-8')) <= 255, 'complete visible graph title bound')
    return sections, lexicon, visible


def display_sections(nodes, symbols, start, size, profile):
    result = []
    for node in nodes:
        rendered = (node['kind'] + ': ' + canonical(node['text']).decode('utf-8')) if profile == 'COMPLETE' else (
            'PROPOSITION ' + node['id'] + '; full proposed text and relations: semantic-graph.md; UNPROVEN')
        require(0 < len(rendered.encode('utf-8')) <= 255, 'complete visible idea exceeds label bound')
        result.append({'id': symbols[node['id']], 'label': rendered,
                       'start': start, 'end': start + size, 'dependencies': []})
    return result


def markdown_cell(value):
    import html
    text = html.escape(value, quote=False)
    for char in '|[]`*_\\':
        text = text.replace(char, '&#' + str(ord(char)) + ';')
    return text.replace('\r', '&#13;').replace('\n', '<br>')


def graph_lexicon(records, artifacts):
    import html
    graph = graph_from_registry(digest(records['GRAPH']), dict(artifacts, **{digest(records['GRAPH']): records['GRAPH']}))
    lines = ['# Complete proposed graph lexicon\n\nNOT_QUALIFIED; authority NONE; truth/context/completeness UNPROVEN.\n',
             '\n| Symbol | ID | Kind | Origin | Documentary state | Complete proposed text |\n|---|---|---|---|---|---|\n']
    symbols = {}
    for ordinal, node in enumerate(graph['nodes'], 1):
        symbol = ('P' if node['kind'] == 'PROPOSITION' else 'N') + str(ordinal)
        symbols[node['id']] = symbol
        row = [symbol, node['id'], node['kind'], node['origin'], node['documentary_state'], node['text']]
        lines.append('| ' + ' | '.join(markdown_cell(value) for value in row) + ' |\n')
    lines.append('\n| From | Declared relation | To |\n|---|---|---|\n')
    for edge in graph['edges']:
        lines.append('| ' + ' | '.join(markdown_cell(value) for value in
            (symbols[edge['from']], edge['kind'], symbols[edge['to']])) + ' |\n')
    lines.append('\nComplete canonical graph record (inert escaped source):\n<pre>' +
                 html.escape(records['GRAPH'].decode('utf-8')) + '</pre>\n')
    raw = ''.join(lines).encode('utf-8')
    require(len(raw) <= 8_388_608, 'complete readable graph byte bound')
    return raw


def decoder_pins(native):
    import transport_document as document
    require(native is not None, 'caller-registered native required')
    path = document.native_path(native)
    return path, digest(document.canonical(document.runtime(path))), digest(document.canonical(document.MODULE_EPOCHS))


def register_bases(decoded, registrations, held_root):
    import transport_document as document
    declared = parse(canonical(decoded['index']['bases']))
    require(type(declared) is list and 1 <= len(declared) <= 64, 'base dependency count')
    for row in declared:
        base_checked(row)
    bases = {row['package_id']: row for row in declared}
    require(len(bases) == len(declared), 'duplicate registered base declaration')
    require(type(registrations) is dict and len(registrations) <= 64
            and set(registrations) == set(bases), 'complete caller base registrations required')
    captured = {}
    for key, row in registrations.items():
        fields(row, ('archive', 'share', 'native'))
        require(all(type(path) is type(Path('/')) and path.is_absolute() for path in row.values()),
                'out-of-band absolute registered paths required')
        captured[key] = dict(row)
    actual = {}
    for key, row in captured.items():
        archive_hash, size = document.file_digest(row['archive'], document.MAX_ARCHIVE)
        _native, runtime, source = decoder_pins(row['native'])
        expected = bases[key]
        require((archive_hash, size, runtime, source) == (expected['archive_sha256'],
            expected['archive_bytes'], expected['decoder_identity_sha256'], expected['decoder_source_sha256']),
            'registered base archive/runtime/source mismatch')
        actual[key] = expected
    require(digest(canonical(actual)) == hash_checked(held_root), 'independently held base registry mismatch')
    return captured


def resolve_registered(decoded, registrations, held_root):
    from .locators import resolve_locator
    from .bindings import bind_graph
    index, records, artifacts = checked_components(decoded['index'], decoded['records'], decoded['artifacts'])
    decoded = dict(index=index, records=records, artifacts=artifacts)
    registrations = register_bases(decoded, registrations, held_root)
    records, artifacts = decoded['records'], decoded['artifacts']
    sets = locator_sets(records, artifacts)
    graph = graph_from_registry(digest(records['GRAPH']), dict(artifacts, **{digest(records['GRAPH']): records['GRAPH']}))
    done, receipts, contexts, context_bytes = set(), [], [], 0
    for row in sets:
        root = parse(artifacts[row['root']])
        key = root['source']['package_id']
        require(key in registrations, 'locator package not registered')
        config = registrations[key]
        left = artifact_subset(row['locator_keys'], artifacts, 64)
        right = artifact_subset(row['revision_keys'], artifacts, 8)
        resolution = resolve_locator(config['archive'], config['share'], artifacts[row['root']],
            row['root'], left, registry_root(left), right, registry_root(right), config['native'])
        context, added = context_output(resolution, 65536 - context_bytes)
        contexts.append(context); context_bytes += added
        selected = [source for source in graph['source_set'] if all(source[field] == root[field]
                    for field in ('source', 'representation', 'revision'))]
        require(bool(selected), 'unused source resolution')
        receipt = bind_graph(dict(graph, source_set=selected), resolution)
        receipt['checked_source_ids'] = [source['id'] for source in selected]
        done.update(receipt['checked_source_ids']); receipts.append(receipt)
    require(done == {source['id'] for source in graph['source_set']}, 'graph source windows unresolved')
    register_bases(decoded, registrations, held_root)
    return {'status': 'ALL_GRAPH_WINDOWS_RESOLVED_TO_REGISTERED_BASES', 'bindings': receipts,
            'qualification': 'NOT_QUALIFIED', 'execution_authority': 'NONE',
            'semantic_completeness': 'UNPROVEN', 'contexts': contexts,
            'source_context_bytes': context_bytes, 'data_encoding': 'EXACT_BYTES_HEX_NOT_INTERPRETATION'}


def write_payload(path, raw):
    require(type(raw) is bytes and len(raw) <= PAYLOAD_CAP, 'payload write byte bound')
    fd = os.open(Path(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        offset = 0
        for _ in range(PAYLOAD_CAP // 65536 + 1):
            if offset == len(raw):
                break
            written = os.write(fd, raw[offset:offset + 65536])
            require(type(written) is int and written > 0, 'short semantic payload write')
            offset += written
        require(offset == len(raw), 'semantic payload write bound')
        os.fsync(fd)
    finally:
        os.close(fd)


def export_entries(index, records, artifacts, output):
    require(type(output) is type(Path('/')) and output.is_absolute(), 'absolute export destination')
    require(not output.exists() and not output.is_symlink(), 'create-only export destination')
    index, records, artifacts = checked_components(index, records, artifacts)
    decoded_graph = content_checked(records, artifacts, index['bases'])
    target = output
    target.mkdir(mode=0o700)
    descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        names = [('record-' + name + '.json', raw) for name, raw in sorted(records.items())]
        names += [('artifact-' + key + '.bin', raw) for key, raw in sorted(artifacts.items())]
        names.append(('index.json', canonical(index)))
        for name, raw in names:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=descriptor)
            try:
                offset = 0
                for _ in range(METADATA // 65536 + 1):
                    if offset == len(raw):
                        break
                    written = os.write(fd, raw[offset:offset + 65536])
                    require(type(written) is int and written > 0, 'short semantic export write')
                    offset += written
                require(offset == len(raw), 'semantic export write bound')
                os.fsync(fd)
            finally:
                os.close(fd)
    finally:
        os.close(descriptor)
    return {'status': 'EXPORTED_INERT_DATA_ONLY', 'files': len(names),
            'graph_sha256': decoded_graph['graph_sha256'], 'execution_authority': 'NONE'}


def checked_components(index, records, artifacts):
    """Snapshot caller containers and verify the complete indexed byte correspondence."""
    index_raw = canonical(index)
    require(len(index_raw) <= INDEX_CAP, 'semantic index bound')
    index = parse(index_raw, INDEX_CAP)
    records, artifacts = records_snapshot(records), capture_registry(artifacts)
    require(type(index.get('items')) is list and len(index['items']) <= 256 + len(RECORDS),
            'semantic item count')
    chunks, record_names, artifact_names, total = [], set(), set(), 8 + len(index_raw)
    for row in index['items']:
        fields(row, ('id', 'kind', 'offset', 'sha256', 'bytes'))
        name = label(row['id'])
        require(row['kind'] in ('RECORD', 'ARTIFACT'), 'semantic item kind')
        values, names = (records, record_names) if row['kind'] == 'RECORD' else (artifacts, artifact_names)
        require(name in values and name not in names, 'semantic component mismatch')
        names.add(name); chunks.append(values[name]); total += len(values[name])
        require(total <= PAYLOAD_CAP, 'semantic component aggregate')
    require(record_names == set(records) and artifact_names == set(artifacts), 'unindexed component')
    raw = b'SNE1' + len(index_raw).to_bytes(4, 'big') + index_raw + b''.join(chunks)
    return decode_payload(raw, digest(raw), index.get('decoder_identity_sha256'),
                          index.get('semantic_decoder_root_sha256'))


def context_output(resolution, remaining):
    require(resolution['status'] == 'RESOLVED_BYTES', 'source context unsupported')
    parts = resolution['parts']
    require(type(parts) is list and len(parts) <= 64, 'resolved context part count')
    total, output = 0, []
    for part in parts:
        require(type(part) is dict and type(part.get('data')) is bytes, 'resolved context byte type')
        start, end = part['span']
        integer(start, 0, 1_073_741_824); integer(end, start + 1, 1_073_741_824)
        raw = part['data']
        require(len(raw) == end - start and total + len(raw) <= remaining, 'source intake byte cap')
        total += len(raw)
        output.append({'span': [start, end], 'data_hex': raw.hex(), 'sha256': digest(raw)})
    return {'locator_sha256': resolution['locator_sha256'], 'source': resolution['source'],
            'representation': resolution['representation'], 'revision': resolution['revision'],
            'coordinate_kind': resolution['coordinate_kind'], 'parts': output,
            'gaps': resolution['gaps']}, total


def current_graph_record(value, graph):
    require(value['graph_sha256'] == graph['graph_sha256']
            and value['source_set_sha256'] == graph['source_set_sha256'],
            'optional record targets another current graph/source set')


def replay_history(records, artifacts, graph, challenge_value):
    from .refinement import history_checked, recheck_prior, test_contract
    require(challenge_value is not None and 'ADMISSION' in records,
            'refinement requires paired current challenges/admission for replay')
    value = history_checked(records['REFINEMENT'], digest(records['REFINEMENT']))
    require(value['source_set_sha256'] == graph['source_set_sha256']
            and value['test_contract_sha256'] == test_contract(challenge_value, parse(records['ADMISSION']))
            and value['rounds'][-1]['graph_sha256'] == graph['graph_sha256'],
            'refinement current graph/source/test contract mismatch')
    recheck_prior(value['rounds'], challenge_value, records['ADMISSION'], artifacts, registry_root(artifacts))


SEMANTIC_FILES = ('sentinel_v1/__init__.py', 'sentinel_v1/common.py', 'sentinel_v1/bindings.py', 'sentinel_v1/graph.py', 'sentinel_v1/census.py', 'sentinel_v1/challenges.py', 'sentinel_v1/refinement.py', 'sentinel_v1/assessments.py', 'sentinel_v1/locators.py', 'sentinel_v1/bundle.py', 'sentinel_v1/cli.py', 'transport_document.py', 'transport_document_io.py', 'transport_document_archive.py', 'transport_document_reading.py', 'transport_document_context.py', 'transport_semantics.py', 'transport_meaning.py', 'transport_schema.py', 'transport_operators.py', 'transport_structure.py', 'transport_references.py', 'transport_wire.py')
PROFILE_BOUND = 'sentinel/semantic-evidence-document/2'


def semantic_identity(expected):
    import sys
    main = sys.modules.get('__main__')
    require(getattr(getattr(main, '__spec__', None), 'name', None) == 'sentinel_v1.cli',
            'bound profile requires fresh admitted CLI interpreter')
    receipt = getattr(main, 'SEMANTIC_BOOTSTRAP', None)
    require(type(receipt) is dict and receipt.get('root_sha256') == hash_checked(expected)
            and getattr(main, 'SEMANTIC_FILES', None) == SEMANTIC_FILES,
            'independently held semantic bootstrap missing/mismatched')
    current = main.fixed_snapshot()
    require(current == receipt['sources'] and current['sentinel_v1/bundle.py']['sha256'] == SOURCE_EPOCH
            and current['sentinel_v1/cli.py']['sha256'] == main.SOURCE_EPOCH,
            'semantic decoder source changed since fresh trusted bootstrap')
    return {'root_sha256': expected, 'sources': current}


def pack_bound(records, artifacts, held_registry, bases, decoder_identity, semantic_root):
    semantic = semantic_identity(semantic_root)
    legacy = pack(records, artifacts, held_registry, bases, decoder_identity)
    size = int.from_bytes(legacy[4:8], 'big')
    index = parse(legacy[8:8 + size], INDEX_CAP)
    index.update(schema=PROFILE_BOUND, semantic_decoder_root_sha256=semantic['root_sha256'],
                 semantic_decoder_sources=semantic['sources'])
    header = canonical(index)
    require(len(header) <= INDEX_CAP, 'bound semantic index byte cap')
    raw = b'SNE1' + len(header).to_bytes(4, 'big') + header + legacy[8 + size:]
    require(len(raw) <= PAYLOAD_CAP, 'bound semantic payload byte cap')
    return raw


def unpack_bound(raw, held, decoder_identity, semantic_root):
    semantic = semantic_identity(semantic_root)
    require(type(raw) is bytes and 8 < len(raw) <= PAYLOAD_CAP, 'bound semantic byte cap')
    require(digest(raw) == hash_checked(held) and raw[:4] == b'SNE1', 'bound semantic identity/magic')
    size = int.from_bytes(raw[4:8], 'big'); integer(size, 1, INDEX_CAP)
    require(8 + size <= len(raw), 'truncated bound semantic header')
    index = parse(raw[8:8 + size], INDEX_CAP)
    fields(index, ('schema', 'bases', 'items', 'decoder_identity_sha256', 'graph_sha256',
        'registry_sha256', 'qualification', 'execution_authority', 'semantic_completeness',
        'authentication', 'semantic_decoder_root_sha256', 'semantic_decoder_sources'))
    require(index['schema'] == PROFILE_BOUND
        and index['semantic_decoder_root_sha256'] == semantic['root_sha256']
        and canonical(index['semantic_decoder_sources']) == canonical(semantic['sources']),
        'received semantic decoder dependency sources differ from independent held root')
    legacy = dict(index); legacy.pop('semantic_decoder_root_sha256'); legacy.pop('semantic_decoder_sources')
    legacy['schema'] = PROFILE
    header = canonical(legacy)
    data = b'SNE1' + len(header).to_bytes(4, 'big') + header + raw[8 + size:]
    _index, records, artifacts = unpack(data, digest(data), decoder_identity)
    return index, records, artifacts


def decode_payload(raw, held, decoder_identity, semantic_root):
    if semantic_root is None:
        return unpack(raw, held, decoder_identity)
    return unpack_bound(raw, held, decoder_identity, semantic_root)


from transport_document_io import loaded_epoch as _loaded_epoch
import sys as _sys
SOURCE_EPOCH = _loaded_epoch(__file__, _sys._getframe().f_code)
