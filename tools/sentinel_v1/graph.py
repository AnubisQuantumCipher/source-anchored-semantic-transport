"""Typed interpretation proposals over immutable supplied windows, no truth gate."""
from .common import (CLAIMS, EDGES, JOB_BYTES, LINKS, METADATA, NODES, SentinelError, canonical,
                     digest, fields, hash_checked, identity, integer, label, parse,
                     registry_snapshot, require)
from .census import acyclic, binding_checked

PROFILE = 'sentinel/meaning-graph/1'
KINDS = ('ENTITY', 'REFERENCE', 'EVENT', 'PROPOSITION', 'PREDICATE', 'ARGUMENT',
         'MODALITY', 'CONDITION', 'EXCEPTION', 'QUANTIFIER', 'TIME', 'ATTRIBUTION',
         'NEGATION', 'UNCERTAINTY', 'REVISION', 'EVIDENCE', 'CONTRADICTION',
         'ALTERNATIVE', 'OPAQUE', 'DOCUMENT_STRUCTURE')
ORIGINS = ('SOURCE_OCCURRENCE', 'AUTHOR_ASSERTION', 'ATTRIBUTED', 'AGENT_INFERENCE',
           'MODEL_RELATIVE', 'EXTERNAL_EVIDENCE')
RELATIONS = ('HAS_ARGUMENT', 'REFERS_TO', 'MODIFIES', 'CONDITION_OF', 'EXCEPTION_TO',
             'QUANTIFIES', 'TEMPORALLY_BEFORE', 'ATTRIBUTED_TO', 'NEGATES',
             'UNCERTAINTY_OF', 'REVISES', 'SUPPORTS', 'CONTRADICTS', 'ALTERNATIVE_TO',
             'DEPENDS_ON')
TERM_KINDS = ('ARGUMENT', 'ENTITY', 'REFERENCE')
CONTENT_KINDS = ('PROPOSITION', 'EVENT', 'PREDICATE', *TERM_KINDS)
EDGE_TYPES = {
    'HAS_ARGUMENT': (('PREDICATE', 'EVENT'), TERM_KINDS),
    'REFERS_TO': (('REFERENCE',), KINDS),
    'MODIFIES': (('MODALITY', 'QUANTIFIER', 'TIME'), CONTENT_KINDS),
    'CONDITION_OF': (('CONDITION', 'PROPOSITION'), ('PROPOSITION', 'EVENT', 'MODALITY')),
    'EXCEPTION_TO': (('EXCEPTION',), ('PROPOSITION', 'EVENT', 'MODALITY')),
    'QUANTIFIES': (('QUANTIFIER',), CONTENT_KINDS),
    'TEMPORALLY_BEFORE': (('TIME', 'EVENT'), ('TIME', 'EVENT')),
    'ATTRIBUTED_TO': (('PROPOSITION', 'EVENT'), ('ATTRIBUTION',)),
    'NEGATES': (('NEGATION',), ('PROPOSITION', 'EVENT', 'PREDICATE', 'MODALITY', 'CONDITION')),
    'UNCERTAINTY_OF': (('UNCERTAINTY',), ('PROPOSITION', 'EVENT', 'PREDICATE', 'MODALITY',
        'CONDITION', 'EXCEPTION', 'REFERENCE', 'ATTRIBUTION')),
    'REVISES': (('REVISION',), ('REVISION',)),
    'SUPPORTS': (KINDS, KINDS), 'CONTRADICTS': (KINDS, KINDS),
    'ALTERNATIVE_TO': (KINDS, KINDS), 'DEPENDS_ON': (KINDS, KINDS)}
ASSURANCE = {'execution_authority': 'NONE', 'qualification': 'NOT_QUALIFIED',
             'interpretation_entailment': 'UNPROVEN', 'semantic_completeness': 'UNPROVEN',
             'context_adequacy': 'UNPROVEN', 'world_truth': 'UNPROVEN',
             'package_binding': 'UNPROVEN'}


def source_set_checked(value, snapshot):
    require(type(value) is list and 1 <= len(value) <= CLAIMS, 'source set count bound')
    sources, used = {}, set()
    for row in value:
        fields(row, ('id', 'source', 'revision', 'representation', 'window'))
        name = label(row['id'])
        require(name not in sources, 'duplicate source set ID')
        binding_checked({key: row[key] for key in ('source', 'revision', 'representation')})
        window, representation = row['window'], row['representation']
        fields(window, ('start', 'end', 'sha256'))
        integer(window['start'], 0, representation['bytes'])
        integer(window['end'], window['start'] + 1, representation['bytes'])
        require(window['end'] - window['start'] <= JOB_BYTES, 'source window byte bound')
        key = hash_checked(window['sha256'])
        require(key in snapshot, 'source window missing')
        raw = snapshot[key]
        require(len(raw) == window['end'] - window['start'], 'source window size mismatch')
        if window['start'] == 0 and window['end'] == representation['bytes']:
            require(key == representation['sha256'], 'whole representation mismatch')
        if representation['kind'] == 'DERIVED_UTF8':
            utf8(raw)
        sources[name] = row
        used.add(key)
    return sources, used


def utf8(raw):
    try:
        raw.decode('utf-8')
    except UnicodeError as error:
        raise SentinelError('derived graph evidence requires complete UTF8 boundaries') from error


def evidence_checked(value, sources, snapshot):
    require(type(value) is list and 1 <= len(value) <= LINKS, 'node evidence count')
    seen, total = set(), 0
    for row in value:
        fields(row, ('source_id', 'start', 'end', 'quote_sha256'))
        name = label(row['source_id'])
        require(name in sources, 'node evidence source missing')
        source, start, end = sources[name], row['start'], row['end']
        window = source['window']
        integer(start, window['start'], window['end'])
        integer(end, start + 1, window['end'])
        require((name, start, end) not in seen, 'duplicate evidence span')
        seen.add((name, start, end))
        total += end - start
        require(total <= JOB_BYTES, 'node evidence byte bound')
        raw = snapshot[window['sha256']][start - window['start']:end - window['start']]
        require(digest(raw) == hash_checked(row['quote_sha256']), 'node quote mismatch')
        if source['representation']['kind'] == 'DERIVED_UTF8':
            utf8(raw)
    return {row['source_id'] for row in value}


def documentary_records(keys, polarity, claim, sources, snapshot):
    require(type(keys) is list and len(keys) <= LINKS, 'documentary record count')
    seen, used_sources = set(), set()
    for key in keys:
        hash_checked(key)
        require(key not in seen and key in snapshot, 'duplicate or missing documentary record')
        record = parse(snapshot[key], 32_768)
        fields(record, ('schema', 'claim_id', 'polarity', 'evidence', 'note'))
        require(record['schema'] == 'sentinel/documentary-record/1', 'documentary record version')
        require(record['claim_id'] == claim and record['polarity'] == polarity,
                'documentary record target or polarity mismatch')
        require(type(record['note']) is str and len(record['note'].encode('utf-8')) <= 4096,
                'documentary record note bound')
        used_sources.update(evidence_checked(record['evidence'], sources, snapshot))
        seen.add(key)
    return seen, used_sources


def nodes_checked(value, sources, snapshot):
    require(type(value) is list and 1 <= len(value) <= NODES, 'graph node count')
    names, used, records, claims = set(), set(), set(), 0
    for row in value:
        fields(row, ('id', 'kind', 'origin', 'text', 'evidence', 'documentary_state', 'assurance',
                     'support_records', 'refutation_records'))
        name = label(row['id'])
        require(name not in names, 'duplicate graph node')
        require(row['kind'] in KINDS and row['origin'] in ORIGINS, 'node kind or origin')
        require(type(row['text']) is str and len(row['text'].encode('utf-8')) <= 4096,
                'node proposal text byte bound')
        require(row['documentary_state'] in ('SUPPORTED', 'REFUTED', 'BOTH', 'NEITHER'),
                'documentary state')
        require(row['assurance'] == ASSURANCE, 'node assurance cannot be promoted')
        support, support_sources = documentary_records(row['support_records'], 'SUPPORT', name,
                                                        sources, snapshot)
        refutation, refutation_sources = documentary_records(row['refutation_records'], 'REFUTATION',
                                                              name, sources, snapshot)
        expected = 'BOTH' if support and refutation else ('SUPPORTED' if support else
                   ('REFUTED' if refutation else 'NEITHER'))
        require(row['documentary_state'] == expected, 'documentary state lacks declared records')
        records.update(support | refutation)
        used.update(support_sources | refutation_sources)
        claims += row['kind'] == 'PROPOSITION'
        require(claims <= CLAIMS, 'proposition count bound')
        used.update(evidence_checked(row['evidence'], sources, snapshot))
        names.add(name)
    require(used == set(sources), 'unused source set records')
    return names, records


def edges_checked(value, kinds):
    require(type(value) is list and len(value) <= EDGES, 'graph edge count')
    seen = set()
    for row in value:
        fields(row, ('from', 'to', 'kind'))
        left, right = label(row['from']), label(row['to'])
        require(left in kinds and right in kinds and left != right, 'graph edge target')
        require(row['kind'] in RELATIONS, 'graph relation kind')
        source_types, target_types = EDGE_TYPES[row['kind']]
        require(kinds[left] in source_types and kinds[right] in target_types,
                'graph relation endpoint sort')
        edge = (left, right, row['kind'])
        require(edge not in seen, 'duplicate graph edge')
        seen.add(edge)
    for kind in ('DEPENDS_ON', 'REVISES', 'TEMPORALLY_BEFORE'):
        acyclic(set(kinds), {(left, right) for left, right, relation in seen if relation == kind})


def validate_graph(raw, artifacts, expected_artifacts_sha256, expected_graph_sha256):
    require(type(raw) is bytes and 0 < len(raw) <= METADATA, 'graph immutable byte bound')
    require(digest(raw) == hash_checked(expected_graph_sha256), 'held graph identity mismatch')
    snapshot = registry_snapshot(artifacts, expected_artifacts_sha256)
    value = parse(raw)
    fields(value, ('schema', 'source_set', 'nodes', 'edges', 'assurance'))
    require(value['schema'] == PROFILE, 'meaning graph version')
    require(value['assurance'] == ASSURANCE, 'graph assurance cannot be promoted')
    sources, windows = source_set_checked(value['source_set'], snapshot)
    names, records = nodes_checked(value['nodes'], sources, snapshot)
    require(windows | records == set(snapshot), 'unused graph registry artifacts')
    edges_checked(value['edges'], {row['id']: row['kind'] for row in value['nodes']})
    result = {'schema': 'sentinel/meaning-validation/1', 'graph_sha256': digest(raw),
              'source_set_sha256': digest(canonical(value['source_set'])),
              'source_set': value['source_set'], 'nodes': value['nodes'], 'edges': value['edges'],
              'source_binding': 'SUPPLIED_WINDOW_BYTES_ONLY',
              'documentary_records': 'DECLARED_UNADJUDICATED', 'assurance': dict(ASSURANCE)}
    require(len(canonical(result)) <= METADATA, 'graph report metadata bound')
    return result


def checked_formal_fragment(source, plan_raw):
    require(type(source) is bytes and len(source) <= JOB_BYTES, 'formal source byte bound')
    require(type(plan_raw) is bytes and len(plan_raw) <= JOB_BYTES, 'formal plan byte bound')
    from transport_semantics import checked_payload, dictionary_pair
    plan = parse(plan_raw)
    grammar, dictionaries, _symbols = dictionary_pair(plan)
    payload = checked_payload({'grammar': grammar, 'dictionaries': dictionaries,
                               'meaning': plan['meaning']}, source, True)
    result = {'payload': payload, 'source_identity': identity(source),
              'assurance': dict(ASSURANCE), 'adapter': 'EXISTING_TYPED_CODEC_NO_COMPACTION'}
    require(len(canonical(result)) <= JOB_BYTES, 'formal result byte bound')
    return result
