"""Source-bound evaluation declarations for an explicitly supported semantic fragment.

The caller must supply a result from the authoritative decoder. The CLI verifies
that dependency. This module checks a declared reading, never English entailment.
"""
from transport_handoff_inputs import ID, digest, fields
from transport_install_support import canonical, require, sha
from transport_response_evidence import safe_json, source_pins

SCHEMA = 'transport/bound-evaluation-contract/1'
CAP, MAX_NODES, MAX_BINDINGS = 32768, 256, 64
PROFILE = 'transport/ground-obligation-evaluation/1'


def identifier(value):
    require(type(value) is str and ID.fullmatch(value) is not None, 'invalid nominal identifier')
    return value


def records(value, limit, minimum=0):
    require(type(value) is list and minimum <= len(value) <= limit, 'evaluation record count bound')
    return value


def node_index(value, nodes, op=None):
    require(type(value) is int and 0 <= value < len(nodes), 'evaluation occurrence out of range')
    if op is not None:
        require(nodes[value]['op'] == op, 'evaluation occurrence has wrong type')
    return value


def select_unit(decoded, value):
    require(decoded.get('schema') == 'transport/decoded/2', 'typed decoded package required')
    require(value['package_identity'] == decoded['identity'], 'evaluation package identity differs')
    sources = {item['id']: item['data'] for item in decoded['sources']}
    pins = source_pins(sources, {item['id']: item['sha256'] for item in decoded['sources']})
    units = records(decoded['meaning_units'], 16, 1)
    matches = [unit for unit in units if unit['id'] == identifier(value['unit_id'])]
    require(len(matches) == 1, 'evaluation unit missing or duplicated')
    unit = matches[0]
    require(sha(canonical(unit)) == digest(value['unit_sha256']), 'evaluation unit revision differs')
    require(value['source_id'] == unit['source'] and value['source_id'] in sources,
            'evaluation source identity differs')
    require(digest(value['source_sha256']) == pins[value['source_id']], 'evaluation source revision differs')
    from transport_meaning import check_meaning
    check_meaning(unit['meaning'], sources[unit['source']], unit['lexicon'])
    require(not unit['meaning']['ambiguities'], 'ambiguous reading is not evaluable by this profile')
    return unit, sources, pins


def declarations(value, nodes):
    terms, predicates, names = {}, {}, set()
    for item in records(value['terms'], 64):
        fields(item, ('node', 'sort'))
        index = node_index(item['node'], nodes, 'term')
        require(index not in terms, 'duplicate term occurrence declaration')
        terms[index] = identifier(item['sort'])
    for item in records(value['predicates'], 32, 1):
        fields(item, ('id', 'name_node', 'argument_sorts'))
        name = identifier(item['id'])
        index = node_index(item['name_node'], nodes, 'text')
        require(name not in predicates and index not in names, 'duplicate predicate identity or name occurrence')
        sorts = records(item['argument_sorts'], 6)
        for sort in sorts:
            identifier(sort)
        predicates[name] = item
        names.add(index)
    return terms, predicates


def bindings(value, nodes, contract_sha256):
    terms, predicates = declarations(value, nodes)
    result, used_terms, used_predicates = {}, set(), set()
    for item in records(value['bindings'], MAX_BINDINGS, 1):
        fields(item, ('node', 'predicate', 'arguments'))
        index = node_index(item['node'], nodes, 'pred')
        require(index not in result, 'duplicate predicate occurrence binding')
        name = identifier(item['predicate'])
        require(name in predicates, 'undeclared predicate')
        declaration = predicates[name]
        args = records(item['arguments'], 6)
        require(all(type(arg) is int and arg in terms for arg in args), 'undeclared ground term')
        require(nodes[index]['args'] == [declaration['name_node']] + args,
                'predicate name or ordered argument occurrences differ')
        require([terms[arg] for arg in args] == declaration['argument_sorts'], 'predicate nominal argument sorts differ')
        identity = dict(contract_sha256=contract_sha256, node=index, predicate=declaration,
                        arguments=[dict(node=arg, sort=terms[arg]) for arg in args])
        result[index] = dict(identity=identity, sha256=sha(canonical(identity)))
        used_terms.update(args)
        used_predicates.add(name)
    require(used_terms == set(terms) and used_predicates == set(predicates), 'unused evaluation declaration')
    require(set(result) == {i for i, item in enumerate(nodes) if item['op'] == 'pred'},
            'every predicate occurrence requires an explicit binding')
    return result


def context_view(decoded, selected):
    from transport_package import focused_ids
    needed = focused_ids(decoded, selected)
    units = [dict(id=item['id'], kind=item['kind'], source=item['source'], context=item['context'],
                  interpretation=item['interpretation'], unit_sha256=sha(canonical(item)),
                  evaluation='SELECTED' if item['id'] == selected else 'NOT_EVALUATED')
             for item in decoded['meaning_units'] if item['id'] in needed]
    return dict(units=units, uncertainties=[item for item in decoded['uncertainties'] if item['id'] in needed],
                relations=[item for item in decoded['relations'] if item['from'] in needed or item['to'] in needed],
                adequacy='UNPROVEN', policy='CONTEXT_LINKS_PRESERVED_NOT_INTERPRETED_AS_SUPERSESSION_OR_AUTHORITY')


def compile_contract(raw, decoded, expected):
    require(sha(raw) == digest(expected), 'externally held evaluation contract differs')
    value = safe_json(raw, CAP)
    fields(value, ('schema', 'profile', 'package_identity', 'unit_id', 'unit_sha256',
                   'source_id', 'source_sha256', 'native_sha256', 'terms', 'predicates', 'bindings'))
    require(value['schema'] == SCHEMA and value['profile'] == PROFILE, 'unsupported evaluation contract/profile')
    digest(value['native_sha256'])
    unit, sources, pins = select_unit(decoded, value)
    nodes = records(unit['meaning']['nodes'], MAX_NODES, 1)
    require(all(node['op'] in ('text', 'term', 'pred', 'not', 'and', 'must') for node in nodes),
            'unsupported operator remains unevaluated; no lowering performed')
    linked = bindings(value, nodes, sha(raw))
    return dict(contract=value, contract_sha256=sha(raw), unit=unit, sources=sources,
                source_pins=pins, bindings=linked,
                context=context_view(decoded, unit['id']),
                unevaluated_units=[item['id'] for item in decoded['meaning_units'] if item['id'] != unit['id']])
