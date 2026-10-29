"""Bounded checked lowering to STV1; observations are attributed input, not facts.

The SPARK parser resolves report masks and checks the lowered tree. Python binds
the source occurrences and serializes data; it never chooses a norm outcome.
"""
import struct

from transport_handoff_inputs import digest, fields
from transport_install_support import canonical, require, sha
from transport_response_evidence import link, safe_json
from transport_bound_contract import CAP, MAX_NODES, records

OBSERVATIONS_SCHEMA = 'transport/bound-observations/1'
REPORT_BITS = {'UNRESOLVED': 1, 'KNOWN_FALSE': 2, 'KNOWN_TRUE': 4}
PROVENANCE = ('attributed_report', 'test_result', 'contract_result')


def observations(raw, compiled, expected):
    require(sha(raw) == digest(expected), 'externally held observation document differs')
    value = safe_json(raw, CAP)
    fields(value, ('schema', 'contract_sha256', 'records'))
    require(value['schema'] == OBSERVATIONS_SCHEMA, 'unsupported observation schema')
    require(value['contract_sha256'] == compiled['contract_sha256'], 'observations name a different contract')
    by_digest = {item['sha256']: node for node, item in compiled['bindings'].items()}
    masks, linked, seen, citation_count = {}, [], set(), 0
    for index, report in enumerate(records(value['records'], 64)):
        fields(report, ('binding_sha256', 'truth', 'provenance', 'citations'))
        binding = digest(report['binding_sha256'])
        require(binding in by_digest, 'observation binding revision or occurrence differs')
        require(type(report['truth']) is str and report['truth'] in REPORT_BITS, 'unknown reported truth state')
        require(type(report['provenance']) is str and report['provenance'] in PROVENANCE, 'unknown report provenance class')
        identity = sha(canonical(report))
        require(identity not in seen, 'duplicate observation record')
        seen.add(identity)
        citations = records(report['citations'], 8, 1)
        citation_count += len(citations)
        require(citation_count <= 64, 'aggregate observation citation bound')
        links = [link(('records', index, 'citations', i), citation, compiled['sources'], compiled['source_pins'])
                 for i, citation in enumerate(citations)]
        node = by_digest[binding]
        masks[node] = masks.get(node, 0) | REPORT_BITS[report['truth']]
        linked.append(dict(report_sha256=identity, binding_sha256=binding, node=node,
                           truth=report['truth'], provenance=report['provenance'], source_links=links))
    return dict(masks=masks, reports=linked, observations_sha256=sha(raw))


def lower(compiled, observed):
    nodes = compiled['unit']['meaning']['nodes']
    mapping, kinds, rows, trace = {}, {}, [], []
    for index, node in enumerate(nodes):
        op = node['op']
        if op in ('text', 'term'):
            continue
        args = node['args']
        if op == 'pred':
            code, kind, left, right = 1, 'FACT', 0, 0
        else:
            require(all(arg in mapping for arg in args), 'lowering operand missing')
            left, right = mapping[args[0]], mapping[args[1]] if len(args) == 2 else 0
            if op == 'not':
                require(kinds[args[0]] == 'FACT', 'norm negation unsupported')
                code, kind = 2, 'FACT'
            elif op == 'must':
                require(kinds[args[0]] == 'FACT', 'nested obligation unsupported')
                code, kind = 4, 'NORM'
            else:
                require(op == 'and' and kinds[args[0]] == kinds[args[1]], 'mixed fact/norm conjunction unsupported')
                kind = kinds[args[0]]
                code = 3 if kind == 'FACT' else 5
        rows.append((code, observed['masks'].get(index, 0), left, right))
        mapping[index], kinds[index] = len(rows), kind
        trace.append(dict(meaning_node=index, evaluator_node=len(rows), sort=kind, operator=op))
    root = compiled['unit']['meaning']['root']
    require(root in mapping and kinds[root] == 'NORM' and 1 <= len(rows) <= MAX_NODES,
            'evaluation requires a bounded obligation root')
    frame = b'STV1' + struct.pack('>H', len(rows)) + b''.join(struct.pack('>BBHH', *row) for row in rows)
    require(len(frame) <= 1542, 'evaluation frame byte bound')
    return dict(frame=frame, trace=trace, root=mapping[root])


def native_result(raw, lowered):
    require(type(raw) is bytes and 0 < len(raw) <= 16384 and raw.endswith(b'\n'), 'native output byte/framing bound')
    lines = raw.decode('ascii', errors='strict').splitlines()
    require(len(lines) == len(lowered['trace']), 'native result node count differs')
    results = []
    for line, item in zip(lines, lowered['trace'], strict=True):
        parts = line.split()
        require(len(parts) == 4 and parts[0] == 'NODE' and parts[1] == str(item['evaluator_node'])
                and parts[2] == item['sort'], 'native result node identity or type differs')
        allowed = REPORT_BITS if item['sort'] == 'FACT' else ('UNKNOWN', 'SATISFIED', 'VIOLATED')
        require(parts[3] in allowed, 'unknown native result value')
        results.append(dict(item, value=parts[3]))
    return results


def check_conclusion(raw, evaluation):
    value = safe_json(raw, CAP)
    fields(value, ('schema', 'evaluation_sha256', 'outcome', 'commentary'))
    require(value['schema'] == 'transport/evaluation-conclusion/1', 'unsupported conclusion schema')
    require(digest(value['evaluation_sha256']) == sha(canonical(evaluation)), 'conclusion evaluation identity differs')
    require(value['outcome'] == evaluation['outcome'], 'candidate conclusion contradicts computed outcome')
    require(type(value['commentary']) is str, 'commentary must be text')
    return dict(status='DECLARED_OUTCOME_MATCH', candidate_sha256=sha(raw),
                evaluation_sha256=value['evaluation_sha256'], commentary='NOT_ASSESSED', execution_authority='NONE')
