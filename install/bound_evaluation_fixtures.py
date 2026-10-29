"""Reproducible synthetic readings; no automatic source interpretation or authority."""
from pathlib import Path

from transport_install_support import canonical, read_regular, require, sha

ROOT = Path(__file__).absolute().parents[1]
EXAMPLES = ROOT / 'examples/bound-evaluation-v1'
NAMES = ('reviews', 'library')
SOURCE_IDS = ('REQUIREMENT', 'EVIDENCE', 'HISTORY')


def sources(name):
    require(name in NAMES, 'unknown bounded fixture')
    return {key: read_regular(EXAMPLES / name / (key.lower() + '.txt'), 4096) for key in SOURCE_IDS}


def span(source, text, start=0):
    raw = text.encode('utf-8')
    begin = source.index(raw, start)
    return [begin, begin + len(raw)]


def leaf(nodes, symbols, source, text, op='term', start=0):
    require(len(nodes) < 32, 'fixture node bound')
    key = 'S' + str(len(symbols))
    symbols[key] = text
    nodes.append(dict(op=op, symbol=key, span=span(source, text, start)))
    return len(nodes) - 1


def relation(nodes, op, args, cue):
    require(len(nodes) < 32 and 1 <= len(args) <= 4, 'fixture relation bound')
    nodes.append(dict(op=op, args=args, cue=cue))
    return len(nodes) - 1


def reading(source, name):
    nodes, symbols = [], {}
    if name == 'reviews':
        norms = []
        for phrase in ('security review', 'validation review'):
            term = leaf(nodes, symbols, source, phrase)
            start = nodes[term]['span'][1]
            text = leaf(nodes, symbols, source, 'complete', 'text', start)
            pred = relation(nodes, 'pred', [text, term], nodes[text]['span'])
            norms.append(relation(nodes, 'must', [pred], span(source, 'must', start)))
        relation(nodes, 'and', norms, span(source, 'and'))
    elif name == 'library':
        actor = leaf(nodes, symbols, source, 'Inez')
        item = leaf(nodes, symbols, source, 'atlas')
        recipient = leaf(nodes, symbols, source, 'Omar')
        text = leaf(nodes, symbols, source, 'deliver', 'text')
        pred = relation(nodes, 'pred', [text, actor, item, recipient], nodes[text]['span'])
        negation = relation(nodes, 'not', [pred], span(source, 'not'))
        relation(nodes, 'must', [negation], span(source, 'must'))
    else:
        leaf(nodes, symbols, source, source.decode('utf-8'), 'atom')
    return dict(schema='transport/encoding-plan/1', symbols=symbols,
                meaning=dict(schema='transport/meaning/1', nodes=nodes, root=len(nodes) - 1, ambiguities=[]))


def plan(name, data):
    interpretations, units = [], []
    for key in SOURCE_IDS:
        interpretations.append(dict(id='I_' + key, label=key, status='proposed',
            text='Explicit synthetic reading; entailment and report authenticity remain unproved.',
            provenance='Bound evaluation deterministic fixture, not external evidence.',
            anchors=[dict(source=key, span=[0, len(data[key])])]))
        units.append(dict(id='U_' + key, source=key, interpretation='I_' + key,
            kind='instruction' if key == 'REQUIREMENT' else 'source_claim', context=[],
            plan=reading(data[key], name if key == 'REQUIREMENT' else 'opaque')))
    return dict(schema='transport/transport-plan/2',
        sources=[dict(id=key, label=key, media_type='text/plain; charset=utf-8',
                      provenance='Synthetic public fixture; no current execution authority.') for key in SOURCE_IDS],
        interpretations=interpretations, meaning_units=units,
        uncertainties=[dict(id='REPORT_AUTHENTICITY', text='Reports and correction precedence remain unauthenticated.',
            affects=['I_REQUIREMENT', 'I_EVIDENCE', 'I_HISTORY'],
            anchors=[dict(source='HISTORY', span=[0, len(data['HISTORY'])])])],
        relations=[dict(kind='qualifies', **{'from': 'I_HISTORY', 'to': 'I_EVIDENCE'},
                        note='History is retained; this relation does not select a true report.',
                        anchors=[dict(source='HISTORY', span=[0, len(data['HISTORY'])])])])


def contract(name, decoded, native_sha256):
    unit = next(item for item in decoded['meaning_units'] if item['id'] == 'U_REQUIREMENT')
    nodes = unit['meaning']['nodes']
    terms, predicates, bindings = [], [], []
    names = ('SECURITY_COMPLETE', 'VALIDATION_COMPLETE') if name == 'reviews' else ('DELIVER',)
    for index, node in enumerate(nodes):
        if node['op'] == 'term':
            literal = unit['lexicon'][node['symbol']]
            sort = 'REVIEW' if name == 'reviews' else ('ITEM' if literal == 'atlas' else 'PERSON')
            terms.append(dict(node=index, sort=sort))
        elif node['op'] == 'pred':
            args = node['args'][1:]
            sorts = [next(item['sort'] for item in terms if item['node'] == arg) for arg in args]
            predicate = names[len(predicates)]
            predicates.append(dict(id=predicate, name_node=node['args'][0], argument_sorts=sorts))
            bindings.append(dict(node=index, predicate=predicate, arguments=args))
    source = next(item for item in decoded['sources'] if item['id'] == 'REQUIREMENT')
    return dict(schema='transport/bound-evaluation-contract/1', profile='transport/ground-obligation-evaluation/1',
        package_identity=decoded['identity'], unit_id=unit['id'], unit_sha256=sha(canonical(unit)),
        source_id='REQUIREMENT', source_sha256=source['sha256'], native_sha256=native_sha256,
        terms=terms, predicates=predicates, bindings=bindings)


def report(compiled, occurrence, truth, source_id='EVIDENCE'):
    source = compiled['sources'][source_id]
    lines = source.splitlines(keepends=True)
    line = 1 if source_id == 'EVIDENCE' and occurrence == 1 else 0
    require(line < len(lines), 'fixture report source line')
    start = sum(len(item) for item in lines[:line])
    quote = lines[line]
    node = list(compiled['bindings'])[occurrence]
    return dict(binding_sha256=compiled['bindings'][node]['sha256'], truth=truth,
        provenance='attributed_report', citations=[dict(source_id=source_id,
            source_sha256=compiled['source_pins'][source_id], start=start,
            end=start + len(quote), quote=quote.decode('utf-8'))])


def observations(compiled, reports):
    return dict(schema='transport/bound-observations/1', contract_sha256=compiled['contract_sha256'], records=reports)
