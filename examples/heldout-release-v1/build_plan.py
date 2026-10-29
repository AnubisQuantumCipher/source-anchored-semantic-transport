#!/usr/bin/env python3
"""Reproduce a proposed documentary reading; no native or candidate execution.

Interpretation decisions: current-rule 'exactly when' is represented by a
sufficient-condition edge AND a necessary-condition edge. Imperative 'Return'
grounds documentary must, which grants no execution authority. The unsupported
hold disjunction and inclusive numeric range remain exact opaque propositions.
The separate testable predicate names the complete rule sentence; it does not
claim to decompose or prove each English clause. Whole-source context is retained.
"""

import argparse
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
sys.path.insert(0, str(ROOT / 'install'))
import transport_plan as plans
from transport_meaning import check_meaning
from transport_semantics import anchored_payload, dictionary_pair
from transport_schema import canonical, json_value, require, sha
from transport_install_support import read_regular, write_new

PINS = {'fixture.json': '4e318cd2a123c717b25d1a826968c227e1420df3dc8225a377473b58bfc8eded',
        'criteria.json': 'e97d9e31bd6350922f38b92d065a31b7ce92f798cd28b1bdecb5dd5b32657c5a'}
COMPLETE_CONDITION = ('Return True exactly when rights_review_complete is True, '
    'curatorial_review_complete is True, age_days is between 0 and 2 inclusive, '
    'and either publication_hold is False or maintenance_replacement is True.')
HOLD_ALTERNATIVE = 'either publication_hold is False or maintenance_replacement is True'
AGE_RANGE = 'age_days is between 0 and 2 inclusive'
FUNCTION_CONTEXT = ('This is rule-r3, the complete current behavior for '
    'may_queue_museum_preview; it supersedes rule-r2 in HISTORY.')
QUALIFICATIONS = ('The maintenance exception waives only the publication hold. '
    'Both review completions and both age bounds still apply during a maintenance replacement, '
    'including when publication_hold is True. When publication_hold is False, '
    'maintenance_replacement has no effect. A hold never waives a review or an age bound.')


def fixture_inputs():
    values = {}
    for name, expected in PINS.items():
        raw = read_regular(HERE / name, 65536)
        require(sha(raw) == expected, 'frozen input differs: ' + name)
        values[name] = json_value(raw, 65536)
    fixture = values['fixture.json']
    sources = fixture['sources']
    require(type(sources) is list and len(sources) == 6, 'six source records required')
    require([item['id'] for item in sources] ==
            ['CODE', 'RULE', 'HISTORY', 'REPORTS', 'ACTIONS', 'UNRELATED'], 'source order differs')
    data = {item['id']: item['text'].encode('utf-8') for item in sources}
    require(sum(len(raw) for raw in data.values()) <= 8192, 'fixture source byte bound')
    return fixture, data


def exact_span(data, quote, within=None):
    raw = quote.encode('utf-8')
    require(type(data) is bytes and 0 < len(data) <= 8192, 'source byte bound')
    require(0 < len(raw) <= 4096, 'quotation byte bound')
    region, offset = data, 0
    if within is not None:
        outer = within.encode('utf-8')
        require(data.count(outer) == 1, 'ambiguous quotation context')
        offset = data.index(outer)
        region = outer
    require(region.count(raw) == 1, 'quotation missing or nonunique')
    begin = offset + region.index(raw)
    require(data[begin:begin + len(raw)] == raw, 'quotation span differs')
    return [begin, begin + len(raw)]


def anchor(data, source, quote=None):
    selected = quote if quote is not None else data[source].decode('utf-8')
    return {'source': source, 'span': exact_span(data[source], selected)}


def leaf(data, source, symbols, nodes, name, text, op='atom', within=None):
    require(name not in symbols and len(symbols) < 64, 'symbol duplicate or count bound')
    symbols[name] = text
    nodes.append(dict(op=op, symbol=name, span=exact_span(data[source], text, within)))
    require(len(nodes) <= 128, 'node count bound')
    return len(nodes) - 1


def operator(nodes, op, args, cue=None):
    require(len(nodes) < 128 and 1 <= len(args) <= 7, 'operator bounds')
    require(all(type(index) is int and 0 <= index < len(nodes) for index in args), 'node order')
    nodes.append(dict(op=op, args=args, cue=[0, 0] if cue is None else cue))
    return len(nodes) - 1


def add_unit(plan, data, name, source, kind, symbols, nodes, context=(), notes=(), reading=None):
    require(len(plan['meaning_units']) < 16, 'unit count bound')
    interpretation = 'I_' + name
    plan['interpretations'].append(dict(id=interpretation, label=name.replace('_', ' ').title(),
        text=reading or 'Proposed documentary reading of the exact source; no truth or authority verdict.',
        status='proposed', provenance='Explicit author-selected fixture interpretation; entailment UNPROVEN.',
        anchors=[anchor(data, source)]))
    meaning = dict(schema='transport/meaning/1', nodes=nodes, root=len(nodes) - 1,
                   ambiguities=list(notes))
    plan['meaning_units'].append(dict(id='MU_' + name, source=source, interpretation=interpretation,
        kind=kind, context=list(context), plan=dict(schema='transport/encoding-plan/1',
                                                  symbols=symbols, meaning=meaning)))


def opaque_unit(plan, data, name, source, symbol, context=(), quote=None, kind='source_claim'):
    symbols, nodes = {}, []
    text = quote if quote is not None else data[source].decode('utf-8')
    leaf(data, source, symbols, nodes, symbol, text)
    add_unit(plan, data, name, source, kind, symbols, nodes, context,
             reading='Whole quoted source unit retained opaquely; qualifications are not silently discarded.')


def documentary_units(plan, data):
    opaque_unit(plan, data, 'COMPLETE_RULE_CONTEXT', 'RULE', 'COMPLETE_RULE_AND_DOMAIN')
    opaque_unit(plan, data, 'CODE', 'CODE', 'ORIGINAL_PREVIEW_QUEUE_CODE', ['MU_COMPLETE_RULE_CONTEXT'])
    opaque_unit(plan, data, 'HISTORY_CONTEXT', 'HISTORY', 'COMPLETE_FICTIONAL_HISTORY')
    history = data['HISTORY'].decode('utf-8').splitlines()
    require(len(history) <= 16, 'history line count bound')
    for name, prefix, symbol, kind in (
        ('SUPERSEDED_CORRECTION', '2026-09-11', 'OLDER_REVIEW_AND_AGE_CORRECTION', 'source_claim'),
        ('HISTORICAL_APPROVAL', '2026-09-12', 'WITHDRAWN_RELEASE_APPROVAL_RECORD', 'historical_approval'),
        ('APPROVAL_WITHDRAWAL', '2026-09-14', 'SUPERSESSION_AND_WITHDRAWAL_RECORD', 'revocation')):
        matches = [line for line in history if line.startswith(prefix)]
        require(len(matches) == 1, 'history quotation not unique')
        opaque_unit(plan, data, name, 'HISTORY', symbol, ['MU_HISTORY_CONTEXT'], matches[0], kind)
    opaque_unit(plan, data, 'REPORTS_CONTEXT', 'REPORTS', 'COMPLETE_CONFLICT_AND_PROVENANCE')
    attributed_report(plan, data, 'NORTH', 'fictional North Desk', 'REPORT-N, fictional North Desk:')
    attributed_report(plan, data, 'SOUTH', 'fictional South Desk', 'REPORT-S, fictional South Desk:')
    opaque_unit(plan, data, 'ACTION_LEDGER', 'ACTIONS', 'UNCHANGED_ACTION_STATES', kind='pending_action')
    opaque_unit(plan, data, 'UNRELATED_NOTE', 'UNRELATED', 'UNRELATED_VISITOR_NOTE')


def attributed_report(plan, data, side, desk, prefix):
    lines = data['REPORTS'].decode('utf-8').splitlines()
    require(len(lines) <= 16, 'report line count bound')
    selected = [line for line in lines if line.startswith(prefix)]
    require(len(selected) == 1 and selected[0].count('"') == 2, 'report quotation framing')
    claim = selected[0].split('"')[1]
    symbols, nodes = {}, []
    who = leaf(data, 'REPORTS', symbols, nodes, side + '_REPORTING_DESK', desk, 'term')
    proposition = leaf(data, 'REPORTS', symbols, nodes, side + '_ATTRIBUTED_RESULT', claim)
    operator(nodes, 'attribution', [who, proposition], exact_span(data['REPORTS'], prefix))
    add_unit(plan, data, side + '_REPORT', 'REPORTS', 'source_claim', symbols, nodes,
             ['MU_REPORTS_CONTEXT'], reading='Attributed historical report only; narrator does not endorse it.')


def detailed_rule(plan, data):
    symbols, nodes = {}, []
    function = leaf(data, 'RULE', symbols, nodes, 'QUEUE_PREVIEW_FUNCTION',
                    'may_queue_museum_preview', 'term', FUNCTION_CONTEXT)
    action = leaf(data, 'RULE', symbols, nodes, 'TRUE_RESULT_ACTION', 'Return True', 'text')
    predicate = operator(nodes, 'pred', [action, function])
    rights = leaf(data, 'RULE', symbols, nodes, 'RIGHTS_REVIEW_IS_COMPLETE', 'rights_review_complete is True')
    curator = leaf(data, 'RULE', symbols, nodes, 'CURATORIAL_REVIEW_IS_COMPLETE', 'curatorial_review_complete is True')
    age = leaf(data, 'RULE', symbols, nodes, 'INCLUSIVE_REVIEW_AGE_RANGE', AGE_RANGE)
    alternative = leaf(data, 'RULE', symbols, nodes, 'OPAQUE_HOLD_OR_MAINTENANCE', HOLD_ALTERNATIVE)
    reviews = operator(nodes, 'and', [rights, curator])
    reviewed_age = operator(nodes, 'and', [reviews, age])
    condition = operator(nodes, 'and', [reviewed_age, alternative])
    cue = exact_span(data['RULE'], 'exactly when')
    sufficient = operator(nodes, 'if', [condition, predicate], cue)
    necessary = operator(nodes, 'requires', [predicate, condition], cue)
    equivalence = operator(nodes, 'and', [sufficient, necessary])
    obligation = operator(nodes, 'must', [equivalence], exact_span(data['RULE'], 'Return True'))
    scope = leaf(data, 'RULE', symbols, nodes, 'NARROW_EXCEPTION_AND_RETAINED_GUARDS', QUALIFICATIONS)
    operator(nodes, 'and', [obligation, scope])
    notes = [dict(span=exact_span(data['RULE'], HOLD_ALTERNATIVE), note=
        'The fixed dictionary has no disjunction. This entire alternative is one exact opaque proposition; no invented OR operator or internal decomposition is asserted.'),
        dict(span=exact_span(data['RULE'], AGE_RANGE), note=
        'The inclusive age range is retained verbatim as an opaque proposition. Documentary operators do not evaluate comparisons or prove numeric behavior.')]
    add_unit(plan, data, 'DETAILED_RULE', 'RULE', 'instruction', symbols, nodes,
        ['MU_COMPLETE_RULE_CONTEXT', 'MU_CODE', 'MU_APPROVAL_WITHDRAWAL', 'MU_REPORTS_CONTEXT', 'MU_ACTION_LEDGER'],
        notes, 'Author reads exactly when as sufficiency AND necessity and Return as a documentary obligation. Both reviews are explicitly conjoined. Whole-source context preserves definitions, qualifications, domain, types, interface and authority limits. Interpretation entailment and completeness remain UNPROVEN.')


def testable_rule(plan, data):
    symbols, nodes = {}, []
    leaf(data, 'RULE', symbols, nodes, 'QUEUE_PREVIEW_FUNCTION',
         'may_queue_museum_preview', 'term', FUNCTION_CONTEXT)
    leaf(data, 'RULE', symbols, nodes, 'ENTIRE_CURRENT_TRUE_CONDITION', COMPLETE_CONDITION, 'text')
    operator(nodes, 'pred', [1, 0], exact_span(data['RULE'], COMPLETE_CONDITION))
    operator(nodes, 'must', [2], exact_span(data['RULE'], 'Return True'))
    contexts = ['MU_DETAILED_RULE', 'MU_COMPLETE_RULE_CONTEXT', 'MU_CODE', 'MU_HISTORY_CONTEXT',
        'MU_SUPERSEDED_CORRECTION', 'MU_HISTORICAL_APPROVAL', 'MU_APPROVAL_WITHDRAWAL',
        'MU_REPORTS_CONTEXT', 'MU_NORTH_REPORT', 'MU_SOUTH_REPORT', 'MU_ACTION_LEDGER']
    add_unit(plan, data, 'TESTABLE_RULE', 'RULE', 'instruction', symbols, nodes, contexts,
        reading='This separately bindable named predicate quotes the entire current condition. It is not a decomposition of every English clause or a proof of entailment; detailed and complete source context remain explicit dependencies.')


def declarations(plan, data):
    plan['uncertainties'] = [dict(id='U_REPORT_PROVENANCE',
        text='North and South reports conflict and lack execution provenance; neither authenticates a current correction.',
        anchors=[anchor(data, 'REPORTS')], affects=['I_NORTH_REPORT', 'I_SOUTH_REPORT', 'I_REPORTS_CONTEXT', 'I_TESTABLE_RULE']),
        dict(id='U_CURRENT_VERIFICATION', text='No supplied record establishes current exhaustive verification, proof or independent acceptance.',
        anchors=[anchor(data, 'REPORTS'), anchor(data, 'RULE')], affects=['I_CODE', 'I_DETAILED_RULE', 'I_TESTABLE_RULE']),
        dict(id='U_REPRESENTATION_LIMIT', text='Hold disjunction and inclusive numeric comparison are opaque; typed graphs do not establish natural-language entailment, whole-clause decomposition, completeness or real authority.',
        anchors=[anchor(data, 'RULE', COMPLETE_CONDITION)], affects=['I_COMPLETE_RULE_CONTEXT', 'I_DETAILED_RULE', 'I_TESTABLE_RULE'])]
    selected = [('contradicts', 'I_NORTH_REPORT', 'I_SOUTH_REPORT', 'REPORTS',
        'Declared conflicting attributed outputs; no historical execution provenance is resolved.'),
        ('supersedes', 'I_COMPLETE_RULE_CONTEXT', 'I_SUPERSEDED_CORRECTION', 'HISTORY',
        'The source explicitly records rule-r3 replacing COR-02; this relation grants no authority.'),
        ('qualifies', 'I_APPROVAL_WITHDRAWAL', 'I_HISTORICAL_APPROVAL', 'HISTORY',
        'The source records withdrawal of HAPP-M1 with no continuing publication approval.'),
        ('qualifies', 'I_REPORTS_CONTEXT', 'I_TESTABLE_RULE', 'REPORTS',
        'A proposed replacement has UNKNOWN current verification in the source snapshot.'),
        ('qualifies', 'I_ACTION_LEDGER', 'I_TESTABLE_RULE', 'ACTIONS',
        'Pending actions remain source states; drafting does not complete independent verification or publication decisions.'),
        ('derived_from', 'I_DETAILED_RULE', 'I_COMPLETE_RULE_CONTEXT', 'RULE',
        'Author-selected decomposition remains linked to the entire unsplit source context.'),
        ('derived_from', 'I_TESTABLE_RULE', 'I_DETAILED_RULE', 'RULE',
        'A separately named complete predicate retains detailed and whole-source dependencies.')]
    for kind, origin, target, source, note in selected:
        plan['relations'].append(dict(kind=kind, **{'from': origin, 'to': target},
                                      note=note, anchors=[anchor(data, source)]))


def validate_without_native(plan, data):
    source_tuple = tuple(data[item['id']] for item in plan['sources'])
    plans.check_sources(plan['sources'], source_tuple)
    names = plans.collect_ids(plan)
    interpretations = plans.check_interpretations(plan['interpretations'], data, False)
    plans.check_uncertainties(plan['uncertainties'], data, names, False)
    plans.check_relations(plan['relations'], data, names, False)
    by_id = {item['id']: item for item in interpretations}
    seen, stored = set(), []
    for unit in plan['meaning_units']:
        require(all(name in seen for name in unit['context']), 'context must precede its dependent')
        require(len(set(unit['context'])) == len(unit['context']), 'duplicate context dependency')
        grammar, dictionaries, symbols = dictionary_pair(unit['plan'])
        meaning = unit['plan']['meaning']
        check_meaning(meaning, data[unit['source']], symbols['entries'])
        anchored_payload(meaning, by_id[unit['interpretation']]['anchors'], unit['source'])
        used = {node['symbol'] for node in meaning['nodes'] if 'symbol' in node}
        require(used == set(symbols['entries']), 'unused symbol')
        stored.append({key: value for key, value in unit.items() if key != 'plan'} |
                      dict(grammar=grammar, dictionaries=dictionaries, meaning=meaning))
        seen.add(unit['id'])
    require(len(plan['meaning_units']) <= 16 and len(plan['interpretations']) <= 32, 'record bounds')
    require(len(canonical(plan | {'meaning_units': stored})) <= 65536, 'stored metadata bound')


def build():
    fixture, data = fixture_inputs()
    metadata = [{key: value for key, value in item.items() if key != 'text'} for item in fixture['sources']]
    plan = dict(schema='transport/transport-plan/2', sources=metadata, interpretations=[],
                uncertainties=[], relations=[], meaning_units=[])
    documentary_units(plan, data)
    detailed_rule(plan, data)
    testable_rule(plan, data)
    declarations(plan, data)
    validate_without_native(plan, data)
    raw = canonical(plan)
    require(len(raw) <= 65536, 'input metadata bound')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    raw = build()
    target = HERE / 'plan.json'
    if args.check:
        require(read_regular(target, 65536) == raw, 'derived plan bytes differ')
    else:
        write_new(target, raw, 65536)
    print(canonical(dict(status='PLAN_REPRODUCED' if args.check else 'PLAN_WRITTEN',
        bytes=len(raw), sha256=sha(raw), source_inputs=PINS,
        native_execution='UNRUN', encoding='UNRUN', entailment='UNPROVEN')).decode('utf-8'))


if __name__ == '__main__':
    main()
