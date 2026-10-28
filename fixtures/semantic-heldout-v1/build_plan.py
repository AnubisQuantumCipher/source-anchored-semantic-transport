"""Reproduce an explicit held-out library reading; not an automatic interpreter."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'tools'))
from transport_author import Plan
from transport_schema import canonical, json_value, sha
from transport_wire import MAX_SOURCE, read_bounded, write_new


def opaque(source: bytes, phrase: str, ambiguity: str | None = None) -> dict:
    plan = Plan(source)
    root = plan.quote(phrase, 'atom')
    if ambiguity is not None:
        plan.ambiguity(phrase, ambiguity)
    return json_value(plan.finish(root))


def rule(source: bytes) -> dict:
    plan = Plan(source)
    librarian = plan.quote('Inez')
    atlas = plan.reference('atlas', [plan.mention('atlas')])
    cover = plan.reference('cover_review', [plan.mention('the cover review')])
    provenance = plan.reference('provenance_review', [plan.mention('the provenance review')])
    both = plan.relation('and', plan.predicate('complete', cover),
                         plan.predicate('complete', provenance), cue='both')
    lend = plan.predicate('lent', atlas)
    permission = plan.relation('permission_after', lend, both, cue='may be lent only after')
    return json_value(plan.finish(plan.relation('attribution', librarian, permission, cue='reports')))


def interpretation(source: bytes, name: str, phrase: str) -> dict:
    raw = phrase.encode('utf-8')
    begin = source.index(raw)
    return {'id': name, 'label': name, 'text': 'Explicit proposed reading of the anchored passage.',
            'status': 'proposed', 'provenance': 'Synthetic held-out library fixture; not external evidence.',
            'anchors': [{'source': 'LOAN', 'span': [begin, begin + len(raw)]}]}


def build(source: bytes) -> dict:
    first = 'Librarian Inez reports: "The atlas may be lent only after both the cover review and the provenance review are complete."'
    revoked = 'The earlier approval was revoked.'
    unknown = 'The return date is unspecified.'
    units = [dict(id='UNIT_REVOKED', source='LOAN', interpretation='READING_REVOKED',
                  kind='revocation', context=[], plan=opaque(source, revoked,
                  'The source does not name the earlier approval or approving actor.')),
             dict(id='UNIT_UNKNOWN', source='LOAN', interpretation='READING_UNKNOWN',
                  kind='source_claim', context=[], plan=opaque(source, unknown)),
             dict(id='UNIT_RULE', source='LOAN', interpretation='READING_RULE',
                  kind='source_claim', context=['UNIT_REVOKED', 'UNIT_UNKNOWN'], plan=rule(source))]
    readings = [interpretation(source, 'READING_REVOKED', revoked),
                interpretation(source, 'READING_UNKNOWN', unknown),
                interpretation(source, 'READING_RULE', first)]
    uncertainty = {'id': 'APPROVAL_SCOPE',
                   'text': 'The source does not name the earlier approval or approving actor; present authority is not established.',
                   'anchors': readings[0]['anchors'], 'affects': ['READING_RULE', 'READING_REVOKED']}
    return dict(schema='transport/transport-plan/2',
                sources=[dict(id='LOAN', label='Held-out library passage', media_type='text/plain; charset=utf-8',
                              provenance='Synthetic fixture authored for this receiving trial; not a real authorization.')],
                interpretations=readings, uncertainties=[uncertainty], relations=[], meaning_units=units)


def main() -> None:
    directory = Path(__file__).resolve().parent
    source = read_bounded(directory / 'loan.txt', MAX_SOURCE)
    data = canonical(build(source))
    warning = write_new(directory / 'loan-plan.json', data)
    if warning:
        raise ValueError(warning)
    sys.stdout.buffer.write(canonical(dict(source_bytes=len(source), source_sha256=sha(source),
                                          plan_bytes=len(data), plan_sha256=sha(data))) + b'\n')


if __name__ == '__main__':
    main()
