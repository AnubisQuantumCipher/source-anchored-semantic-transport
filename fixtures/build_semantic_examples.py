"""Prepare four retained corpus readings; source interpretation is not automated."""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from transport_schema import canonical, json_value, sha
from transport_wire import MAX_WIRE, read_bounded, write_new

SELECTION = (('controller', 'CONTROLLER', 'instruction', 'codec-cases.json'),
             ('publication', 'PARALLEL_BOTH', 'instruction', 'codec-semantics-cases.json'),
             ('attributed', 'ATTRIBUTED', 'source_claim', 'codec-cases.json'),
             ('emotion', 'EMOTION', 'source_claim', 'codec-cases.json'))


def envelope(case: dict, source: bytes, kind: str) -> dict:
    reading = dict(id='READING', label=case['id'], text='Explicit supplied corpus reading.',
                   status='proposed', provenance='Retained authored test corpus; interpretation unproved.',
                   anchors=[dict(source='SOURCE', span=[0, len(source)])])
    unit = dict(id='MEANING', source='SOURCE', interpretation='READING', kind=kind,
                context=[], plan=case['plan'])
    return dict(schema='transport/transport-plan/2',
                sources=[dict(id='SOURCE', label=case['id'], media_type='text/plain; charset=utf-8',
                              provenance='Authored test corpus, preserved verbatim; not an execution authorization.')],
                interpretations=[reading], uncertainties=[], relations=[], meaning_units=[unit])


def write(path: Path, data: bytes) -> None:
    warning = write_new(path, data)
    if warning:
        raise ValueError(warning)
    if read_bounded(path, MAX_WIRE) != data:
        raise ValueError('example readback mismatch')


def main() -> None:
    output = ROOT / 'fixtures/semantic-examples-v1'
    output.mkdir(mode=0o700)
    records = []
    for name, identifier, kind, corpus in SELECTION:
        cases = json_value(read_bounded(ROOT / 'corpus' / corpus, MAX_WIRE))['cases']
        matches = [item for item in cases if item['id'] == identifier]
        if len(matches) != 1:
            raise ValueError('missing or duplicate example')
        case = matches[0]
        source = case['source'].encode('utf-8')
        plan = canonical(envelope(case, source, kind))
        write(output / (name + '.txt'), source)
        write(output / (name + '-plan.json'), plan)
        records.append(dict(example=name, source_bytes=len(source), source_sha256=sha(source),
                            plan_bytes=len(plan), plan_sha256=sha(plan)))
    sys.stdout.buffer.write(canonical(records) + b'\n')


if __name__ == '__main__':
    main()
