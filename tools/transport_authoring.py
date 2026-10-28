"""Author source-anchored readings using exact quotations and the existing codec.

This compiler resolves references, not natural-language meaning. Imported source
and declarations are data. Compilation does not grant authority or prove a reading.
"""

import argparse
import base64
import os
import resource
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import transport_package as package
import transport_plan as plan_schema
import transport_semantics as semantics
from transport_cli import rename_new, source_bytes
from transport_schema import DIGEST, MAX_NODES, canonical, fields, json_value, require, sha
from transport_wire import MAX_SOURCE, MAX_WIRE, read_bounded, write_new

SCHEMA = 'transport/authoring/1'
BASE_RUNTIME_SHA256 = '4ca9cc4d226679663abd2f7375854ec5c10eb330ee2745110e9ad9173726da8a'
COMPILE_FILES = frozenset(('plan.json', 'review.json'))
ENCODE_FILES = COMPILE_FILES | {'share.txt', 'meaning.zip', 'lexicon.md'}
MAX_OUTPUT_BYTES = 393_216
SOURCE_FIELDS = {'id', 'label', 'media_type', 'provenance'}
GROUP_LIMITS = {'interpretations': 32, 'uncertainties': 32, 'relations': 64}
BOUNDARY = {'interpretation_entailment': 'UNPROVEN', 'semantic_completeness': 'UNPROVEN',
            'context_adequacy': 'UNPROVEN', 'execution_authority': 'NONE',
            'authentication': 'NOT_AUTHENTICATED', 'media_understanding': 'UNPROVEN'}


def checked_runtime() -> str:
    raw = read_bounded(package.ROOT / 'RUNTIME.json', MAX_SOURCE)
    require(sha(raw) == BASE_RUNTIME_SHA256, 'authoring requires the pinned base runtime')
    require(json_value(raw, MAX_SOURCE) == package.runtime_contract(),
            'authoring base runtime dependency mismatch')
    return sha(raw)


def digest(value: object) -> str:
    require(type(value) is str and DIGEST.fullmatch(value) is not None,
            'authoring digest must be lowercase SHA-256')
    return value


def source_map(document: dict, sources: tuple[bytes, ...]) -> dict:
    require(type(sources) is tuple and 1 <= len(sources) <= 16,
            'authoring requires an immutable source tuple of 1..16 entries')
    require(all(type(data) is bytes for data in sources), 'authoring source must be immutable bytes')
    require(sum(map(len, sources)) <= MAX_SOURCE, 'authoring aggregate source byte budget exceeded')
    metadata = plan_schema.records(document['sources'], 16, 1)
    require(len(metadata) == len(sources), 'authoring source count mismatch')
    result = {}
    for item, data in zip(metadata, sources, strict=True):
        fields(item, SOURCE_FIELDS | {'sha256'})
        name = plan_schema.identifier(item['id'])
        require(name not in result, 'authoring duplicate source identifier')
        require(digest(item['sha256']) == sha(data), 'authoring whole-source digest mismatch: ' + name)
        for key in ('label', 'media_type', 'provenance'):
            plan_schema.text(item[key])
        require(bool(item['media_type']), 'authoring media type must be explicit')
        result[name] = data
    return result


def quoted_span(selection: dict, data: bytes) -> list[int]:
    fields(selection, {'quote', 'at'})
    require(type(selection['quote']) is str, 'authoring quotation must be text')
    raw = selection['quote'].encode('utf-8', errors='strict')
    require(0 < len(raw) <= MAX_SOURCE, 'authoring quotation byte budget exceeded')
    data.decode('utf-8', errors='strict')
    start = selection['at']
    if start is None:
        start = data.find(raw)
        require(start >= 0, 'authoring quotation not found')
        require(data.find(raw, start + 1) < 0,
                'authoring quotation is ambiguous; supply its original byte offset')
    require(type(start) is int and 0 <= start <= len(data), 'authoring invalid quotation byte offset')
    end = start + len(raw)
    require(data[start:end] == raw, 'authoring quotation differs at the supplied byte offset')
    data[:start].decode('utf-8', errors='strict')
    return [start, end]


def selected_span(selection: object, data: bytes) -> list[int]:
    require(type(selection) is dict, 'authoring selection must be an object')
    if 'quote' in selection:
        return quoted_span(selection, data)
    fields(selection, {'span', 'sha256'})
    span = selection['span']
    require(type(span) is list and len(span) == 2, 'authoring byte selection needs two offsets')
    begin, end = span
    require(type(begin) is int and type(end) is int and 0 <= begin <= end <= len(data),
            'authoring selected byte range out of bounds')
    require(begin < end or (not data and begin == end == 0),
            'authoring empty selection permitted only for empty source')
    require(digest(selection['sha256']) == sha(data[begin:end]), 'authoring selected byte digest mismatch')
    return [begin, end]


def anchors(value: object, sources: dict) -> list:
    result = []
    for item in plan_schema.records(value, 16, 1):
        fields(item, {'source', 'selection'})
        name = plan_schema.identifier(item['source'])
        require(name in sources, 'authoring anchor source missing')
        result.append({'source': name, 'span': selected_span(item['selection'], sources[name])})
    return result


def declarations(value: object, cap: int, sources: dict) -> list:
    result = []
    for item in plan_schema.records(value, cap):
        require(type(item) is dict and 'anchors' in item, 'authoring declaration anchors missing')
        result.append(dict(item, anchors=anchors(item['anchors'], sources)))
    return result


def node(value: object, data: bytes) -> dict:
    require(type(value) is dict, 'authoring node must be an object')
    result = dict(value)
    if 'span' in value:
        result['span'] = selected_span(value['span'], data)
    if 'cue' in value:
        result['cue'] = [0, 0] if value['cue'] is None else selected_span(value['cue'], data)
    if 'mentions' in value:
        mentions = []
        for mention in plan_schema.records(value['mentions'], 8, 1):
            fields(mention, {'symbol', 'span'})
            mentions.append(dict(mention, span=selected_span(mention['span'], data)))
        result['mentions'] = mentions
    return result


def typed_plan(value: object, data: bytes) -> dict:
    fields(value, {'schema', 'symbols', 'meaning'})
    meaning = value['meaning']
    fields(meaning, {'schema', 'nodes', 'root', 'ambiguities'})
    nodes = [node(item, data) for item in plan_schema.records(meaning['nodes'], MAX_NODES, 1)]
    ambiguities = []
    for item in plan_schema.records(meaning['ambiguities'], 16):
        fields(item, {'span', 'note'})
        ambiguities.append(dict(item, span=selected_span(item['span'], data)))
    return dict(value, meaning=dict(meaning, nodes=nodes, ambiguities=ambiguities))


def units(value: object, sources: dict) -> list:
    result = []
    for item in plan_schema.records(value, semantics.MAX_UNITS):
        fields(item, semantics.UNIT_KEYS | {'plan'})
        name = plan_schema.identifier(item['source'])
        require(name in sources, 'authoring unit source missing')
        result.append(dict(item, plan=typed_plan(item['plan'], sources[name])))
    return result


def compile_plan(sources: tuple[bytes, ...], document: bytes) -> bytes:
    checked_runtime()
    value = json_value(document, MAX_SOURCE)
    fields(value, {'schema', 'sources', 'interpretations', 'uncertainties', 'relations', 'meaning_units'})
    require(value['schema'] == SCHEMA, 'incompatible authoring schema')
    source_data = source_map(value, sources)
    result = {'schema': plan_schema.PLAN,
              'sources': [{key: item[key] for key in SOURCE_FIELDS} for item in value['sources']]}
    for group, cap in GROUP_LIMITS.items():
        result[group] = declarations(value[group], cap, source_data)
    typed = units(value['meaning_units'], source_data)
    if typed:
        result.update(schema=plan_schema.PLAN_V2, meaning_units=typed)
    compiled = canonical(result)
    plan_schema.check_plan(compiled, sources)
    return compiled


def excerpts(checked: dict, sources: dict) -> list:
    intervals = set()
    for group in GROUP_LIMITS:
        for item in checked[group]:
            for anchor in item['anchors']:
                intervals.add((anchor['source'], *anchor['span']))
    result, total = [], 0
    for name, begin, end in sorted(intervals):
        total += end - begin
        require(total <= MAX_SOURCE, 'authoring review excerpt byte budget exceeded; no excerpts dropped')
        raw = sources[name][begin:end]
        result.append(dict(source=name, span=[begin, end], bytes=len(raw), sha256=sha(raw),
                           bytes_base64=base64.b64encode(raw).decode('ascii')))
    return result


def review(sources: tuple[bytes, ...], document: bytes, compiled: bytes) -> bytes:
    checked = plan_schema.check_plan(compiled, sources)
    source_data = {item['id']: data for item, data in zip(checked['sources'], sources, strict=True)}
    bound_sources = [dict(item, bytes=len(source_data[item['id']]), sha256=sha(source_data[item['id']]))
                     for item in checked['sources']]
    typed = [semantics.unit_view(item, source_data[item['source']])
             for item in checked.get('meaning_units', [])]
    producer = read_bounded(Path(__file__).resolve(), MAX_WIRE)
    report = dict(schema='transport/authoring-review/1', status='SOURCE_REFERENCES_AND_TYPES_CHECKED',
                  document_sha256=sha(document), plan_sha256=sha(compiled), sources=bound_sources,
                  producer=dict(path='tools/transport_authoring.py', bytes=len(producer), sha256=sha(producer)),
                  base_runtime_sha256=BASE_RUNTIME_SHA256, assurance=dict(BOUNDARY),
                  formula=plan_schema.formula(checked).decode('utf-8'), meaning_units=typed,
                  source_excerpts=excerpts(checked, source_data), coverage=plan_schema.coverage(checked),
                  display_definitions=plan_schema.DISPLAY, relation_definitions=plan_schema.RELATIONS,
                  interpretation_supplied=bool(checked['interpretations']))
    for group in GROUP_LIMITS:
        report[group] = checked[group]
    return canonical(report)


def check_outputs(files: dict) -> None:
    require(type(files) is dict and set(files) in (COMPILE_FILES, ENCODE_FILES),
            'authoring output membership mismatch')
    require(all(type(data) is bytes and len(data) <= MAX_WIRE for data in files.values()),
            'authoring output file byte budget exceeded')
    require(sum(map(len, files.values())) <= MAX_OUTPUT_BYTES,
            'authoring aggregate output byte budget exceeded')


def compile_outputs(sources: tuple[bytes, ...], document: bytes) -> dict[str, bytes]:
    compiled = compile_plan(sources, document)
    result = {'plan.json': compiled, 'review.json': review(sources, document, compiled)}
    check_outputs(result)
    return result


def encode(sources: tuple[bytes, ...], document: bytes,
           reference: str = 'attached:meaning.zip', budget: int = 512) -> dict[str, bytes]:
    result = compile_outputs(sources, document)
    pair = package.encode(sources, result['plan.json'], reference, budget)
    result.update({'share.txt': pair.text, 'meaning.zip': pair.archive, 'lexicon.md': pair.lexicon})
    check_outputs(result)
    return result


def publish(directory: Path, files: dict[str, bytes]) -> None:
    check_outputs(files)
    stage = Path(tempfile.mkdtemp(prefix='.transport-authoring-', dir=directory.parent))
    identity = stage.lstat()
    require(stat.S_ISDIR(identity.st_mode) and identity.st_uid == os.geteuid()
            and stat.S_IMODE(identity.st_mode) == 0o700, 'authoring stage ownership mismatch')
    published = False
    try:
        for name, data in sorted(files.items()):
            warning = write_new(stage / name, data)
            require(not warning, 'authoring output cleanup warning: ' + warning)
            require(read_bounded(stage / name, MAX_WIRE) == data, 'authoring output readback mismatch')
        rename_new(stage, directory)
        published = True
    finally:
        if not published:
            current = stage.lstat()
            require((current.st_dev, current.st_ino, current.st_uid) ==
                    (identity.st_dev, identity.st_ino, identity.st_uid),
                    'authoring stage identity changed; cleanup refused')
            for name in files:
                (stage / name).unlink(missing_ok=True)
            stage.rmdir()


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    for action in ('compile', 'encode'):
        command = commands.add_parser(action)
        command.add_argument('document', type=Path)
        command.add_argument('output', type=Path)
        command.add_argument('--source', action='append', required=True, default=[])
        if action == 'encode':
            command.add_argument('--reference', default='attached:meaning.zip')
            command.add_argument('--budget', type=int, default=512,
                                 help='Whole share Unicode code points, including identity and reference')
    return parser.parse_args()


def main() -> int:
    resource.setrlimit(resource.RLIMIT_AS, (268_435_456, 268_435_456))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_WIRE, MAX_WIRE))
    args = arguments()
    try:
        document = read_bounded(args.document, MAX_SOURCE)
        sources = source_bytes(document, args.source)
        files = (encode(sources, document, args.reference, args.budget) if args.action == 'encode'
                 else compile_outputs(sources, document))
        publish(args.output, files)
        result = dict(status='MATCHED_PAIR_WRITTEN' if args.action == 'encode' else 'PLAN_COMPILED',
                      files=[dict(path=name, bytes=len(data), sha256=sha(data))
                             for name, data in sorted(files.items())], assurance=dict(BOUNDARY))
        if 'share.txt' in files:
            result.update(share_characters=len(files['share.txt'].decode('utf-8')),
                          counting='Unicode code points including identity, reference and newlines')
        sys.stdout.buffer.write(canonical(result) + b'\n')
        return 0
    except (ValueError, OSError, MemoryError, UnicodeError, subprocess.TimeoutExpired) as error:
        print('REFUSED: ' + str(error)[:256], file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
