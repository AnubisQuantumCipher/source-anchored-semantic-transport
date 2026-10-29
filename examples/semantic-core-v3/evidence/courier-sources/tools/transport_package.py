"""Source-Anchored Semantic Transport: bounded source and declared meanings."""

import base64
import binascii
import os
import platform
import re
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

import transport_plan as schema
import transport_semantics as semantics
from transport_schema import canonical, fields, json_value, require, sha
from transport_archive import read_archive, write_archive
from transport_wire import CORE, MAX_SOURCE, MAX_WIRE, TransportError, pack, unpack

ROOT = Path(__file__).resolve().parents[1]
CORE_SHA256 = '299c0457f9047c8c68bdd1227418d5968c195ca683b32a2a7e02cf73f4411013'
MODULES = ('transport_archive', 'transport_author', 'transport_cli', 'transport_codec', 'transport_codec_cli', 'transport_corpus', 'transport_formula', 'transport_graph', 'transport_lexicon', 'transport_meaning', 'transport_operators', 'transport_package', 'transport_plan', 'transport_readable', 'transport_references', 'transport_requirement_language', 'transport_schema', 'transport_semantics', 'transport_source_map', 'transport_structure', 'transport_wire')
PRODUCT = 'Source-Anchored Semantic Transport'
FORMATS = {'byte_frame': 'STB1', 'graph': 'STG1', 'mapping': 'STM1',
           'path': 'STP1', 'temporal': 'STT1', 'evaluation': 'STE1', 'share': 'STS1',
           'schema_namespace': 'transport/', 'compatibility': 'EXACT_VERSION_ONLY_NO_FALLBACK'}
LIBRARIES = ('/lib/ld-linux-aarch64.so.1', '/usr/lib/libc.so.6')
REFERENCE = re.compile(r'https://[A-Za-z0-9][A-Za-z0-9._~:/?#\[\]@!$&\x27()*+,;=%-]{0,247}\Z')
BOUNDARIES = dict(schema.ASSURANCE)
LIMITS = {'source_bytes': MAX_SOURCE, 'archive_bytes': MAX_WIRE,
          'metadata_bytes': schema.MAX_METADATA, 'sources': 16, 'interpretations': 32,
          'uncertainties': 32, 'relations': 64, 'anchors_per_record': 16,
          'share_budget_unit': 'Unicode code points', 'share_utf8_bytes': MAX_WIRE}


@dataclass(frozen=True)
class Transport:
    text: bytes
    archive: bytes
    lexicon: bytes


def runtime_file(path: Path, cap: int) -> bytes:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),
                    'Transport runtime dependency must be a regular file')
            data = stream.read(cap + 1)
    except OSError as error:
        raise TransportError('Transport missing or unreadable external dependency: ' + str(path)) from error
    require(len(data) <= cap, 'Transport runtime dependency byte budget exceeded')
    return data


def dependency(path: Path, name: str, cap: int) -> dict:
    data = runtime_file(path, cap)
    return {'path': name, 'bytes': len(data), 'sha256': sha(data)}


def runtime_contract() -> dict:
    require(sys.version_info[:2] == (3, 14), 'Transport incompatible dependency: requires Python 3.14')
    require(platform.system() == 'Linux' and platform.machine() == 'aarch64',
            'Transport incompatible dependency: requires Linux aarch64')
    native = dependency(CORE, 'bin/transport_native', 4_194_304)
    require(native['sha256'] == CORE_SHA256, 'Transport incompatible native core dependency')
    files = [native]
    for name in MODULES:
        relative = 'tools/' + name + '.py'
        files.append(dependency(ROOT / relative, relative, MAX_WIRE))
    libraries = [dependency(Path(name), name, 4_194_304) for name in LIBRARIES]
    return {'schema': 'transport/runtime/1', 'decoder': 'transport/transport/2',
            'python': '3.14', 'platform': 'Linux-aarch64', 'files': files,
            'standard_library': 'Trusted external Python 3.14 standard library',
            'native_libraries': libraries, 'product': PRODUCT, 'formats': FORMATS,
            'boundary': BOUNDARIES['runtime_boundary']}


def reference(value: object) -> str:
    require(type(value) is str and (value == 'attached:meaning.zip' or REFERENCE.fullmatch(value)),
            'Transport reference requires attached:meaning.zip or bounded HTTPS placeholder')
    return value


def share_text(display: bytes, digest: str, ref: str, budget: int) -> bytes:
    require(type(budget) is int and 1 <= budget <= MAX_WIRE, 'Transport share budget invalid')
    result = display + b'\nSTS1:' + digest.encode('ascii') + b'\n' + reference(ref).encode('ascii')
    require(len(result) <= MAX_WIRE, 'Transport share UTF-8 resource byte budget exceeded')
    require(len(result.decode('utf-8')) <= budget,
            'Transport complete share character budget exceeded; no fields dropped')
    return result


def frames(sources: tuple[bytes, ...], plan: dict) -> list:
    result = []
    for metadata, data in zip(plan['sources'], sources, strict=True):
        wire = pack(data)
        result.append({'id': metadata['id'], 'bytes': len(data), 'sha256': sha(data),
                       'wire_base64': base64.b64encode(wire).decode('ascii')})
    return result


def index(plan: dict, source_data: tuple[bytes, ...], lexicon_data: bytes) -> dict:
    sources = []
    for item, data in zip(plan['sources'], source_data, strict=True):
        sources.append({'id': item['id'], 'bytes': len(data), 'sha256': sha(data)})
    result = {'schema': 'transport/index/1', 'sources': sources, 'coverage': schema.coverage(plan),
              'lexicon_sha256': sha(lexicon_data), 'assurance': BOUNDARIES}
    require(len(canonical(result)) <= schema.MAX_METADATA, 'Transport stored index byte budget exceeded')
    return result


def content_entries(plan: dict, source_data: tuple[bytes, ...], source_frames: list) -> dict:
    lexicon_data = schema.lexicon(plan)
    version = '2' if plan['schema'] == schema.PLAN_V2 else '1'
    codec = {'schema': 'transport/codec/' + version, 'plan': plan, 'source_frames': source_frames}
    return {'codec.json': canonical(codec),
            'index.json': canonical(index(plan, source_data, lexicon_data)),
            'formula.txt': schema.formula(plan), 'README.md': lexicon_data}


def manifest_body(entries: dict, runtime: dict, ref: str, budget: int) -> dict:
    bound = [{'name': name, 'bytes': len(entries[name]), 'sha256': sha(entries[name])}
             for name in sorted(entries)]
    return {'entries': bound, 'runtime': runtime, 'reference': reference(ref),
            'share_budget': budget, 'limits': LIMITS, 'assurance': BOUNDARIES,
            'display_definitions': schema.DISPLAY, 'relation_definitions': schema.RELATIONS}


def seal(entries: dict, runtime: dict, ref: str, budget: int) -> tuple[bytes, bytes]:
    body = manifest_body(entries, runtime, ref, budget)
    digest = sha(canonical(body))
    manifest = {'schema': 'transport/meaning-zip/1', 'sha256': digest, 'body': body}
    result = dict(entries, **{'manifest.json': canonical(manifest)})
    text_data = share_text(entries['formula.txt'], digest, ref, budget)
    return text_data, write_archive(result)


def encode(sources: tuple[bytes, ...], plan_data: bytes,
           reference: str = 'attached:meaning.zip', budget: int = 512) -> Transport:
    runtime = runtime_contract()
    plan = schema.check_plan(plan_data, sources)
    require(len(canonical(json_value(plan_data, schema.MAX_METADATA))) <= schema.MAX_METADATA,
            'Transport canonical input plan budget exceeded')
    source_frames = frames(sources, plan)
    entries = content_entries(plan, sources, source_frames)
    text_data, archive_data = seal(entries, runtime, reference, budget)
    recovered = decode(text_data, archive_data)
    require(tuple(item['data'] for item in recovered['sources']) == sources,
            'Transport authoritative reconstruction mismatch')
    require(len(canonical(metadata_view(recovered))) + 1 <= MAX_WIRE,
            'Transport metadata view including output newline exceeds byte budget')
    return Transport(text_data, archive_data, entries['README.md'])


def check_manifest(entries: dict, text_data: bytes) -> dict:
    manifest = json_value(entries['manifest.json'])
    fields(manifest, {'schema', 'sha256', 'body'})
    require(manifest['schema'] == 'transport/meaning-zip/1', 'Transport incompatible manifest schema')
    body = manifest['body']
    fields(body, {'entries', 'runtime', 'reference', 'share_budget', 'limits', 'assurance',
                  'display_definitions', 'relation_definitions'})
    runtime = runtime_contract()
    require(body['runtime'] == runtime, 'Transport missing or incompatible decoder dependency identity')
    content = {name: value for name, value in entries.items() if name != 'manifest.json'}
    expected = manifest_body(content, runtime, body['reference'], body['share_budget'])
    require(body == expected, 'Transport manifest content, limits or definitions mismatch')
    digest = sha(canonical(expected))
    require(manifest['sha256'] == digest, 'Transport manifest identity mismatch')
    require(type(text_data) is bytes and len(text_data) <= MAX_WIRE, 'Transport immutable share text budget exceeded')
    require(text_data == share_text(entries['formula.txt'], digest, body['reference'], body['share_budget']),
            'Transport share text/package identity or exact layout mismatch')
    require(entries['manifest.json'] == canonical(manifest), 'Transport noncanonical manifest JSON')
    return manifest


def recover_frames(value: object) -> tuple[bytes, ...]:
    schema.records(value, 16, 1)
    result, total = [], 0
    for item in value:
        fields(item, {'id', 'bytes', 'sha256', 'wire_base64'})
        schema.identifier(item['id'])
        require(type(item['bytes']) is int and 0 <= item['bytes'] <= MAX_SOURCE,
                'Transport declared source byte budget exceeded')
        require(type(item['wire_base64']) is str and len(item['wire_base64']) <= MAX_WIRE,
                'Transport native frame byte budget exceeded')
        try:
            wire = base64.b64decode(item['wire_base64'], validate=True)
        except (ValueError, binascii.Error) as error:
            raise TransportError('Transport malformed native frame base64') from error
        require(base64.b64encode(wire).decode('ascii') == item['wire_base64'],
                'Transport noncanonical native frame base64')
        data = unpack(wire)
        require(len(data) == item['bytes'] and sha(data) == item['sha256'],
                'Transport original source hash or length mismatch')
        total += len(data)
        require(total <= MAX_SOURCE, 'Transport aggregate reconstructed source budget exceeded')
        result.append(data)
    return tuple(result)


def checked_content(entries: dict) -> tuple[dict, tuple[bytes, ...]]:
    codec = json_value(entries['codec.json'])
    fields(codec, {'schema', 'plan', 'source_frames'})
    require(codec['schema'] in ('transport/codec/1', 'transport/codec/2'), 'Transport incompatible codec schema')
    require(entries['codec.json'] == canonical(codec), 'Transport noncanonical codec JSON')
    sources = recover_frames(codec['source_frames'])
    plan = schema.check_plan(canonical(codec['plan']), sources, stored=True)
    expected_version = '2' if plan['schema'] == schema.PLAN_V2 else '1'
    require(codec['schema'] == 'transport/codec/' + expected_version, 'Transport codec/plan version mismatch')
    require([item['id'] for item in codec['source_frames']] == [item['id'] for item in plan['sources']],
            'Transport source frame/plan order mismatch')
    expected = content_entries(plan, sources, codec['source_frames'])
    require(expected == {name: value for name, value in entries.items() if name != 'manifest.json'},
            'Transport formula, index, lexicon or source declaration regeneration mismatch')
    return plan, sources


def decode(text: bytes, archive: bytes) -> dict:
    entries = read_archive(archive)
    manifest = check_manifest(entries, text)
    plan, sources = checked_content(entries)
    records = []
    for item, data in zip(plan['sources'], sources, strict=True):
        records.append(dict(item, data=data, bytes=len(data), sha256=sha(data)))
    version = '2' if plan['schema'] == schema.PLAN_V2 else '1'
    result = {'schema': 'transport/decoded/' + version, 'identity': 'STS1:' + manifest['sha256'],
            'sources': records, 'interpretations': plan['interpretations'],
            'uncertainties': plan['uncertainties'], 'relations': plan['relations'],
            'coverage': schema.coverage(plan), 'assurance': dict(BOUNDARIES)}
    if version == '2':
        source_map = {item['id']: item['data'] for item in records}
        result['meaning_units'] = [semantics.unit_view(unit, source_map[unit['source']])
                                   for unit in plan['meaning_units']]
    return result


def metadata_view(result: dict) -> dict:
    sources = [{key: value for key, value in item.items() if key != 'data'} for item in result['sources']]
    return dict(result, sources=sources)


def inspect(text: bytes, archive: bytes) -> dict:
    result = metadata_view(decode(text, archive))
    require(len(canonical(result)) + 1 <= MAX_WIRE, 'Transport metadata output byte budget exceeded')
    return result


def validate(text: bytes, archive: bytes) -> dict:
    return inspect(text, archive)


def focused_ids(decoded: dict, unit: str) -> set:
    """Collect declared retrieval neighbours; edge direction does not grant authority."""
    require('meaning_units' in decoded, 'Transport package has no typed meaning units')
    units = decoded['meaning_units']
    require(type(unit) is str and any(item['id'] == unit for item in units),
            'Transport requested meaning unit not found')
    needed = {unit}
    for _ in range(128):
        before = len(needed)
        for item in units:
            if (item['id'] in needed or item['interpretation'] in needed
                    or any(name in needed for name in item['context'])):
                needed.update(item['context'] + [item['id'], item['interpretation'], item['source']])
        for item in decoded['relations']:
            if item['from'] in needed or item['to'] in needed:
                needed.update((item['from'], item['to']))
        for item in decoded['uncertainties']:
            if item['id'] in needed or any(name in needed for name in item['affects']):
                needed.update([item['id']] + item['affects'])
        if len(needed) == before:
            return needed
    raise TransportError('Transport focused dependency closure failed its finite bound')


def focus(text: bytes, archive: bytes, unit: str) -> dict:
    decoded = decode(text, archive)
    needed = focused_ids(decoded, unit)
    result = {group: [item for item in decoded[group] if item['id'] in needed]
              for group in ('meaning_units', 'interpretations', 'uncertainties')}
    result['relations'] = [item for item in decoded['relations']
                           if item['from'] in needed or item['to'] in needed]
    anchors = set()
    for group in ('interpretations', 'uncertainties', 'relations'):
        for item in result[group]:
            for anchor in item['anchors']:
                anchors.add((anchor['source'], *anchor['span'], anchor['sha256']))
    sources = {item['id']: item for item in decoded['sources']}
    excerpts = []
    for source, begin, end, digest in sorted(anchors):
        data = sources[source]['data'][begin:end]
        require(sha(data) == digest, 'Transport focused source anchor mismatch')
        excerpts.append({'source': source, 'span': [begin, end], 'sha256': digest,
                         'bytes_base64': base64.b64encode(data).decode('ascii')})
    expanded = {item['source'] for item in excerpts}
    result['sources'] = [{key: value for key, value in item.items() if key != 'data'}
                         for item in decoded['sources'] if item['id'] in needed or item['id'] in expanded]
    result.update(schema='transport/focus/1', identity=decoded['identity'], selected_unit=unit,
                  source_excerpts=excerpts, context_adequacy='UNPROVEN',
                  unexpanded_sources=[item['id'] for item in result['sources'] if item['id'] not in expanded],
                  source_coverage='DECLARED_EXCERPTS_ONLY_FURTHER_SOURCE_MAY_BE_REQUIRED',
                  dependency_closure='ALL_DECLARED_LINKS_CHECKED', execution_authority='NONE')
    require(len(canonical(result)) + 1 <= MAX_WIRE,
            'Transport focused output including newline exceeds byte budget')
    return result
