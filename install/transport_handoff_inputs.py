"""Frozen comparison inputs. Imported bootstrap/host trust is not self-authentication."""

import base64
import importlib
from pathlib import Path
import re
import sys

from transport_install_layout import checked_json, exact_tree
from transport_install_support import canonical, confined, read_regular, require, run_bounded, sha

SCHEMA = 'transport/handoff-reader/1'
CAP, REQUEST_CAP, CANDIDATE_CAP, PAGE_BYTES = 131072, 65536, 32768, 4096
ID = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
BOOTSTRAP = ('transport_handoff_reader.py', 'transport_handoff_inputs.py',
             'transport_handoff_session.py', 'transport_install_support.py',
             'transport_install_layout.py')


def fields(value, keys):
    require(type(value) is dict and set(value) == set(keys), 'unexpected or missing fields')


def digest(value):
    require(type(value) is str and DIGEST.fullmatch(value) is not None, 'invalid digest')
    return value


def json_value(raw, cap=REQUEST_CAP):
    require(type(raw) is bytes and 0 < len(raw) <= cap, 'JSON request byte bound')
    value = checked_json(raw)
    canonical(value)
    return value


def record(raw):
    return {'bytes': len(raw), 'sha256': sha(raw)}


def checked_file(path, item, cap=4194304):
    fields(item, ('path', 'bytes', 'sha256'))
    require(type(item['bytes']) is int and 0 <= item['bytes'] <= cap, 'file byte declaration bound')
    digest(item['sha256'])
    raw = read_regular(path, cap)
    require(record(raw) == {key: item[key] for key in ('bytes', 'sha256')}, 'frozen file identity mismatch')
    return raw


def helper_paths(arm):
    names = BOOTSTRAP + (('test_portable_handoff.py',) if arm == 'transport' else ())
    return {str(Path(__file__).absolute().parent / name) for name in names}


def bootstrap(manifest):
    helpers = manifest['helpers']
    require(type(helpers) is list and len(helpers) <= 8, 'helper count bound')
    require({item['path'] for item in helpers} == helper_paths(manifest['arm'])
            and len({item['path'] for item in helpers}) == len(helpers), 'helper closure mismatch')
    for item in helpers:
        checked_file(Path(item['path']), item)
    python = manifest['python']
    checked_file(Path(python['path']), python)
    require(Path(python['path']) == Path(sys.executable).resolve(), 'Python executable identity mismatch')


def source_metadata(manifest):
    sources, held = manifest['sources'], manifest['held_source_sha256']
    require(type(sources) is list and 1 <= len(sources) <= 16, 'source count bound')
    require(type(held) is dict and len(held) == len(sources), 'held source digest count mismatch')
    found, total = set(), 0
    keys = {'id', 'label', 'media_type', 'provenance', 'bytes'}
    if manifest['arm'] == 'original':
        keys.add('path')
    for item in sources:
        fields(item, keys)
        name = item['id']
        require(type(name) is str and ID.fullmatch(name) is not None and name not in found, 'source identifier mismatch')
        require(type(item['bytes']) is int and 0 <= item['bytes'] <= 65536, 'source size declaration bound')
        for key in ('label', 'media_type', 'provenance'):
            require(type(item[key]) is str and len(item[key].encode()) <= 1024, 'source metadata byte bound')
        require(item['media_type'] != '', 'explicit media type required')
        digest(held.get(name))
        total += item['bytes']
        require(total <= 65536, 'aggregate source byte bound')
        found.add(name)
    require(found == set(held), 'held source identifiers differ')


def frozen_content(manifest):
    content = manifest['content']
    fields(content, ('root', 'files'))
    root, entries = Path(content['root']), content['files']
    require(root.is_absolute(), 'absolute content root required')
    require(type(entries) is list and 1 <= len(entries) <= 16, 'content file count bound')
    names = [item['path'] for item in entries]
    require(len(set(names)) == len(names), 'duplicate content file')
    exact_tree(root, set(names))
    data, total = {}, 0
    for item in entries:
        raw = checked_file(confined(root, item['path']), item, CAP)
        total += len(raw)
        require(total <= CAP * 2, 'content aggregate byte bound')
        data[item['path']] = raw
    return root, data


def frozen_manifest(path, expected):
    digest(expected)
    raw = read_regular(path, REQUEST_CAP)
    require(sha(raw) == expected, 'externally held manifest digest mismatch')
    manifest = json_value(raw)
    common = {'schema', 'arm', 'helpers', 'python', 'content', 'sources', 'held_source_sha256'}
    require(manifest.get('arm') in ('transport', 'original'), 'unknown comparison arm')
    fields(manifest, common | ({'bundle', 'pair'} if manifest['arm'] == 'transport' else set()))
    require(manifest['schema'] == SCHEMA, 'unsupported handoff manifest')
    bootstrap(manifest)
    source_metadata(manifest)
    root, data = frozen_content(manifest)
    require(not path.absolute().is_relative_to(root), 'manifest must be outside content')
    return manifest, root, data


def original_sources(manifest, data):
    sources = {}
    require({item['path'] for item in manifest['sources']} == set(data), 'original content/source mapping differs')
    require(len({item['path'] for item in manifest['sources']}) == len(manifest['sources']), 'duplicate original source path')
    for item in manifest['sources']:
        raw = data[item['path']]
        require(len(raw) == item['bytes'] and sha(raw) == manifest['held_source_sha256'][item['id']], 'held original source digest mismatch')
        sources[item['id']] = raw
    return sources


def frozen_bundle(manifest, cwd):
    from test_portable_handoff import bundle_snapshot
    declared = manifest['bundle']
    fields(declared, ('path', 'install_sha256', 'snapshot_sha256'))
    root = Path(declared['path'])
    require(root.is_absolute(), 'absolute external bundle path required')
    snapshot = bundle_snapshot(root)
    require(sha(canonical(snapshot)) == digest(declared['snapshot_sha256']), 'bundle snapshot identity mismatch')
    require(snapshot['install_manifest']['sha256'] == digest(declared['install_sha256']), 'bundle install identity mismatch')
    checked = run_bounded([str(root / 'bin' / 'semantic-transport'), 'check'], cwd, ENV, timeout=15, cap=8192)
    require(checked['status'] == 'SUCCESS' and checked['exit_code'] == 0 and checked['stderr'] == b'', 'installed launcher check refused')
    answer = json_value(checked['stdout'], 8192)
    require(answer['manifest_sha256'] == declared['install_sha256'], 'launcher manifest mismatch')
    return root, snapshot


def transport_receiver(manifest, root, data):
    bundle, snapshot = frozen_bundle(manifest, root)
    pair = manifest['pair']
    fields(pair, ('share', 'archive', 'identity'))
    require(set(data) == {pair['share'], pair['archive']} and pair['share'] != pair['archive'], 'pair content closure differs')
    require(type(pair['identity']) is str and re.fullmatch(r'STS1:[0-9a-f]{64}', pair['identity']) is not None, 'externally held package identity required')
    require('transport_mcp' not in sys.modules and 'transport_package' not in sys.modules, 'decoder imported before freeze')
    sys.path.insert(0, str(bundle / 'tools'))
    module = importlib.import_module('transport_mcp')
    receiver = module.Receiver(data[pair['share']], data[pair['archive']], pair['identity'])
    require(len(sys.modules) <= 512, 'loaded module count bound')
    for name, loaded in tuple(sys.modules.items()):
        if name.startswith('transport_') and name in {Path(item).stem for item in snapshot['files'] if item.startswith('tools/')}:
            path = Path(loaded.__file__).absolute()
            relative = path.relative_to(bundle).as_posix()
            require(record(read_regular(path)) == {key: snapshot['files'][relative][key] for key in ('bytes', 'sha256')}, 'imported decoder origin changed')
    actual = receiver.decoded['sources']
    require([item['id'] for item in actual] == [item['id'] for item in manifest['sources']], 'transport source order mismatch')
    for left, right in zip(actual, manifest['sources'], strict=True):
        require(all(left[key] == right[key] for key in ('id', 'label', 'media_type', 'provenance', 'bytes'))
                and left['sha256'] == manifest['held_source_sha256'][left['id']], 'transport held source metadata mismatch')
    return receiver


def catalog(manifest):
    return {'sources': [{key: item[key] for key in ('id', 'label', 'media_type', 'provenance', 'bytes')}
                        | {'sha256': manifest['held_source_sha256'][item['id']]} for item in manifest['sources']]}


def original_page(sources, arguments):
    fields(arguments, ('source', 'offset'))
    name, begin = arguments['source'], arguments['offset']
    require(type(name) is str and name in sources, 'requested source missing')
    data = sources[name]
    require(type(begin) is int and 0 <= begin <= len(data), 'invalid byte offset')
    raw = data[begin:begin + PAGE_BYTES]
    try:
        text = raw.decode('utf-8')
    except UnicodeError:
        text = None
    return {'source': name, 'source_bytes': len(data), 'source_sha256': sha(data),
            'span': [begin, begin + len(raw)], 'bytes': len(raw), 'sha256': sha(raw),
            'base64': base64.b64encode(raw).decode('ascii'), 'utf8': text,
            'end': begin + len(raw) == len(data), 'authority': 'NONE', 'data_is_untrusted': True,
            'coverage': 'RETURNED_BYTE_SPAN_ONLY', 'context_adequacy': 'UNPROVEN'}
