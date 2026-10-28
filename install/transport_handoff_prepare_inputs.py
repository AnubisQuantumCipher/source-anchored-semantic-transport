"""Pinned generic preparation inputs; local helper bootstrap and host are trusted."""

from pathlib import Path
import sys

import transport_handoff_inputs as inputs
from transport_install_support import canonical, read_regular, require, sha

SCHEMA = 'transport/handoff-preparation/1'
MAX_TASK, MAX_PREP_BYTES = 32768, 16777216


def absolute(value):
    require(type(value) is str and 0 < len(value.encode()) < 4096, 'absolute path byte bound')
    path = Path(value)
    require(path.is_absolute() and '..' not in path.parts and len(path.parts) <= 65
            and str(path) == value, 'canonical absolute path required')
    return path


def pinned(item, cap=4194304):
    inputs.fields(item, ('path', 'bytes', 'sha256'))
    path = absolute(item['path'])
    return path, inputs.checked_file(path, item, cap)


def source_inputs(config):
    sources, held, content, checks = [], {}, {}, []
    entries = config['sources']
    require(type(entries) is list and 1 <= len(entries) <= 16, 'source count bound')
    total = 0
    for index, entry in enumerate(entries):
        keys = {'id', 'label', 'media_type', 'provenance', 'bytes', 'sha256'}
        inputs.fields(entry, keys | ({'path'} if config['arm'] == 'original' else set()))
        value = {key: entry[key] for key in ('id', 'label', 'media_type', 'provenance', 'bytes')}
        require(type(entry['bytes']) is int and 0 <= entry['bytes'] <= 65536, 'source byte bound')
        require(type(entry['id']) is str and entry['id'] not in held, 'duplicate/invalid source id')
        held[entry['id']] = inputs.digest(entry['sha256'])
        if config['arm'] == 'original':
            item = {key: entry[key] for key in ('path', 'bytes', 'sha256')}
            path, raw = pinned(item, 65536)
            checks.append((path, raw))
            value['path'] = 'source-%02d.bin' % index
            content[value['path']] = raw
        total += entry['bytes']
        require(total <= 65536, 'aggregate source byte bound')
        sources.append(value)
    inputs.source_metadata(dict(arm=config['arm'], sources=sources, held_source_sha256=held))
    return sources, held, content, checks


def transport_inputs(config):
    pair, bundle = config['pair'], config['bundle']
    inputs.fields(pair, ('share', 'archive', 'identity'))
    inputs.fields(bundle, ('path', 'install_sha256', 'snapshot_sha256'))
    require(type(pair['identity']) is str and inputs.re.fullmatch(r'STS1:[0-9a-f]{64}', pair['identity']) is not None,
            'externally held package identity required')
    root = absolute(bundle['path'])
    from test_portable_handoff import bundle_snapshot
    snapshot = bundle_snapshot(root)
    require(sha(canonical(snapshot)) == inputs.digest(bundle['snapshot_sha256'])
            and snapshot['install_manifest']['sha256'] == inputs.digest(bundle['install_sha256']),
            'externally held bundle identity mismatch')
    content, checks = {}, []
    for key, name in (('share', 'share.txt'), ('archive', 'meaning.zip')):
        path, raw = pinned(pair[key], inputs.CAP)
        content[name] = raw
        checks.append((path, raw))
    require(checks[0][0] != checks[1][0], 'duplicate pair path')
    return content, checks, snapshot


def load(path, expected):
    path = absolute(str(path))
    raw = read_regular(path, inputs.REQUEST_CAP)
    require(sha(raw) == inputs.digest(expected), 'externally held preparation config mismatch')
    config = inputs.json_value(raw)
    common = {'schema', 'arm', 'task', 'python', 'sources'}
    require(config.get('arm') in ('original', 'transport'), 'unknown preparation arm')
    inputs.fields(config, common | ({'bundle', 'pair'} if config['arm'] == 'transport' else set()))
    require(config['schema'] == SCHEMA, 'unsupported preparation config')
    task_path, task = pinned(config['task'], MAX_TASK)
    require(task and '\x00' not in task.decode('utf-8'), 'nonempty UTF-8 task required')
    python, python_raw = pinned(config['python'])
    require(python == Path(sys.executable).resolve(), 'running Python differs from held executable')
    sources, held, content, checks = source_inputs(config)
    checks.extend([(path, raw), (task_path, task), (python, python_raw)])
    snapshot = None
    if config['arm'] == 'transport':
        content, extra, snapshot = transport_inputs(config)
        checks.extend(extra)
    require(len({str(item[0]) for item in checks}) == len(checks), 'duplicate input paths')
    require(sum(len(item[1]) for item in checks) <= MAX_PREP_BYTES, 'preparation input byte bound')
    return dict(config=config, config_raw=raw, task=task, sources=sources, held=held,
                content=content, checks=checks, snapshot=snapshot)


def verify(state):
    require(len(state['checks']) <= 32, 'checked input count bound')
    for path, raw in state['checks']:
        require(read_regular(path) == raw, 'preparation input changed')
    if state['snapshot'] is not None:
        from test_portable_handoff import bundle_snapshot
        require(bundle_snapshot(Path(state['config']['bundle']['path'])) == state['snapshot'], 'source bundle changed')
