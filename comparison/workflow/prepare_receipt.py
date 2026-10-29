#!/usr/bin/env python3
"""Retain bounded raw observations and reproduce this checkpoint's byte receipt.

No archive member is extracted or executed. Materialized test workspaces are
excluded; their complete literal expectations and frozen test code are retained.
This is recorded engineering evidence, not a fresh test or semantic verdict.
"""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import zipfile
import zlib

HERE = Path(__file__).absolute().parent
ROOT = HERE.parents[1]
UTILITY_SHA = '37fcb93b3ed20edb98b62416d923fe4a8612496e77f218ef5367a4de7a80d983'
SOURCES = ('native_workspace.py', 'test_workflow.py', 'test_boundaries.py', 'test_evidence.py',
           'test_native_tools.py', 'contract.json', 'contract-io-addendum.json',
           'oracle.json', 'boundary-controls.json', 'native-tool-oracle.json',
           'README.md', 'review.json', 'prepare_receipt.py', 'evidence-first/observations.zip',
           'evidence-first/origins.json', 'evidence-first/failure.json', 'evidence-first/review-index.json')
MEMBERS, TOTAL, MEMBER_BYTES = 2048, 8388608, 262144
CAPTURE_DIRS = ('captures', 'receipts', 'configs')
BASE_SOURCES = (
    'comparison/workflow/native_workspace.py', 'comparison/workflow/test_workflow.py',
    'comparison/workflow/contract.json', 'comparison/workflow/oracle.json',
    'comparison/workflow/contract-io-addendum.json', 'comparison/retrieval/oracle.json',
    'comparison/retrieval/retrieval.py', 'comparison/retrieval/adapter.py',
    'install/transport_handoff_reader.py', 'install/transport_handoff_inputs.py',
    'install/transport_handoff_session.py', 'install/transport_install_support.py',
    'install/transport_install_layout.py', 'install/transport_response_evidence.py',
    'install/transport_response_contract_model.py', 'install/transport_response_contract.py')


def need(value, reason):
    if type(value) is not bool or not value:
        raise ValueError(reason)


def utility():
    path = ROOT / 'comparison/retrieval/client/prepare_receipt.py'
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        item = os.fstat(descriptor)
        need(stat.S_ISREG(item.st_mode) and item.st_size <= 65536, 'fixed utility bound')
        with os.fdopen(os.dup(descriptor), 'rb') as stream:
            raw = stream.read(65537)
    finally:
        os.close(descriptor)
    need(hashlib.sha256(raw).hexdigest() == UTILITY_SHA, 'fixed utility pin')
    specification = importlib.util.spec_from_file_location('_native_evidence_bytes', path)
    module = importlib.util.module_from_spec(specification)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def children(path):
    found = []
    with os.scandir(path) as entries:
        for unused in range(MEMBERS + 1):
            item = next(entries, None)
            if item is None:
                return sorted(found, key=lambda value: value.name)
            need(len(found) < MEMBERS and not item.is_symlink(), 'observation directory bound/type')
            found.append(item)
    raise ValueError('observation directory iteration bound')


def selected(root, checked):
    need(root.is_absolute() and '..' not in root.parts and not root.is_symlink(), 'observation root')
    result = {}
    for entry in children(root):
        if entry.is_file(follow_symlinks=False):
            result[entry.name] = Path(entry.path)
        elif entry.is_dir(follow_symlinks=False):
            for item in children(Path(entry.path)):
                relative = entry.name + '/' + item.name
                if item.is_file(follow_symlinks=False):
                    result[relative] = Path(item.path)
                elif item.is_dir(follow_symlinks=False) and item.name in CAPTURE_DIRS:
                    for captured in children(Path(item.path)):
                        need(captured.is_file(follow_symlinks=False), 'capture must be regular')
                        result[relative + '/' + captured.name] = Path(captured.path)
                need(len(result) <= MEMBERS, 'observation member bound')
        need(len(result) <= MEMBERS, 'observation member bound')
    for name in result:
        checked.member_name(name)
    return result


def capture(root, checked):
    files = selected(root, checked)
    need(bool(files), 'no observations')
    destination = HERE / 'evidence'
    destination.mkdir(mode=0o700)
    total, origins = 0, {}
    with zipfile.ZipFile(destination / 'observations.zip', 'x', compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9, allowZip64=False) as archive:
        for name, path in sorted(files.items()):
            raw = checked.read(path)
            need(len(raw) <= MEMBER_BYTES, 'observation file byte bound')
            total += len(raw)
            need(total <= TOTAL, 'observation aggregate byte bound')
            item = zipfile.ZipInfo(name, date_time=(2026, 10, 29, 0, 0, 0))
            item.create_system, item.external_attr = 3, (stat.S_IFREG | 0o600) << 16
            item.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(item, raw)
            origins[name] = dict(path=str(path), **checked.pin(raw))
    need((destination / 'observations.zip').stat().st_size <= checked.MAX_FILE, 'archive byte bound')
    value = {'schema': 'transport/native-workflow-observations/1', 'members': origins,
             'selection': 'Root files; campaign root files and captures/receipts/configs. '
                          'Materialized inputs/outputs/negative trees/tmp excluded; no execution or extraction.'}
    with (destination / 'origins.json').open('xb') as stream:
        raw = checked.canonical(value)
        need(stream.write(raw) == len(raw), 'short origins write')
    return len(files), total


def observations(checked):
    archive_raw = checked.read(HERE / 'evidence/observations.zip')
    origins_raw = checked.read(HERE / 'evidence/origins.json')
    origins = checked.json_value(origins_raw)
    need(type(origins) is dict and set(origins) == {'schema', 'members', 'selection'}
         and origins['schema'] == 'transport/native-workflow-observations/1'
         and type(origins['selection']) is str and len(origins['selection']) <= 1024, 'origins schema')
    expected = origins['members']
    need(type(expected) is dict and 1 <= len(expected) <= MEMBERS, 'origin member bound')
    contents, total = {}, 0
    with zipfile.ZipFile(io.BytesIO(archive_raw)) as archive:
        entries = archive.infolist()
        need(1 <= len(entries) <= MEMBERS, 'archive member bound')
        for item in entries:
            checked.member_name(item.filename)
            need(item.filename not in contents and item.filename in expected and not item.is_dir()
                 and item.orig_filename == item.filename and item.flag_bits == 0
                 and item.compress_type == zipfile.ZIP_DEFLATED and 0 <= item.file_size <= MEMBER_BYTES
                 and stat.S_ISREG(item.external_attr >> 16), 'archive entry type/bound')
            total += item.file_size
            need(total <= TOTAL, 'archive aggregate byte bound')
            with archive.open(item) as stream:
                raw = stream.read(item.file_size + 1)
            held = expected[item.filename]
            need(type(held) is dict and set(held) == {'path', 'bytes', 'sha256'}
                 and type(held['path']) is str and len(held['path']) <= 4096
                 and type(held['bytes']) is int and type(held['sha256']) is str
                 and len(raw) == item.file_size
                 and checked.pin(raw) == {key: held[key] for key in ('bytes', 'sha256')}, 'observation pin differs')
            contents[item.filename] = raw
    need(set(contents) == set(expected), 'missing observations')
    return contents, total, archive_raw, origins_raw


def process_counts(contents, checked):
    counts = {}
    for name, raw in sorted(contents.items()):
        if not name.endswith('.json') or not ('/captures/' in name or name.count('/') == 1):
            continue
        value = checked.json_value(raw)
        if type(value) is not dict or not {'argv', 'stdout', 'stderr', 'exit_code'} <= set(value):
            continue
        for stream in ('stdout', 'stderr'):
            path = name[:-5] + '.' + stream
            need(path in contents and value[stream] == checked.pin(contents[path]), 'process stream pin differs')
        campaign = name.split('/', 1)[0]
        counts[campaign] = counts.get(campaign, 0) + 1
    for name, count in (('portable-03', 87), ('local-01', 139), ('portable-O-01', 87), ('boundaries-02', 22)):
        need(counts.get(name) == count, 'required retained process count differs: ' + name)
    return counts


def native_binding(contents, checked):
    for campaign, calls in (('native-tools-local-01', 16), ('native-tools-portable-01', 8)):
        raw = contents[campaign + '/T-preparation.json']
        before = checked.json_value(raw)
        run = checked.json_value(contents[campaign + '/receipt.json'])
        need(run['status'] == 'PASS' and run['preparation'] == checked.pin(raw)
             and run['calls'] == calls and len(before['schedule']) == calls, 'native preparation binding')
        for item in before['schedule']:
            prefix = campaign + '/' + item['label']
            record = checked.json_value(contents[prefix + '.json'])
            need(all(record[key] == item[key] for key in ('argv', 'cwd', 'arm', 'kind', 'label')),
                 'native schedule record differs')
            for stream in ('stdout', 'stderr'):
                need(record[stream] == checked.pin(contents[prefix + '.' + stream]), 'native stream absent/differs')


def source_binding(contents, checked, counts):
    for campaign in ('portable-03', 'portable-O-01', 'local-01'):
        run = checked.json_value(contents[campaign + '/receipt.json'])
        before = checked.json_value(contents[campaign + '/T-preparation.json'])
        need(run['status'] == 'PASS' and run['source_pins'] == before['source_pins'], 'run/freeze sources differ')
        need(run['profile']['executions'] == counts[campaign]
             and {k: v for k, v in run['profile'].items() if k != 'executions'} ==
                 {k: v for k, v in before['profile'].items() if k != 'executions'}, 'run/freeze profile differs')
        need(run['cases'] == [item['name'] for item in before['cases']], 'run/freeze cases differ')
        records = run['source_pins']
        need(type(records) is list and len(records) == len(BASE_SOURCES) + 1, 'base source inventory shape')
        for relative in BASE_SOURCES:
            matches = [item for item in records if type(item) is dict
                       and type(item.get('path')) is str and item['path'].endswith('/' + relative)]
            need(len(matches) == 1 and set(matches[0]) == {'path', 'bytes', 'sha256'}, 'base source record')
            need({key: matches[0][key] for key in ('bytes', 'sha256')}
                 == checked.pin(checked.read(ROOT / relative)), 'tested source no longer matches: ' + relative)


def derived(checked):
    contents, expanded, archive_raw, origins_raw = observations(checked)
    counts = process_counts(contents, checked)
    source_binding(contents, checked, counts)
    native_binding(contents, checked)
    sources = {name: checked.pin(checked.read(HERE / name)) for name in SOURCES}
    sources['ci/native-source-workflow.yml'] = checked.pin(
        checked.read(ROOT / '.github/workflows/native-source-workflow.yml'))
    sources['evidence/observations.zip'] = checked.pin(archive_raw)
    sources['evidence/origins.json'] = checked.pin(origins_raw)
    runs = {}
    for name, raw in sorted(contents.items()):
        if name.count('/') == 1 and name.endswith('/receipt.json'):
            value = checked.json_value(raw)
            if type(value) is dict and value.get('status') == 'PASS':
                runs[name] = {'pin': checked.pin(raw), 'mode': value.get('mode'),
                              'profile': value.get('profile'), 'calls': value.get('calls'), 'status': 'PASS'}
    need(all(name + '/receipt.json' in runs for name in ('portable-03', 'portable-O-01', 'local-01')),
         'missing required retained PASS assertions')
    return checked.canonical({'schema': 'transport/native-workflow-development-receipt/1',
        'status': 'TESTED_DEVELOPMENT_NOT_ACCEPTED', 'source_base': '3ce26592d87521a7e2d9d74a49a2d3eb6daf1c6a',
        'files': sources, 'observation_members': len(contents), 'observation_expanded_bytes': expanded,
        'process_records': counts, 'recorded_runs': runs,
        'claims': 'Exact recorded bytes, source pins and process streams checked; no archive extraction or execution. '
                  'Fresh behavior requires the documented tests. Python tests do not extend existing SPARK proof scope.',
        'open': ['semantic adequacy', 'strongest baseline qualification', 'human or model continuation benefit',
                 'external validation', 'formal integration proof', 'hostile same-user and crash durability']})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--capture-from', type=Path)
    args = parser.parse_args()
    need(not (args.check and args.capture_from is not None), 'closed operation')
    checked = utility()
    if args.capture_from is not None:
        print(capture(args.capture_from, checked))
        return
    raw = derived(checked)
    if args.check:
        need(checked.read(HERE / 'receipt.json') == raw, 'receipt does not reproduce')
    else:
        with (HERE / 'receipt.json').open('xb') as stream:
            need(stream.write(raw) == len(raw), 'short receipt write')
    print('Native source workflow inventory and retained process streams match')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, UnicodeError, KeyError, TypeError, zipfile.BadZipFile,
            zipfile.LargeZipFile, zlib.error, NotImplementedError) as error:
        print('REFUSED: ' + str(error), file=sys.stderr)
        raise SystemExit(1)
