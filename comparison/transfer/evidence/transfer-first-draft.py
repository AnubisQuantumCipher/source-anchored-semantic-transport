#!/usr/bin/env python3
"""Bounded conventional transfer comparison; no semantic or authority decisions."""
import argparse
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import re
import resource
import stat
import struct
import subprocess
import sys
import time
import types
import zipfile

ROOT = Path(__file__).resolve().parents[2]
PAYLOAD = 1048576
ARCHIVE = 2097152
OUT_CAP = 33554432
ALIAS = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
REVISION = re.compile(r'[A-Za-z0-9_.:-]{1,32}\Z')
HASH = re.compile(r'[0-9a-f]{64}\Z')
COMMON_SHA = '23119618174b44cf9fd411014c861751a87317d59a5bb333842b5fa7c356d830'
PROFILES = (('stored', 0, None), ('deflate9', 8, 9), ('bzip2-9', 12, 9),
            ('lzma', 14, None), ('zstd19', 93, 19))


class BaselineError(ValueError):
    """Named preparation or reconstruction refusal, never a source verdict."""


def need(value, reason):
    if not value:
        raise BaselineError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def pin(raw):
    return {'bytes':len(raw), 'sha256':hashlib.sha256(raw).hexdigest()}


def common():
    path = ROOT / 'install/prepare_quorum_replay.py'
    need(path.is_file() and not path.is_symlink(), 'BASELINE_HELPER')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    need(len(raw) <= 65536 and pin(raw)['sha256'] == COMMON_SHA, 'BASELINE_HELPER')
    module = types.ModuleType('_approved_baseline_io')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def closed(value, names):
    need(type(value) is dict and set(value) == set(names), 'BASELINE_FIELDS')


def version_rows(p, rows):
    need(type(rows) is list and len(rows) <= 32, 'BASELINE_COUNT')
    result, total, observations = {}, 0, []
    for row in rows:
        closed(row, ('id','revision','path','bytes','sha256'))
        name, revision = row['id'], row['revision']
        need(type(name) is str and ALIAS.fullmatch(name) is not None and
             name not in result and type(revision) is str and
             REVISION.fullmatch(revision) is not None, 'BASELINE_ID')
        expected = p.checked_pin({key:row[key] for key in ('bytes','sha256')})
        need(expected['bytes'] <= PAYLOAD, 'BASELINE_PAYLOAD')
        path = p.absolute(row['path'])
        data = p.read(path, PAYLOAD)
        need(pin(data) == expected, 'BASELINE_SOURCE_PIN')
        total += len(data)
        need(total <= PAYLOAD, 'BASELINE_PAYLOAD')
        result[name] = {'revision':revision, 'data':data, 'name':path.name}
        observations.append((path, data))
    return result, observations


def request(path):
    p = common()
    try:
        raw = p.read(p.absolute(str(path)), 65536)
        value = p.document(raw)
        closed(value, ('schema','current','prior'))
        need(value['schema'] == 'transport/transfer-comparison-input/1', 'BASELINE_VERSION')
        current, first = version_rows(p, value['current'])
        prior, second = version_rows(p, value['prior'])
        need(bool(current), 'BASELINE_EMPTY_CURRENT')
        return p, raw, current, prior, first + second + [(path,raw)]
    except (ValueError, OSError, KeyError, TypeError, RecursionError) as error:
        if isinstance(error, BaselineError):
            raise
        raise BaselineError('BASELINE_INPUT') from error


def objects(rows):
    result = {}
    for row in rows.values():
        digest = pin(row['data'])['sha256']
        need(digest not in result or result[digest] == row['data'], 'BASELINE_HASH_COLLISION')
        result[digest] = row['data']
    return result


def plan(current, prior):
    have, wanted = objects(prior), objects(current)
    changes = []
    for name in sorted(set(current) | set(prior)):
        if name not in current:
            status = 'REMOVED'
        elif name not in prior:
            status = 'ADDED'
        elif current[name]['data'] != prior[name]['data']:
            status = 'CHANGED'
        elif current[name]['revision'] != prior[name]['revision']:
            status = 'METADATA_CHANGED'
        else:
            status = 'UNCHANGED'
        changes.append({'id':name, 'status':status})
    return {'hits':sorted(set(wanted) & set(have)),
            'needed':sorted(set(wanted) - set(have)), 'changes':changes}


def manifest(rows, changes):
    sources = [dict(id=name, revision=row['revision'], name=row['name'],
                    **pin(row['data'])) for name,row in sorted(rows.items())]
    lines = ['# Original file catalog', '', 'Source bytes are separate objects.',
             'This catalog is not a semantic search index or evidence of currency.', '']
    lines.extend(json.dumps(row, ensure_ascii=True, sort_keys=True) for row in sources)
    catalog = ('\n'.join(lines) + '\n').encode()
    value = {'schema':'transport/conventional-transfer-manifest/1', 'sources':sources,
             'catalog':pin(catalog), 'changes':changes,
             'authority':'NONE', 'freshness':'UNKNOWN'}
    raw = canonical(value)
    need(len(raw) <= 65536 and len(catalog) <= 65536, 'BASELINE_METADATA')
    return raw, catalog


def archive_bytes(raw_manifest, catalog, values, method, level):
    entries = {'manifest.json':raw_manifest, 'index.md':catalog}
    entries.update({'objects/' + key + '.bin':value for key,value in values.items()})
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=method, compresslevel=level,
                         allowZip64=False) as archive:
        for name, raw in sorted(entries.items()):
            info = zipfile.ZipInfo(name, (1980,1,1,0,0,0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = method
            info.compress_level = level
            archive.writestr(info, raw)
    result = buffer.getvalue()
    need(len(result) <= ARCHIVE, 'BASELINE_ARCHIVE_BOUND')
    return result


def archive_directory(raw):
    need(type(raw) is bytes and 22 <= len(raw) <= ARCHIVE, 'BASELINE_ARCHIVE_BOUND')
    fields = struct.unpack('<4s4H2IH', raw[-22:])
    need(fields[0] == b'PK\x05\x06' and fields[1:3] == (0,0) and
         fields[3] == fields[4] and 2 <= fields[3] <= 34 and fields[7] == 0 and
         fields[5] + fields[6] == len(raw) - 22, 'BASELINE_ZIP_LAYOUT')


def manifest_rows(p, raw):
    value = p.document(raw)
    closed(value, ('schema','sources','catalog','changes','authority','freshness'))
    need(value['schema'] == 'transport/conventional-transfer-manifest/1' and
         value['authority'] == 'NONE' and value['freshness'] == 'UNKNOWN', 'BASELINE_VERSION')
    rows = value['sources']
    need(type(rows) is list and 0 <= len(rows) <= 32, 'BASELINE_COUNT')
    found, total = {}, 0
    for row in rows:
        closed(row, ('id','revision','name','bytes','sha256'))
        need(type(row['id']) is str and ALIAS.fullmatch(row['id']) is not None and
             row['id'] not in found and type(row['revision']) is str and
             REVISION.fullmatch(row['revision']) is not None and
             type(row['name']) is str and len(row['name'].encode()) <= 1024, 'BASELINE_ID')
        selected = p.checked_pin({key:row[key] for key in ('bytes','sha256')})
        total += selected['bytes']
        need(total <= PAYLOAD, 'BASELINE_PAYLOAD')
        found[row['id']] = row
    return value, found


def restore(archive, expected_archive_sha256, expected_manifest_sha256, cache):
    need(type(archive) is bytes and type(expected_archive_sha256) is str and
         HASH.fullmatch(expected_archive_sha256) is not None and
         type(expected_manifest_sha256) is str and HASH.fullmatch(expected_manifest_sha256) is not None,
         'BASELINE_ARCHIVE_PIN')
    need(pin(archive)['sha256'] == expected_archive_sha256, 'BASELINE_ARCHIVE_PIN')
    archive_directory(archive)
    need(type(cache) is dict and len(cache) <= 32, 'BASELINE_CACHE')
    for key, raw in cache.items():
        need(type(key) is str and HASH.fullmatch(key) is not None and
             type(raw) is bytes and len(raw) <= PAYLOAD and pin(raw)['sha256'] == key,
             'BASELINE_CACHE')
    try:
        with zipfile.ZipFile(io.BytesIO(archive), allowZip64=False) as stream:
            infos = stream.infolist()
            names = [info.filename for info in infos]
            need(len(names) == len(set(names)) and len(names) <= 34 and
                 {'manifest.json','index.md'} <= set(names), 'BASELINE_ZIP_MEMBERS')
            for info in infos:
                need(info.filename == info.orig_filename and info.create_system == 3 and
                     info.external_attr == 0o100644 << 16 and info.extra == info.comment == b''
                     and 0 <= info.file_size <= PAYLOAD and info.compress_type in (0,8,12,14,93)
                     and not info.flag_bits & 1, 'BASELINE_ZIP_ENTRY')
            raw_manifest = bounded_entry(stream, 'manifest.json', 65536)
            need(pin(raw_manifest)['sha256'] == expected_manifest_sha256, 'BASELINE_MANIFEST_PIN')
            value, rows = manifest_rows(common(), raw_manifest)
            need(pin(bounded_entry(stream,'index.md',65536)) == value['catalog'], 'BASELINE_CATALOG_PIN')
            wanted = {row['sha256'] for row in rows.values()}
            known = {'manifest.json','index.md'} | {'objects/'+key+'.bin' for key in wanted}
            need(set(names) <= known, 'BASELINE_ZIP_MEMBERS')
            recovered = {}
            for name,row in rows.items():
                member = 'objects/' + row['sha256'] + '.bin'
                data = bounded_entry(stream,member,row['bytes']) if member in names else cache.get(row['sha256'])
                need(type(data) is bytes and pin(data) == {key:row[key] for key in ('bytes','sha256')},
                     'BASELINE_MISSING_OR_CHANGED_OBJECT')
                recovered[name] = data
            return recovered
    except (OSError, ValueError, RuntimeError, EOFError, KeyError, NotImplementedError,
            zipfile.BadZipFile, zipfile.LargeZipFile, struct.error, RecursionError) as error:
        if isinstance(error, BaselineError):
            raise
        raise BaselineError('BASELINE_ZIP') from error


def bounded_entry(stream, name, cap):
    info = stream.getinfo(name)
    need(info.file_size <= cap, 'BASELINE_EXPANSION')
    with stream.open(info) as member:
        raw = member.read(cap + 1)
    need(len(raw) == info.file_size and len(raw) <= cap, 'BASELINE_EXPANSION')
    return raw


def write(path, raw, state):
    need(state['bytes'] + len(raw) <= OUT_CAP, 'BASELINE_OUTPUT_BOUND')
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'BASELINE_SHORT_WRITE')
    state['bytes'] += len(raw)
    need(path.read_bytes() == raw, 'BASELINE_WRITE_CHANGED')


def new_output(p, out):
    path = p.absolute(str(out))
    for parent in path.parents:
        need(not parent.is_symlink(), 'BASELINE_OUTPUT_PATH')
    info = path.parent.stat()
    need(info.st_uid == os.getuid() and not info.st_mode & 0o022,
         'BASELINE_PRIVATE_PARENT')
    try:
        path.mkdir(mode=0o700)
    except FileExistsError as error:
        raise BaselineError('BASELINE_OUTPUT_EXISTS') from error
    return path


def candidate(out, state, label, method, level, current, prior, raw_manifest, catalog):
    have, wanted = objects(prior), objects(current)
    old_manifest, old_catalog = manifest(prior, plan(prior,{})['changes'])
    datasets = (('setup',old_manifest,old_catalog,have,prior,{}),
                ('cold',raw_manifest,catalog,wanted,current,{}),
                ('warm',raw_manifest,catalog,{k:v for k,v in wanted.items() if k not in have},current,have))
    result = {'status':'TESTED'}
    for phase, meta, index, values, expected, cache in datasets:
        start = time.perf_counter_ns()
        encoded = archive_bytes(meta,index,values,method,level)
        encoded_ns = time.perf_counter_ns() - start
        start = time.perf_counter_ns()
        decoded = restore(encoded,pin(encoded)['sha256'],pin(meta)['sha256'],cache) if expected else {}
        elapsed = time.perf_counter_ns() - start
        need(decoded == {key:row['data'] for key,row in expected.items()}, 'BASELINE_RECOVERY')
        filename = label + '-' + phase + '.zip'
        write(out / filename, encoded, state)
        result[phase] = dict(path=filename, **pin(encoded),
                            manifest_sha256=pin(meta)['sha256'], encode_ns=encoded_ns, decode_ns=elapsed)
    return result


def rsync_files(out, name, rows, state):
    raw_manifest,catalog = manifest(rows,plan(rows,{})['changes'])
    root = out / name
    write(root / 'manifest.json',raw_manifest,state)
    write(root / 'index.md',catalog,state)
    for alias,row in rows.items():
        write(root / 'files' / (alias+'.bin'),row['data'],state)
    return root


def run_rsync(out, source, destination, phase):
    args = ['/usr/bin/rsync','--recursive','--delete','--checksum','--no-whole-file',
            '--no-inc-recursive','--compress','--compress-choice=zstd','--compress-level=9',
            '--stats','--',str(source)+'/',str(destination)+'/']
    start = time.perf_counter_ns()
    with (out/(phase+'.stdout')).open('xb') as stdout, (out/(phase+'.stderr')).open('xb') as stderr:
        result = subprocess.run(args,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C'},timeout=30,check=False)
    elapsed = time.perf_counter_ns()-start
    first,second = (out/(phase+'.stdout')).read_bytes(), (out/(phase+'.stderr')).read_bytes()
    need(len(first)+len(second) <= 131072 and result.returncode == 0, 'BASELINE_RSYNC_FAILED')
    stats = {}
    for name in ('Literal data','Matched data','Total bytes sent','Total bytes received'):
        matches = re.findall(r'^'+name+r': ([0-9,]+) bytes$',first.decode('utf-8'),re.M)
        need(len(matches) == 1, 'BASELINE_RSYNC_STATS')
        stats[name] = int(matches[0].replace(',',''))
    return {'argv':args,'exit_code':result.returncode,'elapsed_ns':elapsed,
            'stdout':pin(first),'stderr':pin(second),'stats':stats}


def rsync_compare(out, current, prior, expected, state):
    executable = Path('/usr/bin/rsync')
    need(type(expected) is str and HASH.fullmatch(expected) is not None, 'BASELINE_RSYNC_PIN')
    with executable.open('rb') as stream:
        raw = stream.read(4194305)
    need(len(raw) <= 4194304 and pin(raw)['sha256'] == expected, 'BASELINE_RSYNC_PIN')
    source = rsync_files(out,'rsync-source',current,state)
    warm = rsync_files(out,'rsync-warm',prior,state)
    cold = out/'rsync-cold'
    cold.mkdir(mode=0o700)
    result = {'cold':run_rsync(out,source,cold,'rsync-cold'),
              'warm':run_rsync(out,source,warm,'rsync-warm'), 'executable':pin(raw)}
    expected_files = file_snapshot(source)
    for root in (cold,warm):
        found = file_snapshot(root)
        need(found == expected_files, 'BASELINE_RSYNC_RECOVERY')
    need(pin(executable.read_bytes()) == pin(raw), 'BASELINE_RSYNC_CHANGED')
    return dict(result,status='TESTED_LOCAL_TRANSFER_EXACT',network='NOT_MEASURED',
                layout='STABLE_ALIAS_FILES_FOR_BLOCK_DELTA')


def file_snapshot(root):
    result, pending, visited = {}, [root], 0
    for unused in range(2):
        if not pending:
            break
        with os.scandir(pending.pop()) as entries:
            for item in entries:
                visited += 1
                need(visited <= 35 and not item.is_symlink(), 'BASELINE_RSYNC_TREE')
                path = Path(item.path)
                if item.is_dir(follow_symlinks=False):
                    need(path == root/'files', 'BASELINE_RSYNC_TREE')
                    pending.append(path)
                else:
                    need(item.is_file(follow_symlinks=False), 'BASELINE_RSYNC_TREE')
                    with path.open('rb') as stream:
                        raw = stream.read(PAYLOAD+1)
                    need(len(raw) <= PAYLOAD, 'BASELINE_RSYNC_TREE')
                    result[str(path.relative_to(root))] = raw
    need(not pending, 'BASELINE_RSYNC_TREE')
    return result


def prepare(request_path, out, with_rsync=False, expected_rsync=None):
    started = time.perf_counter_ns()
    p,raw,current,prior,observed = request(Path(request_path))
    frozen = plan(current,prior)
    raw_manifest,catalog = manifest(current,frozen['changes'])
    out = new_output(p,Path(out))
    state = {'bytes':0}
    write(out/'manifest.json',raw_manifest,state)
    write(out/'index.md',catalog,state)
    candidates = {}
    for label,method,level in PROFILES:
        try:
            module = {8:'zlib',12:'bz2',14:'lzma',93:'compression.zstd'}.get(method)
            if module is not None:
                importlib.import_module(module)
        except ImportError as error:
            candidates[label] = {'status':'UNAVAILABLE','reason':str(error)}
            continue
        candidates[label] = candidate(out,state,label,method,level,current,prior,raw_manifest,catalog)
    need(all(candidates[name]['status'] == 'TESTED' for name in ('stored','deflate9')),
         'BASELINE_REQUIRED_CANDIDATE')
    rsync = rsync_compare(out,current,prior,expected_rsync,state) if with_rsync else {'status':'UNPERFORMED'}
    for path,data in observed:
        need(p.read(path,max(PAYLOAD,len(data))) == data, 'BASELINE_INPUT_CHANGED')
    result = {'schema':'transport/transfer-comparison-report/1','status':'TESTED_TRANSFER_MECHANICS',
        'request':pin(raw),'manifest':pin(raw_manifest),'plan':frozen,'candidates':candidates,
        'rsync':rsync,'elapsed_prepare_ns':time.perf_counter_ns()-started,
        'python':sys.version,'zlib_version':zipfile.zlib.ZLIB_RUNTIME_VERSION,
        'helper':{'path':'install/prepare_quorum_replay.py','sha256':COMMON_SHA},
        'measurement_scope':'Local machine bytes/time; OS page cache uncontrolled.',
        'human_work':'UNMEASURED','model_tokens':'UNMEASURED','monetary_cost':'UNMEASURED',
        'complete_dependency_cost':'UNMEASURED','strongest_retrieval_baseline':'NOT_QUALIFIED',
        'semantic_fidelity':'NOT_ASSESSED','current_authority':'NONE','freshness':'UNKNOWN'}
    write(out/'report.json',canonical(result),state)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('request',type=Path)
    parser.add_argument('out',type=Path)
    parser.add_argument('--with-rsync',action='store_true')
    parser.add_argument('--expect-rsync-sha256')
    args = parser.parse_args()
    for kind,limit in ((resource.RLIMIT_AS,1073741824),(resource.RLIMIT_CPU,120),
                       (resource.RLIMIT_FSIZE,ARCHIVE)):
        unused,hard = resource.getrlimit(kind)
        need(hard == resource.RLIM_INFINITY or hard >= limit, 'BASELINE_RESOURCE')
        resource.setrlimit(kind,(limit,limit))
    try:
        result = prepare(args.request,args.out,args.with_rsync,args.expect_rsync_sha256)
        print(json.dumps({'status':result['status'],'report':str(args.out/'report.json')}))
    except (BaselineError,OSError,MemoryError,subprocess.SubprocessError) as error:
        print(json.dumps({'status':'REFUSED_TRANSFER_COMPARISON','reason':str(error)}))
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
