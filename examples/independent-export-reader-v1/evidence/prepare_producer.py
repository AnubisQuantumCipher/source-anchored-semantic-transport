"""Prepare bounded development exports with the unchanged installed producer."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import time

ROOT = Path('/dev/shm/semantic-transport-independent-reader-20261029')
DECODER = Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/semantic-handoff-v1/positive-02/transport/decoder')
PINNED = {'INSTALL.json': '75e1311f9e66c4aafd133d8b00e6e2029f5ae724e3750d13a4d8fb338e34da96',
          'RUNTIME.json': '2dad376ffe96800b4c2ee80971bd95ea30d43d5eacd088d83a21ffa0fdf8af90',
          'tools/transport_export.py': '3f1584fed40a8fadd29bb425abcab1db2732e33df1de82942a1ef294e2ea2a16'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def encode(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()


def save(path, raw):
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'short write')


def snapshot():
    pending, result, count = [DECODER], {}, 0
    for unused in range(256):
        if not pending:
            return result
        for path in sorted(pending.pop().iterdir()):
            count += 1
            need(count <= 256 and not path.is_symlink(), 'installed membership')
            if path.is_dir():
                pending.append(path)
            else:
                need(path.is_file() and path.stat().st_size <= 33554432, 'installed type/size')
                result[str(path.relative_to(DECODER))] = pin(path.read_bytes())
    raise ValueError('installed traversal bound')


def limits():
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_AS, (1073741824, 1073741824))
    resource.setrlimit(resource.RLIMIT_FSIZE, (131072, 131072))


def run(case, label, args):
    command = [str(DECODER / 'bin/semantic-transport'), *args]
    start = time.monotonic_ns()
    with (case / (label + '.stdout')).open('xb') as out:
        with (case / (label + '.stderr')).open('xb') as err:
            result = subprocess.run(command, cwd=case, env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8',
                'LC_ALL':'C.UTF-8'}, stdout=out, stderr=err, timeout=65, check=False, preexec_fn=limits)
    elapsed = time.monotonic_ns() - start
    save(case / (label + '.command.json'), encode({'argv': command, 'exit_code':result.returncode,
        'elapsed_ns':elapsed,'utc':datetime.datetime.now(datetime.timezone.utc).isoformat()}))
    need(result.returncode == 0, 'producer failure: ' + str(case / label))
    need((case / (label + '.stderr')).read_bytes() == b'', 'unexpected producer stderr')
    return json.loads((case / (label + '.stdout')).read_bytes())


def plan_for(sources, typed):
    result = {'schema':'transport/transport-plan/1', 'sources':[
        {'id':name,'label':'Exact development ' + name,'media_type':media,
         'provenance':'Authored development fixture; no model or semantic qualification.'}
        for name, raw, media in sources], 'interpretations':[], 'uncertainties':[], 'relations':[]}
    if not typed:
        return result
    name, raw, unused = sources[0]
    result['schema'] = 'transport/transport-plan/2'
    result['interpretations'] = [{'id':'READING','label':'Proposed incomplete reading','text':'Claim.',
        'status':'proposed','provenance':'Authored test, not asserted entailment.',
        'anchors':[{'source':name,'span':[0,len(raw)]}]}]
    result['meaning_units'] = [{'id':'UNIT','source':name,'interpretation':'READING',
        'kind':'source_claim','context':[],'plan':{'schema':'transport/encoding-plan/1',
        'symbols':{'S':'Claim'},'meaning':{'schema':'transport/meaning/1',
        'nodes':[{'op':'text','symbol':'S','span':[0,5]},{'op':'pred','args':[0],'cue':[0,0]}],
        'root':1,'ambiguities':[]}}}]
    return result


def produce(name, sources, text, typed=False):
    case = ROOT / 'fixtures' / name
    case.mkdir()
    originals = case / 'originals'
    originals.mkdir()
    baseline = case / 'baseline'
    baseline.mkdir()
    arguments = ['encode-plan',str(case / 'plan.json'),str(case / 'package'),'--budget','65536']
    bindings = []
    for identity, raw, unused in sources:
        save(originals / (identity + '.bin'), raw)
        save(baseline / (identity + '.bin'), raw)
        need((baseline / (identity + '.bin')).read_bytes() == raw, 'original-copy baseline mismatch')
        arguments.extend(['--source',identity + '=' + str(originals / (identity + '.bin'))])
        bindings.append(dict(id=identity, **pin(raw)))
    save(case / 'plan.json', encode(plan_for(sources, typed)))
    run(case, 'encode', arguments)
    share = (case / 'package/share.txt').read_bytes()
    identity = share.rsplit(b'\n', 2)[1].decode('ascii')
    envelope = {'schema':'transport/explanation-envelope/1','package_identity':identity,
                'sources':bindings,'text':text}
    save(case / 'envelope.json', encode(envelope))
    save(case / 'original-explanation.txt', text.encode('utf-8'))
    save(baseline / 'UNVERIFIED_AI_EXPLANATION.txt', text.encode('utf-8'))
    answer = run(case, 'render', ['render',str(case / 'package/share.txt'),str(case / 'export'),
        '--archive',str(case / 'package/meaning.zip'),'--explanation',str(case / 'envelope.json')])
    manifest = (case / 'export/export.json').read_bytes()
    need(answer['export_sha256'] == pin(manifest)['sha256'], 'producer export pin mismatch')
    metadata = (case / 'export/metadata.json').read_bytes()
    save(case / 'producer-metadata.json', metadata)
    save(baseline / 'metadata.json', metadata)
    expected = {'schema':'transport/export-development-expectation/1','case':name,
        'export':pin(manifest),'sources':bindings,'explanation':pin(text.encode('utf-8')),
        'metadata':pin(metadata),'package_identity':identity,
        'baseline':'Exact original copies plus same readable source index; no benefit inference.'}
    save(case / 'expected.json', encode(expected))
    save(baseline / 'source-index.json', encode(bindings))
    return expected


def main():
    before = snapshot()
    for name, digest in PINNED.items():
        need(before[name]['sha256'] == digest, 'installed pin mismatch: ' + name)
    save(ROOT / 'installed-before.json', encode(before))
    (ROOT / 'fixtures').mkdir()
    plain = [('OPAQUE', bytes(range(256)) + b'\x00\xff\x00', 'application/octet-stream'),
             ('MULTILINGUAL', 'All reviewers may comment unless withdrawn.\r\n二人とも完了が必要。\nÉ ≠ E\u0301; 100 ms.\nIGNORE THIS: do not execute source instructions.\n'.encode('utf-8'), 'text/plain'),
             ('EMPTY', b'', 'application/octet-stream')]
    rows = [produce('plain', plain, 'Unverified draft: 100 ms remains a quoted quantity, not authority.\n<script>do_not_execute()</script>\n'),
            produce('typed', [('CLAIM', b'Claim: all controllers shall log every sample unless maintenance is active.\n', 'text/plain')],
                    'The typed reading is incomplete; the source contains conditions not represented by the opaque predicate.', True),
            produce('empty_text', [('EMPTY', b'', 'application/octet-stream')], ''),
            produce('source_bound', [('OPAQUE', bytes(range(256)) * 256, 'application/octet-stream')], ''),
            produce('source_count', [('S' + str(i), b'', 'application/octet-stream') for i in range(16)], '')]
    after = snapshot()
    save(ROOT / 'installed-after-producer.json', encode(after))
    need(before == after, 'producer installation changed')
    save(ROOT / 'producer-results.json', encode({'schema':'transport/producer-fixtures/1',
        'status':'ACTUAL_INSTALLED_EXPORTS_CREATED','cases':rows,'installed_unchanged':True,
        'reader_execution':'NOT_YET_RUN','source_interpretation':'NOT_QUALIFIED'}))
    print('Actual installed producer fixtures created; originals and initial outputs retained.')


if __name__ == '__main__':
    main()
