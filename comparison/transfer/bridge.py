#!/usr/bin/env python3
"""Frozen public-fixture transfer to the unchanged, qualified QUORUM checker."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
import types

ROOT = Path(__file__).resolve().parents[2]
CORE = '7b66cf356b991c58a0d97c61a54eca6e627c36904692b6a946211537a263c7a3'
BOOT = '03f2bf18a67b9a6d6ccf25fd506b252b38ac34c78f56153eb22b8ecfca5738ea'
RSYNC = 'cdd6759b34905d289e4b993efc726f7586fe2c12a0e84d712fcf254b1b3ef4b8'
CAP = 2097152
STDOUT = {'original':'a28d1eb66e77ed991cc926106f5cbe7a68e50667410bf025217e4a591c3307cb',
          'transport':'46f5bfa835239d89184b518601e9c5c26db5a9e30222946dbf53fdc9e0d7d159'}
INVOCATION = {'original':'59907c09b5395e5aa6b4a025b2f49ddafc18273fb0e5b578032543317707f0af',
              'transport':'9b9ab9fdbf7f83b41a84efd7ac6accd8ac80bb41ff0bececeb1b3ae25f0ae31b'}


def need(value, reason):
    if not value:
        raise ValueError(reason)


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode()


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def read(path, observed):
    need(path.is_file() and not path.is_symlink(), 'BRIDGE_INPUT_FILE')
    with path.open('rb') as stream:
        raw = stream.read(CAP + 1)
    need(len(raw) <= CAP, 'BRIDGE_INPUT_BOUND')
    observed[str(path)] = raw
    return raw


def write(path, raw):
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'BRIDGE_WRITE')
    need(path.read_bytes() == raw, 'BRIDGE_WRITE_READBACK')


def load_core(observed):
    path = ROOT / 'comparison/transfer/transfer.py'
    raw = read(path, observed)
    need(pin(raw)['sha256'] == CORE, 'BRIDGE_CORE_PIN')
    module = types.ModuleType('_approved_transfer_bridge_core')
    module.__file__ = str(path)
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def fixture(invocation, observations, observed):
    raw = read(invocation, observed)
    need(pin(raw)['sha256'] == INVOCATION['original'], 'BRIDGE_ORIGINAL_INVOCATION_PIN')
    inv = json.loads(raw)
    execution = json.loads(read(observations / 'normal-original-execution.json', observed))
    need(pin(raw)['sha256'] == execution['argv'][6], 'BRIDGE_ORIGINAL_INVOCATION_PIN')
    paths = {'Q_RECORDS':ROOT/'examples/quorum-sender-v1/body.json'}
    expected = {'Q_RECORDS':inv['body']}
    for row in inv['originals']:
        paths[row['alias']] = ROOT/'examples/quorum-sender-v1'/(row['alias']+'.bin')
        expected[row['alias']] = row['key']
    for alias, field in (('ORIGINAL_INDEX','package'),('REQUEST','request'),
            ('ENVELOPE','envelope'),('CHECKER_DESCRIPTOR','checker_descriptor')):
        paths[alias] = Path(inv[field]['path'])
        expected[alias] = inv[field].get('key', inv[field])
    rows, data = [], {}
    for alias, path in paths.items():
        raw = read(path, observed)
        need(pin(raw) == {k:expected[alias][k] for k in ('bytes','sha256')},
             'BRIDGE_FIXTURE_PIN')
        rows.append(dict(id=alias, revision='V1', path=str(path), **pin(raw)))
        data[alias] = raw
    return inv, rows, data


def reconstruct(core, report, out, data):
    selected = report['candidates']['deflate9']['warm']
    archive = (out/'transfer'/selected['path']).read_bytes()
    cache = {pin(data[name])['sha256']:data[name]
             for name in ('ACCESS_NOTICE','TIMETABLE_BEFORE')}
    recovered = core.restore(archive, selected['sha256'],
                             selected['manifest_sha256'], cache)
    need(recovered == data, 'BRIDGE_RECOVERED_BYTES')
    recipient = out/'original-recipient'
    recipient.mkdir(mode=0o700)
    for alias, raw in recovered.items():
        write(recipient/(alias+'.bin'), raw)
    return recipient


def relocate(inv, recipient):
    clone = json.loads(canonical(inv))
    clone['body']['path'] = str(recipient/'Q_RECORDS.bin')
    for row in clone['originals']:
        row['path'] = str(recipient/(row['alias']+'.bin'))
    for field, alias in (('package','ORIGINAL_INDEX'),('request','REQUEST'),
                         ('envelope','ENVELOPE'),('checker_descriptor','CHECKER_DESCRIPTOR')):
        clone[field]['path'] = str(recipient/(alias+'.bin'))
    restored = json.loads(canonical(clone))
    restored['body']['path'] = inv['body']['path']
    for old, new in zip(inv['originals'], restored['originals'], strict=True):
        new['path'] = old['path']
    for field in ('package','request','envelope','checker_descriptor'):
        restored[field]['path'] = inv[field]['path']
    need(restored == inv, 'BRIDGE_NONPATH_CHANGE')
    return clone


def launch(out, label, args, observed):
    start = time.perf_counter_ns()
    timeout = False
    with (out/(label+'.stdout')).open('xb') as first, (out/(label+'.stderr')).open('xb') as second:
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=first, stderr=second,
            env={'PATH':'/usr/bin:/bin','LC_ALL':'C','TMPDIR':str(out)}, start_new_session=True)
        try:
            code = child.wait(timeout=30)
        except subprocess.TimeoutExpired:
            timeout = True
            os.killpg(child.pid, signal.SIGKILL)
            code = child.wait(timeout=5)
    elapsed = time.perf_counter_ns()-start
    stdout = read(out/(label+'.stdout'), observed)
    stderr = read(out/(label+'.stderr'), observed)
    need(len(stdout)+len(stderr) <= 131072, 'BRIDGE_OUTPUT_BOUND')
    record = dict(argv=args, exit_code=code, timeout=timeout, elapsed_ns=elapsed,
                  stdout=pin(stdout), stderr=pin(stderr),
                  environment={'PATH':'/usr/bin:/bin','LC_ALL':'C','TMPDIR':str(out)},
                  inherited_hard_limits=dict(address_space=1073741824,cpu_seconds=120,
                                             file_bytes=33554432))
    write(out/(label+'-execution.json'), canonical(record))
    return record, stdout


def execute(out, label, invocation, expected, observed):
    bootstrap = ROOT/'install/transport_quorum_bootstrap.py'
    need(pin(read(bootstrap, observed))['sha256'] == BOOT, 'BRIDGE_BOOTSTRAP_PIN')
    raw = read(invocation, observed)
    args = [str(Path(sys.executable).resolve()), '-I', '-S', str(bootstrap),
            str(invocation), '--expect-invocation-sha256', pin(raw)['sha256'],
            '--expect-bootstrap-sha256', BOOT]
    record, stdout = launch(out,label,args,observed)
    record.update(expected_stdout=pin(expected),complete_stdout_byte_match=stdout == expected)
    write(out/(label+'-comparison.json'),canonical(record))
    need(not record['timeout'] and record['exit_code'] == 0 and stdout == expected,
         'BRIDGE_CHECKER_RESULT')
    return record


def prepare(out, observed):
    script = ROOT/'comparison/transfer/transfer.py'
    need(pin(read(script, observed))['sha256'] == CORE, 'BRIDGE_CORE_PIN')
    args = [str(Path(sys.executable).resolve()),'-I','-S',str(script),str(out/'request.json'),
            str(out/'transfer'),'--with-rsync','--expect-rsync-sha256',RSYNC]
    record, unused = launch(out,'transfer-prepare',args,observed)
    need(not record['timeout'] and record['exit_code'] == 0, 'BRIDGE_PREPARE_RESULT')
    record['cli_effective_hard_file_bytes'] = 2097152
    write(out/'transfer-prepare-profile.json', canonical(record))
    report = json.loads(read(out/'transfer/report.json', observed))
    need(report['status'] == 'TESTED_TRANSFER_MECHANICS', 'BRIDGE_TRANSFER_REPORT')
    return report


def transport(out, path, observations, observed):
    raw = read(path, observed)
    need(pin(raw)['sha256'] == INVOCATION['transport'], 'BRIDGE_TRANSPORT_INVOCATION_PIN')
    inv = json.loads(raw)
    execution = json.loads(read(observations/'normal-transport-execution.json', observed))
    need(pin(raw)['sha256'] == execution['argv'][6], 'BRIDGE_TRANSPORT_INVOCATION_PIN')
    for field in ('package','request','envelope','share','checker_descriptor'):
        item = inv[field]
        actual = read(Path(item['path']), observed)
        key = item.get('key', item)
        need(pin(actual) == {k:key[k] for k in ('bytes','sha256')}, 'BRIDGE_TRANSPORT_PIN')
    need(all(not Path(row['path']).exists() for row in inv['originals']) and
         not Path(inv['body']['path']).exists(), 'BRIDGE_SIDECARS_PRESENT')
    expected = read(observations/'normal-transport-stdout.bin', observed)
    need(pin(expected) == execution['stdout'] and pin(expected)['sha256'] == STDOUT['transport'],
         'BRIDGE_TRANSPORT_EXPECTED_PIN')
    return execute(out, 'transport', path, expected, observed)


def run(out, original_invocation, transport_invocation, observations):
    observed = {}
    read(Path(__file__).resolve(), observed)
    core = load_core(observed)
    inv, rows, data = fixture(original_invocation, observations, observed)
    out.mkdir(mode=0o700)
    request = dict(schema='transport/transfer-comparison-input/1', current=rows,
                   prior=[row for row in rows if row['id'] in ('ACCESS_NOTICE','TIMETABLE_BEFORE')])
    write(out/'request.json', canonical(request))
    report = prepare(out,observed)
    recipient = reconstruct(core, report, out, data)
    write(out/'original-invocation.json', canonical(relocate(inv, recipient)))
    expected = read(observations/'normal-original-stdout.bin', observed)
    execution = json.loads(read(observations/'normal-original-execution.json', observed))
    need(pin(expected) == execution['stdout'] and pin(expected)['sha256'] == STDOUT['original'],
         'BRIDGE_ORIGINAL_EXPECTED_PIN')
    original = execute(out, 'original', out/'original-invocation.json', expected, observed)
    counterpart = transport(out, transport_invocation, observations, observed)
    for path, raw in observed.items():
        need(Path(path).read_bytes() == raw, 'BRIDGE_SOURCE_CHANGED')
    result = dict(schema='transport/conventional-checker-bridge/1', status='TESTED',
        same_checker_integration=True, original=original, transport=counterpart,
        transfer_report=pin((out/'transfer/report.json').read_bytes()),
        observed_inputs=[dict(path=path, **pin(raw)) for path, raw in sorted(observed.items())],
        python=sys.version, human_work='UNMEASURED', semantic_fidelity='NOT_ASSESSED',
        model_runs='UNPERFORMED', strongest_retrieval_baseline='NOT_QUALIFIED',
        required_external_dependencies=['Qualified decoder bundle and decoder source root declared by held checker descriptor',
            'Held fixed checker tree, bootstrap and helper closure',
            'Exact Python executable and OS libraries; transitive cost UNMEASURED'],
        qualified_dependencies=dict(checker_descriptor=json.loads(data['CHECKER_DESCRIPTOR']),
            decoder_install_descriptor=inv['decoder_install_descriptor'],
            runtime_descriptor=inv['runtime_descriptor'],source_manifest_pin=inv['source_manifest_pin'],
            bundle_snapshot_pin=inv['bundle_snapshot_pin']),
        scope='Frozen public fixture, conventional warm ZIP plus declared cache; exact complete checker output per arm.',
        authority='NONE', freshness='UNKNOWN')
    write(out/'result.json', canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('out', type=Path)
    parser.add_argument('--original-invocation',type=Path,required=True)
    parser.add_argument('--transport-invocation',type=Path,required=True)
    parser.add_argument('--observations',type=Path,required=True)
    args = parser.parse_args()
    allowed = Path('/dev/shm/semantic-transport-transfer-comparison-20261029')
    need(args.out.is_absolute() and args.out.parent in (allowed,allowed/'bridge-01'),
         'BRIDGE_OUTPUT_LOCATION')
    need(args.out.parent.stat().st_uid == os.getuid() and
         not args.out.parent.stat().st_mode & 0o022, 'BRIDGE_PRIVATE_PARENT')
    for kind, limit in ((resource.RLIMIT_AS,1073741824),(resource.RLIMIT_CPU,120),
                        (resource.RLIMIT_FSIZE,33554432)):
        unused, hard = resource.getrlimit(kind)
        need(hard == resource.RLIM_INFINITY or hard >= limit, 'BRIDGE_RESOURCE')
        resource.setrlimit(kind,(limit,limit))
    result = run(args.out,args.original_invocation,args.transport_invocation,args.observations)
    print(json.dumps(dict(status=result['status'], report=str(args.out/'result.json'))))


if __name__ == '__main__':
    main()
