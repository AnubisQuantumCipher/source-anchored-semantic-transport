"""Actual bounded sender/recipient controls; requires an independently held runtime.

No product imports, expected verdict generation, model calls or native builds.
All complete first streams are retained in a create-only evidence directory.
"""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'examples/quorum-sender-v1'
ORACLE_SHA = '21cd8b27977c3f64de30341eda57aee76a2e70a657a02caa03530e9abcda2c78'
ID_ORACLE_SHA = '1593245b48ab74ae8154447af944f6c05e44749202a0c005b67fda01f88b5e9d'
HOST_NAMES = ('bootstrap_entry', 'decoder_install_descriptor',
              'runtime_descriptor', 'source_manifest', 'bundle_snapshot')


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def need(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    need(path.is_file() and not path.is_symlink(), 'Fixture regular file required')
    with path.open('rb') as stream:
        raw = stream.read(131073)
    need(len(raw) <= 131072, 'Fixture bound')
    return raw


def save(path, value):
    raw = value if type(value) is bytes else canonical(value)
    need(len(raw) <= 1048577, 'Evidence file bound')
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'Evidence incomplete write')


def limits():
    # The qualified host's existing child checker sets these exact hard limits.
    # A lower inherited hard limit makes its launch fail before checking the bundle.
    resource.setrlimit(resource.RLIMIT_FSIZE, (33554432, 33554432))
    resource.setrlimit(resource.RLIMIT_CPU, (120, 120))


def capture(command, directory):
    directory.mkdir()
    start, timeout = time.monotonic_ns(), False
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, start_new_session=True,
        preexec_fn=limits, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8',
                              'PYTHONDONTWRITEBYTECODE': '1'})
    streams, buffers, overflow = (process.stdout, process.stderr), [bytearray(), bytearray()], False
    with selectors.DefaultSelector() as selector:
        for index, stream in enumerate(streams):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, index)
        for unused in range(6000):
            timeout = time.monotonic_ns() - start > 45000000000
            if timeout or overflow or (not selector.get_map() and process.poll() is not None):
                break
            for key, unused_mask in selector.select(0.01):
                buffer = buffers[key.data]
                raw = os.read(key.fileobj.fileno(), min(16384, 1048577 - len(buffer)))
                if raw:
                    buffer.extend(raw)
                    overflow = overflow or len(buffer) > 1048576
                else:
                    selector.unregister(key.fileobj)
        else:
            timeout = True
    if timeout or overflow:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    code = process.wait(timeout=5)
    for stream in streams:
        stream.close()
    stdout, stderr = (bytes(buffer) for buffer in buffers)
    save(directory / 'stdout.bin', stdout)
    save(directory / 'stderr.bin', stderr)
    result = dict(argv=command, exit_code=code, timeout=timeout, capture_overflow=overflow,
                  elapsed_ns=time.monotonic_ns() - start,
                  stdout=pin(stdout), stderr=pin(stderr))
    save(directory / 'execution.json', result)
    return result, stdout, stderr


def fixtures():
    raw = read(FIXTURE / 'oracle-pins.json')
    need(hashlib.sha256(raw).hexdigest() == ORACLE_SHA, 'Oracle index pin')
    index = json.loads(raw)
    need(len(index) == 10, 'Oracle roster')
    for name, expected in index.items():
        need('/' not in name and pin(read(FIXTURE / name)) == expected, 'Oracle file pin')
    return json.loads(read(FIXTURE / 'input-template.json'))


def identifier_fixtures():
    root = FIXTURE / 'identifier-case'
    raw = read(root / 'oracle-pins.json')
    need(hashlib.sha256(raw).hexdigest() == ID_ORACLE_SHA, 'Identifier oracle pin')
    index = json.loads(raw)
    need(len(index) == 10, 'Identifier oracle roster')
    for name, expected in index.items():
        need(not name.startswith('/') and '..' not in Path(name).parts and
             pin(read(root / name)) == expected, 'Identifier oracle file')
    return [root, root / 'finalLF']


def materialize(directory, template, fixture=FIXTURE):
    directory.mkdir()
    doc = copy.deepcopy(template)
    for row in [doc['body']] + doc['sources']:
        name = row['path']
        save(directory / name, read(fixture / name))
        row['path'] = str(directory / name)
    return doc


def hold(args, doc, directory):
    save(directory / 'sender-input.json', doc)
    held = {n: copy.deepcopy(args.host[n]) for n in HOST_NAMES}
    held.update(schema='quorum/sender-held-identities/1',
        sender_input=pin(read(directory / 'sender-input.json')),
        encoder_launcher=pin(read(Path(args.decoder_root) / 'bin/semantic-transport')))
    save(directory / 'held.json', held)
    return held


def command(args, directory, optimized):
    argv = [sys.executable, '-I', '-S', '-B', '-Werror']
    if optimized:
        argv.append('-O')
    argv.append(str(ROOT / 'install/prepare_quorum_sender.py'))
    for name, value in (('checker-root', str(ROOT)), ('decoder-root', args.decoder_root),
            ('decoder-source-root', args.decoder_source_root),
            ('snapshot-file', args.snapshot_file), ('held-identities', str(directory / 'held.json')),
            ('sender-input', str(directory / 'sender-input.json')),
            ('out', str(directory / 'output')), ('budget', '512')):
        argv.extend(('--' + name, value))
    return argv


def replay(args, directory, held, arm, optimized, fixture=FIXTURE):
    out = directory / 'output'
    path = out / (arm + '-invocation.json')
    argv = [str(Path(sys.executable).resolve()), '-I', '-S',
        str(ROOT / 'install/transport_quorum_bootstrap.py'), str(path),
        '--expect-invocation-sha256', pin(read(path))['sha256'],
        '--expect-bootstrap-sha256', held['bootstrap_entry']['sha256']]
    declared = json.loads(read(out / (arm + '-result-command.json')))
    need(declared['argv'] == argv, 'Generated recipient command differs')
    if optimized:
        argv.insert(3, '-O')
    execution, stdout, stderr = capture(argv, directory / (arm + '-run'))
    expected = json.loads(read(fixture / 'expected.json'))
    expected['request'] = dict(id='REPLAY_REQUEST', **pin(read(out / (arm + '-request.json'))))
    save(directory / (arm + '-expected.json'), expected)
    need(execution['exit_code'] == 0 and not execution['timeout'] and
         not execution['capture_overflow'], 'Recipient execution')
    need(json.loads(stdout) == expected, 'Literal full result differs from independent oracle')
    need(json.loads(stderr)['status'] == 'QUALIFIED_FIXED_HOST', 'Actual host qualification absent')
    return execution


def recovery(args, directory, doc):
    out, rows = directory / 'output', []
    supplied = [('Q_RECORDS', doc['body']['path'])]
    supplied.extend((r['alias'], r['path']) for r in doc['sources'])
    for alias, path in supplied:
        destination = directory / ('recovered-' + alias + '.bin')
        argv = [str(Path(args.decoder_root) / 'bin/semantic-transport'), 'recover',
            str(out / 'encoded/share.txt'), str(destination),
            '--archive', str(out / 'encoded/meaning.zip'), '--source', alias]
        execution, unused, unused_error = capture(argv, directory / ('recover-' + alias))
        need(execution['exit_code'] == 0 and read(destination) == read(Path(path)),
             'Exact source recovery failed')
        rows.append(dict(alias=alias, **pin(read(destination))))
    return rows


def positive(args, template, directory, optimized, fixture=FIXTURE):
    doc = materialize(directory, template, fixture)
    held = hold(args, doc, directory)
    execution, stdout, unused = capture(command(args, directory, optimized), directory / 'prepare')
    need(execution['exit_code'] == 0 and not execution['timeout'] and
         not execution['capture_overflow'], 'Sender preparation failed')
    out = directory / 'output'
    receipt = json.loads(read(out / 'preparation-receipt.json'))
    need(receipt['status'] == 'PREPARED_NOT_EXECUTED', 'Preparation overclaimed')
    need(not (out / 'expected.json').exists(), 'Product manufactured an expected result')
    replay(args, directory, held, 'original', optimized, fixture)
    # Remove every original-arm sidecar from its declared location before ZIP replay.
    inv = json.loads(read(out / 'original-invocation.json'))
    paths = [Path(inv['body']['path'])] + [Path(r['path']) for r in inv['originals']]
    quarantine = directory / 'evaluator-only'
    quarantine.mkdir()
    for index, path in enumerate(paths):
        path.rename(quarantine / str(index))
    replay(args, directory, held, 'transport', optimized, fixture)
    recovered = recovery(args, directory, doc)
    share = read(out / 'encoded/share.txt')
    return dict(case='POSITIVE', optimized=optimized, status='PASS',
        original_sidecars_absent_during_zip_replay=all(not p.exists() for p in paths),
        exact_recovery=recovered, share_characters=len(share.decode('utf-8')),
        share_utf8_bytes=len(share), archive=pin(read(out / 'encoded/meaning.zip')),
        input_body=doc['body'], sender_execution=execution)


def changed_body(doc, mutate):
    path = Path(doc['body']['path'])
    value = json.loads(read(path))
    mutate(value)
    raw = canonical(value)
    path.write_bytes(raw)
    doc['body'].update(pin(raw))


def mutate_case(doc, directory, name):
    if name == 'MISSING_ALIAS':
        doc['sources'].pop()
    elif name == 'EXTRA_ALIAS':
        row = copy.deepcopy(doc['sources'][0])
        row['alias'] = 'EXTRA'
        doc['sources'].append(row)
    elif name == 'DUPLICATE_ALIAS':
        doc['sources'].append(copy.deepcopy(doc['sources'][0]))
    elif name == 'RESERVED_ALIAS':
        doc['sources'][0]['alias'] = 'Q_RECORDS'
    elif name in ('SOURCE_TAMPER', 'BODY_TAMPER'):
        path = Path(doc['body']['path'] if name == 'BODY_TAMPER' else doc['sources'][0]['path'])
        path.write_bytes(read(path) + b'!')
    elif name == 'UNSUPPORTED_SCHEMA':
        doc['schema'] = 'quorum/sender-input/2'
    elif name == 'OVERSIZE':
        # Valid individual read; cumulative declared-and-actual source bytes exceed cap.
        row = doc['sources'][0]
        raw = b'x' * 65536
        Path(row['path']).write_bytes(raw)
        row['key'].update(pin(raw))
        def update(value):
            value['sources'][0]['key'] = copy.deepcopy(row['key'])
        changed_body(doc, update)
    elif name == 'TASK_ZERO':
        changed_body(doc, lambda v: v.update(tasks=[]))
    elif name == 'TASK_TWO':
        changed_body(doc, lambda v: v['tasks'].append(copy.deepcopy(v['tasks'][0])))
    elif name == 'OUTPUT_EXISTS':
        (directory / 'output').mkdir()
        save(directory / 'output/sentinel.bin', b'UNCHANGED')
    else:
        raise ValueError('Unadmitted negative control')


def negative(args, template, directory, case, optimized):
    doc = materialize(directory, template)
    mutate_case(doc, directory, case['id'])
    hold(args, doc, directory)
    execution, stdout, unused = capture(command(args, directory, optimized), directory / 'prepare')
    result = json.loads(stdout)
    need(execution['exit_code'] == 2 and not execution['timeout'] and
         not execution['capture_overflow'], 'Expected refusal exit')
    need(result['status'] == 'REFUSED_SENDER_PREPARATION', 'Wrong refusal status')
    need(result['reason'] in case['expected_reason_codes'], 'Wrong independent refusal reason')
    out = directory / 'output'
    if case['id'] == 'OUTPUT_EXISTS':
        need(list(out.iterdir()) == [out / 'sentinel.bin'] and
             read(out / 'sentinel.bin') == b'UNCHANGED', 'Output overwrite')
    else:
        need(not out.exists(), 'Input rejection left a product directory')
    return dict(case=case['id'], optimized=optimized, status='PASS', result=result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('decoder-root', 'decoder-source-root', 'snapshot-file',
                 'host-identities', 'evidence'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    template = fixtures()
    identifiers = identifier_fixtures()
    args.host = json.loads(read(Path(args.host_identities)))
    evidence = Path(args.evidence).absolute()
    evidence.mkdir()
    negative_cases = json.loads(read(FIXTURE / 'negative-oracle-classes.json'))['cases']
    need(len(negative_cases) == 11, 'Negative oracle cardinality')
    results = []
    for optimized in (False, True):
        cases = [('POSITIVE', None)] + [(r['id'], r) for r in negative_cases]
        for name, case in cases:
            directory = evidence / (('optimized-' if optimized else 'normal-') + name)
            try:
                result = positive(args, template, directory, optimized) if case is None else (
                    negative(args, template, directory, case, optimized))
            except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
                result = dict(case=name, optimized=optimized, status='FAIL', error=str(error))
            results.append(result)
            save(evidence / (directory.name + '-result.json'), result)
        for fixture in identifiers:
            name = 'IDENTIFIER_' + fixture.name
            directory = evidence / (('optimized-' if optimized else 'normal-') + name)
            try:
                data = json.loads(read(fixture / 'input-template.json'))
                result = positive(args, data, directory, optimized, fixture)
                result['case'] = name
            except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
                result = dict(case=name, optimized=optimized, status='FAIL', error=str(error))
            results.append(result)
            save(evidence / (directory.name + '-result.json'), result)
    report = dict(schema='quorum/sender-development-results/1',
        results=results, all_pass=all(r['status'] == 'PASS' for r in results),
        classification='DEVELOPMENT_ONLY_NOT_HELDOUT_NOT_ACCEPTANCE',
        tested_python=sys.version, model_tokens='NOT_MEASURED',
        human_work='NOT_MEASURED', behavioral_superiority='NOT_ESTABLISHED')
    save(evidence / 'results.json', report)
    print(canonical(report).decode())
    return 0 if report['all_pass'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
