"""Independent frozen exact-byte wrapper controls; no expected output from product."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time

ORACLE_SHA = '8b47afe942fac6d1efd6bfee64b071775a6ce78c94ae2147fa5bec6d52f4591c'


def C(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def save(path, raw):
    with path.open('xb') as stream:
        if stream.write(raw) != len(raw):
            raise OSError('incomplete create-only write')


def snapshot(directory):
    items = sorted(directory.iterdir())
    if len(items) > 5:
        raise ValueError('fixture inventory bound')
    result = {}
    for path in items:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > 131072:
            raise ValueError('fixture shape')
        result[path.name] = pin(path.read_bytes())
    return result


def capture(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True,
                               env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C.UTF-8'})
    selector = selectors.DefaultSelector()
    buffers = [bytearray(), bytearray()]
    caps = [1048576, 131072]
    for index, stream in enumerate((process.stdout, process.stderr)):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, index)
    start = time.monotonic()
    failure = None
    for unused in range(8000):
        if time.monotonic() - start > 40:
            failure = 'TIMEOUT'
            break
        for key, unused_mask in selector.select(0.01):
            data = os.read(key.fileobj.fileno(), min(4096, caps[key.data] + 1 - len(buffers[key.data])))
            if data:
                buffers[key.data].extend(data)
            else:
                selector.unregister(key.fileobj)
            if len(buffers[key.data]) > caps[key.data]:
                failure = 'CAPTURE_BOUND'
                break
        if failure or (not selector.get_map() and process.poll() is not None):
            break
    else:
        failure = 'CAPTURE_WORK_BOUND'
    if failure:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    code = process.wait(timeout=5)
    selector.close()
    process.stdout.close()
    process.stderr.close()
    return {'exit_code': code, 'capture_failure': failure,
            'elapsed_monotonic_seconds': time.monotonic() - start}, bytes(buffers[0]), bytes(buffers[1])


def run_case(case, lane, folder, args, oracle, source):
    folder.mkdir()
    inputs = folder / 'inputs'
    inputs.mkdir()
    for row in oracle['input_files']:
        raw = (args.oracle.parent / 'inputs' / row['name']).read_bytes()
        if pin(raw) != {k: row[k] for k in ('bytes', 'sha256')}:
            raise ValueError('frozen input pin')
        save(inputs / row['name'], raw)
    before = snapshot(inputs)
    public = folder / 'display.txt'
    encoded = folder / 'encoded'
    if case['existing_public_hex'] is not None:
        save(public, bytes.fromhex(case['existing_public_hex']))
    command = [str(Path(sys.executable).resolve())] + (['-O'] if lane == 'opt1' else [])
    command += ['-I', '-S', str(args.module), case['action'], '--encoder', str(args.encoder),
                '--expect-encoder-sha256', case['held_launcher_sha256'],
                str(inputs / case['document']), str(encoded), str(public), '--source',
                'SOURCE=' + str(inputs / 'source.txt'), '--budget', str(case['budget']),
                '--reference', oracle['reference']]
    if args.module.read_bytes() != source:
        raise ValueError('source changed before case')
    result, stdout, stderr = capture(command)
    save(folder / 'first.stdout', stdout)
    save(folder / 'first.stderr', stderr)
    canonical_ok = not encoded.exists() and not encoded.is_symlink()
    if case['expected_canonical_files']:
        try:
            actual = snapshot(encoded) if encoded.is_dir() and not encoded.is_symlink() else {}
        except (OSError, ValueError):
            actual = {}
        expected = {r['name']: {k: r[k] for k in ('bytes', 'sha256')}
                    for r in case['expected_canonical_files']}
        canonical_ok = actual == expected
        for name in expected:
            canonical_ok = canonical_ok and (encoded / name).read_bytes() == (args.oracle.parent / case['baseline'] / name).read_bytes()
    wanted = case['expected_companion_hex']
    if wanted is None:
        wanted = case['existing_public_hex']
    public_ok = not public.exists() and not public.is_symlink()
    if wanted is not None:
        public_ok = public.is_file() and not public.is_symlink() and public.stat().st_size <= 131072 and public.read_bytes() == bytes.fromhex(wanted)
    checks = {'complete_capture': result['capture_failure'] is None,
              'exit': result['exit_code'] == case['expected_exit_code'],
              'stdout': stdout == bytes.fromhex(case['expected_stdout_hex']),
              'stderr': stderr == bytes.fromhex(case['expected_stderr_hex']),
              'canonical_exact': canonical_ok, 'public_exact_or_absent': public_ok,
              'inputs_unchanged': snapshot(inputs) == before,
              'source_unchanged': args.module.read_bytes() == source}
    row = {'id': case['id'], 'lane': lane, 'scope': 'PUBLIC_FIXED_ENCODER_WRAPPER',
           'argv': command, 'execution': result, 'stdout': pin(stdout), 'stderr': pin(stderr), 'checks': checks}
    save(folder / 'first-result.json', C(row))
    return row


def main():
    parser = argparse.ArgumentParser()
    for name in ('oracle', 'module', 'out'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expect-source-sha256', required=True)
    parser.add_argument('--encoder', type=Path)
    args = parser.parse_args()
    raw = args.oracle.read_bytes()
    if len(raw) > 65536 or pin(raw)['sha256'] != ORACLE_SHA:
        raise ValueError('frozen oracle identity')
    oracle = json.loads(raw)
    if args.encoder is None:
        args.encoder = Path(oracle['supported_encoder'])
    if not args.encoder.is_absolute() or args.encoder.stat().st_size > 131072:
        raise ValueError('explicit bounded absolute qualified encoder path')
    if pin(args.encoder.read_bytes())['sha256'] != '7366d0bc297e782dfc48593befe57828165f3a671c78bc75296a3e837a15a5e9':
        raise ValueError('qualified encoder source identity')
    if len(oracle['cases']) != 8:
        raise ValueError('fixed bounded eight variants')
    source = args.module.read_bytes()
    if pin(source)['sha256'] != args.expect_source_sha256:
        raise ValueError('owner-held implementation pin')
    originals = snapshot(args.oracle.parent / 'inputs')
    args.out.mkdir()
    rows = []
    for lane in ('normal', 'opt1'):
        folder = args.out / lane
        folder.mkdir()
        for case in oracle['cases']:
            rows.append(run_case(case, lane, folder / case['id'], args, oracle, source))
    report = {'scope': 'OBSERVED_FIXED_WRAPPER_NOT_AUTHENTICATION_OR_ACCEPTANCE',
              'oracle': pin(raw), 'source': pin(source), 'cases': rows,
              'original_inputs_unchanged': snapshot(args.oracle.parent / 'inputs') == originals,
              'source_unchanged': args.module.read_bytes() == source,
              'failures': [r['id'] + '__' + r['lane'] for r in rows if not all(r['checks'].values())]}
    save(args.out / 'first-run.json', C(report))
    print(json.dumps(pin((args.out / 'first-run.json').read_bytes())))
    return int(bool(report['failures']) or not report['original_inputs_unchanged'] or not report['source_unchanged'])


if __name__ == '__main__':
    raise SystemExit(main())
