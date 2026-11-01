"""Bounded local build/proof evidence; never changes legacy sources."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time
import zipfile

ROOT = Path(__file__).resolve().parent
OUT = Path('/dev/shm/semantic-transport-large-document-20261030/native')
CAP = 536870912
ENTRY_CAP = 8192
GNAT = Path('/home/sicarii/opt/gnat')


def footprint():
    size, count = 0, 0
    for base, dirs, files in os.walk(OUT, followlinks=False):
        for name in dirs + files:
            item = Path(base) / name
            info = item.lstat()
            size += max(info.st_size, info.st_blocks * 512)
            count += 1
            if size > CAP - 1048576 or count > ENTRY_CAP:
                raise ValueError('native evidence resource bound')
    return {'allocated_or_logical_bytes': size, 'entries': count}


def sources(target):
    mapping = {}
    paths = sorted(p for p in ROOT.iterdir() if p.is_file()
                   and p.suffix in {'.ads', '.adb', '.gpr', '.py', '.md'})
    paths += sorted((ROOT.parent / 'src').glob('*.ad?'))
    with zipfile.ZipFile(target, 'x', zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            data = path.read_bytes()
            name = str(path.relative_to(ROOT.parent))
            mapping[name] = hashlib.sha256(data).hexdigest()
            archive.writestr(name, data)
    return mapping


def limits():
    resource.setrlimit(resource.RLIMIT_AS, (1073741824, 1073741824))
    resource.setrlimit(resource.RLIMIT_FSIZE, (16777216, 16777216))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def environment(attempt):
    bins = ['gnat-aarch64-linux-16.1.0-1/bin',
            'gprbuild-aarch64-linux-26.0.0-1/bin',
            'gnatprove-aarch64-linux-16.1.0-1/bin']
    result = {'HOME': os.environ['HOME'], 'LANG': 'C', 'LC_ALL': 'C',
              'PATH': ':'.join(str(GNAT / p) for p in bins) + ':/usr/bin:/bin',
              'TMPDIR': str(attempt / 'tmp'),
              'XDG_CACHE_HOME': str(attempt / 'cache'),
              'GPR_PROJECT_PATH': str(GNAT / 'gnatprove-aarch64-linux-16.1.0-1/lib/gnat'),
              'DOCUMENT_NATIVE_OBJ': str(attempt / 'obj'),
              'DOCUMENT_NATIVE_BIN': str(attempt / 'bin'),
              'DOCUMENT_PROOF_OBJ': str(attempt / 'proof-obj')}
    for key in ['TMPDIR', 'XDG_CACHE_HOME', 'DOCUMENT_NATIVE_OBJ',
                'DOCUMENT_NATIVE_BIN', 'DOCUMENT_PROOF_OBJ']:
        Path(result[key]).mkdir(parents=True, exist_ok=True)
    return result


def terminate(proc):
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait(timeout=2)


def invoke(command, seconds, deadline, attempt, label, env):
    start = time.monotonic()
    failure = None
    with (attempt / (label + '.stdout')).open('xb') as stdout:
        with (attempt / (label + '.stderr')).open('xb') as stderr:
            proc = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stdout,
                                    stderr=stderr, start_new_session=True,
                                    preexec_fn=limits)
            try:
                while proc.poll() is None:
                    footprint()
                    if time.monotonic() >= min(start + seconds, deadline):
                        raise TimeoutError('phase/outer deadline')
                    time.sleep(0.1)
            except BaseException as error:
                failure = repr(error)
            finally:
                terminate(proc)
    record = {'argv': command, 'returncode': proc.returncode,
              'elapsed_seconds': time.monotonic() - start,
              'failure': failure, 'footprint': footprint()}
    (attempt / (label + '.json')).write_text(json.dumps(record, indent=2) + '\n')
    if failure or proc.returncode:
        raise ValueError(label + ' FAILED; preserved logs')
    return record


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('attempt')
    parser.add_argument('--build-only', action='store_true')
    args = parser.parse_args()
    if not args.attempt.isalnum():
        raise ValueError('fixed alphanumeric attempt name required')
    attempt = OUT / args.attempt
    attempt.mkdir()
    start = time.monotonic()
    mapping = sources(attempt / 'sources.zip')
    env = environment(attempt)
    base = ['gprbuild', '-P', str(ROOT / 'document_native.gpr'), '-j1']
    proof = ['gnatprove', '-P', str(ROOT / 'document_ledger_proof.gpr'),
             '-U', '--level=2', '--report=all', '--warnings=error', '-j1',
             '--prover=z3', '--timeout=1', '--counterexamples=off']
    records = []
    try:
        records.append(invoke(base, 120, start + 450, attempt, 'build', env))
        if not args.build_only:
            records.append(invoke(proof, 300, start + 450, attempt, 'proof', env))
    finally:
        after = {name: hashlib.sha256((ROOT.parent / name).read_bytes()).hexdigest()
                 for name in mapping}
        receipt = {'sources': mapping, 'sources_unchanged': mapping == after,
                   'records': records, 'footprint': footprint()}
        (attempt / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if mapping != after:
        raise ValueError('source changed during qualification')


if __name__ == '__main__':
    main()
