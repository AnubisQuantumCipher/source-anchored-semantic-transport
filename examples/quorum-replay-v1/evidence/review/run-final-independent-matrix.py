"""Independent exact frozen CLI reruns; only review output paths are rebound."""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys

C = Path(__file__).parent
M = Path('/dev/shm/semantic-transport-replay-controls-20261029/materialization-03/remaining-manifests-r02')
RUNNER = M.parents[1] / 'materialization-02/run_frozen_cli_v05.py'
W = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')


def pin(p):
    raw = p.read_bytes()
    return dict(path=str(p), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def save(p, value):
    with p.open('xb') as stream:
        stream.write(json.dumps(value, sort_keys=True, separators=(',', ':')).encode())


def run_group(group, lane):
    old = M / f'{group}-{lane}-ready.json'
    value = copy.deepcopy(json.loads(old.read_bytes()))
    for case in value['cases']:
        if case['mode'] == 'preentry_instrumented_cli':
            case['command'][-1] = str(C / f'final-{group}-{lane}-{case["id"]}.preentry.json')
    local = C / f'final-{group}-{lane}-manifest.json'
    save(local, value)
    command = [sys.executable, '-I', '-B', str(RUNNER), '--frozen-run-manifest',
               str(local), '--out', str(C / f'final-{group}-{lane}-observations')]
    with (C / f'final-{group}-{lane}.stdout').open('xb') as first:
        with (C / f'final-{group}-{lane}.stderr').open('xb') as second:
            result = subprocess.run(command, stdout=first, stderr=second, timeout=600, check=False)
    record = dict(original_manifest=pin(old), local_manifest=pin(local), command=command,
                  exit_code=result.returncode, change='Only instrumented state receipt output paths rebound.')
    save(C / f'final-{group}-{lane}-runner.json', record)
    print(group, lane, result.returncode, flush=True)
    return record


def pure(lane):
    cache = C / f'final-core-{lane}-fresh-cache'
    cache.mkdir()
    evidence = C / f'final-core-{lane}-results.json'
    command = [sys.executable, '-I', '-B', '-X', 'pycache_prefix=' + str(cache)]
    if lane == 'opt1':
        command.append('-O')
    harness = W / 'install/test_quorum_replay.py'
    before = pin(harness)
    command += [str(harness), '--evidence', str(evidence)]
    with (C / f'final-core-{lane}.stdout').open('xb') as first:
        with (C / f'final-core-{lane}.stderr').open('xb') as second:
            result = subprocess.run(command, stdout=first, stderr=second, timeout=60, check=False)
    record = dict(command=command, harness=before, exit_code=result.returncode,
                  harness_unchanged=before == pin(harness), fresh_cache_empty=not any(cache.iterdir()))
    save(C / f'final-core-{lane}-runner.json', record)
    print('pure', lane, result.returncode, flush=True)
    return record


results = []
for group in ('original-semantic14', 'transport14', 'host-cache15'):
    for lane in ('normal', 'opt1'):
        results.append(run_group(group, lane))
for lane in ('normal', 'opt1'):
    results.append(pure(lane))
save(C / 'final-independent-matrix-runner-receipt.json', dict(runs=results, runner=pin(RUNNER)))
raise SystemExit(1 if any(r['exit_code'] for r in results) else 0)
