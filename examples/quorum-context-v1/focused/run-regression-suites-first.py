"""Create-only independent input/source regression runs after context readiness."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

OUT = Path('/dev/shm/semantic-transport-context-controls-20261029')
ROOT = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


if not (OUT / 'ready-receipt.json').is_file():
    raise RuntimeError('readiness receipt required before regression execution')
suite = sys.argv[1] if len(sys.argv) == 2 else None
if suite not in ('input', 'source', 'claim', 'impact'):
    raise ValueError('fixed suite input or source required')
paths = sorted((ROOT / 'tools').glob('*.py'))
paths += [ROOT / 'tools/transport_quorum_body.schema.json',
          ROOT / ('install/test_quorum_' + suite + '.py')]
before = [pin(path) for path in paths]
env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', TMPDIR=str(OUT / 'suite-test-tmp'))
evidence = OUT / (suite + '-suite-evidence-first-run.json')
command = [sys.executable, '-B', str(ROOT / ('install/test_quorum_' + suite + '.py')),
           '--evidence', str(evidence)]
log = OUT / (suite + '-suite-first-run.log')
with log.open('xb') as stream:
    try:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
            stderr=subprocess.STDOUT, timeout=25, check=False)
        execution = {'outcome': 'returned', 'exit_code': result.returncode}
    except subprocess.TimeoutExpired:
        execution = {'outcome': 'timeout', 'timeout_seconds': 25}
after = [pin(path) for path in paths]
report = {'command': command, 'execution': execution,
    'source_pins_before': before, 'source_pins_after': after,
    'source_pins_unchanged_during_run': before == after, 'log': pin(log)}
if evidence.is_file():
    report['evidence'] = pin(evidence)
path = OUT / (suite + '-suite-first-run.json')
with path.open('xb') as stream:
    stream.write(json.dumps(report, sort_keys=True, separators=(',', ':')).encode())
print(json.dumps({'suite': suite, 'execution': execution, 'receipt': pin(path),
                  'source_pins_unchanged': before == after}))
raise SystemExit(0 if execution.get('exit_code') == 0 and before == after else 1)
