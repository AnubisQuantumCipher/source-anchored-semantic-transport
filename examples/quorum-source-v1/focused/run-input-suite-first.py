"""Run existing input regression suite after readiness; all outputs create-only."""
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

OUT = Path('/dev/shm/semantic-transport-source-controls-20261029')
ROOT = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')


def pin(path):
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


if not (OUT / 'ready-receipt.json').is_file() or not (OUT / 'product-first-run.json').is_file():
    raise RuntimeError('product readiness and first run required before regression run')
paths = [ROOT / 'tools' / name for name in ['transport_quorum_input.py',
    'transport_quorum_shape.py', 'transport_quorum_source.py',
    'transport_quorum_body.schema.json']]
paths.append(ROOT / 'install/test_quorum_input.py')
before = [pin(path) for path in paths]
env = dict(os.environ, PYTHONDONTWRITEBYTECODE='1', TMPDIR=str(OUT / 'test-tmp'))
command = [sys.executable, '-B', str(ROOT / 'install/test_quorum_input.py'),
           '--evidence', str(OUT / 'input-suite-evidence-first-run.json')]
with (OUT / 'input-suite-first-run.log').open('xb') as stream:
    try:
        result = subprocess.run(command, cwd=ROOT, env=env, stdout=stream,
                                stderr=subprocess.STDOUT, timeout=25, check=False)
        outcome = {'outcome': 'returned', 'exit_code': result.returncode}
    except subprocess.TimeoutExpired:
        outcome = {'outcome': 'timeout', 'timeout_seconds': 25}
after = [pin(path) for path in paths]
report = {'command': command, 'execution': outcome,
    'source_pins_before': before, 'source_pins_after': after,
    'source_pins_unchanged_during_run': before == after,
    'log': pin(OUT / 'input-suite-first-run.log')}
evidence = OUT / 'input-suite-evidence-first-run.json'
if evidence.is_file():
    report['suite_evidence'] = pin(evidence)
with (OUT / 'input-suite-first-run.json').open('xb') as stream:
    stream.write(json.dumps(report, sort_keys=True, separators=(',', ':')).encode())
print(json.dumps(report))
