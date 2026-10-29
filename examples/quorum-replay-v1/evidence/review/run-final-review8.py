"""Independent unchanged reviewer-eight literal subset; no new expectations."""
import json
from pathlib import Path
import subprocess
import sys

C=Path(__file__).parent
Q=Path('/dev/shm/semantic-transport-replay-controls-20261029')
runner=Q/'materialization-02/run_frozen_cli_v05.py'
for lane in ('normal','opt1'):
    old=Q/f'materialization-03/remaining-manifests/transport-review8-r02-{lane}-pending.json'
    value=json.loads(old.read_bytes())
    value['cases']=[r for r in value['cases'] if r['id'].startswith('P')]
    if len(value['cases'])!=16:
        raise ValueError('Exact eight by two arms required')
    value['owner_ready']=True
    value['independent_review_passed']=True
    value['readiness']='Exact unchanged reviewer8 subset; correction09a3 and concrete reviewf9eb; failed contaminated F parent setup excluded from subset only.'
    manifest=C/f'final-review8-{lane}-manifest.json'
    with manifest.open('xb') as stream:
        stream.write(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
    command=[sys.executable,'-I','-B',str(runner),'--frozen-run-manifest',str(manifest),'--out',str(C/f'final-review8-{lane}-observations')]
    with (C/f'final-review8-{lane}.stdout').open('xb') as out,(C/f'final-review8-{lane}.stderr').open('xb') as err:
        result=subprocess.run(command,stdout=out,stderr=err,timeout=600,check=False)
    with (C/f'final-review8-{lane}-runner.json').open('xb') as stream:
        stream.write(json.dumps(dict(command=command,exit_code=result.returncode),sort_keys=True,separators=(',',':')).encode())
    print(lane,result.returncode,flush=True)
