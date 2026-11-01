"""Create-only first full CLI comparison runner. No expectation materialization.
Runs exact public_cli or explicitly preentry_instrumented_cli cases with frozen streams, exit and source gate.
Pending private/instrumented probes remain explicitly UNRUN; no silent coverage.
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def pin(p):
 b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}


def C(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()


def save(path,value):
 with path.open('xb') as f:f.write(C(value))
 return pin(path)


def check_pin(item):
 path=Path(item['path'])
 if pin(path)!=item:raise ValueError('frozen file changed '+str(path))
 return path


def execute(case,out):
 if case['mode'] not in ('public_cli','preentry_instrumented_cli'):return {'id':case['id'],'status':'UNRUN','reason':'Explicit private/instrumented probe needs separately reviewed harness; no public coverage claim.'}
 command=case['command'];entry=check_pin(case['independently_held_entry'])
 if str(entry) not in command:raise ValueError('entry missing from fixed command')
 for item in case['frozen_inputs']:check_pin(item)
 expected_stdout=check_pin(case['expected_stdout']).read_bytes();expected_stderr=check_pin(case['expected_stderr']).read_bytes()
 absent_before=[not Path(p).exists() and not Path(p).is_symlink() for p in case.get('absent_paths',[])]
 if not all(absent_before):raise ValueError('required absent sidecar exists before run')
 stdout=out/(case['id']+'.stdout');stderr=out/(case['id']+'.stderr');start=time.monotonic()
 with stdout.open('xb') as first,stderr.open('xb') as second:
  try:
   result=subprocess.run(command,stdout=first,stderr=second,timeout=30,check=False,
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'))
   status={'outcome':'returned','exit_code':result.returncode}
  except subprocess.TimeoutExpired:status={'outcome':'timeout','timeout_seconds':30}
 elapsed=time.monotonic()-start
 absent_after=[not Path(p).exists() and not Path(p).is_symlink() for p in case.get('absent_paths',[])]
 after=[pin(Path(item['path'])) for item in case['frozen_inputs']]
 unchanged=after==case['frozen_inputs']
 matches=status.get('exit_code')==case['expected_exit_code'] and stdout.read_bytes()==expected_stdout and stderr.read_bytes()==expected_stderr
 row={'id':case['id'],'scope':case['mode'],'command':command,'execution':status,'first_stdout':pin(stdout),'first_stderr':pin(stderr),
  'elapsed_monotonic_seconds':elapsed,'absent_before':absent_before,'absent_after':absent_after,
  'matches_frozen_both_streams_and_exit':matches and all(absent_after),'inputs_unchanged':unchanged,'frozen_inputs_after':after}
 save(out/(case['id']+'.first-result.json'),row)
 return row


p=argparse.ArgumentParser();p.add_argument('--frozen-run-manifest',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
frozen=json.loads(a.frozen_run_manifest.read_bytes())
if frozen.get('owner_ready') is not True or frozen.get('independent_review_passed') is not True:raise ValueError('owner readiness and independent source/map/materialization review gates required')
if len(frozen['cases'])>30:raise ValueError('literal15+host15 case count cap')
for item in frozen['source_pins']:check_pin(item)
for item in frozen['oracle_pins']:check_pin(item)
a.out.mkdir();rows=[execute(case,a.out) for case in frozen['cases']]
report={'classification':'FIRST_FROZEN_FULL_CLI_OBSERVATIONS_NOT_PRODUCT_ACCEPTANCE','manifest':pin(a.frozen_run_manifest),'cases':rows,
 'failures':[r['id'] for r in rows if r.get('matches_frozen_both_streams_and_exit') is False or r.get('inputs_unchanged') is False],
 'unrun':[r['id'] for r in rows if r.get('status')=='UNRUN'],'qualification':'Every first stdout/stderr/exit retained; exact canonical bytes including LF compared. No oracle mutation, retries, salvage parser, semantic normalization, new dependency or acceptance claim.'}
print(json.dumps(save(a.out/'first-run.json',report)))
raise SystemExit(1 if report['failures'] or report['unrun'] else 0)
