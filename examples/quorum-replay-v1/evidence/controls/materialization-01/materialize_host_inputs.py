"""Mechanical host-negative carrier generator. No new product imports/runs.
Prerequisites: owner sourcefreeze and reviewed literal15 materialization. Produces
public carrier mutations; preentry injection/private postorigin probes stay labeled.
Legacy-copy actual construction is deferred to reviewed copy setup, never in-place.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
ROOT=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
ORACLE=Path('/dev/shm/semantic-transport-replay-controls-20261029/host-bootstrap-01/handwritten-host-expectations-03.json')


def C(v):return json.dumps(v,sort_keys=True,separators=(',',':')).encode()


def pin(p):
 b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}


def save(p,v):
 with p.open('xb') as f:f.write(C(v))
 return pin(p)


def flip(digest):return ('1' if digest[0]=='0' else '0')+digest[1:]


def key_for(raw,key):return dict(key,bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def altered_descriptor(target,inv,mode):
 source=Path(inv['checker_descriptor']['path']);raw=source.read_bytes();value=json.loads(raw)
 if mode=='H04_DESCRIPTOR_RAW':raw=bytes.fromhex('7b22736368656d61223a')
 else:
  if mode=='H05_PYTHON_PIN':value['python']['sha256']=flip(value['python']['sha256'])
  if mode=='H06_FILE_SET':value['files'][-1]['path']=value['files'][0]['path']
  if mode=='H07_FILE_PIN':
   for row in value['files']:
    if row['path']=='checker/tools/transport_quorum_input.py':row['sha256']=flip(row['sha256'])
  if mode=='H10_STALE_SOURCE':value['decoder_source_manifest_sha256']=flip(value['decoder_source_manifest_sha256'])
  raw=C(value)
 path=target/'checker-descriptor.json'
 with path.open('xb') as f:f.write(raw)
 inv['checker_descriptor']={'path':str(path),'key':key_for(raw,inv['checker_descriptor']['key'])}


p=argparse.ArgumentParser();p.add_argument('--semantic-root',type=Path,required=True);p.add_argument('--source-freeze',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
ready=json.loads(a.source_freeze.read_bytes())
if ready.get('ready') is not True or ready.get('source')!='/root':raise ValueError('owner sourcefreeze required')
for name,expected in ready['sourcepins_verified_before_run'].items():
 digest=expected['sha256'] if isinstance(expected,dict) else expected
 if pin(ROOT/name)['sha256']!=digest:raise ValueError('frozen product byte changed')
oracle=json.loads(ORACLE.read_bytes());baseline=json.loads((a.semantic_root/'F01_ORIGINAL_ACCEPT/invocation.json').read_bytes())
a.out.mkdir();rows=[]
for case in oracle['cases']:
 target=a.out/case['id'];target.mkdir();inv=copy.deepcopy(baseline);mode='public_cli';pending=[]
 if case['id']=='H00_TWO_ARM_PARITY':
  rows.append({'id':case['id'],'mode':'paired_existing_semantic_cases','semantic_cases':['F01_ORIGINAL_ACCEPT','F02_TRANSPORT_ACCEPT'],
   'remaining':'Exact arm-specific qualified host receipt module maps must be source-audited and frozen; reuse materialized complete replay expected bytes.'});continue
 if case['id'] in ('H02_PRELOADED_TRANSPORT','H03_MODULE_COUNT'):
  mode='preentry_instrumented_cli';pending.append('Freeze reviewed stdlib-only child harness, parent entry verification, exact sys.argv and bounded inert sys.modules injection before __main__ execution. No candidate import callback.')
 if case['id']=='H01_WRONG_ENTRY_PIN':
  pending.append('Outer harness with wrong held entry pin must refuse without execution; if separately testing CLI defense, parent first verifies correct actual entry pin and passes deliberately wrong CLI --expect-bootstrap-sha256. Label these distinct scopes, same ordered host reason.')
 if case['id'] in ('H04_DESCRIPTOR_RAW','H05_PYTHON_PIN','H06_FILE_SET','H07_FILE_PIN','H10_STALE_SOURCE'):
  altered_descriptor(target,inv,case['id'])
 if case['id']=='H08_STALE_INSTALL':inv['decoder_install_descriptor']['sha256']=flip(inv['decoder_install_descriptor']['sha256'])
 if case['id']=='H09_STALE_RUNTIME':inv['runtime_descriptor']['sha256']=flip(inv['runtime_descriptor']['sha256'])
 if case['id'].startswith(('H11_','H12_','H13_')):
  mode='copied_decoder_setup_required';pending+=case['exact_mutation_recipe']['ordered_steps']
 if case['id']=='H14_IMPORTED_ORIGIN':
  mode='private_origin_probe_UNRUN';pending.append('No reviewed private origin probe interface frozen; no claimed public test result permitted.')
 save(target/'invocation.json',inv);save(target/'expected-stdout.json',case['expected_complete_host_result'])
 rows.append({'id':case['id'],'mode':mode,'invocation':pin(target/'invocation.json'),'expected_stdout_json':pin(target/'expected-stdout.json'),
  'expected_exit_code':2,'expected_stderr_hex':'','pending_source_review_or_setup':pending,
  'qualification':'Exact expected host error unchanged. Pending instrumented/copy setup cannot be executed as a complete public test without separate frozen setup evidence.'})
save(a.out/'host-materialization-freeze.json',{'phase':'MECHANICAL_CARRIERS_WITH_EXPLICIT_REACHABILITY_GATES','oracle':pin(ORACLE),'source_freeze':pin(a.source_freeze),
 'cases':rows,'do_not_execute_pending_setups':True,'new_product_imported_or_executed':False})
print(json.dumps(pin(a.out/'host-materialization-freeze.json')))
