"""Data-only bounded run-manifest preparation from frozen literal expectations.
No product calls, outcome-derived expectations, omitted P02, or hidden retries.
"""
import copy
import hashlib
import json
from pathlib import Path
import sys

BASE=Path('/dev/shm/semantic-transport-replay-controls-20261029')
S=BASE/'materialization-03'
SCRIPT=BASE/'materialization-02'
ROOT=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
ENTRY=ROOT/'install/transport_quorum_bootstrap.py'
PYTHON=str(Path(sys.executable).resolve())


def C(value):
 return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def fp(path):
 raw=path.read_bytes()
 return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def save(path,raw):
 with path.open('xb') as stream:stream.write(raw)
 return fp(path)


def case(inv_path,ident,stdout,stderr,code,entry=ENTRY,extra=()):
 inv=json.loads(inv_path.read_bytes());paths=[inv_path,Path(inv['checker_descriptor']['path'])]
 for key in ('request','envelope','body','package'):paths.append(Path(inv[key]['path']))
 paths.extend(Path(row['path']) for row in inv['originals'])
 if inv['share']:paths.append(Path(inv['share']['path']))
 if inv['auxiliary']:paths.append(Path(inv['auxiliary']['path']))
 paths.extend(extra);ip=fp(inv_path);held=fp(entry)
 return {'id':ident,'mode':'public_cli','independently_held_entry':held,
  'command':[PYTHON,'-I','-S',str(entry),str(inv_path),'--expect-invocation-sha256',ip['sha256'],'--expect-bootstrap-sha256',held['sha256']],
  'frozen_inputs':[fp(p) for p in sorted(set(paths))],
  'expected_stdout':fp(stdout),'expected_stderr':fp(stderr),'expected_exit_code':code}


def semantic(folder,exclude):
 manifest=json.loads((S/folder/'materialized-freeze.json').read_bytes());rows=[]
 for row in manifest['cases']:
  if row['id'] in exclude:continue
  if row['id']=='F08_MISSING_CHECKER_AND_GRAPH':
   source=S/'isolated-copies-r02'/row['id'];entry=source/'checker/install/transport_quorum_bootstrap.py'
  else:source=S/folder/row['id'];entry=ENTRY
  rows.append(case(source/'invocation.json',row['id']+'__'+manifest['arm'],source/'expected.stdout',source/'expected.stderr',row['expected_exit_code'],entry))
 return rows


def host_rows(out):
 manifest=json.loads((S/'host15-r02/host-materialization-freeze.json').read_bytes());rows=[]
 for row in manifest['cases']:
  name=row['id']
  if name in ('H00_TWO_ARM_PARITY','H14_IMPORTED_ORIGIN'):continue
  source=S/('isolated-copies-r02' if name.startswith(('H11','H12','H13')) else 'host15-r02')/name
  if name.startswith(('H11','H12','H13')):stdout=source/'expected.stdout';stderr=source/'expected.stderr'
  else:
   stdout=out/(name+'.expected.stdout');stderr=out/(name+'.expected.stderr')
   save(stdout,C(json.loads((source/'expected-stdout.json').read_bytes()))+b'\n');save(stderr,b'')
  item=case(source/'invocation.json',name,stdout,stderr,2)
  if name=='H01_WRONG_ENTRY_PIN':
   item['id']='H01_WRONG_ENTRY_OPTION_CLI_DEFENSE';item['command'][-1]=('1' if item['command'][-1][0]=='0' else '0')+item['command'][-1][1:]
   item['scope_note']='Parent verifies correct actual entry pin; this direct public case tests CLI wrong-held-option defense. External no-execution preflight checked separately.'
  if name in ('H02_PRELOADED_TRANSPORT','H03_MODULE_COUNT'):
   ip=fp(source/'invocation.json');ep=fp(ENTRY);wrapper=SCRIPT/'preentry_probe_r02.py'
   item['mode']='preentry_instrumented_cli'
   item['command']=[PYTHON,'-I','-S',str(wrapper),'preloaded' if name.startswith('H02') else 'count',str(ENTRY),ep['sha256'],ip['path'],ip['sha256'],str(out/(name+'.normal.preentry-state.json'))]
   item['frozen_inputs'].append(fp(wrapper))
  rows.append(item)
 return rows


def cache_row():
 source=S/'stale-cache';frozen=json.loads((source/'stale-cache-freeze.json').read_bytes())
 extra=[Path(row['copy']['path']) for row in frozen['copied_sources']]
 extra.extend(Path(row['cache']['path']) for row in frozen['forged_caches'])
 return case(source/'invocation.json','CACHE01_COPIED_HELPER_TIMESTAMP_PYC',source/'expected.stdout',source/'expected.stderr',0,Path(frozen['entry']['path']),extra)


def private_row(out):
 oracle=SCRIPT/'private-origin-projection-handwritten-oracle.json';expected=json.loads(oracle.read_bytes())
 stdout=out/'H14_PRIVATE.expected.stdout';stderr=out/'H14_PRIVATE.expected.stderr'
 save(stdout,C(expected['expected_stdout_json'])+b'\n');save(stderr,b'')
 wrapper=SCRIPT/'private_origin_probe.py';entry=fp(ENTRY)
 return {'id':'H14_IMPORTED_ORIGIN_PRIVATE_PROJECTION','mode':'private_origin_helper',
  'command':[PYTHON,'-I','-S',str(wrapper),str(ENTRY),entry['sha256']],
  'independently_held_entry':entry,'frozen_inputs':[fp(wrapper),fp(oracle)],
  'expected_stdout':fp(stdout),'expected_stderr':fp(stderr),'expected_exit_code':0,
  'scope_note':'Synthetic private _audit rejection projection only; no public host qualification or replay is invoked.'}


def manifest(base,cases,extra_pins):
 if len(cases)>30:raise ValueError('fixed batch thirty cap')
 result=copy.deepcopy(base);result['cases']=cases
 result.update(owner_ready=False,independent_review_passed=False,readiness='Pending independent concrete fixture/wrapper review; sourcefreeze03 owner authorization conditional only.')
 result['oracle_pins'].extend(fp(p) for p in extra_pins)
 return result


out=S/'remaining-manifests-r02';out.mkdir()
base=json.loads((S/'priority-pair-absence-normal-ready.json').read_bytes())
snap_path=BASE/'external-closure-01/runtime-qualification/installed-snapshot-after.json'
snapshot=json.loads(snap_path.read_bytes());decoder=Path(snapshot['path'])
if len(snapshot['files'])>512:raise ValueError('installed snapshot fixed file cap')
for rel,held in snapshot['files'].items():
 actual=fp(decoder/rel)
 if any(actual[k]!=held[k] for k in ('bytes','sha256')):raise ValueError('qualified installed file changed')
 base['source_pins'].append(actual)
extra=[S/name for name in ('literal15-r02-original/materialized-freeze.json','literal15-r02-transport/materialized-freeze.json','review8-original/materialized-freeze.json','review8-transport/materialized-freeze.json','host15-r02/host-materialization-freeze.json','isolated-copies-r02/isolated-copy-setup-freeze.json','stale-cache/stale-cache-freeze.json')]
extra.extend(SCRIPT/name for name in ('preentry_probe_r02.py','private_origin_probe.py','private-origin-projection-handwritten-oracle.json','run_frozen_cli_v04.py','stale-cache-oracle.json'))
groups={'original-host-cache':semantic('literal15-r02-original',set())+host_rows(out)+[cache_row()],
 'transport14':semantic('literal15-r02-transport',set()),'private-origin':[private_row(out)]}
for item in groups['original-host-cache']:
 if item['id']=='F08_MISSING_CHECKER_AND_GRAPH__original':
  folder=S/'isolated-copies-r02/F08_MISSING_CHECKER_AND_GRAPH'
  copied=json.loads((S/'isolated-copies-r02/isolated-copy-setup-freeze.json').read_bytes())['cases'][0]
  added=[Path(row['path']) for row in copied['copied_before_mutation'] if Path(row['path']).exists()]
  item['absent_paths']=[copied['missing_file']]
  added.append(folder/'removed-replay-bytes.py')
 elif item['id'].startswith(('H11_','H12_','H13_')):
  folder=S/'isolated-copies-r02'/item['id']
  added=[folder/'decoder'/rel for rel in snapshot['files']]
  added.extend(folder/name for name in ('pristine-copied-snapshot.json','pristine-qualification.json','pristine-tampered-member-bytes.py'))
 else:added=[]
 item['frozen_inputs'].extend(fp(p) for p in added)
 item['frozen_file_metadata']=[{'path':row['path'],'mode':Path(row['path']).stat().st_mode&0o7777,'mtime_ns':Path(row['path']).stat().st_mtime_ns} for row in item['frozen_inputs']]
for name,rows in groups.items():
 for optimization in ('normal','opt1'):
  value=manifest(base,rows,extra)
  if optimization=='opt1':
   for item in value['cases']:
    item['command'].insert(1,'-O')
    if item['mode']=='preentry_instrumented_cli':item['command'][-1]=item['command'][-1].replace('.normal.preentry-state.json','.opt1.preentry-state.json')
  p=out/(name+'-'+optimization+'-pending.json');save(p,C(value));print(json.dumps(fp(p)))
