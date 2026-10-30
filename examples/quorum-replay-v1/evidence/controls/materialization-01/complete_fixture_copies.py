"""Source-gated isolated copy setup; never imports/executes new replay/bootstrap.
Qualified existing verify_install may regenerate copied runtime in isolated Python.
Every old fixture remains immutable; all revised carriers written to a new root.
"""
import argparse
import copy
import hashlib
import json
import os
import stat
import sys
from pathlib import Path
ROOT=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
DEC=Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/semantic-handoff-v1/positive-02/transport/decoder')
SOURCE=Path('/dev/shm/semantic-transport-replay-integration-20261029/qualified-decoder-source')
P=Path('/dev/shm/semantic-transport-replay-integration-20261029/revision-02')
QUAL=Path('/dev/shm/semantic-transport-replay-controls-20261029/external-closure-01/runtime-qualification')
SOURCE_SHA='f401ff305afcdb6a8232d6e25228c6e156a9d4505c8228d80c263a51ea21817a'
INSTALL_SHA='75e1311f9e66c4aafd133d8b00e6e2029f5ae724e3750d13a4d8fb338e34da96'
BUDGET={'bytes':0,'files':0}


def C(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def bp(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def fp(path):return dict(path=str(path),**bp(path.read_bytes()))


def save(path,value):
 with path.open('xb') as f:f.write(C(value))
 return fp(path)


def rawsave(path,raw):
 with path.open('xb') as f:f.write(raw)
 return fp(path)


def copy_one(source,target,expected=None):
 raw=source.read_bytes();actual=bp(raw)
 if len(raw)>4194304:raise ValueError('copy member cap')
 if expected and any(actual[k]!=expected[k] for k in ('bytes','sha256')):raise ValueError('qualified source changed')
 BUDGET['bytes']+=len(raw);BUDGET['files']+=1
 if BUDGET['bytes']>8388608 or BUDGET['files']>512:raise ValueError('total fixture copy budget')
 target.parent.mkdir(parents=True,exist_ok=True)
 rawsave(target,raw);target.chmod(stat.S_IMODE(source.stat().st_mode))
 return fp(target)


def rebind(target,inv,descriptor):
 raw=C(descriptor);rawsave(target/'checker-descriptor.json',raw)
 key=dict(inv['checker_descriptor']['key'],**bp(raw))
 inv['checker_descriptor']={'path':str(target/'checker-descriptor.json'),'key':key}
 request=json.loads(Path(inv['request']['path']).read_bytes());request['checker']['checker_descriptor']=key
 request_raw=C(request);rawsave(target/'request.json',request_raw)
 inv['request']=fp(target/'request.json');inv['held_request']=bp(request_raw)
 envelope=json.loads(Path(inv['envelope']['path']).read_bytes());envelope['request']=request
 save(target/'envelope.json',envelope);inv['envelope']=fp(target/'envelope.json')
 save(target/'invocation.json',inv)
 return inv


def stdout_files(target,expected):
 rawsave(target/'expected.stdout',C(expected)+b'\n');rawsave(target/'expected.stderr',b'')
 return {'expected_stdout':fp(target/'expected.stdout'),'expected_stderr':fp(target/'expected.stderr'),'expected_exit_code':2}


def checker_copy(out,semantic):
 target=out/'F08_MISSING_CHECKER_AND_GRAPH';target.mkdir();checker=target/'checker';checker.mkdir()
 inv=json.loads((semantic/'F08_MISSING_CHECKER_AND_GRAPH/invocation.json').read_bytes())
 descriptor=json.loads(Path(inv['checker_descriptor']['path']).read_bytes());copied=[]
 for row in descriptor['files']:
  if row['path'].startswith('checker/'):
   relative=row['path'].split('/',1)[1];copied.append(copy_one(ROOT/relative,checker/relative,row))
 descriptor['checker_root']=str(checker)
 rebind(target,inv,descriptor)
 missing=checker/'tools/transport_quorum_replay.py';rawsave(target/'removed-replay-bytes.py',missing.read_bytes());missing.unlink()
 expected=json.loads((semantic/'F08_MISSING_CHECKER_AND_GRAPH/expected.json').read_bytes())
 return {'id':'F08_MISSING_CHECKER_AND_GRAPH','mode':'public_cli','invocation':fp(target/'invocation.json'),
  'entry':fp(checker/'install/transport_quorum_bootstrap.py'),'missing_file':str(missing),'copied_before_mutation':copied,
  'mechanical_correction':'Run copied entry with copied checker root; bind full descriptor before removing replay.py.',**stdout_files(target,expected)}


def decoder_copy(out,host,name,filename,files):
 target=out/name;target.mkdir();decoder=target/'decoder';decoder.mkdir()
 before=json.loads((QUAL/'installed-snapshot-after.json').read_bytes())
 for relative,expected in before['files'].items():copy_one(DEC/relative,decoder/relative,expected)
 command_dir=target/'pristine-verify-install';command_dir.mkdir(mode=0o700)
 # Actual trusted current helper reconstruction on the pristine COPY, no rebuild.
 from transport_install_check import verify_install
 result=verify_install(decoder,files,SOURCE_SHA,INSTALL_SHA,
  dict(PATH='/usr/bin:/bin',LANG='C',LC_ALL='C',PYTHONDONTWRITEBYTECODE='1'),command_dir)
 save(target/'pristine-qualification.json',result)
 if result['status']!='INSTALLATION_RECONSTRUCTION_CHECKED':raise ValueError('pristine copied decoder qualification')
 after=copy.deepcopy(before);after['path']=str(decoder)
 for relative,expected in after['files'].items():
  actual=fp(decoder/relative)
  if any(actual[k]!=expected[k] for k in ('bytes','sha256')):raise ValueError('pristine copy bytes changed')
 save(target/'pristine-copied-snapshot.json',after)
 inv=json.loads((host/name/'invocation.json').read_bytes());inv['bundle_snapshot_pin']=bp(C(after))
 descriptor=json.loads(Path(inv['checker_descriptor']['path']).read_bytes());descriptor['decoder_bundle_root']=str(decoder)
 rebind(target,inv,descriptor)
 member=decoder/'tools'/filename;old=member.read_bytes();rawsave(target/'pristine-tampered-member-bytes.py',old)
 # Mutation only in owned test copy. Keep exact pristine mode and held snapshot.
 with member.open('wb') as f:f.write(old+b'\n')
 expected=json.loads((host/name/'expected-stdout.json').read_bytes())
 return {'id':name,'mode':'public_cli','invocation':fp(target/'invocation.json'),
  'entry':fp(ROOT/'install/transport_quorum_bootstrap.py'),'pristine_qualification':fp(target/'pristine-qualification.json'),
  'pristine_snapshot':fp(target/'pristine-copied-snapshot.json'),'mutated_member':fp(member),**stdout_files(target,expected)}


parser=argparse.ArgumentParser();parser.add_argument('--source-freeze',type=Path,required=True);parser.add_argument('--semantic-root',type=Path,required=True);parser.add_argument('--host-root',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);a=parser.parse_args()
ready=json.loads(a.source_freeze.read_bytes())
if ready.get('source')!='/root' or ready.get('ready') is not True:raise ValueError('owner sourcefreeze required')
for relative,expected in ready['sourcepins_verified_before_run'].items():
 digest=expected['sha256'] if isinstance(expected,dict) else expected
 if fp(ROOT/relative)['sha256']!=digest:raise ValueError('sourcefreeze mismatch')
# Existing helper pins are separately source-bound qualification roots, not part
# of the new runtime imported module map.
for expected in json.loads((QUAL/'helper-pins-after.json').read_bytes()):
 if fp(Path(expected['path']))!=expected:raise ValueError('prior actual helper changed')
sys.dont_write_bytecode=True;sys.path.insert(0,str(ROOT/'install'))
from transport_install_layout import source_inputs
_,files=source_inputs(SOURCE,SOURCE_SHA)
a.out.mkdir();rows=[checker_copy(a.out,a.semantic_root)]
for name,filename in (('H11_LEGACY_SCHEMA','transport_schema.py'),('H12_LEGACY_WIRE','transport_wire.py'),('H13_LEGACY_OPERATORS','transport_operators.py')):
 rows.append(decoder_copy(a.out,a.host_root,name,filename,files))
save(a.out/'isolated-copy-setup-freeze.json',{'phase':'PRE_NEW_PRODUCT_EXECUTION_ISOLATED_NEGATIVE_COPIES_FROZEN','cases':rows,'copy_budget_observed':BUDGET,
 'qualification':'Pristine decoder copies actual existing-helper reconstruction qualified before one-byte tamper. Copied-root snapshot path correctly bound; all manual expected host envelopes unchanged. No new bootstrap/replay called. Original decoder/owner checkout untouched.'})
print(json.dumps(fp(a.out/'isolated-copy-setup-freeze.json')))
