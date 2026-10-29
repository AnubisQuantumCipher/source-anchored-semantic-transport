"""Data-only copied-root timestamp-pyc regression construction; no product import.
All expected semantics come from pre-code frozen F01, not checker output.
One case, sixteen source files, two forged cache files, <=2MiB copied bytes.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
import marshal
import os
from pathlib import Path
import stat
import struct
import sys

ROOT=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
PAYLOAD=b"raise RuntimeError('STALE_CACHE_EXECUTED')\n"


def C(v):
 return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def bp(raw):
 return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def fp(path):
 return dict(path=str(path),**bp(path.read_bytes()))


def rawsave(path,raw):
 with path.open('xb') as stream:stream.write(raw)
 return fp(path)


def save(path,value):
 return rawsave(path,C(value))


def copy_roster(descriptor,target,source_pins):
 total=0;rows=[]
 if len(descriptor['files'])!=16:raise ValueError('fixed sixteen file roster')
 for row in descriptor['files']:
  relative=row['path'].split('/',1)[1];source=ROOT/relative
  raw=source.read_bytes();st=source.stat();total+=len(raw)
  if total>2097152 or len(raw)>131072:raise ValueError('copy byte bound')
  if bp(raw)!={k:row[k] for k in ('bytes','sha256')}:raise ValueError('descriptor source drift')
  if source_pins[relative]['sha256']!=bp(raw)['sha256']:raise ValueError('sourcefreeze drift')
  dest=target/relative;dest.parent.mkdir(parents=True,exist_ok=True)
  rawsave(dest,raw);dest.chmod(stat.S_IMODE(st.st_mode))
  os.utime(dest,ns=(st.st_atime_ns,st.st_mtime_ns))
  rows.append({'source':fp(source),'copy':fp(dest),'mode':stat.S_IMODE(st.st_mode),'mtime_ns':st.st_mtime_ns})
 return rows


def forge_cache(target):
 source=target/'install/transport_install_support.py';st=source.stat()
 if not 0<=st.st_size<2**32:raise ValueError('timestamp pyc size bound')
 cache=source.parent/'__pycache__';cache.mkdir()
 header=importlib.util.MAGIC_NUMBER+struct.pack('<III',0,int(st.st_mtime)&0xffffffff,st.st_size)
 rows=[]
 for lane in ('','1'):
  name=source.stem+'.'+sys.implementation.cache_tag+('.opt-'+lane if lane else '')+'.pyc'
  code=compile(PAYLOAD,str(source),'exec',dont_inherit=True,optimize=int(lane or '0'))
  raw=header+marshal.dumps(code);path=cache/name
  rows.append({'optimization':lane or 'normal','cache':rawsave(path,raw),'header_hex':header.hex(),
   'source':fp(source),'source_mtime_ns':st.st_mtime_ns,'source_mtime_uint32':int(st.st_mtime)&0xffffffff,
   'source_size_uint32':st.st_size,'source_mode':stat.S_IMODE(st.st_mode)})
 return rows


def rebind(a,target,descriptor,invocation,modulemap):
 descriptor['checker_root']=str(target);descriptor['handoff_root']=str(target)
 raw=C(descriptor);save(a.out/'checker-descriptor.json',descriptor)
 key=dict(invocation['checker_descriptor']['key'],**bp(raw))
 invocation['checker_descriptor']={'path':str(a.out/'checker-descriptor.json'),'key':key}
 request=json.loads(Path(invocation['request']['path']).read_bytes())
 request['checker']['checker_descriptor']=key;raw=C(request);rawsave(a.out/'request.json',raw)
 invocation['request']=fp(a.out/'request.json');invocation['held_request']=bp(raw)
 envelope=json.loads(Path(invocation['envelope']['path']).read_bytes());envelope['request']=request
 save(a.out/'envelope.json',envelope);invocation['envelope']=fp(a.out/'envelope.json')
 save(a.out/'invocation.json',invocation)
 expected=json.loads((a.semantic_root/'F01_ORIGINAL_ACCEPT/expected.json').read_bytes())
 expected['request']=dict(id='REPLAY_REQUEST',**invocation['held_request'])
 save(a.out/'expected.json',expected);rawsave(a.out/'expected.stdout',C(expected)+b'\n')
 host=json.loads((a.semantic_root/'F01_ORIGINAL_ACCEPT/expected.stderr').read_bytes())
 host['checker_descriptor']=key;host['modules']=copy.deepcopy(modulemap['per_arm_expected_modules']['original'])
 for row in host['modules']:
  path=Path(row['path'])
  if path.is_relative_to(ROOT):row['path']=str(target/path.relative_to(ROOT))
 rawsave(a.out/'expected.stderr',C(host)+b'\n')


parser=argparse.ArgumentParser()
for name in ('source-freeze','semantic-root','module-map','out'):parser.add_argument('--'+name,type=Path,required=True)
a=parser.parse_args();frozen=json.loads(a.source_freeze.read_bytes())
if frozen.get('source')!='/root' or frozen.get('ready') is not True:raise ValueError('owner sourcefreeze')
for relative,row in frozen['sourcepins_verified_before_run'].items():
 if fp(ROOT/relative)['sha256']!=row['sha256']:raise ValueError('sourcefreeze mismatch')
case=a.semantic_root/'F01_ORIGINAL_ACCEPT';inv=json.loads((case/'invocation.json').read_bytes())
if inv['arm']!='original':raise ValueError('exact baseline original arm')
descriptor=json.loads(Path(inv['checker_descriptor']['path']).read_bytes())
modulemap=json.loads(a.module_map.read_bytes());a.out.mkdir();target=a.out/'checker';target.mkdir()
copied=copy_roster(descriptor,target,frozen['sourcepins_verified_before_run']);caches=forge_cache(target)
rebind(a,target,descriptor,inv,modulemap)
report={'id':'CACHE01_COPIED_HELPER_TIMESTAMP_PYC','classification':'PRE_EXECUTION_DATA_ONLY_FROZEN_CACHE_CANDIDATE',
 'sourcefreeze':fp(a.source_freeze),'semantic_baseline':fp(case/'expected.json'),'source_modulemap':fp(a.module_map),
 'python':fp(Path(sys.executable).resolve()),'cache_tag':sys.implementation.cache_tag,'magic_hex':importlib.util.MAGIC_NUMBER.hex(),
 'payload_hex':PAYLOAD.hex(),'copied_sources':copied,'forged_caches':caches,
 'entry':fp(target/'install/transport_quorum_bootstrap.py'),'invocation':fp(a.out/'invocation.json'),
 'expected_stdout':fp(a.out/'expected.stdout'),'expected_stderr':fp(a.out/'expected.stderr'),'expected_exit_code':0,
 'product_execution':'UNRUN; future fixed source must execute owned .py bytes regardless of these timestamp-valid caches.'}
save(a.out/'stale-cache-freeze.json',report)
print(json.dumps(fp(a.out/'stale-cache-freeze.json')))
