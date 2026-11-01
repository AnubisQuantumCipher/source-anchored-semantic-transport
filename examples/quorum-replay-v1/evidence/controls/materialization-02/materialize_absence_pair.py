"""Data-only absent-sidecar pair from independently reviewed baseline carriers.
Two cases, <=16 original-source aliases; source semantics are never regenerated.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path


def C(value):
 return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def fp(path):
 raw=path.read_bytes()
 return {'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def save(path,raw):
 with path.open('xb') as stream:stream.write(raw)
 return fp(path)


def make_case(root,out,arm):
 source=root/('F01_ORIGINAL_ACCEPT' if arm=='original' else 'F02_TRANSPORT_ACCEPT')
 ident='ABS01_TRANSPORT_NO_BODY_OR_SOURCE_SIDECARS' if arm=='transport' else 'ABS02_ORIGINAL_MISSING_BODY_OR_SOURCE_SIDECARS'
 target=out/ident;target.mkdir();inv=copy.deepcopy(json.loads((source/'invocation.json').read_bytes()))
 if inv['arm']!=arm or len(inv['originals'])>16:raise ValueError('fixed baseline arm/source bound')
 absent=[target/'absent-body.json'];inv['body']['path']=str(absent[0])
 for index,row in enumerate(inv['originals']):
  path=target/('absent-original-'+str(index));row['path']=str(path);absent.append(path)
 for path in absent:
  if path.exists() or path.is_symlink():raise ValueError('absence control path exists')
 invocation=save(target/'invocation.json',C(inv))
 if arm=='transport':
  stdout=(source/'expected.stdout').read_bytes();stderr=(source/'expected.stderr').read_bytes();code=0
 else:
  refusal={'schema':'quorum/bootstrap-refusal/1','status':'REFUSED_HOST_PRECONDITION','authority':'NONE','reason':'CHECKER_FILE_IDENTITY'}
  stdout=C(refusal)+b'\n';stderr=b'';code=2
 return {'id':ident,'arm':arm,'source_baseline_invocation':fp(source/'invocation.json'),
  'source_baseline_expected':fp(source/'expected.json'),'invocation':invocation,
  'absent_paths':[str(path) for path in absent],
  'expected_stdout':save(target/'expected.stdout',stdout),'expected_stderr':save(target/'expected.stderr',stderr),
  'expected_exit_code':code,'changed_field_inventory':['/body/path','/originals/*/path'],
  'unchanged_request':inv['request'],'unchanged_held_request':inv['held_request']}


parser=argparse.ArgumentParser()
for name in ('original-root','transport-root','out'):parser.add_argument('--'+name,type=Path,required=True)
a=parser.parse_args();a.out.mkdir()
cases=[make_case(a.transport_root,a.out,'transport'),make_case(a.original_root,a.out,'original')]
report={'classification':'PRE_EXECUTION_ABSENCE_PAIR_DATA_ONLY','cases':cases,
 'semantic_policy':'Only invocation Body/original path fields differ. Exact baseline Request, declared Body/original keys, ZIP, semantic expected envelope and source-derived host expected fields retained. No product import/run.'}
p=a.out/'absence-pair-freeze.json';save(p,C(report));print(json.dumps(fp(p)))
