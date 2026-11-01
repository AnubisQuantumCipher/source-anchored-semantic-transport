"""Mechanical encoding only with already qualified existing decoder; no new checker.
Finite15 literal source tuples, <=16sources/65536bytes each; exact packages<=131072.
No expected semantic labels/counts/errors obtained from encoder/decoder outputs.
"""
import base64
import hashlib
import json
import sys
from pathlib import Path
sys.dont_write_bytecode=True
P=Path('/dev/shm/semantic-transport-replay-integration-20261029/revision-02/literal-controls')
OUT=Path('/dev/shm/semantic-transport-replay-controls-20261029/materialization-01')
DEC=Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/semantic-handoff-v1/positive-02/transport/decoder')
QUAL=Path('/dev/shm/semantic-transport-replay-controls-20261029/external-closure-01/runtime-qualification')


def C(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def pin(p):
 b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}


def save(path,v):
 with path.open('xb') as f:f.write(C(v))
 return pin(path)


qualification=json.loads((QUAL/'qualification-first-result.json').read_bytes())
if qualification['execution'].get('value',{}).get('status')!='INSTALLATION_RECONSTRUCTION_CHECKED':raise ValueError('actual source-bound qualification required')
snapshot=json.loads((QUAL/'installed-snapshot-after.json').read_bytes())
for name,expected in snapshot['files'].items():
 actual=pin(DEC/name)
 if actual['bytes']!=expected['bytes'] or actual['sha256']!=expected['sha256']:raise ValueError('qualified tool bytes changed '+name)
sys.path.insert(0,str(DEC/'tools'))
import transport_package
oracle=json.loads((P/'oracle.json').read_bytes())
if len(oracle['cases'])!=15:raise ValueError('fixed literal case count')
known={};rows=[]
for item in oracle['cases']:
 for expected in item['files']:
  if pin(Path(expected['path']))!=expected:raise ValueError('frozen literal changed')
 d=P/item['id'];raw=(d/'body.json').read_bytes();o=json.loads((d/'originals.json').read_bytes())
 source_rows=[('Q_RECORDS',raw)]
 for original in o['items']:
  data=base64.b64decode(original['base64'],validate=True)
  if len(data)!=original['key']['bytes'] or hashlib.sha256(data).hexdigest()!=original['key']['sha256']:raise ValueError('original mismatch')
  source_rows.append((original['alias_id'],data))
 source_rows.sort(key=lambda pair:C(pair[0]))
 if len(source_rows)>16 or sum(len(data) for _,data in source_rows)>65536:raise ValueError('source tuple cap')
 # Body bytes alone do not key sharing; every physical alias+byte contributes.
 identity=hashlib.sha256(C([{'alias':name,'hex':data.hex()} for name,data in source_rows])).hexdigest()
 if identity not in known:
  target=OUT/('package-'+str(len(known)).zfill(2));target.mkdir()
  plan={'schema':'transport/transport-plan/1','sources':[{'id':name,'label':'Exact fixture '+name,
    'media_type':'application/octet-stream','provenance':'Manually supplied frozen original bytes; no semantic qualification.'} for name,_ in source_rows],
    'interpretations':[],'uncertainties':[],'relations':[]}
  save(target/'plan.json',plan)
  package=transport_package.encode(tuple(data for _,data in source_rows),C(plan),budget=131072)
  for filename,data in (('meaning.zip',package.archive),('share.txt',package.text),('lexicon.md',package.lexicon)):
   with (target/filename).open('xb') as stream:stream.write(data)
  # Existing qualified decoder identity is construction provenance only, no new replay result.
  from transport_schema import json_value
  from transport_archive import read_archive
  manifest=json_value(read_archive(package.archive)['manifest.json'])
  record={'source_tuple_sha256':identity,'sources':[{'id':name,'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()} for name,data in source_rows],
    'archive':pin(target/'meaning.zip'),'share':pin(target/'share.txt'),'plan':pin(target/'plan.json'),'lexicon':pin(target/'lexicon.md'),
    'STS1_identity':'STS1:'+manifest['sha256'],'scope':'Existing qualified transport encoding/readback only; no new replay/host/bootstrap function called.'}
  known[identity]=record;save(target/'package-receipt.json',record)
 rows.append({'id':item['id'],'mechanical_package':known[identity]})
loaded=[]
for name,module in sorted(sys.modules.items()):
 if name.startswith('transport_'):
  path=Path(module.__file__).resolve();relative=path.relative_to(DEC).as_posix();expected=snapshot['files'].get(relative)
  if expected is None or pin(path)['sha256']!=expected['sha256']:raise ValueError('encoder imported outside qualified installed closure '+name)
  loaded.append({'name':name,'file':pin(path)})
for name,expected in snapshot['files'].items():
 if pin(DEC/name)['sha256']!=expected['sha256']:raise ValueError('qualified tool changed during construction')
r={'classification':'MECHANICAL_FROZEN_LITERAL_PACKAGE_CONSTRUCTION_NOT_NEW_REPLAY_EXECUTION','literal_oracle':pin(P/'oracle.json'),'qualified_existing_decoder_receipt':pin(QUAL/'verification-receipt.json'),
 'cases':rows,'distinct_package_count_observed':len(known),'loaded_existing_encoder_module_files':loaded,
 'qualification':'Existing encode may call its already qualified native byte codec and internal exact decode readback. This is expressly authorized package construction, not new fullReplay/bootstrap execution or expected semantic-output derivation. No semantic record/error/count changed. All first failures retained create-only.'}
result=save(OUT/'package-construction-first-run.json',r)
print(json.dumps({'result':result,'cases':len(rows),'packages':len(known)}))
