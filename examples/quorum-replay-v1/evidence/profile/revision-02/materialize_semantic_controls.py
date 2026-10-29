"""Literal preimplementation control inputs and manual output judgments; no checker."""
import base64
import copy
import hashlib
import json
from pathlib import Path
P=Path('/dev/shm/semantic-transport-replay-integration-20261029')
O=P/'revision-02'/'literal-controls'
O.mkdir(exist_ok=False)
FIELDS=('blobs','challenges','claims','dependencies','history','input_manifests','provenance','reading_withdrawals','readings','rules','run_evidence','selectors','sources','tasks','updates')
def C(v):
 return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def H(b):
 return hashlib.sha256(b).hexdigest()
def pin(v):
 raw=C(v);return dict(id=v['id'],bytes=len(raw),sha256=H(raw))
def ck(v):
 p=pin(v);return dict(claim_id=v['id'],revision=v['revision'],bytes=p['bytes'],sha256=p['sha256'])
def read(f):
 return json.loads(f.read_bytes())
def dump(f,v):
 f.write_bytes(C(v))
def base():
 return read(P/'body.json'),read(P/'originals.json')
def seal(b):
 claims={(x['id'],x['revision']):x for x in b['claims']}
 for d in b['dependencies']:
  if d['requires']['kind']=='CLAIM':
   t=d['requires']['claim'];d['requires']['claim']=ck(claims[t['claim_id'],t['revision']])
 for t in b['tasks']:
  for r in t['claim_rosters']:
   q=r['claim'];r['claim']=ck(claims[q['claim_id'],q['revision']]);r['expected_seat_ids'].sort(key=C)
  t['claim_rosters'].sort(key=C)
  for f in ('selected_sources','context_dependency_ids','rule_ids'):t[f].sort(key=C)
 deps={x['id']:x for x in b['dependencies']};selectors={x['id']:x for x in b['selectors']}
 blobs={x['id']:x for x in b['blobs']};tasks={x['id']:x for x in b['tasks']}
 for m in b['input_manifests']:
  q=m['claim'];cl=claims[q['claim_id'],q['revision']];t=tasks[cl['task_view_id']]
  m['task']=pin(t);m['claim']=ck(cl);m['registry_snapshot']=copy.deepcopy(b['registry'])
  m['dependencies']=sorted([pin(deps[i]) for i in set(cl['dependency_ids']+t['context_dependency_ids'])],key=C)
  m['selectors']=sorted([pin(selectors[i]) for i in cl['selector_ids']],key=C)
  m['source_versions']=copy.deepcopy(t['selected_sources'])
 for r in b['readings']:
  q=r['claim'];cl=claims[q['claim_id'],q['revision']]
  m=next(x for x in b['input_manifests'] if (x['claim']['claim_id'],x['claim']['revision'])==(cl['id'],cl['revision']))
  r['claim']=ck(cl);r['input_manifest']=pin(m);r['source_versions']=copy.deepcopy(m['source_versions'])
 for f in FIELDS:b[f].sort(key=(lambda x:(C(x['id']),C(x['revision']))) if f=='claims' else lambda x:C(x['id']))
def cycle(b):
 cl=b['claims'][0];cl['dependency_ids'].append('D_SELF');cl['dependency_ids'].sort(key=C)
 b['dependencies'].append(dict(id='D_SELF',dependent=dict(claim_id=cl['id'],revision=cl['revision']),role='CONTEXT',meaning='DECLARED_REVALIDATION_DEPENDENCY_ONLY',requires=dict(kind='CLAIM',claim=ck(cl))))
def withdrawal(b):
 p=next(x for x in b['provenance'] if x['id']=='READ_PROV')
 b['reading_withdrawals'].append(dict(id='W1',reading_id='R1',reason='Preserved illustrative withdrawal request.',provenance=pin(p),evidence=None,predecessor_withdrawal_id='W1',status='RECORDED_REQUEST_NO_AUTHORITY'))
def replace_source(b,o):
 old=copy.deepcopy(next(x for x in o['items'] if x['alias_id']=='SOURCE')['key'])
 new=dict(logical_source_id=old['logical_source_id'],bytes=1,sha256=H(b'{'))
 todo=[b]
 for unused in range(8192):
  if not todo:break
  v=todo.pop()
  if type(v) is dict:
   for k,x in list(v.items()):
    if x==old:v[k]=copy.deepcopy(new)
    elif type(x) in (dict,list):todo.append(x)
  elif type(v) is list:
   for i,x in enumerate(v):
    if x==old:v[i]=copy.deepcopy(new)
    elif type(x) in (dict,list):todo.append(x)
 else:raise ValueError('preparation traversal bound')
 for x in o['items']:
  if x['alias_id']=='SOURCE':x['key']=copy.deepcopy(new);x['base64']='ew=='
 s=b['selectors'][0];s.update(begin=0,end=1,quote_bytes=1,quote_sha256=new['sha256'],quote_base64='ew==')
def held(rows):
 return dict(outer_type='tuple',items=[dict(item_type='tuple',event_id=x['id'],sha256=H(C(x)),byte_length=len(C(x))) for x in rows])
prior=read(P/'revision-02'/'manual-oracle-recipes.json');rows=[]
for case in prior['cases']:
 b,o=base();name=case['id'];outer=[];identity_overrides=[]
 if name=='F04_BOUNDS_AND_UNKNOWN_RULE':
  b['rules'][0]['kind']='UNKNOWN_RULE'
  n=2+len(b['registry']['seats'])+sum(len(b[f]) for f in FIELDS)+sum(1+len(m['registry_snapshot']['seats']) for m in b['input_manifests'])
  for i in range(97-n):
   b['blobs'].append(dict(id='PAD_'+str(i).zfill(2),kind='PROVENANCE_EVIDENCE',encoding='OPAQUE_BYTES',bytes=0,sha256=H(b''),base64=''))
 if name=='F05_VERSION_AND_RUNTIME':
  b['tasks'][0]['version']='V2';identity_overrides.append(dict(scope='Request',path='/checker/runtime_descriptor/sha256',value='0'*64))
 if name=='F06_REQUEST_PIN_AND_RECORD':
  identity_overrides.extend([dict(scope='held_Request',path='/sha256',value='0'*64),dict(scope='Request.record_pins',remove_id='RESPONSE')])
 if name=='F07_PACKAGE_AND_REFERENCE':
  b['tasks'][0]['registry_id']='ABSENT';identity_overrides.append(dict(scope='Request',path='/package/sha256',value='0'*64))
 if name in ('F08_MISSING_CHECKER_AND_GRAPH','F10_REFERENCE_AND_CYCLE','F12_DAG_AND_DECLARATION'):cycle(b)
 if name=='F08_MISSING_CHECKER_AND_GRAPH':outer.append(dict(operation='make_absent_in_test_copy',path='checker/tools/transport_quorum_replay.py'))
 if name=='F10_REFERENCE_AND_CYCLE':b['tasks'][0]['registry_id']='ABSENT'
 if name in ('F11_HISTORY_AND_WITHDRAWAL_CYCLE','F13_WITHDRAWAL_DAG_AND_COUNT'):withdrawal(b)
 if name=='F11_HISTORY_AND_WITHDRAWAL_CYCLE':
  artifact=copy.deepcopy(next(x for x in b['sources'] if x['id']=='DEF_OLD')['key'])
  b['history'].append(dict(id='H_RETAINED',artifact=artifact,classification='FAILED',kind='RETAINED_RAW_FIRST_OUTPUT',note='Original old bytes retained; no authority.',related_record_ids=['ABSENT']))
 if name=='F12_DAG_AND_DECLARATION':replace_source(b,o)
 if name=='F13_WITHDRAWAL_DAG_AND_COUNT':
  r=copy.deepcopy(b['readings'][0]);r['id']='R2';b['readings'].append(r)
 seal(b)
 if name=='F09_RECORD_PIN_AND_READING':
  b['readings'][0]['provenance']['id']='ABSENT'
  identity_overrides.append(dict(scope='Request.record_pins',id='RESPONSE',path='/sha256',value='0'*64))
 d=O/name;d.mkdir()
 raw=C(b)
 if name=='F03_BAD_UTF8_AND_STALE_PIN':
  raw=b'\xff';identity_overrides.append(dict(scope='held_Request',path='/sha256',value='0'*64))
 (d/'body.json').write_bytes(raw);dump(d/'originals.json',o)
 dump(d/'held-update-pins.json',held(b['updates']))
 dump(d/'held-withdrawal-pins.json',held(b['reading_withdrawals']))
 ids=sorted([dict(id=x['alias_id'],bytes=x['key']['bytes'],sha256=x['key']['sha256']) for x in o['items']]+[dict(id='Q_RECORDS',bytes=len(raw),sha256=H(raw))],key=lambda x:C(x['id']))
 dump(d/'original-source-envelope.json',dict(schema='quorum/original-source-envelope/1',sources=ids))
 dump(d/'expected.json',case['expected'])
 if name=='F14_IMPORT_MISMATCH':
  aux=copy.deepcopy(prior['cases'][0]['expected']);aux['request']=dict(id='REPLAY_REQUEST',bytes=1,sha256='1'*64)
  auxraw=C(aux);(d/'auxiliary-result.json').write_bytes(auxraw)
  key=dict(logical_source_id='IMPORTED_RESULT',sha256=H(auxraw),bytes=len(auxraw))
  dump(d/'auxiliary-input.json',dict(alias_id='IMPORTED_RESULT',key=key,data_type='bytes',base64=base64.b64encode(auxraw).decode()))
 if name=='F15_IGNORED_CLAIMED_VERDICT':
  (d/'auxiliary-result.json').write_bytes(b'ignored')
  key=dict(logical_source_id='IMPORTED_RESULT',sha256=H(b'ignored'),bytes=7)
  dump(d/'auxiliary-input.json',dict(alias_id='IMPORTED_RESULT',key=key,data_type='bytes',base64='aWdub3JlZA=='))
 dump(d/'materialization.json',dict(schema='quorum/replay-literal-materialization/2',body_and_originals='EXACT_LITERAL_COMPLETE',held_events='EXACT_LITERAL_COMPLETE',identity_overrides_after_mechanical_pin_derivation=identity_overrides,outer_host_mutations=outer,receipt_validate_import=name=='F14_IMPORT_MISMATCH',claimed_verdict='UNTRUSTED_DIFFERENT_VERDICT' if name=='F15_IGNORED_CLAIMED_VERDICT' else None,remaining='Only actual source-frozen checker/runtime/Request/package identities and exact request-pin substitution in expected remain approved mechanical derivation; no semantic records omitted. Transport archive encoding of these literal original sets occurs only after explicit admission and qualified adapter setup.'))
 files=[]
 for f in sorted(d.iterdir()):
  z=f.read_bytes();files.append(dict(path=str(f),bytes=len(z),sha256=H(z)))
 rows.append(dict(id=name,files=files))
dump(O/'oracle.json',dict(schema='quorum/replay-full-literal-semantic-oracle/2',status='LITERAL_BODY_SOURCE_EVENT_CONTROLS_WITH_MECHANICAL_EXECUTABLE_IDENTITY_PARAMETERS',derivation='All outcomes and multi-fault semantic records authored before implementation. No candidate/product checker imported/executed. Runtime/checker/package/Request identities cannot be fabricated and remain explicit post-sourcefreeze mechanical parameters. Earlier draft omissions preserved.',cases=rows))
print(H((O/'oracle.json').read_bytes()),len((O/'oracle.json').read_bytes()))
