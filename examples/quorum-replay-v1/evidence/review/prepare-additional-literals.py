"""Independent manual semantic controls; stdlib only; no product import/run."""
import base64,copy,hashlib,json
from pathlib import Path
P=Path('/dev/shm/semantic-transport-replay-integration-20261029')
B=P/'revision-02/literal-controls/F01_ORIGINAL_ACCEPT'
O=P/'code-review-01/additional-literals'
O.mkdir(exist_ok=False)
FIELDS=('blobs','challenges','claims','dependencies','history','input_manifests','provenance','reading_withdrawals','readings','rules','run_evidence','selectors','sources','tasks','updates')
def C(x):return json.dumps(x,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def H(x):return hashlib.sha256(x).hexdigest()
def read(p):return json.loads(p.read_bytes())
def put(p,x):
 with p.open('xb') as f:f.write(C(x))
def pin(x):return dict(id=x['id'],bytes=len(C(x)),sha256=H(C(x)))
def ck(x):return dict(claim_id=x['id'],revision=x['revision'],bytes=len(C(x)),sha256=H(C(x)))
def walkreplace(root,old,new):
 stack=[root]
 for unused in range(8192):
  if not stack:return
  v=stack.pop()
  if type(v) is dict:
   for k,x in list(v.items()):
    if x==old:v[k]=copy.deepcopy(new)
    elif type(x) in (dict,list):stack.append(x)
  elif type(v) is list:
   for i,x in enumerate(v):
    if x==old:v[i]=copy.deepcopy(new)
    elif type(x) in (dict,list):stack.append(x)
 raise ValueError('preparation bound')
def seal(b):
 claims={(x['id'],x['revision']):x for x in b['claims']}
 for c in b['claims']:
  for n in ('selector_ids','dependency_ids'):c[n].sort(key=C)
 for t in b['tasks']:
  for r in t['claim_rosters']:
   q=r['claim'];r['claim']=ck(claims[q['claim_id'],q['revision']])
   r['expected_seat_ids'].sort(key=C)
  t['claim_rosters'].sort(key=C)
  for n in ('selected_sources','context_dependency_ids','rule_ids'):t[n].sort(key=C)
 deps={x['id']:x for x in b['dependencies']};sels={x['id']:x for x in b['selectors']};tasks={x['id']:x for x in b['tasks']}
 for m in b['input_manifests']:
  q=m['claim'];cl=claims[q['claim_id'],q['revision']];t=tasks[cl['task_view_id']]
  m['claim']=ck(cl);m['task']=pin(t)
  m['dependencies']=sorted([pin(deps[n]) for n in set(cl['dependency_ids']+t['context_dependency_ids'])],key=C)
  m['selectors']=sorted([pin(sels[n]) for n in cl['selector_ids']],key=C)
  m['source_versions']=copy.deepcopy(t['selected_sources'])
  m['registry_snapshot']=copy.deepcopy(b['registry'])
 for f in FIELDS:b[f].sort(key=(lambda x:(C(x['id']),C(x['revision']))) if f=='claims' else lambda x:C(x['id']))
 readers(b)
def readers(b):
 for r in b['readings']:
  q=r['claim'];c=next(c for c in b['claims'] if (c['id'],c['revision'])==(q['claim_id'],q['revision']))
  m=next(m for m in b['input_manifests'] if (m['claim']['claim_id'],m['claim']['revision'])==(c['id'],c['revision']))
  r['claim']=ck(c);r['input_manifest']=pin(m);r['source_versions']=copy.deepcopy(m['source_versions'])
def refusal(stage,replay,reason,targets=None,parents=None,held=True):
 return dict(schema='quorum/replay-refusal/1',accepted_result=False,replay=replay,input_request={'$mechanical':'exact REPLAY_REQUEST Pin after source-bound Request canonical materialization'} if held else None,failed_stage=stage,reasons=[dict(code=reason,detail='',record_ids=[])],missing_target_keys=targets or [],missing_predecessor_ids=parents or [],dimension_status='NOT_EVALUATED',diagnostic_result=None,diagnostic_result_accepted=False,previous_receipt=None,authority='NONE',freshness='UNKNOWN')
def held(rows):return dict(outer_type='tuple',items=[dict(item_type='tuple',event_id=r['id'],sha256=H(C(r)),byte_length=len(C(r))) for r in rows])
rows=[]
for name in ('P01_REQUEST_PIN_CANONICAL','P02_EMPTY_SOURCE','P03_MISSING_CLAIM','P04_MISSING_SOURCE','P05_READING_PARENT_BEFORE_UPDATE','P06_DEP_BEFORE_POSITIONAL','P07_FINAL_LF_SET_ORDER','P08_AUXILIARY_LOWERCASE'):
 b,o=read(B/'body.json'),read(B/'originals.json');expected=read(B/'expected.json');overrides=[];body_suffix=b'';extra={}
 if name=='P01_REQUEST_PIN_CANONICAL':
  body_suffix=b'\n';overrides=[dict(scope='held_Request',path='/sha256',value='0'*64)]
  expected=refusal('IDENTITY','REFUSED_INPUT_INTEGRITY','REQUEST_PIN',held=False)
 if name=='P02_EMPTY_SOURCE':
  old=copy.deepcopy(next(s for s in b['sources'] if s['id']=='SOURCE')['key'])
  new=dict(logical_source_id='RULE_TEXT',bytes=0,sha256=H(b''));walkreplace(b,old,new)
  row=next(r for r in o['items'] if r['alias_id']=='SOURCE');row['key']=new;row['base64']=''
  b['selectors'][0].update(begin=0,end=0,quote_base64='',quote_bytes=0,quote_sha256=H(b''))
  ent=expected['claims'][0];ent['interpretation']='UNRESOLVED_INSUFFICIENT_SCOPE'
  agg=ent['aggregation'];agg['readings'][0]['claim_structural_qualification']='UNQUALIFIED_INSUFFICIENT_SCOPE'
  agg['structurally_qualified_counts']['SUPPORT']=0;agg['qualified_stance_agreement']='NO_DECISIVE_READINGS'
 if name=='P03_MISSING_CLAIM':
  target=dict(claim_id='ABSENT',revision='V1',bytes=1,sha256='0'*64)
  dep=dict(id='D_MISSING',dependent=dict(claim_id='CLAIM_A',revision='V1'),requires=dict(kind='CLAIM',claim=target),role='CONTEXT',meaning='DECLARED_REVALIDATION_DEPENDENCY_ONLY')
  b['dependencies'].append(dep);b['claims'][0]['dependency_ids'].append('D_MISSING')
  expected=refusal('IDENTITY','REFUSED_MISSING_DEPENDENCY','MISSING_TARGET',[dict(kind='CLAIM',claim=target)])
 if name=='P04_MISSING_SOURCE':
  target=dict(logical_source_id='ABSENT',bytes=1,sha256='0'*64)
  b['claims'][0]['payload']['statement']['condition']['nodes']=[dict(op='REF',target=target)]
  expected=refusal('IDENTITY','REFUSED_MISSING_DEPENDENCY','MISSING_TARGET',[dict(kind='SOURCE',source=target)])
 if name=='P05_READING_PARENT_BEFORE_UPDATE':
  p=next(x for x in b['provenance'] if x['id']=='READ_PROV')
  b['reading_withdrawals']=[dict(id='W1',reading_id='R1',reason='Manual predecessor priority control.',provenance=pin(p),evidence=None,predecessor_withdrawal_id='ABSENT',status='RECORDED_REQUEST_NO_AUTHORITY')]
  b['updates'][0]['logical_source_id']='WRONG'
  expected=refusal('REFERENCES','REFUSED_MISSING_DEPENDENCY','MISSING_PREDECESSOR',parents=['ABSENT'])
 if name=='P06_DEP_BEFORE_POSITIONAL':
  target=copy.deepcopy(next(s for s in b['sources'] if s['id']=='DEF_OLD')['key'])
  b['claims'][0]['payload']['statement']['condition']['nodes']=[dict(op='REF',target=target)]
  d=copy.deepcopy(b['dependencies'][1]);d['id']='D_UNUSED';d['requires']['source']=copy.deepcopy(next(s for s in b['sources'] if s['id']=='DEF_NEW')['key'])
  b['dependencies'].append(d)
  expected=refusal('REFERENCES','REFUSED_REFERENCE_INCONSISTENCY','DEPENDENCY_REFERENCE')
 if name=='P07_FINAL_LF_SET_ORDER':
  a=b['updates'][0];a['id']='A-';z=copy.deepcopy(a);z.update(id='A\n',kind='WITHDRAWAL',new_version=None);b['updates'].append(z)
  expected['quarantined_update_ids']=['A-','A\n'];expected['conflicting_update_ids']=['A-','A\n']
  ent=expected['claims'][0];ent['declared_preconditions']='CONFLICT';ent['trigger_update_ids']=['A-','A\n']
  oldpath=ent['impact_paths'][0];ent['impact_paths']=[dict(copy.deepcopy(oldpath),trigger_update_id='A\n'),dict(copy.deepcopy(oldpath),trigger_update_id='A-')]
 if name=='P08_AUXILIARY_LOWERCASE':
  extra['auxiliary-result.json']=b'ignored'
  extra['auxiliary-input.json']=dict(alias_id='result_old',key=dict(logical_source_id='IMPORTED_RESULT',bytes=7,sha256=H(b'ignored')),data_type='bytes',base64='aWdub3JlZA==')
 seal(b)
 if expected.get('accepted_result'):
  k=ck(b['claims'][0]);expected['claims'][0]['claim']=k
  for q in expected['claims'][0]['impact_paths']:q['affected_claim']=copy.deepcopy(k)
 raw=C(b)+body_suffix;d=O/name;d.mkdir()
 with (d/'body.json').open('xb') as f:f.write(raw)
 for n,x in [('originals.json',o),('expected.json',expected),('held-update-pins.json',held(b['updates'])),('held-withdrawal-pins.json',held(b['reading_withdrawals']))]:put(d/n,x)
 ids=[dict(id=r['alias_id'],bytes=r['key']['bytes'],sha256=r['key']['sha256']) for r in o['items']]+[dict(id='Q_RECORDS',bytes=len(raw),sha256=H(raw))]
 put(d/'original-source-envelope.json',dict(schema='quorum/original-source-envelope/1',sources=sorted(ids,key=lambda r:C(r['id']))))
 put(d/'materialization.json',dict(schema='quorum/replay-literal-materialization/2',body_and_originals='EXACT_LITERAL_COMPLETE',held_events='EXACT_LITERAL_COMPLETE',identity_overrides_after_mechanical_pin_derivation=overrides,outer_host_mutations=[],receipt_validate_import=False,claimed_verdict='UNTRUSTED_DIFFERENT_VERDICT' if name=='P08_AUXILIARY_LOWERCASE' else None,remaining='Only actual source-frozen checker/runtime/Request/package identities and exact request-pin substitution in expected remain approved mechanical derivation; no outcome-derived judgments.'))
 for n,x in extra.items():
  if type(x) is bytes:
   with (d/n).open('xb') as f:f.write(x)
  else:put(d/n,x)
 files=[]
 for f in sorted(d.iterdir()):z=f.read_bytes();files.append(dict(path=str(f),bytes=len(z),sha256=H(z)))
 rows.append(dict(id=name,files=files))
put(O/'oracle.json',dict(schema='quorum/replay-independent-additional-oracle/1',status='MANUAL_EXPECTED_VALUES_BEFORE_ANY_NEW_PRODUCT_EXECUTION',reviewer='actual GPT-6.1',base_semantics='F01_ORIGINAL_ACCEPT',cases=rows,scope='Pure replay controls. Full success expected request pins are explicit mechanical templates. No checker imported or executed. Keep semantic dependency path sequence/order from frozen component; only set-valued IDs use canonical UTF8 order.'))
print(H((O/'oracle.json').read_bytes()))
