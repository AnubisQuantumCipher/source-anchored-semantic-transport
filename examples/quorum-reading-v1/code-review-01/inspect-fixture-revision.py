import copy,hashlib,json,pathlib
R=pathlib.Path('/dev/shm/semantic-transport-reading-controls-20261029');D=pathlib.Path('/dev/shm/semantic-transport-reading-20261029/code-review-01')
def can(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def pin(v):return {'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()}
def rp(v):return {'id':v['id'],**pin(can(v))}
a=json.loads((R/'handwritten-expectations.json').read_bytes());b=json.loads((R/'revision-02/handwritten-expectations.json').read_bytes());assert [c['id'] for c in a['cases']]==[c['id'] for c in b['cases']];rows=[]
fields=('blobs','challenges','claims','dependencies','history','input_manifests','provenance','reading_withdrawals','readings','rules','run_evidence','selectors','sources','tasks','updates')
def order(v,key=can):assert v==sorted(v,key=key)
def all_orders(body):
 for f in fields:order(body[f],(lambda v:(can(v['id']),can(v['revision']))) if f=='claims' else (lambda v:can(v['id'])))
 order(body['registry']['seats'],lambda v:can(v['id']))
 for c in body['claims']:
  for f in ('dependency_ids','selector_ids','conflict_claims'):order(c[f])
 for t in body['tasks']:
  for f in ('context_dependency_ids','rule_ids','selected_sources','claim_rosters'):order(t[f])
  for c in t['claim_rosters']:order(c['expected_seat_ids'])
 for m in body['input_manifests']:
  order(m['registry_snapshot']['seats'],lambda v:can(v['id']))
  for f in ('dependencies','rule_specs','selectors','source_versions'):order(m[f])
 for r in body['readings']:
  for f in ('challenge_ids','source_versions'):order(r[f])
for old,new in zip(a['cases'],b['cases']):
 oldraw=pathlib.Path(old['body_raw']['path']).read_bytes();newraw=pathlib.Path(new['body_raw']['path']).read_bytes();assert pin(oldraw)=={k:old['body_raw'][k] for k in ('bytes','sha256')};assert pin(newraw)=={k:new['body_raw'][k] for k in ('bytes','sha256')};body=json.loads(oldraw);after=copy.deepcopy(body);mapping=[]
 for m in after['input_manifests']:
  before=rp(m);m['rule_specs'].sort(key=can);mapping.append((before,rp(m)))
 for f in ('readings','run_evidence'):
  for record in after[f]:
   for oldpin,newpin in mapping:
    if record['input_manifest']==oldpin:record['input_manifest']=copy.deepcopy(newpin);break
 assert can(after)==newraw,'unexpected fixture change '+old['id'];all_orders(after)
 for key in set(old)|set(new):
  if key not in ('body_raw','handwritten_expected_complete_result'):assert old[key]==new[key],(old['id'],key)
 expected=copy.deepcopy(old['handwritten_expected_complete_result'])
 if expected['status']=='ok':expected['body_pin']=pin(newraw)
 assert expected==new['handwritten_expected_complete_result'],'changed manual judgment '+old['id']
 rows.append({'id':old['id'],'status':'PASS','changes':'C-sort Manifest.rule_specs and update only previously exact complete matching Manifest references; success body_pin mechanical only. All other body bytes/recipe/manual metadata/counts/dispositions/statuses unchanged.','all_context_array_orders':'PASS'})
report={'schema':'quorum/independent-reading-fixture-revision-review/1','status':'PASS','old_expectation_pin':pin((R/'handwritten-expectations.json').read_bytes()),'new_expectation_pin':pin((R/'revision-02/handwritten-expectations.json').read_bytes()),'repair_record_pin':pin((R/'revision-02/repair-record.json').read_bytes()),'method':'Independent reconstruction of permitted sort/fullpin-only transformation from original bytes, exact new-byte comparison and exhaustive frozen Context C-array inventory; full manual expectation equality except recomputed success body_pin. No Reading product execution or product-generated oracle.','classification':'DEVELOPMENT_FIXTURE_REPAIR_NOT_PRODUCT_REPAIR_OR_HELDOUT_RESULT','cases':rows,'conclusion':'No unexpected intent/status/count/disposition drift; deliberate incorrect Manifest pins remain unchanged and incorrect. Exact corrected46 may now be executed separately; original failure artifacts/results must remain.'}
p=D/'fixture-revision-review.json';p.open('xb').write(can(report)+b'\n');print('PASS',len(rows),pin(p.read_bytes()))
