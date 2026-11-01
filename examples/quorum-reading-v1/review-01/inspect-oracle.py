import base64,collections,hashlib,json,pathlib
import jsonschema
R=pathlib.Path('/dev/shm/semantic-transport-reading-20261029');D=R/'review-01';S=pathlib.Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/tools/transport_quorum_body.schema.json');defs=json.loads(S.read_bytes())['$defs']
def can(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def pin(v):return {'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()}
def validate(kind,value):
 errors=list(jsonschema.Draft202012Validator({'$ref':'#/$defs/'+kind,'$defs':defs}).iter_errors(value));assert not errors,[(e.json_path,e.message) for e in errors]
def counts(values):return {stance:values.count(stance) for stance in ('ABSTAIN','DISPUTE','OPPOSE','SUPPORT')}
rows=[]
for case in json.loads((R/'oracle.json').read_bytes())['cases']:
 p=R/case['id'];f={}
 for name,expected in case['files'].items():
  raw=(p/name).read_bytes();assert pin(raw)==expected;f[name]=raw
 b=json.loads(f['body.json']);e=json.loads(f['expected.json']);assert can(b)==f['body.json'];validate('ReplayBody',b)
 for original in json.loads(f['originals.json'])['items']:assert pin(base64.b64decode(original['base64'],validate=True))=={k:original['key'][k] for k in ('bytes','sha256')}
 if e['status']=='ok':
  assert set(e)=={'body_pin','claims','current_authority','declared_model_family_identity','deferred_gates','dynamic_typed_reference_closure','external_record_pin_match','freshness','full_reference_closure','held_withdrawal_pin_match','independent_custody','raw_first_output_provenance','semantic_completeness','source_authentication','stage','status','withdrawals'};assert e['body_pin']==pin(f['body.json']);assert len(can(e))+1<=32768
  actualclaims={(c['id'],c['revision']):c for c in b['claims']};assert [(x['claim']['claim_id'],x['claim']['revision']) for x in e['claims']]==sorted(actualclaims,key=lambda x:(can(x[0]),can(x[1])))
  for entry in e['claims']:
   key=entry['claim'];claim=actualclaims[(key['claim_id'],key['revision'])];assert {k:key[k] for k in ('bytes','sha256')}==pin(can(claim));a=entry['aggregation'];validate('Aggregation',a);reading=[x for x in b['readings'] if x['claim']==key];dispositions=a['readings'];assert [x['reading_id'] for x in dispositions]==[x['id'] for x in sorted(reading,key=lambda x:can(x['id']))]
   byid={x['id']:x for x in reading}
   for x in dispositions:assert x['raw_stance']==byid[x['reading_id']]['stance'] and x['seat_id']==byid[x['reading_id']]['seat_id'];assert x['reason_codes']==sorted(x['reason_codes'],key=can)
   assert a['raw_counts']==counts([x['stance'] for x in reading]);eligible=[x for x in dispositions if x['observation_eligibility']=='ELIGIBLE_MANUAL_FIXTURE_ONLY'];qualified=[x for x in eligible if x['claim_structural_qualification']=='QUALIFIED_STRUCTURE_ONLY'];assert a['eligible_counts']==counts([x['raw_stance'] for x in eligible]);assert a['structurally_qualified_counts']==counts([x['raw_stance'] for x in qualified])
   assert a['raw_dissent_reading_ids']==sorted([x['id'] for x in reading if x['stance'] in ('OPPOSE','DISPUTE')],key=can)
   assert a['ineligible_dissent_reading_ids']==sorted([x['reading_id'] for x in dispositions if x['raw_stance'] in ('OPPOSE','DISPUTE') and x['observation_eligibility']!='ELIGIBLE_MANUAL_FIXTURE_ONLY'],key=can)
   assert a['qualified_dissent_reading_ids']==sorted([x['reading_id'] for x in qualified if x['raw_stance'] in ('OPPOSE','DISPUTE')],key=can)
   assert a['challenge_ids']==sorted([x['id'] for x in b['challenges'] if x['claim']==key],key=can)
   assert a['withdrawal_ids']==sorted([x['id'] for x in b['reading_withdrawals'] if x['reading_id'] in byid],key=can)
   for item in dispositions:assert item['withdrawal_ids']==sorted([x['id'] for x in b['reading_withdrawals'] if x['reading_id']==item['reading_id']],key=can)
   assert a['abstaining_reading_ids']==sorted([x['id'] for x in reading if x['stance']=='ABSTAIN'],key=can)
   expected=next(x['expected_seat_ids'] for x in b['tasks'][0]['claim_rosters'] if x['claim']==key);assert a['expected_seat_ids']==expected;present={x['seat_id'] for x in reading}&set(expected);assert a['present_seat_ids']==sorted(present,key=can);assert a['missing_seat_ids']==sorted(set(expected)-present,key=can)
  assert [x['pin']['id'] for x in e['withdrawals']]==[x['id'] for x in b['reading_withdrawals']]
  for out,event in zip(e['withdrawals'],b['reading_withdrawals']):assert out['pin']=={'id':event['id'],**pin(can(event))};assert out['reading_id']==event['reading_id']
 else:assert set(e)=={'status','stage','error'}
 rows.append({'id':case['id'],'status':'PASS','expected_error':e.get('error')})
report={'schema':'quorum/independent-reading-literal-inspection/1','status':'PASS','method':'Manifest/hash/canonical/source-byte pins, pinned schema shape, complete output shape/pins, exact preserved raw Reading identities/stances, consistency of hand-authored counts with literal expected dispositions, all raw/ineligible/qualified dissent and Challenge/Withdrawal identity retention. Manual dispositions/agreement/phase expectations reviewed separately, not derived from product. No future Reading implementation imported/executed.','oracle_pin':pin((R/'oracle.json').read_bytes()),'contract_pin':pin((R/'contract.json').read_bytes()),'addendum_pin':pin((R/'design-addendum.json').read_bytes()),'cases':rows};p=D/'author-oracle-inspection.json';p.open('xb').write(can(report)+b'\n');print('PASS',len(rows),pin(p.read_bytes()))
