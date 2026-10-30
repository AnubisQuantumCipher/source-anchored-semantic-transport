import base64,hashlib,json,pathlib
import jsonschema
R=pathlib.Path('/dev/shm/semantic-transport-context-bindings-20261029')
S=pathlib.Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/tools/transport_quorum_body.schema.json')
def can(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def pin(v):return {'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()}
def record_pin(v,name=None):return {'id':v['id'] if name is None else name,**pin(can(v))}
def original_items(v):return v['items']
array_record={'blobs':'Blob','challenges':'Challenge','claims':'Claim','dependencies':'Dependency','history':'HistoryEntry','input_manifests':'InputManifest','provenance':'Provenance','reading_withdrawals':'ReadingWithdrawal','readings':'Reading','rules':'RuleSpec','run_evidence':'RunEvidence','selectors':'Selector','sources':'SourceVersion','tasks':'TaskView','updates':'UpdateNotice'}
validator=jsonschema.Draft202012Validator({'$ref':'#/$defs/ReplayBody','$defs':json.loads(S.read_bytes())['$defs']})
rows=[]
for c in json.loads((R/'oracle.json').read_bytes())['cases']:
 d=R/c['id'];checks=[]
 for name,p in c['files'].items():assert pin((d/name).read_bytes())==p
 raw=(d/'body.json').read_bytes();b=json.loads(raw);assert can(b)==raw;checks.append('manifest_hashes_and_canonical_body')
 errors=list(validator.iter_errors(b));assert not errors,[(e.json_path,e.message) for e in errors];checks.append('pinned_closed_JSON_Schema_shape_only')
 o=json.loads((d/'originals.json').read_bytes())
 for v in original_items(o):assert pin(base64.b64decode(v['base64'],validate=True))=={k:v['key'][k] for k in ('bytes','sha256')}
 checks.append('original_byte_pins')
 e=json.loads((d/'expected.json').read_bytes())
 if e['status']=='ok':
  assert set(e)=={'body_pin','current_authority','deferred_gates','external_record_pin_match','freshness','full_reference_closure','independent_inputs','manifests','records','registry','seat_evidence','semantic_completeness','source_authentication','stage','status','task'}
  assert e['body_pin']==pin(raw);assert len(can(e))+1<=32768
  records=[('Registry',b['registry']),('Policy',b['policy'])]+[('Seat',v) for v in b['registry']['seats']]
  for field,kind in array_record.items():records.extend((kind,v) for v in b[field])
  wanted=[]
  for kind,v in records:
   p=record_pin(v,v['id']+':'+v['revision'] if kind=='Claim' else None);wanted.append({'record_type':kind,**p})
  wanted.sort(key=lambda p:can(p['id']));assert e['records']==wanted
  assert e['registry']=={'pin':record_pin(b['registry']),'binding':'MATCH_STATIC_DECLARATIONS_ONLY'}
  assert e['task']=={'pin':record_pin(b['tasks'][0]),'binding':'MATCH_EXACT_TASK_CONTEXT_ONLY'}
  assert e['manifests']==[{'pin':record_pin(v),'claim':v['claim'],'binding':'MATCH_PREASSESSMENT_TYPED_CONTEXT_ONLY'} for v in sorted(b['input_manifests'],key=lambda v:can(v['id']))]
  wanted=[]
  for seat in sorted(b['registry']['seats'],key=lambda v:can(v['id'])):
   source=None if seat['identity_evidence'] is None else seat['identity_evidence']['source']
   wanted.append({'seat_id':seat['id'],'source':source,'typed_binding':'ABSENT' if source is None else 'MATCH_SUPPLIED_ORIGINAL','temporal_origin':'UNKNOWN','authentication':'UNVERIFIED'})
  assert e['seat_evidence']==wanted
  for field in array_record:
   key=(lambda v:(can(v['id']),can(v['revision']))) if field=='claims' else (lambda v:can(v['id']))
   assert b[field]==sorted(b[field],key=key)
  assert b['registry']['seats']==sorted(b['registry']['seats'],key=lambda v:can(v['id']))
  for claim in b['claims']:
   for name in ('dependency_ids','selector_ids','conflict_claims'):assert claim[name]==sorted(claim[name],key=can)
  for task in b['tasks']:
   for name in ('context_dependency_ids','rule_ids','selected_sources','claim_rosters'):assert task[name]==sorted(task[name],key=can)
   for roster in task['claim_rosters']:assert roster['expected_seat_ids']==sorted(roster['expected_seat_ids'],key=can)
  for manifest in b['input_manifests']:
   for name in ('dependencies','rule_specs','selectors','source_versions'):assert manifest[name]==sorted(manifest[name],key=can)
   assert manifest['registry_snapshot']['seats']==sorted(manifest['registry_snapshot']['seats'],key=lambda v:can(v['id']))
  for reading in b['readings']:
   for name in ('challenge_ids','source_versions'):assert reading[name]==sorted(reading[name],key=can)
  assert e['deferred_gates']==sorted(e['deferred_gates'],key=can)
  for field,value in {'current_authority':'NONE','external_record_pin_match':'NOT_EVALUATED','freshness':'UNKNOWN','full_reference_closure':'NOT_EVALUATED','independent_inputs':'UNKNOWN','semantic_completeness':'UNPROVEN','source_authentication':'UNVERIFIED','stage':'CONTEXT_BINDINGS_ONLY'}.items():assert e[field]==value
  checks+=['complete_closed_expected_envelope','exact_local_record_index_pins_no_inline_identity_duplicates','registry_task_manifest_full_pins','seat_evidence_unknown_flags','canonical_C_array_orders','output_byte_cap']
 else:
  assert set(e)=={'status','stage','error'};checks.append('closed_manual_refusal_envelope')
 rows.append({'id':c['id'],'status':'PASS','expected_error':e.get('error'),'checks':checks})
report={'schema':'quorum/independent-context-literal-inspection/1','status':'PASS','oracle_pin':pin((R/'oracle.json').read_bytes()),'contract_pin':pin((R/'contract.json').read_bytes()),'addendum_pin':pin((R/'design-addendum.json').read_bytes()),'schema_pin':pin(S.read_bytes()),'method':'Stdlib literal/hash/canonical/index/order checks plus pinned closed JSON Schema shape validation. Manual error/precedence review separate. No future context checker import/execution, no full binding oracle generation or acceptance.','cases':rows}
p=R/'review-01'/'author-oracle-inspection.json';p.open('x').write(json.dumps(report,sort_keys=True,separators=(',',':'))+'\n');print('PASS',len(rows),pin(p.read_bytes()))
