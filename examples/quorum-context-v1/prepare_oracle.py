"""Manual context dispositions; no product or graph checker imported/run."""
import base64
import copy
import hashlib
import json
from pathlib import Path
OUT=Path('/dev/shm/semantic-transport-context-bindings-20261029')
BASE=Path('/dev/shm/semantic-transport-impact-20261029/I02_REPLACEMENT')
TYPES={'sources':'SourceVersion','rules':'RuleSpec','tasks':'TaskView','claims':'Claim','selectors':'Selector','dependencies':'Dependency','input_manifests':'InputManifest','blobs':'Blob','provenance':'Provenance','run_evidence':'RunEvidence','readings':'Reading','challenges':'Challenge','reading_withdrawals':'ReadingWithdrawal','updates':'UpdateNotice','history':'HistoryEntry'}

def C(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def digest(raw):return hashlib.sha256(raw).hexdigest()
def pin(v):
 raw=C(v);return dict(id=v['id'],sha256=digest(raw),bytes=len(raw))
def ck(v):
 p=pin(v);return dict(claim_id=v['id'],revision=v['revision'],sha256=p['sha256'],bytes=p['bytes'])
def label(v):return v['id'],v['revision']
def pk(v):return C(v['id']),C(v['revision'])
def failure(stage,error):return dict(status='error',stage=stage,error=error)
def seat(name='SEAT_A'):
 return dict(id=name,declared_label='Manually authored context fixture.',origin_kind='MANUAL_DEVELOPMENT_FIXTURE',declared_model_id=None,declared_family_id='MANUAL_FAMILY',identity_evidence=None,identity_assurance='MANUAL_FIXTURE_ONLY')
def blob(name,kind,data,encoding='STRICT_UTF8'):
 return dict(id=name,kind=kind,encoding=encoding,bytes=len(data),sha256=digest(data),base64=base64.b64encode(data).decode())

def normalize(b):
 for field,kind in TYPES.items():b[field].sort(key=pk if kind=='Claim' else lambda r:C(r['id']))
 b['registry']['seats'].sort(key=lambda r:C(r['id']))
 for c in b['claims']:
  for name in ('dependency_ids','selector_ids','conflict_claims'):c[name].sort(key=C)
 for t in b['tasks']:
  for name in ('context_dependency_ids','rule_ids','selected_sources','claim_rosters'):t[name].sort(key=C)
  for r in t['claim_rosters']:r['expected_seat_ids'].sort(key=C)
  t['claim_rosters'].sort(key=C)
 for m in b['input_manifests']:
  m['registry_snapshot']['seats'].sort(key=lambda r:C(r['id']))
  for name in ('dependencies','rule_specs','selectors','source_versions'):m[name].sort(key=C)
 for r in b['readings']:
  for name in ('source_versions','challenge_ids'):r[name].sort(key=C)

def manifest(b,c,name='MANIFEST'):
 t=b['tasks'][0];deps={d['id']:d for d in b['dependencies']};sels={s['id']:s for s in b['selectors']};blobs={x['id']:x for x in b['blobs']}
 return dict(id=name,schema='quorum/preassessment-input/1',task=pin(t),claim=ck(c),source_versions=copy.deepcopy(t['selected_sources']),selectors=sorted([pin(sels[n]) for n in c['selector_ids']],key=C),dependencies=sorted([pin(deps[n]) for n in set(c['dependency_ids'])|set(t['context_dependency_ids'])],key=C),registry_snapshot=copy.deepcopy(b['registry']),rule_specs=sorted([pin(r) for r in b['rules']],key=C),policy=pin(b['policy']),prompt=pin(blobs['PROMPT']),settings=pin(blobs['SETTINGS']))

def refresh(b):
 normalize(b);t=b['tasks'][0]
 seats={ (r['claim']['claim_id'],r['claim']['revision']):r['expected_seat_ids'] for r in t['claim_rosters'] }
 t['claim_rosters']=[dict(claim=ck(c),expected_seat_ids=copy.deepcopy(seats.get(label(c),['SEAT_A']))) for c in b['claims']]
 t['selected_sources']=sorted({C(r['key']):r['key'] for r in b['sources']}.values(),key=C)
 normalize(b);old=b['input_manifests'];b['input_manifests']=[]
 bylabel={label(c):c for c in b['claims']}
 for m in old:
  target=(m['claim']['claim_id'],m['claim']['revision']);c=bylabel.get(target,b['claims'][0]);b['input_manifests'].append(manifest(b,c,m['id']))
 normalize(b)

def base():
 b=json.loads((BASE/'body.json').read_bytes());o=json.loads((BASE/'originals.json').read_bytes());h=json.loads((BASE/'held-update-pins.json').read_bytes())
 b['registry']['seats']=[seat()];b['blobs']=[blob('PROMPT','PROMPT',b'Manual context prompt.'),blob('SETTINGS','SETTINGS',b'{}','CANONICAL_JSON')]
 b['tasks'][0]['context_dependency_ids']=[];b['tasks'][0]['claim_rosters'][0]['expected_seat_ids']=['SEAT_A']
 refresh(b);b['input_manifests']=[manifest(b,b['claims'][0])];normalize(b);return b,o,h

def rename_claim(b,c,name,revision='V1'):
 old=label(c);c['id']=name;c['revision']=revision
 for d in b['dependencies']:
  if (d['dependent']['claim_id'],d['dependent']['revision'])==old:d['dependent']=dict(claim_id=name,revision=revision)

def child(b,name,revision='V1'):
 c=copy.deepcopy(b['claims'][0]);c['id']=name;c['revision']=revision;c['dependency_ids']=['P_'+name];c['conflict_claims']=[];b['claims'].append(c)
 b['dependencies'].append(dict(id='P_'+name,dependent=dict(claim_id=name,revision=revision),requires=dict(kind='SOURCE',source=copy.deepcopy(b['selectors'][0]['source'])),role='SOURCE',meaning='DECLARED_REVALIDATION_DEPENDENCY_ONLY'))
 return c

def original(b,o,name,logical,data):
 k=dict(logical_source_id=logical,bytes=len(data),sha256=digest(data))
 b['sources'].append(dict(id=name,key=copy.deepcopy(k),media_type='application/octet-stream',origin_kind='MANUAL_DEVELOPMENT_FIXTURE',issuer_claim_id=None,authentication='UNVERIFIED'))
 o['items'].append(dict(item_type='tuple',alias_id=name,key=copy.deepcopy(k),data_type='bytes',base64=base64.b64encode(data).decode()));o['items'].sort(key=lambda x:x['alias_id']);return k

def expected(b,raw):
 records=[]
 for typ,rows in [('Registry',[b['registry']]),('Seat',b['registry']['seats']),('Policy',[b['policy']])]+[(TYPES[n],b[n]) for n in TYPES]:
  for v in rows:
   p=pin(v)
   if typ=='Claim':p['id']=v['id']+':'+v['revision']
   records.append(dict(p,record_type=typ))
 evidence=[]
 for s in b['registry']['seats']:
  source=None if s['identity_evidence'] is None else s['identity_evidence']['source']
  evidence.append(dict(seat_id=s['id'],source=copy.deepcopy(source),typed_binding='ABSENT' if source is None else 'MATCH_SUPPLIED_ORIGINAL',temporal_origin='UNKNOWN',authentication='UNVERIFIED'))
 return dict(status='ok',stage='CONTEXT_BINDINGS_ONLY',body_pin=dict(bytes=len(raw),sha256=digest(raw)),records=sorted(records,key=lambda r:C(r['id'])),task=dict(pin=pin(b['tasks'][0]),binding='MATCH_EXACT_TASK_CONTEXT_ONLY'),registry=dict(pin=pin(b['registry']),binding='MATCH_STATIC_DECLARATIONS_ONLY'),seat_evidence=sorted(evidence,key=lambda r:C(r['seat_id'])),manifests=[dict(pin=pin(m),claim=copy.deepcopy(m['claim']),binding='MATCH_PREASSESSMENT_TYPED_CONTEXT_ONLY') for m in b['input_manifests']],source_authentication='UNVERIFIED',current_authority='NONE',freshness='UNKNOWN',semantic_completeness='UNPROVEN',independent_inputs='UNKNOWN',full_reference_closure='NOT_EVALUATED',external_record_pin_match='NOT_EVALUATED',deferred_gates=['AGGREGATION','BOOTSTRAP_RUNTIME_EXTERNAL_REQUEST','CHALLENGE_WITHDRAWAL','READING_RUN_PROVENANCE'])

def emit(name,b,o,h,reason,error=None):
 raw=C(b);out=expected(b,raw) if error is None else error;folder=OUT/name;folder.mkdir()
 files={'body.json':raw,'originals.json':C(o),'held-update-pins.json':C(h),'expected.json':C(out)}
 for n,data in files.items():(folder/n).write_bytes(data)
 return dict(id=name,rationale=reason,expected_authorship='MANUAL_DISPOSITION_AND_COMPLETE_ENVELOPE_BEFORE_COMPONENT',files={n:dict(bytes=len(data),sha256=digest(data)) for n,data in files.items()})

cases=[]
def success(name,reason,mut=None):
 b,o,h=base()
 if mut is not None:mut(b,o,h)
 cases.append(emit(name,b,o,h,reason))
def refuse(name,stage,code,mut):
 b,o,h=base();mut(b,o,h);cases.append(emit(name,b,o,h,code,error=failure(stage,code)))

success('C01_COMPLETE_BASE','Exact Task, Registry, source set and preassessment manifest; held U remains quarantined upstream.')
success('C02_NO_MANIFEST','No supplied Manifest is allowed absent dynamic coverage gate.',lambda b,o,h:b['input_manifests'].clear())
refuse('C03_NONCLAIM_ID_COLLISION','CONTEXT_IDENTITIES','CONTEXT_ID_DUPLICATE',lambda b,o,h:b['policy'].update(id='REGISTRY'))
refuse('C04_RAW_CLAIM_LABEL_COLLISION','CONTEXT_IDENTITIES','CONTEXT_CLAIM_LABEL_COLLISION',lambda b,o,h:b['policy'].update(id='CLAIM_A'))
refuse('C05_DERIVED_CLAIM_PIN_COLLISION','CONTEXT_IDENTITIES','CONTEXT_ID_DUPLICATE',lambda b,o,h:b['policy'].update(id='CLAIM_A:V1'))
b,o,h=base();rename_claim(b,b['claims'][0],'A'*32);refresh(b);cases.append(emit('C06_DERIVED_ID_BOUND',b,o,h,'Raw Claim ID admits32 but derived pin ID exceeds32.',failure('CONTEXT_IDENTITIES','CONTEXT_CLAIM_PIN_ID_SHAPE')))
b,o,h=base();rename_claim(b,b['claims'][0],'A:B','C');child(b,'A','B:C');refresh(b);cases.append(emit('C07_COLON_COLLISION',b,o,h,'Distinct Claim labels collapse to same unescaped derived pinID.',failure('CONTEXT_IDENTITIES','CONTEXT_ID_DUPLICATE')))
b,o,h=base();child(b,'CLAIM_A','V2');b['dependencies'][-1]['id']='P_REV2';b['claims'][-1]['dependency_ids']=['P_REV2'];refresh(b);cases.append(emit('C08_DISTINCT_REVISIONS',b,o,h,'One raw Claim label may have distinct exact revisions and unique derived addresses.'))
refuse('C09_RECORD_ARRAY_ORDER','CONTEXT_ARRAY_ORDER','CONTEXT_ARRAY_ORDER',lambda b,o,h:b['rules'].reverse())
refuse('C10_SOURCE_SET_ORDER','CONTEXT_ARRAY_ORDER','CONTEXT_ARRAY_ORDER',lambda b,o,h:b['tasks'][0]['selected_sources'].reverse())
b,o,h=base();b['registry']['seats']=[seat('S\n'),seat('S0')];b['tasks'][0]['claim_rosters'][0]['expected_seat_ids']=['S\n','S0'];refresh(b);cases.append(emit('C11_FINAL_LF_ID_CANONICAL_ORDER',b,o,h,'Admitted finalLF ID survives; C(string) orders S0 before escaped finalLF.'))
b['registry']['seats'].reverse();cases.append(emit('C12_FINAL_LF_RAW_ORDER_REFUSED',b,o,h,'Raw Unicode string order is not canonical UTF8 JSON scalar order.',failure('CONTEXT_ARRAY_ORDER','CONTEXT_ARRAY_ORDER')))
refuse('C13_MANUAL_MODEL_LABEL','CONTEXT_REGISTRY','CONTEXT_SEAT_ORIGIN',lambda b,o,h:b['registry']['seats'][0].update(declared_model_id='Proposed label only'))
refuse('C14_MISSING_SEAT_EVIDENCE','CONTEXT_REGISTRY','CONTEXT_SEAT_EVIDENCE_SOURCE',lambda b,o,h:b['registry']['seats'][0].update(identity_evidence=dict(source=dict(logical_source_id='ABSENT',sha256='0'*64,bytes=0),assertion='Unverified assertion.')))
b,o,h=base();s=b['registry']['seats'][0];s.update(origin_kind='RECORDED_EXTERNAL_ASSESSOR',declared_model_id='Unverified model label',identity_assurance='UNVERIFIED',identity_evidence=dict(source=copy.deepcopy(b['sources'][0]['key']),assertion='Declared identity only.'));refresh(b);cases.append(emit('C15_EXTERNAL_DECLARATION_UNVERIFIED',b,o,h,'Static typed evidence resolves; no actual model/run eligibility is granted.'))
b,o,h=base();k=original(b,o,'OPAQUE_EVENT_BYTES','OPAQUE_IDENTITY_SOURCE',C(b['updates'][0]));b['registry']['seats'][0]['identity_evidence']=dict(source=k,assertion='Opaque exact event-like bytes; temporal origin remains unknown.');refresh(b);cases.append(emit('C16_OPAQUE_SOURCE_TEMPORAL_UNKNOWN',b,o,h,'Original leaf bytes equal event bytes; typed SourceKey resolution cannot prove temporal provenance.'))
refuse('C17_TASK_RULE_SET','CONTEXT_TASK','CONTEXT_TASK_RULE_SET',lambda b,o,h:b['tasks'][0]['rule_ids'].__setitem__(0,'ABSENT'))
refuse('C18_TASK_ROSTER_PIN','CONTEXT_TASK','CONTEXT_TASK_ROSTER_PIN',lambda b,o,h:b['tasks'][0]['claim_rosters'][0]['claim'].update(sha256='0'*64))
refuse('C19_TASK_EXPECTED_SEAT','CONTEXT_TASK','CONTEXT_TASK_ROSTER_SEAT',lambda b,o,h:b['tasks'][0]['claim_rosters'][0].update(expected_seat_ids=['ABSENT']))
refuse('C20_TASK_SOURCE_SET','CONTEXT_TASK','CONTEXT_TASK_SOURCE_SET',lambda b,o,h:b['tasks'][0]['selected_sources'].pop())
b,o,h=base();b['claims'][0]['conflict_claims']=[dict(claim_id='ABSENT',revision='V1')];refresh(b);cases.append(emit('C21_MISSING_CONFLICT_LABEL',b,o,h,'Declared conflict target is actual exact ClaimLabel, never inferred contradiction.',failure('CONTEXT_CLAIM_CONFLICTS','CONTEXT_CLAIM_CONFLICT_MISSING')))
b,o,h=base();b['claims'][0]['conflict_claims']=[dict(claim_id='CLAIM_A',revision='V1')];refresh(b);cases.append(emit('C22_SELF_CONFLICT_LABEL',b,o,h,'Self conflict-label identity is preserved; no invented semantic/self prohibition.'))
refuse('C23_TASK_POSTASSESSMENT_PIN','CONTEXT_TASK_TEXT','CONTEXT_TASK_TEXT_TYPE',lambda b,o,h:b['tasks'][0].update(task_text=pin(b['updates'][0])))
refuse('C24_MANIFEST_SOURCE_SET','CONTEXT_MANIFESTS','CONTEXT_MANIFEST_SOURCE_SET',lambda b,o,h:b['input_manifests'][0]['source_versions'].pop())
refuse('C25_MANIFEST_SELECTOR_SET','CONTEXT_MANIFESTS','CONTEXT_MANIFEST_SELECTOR_SET',lambda b,o,h:b['input_manifests'][0].update(selectors=[pin(b['updates'][0])]))
b,o,h=base();child(b,'CLAIM_Z');b['tasks'][0]['context_dependency_ids']=['P_CLAIM_Z'];refresh(b);cases.append(emit('C26_TASK_CONTEXT_UNION',b,o,h,'Manifest includes own Claim deps plus Task context subset owned by another supplied Claim.'))
b['input_manifests'][0]['dependencies']=[p for p in b['input_manifests'][0]['dependencies'] if p['id']!='P_CLAIM_Z'];cases.append(emit('C27_MISSING_CONTEXT_UNION_MEMBER',b,o,h,'Exact Task context union cannot be omitted from Manifest.',failure('CONTEXT_MANIFESTS','CONTEXT_MANIFEST_DEPENDENCY_SET')))
refuse('C28_REGISTRY_SNAPSHOT','CONTEXT_MANIFESTS','CONTEXT_MANIFEST_REGISTRY',lambda b,o,h:b['input_manifests'][0]['registry_snapshot']['seats'][0].update(declared_label='Changed static declaration.'))
refuse('C29_PROMPT_POSTASSESSMENT_TYPE','CONTEXT_MANIFESTS','CONTEXT_MANIFEST_PROMPT_TYPE',lambda b,o,h:b['input_manifests'][0].update(prompt=pin(b['updates'][0])))
b,o,h=base();p=next(x for x in b['blobs'] if x['id']=='PROMPT');p['kind']='RAW_RESPONSE';b['input_manifests'][0]['prompt']=pin(p);cases.append(emit('C30_PROMPT_RESPONSE_KIND',b,o,h,'Fresh correct full Blob record pin still cannot substitute RAW_RESPONSE for preassessment prompt.',failure('CONTEXT_MANIFESTS','CONTEXT_MANIFEST_PROMPT_KIND')))
b,o,h=base();p=next(x for x in b['blobs'] if x['id']=='PROMPT');p['encoding']='OPAQUE_BYTES';cases.append(emit('C31_STALE_PROMPT_RECORD_PIN',b,o,h,'Unchanged payload with changed encoding invalidates complete Blob record pin.',failure('CONTEXT_MANIFESTS','CONTEXT_MANIFEST_PROMPT_PIN')))
report=dict(schema='quorum/context-literal-oracle/1',contract_pin=dict(bytes=len((OUT/'contract.json').read_bytes()),sha256=digest((OUT/'contract.json').read_bytes())),addendum_pin=dict(bytes=len((OUT/'design-addendum.json').read_bytes()),sha256=digest((OUT/'design-addendum.json').read_bytes())),status='MANUAL_COMPLETE_EXPECTED_ENVELOPES_NO_PRODUCT_RUN',derivation='Dispositions are manual before component code. Generator canonicalizes/hashes actual literal bytes and emits complete exact success index/status envelopes or exact first three-field refusal; no product/source/claim/impact/graph checker imported/run.',cases=cases,omissions='No model/assessor call, runtime proof, external record-pin custody/authentication, deferred dynamic reference qualification, fullReplay acceptance or whole-system assurance. Independent controls separately expand hostile-host/precedence/shape boundaries.')
(OUT/'oracle.json').write_bytes(C(report));print('Prepared',len(cases),'complete manual context envelopes; no product checker run.')
