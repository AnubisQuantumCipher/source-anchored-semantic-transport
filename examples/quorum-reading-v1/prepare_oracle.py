"""Literal Reading dispositions/counts hand-designated; no checker imported."""
import base64,copy,hashlib,json
from pathlib import Path
OUT=Path('/dev/shm/semantic-transport-reading-20261029');BASE=Path('/dev/shm/semantic-transport-context-bindings-20261029/C01_COMPLETE_BASE')
FIELDS=('blobs','challenges','claims','dependencies','history','input_manifests','provenance','reading_withdrawals','readings','rules','run_evidence','selectors','sources','tasks','updates')
def C(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def H(b):return hashlib.sha256(b).hexdigest()
def pin(v):
 b=C(v);return dict(id=v['id'],sha256=H(b),bytes=len(b))
def ck(v):
 p=pin(v);return dict(claim_id=v['id'],revision=v['revision'],sha256=p['sha256'],bytes=p['bytes'])
def blob(name,kind,data):return dict(id=name,kind=kind,encoding='STRICT_UTF8',bytes=len(data),sha256=H(data),base64=base64.b64encode(data).decode())
def prov(name='READ_PROV',author='Manual reading author.',external=False,run=None):return dict(id=name,origin_kind='RECORDED_EXTERNAL_ASSESSOR' if external else 'MANUAL_DEVELOPMENT_FIXTURE',author_claim=author,method='RECORDED_UNVERIFIED_EXTERNAL_RUN' if external else 'MANUALLY_AUTHORED_ILLUSTRATION',run_evidence_id=run,evidence=None,limitations='Unverified declared illustration only.',authentication='UNVERIFIED')
def seat(name,external=False):return dict(id=name,declared_label='Declared fixture Seat.',origin_kind='RECORDED_EXTERNAL_ASSESSOR' if external else 'MANUAL_DEVELOPMENT_FIXTURE',declared_model_id='Unverified static model' if external else None,declared_family_id='STATIC_FAMILY',identity_evidence=None,identity_assurance='UNVERIFIED' if external else 'MANUAL_FIXTURE_ONLY')
def sortbody(b):
 for f in FIELDS:b[f].sort(key=(lambda r:(C(r['id']),C(r['revision']))) if f=='claims' else lambda r:C(r['id']))
 b['registry']['seats'].sort(key=lambda r:C(r['id']))
 for t in b['tasks']:
  for r in t['claim_rosters']:r['expected_seat_ids'].sort(key=C)
  for f in ('claim_rosters','selected_sources','context_dependency_ids','rule_ids'):t[f].sort(key=C)
 for m in b['input_manifests']:
  m['registry_snapshot']['seats'].sort(key=lambda r:C(r['id']))
  for f in ('dependencies','selectors','rule_specs','source_versions'):m[f].sort(key=C)
 for r in b['readings']:
  for f in ('source_versions','challenge_ids'):r[f].sort(key=C)

def reseal(b):
 t=b['tasks'][0];t['claim_rosters'][0]['claim']=ck(b['claims'][0]);sortbody(b)
 for m in b['input_manifests']:
  m['task']=pin(t);m['claim']=ck(b['claims'][0]);m['registry_snapshot']=copy.deepcopy(b['registry'])
 sortbody(b)

def base(expected=('SEAT_A',),extra=()):
 b=json.loads((BASE/'body.json').read_bytes());o=json.loads((BASE/'originals.json').read_bytes());held=json.loads((BASE/'held-update-pins.json').read_bytes())
 b['registry']['seats']=[seat('SEAT_A')]+[seat(n,e) for n,e in extra];b['tasks'][0]['claim_rosters'][0]['expected_seat_ids']=list(expected)
 b['provenance'].append(prov());b['blobs'].append(blob('RESPONSE','RAW_RESPONSE',b'Preserved manual first-output claim.'));reseal(b);return b,o,held

def reading(b,name='R1',seatid='SEAT_A',stance='SUPPORT',external=False,provenance='READ_PROV'):
 m=b['input_manifests'][0];p=next(p for p in b['provenance'] if p['id']==provenance);response=next(x for x in b['blobs'] if x['id']=='RESPONSE')
 r=dict(id=name,seat_id=seatid,claim=copy.deepcopy(m['claim']),task_view_id=b['tasks'][0]['id'],source_versions=copy.deepcopy(m['source_versions']),input_manifest=pin(m),prompt=copy.deepcopy(m['prompt']),settings=copy.deepcopy(m['settings']),response=pin(response),provenance=pin(p),stance=stance,challenge_ids=[],origin_kind='RECORDED_EXTERNAL_ASSESSOR' if external else 'MANUAL_DEVELOPMENT_FIXTURE');b['readings'].append(r);sortbody(b);return r

def withdraw(b,name='W1',target='R1',provenance='READ_PROV',predecessor=None):
 p=next(p for p in b['provenance'] if p['id']==provenance);w=dict(id=name,reading_id=target,reason='Preserved illustrative withdrawal request.',provenance=pin(p),evidence=None,predecessor_withdrawal_id=predecessor,status='RECORDED_REQUEST_NO_AUTHORITY');b['reading_withdrawals'].append(w);sortbody(b);return w

def challenge(b,name='CH1',target=None,seatid=None):
 ch=dict(id=name,claim=ck(b['claims'][0]),reading_id=target,seat_id=seatid,kind='OTHER',reason='Preserved unresolved challenge.',evidence=None,provenance=pin(next(p for p in b['provenance'] if p['id']=='READ_PROV')),status='UNRESOLVED_INFORMATIONAL');b['challenges'].append(ch);sortbody(b);return ch

def external(b):
 m=b['input_manifests'][0];response=next(x for x in b['blobs'] if x['id']=='RESPONSE')
 run=dict(id='RUN1',seat_id='SEAT_E',input_manifest=pin(m),provider_claim='Unverified provider claim',model_id_claim='Different declared run model',family_id_claim='OTHER_FAMILY',provider_run_id_claim=None,prompt=copy.deepcopy(m['prompt']),settings=copy.deepcopy(m['settings']),response=pin(response),raw_run_evidence=None,externally_pinned_eligibility_policy=copy.deepcopy(b['sources'][0]['key']),asserted_utc=None,verification='UNVERIFIED',independent_inputs='UNKNOWN');b['run_evidence'].append(run);b['provenance'].append(prov('EXT_PROV',external=True,run='RUN1'));sortbody(b);return run

def counts(s=0,o=0,a=0,d=0):return dict(SUPPORT=s,OPPOSE=o,ABSTAIN=a,DISPUTE=d)
def rd(name,seatid,stance,elig='ELIGIBLE_MANUAL_FIXTURE_ONLY',qual='QUALIFIED_STRUCTURE_ONLY',withdrawals=(),reasons=None):return dict(reading_id=name,seat_id=seatid,observation_eligibility=elig,claim_structural_qualification=qual,raw_stance=stance,withdrawal_ids=list(withdrawals),reason_codes=sorted([elig] if reasons is None else reasons,key=C))
def aggregation(expected=('SEAT_A',),present=(),raw=None,eligible=None,qualified=None,rows=(),agreement='NO_DECISIVE_READINGS',qagreement=None,abstain=(),dissent=(),ineligible_dissent=(),qualified_dissent=(),challenges=(),withdrawals=(),duplicates=(),origin='MANUAL_FIXTURES_ONLY'):
 return dict(observation_class=origin,expected_seat_ids=sorted(expected,key=C),present_seat_ids=sorted(present,key=C),missing_seat_ids=sorted(set(expected)-set(present),key=C),raw_counts=raw or counts(),eligible_counts=eligible or counts(),structurally_qualified_counts=qualified or counts(),eligible_stance_agreement=agreement,qualified_stance_agreement=agreement if qagreement is None else qagreement,abstaining_reading_ids=list(abstain),raw_dissent_reading_ids=list(dissent),ineligible_dissent_reading_ids=list(ineligible_dissent),qualified_dissent_reading_ids=list(qualified_dissent),challenge_ids=list(challenges),withdrawal_ids=list(withdrawals),conflicting_duplicate_reading_ids=list(duplicates),readings=list(rows),threshold_verdict='NOT_DEFINED')
def result(b,raw,agg,effects):return dict(status='ok',stage='READING_CLOSURE_AGGREGATION_ONLY',body_pin=dict(bytes=len(raw),sha256=H(raw)),claims=[dict(claim=ck(b['claims'][0]),aggregation=agg)],withdrawals=[dict(pin=pin(w),reading_id=w['reading_id'],manual_count_effect=effects[w['id']]) for w in b['reading_withdrawals']],held_withdrawal_pin_match='MATCH',independent_custody='UNKNOWN',dynamic_typed_reference_closure='MATCH_READING_SCOPE_ONLY',declared_model_family_identity='NOT_VALIDATED',raw_first_output_provenance='UNVERIFIED',source_authentication='UNVERIFIED',current_authority='NONE',freshness='UNKNOWN',semantic_completeness='UNPROVEN',external_record_pin_match='NOT_EVALUATED',full_reference_closure='NOT_EVALUATED',deferred_gates=['BOOTSTRAP_RUNTIME_EXTERNAL_REQUEST','FULL_TYPED_DIGEST_GRAPH_AND_EXTERNAL_PINS','HISTORY_RELATED_ROLE_CLOSURE','IMPORT_COMPARISON_FULL_REPLAY_ORDER'])
def fail(stage,code):return dict(status='error',stage=stage,error=code)
def emit(name,b,o,h,why,agg=None,effects=None,error=None,held_mut=None):
 sortbody(b);raw=C(b);held=dict(outer_type='tuple',items=[dict(item_type='tuple',event_id=w['id'],sha256=pin(w)['sha256'],byte_length=pin(w)['bytes']) for w in b['reading_withdrawals']])
 if held_mut is not None:held_mut(held)
 expected=error if error is not None else result(b,raw,agg,effects or {})
 d=OUT/name;d.mkdir();files={'body.json':raw,'originals.json':C(o),'held-update-pins.json':C(h),'held-withdrawal-pins.json':C(held),'expected.json':C(expected)}
 for n,data in files.items():(d/n).write_bytes(data)
 return dict(id=name,rationale=why,expected_authorship='MANUAL_COUNTS_DISPOSITIONS_BEFORE_IMPLEMENTATION',files={n:dict(bytes=len(data),sha256=H(data)) for n,data in files.items()})
cases=[]
b,o,h=base();cases.append(emit('R01_NO_READINGS',b,o,h,'Expected Seat stays missing, explicit no observations.',agg=aggregation(origin='NO_RECORDED_READINGS')))
b,o,h=base();reading(b);cases.append(emit('R02_MANUAL_SUPPORT',b,o,h,'One qualified manual observation; no actual model run.',agg=aggregation(present=['SEAT_A'],raw=counts(1),eligible=counts(1),qualified=counts(1),rows=[rd('R1','SEAT_A','SUPPORT')],agreement='SINGLE_DECISIVE_READING')))
b,o,h=base(expected=('SEAT_A','SEAT_B'),extra=(('SEAT_B',False),));reading(b);reading(b,'R2','SEAT_B','OPPOSE');challenge(b);cases.append(emit('R03_DISSENT_UNLISTED_CHALLENGE',b,o,h,'Unlisted unresolved Claim challenge and opposing qualified dissent survive.',agg=aggregation(expected=['SEAT_A','SEAT_B'],present=['SEAT_A','SEAT_B'],raw=counts(1,1),eligible=counts(1,1),qualified=counts(1,1),rows=[rd('R1','SEAT_A','SUPPORT'),rd('R2','SEAT_B','OPPOSE')],agreement='RECORDED_DISAGREEMENT',dissent=['R2'],qualified_dissent=['R2'],challenges=['CH1'])))
b,o,h=base();reading(b,stance='ABSTAIN');cases.append(emit('R04_ABSTAIN_PRESENT',b,o,h,'ABSTAIN counts raw/eligible, marks Seat present, no decisive agreement.',agg=aggregation(present=['SEAT_A'],raw=counts(a=1),eligible=counts(a=1),qualified=counts(a=1),rows=[rd('R1','SEAT_A','ABSTAIN')],abstain=['R1'])))
b,o,h=base();reading(b,stance='OPPOSE');withdraw(b);cases.append(emit('R05_MANUAL_WITHDRAWAL',b,o,h,'Manual author text match excludes illustration count only; raw dissent remains.',effects={'W1':'EXCLUDES_MANUAL_FIXTURE'},agg=aggregation(present=['SEAT_A'],raw=counts(o=1),rows=[rd('R1','SEAT_A','OPPOSE','INELIGIBLE_WITHDRAWN',withdrawals=['W1'])],dissent=['R1'],ineligible_dissent=['R1'],withdrawals=['W1'])))
b,o,h=base();reading(b,stance='OPPOSE');reading(b,'R2',stance='SUPPORT');withdraw(b);cases.append(emit('R06_DUPLICATE_BEFORE_WITHDRAWN',b,o,h,'All duplicate records count raw; duplicate priority retains withdrawn reason too.',effects={'W1':'EXCLUDES_MANUAL_FIXTURE'},agg=aggregation(present=['SEAT_A'],raw=counts(1,1),rows=[rd('R1','SEAT_A','OPPOSE','INELIGIBLE_DUPLICATE_SEAT',withdrawals=['W1'],reasons=['INELIGIBLE_DUPLICATE_SEAT','INELIGIBLE_WITHDRAWN']),rd('R2','SEAT_A','SUPPORT','INELIGIBLE_DUPLICATE_SEAT')],dissent=['R1'],ineligible_dissent=['R1'],withdrawals=['W1'],duplicates=['R1','R2'])))
b,o,h=base(extra=(('SEAT_C',False),));reading(b,seatid='SEAT_C',stance='DISPUTE');cases.append(emit('R07_UNEXPECTED_REGISTERED_SEAT',b,o,h,'Registered unexpected dispute preserves dissent and does not satisfy expected Seat.',agg=aggregation(raw=counts(d=1),rows=[rd('R1','SEAT_C','DISPUTE','INELIGIBLE_NOT_EXPECTED_SEAT')],dissent=['R1'],ineligible_dissent=['R1'])))
b,o,h=base(expected=('SEAT_E',),extra=(('SEAT_E',True),));external(b);reading(b,seatid='SEAT_E',stance='DISPUTE',external=True,provenance='EXT_PROV');cases.append(emit('R08_EXTERNAL_DECLARED_POLICY',b,o,h,'Different model/family labels and supplied policy are unverified; external remains ineligible.',agg=aggregation(expected=['SEAT_E'],present=['SEAT_E'],raw=counts(d=1),rows=[rd('R1','SEAT_E','DISPUTE','INELIGIBLE_UNVERIFIED')],dissent=['R1'],ineligible_dissent=['R1'],origin='UNVERIFIED_EXTERNAL_RECORDS_ONLY')))
b,o,h=base(expected=('SEAT_A','SEAT_B'),extra=(('SEAT_B',False),));b['claims'][0]['payload']=dict(profile='OPAQUE_PROSE_V1',text='Opaque declared prose.',uncertainty='No natural-language extraction.',omitted_scope='');reseal(b);reading(b);reading(b,'R2','SEAT_B');cases.append(emit('R09_OPAQUE_AGREEMENT_UNQUALIFIED',b,o,h,'Eligible agreement does not create structural qualification.',agg=aggregation(expected=['SEAT_A','SEAT_B'],present=['SEAT_A','SEAT_B'],raw=counts(2),eligible=counts(2),rows=[rd('R1','SEAT_A','SUPPORT',qual='UNQUALIFIED_UNSUPPORTED'),rd('R2','SEAT_B','SUPPORT',qual='UNQUALIFIED_UNSUPPORTED')],agreement='RECORDED_AGREEMENT',qagreement='NO_DECISIVE_READINGS')))
b,o,h=base();reading(b);b['provenance'].append(prov('OTHER_PROV',author='Different declared author.'));withdraw(b,provenance='OTHER_PROV');cases.append(emit('R10_NONMATCHING_AUTHOR_VISIBLE',b,o,h,'Different author string produces ineffective visible request, no authentication.',effects={'W1':'NO_COUNT_EFFECT'},agg=aggregation(present=['SEAT_A'],raw=counts(1),eligible=counts(1),qualified=counts(1),rows=[rd('R1','SEAT_A','SUPPORT',withdrawals=['W1'])],agreement='SINGLE_DECISIVE_READING',withdrawals=['W1'])))
b,o,h=base();reading(b);withdraw(b);withdraw(b,'W2',predecessor='W1');cases.append(emit('R11_WITHDRAWAL_CHAIN',b,o,h,'Both held matching events retained; request chain does not erase evidence.',effects={'W1':'EXCLUDES_MANUAL_FIXTURE','W2':'EXCLUDES_MANUAL_FIXTURE'},agg=aggregation(present=['SEAT_A'],raw=counts(1),rows=[rd('R1','SEAT_A','SUPPORT','INELIGIBLE_WITHDRAWN',withdrawals=['W1','W2'])],withdrawals=['W1','W2'])))
b,o,h=base();reading(b);withdraw(b);cases.append(emit('R12_MISSING_WITHDRAWAL_PIN',b,o,h,'Missing held event pin refuses before count projection.',error=fail('READING_WITHDRAWAL_EVENT_PINS','READING_PIN_SET'),held_mut=lambda x:x['items'].clear()))
b,o,h=base();reading(b);withdraw(b,predecessor='W1');cases.append(emit('R13_WITHDRAWAL_SELF_CYCLE',b,o,h,'Exact held pin cannot make request predecessor cycle valid.',error=fail('READING_WITHDRAWAL_PREDECESSORS','READING_WITHDRAWAL_PREDECESSOR_CYCLE')))
b,o,h=base();r=reading(b);r['input_manifest']['sha256']='0'*64;cases.append(emit('R14_STALE_MANIFEST_PIN',b,o,h,'Reading full Manifest pin mismatch refuses without partial counts.',error=fail('READING_RECORDS','READING_MANIFEST_PIN')))
b,o,h=base();r=reading(b);r['response']=copy.deepcopy(b['input_manifests'][0]['prompt']);cases.append(emit('R15_RESPONSE_WRONG_KIND',b,o,h,'Fresh full PROMPT Blob record pin cannot serve as RAW_RESPONSE.',error=fail('READING_RECORDS','READING_RESPONSE_KIND')))
b,o,h=base(expected=('SEAT_E',),extra=(('SEAT_E',True),));run=external(b);reading(b,seatid='SEAT_E',external=True,provenance='EXT_PROV');run['raw_run_evidence']=copy.deepcopy(b['input_manifests'][0]['prompt']);cases.append(emit('R16_RUN_RAW_EVIDENCE_KIND',b,o,h,'Explicit V1 raw-run evidence kind is PROVENANCE_EVIDENCE.',error=fail('READING_RUN_EVIDENCE','READING_RUN_RAW_EVIDENCE_KIND')))
b,o,h=base();reading(b);challenge(b,target='R1',seatid='SEAT_A');b['readings'][0]['challenge_ids']=['CH1'];cases.append(emit('R17_BOUND_CHALLENGE',b,o,h,'Listed challenge exact Reading/Seat/Claim stays unresolved.',agg=aggregation(present=['SEAT_A'],raw=counts(1),eligible=counts(1),qualified=counts(1),rows=[rd('R1','SEAT_A','SUPPORT')],agreement='SINGLE_DECISIVE_READING',challenges=['CH1'])))
b,o,h=base(extra=(('SEAT_C',False),));reading(b);challenge(b,seatid='SEAT_C');b['readings'][0]['challenge_ids']=['CH1'];cases.append(emit('R18_UNATTACHED_CHALLENGE_OTHER_SEAT',b,o,h,'Unattached Claim challenge may name any registered Seat; no invented roster/Reading-seat restriction.',agg=aggregation(present=['SEAT_A'],raw=counts(1),eligible=counts(1),qualified=counts(1),rows=[rd('R1','SEAT_A','SUPPORT')],agreement='SINGLE_DECISIVE_READING',challenges=['CH1'])))
report=dict(schema='quorum/reading-literal-oracle/1',contract_pin=dict(bytes=len((OUT/'contract.json').read_bytes()),sha256=H((OUT/'contract.json').read_bytes())),addendum_pin=dict(bytes=len((OUT/'design-addendum.json').read_bytes()),sha256=H((OUT/'design-addendum.json').read_bytes())),status='MANUAL_COMPLETE_COUNTS_DISPOSITIONS_NO_PRODUCT_EXECUTION',derivation='All stance counts, eligibility, qualified counts, dissent arrays, withdrawal effects and expected first errors above are manually written literals. Helpers format/hash exact input and complete output bytes; no aggregation/closure checker imported or executed. External-origin rows are manually authored synthetic unverified specimens, not evidence that any external assessor/model run occurred.',cases=cases,omissions='No new implementation, actual model campaign, external custody/authentication/runtime pins/fullReplay-stage-order/import acceptance or semantic correctness established. Independently reviewed control fixtures remain separate evidence.')
(OUT/'oracle.json').write_bytes(C(report));print('Prepared',len(cases),'manual complete Reading envelopes; no checker execution.')
