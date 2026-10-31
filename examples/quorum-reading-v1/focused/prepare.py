"""Bounded manual reading fixtures. No product imports or output-derived expectations.
At most64 cases, 32 withdrawals, 3 Seats, 1 Claim, 1 verified original.
Expected dispositions/counts/sets/agreements below are handwritten literal tables.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path

OUT=Path('/dev/shm/semantic-transport-reading-controls-20261029')
AUTHOR=Path('/dev/shm/semantic-transport-reading-20261029')
OLD=Path('/dev/shm/semantic-transport-claim-structure-controls-20261029')
EXPECTED_CONTRACT='f7303d91e238b95a794ff49477903c872981891ccc268e75c81e4d2b972d0c84'
EXPECTED_ADDENDUM='87f9f5fb6bdd1156ca73987392aa973f9cc7fa85406fcbfed39457fbc1b6a6d8'
MAN='MANUAL_DEVELOPMENT_FIXTURE'
EXT='RECORDED_EXTERNAL_ASSESSOR'
E='ELIGIBLE_MANUAL_FIXTURE_ONLY'
D='INELIGIBLE_DUPLICATE_SEAT'
U='INELIGIBLE_NOT_EXPECTED_SEAT'
W='INELIGIBLE_WITHDRAWN'
X='INELIGIBLE_UNVERIFIED'
Q='QUALIFIED_STRUCTURE_ONLY'
CASES=[]


def C(v):
    return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def filepin(p):
    b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':sha(b)}


def rp(r):
    b=C(r);return {'id':r['id'],'bytes':len(b),'sha256':sha(b)}


def ck(r):
    b=C(r);return {'claim_id':r['id'],'revision':r['revision'],'bytes':len(b),'sha256':sha(b)}


def blob(i,k,b):
    return {'id':i,'kind':k,'encoding':'OPAQUE_BYTES','bytes':len(b),'sha256':sha(b),'base64':base64.b64encode(b).decode()}


def row(i,s,t,e=E,reasons=None,withdrawals=None):
    return {'reading_id':i,'seat_id':s,'raw_stance':t,'observation_eligibility':e,
        'reason_codes':sorted(reasons if reasons is not None else [e],key=C),
        'withdrawal_ids':withdrawals or []}


def good(name,rationale,rows,raw,eligible,present,missing,agreement,**spec):
    if len(CASES)>=64:raise ValueError('case budget')
    CASES.append({'id':name,'manual_rationale':rationale,'specification':spec,
        'manual':{'rows':rows,'raw':raw,'eligible':eligible,'present':present,'missing':missing,
        'agreement':agreement,'qualified_agreement':spec.get('qualified_agreement',agreement),
        'qualified':spec.get('qualified',eligible),'qualification':spec.get('qualification',Q),
        'observation':spec.get('observation','MANUAL_FIXTURES_ONLY'),
        'raw_dissent':spec.get('raw_dissent',[]),'ineligible_dissent':spec.get('ineligible_dissent',[]),
        'qualified_dissent':spec.get('qualified_dissent',[]),'abstain':spec.get('abstain',[]),
        'duplicates':spec.get('duplicates',[]),'challenges':spec.get('challenge_ids',[]),
        'withdrawals':spec.get('withdrawals',[])}})


def bad(name,rationale,error,stage,**spec):
    if len(CASES)>=64:raise ValueError('case budget')
    CASES.append({'id':name,'manual_rationale':rationale,'manual_error':error,'manual_stage':stage,'specification':spec})


good('P00_NONE','Every Claim emitted even with no Readings; both expected Seats missing.',[],[0,0,0,0],[0,0,0,0],[],['S0','S1'],'NO_DECISIVE_READINGS',reading=[],observation='NO_RECORDED_READINGS')
good('P01_SINGLE_SUPPORT','A single manual exact structured observation is eligible and qualified; missing Seat remains visible.',[row('R0','S0','SUPPORT')],[1,0,0,0],[1,0,0,0],['S0'],['S1'],'SINGLE_DECISIVE_READING')
good('P02_ABSTAIN_PRESENT','ABSTAIN is present and eligible but never decisive.',[row('R0','S0','ABSTAIN')],[0,0,1,0],[0,0,1,0],['S0'],['S1'],'NO_DECISIVE_READINGS',reading=[('R0','S0','ABSTAIN')],abstain=['R0'])
good('P03_OPPOSE_AGREE','Two OPPOSE observations agree as opposition; both remain qualified dissent.',[row('R0','S0','OPPOSE'),row('R1','S1','OPPOSE')],[0,2,0,0],[0,2,0,0],['S0','S1'],[],'RECORDED_AGREEMENT',reading=[('R0','S0','OPPOSE'),('R1','S1','OPPOSE')],raw_dissent=['R0','R1'],qualified_dissent=['R0','R1'])
good('P04_DISPUTE_AGREE','DISPUTE is decisive dissent; agreement cannot delete unlisted challenges.',[row('R0','S0','DISPUTE'),row('R1','S1','DISPUTE')],[0,0,0,2],[0,0,0,2],['S0','S1'],[],'RECORDED_AGREEMENT',reading=[('R0','S0','DISPUTE'),('R1','S1','DISPUTE')],raw_dissent=['R0','R1'],qualified_dissent=['R0','R1'],challenge_ids=['C0','C1'],challenge='unlisted')
good('P05_DISAGREE','SUPPORT versus OPPOSE has no threshold winner.',[row('R0','S0','SUPPORT'),row('R1','S1','OPPOSE')],[1,1,0,0],[1,1,0,0],['S0','S1'],[],'RECORDED_DISAGREEMENT',reading=[('R0','S0','SUPPORT'),('R1','S1','OPPOSE')],raw_dissent=['R1'],qualified_dissent=['R1'])
good('P06_DUP_WITHDRAWN','Both sameSeat records duplicate first; withdrawn dissent retains both applicable reasons and all raw counts.',[row('R0','S0','OPPOSE',D,[D,W],['W0']),row('R1','S0','SUPPORT',D)],[1,1,0,0],[0,0,0,0],['S0'],['S1'],'NO_DECISIVE_READINGS',reading=[('R0','S0','OPPOSE'),('R1','S0','SUPPORT')],withdrawal='matching',withdrawals=['W0'],raw_dissent=['R0'],ineligible_dissent=['R0'],duplicates=['R0','R1'])
good('P07_UNEXPECTED_WITHDRAWN','Registered unexpected Seat takes precedence over matching withdrawal while retaining both reasons.',[row('R0','S2','OPPOSE',U,[U,W],['W0'])],[0,1,0,0],[0,0,0,0],[],['S0','S1'],'NO_DECISIVE_READINGS',reading=[('R0','S2','OPPOSE')],withdrawal='matching',withdrawals=['W0'],raw_dissent=['R0'],ineligible_dissent=['R0'])
good('P08_EXTERNAL_IDENTITY','External model/family/provider text may differ from static Seat and remains unverified even with policy SourceKey.',[row('R0','S0','DISPUTE',X)],[0,0,0,1],[0,0,0,0],['S0'],['S1'],'NO_DECISIVE_READINGS',reading=[('R0','S0','DISPUTE')],external=['S0'],observation='UNVERIFIED_EXTERNAL_RECORDS_ONLY',raw_dissent=['R0'],ineligible_dissent=['R0'])
good('P09_MIXED','An external support cannot join eligible manual opposition to manufacture agreement.',[row('R0','S0','SUPPORT',X),row('R1','S1','OPPOSE')],[1,1,0,0],[0,1,0,0],['S0','S1'],[],'SINGLE_DECISIVE_READING',reading=[('R0','S0','SUPPORT'),('R1','S1','OPPOSE')],external=['S0'],observation='MIXED_MANUAL_AND_UNVERIFIED',raw_dissent=['R1'],qualified_dissent=['R1'])
good('P10_OPAQUE_AGREE','Eligible illustrative agreement does not qualify opaque source interpretation.',[row('R0','S0','SUPPORT'),row('R1','S1','SUPPORT')],[2,0,0,0],[2,0,0,0],['S0','S1'],[],'RECORDED_AGREEMENT',reading=[('R0','S0','SUPPORT'),('R1','S1','SUPPORT')],profile='opaque',qualification='UNQUALIFIED_UNSUPPORTED',qualified=[0,0,0,0],qualified_agreement='NO_DECISIVE_READINGS')
for name,mode,qualification in [('P11_MISMATCH','mismatch','UNQUALIFIED_MISMATCH'),('P12_PARTIAL','partial','UNQUALIFIED_INSUFFICIENT_SCOPE'),('P13_QUOTE_DIFFERS','differs','NOT_EVALUATED')]:
    good(name,'Structural qualification is independent of eligible stance; original source evidence controls it.',[row('R0','S0','SUPPORT')],[1,0,0,0],[1,0,0,0],['S0'],['S1'],'SINGLE_DECISIVE_READING',profile=mode,qualification=qualification,qualified=[0,0,0,0],qualified_agreement='NO_DECISIVE_READINGS')
good('P14_INEFFECTIVE_WITHDRAWAL','Different declared author request is retained with NO_COUNT_EFFECT.',[row('R0','S0','SUPPORT',E,withdrawals=['W0'])],[1,0,0,0],[1,0,0,0],['S0'],['S1'],'SINGLE_DECISIVE_READING',withdrawal='different',withdrawals=['W0'])
good('P15_WITHDRAWAL32','Inclusive32-event predecessor chain stays bounded; all events retained and exclude manual count.',[row('R0','S0','SUPPORT',W,withdrawals=['W'+str(i).zfill(2) for i in range(32)])],[1,0,0,0],[0,0,0,0],['S0'],['S1'],'NO_DECISIVE_READINGS',withdrawal='chain32',withdrawals=['W'+str(i).zfill(2) for i in range(32)])
good('P16_UNATTACHED_OTHER_SEAT','Reading may list sameClaim unattached Challenge from any registered Seat; unlisted second challenge survives.',[row('R0','S0','SUPPORT')],[1,0,0,0],[1,0,0,0],['S0'],['S1'],'SINGLE_DECISIVE_READING',challenge='listed_other_seat',challenge_ids=['C0','C1'])

for n,f,c in [('PIN_MISSING','held_missing','READING_PIN_SET'),('PIN_DUPLICATE','held_duplicate','READING_PIN_DUPLICATE'),('PIN_WRONG_HASH','held_hash','READING_WITHDRAWAL_PIN'),('PIN_WRONG_LENGTH','held_length','READING_WITHDRAWAL_PIN')]:
    bad('N_'+n,'Held complete-record pins must independently match every withdrawal; no candidate inferred replacement.',c,'READING_WITHDRAWAL_EVENT_PINS',withdrawal='matching',fault=f)
for n,f,c in [('PROV_METHOD','prov_method','READING_PROVENANCE_ORIGIN'),('PROV_EVIDENCE_KIND','prov_evidence_kind','READING_PROVENANCE_EVIDENCE_KIND'),('UNUSED_EXTERNAL_PROV','unused_prov','READING_PROVENANCE_ORIGIN'),('UNUSED_EXTERNAL_RUN_MISSING','unused_prov_missing','READING_PROVENANCE_RUN_MISSING')]:
    bad('N_'+n,'Every supplied Provenance closes before any Readings or counts, including unused records.',c,'READING_PROVENANCE',fault=f)
for n,f,c in [('RUN_MANIFEST','run_manifest','READING_RUN_MANIFEST_PIN'),('RUN_RAW_KIND','run_raw_kind','READING_RUN_RAW_EVIDENCE_KIND'),('RUN_POLICY','run_policy','READING_RUN_POLICY_SOURCE'),('RUN_RESPONSE_KIND','run_response_kind','READING_RUN_RESPONSE_KIND'),('UNUSED_RUN_MANUAL_SEAT','unused_run','READING_RUN_SEAT_ORIGIN')]:
    bad('N_'+n,'Every supplied Run closes exact typed evidence and preassessment inputs even if unused.',c,'READING_RUN_EVIDENCE',external=['S0'],fault=f)
for n,f,c in [('READING_MANIFEST','reading_manifest','READING_MANIFEST_PIN'),('READING_CONTEXT','reading_context','READING_INPUT_CONTEXT'),('RESPONSE_TYPE','response_type','READING_RESPONSE_TYPE'),('RESPONSE_KIND','response_kind','READING_RESPONSE_KIND'),('PROVENANCE_TYPE','provenance_type','READING_PROVENANCE_TYPE'),('UNKNOWN_SEAT','seat_missing','READING_SEAT_MISSING'),('ORIGIN','reading_origin','READING_ORIGIN'),('EXTERNAL_RESPONSE','external_response','READING_RUN_CONTEXT')]:
    bad('N_'+n,'Well-shaped Reading refuses exact typed/context mismatch before aggregation; no accepted ineligible substitute.',c,'READING_RECORDS',fault=f,external=['S0'] if f=='external_response' else [])
for n,f,c in [('CHALLENGE_KIND','challenge_kind','READING_CHALLENGE_EVIDENCE_KIND'),('CHALLENGE_SEAT','challenge_seat','READING_CHALLENGE_CONTEXT'),('CHALLENGE_LIST_CONTEXT','challenge_list','READING_CHALLENGE_REFERENCE_CONTEXT')]:
    bad('N_'+n,'All challenges and every listed challenge reference close independently of stance.',c,'READING_CHALLENGES',fault=f,challenge='bound')
for n,f,c,st in [('WITHDRAWAL_KIND','withdrawal_kind','READING_WITHDRAWAL_EVIDENCE_KIND','READING_WITHDRAWALS'),('PREDECESSOR_MISSING','predecessor_missing','READING_WITHDRAWAL_PREDECESSOR_MISSING','READING_WITHDRAWAL_PREDECESSORS'),('PREDECESSOR_SELF','predecessor_self','READING_WITHDRAWAL_PREDECESSOR_CYCLE','READING_WITHDRAWAL_PREDECESSORS'),('PREDECESSOR_PAIR','predecessor_pair','READING_WITHDRAWAL_PREDECESSOR_CYCLE','READING_WITHDRAWAL_PREDECESSORS'),('PREDECESSOR_TARGET','predecessor_target','READING_WITHDRAWAL_PREDECESSOR_CONTEXT','READING_WITHDRAWAL_PREDECESSORS')]:
    bad('N_'+n,'Complete held pins match candidate symbolic predecessor bytes first; missing/context/cycles are separately refused.',c,st,withdrawal='matching',fault=f)


def make_seat(name,external):
    return {'id':name,'declared_label':'Declared '+name,'origin_kind':EXT if external else MAN,
        'declared_model_id':'Declared model' if external else None,'declared_family_id':'FAMILY_DECLARED',
        'identity_assurance':'UNVERIFIED' if external else 'MANUAL_FIXTURE_ONLY','identity_evidence':None}


def make_prov(name,external=False,author='Author'):
    return {'id':name,'origin_kind':EXT if external else MAN,'author_claim':author,
        'method':'RECORDED_UNVERIFIED_EXTERNAL_RUN' if external else 'MANUALLY_AUTHORED_ILLUSTRATION',
        'run_evidence_id':'RUN' if external else None,'evidence':None,
        'limitations':'Unverified first output claim only','authentication':'UNVERIFIED'}


def prepare_static(spec):
    body=json.loads((OLD/'raw/E00_EXACT.body.json').read_bytes())
    original=json.loads((OLD/'handwritten-expectations.json').read_bytes())['cases'][0]['originals_exact_tuple_recipe']
    claim=body['claims'][0];mode=spec.get('profile')
    if mode=='opaque':claim['payload']={'profile':'OPAQUE_PROSE_V1','text':'Opaque illustration','uncertainty':'','omitted_scope':''}
    if mode=='mismatch':claim['payload']['statement']['modality']='MAY'
    if mode=='partial':body['selectors'][0]['end']=1
    if mode in ('partial','differs'):
        q=b'{' if mode=='partial' else b'well-bound but unequal quote'
        body['selectors'][0].update(quote_base64=base64.b64encode(q).decode(),quote_bytes=len(q),quote_sha256=sha(q))
    external=spec.get('external',[])
    body['registry']['seats']=[make_seat(i,i in external) for i in ('S0','S1','S2')]
    task=body['tasks'][0];task['claim_rosters']=[{'claim':ck(claim),'expected_seat_ids':['S0','S1']}]
    body['blobs']=[blob('PROMPT','PROMPT',b'Prompt'),blob('SETTINGS','SETTINGS',b'Settings'),blob('RESPONSE','RAW_RESPONSE',b'First raw output'),blob('EVIDENCE','PROVENANCE_EVIDENCE',b'Evidence')]
    blobs={b['id']:b for b in body['blobs']}
    manifest={'id':'MANIFEST','schema':'quorum/preassessment-input/1','task':rp(task),'claim':ck(claim),
        'source_versions':copy.deepcopy(task['selected_sources']),'selectors':[rp(s) for s in body['selectors']],
        'dependencies':[rp(d) for d in body['dependencies']],'registry_snapshot':copy.deepcopy(body['registry']),
        'rule_specs':[rp(r) for r in body['rules']],'policy':rp(body['policy']),
        'prompt':rp(blobs['PROMPT']),'settings':rp(blobs['SETTINGS'])}
    body['input_manifests']=[manifest]
    body['provenance']=[make_prov('PROV'),make_prov('WITHDRAW_PROV',author='Other' if spec.get('withdrawal')=='different' else 'Author')]
    if external:
        body['provenance'].append(make_prov('EXT_PROV',True))
        body['run_evidence']=[{'id':'RUN','seat_id':external[0],'input_manifest':rp(manifest),
            'provider_claim':'Unverified provider','model_id_claim':'Different model from Seat',
            'family_id_claim':'DIFFERENT_FAMILY','provider_run_id_claim':'Claimed run',
            'prompt':manifest['prompt'],'settings':manifest['settings'],'response':rp(blobs['RESPONSE']),
            'raw_run_evidence':rp(blobs['EVIDENCE']),'externally_pinned_eligibility_policy':copy.deepcopy(original[0]['key']),
            'asserted_utc':'Opaque timestamp claim','verification':'UNVERIFIED','independent_inputs':'UNKNOWN'}]
    return body,original


def make_dynamic(body,spec):
    m=body['input_manifests'][0];blobs={b['id']:b for b in body['blobs']};provs={p['id']:p for p in body['provenance']}
    reads=spec.get('reading',[('R0','S0','SUPPORT')])
    for name,seat,stance in reads:
        body['readings'].append({'id':name,'seat_id':seat,'claim':m['claim'],'task_view_id':'TASK',
            'source_versions':copy.deepcopy(m['source_versions']),'input_manifest':rp(m),
            'prompt':m['prompt'],'settings':m['settings'],'response':rp(blobs['RESPONSE']),
            'provenance':rp(provs['EXT_PROV' if seat in spec.get('external',[]) else 'PROV']),
            'stance':stance,'challenge_ids':[],'origin_kind':EXT if seat in spec.get('external',[]) else MAN})
    if spec.get('challenge'):
        for i in range(2):
            body['challenges'].append({'id':'C'+str(i),'claim':m['claim'],
                'reading_id':'R0' if spec['challenge']=='bound' else None,'seat_id':'S0' if spec['challenge']=='bound' else 'S2',
                'kind':'OTHER','reason':'Preserved informational challenge','evidence':None,
                'provenance':rp(provs['PROV']),'status':'UNRESOLVED_INFORMATIONAL'})
        if spec['challenge']=='listed_other_seat':body['readings'][0]['challenge_ids']=['C0']
    count=32 if spec.get('withdrawal')=='chain32' else 1 if spec.get('withdrawal') else 0
    for i in range(count):
        body['reading_withdrawals'].append({'id':'W'+str(i).zfill(2) if count==32 else 'W0',
            'reading_id':'R0','reason':'Immutable illustrative request','provenance':rp(provs['WITHDRAW_PROV']),
            'evidence':None,'predecessor_withdrawal_id':'W'+str(i-1).zfill(2) if i else None,'status':'RECORDED_REQUEST_NO_AUTHORITY'})


def mutate_provenance(body,f):
    p=body['provenance'][0];ev=body['blobs'][0]
    if f=='prov_method':p['method']='RECORDED_UNVERIFIED_EXTERNAL_RUN'
    if f=='prov_evidence_kind':p['evidence']=rp(ev)
    if f.startswith('unused_prov'):
        unused=make_prov('ZZ_UNUSED',True);body['provenance'].append(unused)
        unused['run_evidence_id']=None if f=='unused_prov' else 'ABSENT'
    # Refresh consumers so each negative isolates coherence rather than stale provenance Pin.
    for r in body['readings']:
        if r['provenance']['id']==p['id']:r['provenance']=rp(p)


def mutate_run(body,f):
    if not body['run_evidence']:return
    r=body['run_evidence'][0]
    if f=='run_manifest':r['input_manifest']['sha256']='0'*64
    if f=='run_raw_kind':r['raw_run_evidence']=rp(body['blobs'][0])
    if f=='run_policy':r['externally_pinned_eligibility_policy']['sha256']='0'*64
    if f=='run_response_kind':r['response']=rp(body['blobs'][0])
    if f=='unused_run':r['seat_id']='S1';body['readings']=[]


def mutate_reading(body,f):
    if not body['readings']:return
    r=body['readings'][0]
    if f=='reading_manifest':r['input_manifest']['sha256']='0'*64
    if f=='reading_context':r['task_view_id']='OTHER_TASK'
    if f=='response_type':r['response']=rp(body['provenance'][0])
    if f=='response_kind':r['response']=rp(body['blobs'][0])
    if f=='provenance_type':r['provenance']=rp(body['blobs'][0])
    if f=='seat_missing':r['seat_id']='MISSING_SEAT'
    if f=='reading_origin':r['origin_kind']=EXT
    if f=='external_response':
        fresh=blob('OTHER_RESPONSE','RAW_RESPONSE',b'Other first output');body['blobs'].append(fresh);r['response']=rp(fresh)


def mutate_events(body,f):
    if f.startswith('challenge'):
        c=body['challenges'][0]
        if f=='challenge_kind':c['evidence']=rp(body['blobs'][0])
        if f=='challenge_seat':c['seat_id']='S1'
        if f=='challenge_list':
            other=copy.deepcopy(body['readings'][0]);other['id']='R1';body['readings'].append(other)
            c['reading_id']='R1';body['readings'][0]['challenge_ids']=['C0']
    if not body['reading_withdrawals']:return
    w=body['reading_withdrawals'][0]
    if f=='withdrawal_kind':w['evidence']=rp(body['blobs'][0])
    if f=='predecessor_missing':w['predecessor_withdrawal_id']='ABSENT'
    if f=='predecessor_self':w['predecessor_withdrawal_id']='W0'
    if f in ('predecessor_pair','predecessor_target'):
        other=copy.deepcopy(w);other['id']='W1';body['reading_withdrawals'].append(other);w['predecessor_withdrawal_id']='W1'
        if f=='predecessor_pair':other['predecessor_withdrawal_id']='W0'
        else:
            r=copy.deepcopy(body['readings'][0]);r['id']='R1';body['readings'].append(r);other['reading_id']='R1'


def counts(v):
    return dict(zip(('SUPPORT','OPPOSE','ABSTAIN','DISPUTE'),v))


def expected_success(case,body,raw):
    m=case['manual'];ag={'observation_class':m['observation'],'expected_seat_ids':['S0','S1'],
        'present_seat_ids':m['present'],'missing_seat_ids':m['missing'],'raw_counts':counts(m['raw']),
        'eligible_counts':counts(m['eligible']),'structurally_qualified_counts':counts(m['qualified']),
        'eligible_stance_agreement':m['agreement'],'qualified_stance_agreement':m['qualified_agreement'],
        'abstaining_reading_ids':m['abstain'],'raw_dissent_reading_ids':m['raw_dissent'],
        'ineligible_dissent_reading_ids':m['ineligible_dissent'],'qualified_dissent_reading_ids':m['qualified_dissent'],
        'conflicting_duplicate_reading_ids':m['duplicates'],'challenge_ids':m['challenges'],
        'withdrawal_ids':m['withdrawals'],'threshold_verdict':'NOT_DEFINED','readings':[]}
    for r in m['rows']:ag['readings'].append(dict(r,claim_structural_qualification=m['qualification']))
    withdrawals=[{'pin':rp(w),'reading_id':w['reading_id'],'manual_count_effect':'NO_COUNT_EFFECT' if case['specification'].get('withdrawal')=='different' else 'EXCLUDES_MANUAL_FIXTURE'} for w in body['reading_withdrawals']]
    return {'status':'ok','stage':'READING_CLOSURE_AGGREGATION_ONLY','body_pin':{'bytes':len(raw),'sha256':sha(raw)},
        'claims':[{'claim':ck(body['claims'][0]),'aggregation':ag}],'withdrawals':withdrawals,
        'dynamic_typed_reference_closure':'MATCH_READING_SCOPE_ONLY','held_withdrawal_pin_match':'MATCH',
        'independent_custody':'UNKNOWN','declared_model_family_identity':'NOT_VALIDATED',
        'raw_first_output_provenance':'UNVERIFIED','external_record_pin_match':'NOT_EVALUATED',
        'full_reference_closure':'NOT_EVALUATED','source_authentication':'UNVERIFIED','current_authority':'NONE',
        'freshness':'UNKNOWN','semantic_completeness':'UNPROVEN','deferred_gates':['BOOTSTRAP_RUNTIME_EXTERNAL_REQUEST',
        'FULL_TYPED_DIGEST_GRAPH_AND_EXTERNAL_PINS','HISTORY_RELATED_ROLE_CLOSURE','IMPORT_COMPARISON_FULL_REPLAY_ORDER']}


def materialize(case):
    spec=case['specification'];body,original=prepare_static(spec);make_dynamic(body,spec);f=spec.get('fault','')
    mutate_provenance(body,f);mutate_run(body,f);mutate_reading(body,f);mutate_events(body,f)
    for key,value in body.items():
        if isinstance(value,list) and value and isinstance(value[0],dict) and 'id' in value[0]:value.sort(key=lambda r:C(r['id']))
    body['registry']['seats'].sort(key=lambda r:C(r['id']))
    raw=C(body)
    if len(raw)>24576:raise ValueError('candidate bound')
    rawpath=OUT/'raw'/(case['id']+'.body.json')
    with rawpath.open('xb') as stream:stream.write(raw)
    held=[(w['id'],rp(w)['sha256'],rp(w)['bytes']) for w in body['reading_withdrawals']]
    if f=='held_missing':held=[]
    if f=='held_duplicate':held=held+held
    if f=='held_hash':held[0]=(held[0][0],'0'*64,held[0][2])
    if f=='held_length':held[0]=(held[0][0],held[0][1],held[0][2]+1)
    result={'status':'error','error':case['manual_error'],'stage':case['manual_stage']} if case.get('manual_error') else expected_success(case,body,raw)
    return dict(case,body_raw=filepin(rawpath),originals_exact_tuple_recipe=original,
        held_update_pins_exact_tuple_recipe={'outer':'exact_tuple','items':[]},
        held_withdrawal_pins_exact_tuple_recipe={'outer':'exact_tuple','items':[{'event_id':i,'sha256':s,'byte_length':n} for i,s,n in held]},
        handwritten_expected_complete_result=result)


if sha((AUTHOR/'contract.json').read_bytes())!=EXPECTED_CONTRACT:raise ValueError('frozen contract pin mismatch')
if sha((AUTHOR/'design-addendum.json').read_bytes())!=EXPECTED_ADDENDUM:raise ValueError('frozen addendum pin mismatch')
(OUT/'raw').mkdir()
for name in ('contract.json','design-addendum.json'):
    with (OUT/('at-fixture-freeze-'+name)).open('xb') as stream:stream.write((AUTHOR/name).read_bytes())
rows=[materialize(c) for c in CASES]
expected={'classification':'PRE_PRODUCT_HANDWRITTEN_COMPLETE_RESULTS','cases':rows,
    'scope':'Manual literals only, counts/dispositions/agreements/sets hand-derived above; no checker imported/run; canonical serializer and hashlib bind bytes only. No formal proof or full replay claim.'}
p=OUT/'handwritten-expectations.json'
with p.open('xb') as stream:stream.write(C(expected))
freeze={'phase':'PRE_PRODUCT_PRE_ORACLE_FROZEN','expectations':filepin(p),'candidates':[r['body_raw'] for r in rows],
    'source_pins':[filepin(AUTHOR/'contract.json'),filepin(AUTHOR/'design-addendum.json'),filepin(OUT/'prepare.py'),
                  filepin(OLD/'raw/E00_EXACT.body.json'),filepin(OLD/'handwritten-expectations.json')]}
with (OUT/'pre-oracle-freeze.json').open('xb') as stream:stream.write(C(freeze))
print(json.dumps({'cases':len(rows),'expectations':filepin(p),'freeze':filepin(OUT/'pre-oracle-freeze.json')}))
