"""Literal impact fixtures, manual expected paths; no impact checker imported."""
import base64
import copy
import hashlib
import json
from pathlib import Path

OUT=Path('/dev/shm/semantic-transport-impact-20261029')
BASE=Path('/dev/shm/semantic-transport-source-membership-20261029/M01_MATCH')

def canon(value):
    return json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def key(raw,logical):
    return dict(logical_source_id=logical,sha256=sha(raw),bytes=len(raw))

def pin(record):
    raw=canon(record);return dict(id=record['id'],sha256=sha(raw),bytes=len(raw))

def ck(record):
    p=pin(record);return dict(claim_id=record['id'],revision=record['revision'],sha256=p['sha256'],bytes=p['bytes'])

def source(body,originals,name,logical,data):
    k=key(data,logical)
    body['sources'].append(dict(id=name,key=copy.deepcopy(k),media_type='application/octet-stream',origin_kind='MANUAL_DEVELOPMENT_FIXTURE',issuer_claim_id=None,authentication='UNVERIFIED'))
    originals['items'].append(dict(item_type='tuple',alias_id=name,key=copy.deepcopy(k),data_type='bytes',base64=base64.b64encode(data).decode()))
    return k

def dep(body,claim,name,target,role='CONTEXT',kind='SOURCE'):
    body['dependencies'].append(dict(id=name,dependent=dict(claim_id=claim['id'],revision=claim['revision']),requires={kind.lower():copy.deepcopy(target),'kind':kind},role=role,meaning='DECLARED_REVALIDATION_DEPENDENCY_ONLY'))
    claim['dependency_ids'].append(name);claim['dependency_ids'].sort()

def base():
    body=json.loads((BASE/'body.json').read_bytes()); originals=json.loads((BASE/'originals.json').read_bytes())
    old=source(body,originals,'DEF_OLD','SECTION_B',b'old')
    new=source(body,originals,'DEF_NEW','SECTION_B',b'new')
    dep(body,body['claims'][0],'D_CONTEXT',old)
    provenance=dict(id='UPDATE_PROV',origin_kind='MANUAL_DEVELOPMENT_FIXTURE',author_claim='Manual impact fixture author.',method='MANUALLY_AUTHORED_ILLUSTRATION',run_evidence_id=None,evidence=None,limitations='Informational fixture; no authentication or authority.',authentication='UNVERIFIED')
    body['provenance'].append(provenance)
    return body,originals,old,new

def update(body,old,new,name='U',kind='REPLACEMENT',predecessor=None,text=None):
    record=dict(id=name,kind=kind,logical_source_id=old['logical_source_id'],old_version=copy.deepcopy(old),new_version=copy.deepcopy(new),predecessor_event_id=predecessor,issuer_claim_id='DECLARED_ISSUER',provenance=pin(body['provenance'][0]),evidence=None,correction_text=text,status='INFORMATIONAL_QUARANTINED')
    body['updates'].append(record);return record

def child(body,name):
    record=copy.deepcopy(body['claims'][0]);record['id']=name;record['dependency_ids']=[]
    body['claims'].append(record)
    dep(body,record,'P_'+name,body['selectors'][0]['source'],'SOURCE')
    return record

def path(trigger,seed,*ids):
    return dict(trigger_update_id=trigger,seed=copy.deepcopy(seed),dependency_ids=list(ids))

def failure(stage,code):
    return dict(status='error',stage=stage,error=code)

def finish(body,originals):
    claims={ (c['id'],c['revision']):c for c in body['claims']}
    for d in body['dependencies']:
        t=d['requires']
        if t['kind']=='CLAIM' and 'sha256' not in t['claim']:
            t['claim']=ck(claims[(t['claim']['claim_id'],t['claim']['revision'])])
    for field,value in body.items():
        if isinstance(value,list) and value and isinstance(value[0],dict) and 'id' in value[0]:
            value.sort(key=lambda r:(r['id'],r.get('revision','')))
    task=body['tasks'][0]
    task['selected_sources']=sorted([r['key'] for r in body['sources']],key=canon)
    task['claim_rosters']=[dict(claim=ck(c),expected_seat_ids=[]) for c in body['claims']]
    task['context_dependency_ids']=sorted(d['id'] for d in body['dependencies'])
    originals['items'].sort(key=lambda r:r['alias_id'])

def expected(body,raw,paths,conflicts,history_matches):
    updates=[dict(id=u['id'],pin=pin(u),old_version=u['old_version'],status='INFORMATIONAL_QUARANTINED') for u in body['updates']]
    rows=[]
    for c in body['claims']:
        ps=sorted(paths.get(c['id'],[]),key=lambda p:(p['dependency_ids'],p['trigger_update_id']))
        triggers=sorted({p['trigger_update_id'] for p in ps})
        rows.append(dict(claim=ck(c),declared_preconditions='CONFLICT' if any(t in conflicts for t in triggers) else 'MATCH',change_impact='NEEDS_REVALIDATION' if triggers else 'UNCHANGED_DECLARED_CLOSURE',trigger_update_ids=triggers,paths=ps))
    history=[dict(id=h['id'],pin=pin(h),kind=h['kind'],artifact=h['artifact'],classification=h['classification'],related_record_ids=h['related_record_ids'],matched_update_id=history_matches.get(h['id'])) for h in body['history']]
    return dict(status='ok',stage='DECLARED_IMPACT_ONLY',body_pin=dict(bytes=len(raw),sha256=sha(raw)),updates=updates,conflicting_update_ids=sorted(conflicts),claims=rows,held_update_pin_match='MATCH',independent_custody='UNKNOWN',update_authentication='UNVERIFIED',source_authentication='UNVERIFIED',current_authority='NONE',freshness='UNKNOWN',semantic_completeness='UNPROVEN',full_reference_closure='NOT_EVALUATED',history=history,already_recorded_update_ids=sorted(set(history_matches.values())))

def emit(name,body,originals,reason,paths=None,conflicts=(),history_matches=None,error=None,held_mutation=None):
    finish(body,originals);raw=canon(body)
    held=dict(outer_type='tuple',items=[dict(item_type='tuple',event_id=u['id'],sha256=pin(u)['sha256'],byte_length=pin(u)['bytes']) for u in body['updates']])
    if held_mutation is not None:held_mutation(held)
    result=error if error is not None else expected(body,raw,paths or {},conflicts,history_matches or {})
    folder=OUT/name;folder.mkdir()
    for filename,data in (('body.json',raw),('originals.json',canon(originals)),('held-update-pins.json',canon(held)),('expected.json',canon(result))):
        (folder/filename).write_bytes(data)
    return dict(id=name,rationale=reason,expected_authorship='MANUAL_PATHS_AND_DISPOSITIONS_BEFORE_PRODUCT',files={f:dict(bytes=len((folder/f).read_bytes()),sha256=sha((folder/f).read_bytes())) for f in ('body.json','originals.json','held-update-pins.json','expected.json')})

cases=json.loads((OUT/'base-preview.json').read_bytes())['cases']

def add(name,b,o,reason,**kw):cases.append(emit(name,b,o,reason,**kw))
def bad(name,stage,code,mutator):
 b,o,old,new=base();u=update(b,old,new);mutator(b,o,old,new,u)
 add(name,b,o,code,error=failure(stage,code))

b,o,old,new=base();update(b,old,new);c=child(b,'CLAIM_B');dep(b,c,'D_CLAIM',dict(claim_id='CLAIM_A',revision='V1'),kind='CLAIM')
add('I03_TRANSITIVE',b,o,'Claim_B traverses exact Claim target then definition.',paths={'CLAIM_A':[path('U',old,'D_CONTEXT')],'CLAIM_B':[path('U',old,'D_CLAIM','D_CONTEXT')]})

b,o,old,new=base();update(b,old,new);dep(b,b['claims'][0],'D_PARALLEL',old)
add('I04_PARALLEL_IDS',b,o,'Parallel endpoints retain each original DependencyID as distinct path.',paths={'CLAIM_A':[path('U',old,'D_CONTEXT'),path('U',old,'D_PARALLEL')]})

b,o,old,new=base();update(b,old,new);update(b,old,new,'U2')
add('I05_IDENTICAL_EFFECTS',b,o,'Same source/effect different event IDs yield two trigger-path records and no conflict.',paths={'CLAIM_A':[path('U',old,'D_CONTEXT'),path('U2',old,'D_CONTEXT')]})

b,o,old,new=base();third=source(b,o,'DEF_THIRD','SECTION_B',b'third');older=source(b,o,'DEF_OLDER','SECTION_B',b'older')
update(b,older,old,'P1');update(b,new,old,'P2');update(b,old,new,'U1',predecessor='P1');update(b,old,third,'U2',predecessor='P2')
add('I06_SAME_OLD_DIFFERENT_PREDECESSORS',b,o,'Competing distinct effects conflict despite different valid predecessors.',paths={'CLAIM_A':[path('U1',old,'D_CONTEXT'),path('U2',old,'D_CONTEXT')]},conflicts=('U1','U2'))

b,o,old,new=base();update(b,old,None,kind='WITHDRAWAL')
add('I07_WITHDRAWAL',b,o,'Withdrawal quarantined; old-dependent Claim requires revalidation, never false.',paths={'CLAIM_A':[path('U',old,'D_CONTEXT')]})
b,o,old,new=base();update(b,old,None,kind='ATTRIBUTED_CORRECTION',text='Manual attributed correction; truth unverified.')
add('I08_ATTRIBUTED_CORRECTION',b,o,'Correction text is exact effect data, never authoritative truth.',paths={'CLAIM_A':[path('U',old,'D_CONTEXT')]})

b,o,old,new=base();update(b,new,old)
add('I09_UNRELATED_SEED',b,o,'Changing a supplied source outside Claim dependency closure does not trigger it.')

bad('I10_MISSING_SOURCE_TARGET','IMPACT_DEPENDENCIES','IMPACT_SOURCE_TARGET_MISSING',lambda b,o,old,new,u:b['dependencies'][1]['requires']['source'].update(sha256='0'*64))

b,o,old,new=base();update(b,old,new);c=child(b,'CLAIM_B');dep(b,c,'D_CLAIM',dict(claim_id='CLAIM_A',revision='V1',sha256='0'*64,bytes=1),kind='CLAIM')
add('I11_BAD_CLAIM_TARGET_PIN',b,o,'A complete target pin cannot be replaced by label-only resolution.',error=failure('IMPACT_DEPENDENCIES','IMPACT_CLAIM_TARGET_PIN'))

b,o,old,new=base();update(b,old,new);c=child(b,'CLAIM_B');dep(b,c,'D_BA',dict(claim_id='CLAIM_A',revision='V1'),kind='CLAIM');dep(b,b['claims'][0],'D_AB',dict(claim_id='CLAIM_B',revision='V1'),kind='CLAIM')
add('I12_CLAIM_CYCLE',b,o,'All dependency components checked before update semantics.',error=failure('IMPACT_DEPENDENCY_DAG','IMPACT_DEPENDENCY_CYCLE'))

bad('I13_MISSING_PREDECESSOR','IMPACT_PREDECESSORS','IMPACT_PREDECESSOR_MISSING',lambda b,o,old,new,u:u.update(predecessor_event_id='ABSENT'))
bad('I14_SELF_PREDECESSOR','IMPACT_PREDECESSORS','IMPACT_PREDECESSOR_CYCLE',lambda b,o,old,new,u:u.update(predecessor_event_id='U'))
bad('I15_BAD_UPDATE_KIND','IMPACT_UPDATE_RECORDS','IMPACT_UPDATE_KIND',lambda b,o,old,new,u:u.update(kind='WITHDRAWAL'))

b,o,old,new=base();update(b,old,new)
add('I16_MISSING_HELD_PIN',b,o,'Mandatory held event-set equality fails, never infer pin from Body.',error=failure('IMPACT_EVENT_PINS','IMPACT_PIN_SET'),held_mutation=lambda h:h['items'].clear())
b,o,old,new=base();update(b,old,new)
add('I17_STALE_HELD_PIN',b,o,'Held full event pin must match exact canonical bytes.',error=failure('IMPACT_EVENT_PINS','IMPACT_UPDATE_PIN'),held_mutation=lambda h:h['items'][0].update(sha256='0'*64))
b,o,old,new=base();update(b,old,new)
add('I18_DUPLICATE_HELD_PIN',b,o,'Duplicate separately supplied event pins refuse before set equality.',error=failure('IMPACT_EVENT_PINS','IMPACT_PIN_DUPLICATE'),held_mutation=lambda h:h['items'].append(copy.deepcopy(h['items'][0])))
b,o,old,new=base();update(b,old,new)
add('I19_BOOL_PIN_LENGTH',b,o,'Host bool cannot masquerade as exact builtin integer length.',error=failure('IMPACT_PIN_ARGUMENTS','IMPACT_PIN_TYPE'),held_mutation=lambda h:h['items'][0].update(byte_length=True))
b,o,old,new=base();update(b,old,new)
add('I20_PIN_COUNT_BEFORE_ITEM',b,o,'Nine host pins refuse count before inspecting malformed first item.',error=failure('IMPACT_PIN_ARGUMENTS','IMPACT_PIN_COUNT'),held_mutation=lambda h:h.update(items=[None]*9))

b,o,old,new=base();update(b,old,new);artifact=source(b,o,'FIRST_OUTPUT','FIRST_OUTPUT',b'failed first response\n')
b['history'].append(dict(id='H_FIRST',kind='RETAINED_RAW_FIRST_OUTPUT',artifact=artifact,related_record_ids=['U'],classification='FAILED',note='Original failed output retained, not corrected in place.'))
add('I21_RETAINED_FIRST_OUTPUT',b,o,'Failed original bytes/classification remain visible without parsing or authority.',paths={'CLAIM_A':[path('U',old,'D_CONTEXT')]})
b,o,old,new=base();u=update(b,old,new);artifact=source(b,o,'PRIOR_EVENT','PRIOR_EVENT',canon(u))
b['history'].append(dict(id='H_PRIOR',kind='PRIOR_COMMITTED_UPDATE',artifact=artifact,related_record_ids=['U'],classification='OBSERVED',note='Exact event bytes already retained; still informational.'))
add('I22_ALREADY_RECORDED',b,o,'Exact prior event bytes identify U without parsing and without skipping impact.',paths={'CLAIM_A':[path('U',old,'D_CONTEXT')]},history_matches={'H_PRIOR':'U'})
b,o,old,new=base();update(b,old,new);artifact=source(b,o,'PRIOR_EVENT','PRIOR_EVENT',b'not the exact event')
b['history'].append(dict(id='H_PRIOR',kind='PRIOR_COMMITTED_UPDATE',artifact=artifact,related_record_ids=['U'],classification='OBSERVED',note='Mismatched artifact cannot assert already recorded.'))
add('I23_PRIOR_ARTIFACT_MISMATCH',b,o,'History self-bound source is insufficient unless exact supplied event bytes match.',error=failure('IMPACT_HISTORY','IMPACT_HISTORY_EVENT_MISMATCH'))

b,o,old,new=base();u=update(b,old,new);payload=b'update evidence';blob=dict(id='UPD_EVIDENCE',kind='UPDATE_EVIDENCE',encoding='STRICT_UTF8',bytes=len(payload),sha256=sha(payload),base64=base64.b64encode(payload).decode());b['blobs'].append(blob);u['evidence']=pin(blob)
add('I24_EVIDENCE_RECORD_PIN',b,o,'Evidence pin binds complete canonical Blob record in addition to alreadychecked payload.',paths={'CLAIM_A':[path('U',old,'D_CONTEXT')]})
b,o,old,new=base();u=update(b,old,new);payload=b'update evidence';blob=dict(id='UPD_EVIDENCE',kind='UPDATE_EVIDENCE',encoding='STRICT_UTF8',bytes=len(payload),sha256=sha(payload),base64=base64.b64encode(payload).decode());b['blobs'].append(blob);u['evidence']=pin(blob);blob['encoding']='OPAQUE_BYTES'
add('I25_STALE_EVIDENCE_RECORD_PIN',b,o,'Same exact payload with changed encoding invalidates stale canonical Blob record pin.',error=failure('IMPACT_UPDATE_RECORDS','IMPACT_UPDATE_EVIDENCE_PIN'))

b,o,old,new=base();b['claims'][0]['dependency_ids'].remove('D_CONTEXT');b['dependencies']=[d for d in b['dependencies'] if d['id']!='D_CONTEXT'];c=child(b,'CLAIM_B')
for i in range(8):
 dep(b,b['claims'][0],'A'+str(i),dict(claim_id='CLAIM_B',revision='V1'),kind='CLAIM');dep(b,c,'B'+str(i),old)
update(b,old,new)
ps=[path('U',old,'A'+str(i),'B'+str(j)) for i in range(8) for j in range(8)]
add('I26_SIXTY_FOUR_PATHS',b,o,'Exactly64 labeled paths for Claim_A and8 for Claim_B fit the perClaim cap.',paths={'CLAIM_A':ps,'CLAIM_B':[path('U',old,'B'+str(i)) for i in range(8)]})
update(b,old,new,'U2')
add('I27_SECOND_TRIGGER_PATH_LIMIT',b,o,'Distinct same-seed update IDs charge separate paths; 65th path refuses full output.',error=failure('IMPACT_PATHS','IMPACT_PATH_LIMIT'))

report=dict(schema='quorum/impact-literal-oracle/1',contract_pin=dict(bytes=len((OUT/'contract.json').read_bytes()),sha256=sha((OUT/'contract.json').read_bytes())),status='MANUAL_COMPLETE_EXPECTED_ENVELOPES_NOT_PRODUCT_EXECUTION',derivation='Tiny declared paths, triggers, conflict sets and exact first refusal dispositions are manually designated. Generator hashes/canonicalizes actual literal bytes and constructs complete output envelopes; it does not import/run graph/impact/source/claim checkers.',cases=cases,omissions='No runtime path-work/output cap exercise, independent custody, authentication, task/manifest/reading/fullglobalclosure, full replay or natural language interpretation. Independent32 controls separately cover additional precedence/hostile host/pin/history/sourceversion cases. Product implementation remains UNRUN and requires separate owner admission.')
(OUT/'oracle.json').write_bytes(canon(report))
print('Prepared',len(cases),'complete manual envelopes; no component checker executed.')
