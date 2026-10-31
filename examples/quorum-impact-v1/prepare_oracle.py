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

cases=[]
b,o,old,new=base()
cases.append(emit('I01_NO_UPDATES',b,o,'Complete dependencies with no supplied notice have unchanged declared closure.'))
b,o,old,new=base();update(b,old,new)
cases.append(emit('I02_REPLACEMENT',b,o,'Informational replacement seeds old exact definition; quote/source stays unchanged.',{'CLAIM_A':[path('U',old,'D_CONTEXT')]}))
(OUT/'base-preview.json').write_bytes(canon(dict(schema='quorum/impact-base-preview/1',cases=cases,status='MANUAL_EXPECTED_BYTES_NOT_EXECUTED')))
print('Prepared stable base fixtures I01/I02; no checker run.')
