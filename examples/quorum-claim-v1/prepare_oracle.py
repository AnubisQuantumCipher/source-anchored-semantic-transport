"""Prepare fixed manual declaration pairs; no product checker is imported/run."""
import base64
import copy
import hashlib
import json
from pathlib import Path

OUT=Path('/dev/shm/semantic-transport-claim-structure-20261029')
SOURCE=Path('/dev/shm/semantic-transport-source-membership-20261029/M01_MATCH')

def canon(v):
    return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()

def sha(data):
    return hashlib.sha256(data).hexdigest()

def key(data,logical):
    return {'logical_source_id':logical,'sha256':sha(data),'bytes':len(data)}

def base():
    return json.loads((SOURCE/'body.json').read_bytes()),json.loads((SOURCE/'originals.json').read_bytes())

def claim_key(claim):
    data=canon(claim)
    return {'claim_id':claim['id'],'revision':claim['revision'],'sha256':sha(data),'bytes':len(data)}

def declaration(originals):
    raw=base64.b64decode(originals['items'][0]['base64'])
    return json.loads(raw)

def rewrite(body, originals, source):
    data=canon(source); target=key(data,'RULE_TEXT')
    item=next(i for i in originals['items'] if i['alias_id']=='SOURCE')
    item.update(key=copy.deepcopy(target),base64=base64.b64encode(data).decode())
    next(r for r in body['sources'] if r['id']=='SOURCE')['key']=copy.deepcopy(target)
    for selector in body['selectors']:
        selector.update(source=copy.deepcopy(target),begin=0,end=len(data),quote_bytes=len(data),
          quote_base64=base64.b64encode(data).decode(),quote_sha256=sha(data))
    for dep in body['dependencies']:
        if dep['role']=='SOURCE' and dep['requires'].get('source',{}).get('logical_source_id')=='RULE_TEXT':
            dep['requires']['source']=copy.deepcopy(target)

def definition(body, originals):
    data=b'An opaque supplied definition fixture.'; target=key(data,'SECTION_B')
    body['sources'].append({'id':'DEFINITION','key':copy.deepcopy(target),'media_type':'text/plain',
      'origin_kind':'MANUAL_DEVELOPMENT_FIXTURE','issuer_claim_id':None,'authentication':'UNVERIFIED'})
    originals['items'].append({'item_type':'tuple','alias_id':'DEFINITION','key':copy.deepcopy(target),
      'data_type':'bytes','base64':base64.b64encode(data).decode()})
    return target

def edge(body,claim,target,name='DEP_REF',role='CONTEXT'):
    body['dependencies'].append({'id':name,'dependent':{'claim_id':claim['id'],'revision':claim['revision']},
      'requires':{'kind':'SOURCE','source':copy.deepcopy(target)},'role':role,
      'meaning':'DECLARED_REVALIDATION_DEPENDENCY_ONLY'})
    claim['dependency_ids'].append(name);claim['dependency_ids'].sort()

def ref_guard(target):
    return {'nodes':[{'op':'REF','target':copy.deepcopy(target)}],'root':0}

def error(stage,code):
    return {'status':'error','stage':stage,'error':code}

def successful(body,raw,interpretation,membership='MATCH'):
    claim=body['claims'][0]; opaque=claim['payload']['profile']=='OPAQUE_PROSE_V1'
    selector=None if opaque else body['selectors'][0]
    entry={'claim':claim_key(claim),'profile':claim['payload']['profile'],
      'selector_id':None if selector is None else selector['id'],
      'source':None if selector is None else copy.deepcopy(selector['source']),
      'source_membership':'NOT_SELECTED' if selector is None else membership,
      'interpretation':interpretation,'semantic_role_relevance':'UNPROVEN'}
    return {'status':'ok','stage':'CLAIM_STRUCTURE_ONLY','body_pin':{'bytes':len(raw),'sha256':sha(raw)},
      'claims':[entry],'source_authentication':'UNVERIFIED','current_authority':'NONE',
      'freshness':'UNKNOWN','semantic_completeness':'UNPROVEN','full_reference_closure':'NOT_EVALUATED'}

def emit(name,body,originals,reason,disposition=None,membership='MATCH',failure=None):
    for name_field in ('sources','selectors','dependencies','claims'):
        body[name_field].sort(key=lambda r:(r['id'],r.get('revision','')))
    task=body['tasks'][0]
    task['selected_sources']=sorted([r['key'] for r in body['sources']],key=canon)
    task['claim_rosters']=[{'claim':claim_key(c),'expected_seat_ids':[]} for c in body['claims']]
    task['context_dependency_ids']=sorted(d['id'] for d in body['dependencies'])
    originals['items'].sort(key=lambda r:r['alias_id'])
    raw=canon(body)
    expected=failure if failure is not None else successful(body,raw,disposition,membership)
    folder=OUT/name;folder.mkdir()
    (folder/'body.json').write_bytes(raw)
    (folder/'originals.json').write_bytes(canon(originals))
    (folder/'expected.json').write_bytes(canon(expected))
    return {'id':name,'rationale':reason,'expected_authorship':'MANUALLY_DECLARED_PREIMPLEMENTATION',
      'files':{n:{'bytes':len((folder/n).read_bytes()),'sha256':sha((folder/n).read_bytes())}
       for n in ('body.json','originals.json','expected.json')}}

cases=[]
body,originals=base()
cases.append(emit('K01_MATCH',body,originals,'Exact complete five-field declaration identity.','MATCHED_DECLARATION_STRUCTURE_ONLY'))
for name,field,value in (('K02_SUBJECT','subject','LANDLORD'),('K03_ACTION','action','DELETE_INFORMATION'),
 ('K04_MODALITY','modality','MAY'),('K05_CONDITION','condition',{'nodes':[{'op':'FALSE'},{'op':'NOT','operand':0}],'root':1}),
 ('K06_EXCEPTION','exception',{'nodes':[{'op':'TRUE'}],'root':0})):
    body,originals=base();body['claims'][0]['payload']['statement'][field]=value
    cases.append(emit(name,body,originals,'Exactly one of five fields changes; no semantic equivalence/simplification.','DIFFERS_DECLARATION_STRUCTURE_ONLY'))
body,originals=base();body['claims'][0]['payload']={'profile':'OPAQUE_PROSE_V1','text':'Unqualified manual reading.','uncertainty':'Unresolved.','omitted_scope':'No structured interpretation.'}
cases.append(emit('K07_OPAQUE',body,originals,'Opaque Claim stays unsupported even with structured original bytes.','UNRESOLVED_UNSUPPORTED_PROFILE'))
body,originals=base();data=base64.b64decode(originals['items'][0]['base64']);s=body['selectors'][0]
s.update(end=1,quote_bytes=1,quote_base64=base64.b64encode(data[:1]).decode(),quote_sha256=sha(data[:1]))
cases.append(emit('K08_PARTIAL_SCOPE',body,originals,'True one-byte quote is insufficient scope for full declaration.','UNRESOLVED_INSUFFICIENT_SCOPE'))
body,originals=base();data=base64.b64decode(originals['items'][0]['base64']);q=b'x'+data[1:]
body['selectors'][0].update(quote_base64=base64.b64encode(q).decode(),quote_sha256=sha(q))
cases.append(emit('K09_QUOTE_DIFFERS',body,originals,'Full-size self-bound unequal quote cannot supply declaration evidence.','NOT_CHECKED_MISSING_EVIDENCE','DIFFERS'))
for name,guard,code in (
 ('K10_CLAIM_ROOT',{'nodes':[{'op':'TRUE'}],'root':1},'CLAIM_GUARD_ROOT'),
 ('K11_CLAIM_FORWARD',{'nodes':[{'op':'NOT','operand':1},{'op':'TRUE'}],'root':1},'CLAIM_GUARD_ORDER'),
 ('K12_CLAIM_UNREACHABLE',{'nodes':[{'op':'TRUE'},{'op':'TRUE'}],'root':1},'CLAIM_GUARD_UNREACHABLE')):
    body,originals=base();body['claims'][0]['payload']['statement']['condition']=guard
    cases.append(emit(name,body,originals,'Malformed Claim guard refuses before scope/comparison.',failure=error('CLAIM_GUARDS',code)))
body,originals=base();target=definition(body,originals);body['claims'][0]['payload']['statement']['exception']=ref_guard(target)
cases.append(emit('K13_CLAIM_REF_EDGE',body,originals,'Real supplied definition lacks explicit owning-Claim dependency; not inferred.',failure=error('CLAIM_REF_DEPENDENCIES','CLAIM_REF_DEPENDENCY_MISSING')))
body,originals=base();target=definition(body,originals);source=declaration(originals);source['statement']['exception']=ref_guard(target);rewrite(body,originals,source)
cases.append(emit('K14_SOURCE_REF_EDGE',body,originals,'Source-only REF lacks owning edge; mismatch must not conceal missing definition.',failure=error('DECLARATION_REF_DEPENDENCIES','DECLARATION_REF_DEPENDENCY_MISSING')))
body,originals=base();source=declaration(originals);source['statement']['condition']['root']=1;rewrite(body,originals,source)
cases.append(emit('K15_SOURCE_ROOT',body,originals,'Source guard root invalid despite mismatch with valid Claim.',failure=error('DECLARATION_GUARDS','DECLARATION_GUARD_ROOT')))
body,originals=base();source=declaration(originals);del source['statement']['exception'];rewrite(body,originals,source)
cases.append(emit('K16_SOURCE_SCHEMA',body,originals,'Missing source exception is a closed-schema refusal; no false default.',failure=error('DECLARATION_INPUT','DECLARATION_SCHEMA')))
body,originals=base();target=definition(body,originals);g=ref_guard(target)
body['claims'][0]['payload']['statement']['exception']=copy.deepcopy(g)
source=declaration(originals);source['statement']['exception']=copy.deepcopy(g);rewrite(body,originals,source)
edge(body,body['claims'][0],target,role='CONTEXT')
cases.append(emit('K17_ROLE_IDENTITY_ONLY',body,originals,'CONTEXT role exact REF identity is admitted; semantic role relevance remains UNPROVEN.','MATCHED_DECLARATION_STRUCTURE_ONLY'))
body,originals=base();target={'logical_source_id':'SECTION_B','sha256':'0'*64,'bytes':7}
body['claims'][0]['payload']['statement']['exception']=ref_guard(target);edge(body,body['claims'][0],target)
cases.append(emit('K18_REF_SOURCE_MISSING',body,originals,'Explicit REF edge has no supplied exact original SourceKey.',failure=error('CLAIM_REF_DEPENDENCIES','CLAIM_REF_SOURCE_MISSING')))
body,originals=base();target=definition(body,originals);first=body['claims'][0]
second=copy.deepcopy(first);second['id']='CLAIM_B';second['dependency_ids']=['DEP_SOURCE_B'];second['payload']['statement']['condition']['root']=1
body['claims'].append(second);edge(body,second,body['selectors'][0]['source'],'DEP_SOURCE_B','SOURCE');second['dependency_ids']=['DEP_SOURCE_B']
first['payload']['statement']['exception']=ref_guard(target)
cases.append(emit('K19_BATCH_PRECEDENCE',body,originals,'ClaimA missing REF edge precedes later ClaimB bad root: each guards then its REFs, not all guards first.',failure=error('CLAIM_REF_DEPENDENCIES','CLAIM_REF_DEPENDENCY_MISSING')))
body,originals=base();target=definition(body,originals);first=body['claims'][0]
g=ref_guard(target);first['payload']['statement']['exception']=copy.deepcopy(g)
source=declaration(originals);source['statement']['exception']=copy.deepcopy(g);rewrite(body,originals,source);edge(body,first,target)
second=copy.deepcopy(first);second['id']='CLAIM_B';second['dependency_ids']=[];second['payload']['statement']['exception']={'nodes':[{'op':'FALSE'}],'root':0}
body['claims'].append(second);edge(body,second,body['selectors'][0]['source'],'DEP_SOURCE_B','SOURCE')
cases.append(emit('K20_NO_SHARED_ELIGIBILITY',body,originals,'Source REF validated for ClaimA cannot authorize ClaimB missing its own REF edge.',failure=error('DECLARATION_REF_DEPENDENCIES','DECLARATION_REF_DEPENDENCY_MISSING')))
body,originals=base();body['dependencies'][0]['role']='CONTEXT'
cases.append(emit('K21_PRIMARY_ROLE',body,originals,'Primary selector anchoring still requires SOURCE role; CONTEXT alone is insufficient.',failure=error('CLAIM_REFERENCES','CLAIM_PRIMARY_DEPENDENCY_MISSING')))
body,originals=base();body['selectors']=[];body['claims'][0]['selector_ids']=[]
cases.append(emit('K22_SELECTOR_CARDINALITY',body,originals,'Zero structural selectors preserves inherited exact-one refusal.',failure=error('CLAIM_SCOPE','CLAIM_SELECTOR_CARDINALITY')))
manifest={'schema':'quorum/claim-structure-manual-oracle/1','status':'COMPLETE_COMPONENT_EXPECTED_BYTES_DECLARED_NOT_EXECUTED',
 'owner':'/root','authorship':'Manual expected dispositions/errors fixed before claim implementation. Expected metadata pins are projections of literal bytes, not checker output.',
 'fixture_encoding':'body.json raw bytes unchanged; originals.json constructs exact tuples as in frozen source oracle; expected.json is the complete closed component result, not a partial property or ReplayResult.',
 'cases':cases,'omissions':['No product checker imported/run; shape/canonical/source/Claim implementation qualification remains unrun here.','Source wrapper and Claim structural identities do not establish semantic relevance, source truth, full-reference closure or authority.','Separate independent focused controls supply additional malformed/scope/role pairs; no exhaustive interpretation claim.']}
(OUT/'oracle.json').write_bytes(canon(manifest))
print('Prepared22 manual Claim structure examples; no checker imported or run.')
