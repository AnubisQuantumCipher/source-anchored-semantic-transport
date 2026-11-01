"""Create manually specified component examples; no checker is imported or run."""
import base64
import copy
import hashlib
import json
from pathlib import Path

OUT=Path('/dev/shm/semantic-transport-source-membership-20261029')
BASE=Path('/dev/shm/semantic-transport-wire-20261029/literal-vectors-02')

def canonical(v):
    return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode('utf-8')

def digest(b):
    return hashlib.sha256(b).hexdigest()

def key(data, logical='RULE_TEXT'):
    return {'logical_source_id':logical,'bytes':len(data),'sha256':digest(data)}

def read_base(name):
    folder=BASE/name
    body=json.loads((folder/'body.json').read_bytes())
    records=json.loads((folder/'sources.json').read_bytes())
    originals=[(r['id'],r['key'],base64.b64decode(r['base64'])) for r in records]
    return body,originals

def replace_original(body, data, quote=None):
    k=key(data)
    body['sources'][0]['key']=copy.deepcopy(k)
    sel=body['selectors'][0]
    q=data if quote is None else quote
    sel.update(source=copy.deepcopy(k),begin=0,end=len(q),quote_bytes=len(q),
               quote_base64=base64.b64encode(q).decode('ascii'),quote_sha256=digest(q))
    body['dependencies'][0]['requires']['source']=copy.deepcopy(k)
    body['tasks'][0]['selected_sources']=[copy.deepcopy(k)]
    return [('SOURCE',copy.deepcopy(k),data)]

def blob(body, data, encoding='CANONICAL_JSON'):
    body['blobs'].append({'id':'EXAMPLE_BLOB','kind':'SETTINGS','encoding':encoding,
      'bytes':len(data),'sha256':digest(data),'base64':base64.b64encode(data).decode('ascii')})

def success(body, raw, statuses):
    # Expected projection is specified by the contract, not obtained from a checker.
    return {'status':'ok','stage':'SOURCE_BLOB_SELECTOR_ONLY',
      'body_pin':{'bytes':len(raw),'sha256':digest(raw)},
      'source_index':[{'id':r['id'],'key':copy.deepcopy(r['key'])} for r in sorted(body['sources'],key=lambda r:r['id'])],
      'blob_index':[{k:r[k] for k in ('id','kind','encoding','bytes','sha256')} for r in sorted(body['blobs'],key=lambda r:r['id'])],
      'selectors':[{'id':r['id'],'status':statuses[r['id']]} for r in sorted(body['selectors'],key=lambda r:r['id'])],
      'source_authentication':'UNVERIFIED','current_authority':'NONE','freshness':'UNKNOWN'}

def error(stage, code):
    return {'status':'error','stage':stage,'error':code}

def emit(name,body,originals,rationale,expected=None,status='MATCH'):
    path=OUT/name
    path.mkdir()
    for field,value in body.items():
        if isinstance(value,list) and value and isinstance(value[0],dict) and 'id' in value[0]:
            value.sort(key=lambda r:(r['id'],r.get('revision','')))
    raw=canonical(body)
    fixture={'outer_type':'tuple','items':[{'item_type':'tuple','alias_id':alias,
      'key':k,'data_type':'bytes','base64':base64.b64encode(data).decode('ascii')}
      for alias,k,data in originals]}
    result=expected if expected is not None else success(body,raw,{s['id']:status for s in body['selectors']})
    (path/'body.json').write_bytes(raw)
    (path/'originals.json').write_bytes(canonical(fixture))
    (path/'expected.json').write_bytes(canonical(result))
    return {'id':name,'rationale':rationale,'expected_source':'MANUALLY_DECLARED_BEFORE_COMPONENT_IMPLEMENTATION',
      'files':{f:{'bytes':len((path/f).read_bytes()),'sha256':digest((path/f).read_bytes())}
       for f in ('body.json','originals.json','expected.json')}}

cases=[]
for name,base,status,reason,expected in (
 ('M01_MATCH','V01_MATCH','MATCH','Existing manual V01 exact full source quote.',None),
 ('M02_FALSE_QUOTE','V17_FALSE_QUOTE','DIFFERS','Existing V17 self-consistent quote digest but unequal original bytes.',None),
 ('M03_RESPONSE_TAMPER','V12_RAW_RESPONSE_TAMPER','MATCH','Existing V12 raw response bytes changed under old Blob digest; unrelated Reading pin closure deferred.',error('BLOB_INTEGRITY','BLOB_HASH_MISMATCH'))):
    body,originals=read_base(base)
    cases.append(emit(name,body,originals,reason,expected,status))
body,originals=read_base('V01_MATCH')
a,k,data=originals[0]; originals[0]=(a,k,b'X'+data[1:])
cases.append(emit('M04_SOURCE_HASH',body,originals,'Same length, altered first original byte; all quoted Blob integrity remains downstream.',error('SOURCE_INTEGRITY','SOURCE_HASH_MISMATCH')))
body,originals=read_base('V01_MATCH')
a,k,data=originals[0]; originals[0]=(a,k,data[:-1])
cases.append(emit('M05_SOURCE_LENGTH',body,originals,'Actual original truncated under unchanged complete key.',error('SOURCE_INTEGRITY','SOURCE_BYTES_MISMATCH')))
body,originals=read_base('V01_MATCH')
cases.append(emit('M06_MISSING_ALIAS',body,[],'Declared SourceVersion alias has no supplied original.',error('SOURCE_SET','SOURCE_SET_MISMATCH')))
body,originals=read_base('V01_MATCH')
body['sources'].append(dict(copy.deepcopy(body['sources'][0]),id='ALIAS'))
originals.append(('ALIAS',copy.deepcopy(originals[0][1]),originals[0][2]))
cases.append(emit('M07_ALIAS_COPIES',body,originals,'Distinct aliases share full key/equal bytes; both physical copies are charged and indexed.'))
for overflow in (False,True):
    body,originals=read_base('V01_MATCH')
    length=60000
    for unused in range(6):
        originals=replace_original(body,b'a'*length,b'aaa')
        next_length=65536-len(canonical(body))
        if next_length==length:
            break
        length=next_length
    if len(canonical(body))+len(originals[0][2])!=65536:
        raise ValueError('literal exact-budget construction failed')
    if overflow:
        originals=replace_original(body,b'a'*(length+1),b'aaa')
    cases.append(emit('M09_AGGREGATE_OVER' if overflow else 'M08_AGGREGATE_EXACT',body,originals,
      'Body raw Q_RECORDS plus actual originals is exactly65536.' if not overflow else 'Body raw Q_RECORDS plus originals exceeds65536 by one; no second metadata-source charge.',
      error('SOURCE_BOUNDS','SOURCE_BYTE_BOUND') if overflow else None))
body,originals=read_base('V01_MATCH'); originals=replace_original(body,b'a')
record=copy.deepcopy(body['sources'][0]); k=originals[0][1]
body['sources']=[dict(copy.deepcopy(record),id='SOURCE'+str(i).zfill(2)) for i in range(16)]
originals=[(s['id'],copy.deepcopy(k),b'a') for s in body['sources']]
cases.append(emit('M10_SOURCE_COUNT',body,originals,'Sixteen supplied aliases plus one reserved Q_RECORDS exceeds16; all copies count.',error('SOURCE_ARGUMENTS','SOURCE_COUNT_BOUND')))
for name,data,wanted in (
 ('M11_JSON_BLOB',b'{"n":0}',None),
 ('M12_JSON_RESOURCE',b'111111111111111111111',error('BLOB_ENCODING','BLOB_JSON_RESOURCE'))):
    body,originals=read_base('V01_MATCH');blob(body,data)
    cases.append(emit(name,body,originals,'Canonical JSON Blob in admitted bounded profile.' if wanted is None else 'Otherwise canonical21digit unsigned JSON integer exceeds explicit20digit resource profile, not inherently noncanonical.',wanted))
body,originals=read_base('V01_MATCH'); originals=replace_original(body,b'\xff\x00')
cases.append(emit('M13_OPAQUE_ORIGINAL',body,originals,'Invalid UTF8 original bytes remain opaque; byte quote matches.'))
body,originals=read_base('V01_MATCH');originals=replace_original(body,b'')
cases.append(emit('M14_EMPTY_MATCH',body,originals,'Empty original[0,0) with empty quote is explicitly nonprobative.',status='EMPTY_SOURCE_MATCH_NONPROBATIVE'))
body,originals=read_base('V01_MATCH');originals=replace_original(body,b'',b'x');body['selectors'][0]['end']=0
cases.append(emit('M15_EMPTY_DIFFERS',body,originals,'Empty original[0,0) with correctly bound nonempty quote differs.',status='DIFFERS'))
body,originals=read_base('V01_MATCH');sel=body['selectors'][0]
sel.update(end=0,quote_bytes=0,quote_base64='',quote_sha256=digest(b''))
cases.append(emit('M16_NONEMPTY_EMPTY_SLICE',body,originals,'Empty interval over a nonempty source refuses before comparisons.',error('SELECTOR_RANGE','SELECTOR_RANGE')))
body,originals=read_base('V01_MATCH');body['sources'][0]['id']='Q_RECORDS';originals[0]=('Q_RECORDS',originals[0][1],originals[0][2])
cases.append(emit('M17_RESERVED_Q_RECORDS',body,originals,'Body raw already occupies Q_RECORDS; reserved alias cannot reappear as an original.',error('SOURCE_SET','SOURCE_RESERVED_Q_RECORDS')))
body,originals=read_base('V01_MATCH');body['sources'].append(dict(copy.deepcopy(body['sources'][0]),id='ALIAS'))
originals.append(('ALIAS',copy.deepcopy(originals[0][1]),b'X'+originals[0][2][1:]))
cases.append(emit('M18_ALIAS_CONFLICT',body,originals,'Same complete key with unequal actual bytes refuses before either alias can be chosen.',error('SOURCE_SET','SOURCE_ALIAS_BYTES_CONFLICT')))
manifest={'schema':'quorum/source-membership-manual-oracle/1','status':'COMPLETE_COMPONENT_RESULT_BYTES_DECLARED_NOT_EXECUTED',
 'owner':'/root','component':'source/blob/quote integrity and selector bytes only',
 'fixture_encoding':'originals.json is preparation data, not runtime wire. Loader constructs exact tuple of exact(alias_id,key,base64-decoded immutable bytes) tuples. Body.json bytes passed unchanged. Every expected.json is complete canonical result, not a subset or full ReplayResult.',
 'authorship':'Manual independent expected statuses/envelopes were declared before component implementation. Metadata indexes/pins are literal projections of fixed input bytes, not generated by any checker.',
 'cases':cases,'omissions':['No component checker executed. No semantic/claim/manifest/prompt/settings/reference-eligibility or global cross-role ID closure.','No native proof, installed artifact/package/runtime descriptor validation, external human evidence or full replay acceptance.','The separate independent adversarial-control agent prepares additional low-level refusal cases; this compact oracle does not claim exhaustive input coverage.']}
(OUT/'oracle.json').write_bytes(canonical(manifest))
print('Prepared compact manual oracle; no implementation imported or executed.')
