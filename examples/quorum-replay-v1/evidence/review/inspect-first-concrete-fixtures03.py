"""Independent stdlib concrete identity check; no new product import/execution."""
import base64,copy,hashlib,json
from pathlib import Path
P=Path('/dev/shm/semantic-transport-replay-integration-20261029')
Q=Path('/dev/shm/semantic-transport-replay-controls-20261029/materialization-03')
M=Path('/dev/shm/semantic-transport-replay-controls-20261029/materialization-01/source-derived-import-map-03f2bf18a67b-dc9ec11823ad.json')
W=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
def C(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def read(p):return json.loads(p.read_bytes())
def bp(raw):return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())
def fp(p):return dict(path=str(p),**bp(p.read_bytes()))
def pin(x,address=None):return dict(id=x['id'] if address is None else address,**bp(C(x)))
fields=('blobs','challenges','claims','dependencies','history','input_manifests','provenance','reading_withdrawals','readings','rules','run_evidence','selectors','sources','tasks','updates')
rows=[];expected_results=[]
for lane,name in [('original15','F01_ORIGINAL_ACCEPT'),('transport14','F02_TRANSPORT_ACCEPT')]:
 d=Q/lane/name;base=P/'revision-02/literal-controls'/name;inv=read(d/'invocation.json');body=read(d/'body.json');req=read(d/'request.json');env=read(d/'envelope.json');checks={}
 checks['body_exact_original_literal']=(d/'body.json').read_bytes()==(base/'body.json').read_bytes()
 checks['all_carrier_pins']=all({k:v for k,v in item.items() if k!='path'}==bp(Path(item['path']).read_bytes()) for item in [inv[n] for n in ('request','envelope','body','package')]+([] if inv['share'] is None else [{k:v for k,v in inv['share'].items() if k!='identity'}]))
 checks['held_request_actual']=inv['held_request']==bp((d/'request.json').read_bytes())
 checks['envelope_exact_request']=env==dict(schema='quorum/external-replay-envelope/1',request=req,untrusted_receipt=None)
 desc_path=Path(inv['checker_descriptor']['path']);desc=read(desc_path)
 checks['descriptor_pin']={k:v for k,v in inv['checker_descriptor']['key'].items() if k!='logical_source_id'}==bp(desc_path.read_bytes())
 checks['static16_actual_pins']=len(desc['files'])==16 and all({k:v for k,v in r.items() if k!='path'}==bp((W/r['path'].split('/',1)[1]).read_bytes()) for r in desc['files'])
 checks['entry_pin']=inv['bootstrap_entry']==bp((W/'install/transport_quorum_bootstrap.py').read_bytes())
 actual_records=[pin(body['registry']),pin(body['policy'])]+[pin(x) for x in body['registry']['seats']]
 for f in fields:
  actual_records.extend(pin(x,x['id']+':'+x['revision'] if f=='claims' else None) for x in body[f])
 expected_request=dict(schema='quorum/replay-request/1',package=bp(Path(inv['package']['path']).read_bytes()),quorum_body=bp((d/'body.json').read_bytes()),task=pin(body['tasks'][0]),registry=pin(body['registry']),rules=sorted([pin(x) for x in body['rules']],key=C),policy=pin(body['policy']),wire_schema=inv['wire_schema'],protocol_rules=inv['protocol_rules'],checker=dict(supported_platform='LINUX_OMARCHY_ONLY',checker_descriptor=inv['checker_descriptor']['key'],runtime_descriptor=inv['runtime_descriptor'],decoder_install_descriptor=inv['decoder_install_descriptor']),input_manifest_pins=sorted([pin(x) for x in body['input_manifests']],key=C),record_pins=sorted(actual_records,key=C),external_source_pins=sorted({C(x['key']):x['key'] for x in body['sources']}.values(),key=C))
 checks['request_exact_independent_derivation']=req==expected_request and C(req)==(d/'request.json').read_bytes()
 frozen_originals=read(base/'originals.json')['items'];actual_sources=[]
 for src in inv['originals']:
  frozen=next(x for x in frozen_originals if x['alias_id']==src['alias']);z=Path(src['path']).read_bytes()
  actual_sources.append(z==base64.b64decode(frozen['base64'],validate=True) and src['key']==frozen['key'] and bp(z)=={k:v for k,v in src['key'].items() if k!='logical_source_id'})
 checks['originals_exact_frozen_bytes']=all(actual_sources) and len(actual_sources)==len(frozen_originals)
 expected=read(d/'expected.json');manual=read(base/'expected.json');manual['request']=dict(id='REPLAY_REQUEST',**bp((d/'request.json').read_bytes()))
 checks['expected_semantics_only_request_substitution']=expected==manual
 checks['expected_stdout_exact_LF']=(d/'expected.stdout').read_bytes()==C(expected)+b'\n'
 host=read(d/'expected.stderr');maprows=read(M)['per_arm_expected_modules'][inv['arm']]
 expected_host=dict(schema='quorum/bootstrap-qualified/1',status='QUALIFIED_FIXED_HOST',bootstrap_entry=inv['bootstrap_entry'],checker_descriptor=inv['checker_descriptor']['key'],python=desc['python'],decoder_install_descriptor=inv['decoder_install_descriptor'],runtime_descriptor=inv['runtime_descriptor'],source_manifest=inv['source_manifest_pin'],modules=maprows)
 checks['expected_stderr_exact_source_map_and_host_fields']=host==expected_host and (d/'expected.stderr').read_bytes()==C(expected_host)+b'\n'
 checks['actual_document_refs']={k:v for k,v in inv['wire_schema'].items() if k!='logical_source_id'}==bp((W/'tools/transport_quorum_body.schema.json').read_bytes()) and {k:v for k,v in inv['protocol_rules'].items() if k!='logical_source_id'}==bp((W/'tools/transport_quorum_protocol-rules.json').read_bytes())
 rows.append(dict(id=name,arm=inv['arm'],checks=checks,files=[fp(d/n) for n in ('body.json','request.json','envelope.json','invocation.json','expected.stdout','expected.stderr')]))
 e=copy.deepcopy(expected);e.pop('request');expected_results.append(e)
x=dict(schema='quorum/independent-first-concrete-fixture-review/1',reviewer='actual GPT-6.1',scope='Pure stdlib identity/template checks only; no new checker/bootstrap imported or executed.',sourcefreeze=fp(P/'source-freeze-03.json'),source_map=fp(M),cases=rows,normalized_expected_results_equal=expected_results[0]==expected_results[1],normalization='Remove only top-level request; no semantic normalization',status='PASS' if all(all(r['checks'].values()) for r in rows) and expected_results[0]==expected_results[1] else 'FAIL')
p=P/'code-review-01/first-concrete-fixture-review03.json'
with p.open('xb') as h:h.write(C(x))
print(x['status']);print(hashlib.sha256(p.read_bytes()).hexdigest());print(json.dumps([{k:v for k,v in r.items() if k!='files'} for r in rows]))
