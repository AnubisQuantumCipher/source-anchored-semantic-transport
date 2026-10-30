"""Independent concrete semantic fixture audit, no product import or execution."""
import base64,copy,hashlib,json
from pathlib import Path
P=Path('/dev/shm/semantic-transport-replay-integration-20261029')
Q=Path('/dev/shm/semantic-transport-replay-controls-20261029/materialization-03')
M=Path('/dev/shm/semantic-transport-replay-controls-20261029/materialization-01/source-derived-import-map-03f2bf18a67b-dc9ec11823ad.json')
FIELDS=('blobs','challenges','claims','dependencies','history','input_manifests','provenance','reading_withdrawals','readings','rules','run_evidence','selectors','sources','tasks','updates')
def C(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def read(p):return json.loads(p.read_bytes())
def bp(z):return {'bytes':len(z),'sha256':hashlib.sha256(z).hexdigest()}
def fp(p):return dict(path=str(p),**bp(p.read_bytes()))
def record(x,address=None):return dict(id=x['id'] if address is None else address,**bp(C(x)))
def patches(req,held,changes):
 for c in changes:
  if c['scope']=='held_Request':held[c['path'].lstrip('/')]=c['value']
  elif c['scope']=='Request':
   v=req;parts=c['path'].strip('/').split('/')
   for k in parts[:-1]:v=v[k]
   v[parts[-1]]=c['value']
  elif c['scope']=='Request.record_pins':
   if 'remove_id' in c:req['record_pins']=[r for r in req['record_pins'] if r['id']!=c['remove_id']]
   else:
    for r in req['record_pins']:
     if r['id']==c['id']:r[c['path'].lstrip('/')]=c['value']
  else:raise ValueError('unfrozen patch scope')
def derive(body,raw,inv):
 body=copy.deepcopy(body);inv=copy.deepcopy(inv)
 pins=[record(body['registry']),record(body['policy'])]+[record(r) for r in body['registry']['seats']]
 for f in FIELDS:pins.extend(record(r,r['id']+':'+r['revision'] if f=='claims' else None) for r in body[f])
 return dict(schema='quorum/replay-request/1',package=bp(Path(inv['package']['path']).read_bytes()),quorum_body=bp(raw),task=record(body['tasks'][0]),registry=record(body['registry']),rules=sorted([record(r) for r in body['rules']],key=C),policy=record(body['policy']),wire_schema=inv['wire_schema'],protocol_rules=inv['protocol_rules'],checker=dict(supported_platform='LINUX_OMARCHY_ONLY',checker_descriptor=inv['checker_descriptor']['key'],runtime_descriptor=inv['runtime_descriptor'],decoder_install_descriptor=inv['decoder_install_descriptor']),input_manifest_pins=sorted([record(r) for r in body['input_manifests']],key=C),record_pins=sorted(pins,key=C),external_source_pins=sorted({C(r['key']):r['key'] for r in body['sources']}.values(),key=C))
rows=[]
for group,oracle in [('literal15-r02-original',P/'revision-02/literal-controls/oracle.json'),('literal15-r02-transport',P/'revision-02/literal-controls/oracle.json'),('review8-r02-original',P/'code-review-01/additional-literals/revision-02/oracle.json'),('review8-r02-transport',P/'code-review-01/additional-literals/revision-02/oracle.json')]:
 manifest=read(Q/group/'materialized-freeze.json');manual={r['id']:r for r in read(oracle)['cases']}
 for r in manifest['cases']:
  case=r['id'];d=Q/group/case;fs={Path(z['path']).name:Path(z['path']) for z in manual[case]['files']};inv=read(d/'invocation.json');raw=(d/'body.json').read_bytes();req=read(d/'request.json');expected=read(d/'expected.json');checks={}
  checks['frozen_oracle_files_exact']=all(fp(Path(z['path']))==z for z in manual[case]['files'])
  checks['body_exact_literal']=raw==fs['body.json'].read_bytes()
  decoder=Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/semantic-handoff-v1/positive-02/transport/decoder')
  qualified_source=P/'qualified-decoder-source'
  work=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
  checks['host_runtime_independent_actual']=inv['runtime_descriptor']==dict(logical_source_id='DECODER_RUNTIME_DESCRIPTOR',**bp((decoder/'RUNTIME.json').read_bytes()))
  checks['host_install_independent_actual']=inv['decoder_install_descriptor']==dict(logical_source_id='DECODER_INSTALL_DESCRIPTOR',**bp((decoder/'INSTALL.json').read_bytes()))
  checks['host_SOURCE_independent_actual']=inv['source_manifest_pin']==bp((qualified_source/'install/SOURCE.json').read_bytes())
  checks['host_schema_independent_actual']=inv['wire_schema']==dict(logical_source_id='WIRE_SCHEMA',**bp((work/'tools/transport_quorum_body.schema.json').read_bytes()))
  checks['host_protocol_independent_actual']=inv['protocol_rules']==dict(logical_source_id='PROTOCOL_RULES',**bp((work/'tools/transport_quorum_protocol-rules.json').read_bytes()))
  checks['host_entry_independent_actual']=inv['bootstrap_entry']==bp((work/'install/transport_quorum_bootstrap.py').read_bytes())
  descriptor_path=Path(inv['checker_descriptor']['path'])
  descriptor=read(descriptor_path)
  checks['host_descriptor_independent_actual']=inv['checker_descriptor']['key']==dict(logical_source_id='CHECKER_DESCRIPTOR',**bp(descriptor_path.read_bytes()))
  checks['descriptor_static_roots']=descriptor['checker_root']==str(work) and descriptor['handoff_root']==str(work) and descriptor['decoder_bundle_root']==str(decoder) and descriptor['decoder_source_root']==str(qualified_source)
  checks['descriptor_all16_actualfilepins']=len(descriptor['files'])==16 and all({k:v for k,v in z.items() if k!='path'}==bp((work/z['path'].split('/',1)[1]).read_bytes()) for z in descriptor['files'])
  checks['descriptor_python_actualpin']={k:v for k,v in descriptor['python'].items() if k!='path'}==bp(Path(descriptor['python']['path']).read_bytes())
  checks['descriptor_SOURCE_link']=descriptor['decoder_source_manifest_sha256']==inv['source_manifest_pin']['sha256']

  try:body=json.loads(raw)
  except (UnicodeError,ValueError):body=read(P/'revision-02/literal-controls/F01_ORIGINAL_ACCEPT/body.json')
  mut=read(fs['materialization.json']);changes=mut['identity_overrides_after_mechanical_pin_derivation'];want=derive(body,raw,inv)
  patches(want,{},[c for c in changes if c['scope']!='held_Request']);held=bp(C(want));patches(want,held,[c for c in changes if c['scope']=='held_Request'])
  checks['request_exact_independent_mechanical_derivation']=want==req and C(req)==(d/'request.json').read_bytes() and held==inv['held_request']
  frozen=read(fs['originals.json'])['items'];checks['original_bytes_and_keys_exact']=len(frozen)==len(inv['originals']) and all(z['key']==v['key'] and base64.b64decode(v['base64'],validate=True)==Path(z['path']).read_bytes() for z,v in zip(inv['originals'],frozen,strict=True))
  manual_expected=read(fs['expected.json'])
  for k in ('request','input_request'):
   if isinstance(manual_expected.get(k),dict) and set(manual_expected[k])=={'$mechanical'}:manual_expected[k]=dict(id='REPLAY_REQUEST',**held)
  checks['expected_exact_manual_template']=expected==manual_expected
  checks['expected_stdout_exactLF']=(d/'expected.stdout').read_bytes()==C(manual_expected)+b'\n'
  if expected['schema']=='quorum/bootstrap-refusal/1':checks['host_refusal_expectedstderr_empty']=(d/'expected.stderr').read_bytes()==b''
  else:
   desc=read(Path(inv['checker_descriptor']['path']));host=dict(schema='quorum/bootstrap-qualified/1',status='QUALIFIED_FIXED_HOST',bootstrap_entry=inv['bootstrap_entry'],checker_descriptor=inv['checker_descriptor']['key'],python=desc['python'],decoder_install_descriptor=inv['decoder_install_descriptor'],runtime_descriptor=inv['runtime_descriptor'],source_manifest=inv['source_manifest_pin'],modules=read(M)['per_arm_expected_modules'][inv['arm']])
   checks['expected_stderr_exact_source_map']=(d/'expected.stderr').read_bytes()==C(host)+b'\n'
  env=read(d/'envelope.json');checks['envelope_actual_request']=env['request']==req
  if inv['auxiliary'] is not None:
   aux=read(fs['auxiliary-input.json']);z=inv['auxiliary'];receipt=dict(validate_import=mut['receipt_validate_import'],received_result_source=aux['key'],received_result_sha256=aux['key']['sha256'],received_result_bytes=aux['key']['bytes'],claimed_verdict=mut['claimed_verdict'])
   checks['auxiliary_exact_outer_literal']=z['alias']==aux['alias_id'] and z['key']==aux['key'] and z['held_key']==aux['key'] and Path(z['path']).read_bytes()==base64.b64decode(aux['base64'],validate=True) and env['untrusted_receipt']==receipt
  else:checks['no_auxiliary_receipt']=env['untrusted_receipt'] is None
  rows.append(dict(group=group,id=case,arm=inv['arm'],checks=checks,scope='BASE_F08_HOST_MUTATION_REQUIRES_SEPARATE_COPIED_SETUP' if mut['outer_host_mutations'] else 'CONCRETE_FULL_STREAMS_AND_LITERAL_INPUTS_REVIEWED'))
x=dict(schema='quorum/independent-remaining-semantic-concrete-review/1',reviewer='actual GPT-6.1',status='PASS' if all(all(r['checks'].values()) for r in rows) else 'FAIL',scope='Read-only independent mechanical derivation, no new product calls, no expected semantic judgments from outputs.',modulemap=fp(M),cases=rows)
p=P/'code-review-01/remaining-semantic-concrete-isolated-review03-corrected.json'
with p.open('xb') as f:f.write(C(x))
print(x['status'],fp(p));print([r for r in rows if not all(r['checks'].values())])
