"""Create-only mechanical identity materializer; never imports new replay/bootstrap.
Requires explicit sourcefreeze receipt; all semantic outputs/negative mutation recipes
come from previously frozen literal15. <=15cases, <=96 regular addressed records except
intentional bound witness; <=16 sources, files individually <=131072.
"""
import argparse
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path
ROOT=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
P=Path('/dev/shm/semantic-transport-replay-integration-20261029/revision-02')
BASE=Path('/dev/shm/semantic-transport-replay-controls-20261029/materialization-01')
DEC=Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/semantic-handoff-v1/positive-02/transport/decoder')
SOURCE=Path('/dev/shm/semantic-transport-replay-integration-20261029/qualified-decoder-source')
QUAL=BASE.parent/'external-closure-01/runtime-qualification'
ARRAYS=('blobs','challenges','claims','dependencies','history','input_manifests','provenance','reading_withdrawals','readings','rules','run_evidence','selectors','sources','tasks','updates')


def C(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def bytespin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def filepin(path):return dict(path=str(path),**bytespin(path.read_bytes()))


def fullpin(record,address=None):return dict(id=record['id'] if address is None else address,**bytespin(C(record)))


def sk(path,label):return dict(logical_source_id=label,**bytespin(path.read_bytes()))


def save(path,value):
 with path.open('xb') as stream:stream.write(C(value))
 return filepin(path)


def rawsave(path,raw):
 with path.open('xb') as stream:stream.write(raw)
 return filepin(path)


def source_freeze(path):
 frozen=json.loads(path.read_bytes())
 if frozen.get('ready') is not True or frozen.get('source')!='/root':raise ValueError('explicit owner ready required')
 pins=frozen['sourcepins_verified_before_run']
 for relative,expected in pins.items():
  actual=filepin(ROOT/relative)
  digest=expected['sha256'] if isinstance(expected,dict) else expected
  if actual['sha256']!=digest:raise ValueError('source freeze mismatch '+relative)
 required={'tools/transport_quorum_replay.py','install/transport_quorum_bootstrap.py'}
 if not required.issubset(pins):raise ValueError('future code source pins unavailable')
 return frozen


def descriptor(out,contract):
 rows=[]
 for name in contract['bootstrap']['static_files']:
  prefix,relative=name.split('/',1)
  if prefix not in ('checker','handoff'):raise ValueError('fixed roster namespace')
  actual=filepin(ROOT/relative)
  if actual['bytes']>131072:raise ValueError('checker member cap')
  rows.append(dict(path=name,bytes=actual['bytes'],sha256=actual['sha256']))
 value={'schema':'quorum/checker-bootstrap/1','platform':'LINUX_OMARCHY_ONLY',
  'checker_root':str(ROOT),'handoff_root':str(ROOT),'decoder_bundle_root':str(DEC),
  'decoder_source_root':str(SOURCE),'decoder_source_manifest_sha256':filepin(SOURCE/'install/SOURCE.json')['sha256'],
  'python':filepin(Path(sys.executable).resolve()),'files':sorted(rows,key=lambda row:C(row['path']))}
 save(out/'checker-descriptor.json',value)
 return value


def records(body):
 rows=[fullpin(body['registry']),fullpin(body['policy'])]+[fullpin(x) for x in body['registry']['seats']]
 for field in ARRAYS:
  for record in body[field]:
   address=record['id']+':'+record['revision'] if field=='claims' else None
   rows.append(fullpin(record,address))
 return sorted(rows,key=C)


def make_request(body,raw,package,keys):
 return {'schema':'quorum/replay-request/1','package':bytespin(package),'quorum_body':bytespin(raw),
  'task':fullpin(body['tasks'][0]),'registry':fullpin(body['registry']),'rules':sorted([fullpin(r) for r in body['rules']],key=C),
  'policy':fullpin(body['policy']),'wire_schema':keys['wire_schema'],'protocol_rules':keys['protocol_rules'],
  'checker':{name:keys[name] for name in ('checker_descriptor','runtime_descriptor','decoder_install_descriptor')}|{'supported_platform':'LINUX_OMARCHY_ONLY'},
  'input_manifest_pins':sorted([fullpin(r) for r in body['input_manifests']],key=C),'record_pins':records(body),
  'external_source_pins':sorted({C(r['key']):r['key'] for r in body['sources']}.values(),key=C)}


def apply_overrides(request,held,overrides):
 for patch in overrides:
  scope=patch['scope']
  if scope=='held_Request':held[patch['path'].lstrip('/')]=patch['value']
  elif scope=='Request':
   parent=request;parts=patch['path'].strip('/').split('/')
   for key in parts[:-1]:parent=parent[key]
   parent[parts[-1]]=patch['value']
  elif scope=='Request.record_pins':
   if 'remove_id' in patch:request['record_pins']=[r for r in request['record_pins'] if r['id']!=patch['remove_id']]
   else:
    for record in request['record_pins']:
     if record['id']==patch['id']:record[patch['path'].lstrip('/')]=patch['value']
  else:raise ValueError('unadmitted mutation scope')


def mechanical_expected(expected,held):
 value=copy.deepcopy(expected);pending=[value]
 for unused in range(8192):
  if not pending:return value
  node=pending.pop()
  if isinstance(node,dict):
   for key,item in list(node.items()):
    if isinstance(item,dict) and set(item)=={'$mechanical'}:node[key]=dict(id='REPLAY_REQUEST',**held)
    elif isinstance(item,(dict,list)):pending.append(item)
  elif isinstance(node,list):
   for item in node:
    if isinstance(item,(dict,list)):pending.append(item)
 raise ValueError('expected mechanical traversal cap')


def make_case(case,out,package_row,keys,entry,snapshotpin):
 source=P/'literal-controls'/case['id'];target=out/case['id'];target.mkdir()
 for frozen in case['files']:
  if filepin(Path(frozen['path']))!=frozen:raise ValueError('frozen literal changed')
 raw=(source/'body.json').read_bytes();rawsave(target/'body.json',raw)
 try:body=json.loads(raw)
 except (UnicodeError,ValueError):body=json.loads((P/'literal-controls/F01_ORIGINAL_ACCEPT/body.json').read_bytes())
 originals=json.loads((source/'originals.json').read_bytes());carrier=[]
 for original in originals['items']:
  data=base64.b64decode(original['base64'],validate=True);path=target/(original['alias_id']+'.original')
  rawsave(path,data);carrier.append({'alias':original['alias_id'],'key':original['key'],'path':str(path)})
 arm='transport' if case['id']=='F02_TRANSPORT_ACCEPT' else 'original'
 package_path=Path(package_row['mechanical_package']['archive']['path']) if arm=='transport' else source/'original-source-envelope.json'
 package=package_path.read_bytes();request=make_request(body,raw,package,keys)
 mutation=json.loads((source/'materialization.json').read_bytes())
 # Request byte identity is derived after candidate Request mutations; held_Request
 # fault is applied separately only after exact final Request bytes are frozen.
 held_faults=[p for p in mutation['identity_overrides_after_mechanical_pin_derivation'] if p['scope']=='held_Request']
 candidate_faults=[p for p in mutation['identity_overrides_after_mechanical_pin_derivation'] if p['scope']!='held_Request']
 apply_overrides(request,{},candidate_faults);request_raw=C(request);held=bytespin(request_raw)
 apply_overrides(request,held,held_faults);rawsave(target/'request.json',request_raw)
 aux=None;receipt=None
 if (source/'auxiliary-input.json').is_file():
  item=json.loads((source/'auxiliary-input.json').read_bytes());data=base64.b64decode(item['base64'],validate=True)
  rawsave(target/'auxiliary-result.json',data);aux={'alias':item['alias_id'],'key':item['key'],'held_key':item['key'],'path':str(target/'auxiliary-result.json')}
  receipt={'validate_import':mutation['receipt_validate_import'],'received_result_source':item['key'],
   'received_result_sha256':item['key']['sha256'],'received_result_bytes':item['key']['bytes'],'claimed_verdict':mutation['claimed_verdict']}
 save(target/'envelope.json',{'schema':'quorum/external-replay-envelope/1','request':request,'untrusted_receipt':receipt})
 share=None
 if arm=='transport':share=dict(package_row['mechanical_package']['share'],identity=package_row['mechanical_package']['STS1_identity'])
 invocation={'schema':'quorum/bootstrap-invocation/1','arm':arm,'bootstrap_entry':entry,
  'checker_descriptor':{'path':str(out/'checker-descriptor.json'),'key':keys['checker_descriptor']},
  'decoder_install_descriptor':keys['decoder_install_descriptor'],'runtime_descriptor':keys['runtime_descriptor'],
  'source_manifest_pin':bytespin((SOURCE/'install/SOURCE.json').read_bytes()),'bundle_snapshot_pin':snapshotpin,
  'wire_schema':keys['wire_schema'],'protocol_rules':keys['protocol_rules'],
  'request':filepin(target/'request.json'),'held_request':held,'envelope':filepin(target/'envelope.json'),
  'body':filepin(target/'body.json'),'package':filepin(package_path),'originals':carrier,'share':share,'auxiliary':aux}
 save(target/'invocation.json',invocation)
 expected=json.loads((source/'expected.json').read_bytes());save(target/'expected.json',mechanical_expected(expected,held))
 return {'id':case['id'],'arm':arm,'invocation':filepin(target/'invocation.json'),'expected':filepin(target/'expected.json'),
  'entry_expected_sha256':entry['sha256'],'outer_host_mutations_pending':mutation['outer_host_mutations'],
  'qualification':'Mechanical identity materialization only, no new checker function imported or executed.'}


args=argparse.ArgumentParser();args.add_argument('--source-freeze',type=Path,required=True);args.add_argument('--out',type=Path,required=True)
a=args.parse_args();frozen=source_freeze(a.source_freeze);a.out.mkdir()
contract=json.loads((P/'contract.json').read_bytes());descriptor(a.out,contract)
entry=bytespin((ROOT/'install/transport_quorum_bootstrap.py').read_bytes())
keys={'checker_descriptor':sk(a.out/'checker-descriptor.json','CHECKER_DESCRIPTOR'),
 'wire_schema':sk(ROOT/'tools/transport_quorum_body.schema.json','WIRE_SCHEMA'),
 'protocol_rules':sk(ROOT/'tools/transport_quorum_protocol-rules.json','PROTOCOL_RULES'),
 'decoder_install_descriptor':sk(DEC/'INSTALL.json','DECODER_INSTALL_DESCRIPTOR'),
 'runtime_descriptor':sk(DEC/'RUNTIME.json','DECODER_RUNTIME_DESCRIPTOR')}
# A snapshot includes its fixed absolute decoder root; use exact qualified bytes.
snapshotpin=bytespin((QUAL/'installed-snapshot-after.json').read_bytes())
oracle=json.loads((P/'literal-controls/oracle.json').read_bytes());packages=json.loads((BASE/'package-construction-first-run.json').read_bytes())
if len(oracle['cases'])!=15:raise ValueError('literal15 bound')
package_map={r['id']:r for r in packages['cases']}
rows=[make_case(case,a.out,package_map[case['id']],keys,entry,snapshotpin) for case in oracle['cases']]
save(a.out/'materialized-freeze.json',{'phase':'MECHANICAL_PRE_FIRST_NEW_PRODUCT_RUN','source_readiness':filepin(a.source_freeze),
 'literal_semantic_oracle':filepin(P/'literal-controls/oracle.json'),'package_construction':filepin(BASE/'package-construction-first-run.json'),
 'invocation_schema':filepin(P/'bootstrap-invocation.schema.json'),'cases':rows,
 'remaining':'Source-audit exact module map, independently review materialization, apply F08 isolated copied checker missingfile mutation with prebound baseline descriptor, then owner READY before execution. No expected semantic mutation permitted.'})
print(json.dumps(filepin(a.out/'materialized-freeze.json')))
