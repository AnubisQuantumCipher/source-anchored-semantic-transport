import base64,copy,hashlib,json,pathlib,sys
sys.path.insert(0,'/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/tools')
import transport_quorum_impact as product
import transport_quorum_input as meta
R=pathlib.Path('/dev/shm/semantic-transport-impact-20261029');D=R/'review-01'
def can(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def load(name):
 d=R/name;b=json.loads((d/'body.json').read_bytes());o=json.loads((d/'originals.json').read_bytes());return b,tuple((v['alias_id'],v['key'],base64.b64decode(v['base64'])) for v in o['items'])
def held(b):return tuple((v['id'],hashlib.sha256(can(v)).hexdigest(),len(can(v))) for v in b['updates'])
class HostTuple(tuple):
 def __iter__(self):raise RuntimeError('HOST_CALLBACK')
 def __len__(self):raise RuntimeError('HOST_CALLBACK')
 def __eq__(self,other):raise RuntimeError('HOST_CALLBACK')
def public_case(name):
 base='I02_REPLACEMENT'
 if name=='A06_PREDECESSOR_BEFORE_HISTORY':base='I23_PRIOR_ARTIFACT_MISMATCH'
 if name=='A07_CYCLE_BEFORE_KIND':base='I12_CLAIM_CYCLE'
 if name=='A10_ARRAY_ORDER':base='I03_TRANSITIVE'
 b,o=load(base)
 if name=='A03_LATER_KIND_BEFORE_EARLY_PROVENANCE':
  b['updates'][0]['provenance']['id']='MISSING';v=copy.deepcopy(b['updates'][0]);v['id']='Z';v['kind']='WITHDRAWAL';b['updates'].append(v)
 elif name=='A04_OLD_BEFORE_PROVENANCE_DUPLICATE':
  b['updates'][0]['old_version']['sha256']='0'*64;b['provenance'].append(copy.deepcopy(b['provenance'][0]))
 elif name=='A05_DUPLICATE_BEFORE_MISSING_PROVENANCE':
  b['updates'][0]['provenance']['id']='MISSING';b['provenance'].append(copy.deepcopy(b['provenance'][0]))
 elif name=='A06_PREDECESSOR_BEFORE_HISTORY':b['updates'][0]['predecessor_event_id']='MISSING'
 elif name=='A07_CYCLE_BEFORE_KIND':b['updates'][0]['kind']='WITHDRAWAL'
 elif name in ('A08_UNOWNED_RECORD','A09_MISSING_DEPENDENT'):
  v=copy.deepcopy(b['dependencies'][0]);v['id']='ZZ_EXTRA'
  if name=='A09_MISSING_DEPENDENT':v['dependent']['claim_id']='MISSING'
  b['dependencies'].append(v)
 elif name=='A10_ARRAY_ORDER':
  for v in b.values():
   if type(v) is list:v.reverse()
 pins=held(b)
 if name=='A01_HOST_OUTER':pins=HostTuple(pins)
 if name=='A02_HOST_ITEM':pins=(HostTuple(pins[0]),)
 return b,o,pins
rows=[]
# Baseline literal oracle execution; no expected values are inferred from product.
for case in json.loads((R/'oracle.json').read_bytes())['cases']:
 b,o=load(case['id']);p=json.loads((R/case['id']/'held-update-pins.json').read_bytes())
 pins=tuple(tuple(v.get(k) for k in ('event_id','sha256','byte_length')) if isinstance(v,dict) else v for v in p['items'])
 expected=json.loads((R/case['id']/'expected.json').read_bytes());actual=product.check_declared_impact(can(b),o,pins)
 rows.append({'id':case['id'],'pass':actual==expected,'actual':actual,'expected':expected})
ind=json.loads(pathlib.Path('/dev/shm/semantic-transport-impact-controls-20261029/handwritten-expectations.json').read_bytes())
for case in ind['cases']:
 raw=pathlib.Path(case['body_raw']['path']).read_bytes();o=tuple((v['alias'],v['key'],bytes.fromhex(v['immutable_bytes_hex'])) for v in case['originals_exact_tuple_recipe']);p=case['held_update_pins_exact_tuple_recipe'];pins=tuple(tuple(v[k] for k in ('event_id','sha256','byte_length')) if type(v) is dict else v for v in p['items']);actual=product.check_declared_impact(raw,o,pins);expected=case['handwritten_expected_complete_result'];rows.append({'id':'independent32/'+case['id'],'pass':actual==expected,'actual':actual,'expected':expected})
expect=json.loads((D/'probe-expectations.json').read_bytes())
for case in expect['cases']:
 name=case['id'];expected=case['expected'];actual=None
 try:
  if name.startswith('A'):
   b,o,pins=public_case(name)
   if name=='A10_ARRAY_ORDER':expected=json.loads((R/'I03_TRANSITIVE'/'expected.json').read_bytes());expected['body_pin']=pin(can(b))
   actual=product.check_declared_impact(can(b),o,pins)
  elif name=='R01_WORK_CHARGE':product._charge([8192])
  elif name=='R02_DEPTH':product._walk({'paths':[]},{'id':'U','old_version':{}},0,33,[[(i+1,'D'+str(i))] for i in range(33)]+[[]],[0],[0])
  elif name=='R03_OUTPUT_INCREMENTAL':product._append_path({'paths':[]},{'id':'U','old_version':{}},['D'],[32768])
  elif name=='R04_OUTPUT_ACCOUNTING':product._paths({'claims':[]},{},[],{},[],[0])
  elif name=='R05_TRIGGER_COVERAGE':product._verify_paths({'paths':[],'trigger_update_ids':['U']},0,{},[])
  elif name=='R06_EXACT_TERMINAL':product._verify_paths({'paths':[{'dependency_ids':['D'],'seed':{'logical_source_id':'S','sha256':'0'*64,'bytes':0},'trigger_update_id':'U'}],'trigger_update_ids':['U']},0,{can({'logical_source_id':'S','sha256':'0'*64,'bytes':0}):2},[(0,1,'D')])
 except meta.InputError as error:actual=meta._error(error)
 except Exception as error:actual={'exception':type(error).__name__,'message':str(error)}
 rows.append({'id':name,'pass':actual==expected,'actual':actual,'expected':expected})
report={'schema':'quorum/independent-impact-probe-run/1','assertions_enabled':__debug__,'product_pin':pin(pathlib.Path(product.__file__).read_bytes()),'frozen_expectations':pin((D/'probe-expectations.json').read_bytes()),'cases':rows,'status':'PASS' if all(r['pass'] for r in rows) else 'FAILED'}
p=pathlib.Path(sys.argv[1]);p.open('x').write(json.dumps(report,sort_keys=True,separators=(',',':'))+'\n');print(report['status'],len(rows),'cases',[(v['id'],v['actual']) for v in rows if not v['pass']]);print(str(p),pin(p.read_bytes()))
