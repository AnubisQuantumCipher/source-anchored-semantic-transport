import base64,hashlib,json,pathlib,sys
sys.path.insert(0,'/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/tools')
import transport_quorum_reading as product
import transport_quorum_input as metadata
R=pathlib.Path('/dev/shm/semantic-transport-reading-20261029');D=R/'code-review-01'
def can(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
def held(recipe):return tuple(tuple(v[k] for k in ('event_id','sha256','byte_length')) if type(v)is dict else v for v in recipe['items'])
def compact(root,case):
 p=root/case['id'];files={}
 for name,expected in case['files'].items():
  b=(p/name).read_bytes();assert pin(b)==expected;files[name]=b
 o=json.loads(files['originals.json']);return files['body.json'],tuple((v['alias_id'],v['key'],base64.b64decode(v['base64'],validate=True)) for v in o['items']),held(json.loads(files['held-update-pins.json'])),held(json.loads(files['held-withdrawal-pins.json'])),json.loads(files['expected.json'])
def focused(case):
 raw=pathlib.Path(case['body_raw']['path']).read_bytes();assert pin(raw)=={k:case['body_raw'][k] for k in ('bytes','sha256')};return raw,tuple((v['alias'],v['key'],bytes.fromhex(v['immutable_bytes_hex'])) for v in case['originals_exact_tuple_recipe']),held(case['held_update_pins_exact_tuple_recipe']),held(case['held_withdrawal_pins_exact_tuple_recipe']),case['handwritten_expected_complete_result']
rows=[]
def compare(name,args):
 raw,o,u,w,expected=args
 try:actual=product.check_reading_aggregation(raw,o,u,w)
 except Exception as e:actual={'exception':type(e).__name__,'message':str(e)}
 rows.append({'id':name,'pass':actual==expected,'actual':actual,'expected':expected})
author=json.loads((R/'oracle.json').read_bytes())
for case in author['cases']:compare('author/'+case['id'],compact(R,case))
controls=pathlib.Path(sys.argv[2]);fixture=json.loads(controls.read_bytes())
for case in fixture['cases']:compare('independent46/'+case['id'],focused(case))
P=R/'review-01'/'precedence-controls'
for case in json.loads((P/'oracle.json').read_bytes())['cases']:compare('precedence/'+case['id'],compact(P,case))
callbacks=[]
class HostTuple(tuple):
 def __iter__(self):callbacks.append('iter');raise RuntimeError('HOST_CALLBACK')
 def __len__(self):callbacks.append('len');raise RuntimeError('HOST_CALLBACK')
 def __getitem__(self,k):callbacks.append('getitem');raise RuntimeError('HOST_CALLBACK')
raw,o,u,_,_=compact(R,next(c for c in author['cases'] if c['id']=='R02_MANUAL_SUPPORT'));h=json.loads((P/'host-count-probe.json').read_bytes());actual=product.check_reading_aggregation(raw,o,u,(HostTuple(()),)+(None,)*32);rows.append({'id':h['id'],'pass':actual==h['expected'] and callbacks==[],'actual':actual,'expected':h['expected'],'callbacks':callbacks})
for c in json.loads((D/'resource-probe-expectations.json').read_bytes())['cases']:
 name=c['id'];actual=None
 try:
  if name=='S01_APPEND_OVERFLOW_ATOMIC':
   result={'claims':[]}
   try:product._append(result,{'small':'entry'},32768)
   except metadata.InputError as e:actual={'error':metadata._error(e),'claims_unchanged':result=={'claims':[]}}
  elif name=='S02_FINAL_ACCOUNTING':product._finish({'claims':[]},0)
  elif name=='S03_OUTPUT_DEPTH_MAPPED':
   result=0
   for _ in range(14):result={'layer':result}
   product._finish(result,len(can(result))+1)
 except metadata.InputError as e:actual=metadata._error(e)
 except Exception as e:actual={'exception':type(e).__name__,'message':str(e)}
 rows.append({'id':name,'scope':'PRIVATE_HELPER_ONLY','pass':actual==c['expected'],'actual':actual,'expected':c['expected']})
report={'schema':'quorum/independent-reading-probe-run/1','status':'PASS' if all(r['pass'] for r in rows) else 'FAILED','assertions_enabled':__debug__,'independent_controls_pin':pin(controls.read_bytes()),'independent_controls_path':str(controls),'source_pins':{n:pin(pathlib.Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/tools',n).read_bytes()) for n in ('transport_quorum_reading.py','transport_quorum_context.py','transport_quorum_impact.py','transport_quorum_claim.py','transport_quorum_source.py','transport_quorum_input.py','transport_quorum_shape.py','transport_quorum_graph.py','transport_quorum_body.schema.json')},'cases':rows}
p=pathlib.Path(sys.argv[1]);p.open('xb').write(can(report)+b'\n');print(report['status'],len(rows),'cases','failed',[(r['id'],r['actual'].get('error') if type(r['actual'])is dict else type(r['actual']).__name__) for r in rows if not r['pass']]);print(str(p),pin(p.read_bytes()));raise SystemExit(0 if report['status']=='PASS' else 1)
