import base64,copy,hashlib,inspect,json,pathlib,sys
sys.path.insert(0,'/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/tools')
import transport_quorum_context as product
import transport_quorum_input as metadata
R=pathlib.Path('/dev/shm/semantic-transport-context-bindings-20261029');D=R/'code-review-01';C=pathlib.Path('/dev/shm/semantic-transport-context-controls-20261029')
def can(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def pin(v):return {'bytes':len(v),'sha256':hashlib.sha256(v).hexdigest()}
def load_compact(base,case):
 d=base/case['id'];files={}
 for name,p in case['files'].items():
  raw=(d/name).read_bytes();assert pin(raw)==p;files[name]=raw
 o=json.loads(files['originals.json']);originals=tuple((v['alias_id'],v['key'],base64.b64decode(v['base64'],validate=True)) for v in o['items']);h=json.loads(files['held-update-pins.json']);held=tuple(tuple(v[k] for k in ('event_id','sha256','byte_length')) if type(v)is dict else v for v in h['items']);return files['body.json'],originals,held,json.loads(files['expected.json'])
def load_focused(case):
 raw=pathlib.Path(case['body_raw']['path']).read_bytes();assert pin(raw)=={k:case['body_raw'][k] for k in ('bytes','sha256')};originals=tuple((v['alias'],v['key'],bytes.fromhex(v['immutable_bytes_hex'])) for v in case['originals_exact_tuple_recipe']);held=tuple(tuple(v[k] for k in ('event_id','sha256','byte_length')) if type(v)is dict else v for v in case['held_update_pins_exact_tuple_recipe']['items']);return raw,originals,held,case['handwritten_expected_complete_result']
rows=[];callbacks=[]
class HostTuple(tuple):
 def __iter__(self):callbacks.append('iter');raise RuntimeError('HOST_CALLBACK')
 def __len__(self):callbacks.append('len');raise RuntimeError('HOST_CALLBACK')
 def __getitem__(self,k):callbacks.append('getitem');raise RuntimeError('HOST_CALLBACK')
def compare(name,args):
 raw,originals,held,expected=args
 try:actual=product.check_context_bindings(raw,originals,held)
 except Exception as error:actual={'exception':type(error).__name__,'message':str(error)}
 rows.append({'id':name,'pass':actual==expected,'actual':actual,'expected':expected})
author=json.loads((R/'oracle.json').read_bytes())
focused=json.loads((C/'handwritten-expectations.json').read_bytes())
for case in author['cases']:compare('author/'+case['id'],load_compact(R,case))
for case in focused['cases']:compare('independent55/'+case['id'],load_focused(case))
extra=R/'review-01'/'complementary-controls'
for case in json.loads((extra/'oracle.json').read_bytes())['cases']:compare('review5/'+case['id'],load_compact(extra,case))
for case in json.loads((D/'additional-probe-expectations.json').read_bytes())['cases']:
 name=case['id'];expected=case['expected'];actual=None;callbacks.clear()
 try:
  if name.startswith('H'):
   raw,o,h,literal=load_compact(R,author['cases'][0])
   if name=='H01_NO_PARSED_BODY_BYPASS':raw=json.loads(raw)
   elif name=='H02_HELD_TUPLE_SUBCLASS':h=HostTuple(h)
   elif name=='H03_ORIGINALS_TUPLE_SUBCLASS':o=HostTuple(o)
   elif name=='H04_BAD_RAW_BEFORE_HOST':raw=b'{';o=HostTuple(o);h=HostTuple(h)
   elif name=='H05_OWNED_OUTPUT_AND_API':
    raw,o,h,literal=load_focused(focused['cases'][0]);before=[(n,can(k),b) for n,k,b in o];value=product.check_context_bindings(raw,o,h);snapshot=can(value);unchanged=before==[(n,can(k),b) for n,k,b in o]
    for _,key,_ in o:key['bytes']=999
    actual={'output_matches_literal':value==literal,'caller_unchanged_before_mutation':unchanged,'output_unchanged_after_mutation':can(value)==snapshot,'api':list(inspect.signature(product.check_context_bindings).parameters)}
   if actual is None:actual=product.check_context_bindings(raw,o,h)
  elif name=='R01_SORT_EXACT_AGGREGATE_BOUND':
   value=['X'*32766,'Y'*32766];actual={'same_order':product._ordered(value)==value}
  elif name=='R02_SORT_AGGREGATE_OVERFLOW':product._ordered(['X'*32766,'Y'*32766,''])
  elif name=='R03_OUTPUT_BOUND_EXPLICIT':
   body={'registry':{'id':'REGISTRY'},'tasks':[{'id':'TASK'}]};index={n:(kind,{},dict(id=n,sha256='0'*64,bytes=0)) for n,kind in [('REGISTRY','Registry'),('TASK','TaskView')]};product._result(body,{'body_pin':{'sha256':'X'*32768,'bytes':0}},index,[],[])
  elif name=='R04_CANONICAL_SCALAR_ORDER':actual=product._ordered(['S\n','S:'])
  elif name=='R05_CLAIM_PAIR_ORDER':actual=product._ordered([{'id':'A:B','revision':'A'},{'id':'A','revision':'Z'}],'claim')
 except metadata.InputError as error:actual=metadata._error(error)
 except Exception as error:actual={'exception':type(error).__name__,'message':str(error)}
 rows.append({'id':name,'pass':actual==expected and not callbacks,'actual':actual,'expected':expected,'host_callbacks':list(callbacks),'scope':'PRIVATE_HELPER_ONLY' if name.startswith('R') else 'PUBLIC_BOUNDARY'})
report={'schema':'quorum/independent-context-first-probe-run/1','status':'PASS' if all(r['pass'] for r in rows) else 'FAILED','assertions_enabled':__debug__,'source_pins':{n:pin(pathlib.Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/tools',n).read_bytes()) for n in ('transport_quorum_context.py','transport_quorum_impact.py','transport_quorum_claim.py','transport_quorum_source.py','transport_quorum_input.py','transport_quorum_shape.py','transport_quorum_graph.py','transport_quorum_body.schema.json')},'extra_expectation_pin':pin((D/'additional-probe-expectations.json').read_bytes()),'cases':rows}
p=pathlib.Path(sys.argv[1]);p.open('xb').write(can(report)+b'\n');print(report['status'],len(rows),'cases',[(v['id'],v['actual']) for v in rows if not v['pass']]);print(str(p),pin(p.read_bytes()));raise SystemExit(0 if report['status']=='PASS' else 1)
