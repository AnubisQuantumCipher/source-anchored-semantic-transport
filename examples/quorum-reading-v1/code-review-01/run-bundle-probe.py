import base64,hashlib,json,pathlib,sys
sys.path.insert(0,'/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/tools')
import transport_quorum_reading as reading
R=pathlib.Path('/dev/shm/semantic-transport-reading-20261029');D=R/'code-review-01'
def can(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def held(v):return tuple((x['event_id'],x['sha256'],x['byte_length']) for x in v['items'])
p=R/'R02_MANUAL_SUPPORT';raw=(p/'body.json').read_bytes();o=json.loads((p/'originals.json').read_bytes());originals=tuple((v['alias_id'],v['key'],base64.b64decode(v['base64'])) for v in o['items']);u=held(json.loads((p/'held-update-pins.json').read_bytes()));captured=[];target=reading.context.impact.claims._validated_claims.__code__
def observer(frame,event,value):
 if event=='return' and frame.f_code is target:captured.append((value[2],can(value[2])))
prior=sys.getprofile()
try:
 sys.setprofile(observer)
 bundle=reading.context._validated_context(raw,originals,u)
finally:sys.setprofile(prior)
actual={'claim_call_returns':len(captured),'same_actual_claim_object':len(captured)==1 and bundle[2] is captured[0][0],'actual_claim_contents_unchanged':len(captured)==1 and can(captured[0][0])==captured[0][1],'context_tuple_length':len(bundle),'impact_compatibility_tuple_length':len(reading.context.impact._validated_impact(raw,originals,u))}
e=json.loads((D/'bundle-probe-expectation.json').read_bytes());report={'schema':'quorum/independent-reading-bundle-probe-run/1','status':'PASS' if actual==e['expected'] else 'FAILED','assertions_enabled':__debug__,'actual':actual,'expected':e['expected'],'source_pins':{v:hashlib.sha256(pathlib.Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028/tools',v).read_bytes()).hexdigest() for v in ('transport_quorum_reading.py','transport_quorum_context.py','transport_quorum_impact.py','transport_quorum_claim.py')}};out=pathlib.Path(sys.argv[1]);out.open('xb').write(can(report)+b'\n');print(report['status'],actual,hashlib.sha256(out.read_bytes()).hexdigest());raise SystemExit(0 if report['status']=='PASS' else 1)
