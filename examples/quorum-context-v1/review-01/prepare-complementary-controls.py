import copy,hashlib,json,pathlib
R=pathlib.Path('/dev/shm/semantic-transport-context-bindings-20261029');D=R/'review-01'/'complementary-controls';D.mkdir(exist_ok=True)
def can(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()
def pin(b):return {'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}
specs=[('P01_ALL_SHAPES_BEFORE_COLLISION','C05_DERIVED_CLAIM_PIN_COLLISION','CONTEXT_CLAIM_PIN_ID_SHAPE','CONTEXT_IDENTITIES','Early derived Claim_A:V1 collides with Policy; later Z32-derived pin is too long. All shape checks must precede derived collision checks.'),('P02_NONCLAIM_DUP_BEFORE_SHAPE','C03_NONCLAIM_ID_COLLISION','CONTEXT_ID_DUPLICATE','CONTEXT_IDENTITIES','Duplicate Registry/Policy id precedes later malformed derived Claim ID.'),('P03_RAW_LABEL_BEFORE_SHAPE','C04_RAW_CLAIM_LABEL_COLLISION','CONTEXT_CLAIM_LABEL_COLLISION','CONTEXT_IDENTITIES','Raw Claim_A label collision with Policy precedes malformed later derived Claim ID.'),('P04_ROSTER_ROW_SEAT_BEFORE_LATER_PIN','C26_TASK_CONTEXT_UNION','CONTEXT_TASK_ROSTER_SEAT','CONTEXT_TASK','First C(complete roster object) row Claim_Z has missing Seat; later Claim_A row stale ClaimKey. Per-row pin then Seat requires first-row Seat refusal.'),('P05_ORDER_BEFORE_SEAT_ORIGIN','C13_MANUAL_MODEL_LABEL','CONTEXT_ARRAY_ORDER','CONTEXT_ARRAY_ORDER','Reverse Body.rules while manual Seat model label remains invalid: array-order stage must precede Seat origin stage.')]
rows=[]
for name,base,code,stage,reason in specs:
 b=json.loads((R/base/'body.json').read_bytes())
 if name in ('P01_ALL_SHAPES_BEFORE_COLLISION','P02_NONCLAIM_DUP_BEFORE_SHAPE','P03_RAW_LABEL_BEFORE_SHAPE'):
  b['claims'].append({'id':'Z'*32,'revision':'V1','task_view_id':'TASK','payload':{'profile':'OPAQUE_PROSE_V1','text':'Manual later invalid derived address.','uncertainty':'','omitted_scope':''},'selector_ids':[],'dependency_ids':[],'origin_kind':'MANUAL_DEVELOPMENT_FIXTURE','attribution':'','conflict_claims':[]})
 elif name=='P04_ROSTER_ROW_SEAT_BEFORE_LATER_PIN':
  roster=b['tasks'][0]['claim_rosters'];assert roster[0]['claim']['claim_id']=='CLAIM_Z';roster[0]['expected_seat_ids']=['MISSING_SEAT'];roster[1]['claim']['sha256']='0'*64
 elif name=='P05_ORDER_BEFORE_SEAT_ORIGIN':b['rules'].reverse()
 target=D/name;target.mkdir();files={}
 values={'body.json':can(b),'originals.json':(R/base/'originals.json').read_bytes(),'held-update-pins.json':(R/base/'held-update-pins.json').read_bytes(),'expected.json':can({'status':'error','stage':stage,'error':code})}
 for filename,raw in values.items():(target/filename).open('xb').write(raw);files[filename]=pin(raw)
 rows.append({'id':name,'base_literal':base,'base_body_pin':pin((R/base/'body.json').read_bytes()),'manual_rationale':reason,'files':files})
p=D/'oracle.json';p.open('xb').write(can({'schema':'quorum/independent-context-complementary-oracle/1','status':'MANUAL_EXPECTATIONS_FROZEN_BEFORE_COMPONENT_IMPLEMENTATION','contract_pin':pin((R/'contract.json').read_bytes()),'qualification':'Five literal multi-fault refusal controls, hand-authored codes/stages from reviewed contract. No future checker imported or executed, no full replay acceptance. Original immutable source/held pin recipes copied from exact author bases.','cases':rows})+b'\n');print(str(p),pin(p.read_bytes()))
