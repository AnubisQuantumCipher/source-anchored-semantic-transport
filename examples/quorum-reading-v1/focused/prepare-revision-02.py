"""Create-only fixture representation repair; no product imports/runs.
Preserves original46, all manual status/count/dispositions and negative bad pins.
Only sort Manifest.rule_specs by canonical whole-Pin bytes, cascade matching full
Manifest pins in Readings/Runs, and mechanically update successful Body pins.
"""
import copy
import hashlib
import json
from pathlib import Path

BASE=Path('/dev/shm/semantic-transport-reading-controls-20261029')
OUT=BASE/'revision-02'
EXPECTED='5e197b6b1bb63eec9aa54338d649ea2e093a994b246e12b33e4ec4ae98977938'


def C(v):return json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()


def pin(p):
    b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}


def rp(r):
    b=C(r);return {'id':r['id'],'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}


def save(path,value):
    with path.open('xb') as stream:stream.write(C(value))
    return pin(path)


oldpath=BASE/'handwritten-expectations.json'
if pin(oldpath)['sha256']!=EXPECTED:raise ValueError('first expectations changed')
old=json.loads(oldpath.read_bytes());new=copy.deepcopy(old);changes=[]
OUT.mkdir();(OUT/'raw').mkdir()
for oldcase,newcase in zip(old['cases'],new['cases']):
    rawpath=Path(oldcase['body_raw']['path'])
    if pin(rawpath)!=oldcase['body_raw']:raise ValueError('old candidate changed')
    body=json.loads(rawpath.read_bytes());entries=[]
    for m in body['input_manifests']:
        oldpin=rp(m);oldrules=copy.deepcopy(m['rule_specs'])
        m['rule_specs']=sorted(m['rule_specs'],key=C);newpin=rp(m)
        entries.append({'path':'input_manifests/'+m['id']+'/rule_specs','before':oldrules,'after':m['rule_specs']})
        for category in ('readings','run_evidence'):
            for r in body[category]:
                previous=copy.deepcopy(r['input_manifest'])
                if previous==oldpin:
                    r['input_manifest']=copy.deepcopy(newpin)
                    entries.append({'path':category+'/'+r['id']+'/input_manifest','before':previous,'after':newpin})
                elif previous['id']==m['id']:
                    entries.append({'path':category+'/'+r['id']+'/input_manifest','deliberately_invalid_pin_preserved':previous})
    raw=C(body);newpath=OUT/'raw'/(newcase['id']+'.body.json')
    with newpath.open('xb') as stream:stream.write(raw)
    newcase['body_raw']=pin(newpath)
    expected=newcase['handwritten_expected_complete_result']
    if expected['status']=='ok':expected['body_pin']={'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
    oldmeaning=copy.deepcopy(oldcase['handwritten_expected_complete_result']);newmeaning=copy.deepcopy(expected)
    oldmeaning.pop('body_pin',None);newmeaning.pop('body_pin',None)
    if oldmeaning!=newmeaning:raise ValueError('manual expected meaning changed')
    for field in ('manual','manual_error','manual_stage','manual_rationale','specification'):
        if oldcase.get(field)!=newcase.get(field):raise ValueError('manual judgment changed')
    changes.append({'id':newcase['id'],'old_exact_bytes':oldcase['body_raw'],'new_exact_bytes':newcase['body_raw'],
        'mechanical_changes':entries,'manual_expected_fields_unchanged_except_mechanical_body_pin':True})
new['classification']='PRE_SECOND_EXECUTION_FROZEN_DEVELOPMENT_FIXTURE_REPAIR'
new['fixture_repair']='Original46 first failures retained. C-order fixture-only repair, not product repair or heldout qualification. Manual judgments unchanged.'
newpin=save(OUT/'handwritten-expectations.json',new)
repair={'classification':'DEVELOPMENT_FIXTURE_CANONICAL_ORDER_REPAIR','first_expected':pin(oldpath),
    'first_product_run':pin(BASE/'product-first-run.json'),'diagnosis':pin(BASE/'first-failure-fixture-diagnosis.json'),
    'contract_order_source':pin(Path('/dev/shm/semantic-transport-context-controls-20261029/at-fixture-freeze-contract.json')),
    'repair_constructor':pin(BASE/'prepare-revision-02.py'),'changes':changes,
    'qualification':'No product output used to author manual judgments; all old/new exact canonical bytes retained. Independent review required before second execution.'}
repairpin=save(OUT/'repair-record.json',repair)
freeze={'phase':'PRE_SECOND_EXECUTION_PRE_ORACLE_FROZEN','expectations':newpin,
    'candidates':[c['body_raw'] for c in new['cases']],'source_pins':[pin(BASE/'at-fixture-freeze-contract.json'),pin(BASE/'at-fixture-freeze-design-addendum.json'),repairpin]}
freezepin=save(OUT/'pre-oracle-freeze.json',freeze)
print(json.dumps({'cases':len(new['cases']),'expectations':newpin,'repair':repairpin,'freeze':freezepin}))
