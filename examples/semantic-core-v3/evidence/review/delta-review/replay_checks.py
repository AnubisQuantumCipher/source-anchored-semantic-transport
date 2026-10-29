"""Independent replay-guard control tests, with explicit mocked courier boundary."""
import copy
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
REPO=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
sys.dont_write_bytecode=True
sys.path[:0]=[str(REPO/'tools'),str(REPO/'install')]
import transport_core as core
import transport_core_bridge as bridge


def fixture(present):
    source=b'Explicit formal source.'
    symbols=[{'id':'p','kind':'predicate','arity':0,'binding':{'kind':'name','name':'p'}}]
    plan={'schema':core.PLAN,'translation':'declared','symbols':symbols,'tree':{
          'schema':core.GRAMMAR,'nodes':[{'op':'pred','predicate':'p','terms':[]}],'root':0}}
    model=None if not present else core.canonical({'schema':core.MODEL,'symbols':symbols,'tuples':[]})
    dependencies={'schema':'replay-unit-test-only'}
    payload=bridge.envelope(source,core.canonical(plan),model,dependencies)
    node={'node':0,'sort':'FACT','truth':'UNRESOLVED','outcome':'UNKNOWN'}
    original={'status':'NOT_EVALUATED','nodes':[],'result':None} if not present else {
       'status':'EVALUATED_SUPPLIED_MODEL','nodes':[node],'result':node,
       'frame_sha256':'d'*64,'native_sha256':'f'*64}
    recovered=dict(copy.deepcopy(original),package_identity='STS1:'+'e'*64,
                   model_sha256=None if model is None else core.sha(model))
    return source,plan,model,dependencies,payload,original,recovered


def run_case(name,mutate=None,present=True):
    source,plan,model,deps,payload,original,recovered=fixture(present)
    if mutate is not None:mutate(recovered)
    directory=HERE/name
    directory.mkdir(mode=0o700)
    mapping={'roundtrip-SOURCE.bin':source,'roundtrip-CORE.bin':payload,
       'roundtrip-MODEL.bin':model,'share.txt':b'share','meaning.zip':b'archive'}
    observed=None
    try:
        with patch.object(bridge,'pinned'),patch.object(bridge,'runtime',return_value=deps), \
             patch.object(bridge,'evaluate',return_value=original),patch.object(bridge,'call',return_value=b''), \
             patch.object(bridge,'decode',return_value=recovered), \
             patch.object(bridge,'read_regular',side_effect=lambda path,cap:mapping[path.name]):
            observed=bridge.encode(source,core.canonical(plan),model,Path('/mock/decoder'),'a'*64,
                Path('/mock/native'),'f'*64,directory)
        error=None
    except ValueError as exc:error=str(exc)
    if mutate is not None:
        passed=error=='CORE_REPLAY_MISMATCH' and not (directory/'replay.json').exists()
    else:
        receipt=json.loads((directory/'replay.json').read_text())
        status='ORIGINAL_RECOVERED_VALUES_MATCH' if present else 'NOT_EVALUATED'
        passed=observed['replay']==receipt['status']==status and receipt['execution_authority']=='NONE' \
             and receipt['world_truth']=='NOT_CERTIFIED' and receipt['source_sha256']==core.sha(source) \
             and receipt['payload_sha256']==core.sha(payload) and receipt['native_sha256']=='f'*64 \
             and receipt['model_sha256']==recovered['model_sha256']
    return {'id':name,'pass':passed,'error':error,'result':observed}


if __name__=='__main__':
    results=[run_case('matching_values'),run_case('absent_model',present=False),
      run_case('status_changed',lambda r:r.update(status='NOT_EVALUATED')),
      run_case('nodes_changed',lambda r:r.update(nodes=[])),
      run_case('result_changed',lambda r:r.update(result=None))]
    source,plan,_,_,_,_,_=fixture(False)
    plan['schema']='unsupported'
    try:
        bridge.evaluate(plan,None,source,None,None,None,'missing-model')
        error=None
    except ValueError as exc:error=str(exc)
    results.append({'id':'invalid_plan_missing_model','pass':error=='CORE_PLAN_VERSION','error':error})
    report={'schema':'semantic-core-independent-replay-guard/1','results':results,
       'status':'PASS' if all(r['pass'] for r in results) else 'FAILED',
       'boundary':'Mocked courier/native objects test only replay comparison and receipt control; no package/native execution claimed',
       'source_sha256':{name:core.sha((REPO/'tools'/name).read_bytes()) for name in ['transport_core.py','transport_core_bridge.py']}}
    with (HERE/'replay-results.json').open('x') as stream:json.dump(report,stream,sort_keys=True,indent=2);stream.write('\n')
    print(json.dumps({'status':report['status'],'cases':len(results),'failed':[r['id'] for r in results if not r['pass']]}))
