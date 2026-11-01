"""Actual decode/evaluate metadata branch; courier is mocked and native is forbidden."""
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


def run():
    source=b'Explicit formal source.'
    symbols=[{'id':'p','kind':'predicate','arity':0,'binding':{'kind':'name','name':'p'}}]
    value={'schema':core.PLAN,'translation':'declared','symbols':symbols,'tree':{
          'schema':core.GRAMMAR,'nodes':[{'op':'pred','predicate':'p','terms':[]}],'root':0}}
    deps={'schema':'mock-courier-metadata-test'}
    payload=bridge.envelope(source,core.canonical(value),None,deps)
    root=HERE/'missing-model-metadata'
    root.mkdir(mode=0o700)
    with patch.object(bridge,'pinned'),patch.object(bridge,'runtime',return_value=deps), \
         patch.object(bridge,'recover',return_value=({'SOURCE':source,'CORE':payload},'STS1:'+'a'*64)), \
         patch.object(bridge,'read_regular',return_value=b'fixed-pair'), \
         patch.object(bridge,'call',side_effect=RuntimeError('native must not run without model')):
        result=bridge.decode(Path('/mock/share'),Path('/mock/archive'),Path('/mock/decoder'),
               'b'*64,Path('/mock/native'),'c'*64,root)
    expected={'status':'NOT_EVALUATED','semantic_scope':'NONE_NO_MODEL','nodes':[],
         'result':None,'model_sha256':None,'reading_status':'PROPOSED_STRUCTURED_READING',
         'execution_authority':'NONE','world_truth':'NOT_CERTIFIED','interpretation_entailment':'UNPROVEN',
         'entailment':'NOT_CHECKED','translation':'NOT_IN_FRAGMENT'}
    issues=[key for key,value in expected.items() if result.get(key)!=value]
    retained=json.loads((root/'receive-result.json').read_text())
    if retained!=result:issues.append('exact_result_readback')
    return {'status':'PASS' if not issues else 'FAILED','issues':issues,'expected':expected,'result':result,
       'boundary':'Actual decode/envelope/evaluate branches; courier and binary-pinning helpers mocked. Any native call raises. No real package or native run claimed.',
       'bridge_sha256':core.sha((REPO/'tools/transport_core_bridge.py').read_bytes())}


if __name__=='__main__':
    report=run()
    with (HERE/'missing-model-metadata-results.json').open('x') as stream:json.dump(report,stream,sort_keys=True,indent=2);stream.write('\n')
    print(json.dumps({'status':report['status'],'issues':report['issues'],'bridge_sha256':report['bridge_sha256']}))
