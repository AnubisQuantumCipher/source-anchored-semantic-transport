"""Independent envelope mutation checks; no decoder or model service invocation."""
import copy
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
HERE=Path(__file__).resolve().parent
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT/'tools'))
sys.path.insert(0,str(ROOT/'install'))
import transport_core as core
import transport_core_bridge as bridge


def run():
    source=b'Explicit formal reading source.'
    symbols=[{'id':'p','kind':'predicate','arity':0,'binding':{'kind':'name','name':'p'}}]
    plan={'schema':core.PLAN,'symbols':symbols,'translation':'declared','tree':{
          'schema':core.GRAMMAR,'nodes':[{'op':'pred','predicate':'p','terms':[]}],'root':0}}
    model={'schema':core.MODEL,'symbols':symbols,'tuples':[{'predicate':'p','terms':[],'truth':'KNOWN_TRUE'}]}
    raw=core.canonical(model)
    deps={'schema':'independent-test-runtime','native_sha256':'a'*64}
    envelope=bridge.envelope(source,core.canonical(plan),raw,deps)
    cases=[('valid_envelope','ADMITTED',envelope,source,raw,deps),
      ('changed_source','REFUSED',envelope,source+b'x',raw,deps),
      ('changed_model','REFUSED',envelope,source,raw.replace(b'KNOWN_TRUE',b'KNOWN_FALSE'),deps),
      ('removed_model','REFUSED',envelope,source,None,deps),
      ('changed_runtime','REFUSED',envelope,source,raw,dict(deps,native_sha256='b'*64)),
      ('noncanonical_payload','REFUSED',envelope+b'\n',source,raw,deps)]
    absent=bridge.envelope(source,core.canonical(plan),None,deps)
    cases.extend([('absent_model_envelope','ADMITTED',absent,source,None,deps),
                  ('inserted_model','REFUSED',absent,source,raw,deps)])
    for name,change in [('operator',lambda v:v['operators']['entries'].update(must='permission')),
       ('source_digest',lambda v:v.update(source_sha256='c'*64)),
       ('model_digest',lambda v:v['model'].update(sha256='d'*64)),
       ('model_source',lambda v:v['model'].update(source='SOURCE')),
       ('extra_envelope_field',lambda v:v.update(authorizes=True)),
       ('envelope_version',lambda v:v.update(schema='transport/core-envelope/4')),
       ('plan_version',lambda v:v['plan'].update(schema='transport/core-plan/2')),
       ('translation_receipt',lambda v:v['translation'].update(status='CHECKED_CONTROLLED_TRANSLATION'))]:
        value=json.loads(envelope)
        change(value)
        cases.append((name,'REFUSED',core.canonical(value),source,raw,deps))
    results=[]
    for name,expected,payload,src,finite,runtime in cases:
        try:
            bridge.check_envelope(payload,src,finite,runtime)
            actual,error='ADMITTED',None
        except (ValueError,UnicodeError,TypeError,KeyError) as exc:
            actual,error='REFUSED',{'type':type(exc).__name__,'reason':str(exc)}
        results.append({'id':name,'expected':expected,'observed':actual,'pass':actual==expected,
            'error':error,'envelope':payload.decode(),'source_hex':src.hex(),
            'model':None if finite is None else finite.decode(),'runtime':runtime})
    absent_result=bridge.evaluate(plan,None,source,None,None,None,'absent-model')
    results.append({'id':'no_model_no_native_call','expected':{'status':'NOT_EVALUATED','nodes':[],'result':None},
       'observed':absent_result,'pass':absent_result=={'status':'NOT_EVALUATED','nodes':[],'result':None}})
    return results


if __name__=='__main__':
    paths=['tools/transport_core.py','tools/transport_core_bridge.py','tools/transport_core_cli.py',
           'tools/transport_core_language.py','evaluation/src/transport_eval.ads',
           'evaluation/src/transport_eval.adb','evaluation/src/transport_core_parse.ads',
           'evaluation/src/transport_core_parse.adb','evaluation/src/transport_core_native.adb']
    pins={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in paths}
    results=run()
    assert pins=={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in paths}
    report={'schema':'semantic-core-independent-bridge-checks/1','results':results,'source_pins':pins,
       'status':'PASS' if all(r['pass'] for r in results) else 'FAILED',
       'limits':'Envelope helpers and missing-model branch tested; no whole-package decoder run or source-entailment claim'}
    path=HERE/'bridge-results.json'
    with path.open('xb') as stream:stream.write(core.canonical(report)+b'\n')
    path.chmod(0o600)
    print(json.dumps({'status':report['status'],'cases':len(results),'failed':[r['id'] for r in results if not r['pass']]}))
