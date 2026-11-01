"""Focused receipt-validation probes; never writes or regenerates acceptance."""
import gzip
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
ROOT=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
EXAMPLE=HERE/'example'
sys.dont_write_bytecode=True
spec=importlib.util.spec_from_file_location('reviewed_checker',HERE/'checker-01.py')
CHECK=importlib.util.module_from_spec(spec)
spec.loader.exec_module(CHECK)
NATIVE='aa04e9aca4afa2663202eac7085329ac5e1f331057b418d3339c2ed17309c23b'
RESULTS=[]


def mutate_json(path,change):
    raw=path.read_bytes()
    value=json.loads(gzip.decompress(raw) if path.suffix=='.gz' else raw)
    change(value)
    edited=json.dumps(value,sort_keys=True,indent=2).encode()+b'\n'
    path.write_bytes(gzip.compress(edited,mtime=0) if path.suffix=='.gz' else edited)


def probe(name,action,relative=None,mutation=None,expected='REFUSED'):
    path=None if relative is None else EXAMPLE/relative
    original=None if path is None else path.read_bytes()
    try:
        if path is not None:mutation(path)
        try:
            action()
            actual,error='ADMITTED',None
        except (ValueError,OSError,KeyError,TypeError) as exc:
            actual,error='REFUSED',{'type':type(exc).__name__,'reason':str(exc)}
        RESULTS.append({'id':name,'expected':expected,'actual':actual,'pass':actual==expected,'error':error})
    finally:
        if path is not None:path.write_bytes(original)


def run():
    held=lambda:CHECK.held_product(EXAMPLE)
    failures=lambda:CHECK.retained_controls(ROOT,EXAMPLE)
    controls=lambda:CHECK.independent_controls(ROOT,EXAMPLE,NATIVE)
    native=lambda:CHECK.native_sources(ROOT,EXAMPLE)
    runtime=lambda:CHECK.runtime_sources(ROOT,EXAMPLE,NATIVE)
    for name,call in [('held_baseline',held),('failure_baseline',failures),('controls_baseline',controls),('native_baseline',native),('runtime_baseline',runtime)]:
        probe(name,call,expected='ADMITTED')
    for file in ('meaning.zip','lexicon.md','share.txt','core-envelope.json','recipient-result.json','replay.json','source.txt','model.json'):
        probe('held_mutation_'+file,held,file,lambda p:p.write_bytes(p.read_bytes()+b'X'))
    probe('held_coverage',held,'evidence/integration/receipt-04.json',
          lambda p:mutate_json(p,lambda v:v['held_fixture'].pop('archive')))
    probe('schema_failures_erased',failures,'evidence/review/schema-review/results.json.gz',
          lambda p:mutate_json(p,lambda v:[row.update({'pass':True}) for row in v['cases']]))
    probe('process_failure_erased',failures,'evidence/review/process-review/results01.json',
          lambda p:mutate_json(p,lambda v:[row.update({'pass':True}) for row in v['cases']]))
    probe('corrected_proof03_pin_replaced',failures,'evidence/review/delta-review/public-review-receipt-final-02.json',
          lambda p:mutate_json(p,lambda v:next(row for row in v['retained_failures'] if row['id']=='PROOF-03').update(sha256='eb4499a33700abec16c3942482841c42525d49092288a4c252dc358ff0073d87')))
    probe('provenance_record_changed',failures,'evidence/review/delta-review/provenance-correction-01.json',lambda p:p.write_bytes(p.read_bytes()+b'\n'))
    probe('control_failure',controls,'evidence/final-controls-normal.json.gz',
          lambda p:mutate_json(p,lambda v:v['cases'][0].update({'pass':False})))
    probe('control_native_pin',controls,'evidence/final-controls-optimized.json.gz',
          lambda p:mutate_json(p,lambda v:v.update(native_sha256='a'*64)))
    probe('runtime_dependency_omitted',runtime,'core-envelope.json',
          lambda p:mutate_json(p,lambda v:v['runtime']['files'].pop('transport_core_process.py')))
    probe('runtime_dependency_pin',runtime,'core-envelope.json',
          lambda p:mutate_json(p,lambda v:v['runtime']['files'].update({'transport_core.py':'a'*64})))
    probe('proof_source_byte',native,'evidence/native/proof-04-sources/evaluation/src/transport_eval.ads',lambda p:p.write_bytes(p.read_bytes()+b'\n'))
    positive=EXAMPLE/'evidence/native/proof-04-summary.out'
    probe('proof03_replaced_with_proof04',native,'evidence/native/proof-03-summary.out',lambda p:p.write_bytes(positive.read_bytes()))


if __name__=='__main__':
    run()
    report={'schema':'semantic-core-independent-receipt-probes/1','results':RESULTS,
      'status':'PASS' if all(row['pass'] for row in RESULTS) else 'FAILED',
      'checker_sha256':hashlib.sha256((HERE/'checker-01.py').read_bytes()).hexdigest(),
      'boundary':'Focused invariants only; the provisional top receipt is not regenerated or accepted under any mutation. One copied example; no historical checkout duplicated.'}
    with (HERE/'results01.json').open('x') as stream:json.dump(report,stream,sort_keys=True,indent=2);stream.write('\n')
    print(json.dumps({'status':report['status'],'cases':len(RESULTS),'failed':[row['id'] for row in RESULTS if not row['pass']]}))
