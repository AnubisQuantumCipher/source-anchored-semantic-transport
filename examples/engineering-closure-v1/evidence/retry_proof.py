"""One bounded continuation of the two incomplete full-project proof runs."""
import importlib.util
import json
from pathlib import Path

P=Path('/dev/shm/semantic-transport-proof-closure-20261029')
spec=importlib.util.spec_from_file_location('closure_runner',P/'run.py')
r=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def main():
    env,commands,unused=r.configuration()
    selected=[(label+'-02',args) for label,args in commands if label in ('core-proof','evaluation-proof')]
    for label in ('core-proof','evaluation-proof'):
        prior=json.loads((P/(label+'.json')).read_text())
        r.need(prior['status']=='REFUSED_TIMEOUT' and prior['exit_code']==-9,'retry requires confirmed terminal timeout')
    source=json.loads((P/'source-before.json').read_text())
    r.need(source==r.files_snapshot(r.W,list(source)),'source changed')
    r.need(source==r.files_snapshot(P/'source',list(source)),'isolated source changed')
    record=dict(schema='transport/native-proof-continuation/1',
        commands=selected,source_manifest=r.pin((P/'source-before.json').read_bytes()),
        first_attempt_state=r.pin((P/'attempt-01-proof-state.tar.gz').read_bytes()),
        driver=r.pin((P/'retry_proof.py').read_bytes()),
        reason='Two confirmed terminal 120-second timeouts, no complete reports. Retain first raw logs and proof working state; continue unchanged full -U commands with existing GNATprove incremental cache.',
        proof_obligations='UNCHANGED; no unit filter, prover-level escalation, assertion/contract weakening, or product runtime bound changes.',
        budget='One further 120-second attempt per incomplete project within prepaid tranche06; no automatic repeat.',
        status='ADMITTED_NOT_EXECUTED')
    r.save(r.L/'native-proof-continuation-admission-01.json',record)
    r.save(P/'continuation-admission.json',record)
    for label,args in selected:
        r.execute(label,args,env)
    r.save(P/'source-after-continuation.json',r.files_snapshot(r.W,list(source)))
    r.save(P/'installed-after-continuation.json',r.installed_snapshot())


if __name__=='__main__':
    main()
