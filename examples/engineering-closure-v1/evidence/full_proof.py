"""Finite proof-only allowance corrected from historical measured run durations."""
import importlib.util
import json
import os
from pathlib import Path
import resource
import subprocess
import time

P=Path('/dev/shm/semantic-transport-proof-closure-20261029')
spec=importlib.util.spec_from_file_location('closure_runner',P/'run.py')
r=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
from transport_install_support import _kill_group


def limits():
    for kind,value in ((resource.RLIMIT_AS,1073741824),(resource.RLIMIT_CPU,600),
                       (resource.RLIMIT_FSIZE,33554432),(resource.RLIMIT_NOFILE,128)):
        resource.setrlimit(kind,(value,value))


def execute(label,args,env):
    r.need(time.time()<1793279035,'prepaid allowance too short')
    r.size_gate()
    print('START '+label,flush=True)
    started=time.monotonic_ns()
    status='REFUSED_TIMEOUT'
    with (P/(label+'.stdout')).open('xb') as out, (P/(label+'.stderr')).open('xb') as err:
        process=subprocess.Popen(args,cwd=P/'source',env=env,stdin=subprocess.DEVNULL,
            stdout=out,stderr=err,start_new_session=True,close_fds=True,preexec_fn=limits)
        for index in range(6001):
            if max(os.fstat(out.fileno()).st_size,os.fstat(err.fileno()).st_size)>1048576:
                status='REFUSED_OUTPUT_BOUND'
                break
            if process.poll() is not None:
                status='SUCCESS' if process.returncode==0 else 'EXIT_NONZERO'
                break
            if time.monotonic_ns()-started>=600000000000:
                break
            if index%50==0:
                try:
                    r.size_gate()
                except ValueError:
                    status='REFUSED_SCRATCH_BOUND'
                    break
            time.sleep(0.1)
        descendants,clean=_kill_group(process)
        if not clean:
            status+='+CLEANUP_UNVERIFIED'
        elif descendants and status=='SUCCESS':
            status='REFUSED_DESCENDANTS'
    value=dict(argv=args,cwd=str(P/'source'),environment=env,status=status,
        exit_code=process.returncode,elapsed_ns=time.monotonic_ns()-started,
        stdout=r.pin((P/(label+'.stdout')).read_bytes()),
        stderr=r.pin((P/(label+'.stderr')).read_bytes()),storage_after=r.size_gate())
    r.save(P/(label+'.json'),value)
    print(label+' '+status,flush=True)


def admit(commands):
    previous={}
    for label in ('core-proof','evaluation-proof','core-proof-02','evaluation-proof-02'):
        value=json.loads((P/(label+'.json')).read_text())
        r.need(value['status']=='REFUSED_TIMEOUT' and value['exit_code']==-9,'prior run not terminal timeout')
        previous[label]=r.pin((P/(label+'.json')).read_bytes())
    historical=Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/semantic-transport-v1/retained-assurance-v1/native')
    measured={}
    for name in ('core-proof.json','evaluation-proof.json'):
        raw=(historical/name).read_bytes()
        value=json.loads(raw)
        measured[name]=dict(pin=r.pin(raw),elapsed_ns=value['latency_ns'],exit=value['exit'])
    record=dict(schema='transport/proof-resource-correction/1',prior_terminal_results=previous,
        historical_measurements=measured,commands=commands,driver=r.pin((P/'full_proof.py').read_bytes()),
        reason='Initial 120-second installer runner was unsuitable for proof: preserved successful core/evaluation historical elapsed_ns already exceed 120000000000. Two attempts retained. Correct proof harness allowance, not product runtime policy.',
        bounds=dict(wall_seconds_per_project=600,cpu_seconds_per_process=600,
            address_space_bytes=1073741824,each_stream_bytes=1048576,
            per_file_bytes=33554432,parallel_proof_jobs=1,scratch_bytes=268435456),
        limits='One final resource-corrected attempt per incomplete project. No proof level/prover/contract/assertion changes, no Assume/Annotate, no unit filters, no source edits. No further automatic retries.',
        owner_budget='Tranche06 plus prepaid tranche07; one existing development round.',
        risk='Longer proof computation spends finite engineering budget. Same trusted nonescaping toolchain assumption; this is not descendant containment proof.',
        status='ADMITTED_NOT_EXECUTED')
    r.save(r.L/'native-proof-resource-correction-01.json',record)
    r.save(P/'proof-resource-correction.json',record)


def main():
    env,all_commands,unused=r.configuration()
    commands=[(label+'-03',args) for label,args in all_commands if label in ('core-proof','evaluation-proof')]
    admit(commands)
    for label,args in commands:
        execute(label,args,env)
    source=json.loads((P/'source-before.json').read_text())
    r.save(P/'source-after-full-proof.json',r.files_snapshot(r.W,list(source)))
    r.save(P/'installed-after-full-proof.json',r.installed_snapshot())


if __name__=='__main__':
    main()
