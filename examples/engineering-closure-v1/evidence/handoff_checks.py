"""Close inherited installed preparation, retrieval and checked-finish lanes."""
import importlib.util
from pathlib import Path
import sys
import time
P=Path('/dev/shm/semantic-transport-proof-closure-20261029')
spec=importlib.util.spec_from_file_location('closure_runner',P/'run.py')
r=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
from transport_install_build import command


def main():
    root=P/'current-handoff'
    root.mkdir(mode=0o700)
    bundle=P/'install-current/first-bundle'
    tests=('test_handoff_prepare.py','test_handoff_reader.py','test_evidence_finish.py')
    source=r.files_snapshot(r.W,['install/'+name for name in tests])
    env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',
             TMPDIR=str(P/'tmp'),PYTHONDONTWRITEBYTECODE='1')
    commands=[(name[:-3],[sys.executable,'-I','-S','-B','-Werror',str(r.W/'install'/name),
              '--bundle',str(bundle),'--evidence',str(root/name[:-3])]) for name in tests]
    r.save(r.L/'current-handoff-closure-admission-01.json',dict(
      schema='transport/current-handoff-admission/1',tests=source,commands=commands,
      driver=r.pin((P/'handoff_checks.py').read_bytes()),decoder_install=r.pin((bundle/'INSTALL.json').read_bytes()),
      oracle='Existing unchanged inherited tests with actual current installed decoder; no synthetic/original-only substitution accepted.',
      scope='Same finite engineering development round and current-source qualification; prepaid tranche06/07. No model execution, publication of private inputs or persistent changes.',
      bounds='Existing run_bounded120s,1GiB per process,1MiB streams and total task256MiB sampled scratch; no product bound changes.',status='ADMITTED_NOT_EXECUTED'))
    for name,args in commands:
        r.need(time.time()<1793279515,'prepaid command allowance exhausted')
        print('START '+name,flush=True)
        try:
            command(args,r.W,env,root,name)
            print(name+' SUCCESS',flush=True)
        except ValueError as error:
            print(name+' FAILED '+str(error),flush=True)
        r.size_gate()
    r.need(source==r.files_snapshot(r.W,['install/'+name for name in tests]),'test source changed')


if __name__=='__main__':
    main()
