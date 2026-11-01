"""Exercise current bound native evaluator through unchanged integration controls."""
import importlib.util
from pathlib import Path
import sys
P=Path('/dev/shm/semantic-transport-proof-closure-20261029')
spec=importlib.util.spec_from_file_location('closure_runner',P/'run.py')
r=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def main():
    env,unused,unused_tools=r.configuration()
    native=P/'source/evaluation/bin/transport_bound_eval_native'
    bundle=P/'install-current/first-bundle'
    python=[sys.executable,'-I','-S','-B','-Werror']
    commands=[('bound-runtime-build',['/home/sicarii/opt/gnat/gprbuild-aarch64-linux-26.0.0-1/bin/gprbuild',
               '-p','-P','evaluation/transport_bound_eval.gpr','-j1'])]
    for label,test in (('bound-native-integration','test_bound_evaluation.py'),
                       ('bound-test-receipts','test_bound_test_receipts.py')):
        commands.append((label,python+[str(r.W/'install'/test),'--bundle',str(bundle),
                         '--native',str(native),'--evidence',str(P/label)]))
    r.save(r.L/'bound-runtime-test-admission-01.json',dict(
        schema='transport/bound-runtime-test-admission/1',source=r.pin((P/'source-before.json').read_bytes()),
        commands=commands,bundle=r.pin((bundle/'INSTALL.json').read_bytes()),
        driver=r.pin((P/'bound_checks.py').read_bytes()),
        oracle='Existing native integration and bound receipt suites unchanged; no structure-only mode, skipped native or synthetic decoder substitution admitted as success.',
        scope='Current source native C/IO build and bounded tests, same development round, no installed mutation or authority.',
        allocation='Remaining prepaid tranche06; 120-second process caps unchanged; declared task scratch256MiB.',
        status='ADMITTED_NOT_EXECUTED'))
    for label,args in commands:
        value=r.execute(label,args,env)
        if label=='bound-runtime-build':
            r.need(value['status']=='SUCCESS','bound native build failed')
            r.save(P/'bound-native-identity.json',r.pin(native.read_bytes()))


if __name__=='__main__':
    main()
