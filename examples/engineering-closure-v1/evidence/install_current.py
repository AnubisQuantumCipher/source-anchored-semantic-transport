"""Current-source isolated paired installation and inherited runtime checks."""
import importlib.util
import json
from pathlib import Path
import sys

P = Path('/dev/shm/semantic-transport-proof-closure-20261029')
spec = importlib.util.spec_from_file_location('closure_runner', P/'run.py')
r = importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
from transport_install_layout import source_inputs


def main():
    root = P/'install-current'
    root.mkdir(mode=0o700)
    manifest = r.W/'install/SOURCE.json'
    expected = 'e1796ecd8ba6bab8d4e8694cbe73f27315eaac0e0ffe8016abfac0fd9a5827c6'
    r.need(r.pin(manifest.read_bytes())['sha256'] == expected, 'current source pin mismatch')
    unused, files = source_inputs(r.W, expected)
    copy = root/'independent-source'
    copy.mkdir(mode=0o700)
    for name, raw in dict(files, **{'install/SOURCE.json':manifest.read_bytes()}).items():
        target = copy/name
        target.parent.mkdir(parents=True,exist_ok=True)
        with target.open('xb') as stream:
            r.need(stream.write(raw) == len(raw), 'short second source copy')
    r.need(source_inputs(copy,expected)[1] == files, 'second source copy mismatch')
    env = dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',
               TMPDIR=str(P/'tmp'),PYTHONDONTWRITEBYTECODE='1')
    python = [sys.executable,'-I','-S','-B','-Werror']
    commands = []
    for label, source in (('first',r.W),('second',copy)):
        args = python+[str(source/'install/transport_install.py'),'build',str(root/(label+'-bundle')),
            '--expect-source',expected,'--receipt',str(root/(label+'-build')),
            '--gprbuild','/home/sicarii/opt/gnat/gprbuild-aarch64-linux-26.0.0-1/bin/gprbuild',
            '--compiler-bin','/home/sicarii/opt/gnat/gnat-aarch64-linux-16.1.0-1/bin']
        commands.append((label+'-install',args))
    baseline = r.installed_snapshot()
    r.save(root/'source-pin.json',dict(source=expected,files={k:r.pin(v) for k,v in files.items()}))
    r.save(r.L/'current-install-closure-admission-01.json',dict(
        schema='transport/current-install-closure-admission/1',source=expected,
        owner_allocation='Prepaid tranche06; same development round; deadline unchanged.',
        scope='Two isolated existing-installer builds from separately copied identical current source; byte compare; unchanged inherited runtime/product/portable-handoff tests. No persistent services, global installation, dependency changes, old runtime edits, heldout campaign or new paid access.',
        commands=commands,environment=env,driver=r.pin((P/'install_current.py').read_bytes()),
        oracle='Existing unchanged tests and full installed byte comparison; reject skipped/unrun integration as completion.',
        resource='Existing installer/process/output limits and reserve unchanged. Scratch within already pinned 256MiB task envelope; no root-disk build.',
        tests=['test_installed_regression.py','test_install_product.py','test_portable_handoff.py'],
        baseline='Old qualified donor retained; both new bundles must independently pass source reconstruction before paired handoff.',
        status='ADMITTED_NOT_EXECUTED'))
    for label,args in commands:
        result = r.execute(label,args,env)
        r.need(result['status']=='SUCCESS','installer did not succeed: '+label)
    compare_and_test(root,env,python,baseline)


def compare_and_test(root,env,python,baseline):
    first,second = root/'first-bundle',root/'second-bundle'
    manifest = json.loads((first/'INSTALL.json').read_text())
    names = ['INSTALL.json']+[x['path'] for x in manifest['files']]
    left,right = r.files_snapshot(first,names),r.files_snapshot(second,names)
    r.save(root/'paired-comparison.json',dict(first=left,second=right,byte_identical=left==right))
    r.need(left==right,'paired installations differ')
    runtime = r.pin((first/'RUNTIME.json').read_bytes())['sha256']
    tests = [ ('current-regression',python+[str(r.W/'install/test_installed_regression.py'),
          '--bundle',str(first),'--evidence',str(root/'regression')]),
       ('current-product',python+[str(r.W/'install/test_install_product.py'),
          '--bundle',str(first),'--evidence',str(root/'product'),
          '--historical-pair',str(r.D.parent/'content'),'--historical-decoder',str(r.D)]),
       ('current-portable',python+[str(r.W/'install/test_portable_handoff.py'),
          '--sender-bundle',str(first),'--receiver-bundle',str(second),
          '--mismatched-bundle',str(r.D),'--expect-runtime-sha256',runtime,
          '--evidence',str(root/'portable')]) ]
    r.save(root/'test-invocations.json',tests)
    for label,args in tests:
        r.execute(label,args,env)
    r.need(r.installed_snapshot()==baseline,'old installation changed')
    r.save(root/'old-installed-after.json',r.installed_snapshot())
    print('CURRENT_INSTALL_CHECKS_RECORDED; receipt evaluation required',flush=True)


if __name__ == '__main__':
    main()
