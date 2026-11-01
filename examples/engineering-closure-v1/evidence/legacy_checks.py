"""Run original immutable recipient/MCP fixtures in their coherent historical root."""
import importlib.util
import json
from pathlib import Path
import sys

P=Path('/dev/shm/semantic-transport-proof-closure-20261029')
spec=importlib.util.spec_from_file_location('closure_runner',P/'run.py')
r=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)
H=Path('/home/sicarii/Projects/source-anchored-semantic-transport')
SCRIPT=('import sys,unittest;sys.path[:0]=[sys.argv[1]+"/tools",sys.argv[1]+"/tests"];'
        'r=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromNames(sys.argv[2:]));'
        'sys.exit(not r.wasSuccessful() or bool(r.skipped))')


def snapshot():
    runtime=json.loads((H/'RUNTIME.json').read_text())
    names={'RUNTIME.json'}|{x['path'] for x in runtime['files']}
    names.update(str(p.relative_to(H)) for p in (H/'tools').glob('*.py'))
    names.update('tests/'+name+'.py' for name in ('test_transport_recipient_runner',
                   'test_transport_recipient_pagination','test_transport_mcp'))
    for relative in ('deliverables/semantic-transport-v2/controller/share.txt',
                     'deliverables/semantic-transport-v2/controller/meaning.zip'):
        names.add(relative)
    result=r.files_snapshot(H,sorted(names))
    for item in runtime['files']:
        r.need(result[item['path']]=={k:item[k] for k in ('bytes','sha256')},'historical runtime mismatch')
    return result


def main():
    before=snapshot()
    env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',
             TMPDIR=str(P/'tmp'),PYTHONDONTWRITEBYTECODE='1')
    commands=[('legacy-recipient',[sys.executable,'-I','-S','-B','-Werror','-c',SCRIPT,str(H),
                'test_transport_recipient_runner','test_transport_recipient_pagination']),
              ('legacy-mcp',[sys.executable,'-I','-B','-Werror','-c',SCRIPT,str(H),'test_transport_mcp'])]
    r.save(r.L/'legacy-runtime-closure-admission-01.json',dict(
        schema='transport/legacy-runtime-test-admission/1',source=before,commands=commands,
        driver=r.pin((P/'legacy_checks.py').read_bytes()),
        scope='Existing original runtime and original fixture paths, unchanged tests; no retarget/repin. Same finite development round. No model run or new SDK installation.',
        allocation='Prepaid tranche06; existing 120s/process1GiB bounds; scratch within256MiB allowance.',
        oracle='Original unittest assertions with zero failures/errors/skips required. Runtime/tests hashes unchanged before/after.',
        status='ADMITTED_NOT_EXECUTED'))
    r.save(P/'historical-before.json',before)
    for label,args in commands:
        r.execute(label,args,env)
    after=snapshot()
    r.save(P/'historical-after.json',after)
    r.need(after==before,'historical runtime or test changed')


if __name__=='__main__':
    main()
