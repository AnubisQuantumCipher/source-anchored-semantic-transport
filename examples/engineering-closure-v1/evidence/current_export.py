"""Cross-implementation export readback for the freshly built current decoder."""
import importlib.util
import json
from pathlib import Path
import shutil
import sys

P=Path('/dev/shm/semantic-transport-proof-closure-20261029')
spec=importlib.util.spec_from_file_location('closure_runner',P/'run.py')
r=importlib.util.module_from_spec(spec)
spec.loader.exec_module(r)


def invoke(label,args,env):
    result=r.execute(label,args,env)
    r.need(result['status']=='SUCCESS',label+' failed')
    return json.loads((P/(label+'.stdout')).read_text())


def main():
    root=P/'current-export'
    root.mkdir(mode=0o700)
    b=P/'install-current/first-bundle'
    cli=str(b/'bin/semantic-transport')
    fixture=r.W/'examples/authoring-v1/controller'
    source=(fixture/'source.txt').read_bytes()
    before=r.pin((b/'INSTALL.json').read_bytes())
    reader=r.W/'install/read_transport_export.py'
    expected='4fc3f3475d9686ed87d6c6227dfe6edd63f12a53b9cb56821f26407a30310c67'
    r.need(r.pin(reader.read_bytes())['sha256']==expected,'independent reader pin mismatch')
    env=dict(PATH='/usr/bin:/bin',LANG='C.UTF-8',LC_ALL='C.UTF-8',TMPDIR=str(P/'tmp'))
    r.save(r.L/'current-export-reader-admission-01.json',dict(
        schema='transport/current-export-reader-admission/1',decoder_install=before,
        reader=r.pin(reader.read_bytes()),source=r.pin(source),
        scope='Current installed producer encode/render/verify; copy only standalone reader and closed export to fresh recipient directory; byte compare recovered original and metadata. Empty synthetic explanation; no model narrative or semantic adequacy claim.',
        bounds='Existing CLI and reader limits; inherited 120s per command, total task 256MiB scratch; prepaid tranche06.',
        status='ADMITTED_NOT_EXECUTED'))
    pair=root/'pair'
    encoded=invoke('current-export-encode',[cli,'encode',str(fixture/'authoring.json'),str(pair),
        '--source','SOURCE='+str(fixture/'source.txt'),'--budget','65536'],env)
    inspected=invoke('current-export-inspect',[cli,'inspect',str(pair/'share.txt'),
        '--archive',str(pair/'meaning.zip')],env)
    envelope=dict(schema='transport/explanation-envelope/1',package_identity=inspected['identity'],
        sources=[dict(id='SOURCE',**r.pin(source))],text='')
    r.save(root/'envelope.json',envelope)
    exported=root/'export'
    common=[str(pair/'share.txt'),str(exported),'--archive',str(pair/'meaning.zip'),
            '--explanation',str(root/'envelope.json')]
    invoke('current-export-render',[cli,'render']+common,env)
    invoke('current-export-verify',[cli,'verify']+common+['--expect-pair',inspected['identity'],
           '--expect-envelope-sha256',r.pin((root/'envelope.json').read_bytes())['sha256']],env)
    receive(root,exported,reader,source,env)


def receive(root,exported,reader,source,env):
    recipient=root/'recipient'
    recipient.mkdir(mode=0o700)
    shutil.copyfile(reader,recipient/'reader.py')
    shutil.copytree(exported,recipient/'export')
    expected=r.pin((exported/'export.json').read_bytes())['sha256']
    base=[sys.executable,'-I','-S','-B','-Werror',str(recipient/'reader.py')]
    arguments=[str(recipient/'export'),'--expect-export-sha256',expected]
    inspected=invoke('current-independent-inspect',base+['inspect']+arguments,env)
    invoke('current-independent-recover',base+['recover',str(recipient/'export'),
        str(recipient/'SOURCE.recovered'),'--source','SOURCE','--expect-export-sha256',expected],env)
    invoke('current-independent-metadata',base+['metadata',str(recipient/'export'),
        str(recipient/'metadata.recovered'),'--expect-export-sha256',expected],env)
    r.need((recipient/'SOURCE.recovered').read_bytes()==source,'independent source recovery mismatch')
    r.need((recipient/'metadata.recovered').read_bytes()==(exported/'metadata.json').read_bytes(),
           'independent metadata recovery mismatch')
    r.save(root/'receipt.json',dict(status='TESTED_CURRENT_PRODUCER_INDEPENDENT_READER',
        source_byte_equal=True,metadata_byte_equal=True,export_manifest_sha256=expected,
        reader_inspection=inspected,source=r.pin(source),model_narrative='UNRUN',
        isolation='FRESH_DIRECTORY_AND_PROCESS; no hostile same-user filesystem isolation claim',
        delivered=['reader.py','export/'],authority='NONE',semantic_adequacy='UNPROVEN'))


if __name__=='__main__':
    main()
