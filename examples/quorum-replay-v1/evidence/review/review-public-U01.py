"""Read-only concrete U01 comparison; no product import or invocation."""
import hashlib
import json
from pathlib import Path

C=Path(__file__).parent
P=C.parent/'public-reproducer-01'
O=P/'prepared-inputs-01'
B=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
F=B/'examples/quorum-replay-v1/fixture-manifest.json'
M=Path('/dev/shm/semantic-transport-replay-controls-20261029/materialization-03/literal15-r02-transport/F02_TRANSPORT_ACCEPT')


def canonical(v):
    return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()


def pin(p):
    raw=p.read_bytes()
    return dict(bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def load(p):
    raw=p.read_bytes();v=json.loads(raw)
    assert canonical(v)==raw,str(p)
    return v


held=load(P/'held-identities.json')
assert pin(F)==held['fixture_manifest']==dict(bytes=869,sha256='bed37c48a5168f9ed0bf0b1169d7b13dcb942526c46b28c6f985bc8c31e74a04')
manifest=load(F)
for name in ('body','originals','expected','archive','share'):
    item=manifest[name]
    assert pin(F.parent/item['path'])=={k:item[k] for k in ('bytes','sha256')}
body=load(F.parent/manifest['body']['path'])
inv=load(O/'invocation.json');request=load(O/'request.json');descriptor=load(O/'checker-descriptor.json')
base=load(M/'request.json')
assert request==base,'Request differs from independently reviewed fixed F02 materialization'
assert (O/'expected.json').read_bytes()==(M/'expected.json').read_bytes()
assert (O/'envelope.json').read_bytes()==(M/'envelope.json').read_bytes()
assert inv['held_request']==pin(O/'request.json')
for name in ('request','envelope','checker_descriptor'):
    item=inv[name];assert item['path']==str(O/('checker-descriptor.json' if name=='checker_descriptor' else name+'.json'))
    expected=item['key'] if name=='checker_descriptor' else item
    assert pin(Path(item['path']))=={k:expected[k] for k in ('bytes','sha256')}
assert descriptor['files']==load(Path(load(M/'invocation.json')['checker_descriptor']['path']))['files']
assert len(descriptor['files'])==16
for row in descriptor['files']:
    prefix,relative=row['path'].split('/',1)
    assert prefix in ('checker','handoff') and pin(B/relative)=={k:row[k] for k in ('bytes','sha256')}
roots={'bootstrap_entry':B/'install/transport_quorum_bootstrap.py',
       'decoder_install_descriptor':Path(descriptor['decoder_bundle_root'])/'INSTALL.json',
       'runtime_descriptor':Path(descriptor['decoder_bundle_root'])/'RUNTIME.json',
       'source_manifest':Path(descriptor['decoder_source_root'])/'install/SOURCE.json'}
for name,path in roots.items():assert pin(path)==held[name]
assert pin(Path(descriptor['python']['path']))=={k:descriptor['python'][k] for k in ('bytes','sha256')}
for name in ('bootstrap_entry','bundle_snapshot_pin','source_manifest_pin'):
    held_name={'bundle_snapshot_pin':'bundle_snapshot','source_manifest_pin':'source_manifest'}.get(name,name)
    assert inv[name]==held[held_name]
assert inv['arm']=='transport' and inv['auxiliary'] is None
assert inv['body']['path']==str(O/'ABSENT_EVALUATOR_SIDECARS/body.json')
assert inv['body']['bytes']==manifest['body']['bytes'] and inv['body']['sha256']==manifest['body']['sha256']
assert not (O/'ABSENT_EVALUATOR_SIDECARS').exists()
assert [(r['alias'],r['key']) for r in inv['originals']]==sorted([(r['id'],r['key']) for r in body['sources']],key=lambda r:canonical(r[0]))
assert all(not Path(r['path']).exists() and not Path(r['path']).is_symlink() for r in inv['originals'])
for name in ('package','share'):
    member='archive' if name=='package' else name
    assert inv[name]['path']==str(F.parent/manifest[member]['path'])
    assert pin(Path(inv[name]['path']))=={k:inv[name][k] for k in ('bytes','sha256')}
assert inv['share']['identity']==manifest['identity']
receipt=load(O/'preparation-receipt.json')
assert receipt['status']=='PREPARED_NOT_EXECUTED' and receipt['qualification']=='NOT_EVALUATED' and receipt['acceptance']=='NOT_EVALUATED'
assert receipt['independently_held_root_pins']==held
command=load(O/'result-command.json')
assert command['execution']=='NOT_RUN'
assert command['argv'][-1]==held['bootstrap_entry']['sha256']
assert command['argv'][-3]==pin(O/'invocation.json')['sha256']
report=dict(status='PASS_FOR_OWNER_AUTHORIZED_FIRST_BOOTSTRAP_EXECUTION',
 source=pin(P/'prepare_public_replay.py'),prepared_files={p.name:pin(p) for p in sorted(O.iterdir()) if p.is_file()},
 held_identities=held,fixture_manifest=pin(F),baseline=str(M),
 review=['Exact complete Request/envelope/expected bytes equal independently reviewed frozen F02 concrete materialization.','Every descriptor16 member and actual Python/root raw Pin checked.','Held fixture manifest and each frozen member checked.','ZIP/share actual paths and Pins exact; Body and every original path absent; no bootstrap executed by this review.'],
 remaining='Actual bootstrap normal/optimized complete stdout/stderr/exit comparison and pre/post source/absence observations required. Preparation is not host qualification or acceptance.')
with (C/'public-U01-concrete-review.json').open('xb') as f:f.write(canonical(report))
print(json.dumps(dict(path=str(C/'public-U01-concrete-review.json'),**pin(C/'public-U01-concrete-review.json'))))
