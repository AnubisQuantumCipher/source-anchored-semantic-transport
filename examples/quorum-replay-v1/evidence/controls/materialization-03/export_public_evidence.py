"""Create-only curated exact-byte evidence export, never product execution.
Per-file <=1MiB, aggregate <=16MiB, <=1024 files. No decoder/native trees.
Full group rows retain all per-case diagnostics; duplicate per-case JSON copies
stay local, while both actual streams are included for every exported group.
"""
import hashlib
import json
from pathlib import Path

BASE=Path('/dev/shm/semantic-transport-replay-controls-20261029')
S=BASE/'materialization-03'
P=Path('/dev/shm/semantic-transport-replay-integration-20261029')
C=P/'code-review-01'
ROOT=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
OUT=P/'public-evidence-01'
SELECTED={}


def destination(path):
 for root,prefix in ((C,'review'),(BASE,'controls'),(P/'public-reproducer-01','public-reproducer-01'),
  (P/'portable-core-tests-01','portable-core-tests-01'),(P/'portable-core-tests-03','portable-core-tests-03'),
  (P/'revision-02','profile/revision-02')):
  if path.is_relative_to(root):return str(Path(prefix)/path.relative_to(root))
 if path.parent==P and path.name.startswith('source-freeze-'):return 'profile/'+path.name
 if path==ROOT/'install/test_quorum_replay.py':return 'checker-test-harness/'+path.name
 raise ValueError('source outside finite selected evidence roots: '+str(path))


def add(path):
 path=Path(path)
 if path.is_symlink() or not path.is_file():raise ValueError('nonregular selected evidence '+str(path))
 if path.stat().st_size>1048576:raise ValueError('selected per-file byte cap '+str(path))
 relative=destination(path)
 if relative in SELECTED and SELECTED[relative]!=path:raise ValueError('export namespace collision')
 SELECTED[relative]=path
 if len(SELECTED)>1024:raise ValueError('export file count cap')


def tree(root):
 pending=[root]
 for unused in range(1024):
  if not pending:return
  path=pending.pop()
  if path.is_symlink():raise ValueError('selected symlink '+str(path))
  if path.is_dir():pending.extend(sorted(path.iterdir()))
  else:add(path)
 raise ValueError('bounded subtree walk exhausted')


def manifest(path):
 add(path);value=json.loads(path.read_bytes())
 for row in value.get('cases',[]):
  for key in ('expected_stdout','expected_stderr'):
   if key in row:add(row[key]['path'])
  for part in row.get('command',[]):
   candidate=Path(part)
   if candidate.suffix=='.py' and candidate.is_absolute() and (candidate.is_relative_to(BASE) or candidate.is_relative_to(C)):add(candidate)
 for row in value.get('oracle_pins',[]):
  candidate=Path(row['path'])
  if candidate.is_relative_to(BASE) or candidate.is_relative_to(C) or candidate.parent==P:add(candidate)


def observation(path):
 add(path);value=json.loads(path.read_bytes())
 if isinstance(value.get('manifest'),dict):manifest(Path(value['manifest']['path']))
 for row in value.get('cases',[]):
  for key in ('first_stdout','first_stderr'):
   if key in row:add(row[key]['path'])


groups=('priority-pair-absence','transport-review8-r02','transport14-r02','original-semantic14-r02','host-cache15-r02','private-origin')
for stem in groups:
 for lane in ('normal','opt1'):
  name=stem+'-'+lane+'-first'
  observation(S/name/'first-run.json')
  for suffix in ('-command.json','-command.log'):add(S/(name+suffix))
observation(BASE/'materialization-02/first-pair-run/first-run.json')
for name in ('first-pair-first-command.json','first-pair-first-command.log','first-pair-observed-parity.json','source-freeze-01-ineligible.json'):
 add(BASE/'materialization-02'/name)

for dirname in ('materialization-01','materialization-02'):
 for path in (BASE/dirname).iterdir():
  if path.is_file() and path.suffix=='.py':add(path)
for path in (S/'remaining-manifests').iterdir():
 if path.is_file():add(path)
for name in ('complete-matrix-receipt.json','complete-matrix-with-accounting.json','measured-accounting-inputs.json',
 'measured-accounting-receipt.json','accounting-jackal-results.json','fixture-alias-correction-r02.json',
 'portable-zip-only-reproducer-design.json','export_public_evidence.py'):
 add(S/name)
for name in ('handwritten-host-expectations-01.json','handwritten-host-expectations-02.json','handwritten-host-expectations-03.json'):
 path=BASE/'host-bootstrap-01'/name
 if path.exists():add(path)
for name in ('sidecar-absence-pair-handwritten-oracle.json','private-origin-projection-handwritten-oracle.json','stale-cache-oracle.json'):
 add(BASE/'materialization-02'/name)
for name in ('source-freeze-01.json','source-freeze-01-ineligible.json','source-freeze-02.json','source-freeze-03.json'):add(P/name)

for path in (P/'revision-02').iterdir():
 if path.is_file() and path.suffix in ('.json','.py','.patch'):add(path)
for root in (P/'revision-02/literal-controls',C/'additional-literals',C/'additional-literals/revision-02'):
 add(root/'oracle.json')
 for path in root.iterdir():
  if path.is_dir() and (path/'expected.json').is_file():add(path/'expected.json')
add(C/'additional-literals/revision-02/correction-review.json')

review=json.loads((C/'final-independent-full-replay-review.json').read_bytes())
for row in review['runs']:observation(Path(row['report']['path']))
for path in C.iterdir():
 if path.is_file() and path.suffix in ('.json','.py','.stdout','.stderr','.txt'):
  if path.name.startswith(('final-','first-pair-','source03-')) or any(term in path.name for term in ('review','diagnosis','finding','loader','concrete','inspect-','run-final-')):add(path)
for path in C.iterdir():
 if path.is_dir() and path.name.startswith(('first-pair-','source03-priority-')) and (path/'first-run.json').is_file():observation(path/'first-run.json')
for root in (P/'portable-core-tests-01',P/'portable-core-tests-03',P/'public-reproducer-01'):tree(root)
add(ROOT/'install/test_quorum_replay.py')

source=json.loads((P/'source-freeze-03.json').read_bytes());pins=[]
for relative,held in source['sourcepins_verified_before_run'].items():
 path=ROOT/relative;raw=path.read_bytes();actual={'path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
 if actual['sha256']!=held['sha256']:raise ValueError('current source03 drift '+relative)
 pins.append(actual)
current=S/'public-export-current-source-pins.json'
with current.open('xb') as stream:stream.write(json.dumps({'status':'OBSERVED_MATCH_SOURCEFREEZE03','items':pins},sort_keys=True,separators=(',',':')).encode())
add(current)

total=0;items=[]
for relative,path in sorted(SELECTED.items()):
 raw=path.read_bytes();total+=len(raw)
 if total>16777216:raise ValueError('export aggregate byte cap')
 items.append({'path':relative,'source_path':str(path),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()})
OUT.mkdir()
for row in items:
 path=Path(row['source_path']);raw=path.read_bytes()
 if len(raw)!=row['bytes'] or hashlib.sha256(raw).hexdigest()!=row['sha256']:raise ValueError('source changed during export')
 dest=OUT/row['path'];dest.parent.mkdir(parents=True,exist_ok=True)
 with dest.open('xb') as stream:stream.write(raw)
 if dest.read_bytes()!=raw:raise ValueError('copy readback mismatch')
inventory={'status':'CURATED_EXACT_BYTES_WITHIN_FIXED_BOUNDS','scope':'Public evidence only; API scopes public_cli, preentry_instrumented_cli, private_origin_helper remain distinct. Exact group first-run receipts contain every per-case row; redundant per-case first-result JSON remains local. No decoder/native trees, source originality or whole-project acceptance claimed.','items':items}
raw=json.dumps(inventory,sort_keys=True,separators=(',',':')).encode()
with (OUT/'inventory.json').open('xb') as stream:stream.write(raw)
print(json.dumps({'path':str(OUT/'inventory.json'),'sha256':hashlib.sha256(raw).hexdigest(),'observed_file_count':len(items),'observed_copied_bytes':total}))
