"""Source-only bounded transport import ledger; no product import/execution.
Not an automatic actual-import oracle: function/branch scopes and dynamic imports
must be reviewed against the frozen CLI schedule before expected map is frozen.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
ROOT=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
DEC=Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/semantic-handoff-v1/positive-02/transport/decoder')
P=Path('/dev/shm/semantic-transport-replay-integration-20261029/revision-02')


def pin(path):
 b=path.read_bytes();return {'path':str(path),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}


def inspect(path):
 raw=path.read_bytes()
 if len(raw)>131072:raise ValueError('source audit file cap')
 tree=ast.parse(raw);pending=[(tree,[])];rows=[];work=0
 while pending:
  node,scope=pending.pop();work+=1
  if work>100000:raise ValueError('source AST inspection bound')
  if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):scope=scope+[node.name]
  if isinstance(node,ast.Import):
   for alias in node.names:
    if alias.name.startswith('transport_'):rows.append({'line':node.lineno,'kind':'static_import','module':alias.name,'scope':scope})
  if isinstance(node,ast.ImportFrom) and (node.module or '').startswith('transport_'):
   rows.append({'line':node.lineno,'kind':'static_from','module':node.module,'scope':scope})
  if isinstance(node,ast.Call):
   name=node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else ''
   if name in ('__import__','import_module','exec','eval','run_path','run_module'):
    rows.append({'line':node.lineno,'kind':'dynamic_or_execution_boundary','call':name,'argument':ast.unparse(node.args[0]) if node.args else None,'scope':scope})
  for child in ast.iter_child_nodes(node):pending.append((child,scope))
 return {'source':pin(path),'sites':sorted(rows,key=lambda r:r['line']),'ast_nodes_observed':work}


parser=argparse.ArgumentParser();parser.add_argument('--source-freeze',type=Path,required=True);parser.add_argument('--out',type=Path,required=True);a=parser.parse_args()
frozen=json.loads(a.source_freeze.read_bytes())
if frozen.get('source')!='/root' or frozen.get('ready') is not True:raise ValueError('owner sourcefreeze required')
for name,expected in frozen['sourcepins_verified_before_run'].items():
 digest=expected['sha256'] if isinstance(expected,dict) else expected
 if pin(ROOT/name)['sha256']!=digest:raise ValueError('sourcefreeze changed '+name)
contract=json.loads((P/'contract.json').read_bytes())
paths=[ROOT/name.split('/',1)[1] for name in contract['bootstrap']['static_files'] if name.endswith('.py')]
# Qualified existing installed tool roster is already source-bound; no filesystem search.
snapshot=json.loads(Path('/dev/shm/semantic-transport-replay-controls-20261029/external-closure-01/runtime-qualification/installed-snapshot-after.json').read_bytes())
paths += [DEC/name for name in snapshot['files'] if name.startswith('tools/') and name.endswith('.py')]
paths=sorted(set(paths))
if len(paths)>64:raise ValueError('audit source roster bound')
rows=[inspect(p) for p in paths]
report={'classification':'SOURCE_ONLY_IMPORT_LEDGER_NOT_EXECUTION','readiness':pin(a.source_freeze),'sources':rows,
 'required_before_expected_map':'Review each arm actual called import schedule and function/branch-scoped exclusions, audit every dynamic import literal/call against closed pinned module origin maps. Freeze exact per-arm expected module names/paths/byte pins before execution; no actual receipt output may author expected map.',
 'boundaries':'Python stdlib/OS remain declared trusted. MODULES runtime byte roster is not identical to actual imported module set. __main__ entry separate from transport_* sys.modules entries. No bare-name/module.__file__ metadata can override actual regular file hash/origin validation.'}
with a.out.open('x') as f:json.dump(report,f,sort_keys=True,separators=(',',':'))
print(json.dumps(pin(a.out)))
