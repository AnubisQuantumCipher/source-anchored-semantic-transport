"""Source-only expected per-arm module-map derivation. No product imports.
Fixed source-reviewed load schedule: helpers, package BOTHarms, MCP transport,
legacy3, replay. Top-level static import closure; scoped/dynamic sites explicit.
"""
import ast
import hashlib
import json
from pathlib import Path
ROOT=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
DEC=Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/semantic-handoff-v1/positive-02/transport/decoder')
P=Path('/dev/shm/semantic-transport-replay-integration-20261029/revision-02')
OUT=Path('/dev/shm/semantic-transport-replay-controls-20261029/materialization-01')


def C(v):return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()


def pin(p):
 b=p.read_bytes();return {'path':str(p),'bytes':len(b),'sha256':hashlib.sha256(b).hexdigest()}


def inspect(path):
 b=path.read_bytes()
 if len(b)>131072:raise ValueError('source cap')
 tree=ast.parse(b);pending=[(tree,[])];imports=[];scoped=[];dynamic=[];work=0
 while pending:
  node,scope=pending.pop();work+=1
  if work>100000:raise ValueError('AST work cap')
  if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)):scope=scope+[node.name]
  found=[]
  if isinstance(node,ast.Import):found=[x.name for x in node.names if x.name.startswith('transport_')]
  if isinstance(node,ast.ImportFrom) and (node.module or '').startswith('transport_'):found=[node.module]
  for name in found:
   if scope:scoped.append({'line':node.lineno,'module':name,'scope':scope})
   else:imports.append(name)
  if isinstance(node,ast.Call):
   call=node.func.id if isinstance(node.func,ast.Name) else node.func.attr if isinstance(node.func,ast.Attribute) else ''
   if call in ('__import__','import_module','exec_module','run_path','run_module','_load'):
    dynamic.append({'line':node.lineno,'call':call,'scope':scope,'arg':ast.unparse(node.args[0]) if node.args else None})
  for child in ast.iter_child_nodes(node):pending.append((child,scope))
 return {'source':pin(path),'module_scope_imports':sorted(set(imports)),'function_scoped_imports':scoped,'dynamic_sites':dynamic}


contract=json.loads((P/'contract.json').read_bytes());paths={}
for relative in contract['bootstrap']['static_files']:
 if relative.endswith('.py'):
  path=ROOT/relative.split('/',1)[1];paths[path.stem]=path
snapshot=json.loads(Path('/dev/shm/semantic-transport-replay-controls-20261029/external-closure-01/runtime-qualification/installed-snapshot-after.json').read_bytes())
for relative,expected in snapshot['files'].items():
 if relative.startswith('tools/') and relative.endswith('.py'):
  path=DEC/relative
  if pin(path)['sha256']!=expected['sha256']:raise ValueError('qualified decoder changed')
  if path.stem in paths:raise ValueError('ambiguous source namespace')
  paths[path.stem]=path
if len(paths)>64:raise ValueError('fixed module source roster cap')
ledger={name:inspect(path) for name,path in paths.items()}
helpers=['transport_install_support','transport_install_layout','transport_handoff_inputs','test_portable_handoff']
base=helpers+['transport_package','transport_schema','transport_wire','transport_operators','transport_quorum_replay']
maps={};closures={}
for arm in ('original','transport'):
 frontier=base+(['transport_mcp'] if arm=='transport' else []);seen=set()
 for unused in range(256):
  if not frontier:break
  name=frontier.pop()
  if name in seen:continue
  if name not in ledger:raise ValueError('unresolved import '+name)
  seen.add(name);frontier.extend(ledger[name]['module_scope_imports'])
 else:raise ValueError('closure bound')
 closures[arm]=sorted(seen)
 maps[arm]=sorted([dict(name=name,**ledger[name]['source']) for name in seen if name.startswith('transport_')],key=lambda row:C(row['name']))
 # Descriptor receipt rows have no extra source-pin path alias or mode field.
 for row in maps[arm]:
  if set(row)!=set(('name','path','bytes','sha256')):raise ValueError('closed map row')
bootstrap=ledger['transport_quorum_bootstrap']['source']
report={'classification':'SOURCE_DERIVED_EXPECTED_IMPORT_MAP_NO_PRODUCT_EXECUTION','bootstrap_source':bootstrap,
 'per_arm_expected_modules':maps,'per_arm_complete_imported_roots_and_static_closure':closures,'ledger':ledger,
 'source_schedule_evidence':{'helpers':'_helpers explicitly loads support,layout,handoff_inputs,test_portable_handoff',
 'both_arms':'_host invokes _runtime after _legacy, _runtime loads qualified transport_package and calls runtime_contract; static imports occur on that load',
 'transport_only':'_transport loads transport_mcp; Receiver/decode use existing module-scope closure. No SDK main/tools/serve path invoked.',
 'checker':'_run loads transport_quorum_replay; its module scope imports all eight existing Q modules. Legacy three installed modules already loaded through package closure and explicit LEGACY load.',
 'excluded':'Entry executes as __main__, not transport_quorum_bootstrap. test_portable_handoff origin is audited but its name is not transport_*, so absent from modules receipt. Historical handoff adapter functions transport_receiver/bootstrap/frozen_manifest not called; their function-local imports do not add modules.'},
 'required_review':'Independently verify dynamic load schedule/function call exclusions and source pins, then freeze exact maps before any product run. Refresh artifact after source changes; do not derive expected map from receipt output.'}
# Stable snapshot check prevents silently combining two source revisions.
for row in ledger.values():
 if pin(Path(row['source']['path']))!=row['source']:raise ValueError('source changed during AST audit')
name='source-derived-import-map-'+bootstrap['sha256'][:12]+'.json';p=OUT/name
with p.open('xb') as f:f.write(C(report))
print(json.dumps({'path':str(p),'sha256':pin(p)['sha256'],'bootstrap':bootstrap,
 'per_arm_names':{arm:[r['name'] for r in rows] for arm,rows in maps.items()}}))
