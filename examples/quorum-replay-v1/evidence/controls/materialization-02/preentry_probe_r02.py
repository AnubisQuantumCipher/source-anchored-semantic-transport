"""INSTRUMENTED exact frozen H02/H03 preentry states; not direct public scope.
All bootstrap stdlib imports occur before exact module-count construction.
No inert entry callback/imports and no candidate imports before host execution.
"""
import hashlib
import importlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import types

if len(sys.argv)!=7:
 raise SystemExit('fixed mode, entry, entrySHA, invocation, invocationSHA, state-output required')
_,mode,entry,entry_sha,invocation,invocation_sha,state_output=sys.argv
raw=Path(entry).read_bytes();inv_raw=Path(invocation).read_bytes()
if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=entry_sha:
 raise SystemExit('independent entry pin mismatch before execution')
if len(inv_raw)>65536 or hashlib.sha256(inv_raw).hexdigest()!=invocation_sha:
 raise SystemExit('independent invocation pin mismatch before execution')
if any(name.startswith('transport_') for name in sys.modules):
 raise SystemExit('fresh child has an unexpected transport module')
if mode=='preloaded':
 name='transport_untrusted_preload';sys.modules[name]=types.ModuleType(name)
 if len(sys.modules)>512:raise SystemExit('H02 fresh module budget exceeded')
elif mode=='count':
 initial=len(sys.modules)
 if initial>513:raise SystemExit('H03 fresh module budget already exceeded')
 for index in range(513-initial):
  name='fixed_host_count_probe_'+str(index)
  if name in sys.modules:raise SystemExit('inert count entry collision')
  sys.modules[name]=types.ModuleType(name)
 if len(sys.modules)!=513:raise SystemExit('H03 exact module count not constructed')
else:
 raise SystemExit('fixed preentry probe mode')
state={'scope':'PREENTRY_INSTRUMENTED_CLI','mode':mode,'module_count':len(sys.modules),
 'module_names':sorted(sys.modules),'entry_sha256':entry_sha,'invocation_sha256':invocation_sha}
with Path(state_output).open('xb') as stream:
 stream.write(json.dumps(state,sort_keys=True,separators=(',',':')).encode())
sys.argv=[entry,invocation,'--expect-invocation-sha256',invocation_sha,
          '--expect-bootstrap-sha256',entry_sha]
scope={'__name__':'__main__','__file__':entry,'__package__':None,'__cached__':None}
exec(compile(raw,entry,'exec',dont_inherit=True),scope)
