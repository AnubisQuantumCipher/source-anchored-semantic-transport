"""INSTRUMENTED host preentry test; never a direct public-CLI scope claim.
Parent independently pins this wrapper and entry. Only inert sys.modules entries
are injected before compiling the checked owned entry bytes as actual __main__.
"""
import hashlib
from pathlib import Path
import sys
import types

if len(sys.argv)!=6:
 raise SystemExit('fixed mode, entry, entrySHA, invocation, invocationSHA required')
_,mode,entry,entry_sha,invocation,invocation_sha=sys.argv
raw=Path(entry).read_bytes()
if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=entry_sha:
 raise SystemExit('independent entry pin mismatch before execution')
inv_raw=Path(invocation).read_bytes()
if len(inv_raw)>65536 or hashlib.sha256(inv_raw).hexdigest()!=invocation_sha:
 raise SystemExit('independent invocation pin mismatch before execution')
if mode=='preloaded':
 sys.modules['transport_preloaded_host_control']=types.ModuleType('transport_preloaded_host_control')
elif mode=='count':
 for index in range(520):
  name='fixed_host_count_probe_'+str(index)
  sys.modules[name]=types.ModuleType(name)
else:
 raise SystemExit('fixed preentry probe mode')
sys.argv=[entry,invocation,'--expect-invocation-sha256',invocation_sha,
          '--expect-bootstrap-sha256',entry_sha]
scope={'__name__':'__main__','__file__':entry,'__package__':None,'__cached__':None}
exec(compile(raw,entry,'exec',dont_inherit=True),scope)
