"""PRIVATE helper-only H14 projection; does not call public host or replay.
The earlier handwritten host oracle requires wrong imported origin rejection.
This synthetic sys.modules state cannot be supplied through the fixed public CLI.
"""
import hashlib
import json
from pathlib import Path
import sys
import types

if len(sys.argv)!=3:raise SystemExit('fixed checked entry path and SHA required')
entry,expected=sys.argv[1:];raw=Path(entry).read_bytes()
if len(raw)>131072 or hashlib.sha256(raw).hexdigest()!=expected:
 raise SystemExit('independent source pin mismatch')
scope={'__name__':'private_host_definitions','__file__':entry,'__package__':None}
exec(compile(raw,entry,'exec',dont_inherit=True),scope)
name='transport_origin_private_control';module=types.ModuleType(name)
module.__file__='/not/the/held/origin.py';sys.modules[name]=module
held={'path':entry,'bytes':len(raw),'sha256':expected}
try:
 scope['_audit']({name:held})
 result={'schema':'quorum/private-origin-probe/1','scope':'PRIVATE_AUDIT_ONLY','error':'NO_REFUSAL'}
except scope['HostError'] as error:
 result={'schema':'quorum/private-origin-probe/1','scope':'PRIVATE_AUDIT_ONLY','error':str(error)}
sys.stdout.write(json.dumps(result,sort_keys=True,separators=(',',':'))+'\n')
