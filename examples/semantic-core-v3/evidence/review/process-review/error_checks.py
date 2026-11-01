"""Independent injected-error controls; object patching is confined to this process."""
from contextlib import redirect_stderr
import hashlib
import io
import json
from pathlib import Path
import sys
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
REPO=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
sys.dont_write_bytecode=True
sys.path[:0]=[str(HERE/'results02/snapshot'),str(REPO/'tools'),str(REPO/'install')]
import transport_core_process as process
import transport_core_cli as cli


def fail(*args):
    raise OSError('injected limit failure')


def checks():
    results=[]
    for exception in (OSError,ValueError,MemoryError):
        stderr=io.StringIO()
        with patch.object(cli,'limit',side_effect=exception('injected limit failure')):
            with redirect_stderr(stderr):status=cli.main()
        observed={'exit':status,'stderr':stderr.getvalue()}
        results.append({'id':'cli_'+exception.__name__,'observed':observed,
          'pass':status==1 and stderr.getvalue()=='REFUSED: injected limit failure\n'})
    with patch.object(process,'child_limits',fail):
        result=process.run_bounded([sys.executable,'-I','-S','-B','-c','print(1)'],HERE,{'PATH':'/usr/bin:/bin'},timeout=2,cap=128)
    result['stdout']=result['stdout'].decode()
    result['stderr']=result['stderr'].decode()
    results.append({'id':'preexec_limit_failure','observed':result,
      'pass':result['status']=='REFUSED_LAUNCH' and result['exit_code'] is None and result['stdout']==result['stderr']==''})
    return results


if __name__=='__main__':
    results=checks()
    report={'schema':'semantic-core-independent-error-injection/1','status':'PASS' if all(r['pass'] for r in results) else 'FAILED','cases':results}
    with (HERE/'error-results.json').open('x') as stream:json.dump(report,stream,sort_keys=True,indent=2);stream.write('\n')
    (HERE/'error-results.json').chmod(0o600)
    print(json.dumps({'status':report['status'],'cases':len(results),'failed':[r['id'] for r in results if not r['pass']]}))
