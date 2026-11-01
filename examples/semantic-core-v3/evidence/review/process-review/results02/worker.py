"""One isolated inherited-limit fixture; never lowers the reviewing process limits."""
import json
import os
from pathlib import Path
import resource
import sys

HERE=Path(__file__).resolve().parent
REPO=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
sys.dont_write_bytecode=True
sys.path[:0]=[str(HERE/'snapshot'),str(REPO/'tools'),str(REPO/'install')]
import transport_core_process as process
import transport_core_bridge as bridge
CATEGORIES={'AS':resource.RLIMIT_AS,'CPU':resource.RLIMIT_CPU,'FSIZE':resource.RLIMIT_FSIZE,'NOFILE':resource.RLIMIT_NOFILE}
PROBE='''import json,os,resource
categories={'AS':resource.RLIMIT_AS,'CPU':resource.RLIMIT_CPU,'FSIZE':resource.RLIMIT_FSIZE,'NOFILE':resource.RLIMIT_NOFILE}
fds=[]
for name in os.listdir('/proc/self/fd'):
 try:fds.append([name,os.readlink('/proc/self/fd/'+name)])
 except FileNotFoundError:pass
print(json.dumps({'limits':{name:list(resource.getrlimit(value)) for name,value in categories.items()},'cwd':os.getcwd(),'fds':fds},sort_keys=True))
'''


def execute(configuration):
    cwd=HERE/configuration['id']
    cwd.mkdir(mode=0o700)
    for name,pair in configuration.get('limits',{}).items():
        resource.setrlimit(CATEGORIES[name],tuple(pair))
    kind=configuration.get('kind','probe')
    scripts={'probe':PROBE,'nonzero':"import os,sys;os.write(1,b'out-prefix');os.write(2,b'err-prefix');sys.exit(7)",
      'stderr':"import os;os.write(2,b'err-prefix')",'output':"import os;os.write(1,b'x'*4096)",
      'timeout':"import os,time;os.write(1,b'prefix');time.sleep(30)"}
    argv=[sys.executable,'-I','-S','-B','-c',scripts.get(kind,PROBE)]
    if kind=='missing':argv=['/nonexistent/semantic-core-independent-no-such-tool']
    if kind=='invalid_argv':argv=['bad\x00tool']
    try:
        if kind=='bridge_stderr':
            bridge.call([sys.executable,'-I','-S','-B','-c',scripts['stderr']],cwd,'child')
            return {'status':'UNEXPECTED_BRIDGE_SUCCESS'}
        result=process.run_bounded(argv,cwd,{'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'},
                                   timeout=configuration.get('timeout',2),cap=configuration.get('cap',4096))
        result['stdout']=result['stdout'].decode('ascii','backslashreplace')
        result['stderr']=result['stderr'].decode('ascii','backslashreplace')
        if kind=='probe' and result['status']=='SUCCESS':result['probe']=json.loads(result['stdout'])
        return result
    except (ValueError,OSError,TypeError) as error:
        return {'status':'EXPLICIT_EXCEPTION','exception':type(error).__name__,'reason':str(error)}


if __name__=='__main__':
    print(json.dumps(execute(json.loads(sys.argv[1])),sort_keys=True))
