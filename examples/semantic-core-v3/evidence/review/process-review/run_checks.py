"""Bounded independent launcher resource and error-state oracle."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

HERE=Path(__file__).resolve().parent
MIB=1048576
CASES=[
 {'id':'below_caps','limits':{'AS':[128*MIB,256*MIB],'CPU':[2,4],'FSIZE':[65536,131072],'NOFILE':[32,64]},
  'expected_limits':{'AS':[128*MIB,128*MIB],'CPU':[2,2],'FSIZE':[65536,65536],'NOFILE':[32,32]}},
 {'id':'above_caps','limits':{'AS':[768*MIB,768*MIB],'CPU':[180,180],'FSIZE':[8*MIB,8*MIB],'NOFILE':[256,256]},
  'expected_limits':{'AS':[512*MIB,512*MIB],'CPU':[120,120],'FSIZE':[4*MIB,4*MIB],'NOFILE':[128,128]}},
 {'id':'zero_fsize','limits':{'FSIZE':[0,131072]},'expected_limits_subset':{'FSIZE':[0,0]}},
 {'id':'low_nofile','limits':{'NOFILE':[16,32]},'expected_limits_subset':{'NOFILE':[16,16]}},
 {'id':'directory_fd_closed','expected_no_directory_fd':True},
 {'id':'nonzero','kind':'nonzero','expected_status':'EXIT_NONZERO','expected_exit':7,'expected_stdout':'out-prefix','expected_stderr':'err-prefix'},
 {'id':'stderr_success','kind':'stderr','expected_status':'SUCCESS','expected_exit':0,'expected_stderr':'err-prefix'},
 {'id':'bridge_stderr','kind':'bridge_stderr','expected_status':'EXPLICIT_EXCEPTION','expected_reason':'CORE_CHILD_REFUSED_child'},
 {'id':'overflow','kind':'output','cap':128,'expected_status':'REFUSED_OUTPUT_LIMIT','expected_stdout_length':128},
 {'id':'timeout','kind':'timeout','timeout':0.1,'expected_status':'REFUSED_TIMEOUT','expected_stdout':'prefix'},
 {'id':'missing','kind':'missing','expected_status':'REFUSED_LAUNCH','expected_exit':None},
 {'id':'invalid_argv','kind':'invalid_argv','expected_status':'EXPLICIT_EXCEPTION','expected_reason':'invalid argv value'}]


def checks(case,result):
    issues=[]
    for key,field in [('expected_status','status'),('expected_exit','exit_code'),('expected_stdout','stdout'),('expected_stderr','stderr'),('expected_reason','reason')]:
        if key in case and result.get(field)!=case[key]:issues.append(field+' differs')
    if 'expected_stdout_length' in case and len(result.get('stdout',''))!=case['expected_stdout_length']:
        issues.append('stdout retained prefix bound differs')
    if case.get('kind','probe')=='probe':
        if result.get('status')!='SUCCESS':return issues+['probe not successful']
        probe=result['probe']
        for name,pair in case.get('expected_limits',case.get('expected_limits_subset',{})).items():
            if probe['limits'][name]!=pair:issues.append(name+' limit differs')
        if probe['cwd']!=str(HERE/case['id']):issues.append('cwd differs')
        if case.get('expected_no_directory_fd') and any(target==probe['cwd'] for _,target in probe['fds']):
            issues.append('working directory descriptor leaked through exec')
    return issues


def run():
    rows=[]
    for case in CASES:
        args=[sys.executable,'-I','-S','-B','-Werror',str(HERE/'worker.py'),json.dumps(case)]
        child=subprocess.run(args,capture_output=True,timeout=8,check=False)
        try:
            result=json.loads(child.stdout)
            issues=checks(case,result)
        except (ValueError,KeyError,TypeError) as error:
            result=None
            issues=['fixture output invalid: '+str(error)]
        if child.returncode!=0 or child.stderr:issues.append('worker failed or emitted stderr')
        rows.append({'case':case,'result':result,'pass':not issues,'issues':issues,
           'worker_exit':child.returncode,'worker_stdout':child.stdout.decode('ascii','backslashreplace'),
           'worker_stderr':child.stderr.decode('ascii','backslashreplace')})
    pins={str(p.relative_to(HERE)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (HERE/'snapshot').iterdir()}
    report={'schema':'semantic-core-independent-process-review/1','cases':rows,'pins':pins,
            'status':'PASS' if all(r['pass'] for r in rows) else 'FAILED','whole_system_proof':'NOT_CLAIMED'}
    with (HERE/'results01.json').open('x') as stream:json.dump(report,stream,sort_keys=True,indent=2);stream.write('\n')
    print(json.dumps({'status':report['status'],'cases':len(rows),'failed':[r['case']['id'] for r in rows if not r['pass']]}))


if __name__=='__main__':run()
