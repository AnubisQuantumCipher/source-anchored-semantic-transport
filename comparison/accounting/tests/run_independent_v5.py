"""Independent literal-oracle runner; input identities and observations stay separate."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import resource
import types
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
MAX_READ = 8 * 1024 * 1024


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def read(path):
    with Path(path).open('rb') as stream:
        raw=stream.read(MAX_READ+1)
    need(len(raw)<=MAX_READ,'test input read cap')
    return raw


def load(path):
    return json.loads(read(path))


def verify_freeze(held):
    raw=read(ROOT/'fixtures-v4-manifest.json')
    need(sha(raw)==held,'held fixture manifest mismatch')
    manifest=json.loads(raw)
    need(sha(read(ROOT/'contract-v2.json'))==manifest['contract_sha256'],'contract changed')
    need(sha(read(ROOT/'oracle-v2.json'))==manifest['oracle_sha256'],'oracle changed')
    need(sha(read(ROOT/'materialize_boundaries.py'))==manifest['builder_sha256'],'builder changed')
    need(sha(read(ROOT/'materialize_iterative.py'))==manifest['helper_sha256'],'builder helper changed')
    for relative,pin in manifest['files'].items():
        path=ROOT/relative
        need(path.is_relative_to(ROOT/'fixtures-v4'),'fixture path escaped')
        data=read(path)
        need(len(data)==pin['bytes'] and sha(data)==pin['sha256'],'fixture changed: '+relative)
    return manifest


def import_product(path,held):
    path=Path(path).resolve(strict=True)
    need(sha(read(path))==held,'product source mismatch')
    raw=read(path)
    need(sha(raw)==held,'checked product bytes changed')
    module=types.ModuleType('accounting_subject')
    module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    need(callable(module.validate),'product API missing')
    return module


def case_inputs(case_id):
    folder=ROOT/'fixtures-v4'/case_id
    held=load(folder/'held.json')
    bindings={name:read(folder/(name+'.json')) for name in held['bindings']}
    return read(folder/'plan.json'),read(folder/'ledger.json'),bindings,held


def evidence_map(bindings):
    result={}
    for artifact,raw in bindings.items():
        source=json.loads(raw)
        for measurement in source['measurements']:
            result[measurement['id']]=(artifact,sha(raw),measurement)
    return result


def expected_slots(plan,ledger,bindings):
    evidence=evidence_map(bindings)
    records={item['slot']:item for item in ledger['records']}
    result=[]
    for slot in sorted(plan['slots'],key=lambda value:value['id']):
        record=records[slot['id']]
        reason=slot['reason'] if record['status']=='NOT_APPLICABLE' else record['reason']
        value={key:slot[key] for key in ('id','attempt','phase','metric','currency')}
        value.update(status=record['status'],reason=reason)
        if record['status']=='RECORDED':
            artifact,digest,measurement=evidence[record['measurement']]
            value.update(measurement=measurement['id'],artifact=artifact,artifact_sha256=digest,
                value=measurement['value'],interval=measurement['interval'],
                aggregation=('NONADDITIVE_OBSERVATION' if slot['metric'].startswith('provider_cumulative_')
                             else 'NO_AGGREGATION'))
        result.append(value)
    return result


def verify_report(actual,case_id,plan_raw,ledger_raw,bindings,held,contract,oracle):
    need(type(actual) is dict,'report must be dictionary')
    expected=held['expected']
    need(actual.get('status')==expected['status'],'literal status mismatch')
    if expected['status']=='REFUSED':
        wanted={'schema':contract['refusals']['schema'],'status':'REFUSED',
                'reason':expected['reason'],'authority':'NONE'}
        need(actual==wanted,'literal refusal shape/reason mismatch')
        return
    need(set(actual)==set(contract['core']['output_exact_keys']),'report closed keys')
    for key,value in contract['core']['output_constants'].items():
        need(actual[key]==value,'report boundary constant: '+key)
    plan,ledger=json.loads(plan_raw),json.loads(ledger_raw)
    need(actual['plan_sha256']==held['plan_sha256'],'report plan anchor')
    need(actual['ledger_sha256']==held['ledger_sha256'],'report ledger anchor')
    need(actual['attempts']==plan['attempts'],'ordered attempts/outcomes/retries lost')
    need(actual['slots']==expected_slots(plan,ledger,bindings),'complete slot values/anchors/status shape')
    if case_id=='P01_COMPLETE_BASE':
        literal=copy.deepcopy(oracle['literal_base_expected_output'])
        literal['plan_sha256']=held['plan_sha256']
        literal['ledger_sha256']=held['ledger_sha256']
        artifact_sha=ledger['artifacts'][0]['sha256']
        for slot in literal['slots']:
            slot['artifact_sha256']=artifact_sha
        need(actual==literal,'full literal base output mismatch')


def run_core(module,case_id,contract,oracle):
    plan,ledger,bindings,held=case_inputs(case_id)
    if held['scope']=='CLI_ONLY':
        return {'case':case_id,'status':'UNRUN','reason':'CLI_ONLY'}
    before=copy.deepcopy(bindings)
    actual=module.validate(plan,held['plan_sha256'],ledger,held['ledger_sha256'],bindings)
    need(bindings==before,'product mutated caller binding dictionary')
    verify_report(actual,case_id,plan,ledger,bindings,held,contract,oracle)
    return {'case':case_id,'status':'PASS','observed_status':actual['status']}


def cli_request(case_id):
    folder=ROOT/'fixtures-v4'/case_id
    plan,ledger,bindings,held=case_inputs(case_id)
    if held['scope']=='CLI_ONLY':
        return read(folder/'request.raw'),held
    def reference(path,data):
        return {'path':str(path),'bytes':len(data),'sha256':sha(data)}
    request={'schema':'transport/accounting-request/1',
             'plan':reference(folder/'plan.json',plan),
             'ledger':reference(folder/'ledger.json',ledger),'artifacts':[]}
    declared={item['id']:item for item in json.loads(ledger)['artifacts']}
    for name,raw in bindings.items():
        pin=declared.get(name,{'bytes':len(raw),'sha256':sha(raw)})
        request['artifacts'].append(dict(id=name,path=str(folder/(name+'.json')),**{k:pin[k] for k in ('bytes','sha256')}))
    return canonical(request),held


def run_cli(cli,case_id,contract,oracle,stage):
    raw,held=cli_request(case_id)
    request=stage/(case_id+'.json')
    with request.open('xb') as stream:
        need(stream.write(raw)==len(raw),'request short write')
    command=[sys.executable,'-I','-S','-B']+(['-O'] if sys.flags.optimize else [])
    command+=['-Werror',str(cli),'--request',str(request),
             '--expect-plan-sha256',held['plan_sha256'],'--expect-ledger-sha256',held['ledger_sha256']]
    completed=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,
                             cwd=ROOT,check=False)
    need(len(completed.stdout)<=131072 and len(completed.stderr)<=131072,'CLI output bound')
    need(completed.stderr==b'','unexpected CLI stderr')
    actual=json.loads(completed.stdout)
    need(canonical(actual)+b'\n'==completed.stdout,'CLI canonical output framing')
    plan,ledger,bindings,held=case_inputs(case_id)
    verify_report(actual,case_id,plan,ledger,bindings,held,contract,oracle)
    wanted=1 if held['expected']['status']=='REFUSED' else 0
    need(completed.returncode==wanted,'CLI exit semantics')
    return {'case':case_id,'status':'PASS','observed_status':actual['status']}


def arguments():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--data-root',required=True,type=Path)
    parser.add_argument('--expect-fixtures-sha256',required=True)
    parser.add_argument('--module',type=Path)
    parser.add_argument('--expect-module-sha256')
    parser.add_argument('--cli',type=Path)
    parser.add_argument('--expect-cli-sha256')
    parser.add_argument('--cli-stage',type=Path)
    return parser.parse_args()


def main():
    global ROOT
    resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
    resource.setrlimit(resource.RLIMIT_CPU,(30,30))
    args=arguments()
    ROOT=args.data_root.resolve(strict=True)
    manifest=verify_freeze(args.expect_fixtures_sha256)
    contract,oracle=load(ROOT/'contract-v2.json'),load(ROOT/'oracle-v2.json')
    results=[]
    module=import_product(args.module,args.expect_module_sha256) if args.module else None
    if args.cli:
        need(args.cli_stage is not None and args.cli_stage.is_relative_to(ROOT),'new scratch CLI stage required')
        need(sha(read(args.cli))==args.expect_cli_sha256,'CLI source mismatch')
        args.cli_stage.mkdir()
    for case_id in manifest['case_ids']:
        try:
            item=run_core(module,case_id,contract,oracle) if module else {'case':case_id,'status':'UNRUN','reason':'NO_PRODUCT_MODULE'}
            if args.cli:
                item['cli']=run_cli(args.cli,case_id,contract,oracle,args.cli_stage)
            results.append(item)
        except (OSError,ValueError,KeyError,TypeError,TimeoutError,subprocess.TimeoutExpired) as error:
            results.append({'case':case_id,'status':'FAIL','error':str(error)[:256]})
    verify_freeze(args.expect_fixtures_sha256)
    failed=any(item['status']=='FAIL' for item in results)
    print(json.dumps({'schema':'transport/accounting-independent-test-run/1','status':'FAIL' if failed else ('TESTED' if module else 'FIXTURE_IDENTITY_CHECKED_PRODUCT_UNRUN'),
                      'fixtures_sha256':args.expect_fixtures_sha256,'module_sha256':args.expect_module_sha256,
                      'results':results},sort_keys=True))
    return 1 if failed else 0


if __name__=='__main__':
    sys.exit(main())
