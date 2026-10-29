"""Bounded independent schema and frozen-oracle execution; no semantic implementation."""
import base64
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import resource
import shutil
import struct
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
NATIVE = Path('/dev/shm/semantic-transport-core-20261029/native/bin/transport_core_native')
FROZEN = Path('/dev/shm/semantic-core-contract-review-20261029/oracle.json')
CAP = 4194304
RESULTS = []
SOURCE = b'a b e x q r d empty'
sys.dont_write_bytecode = True


def digest(data):
    return hashlib.sha256(data).hexdigest()


def emit(name, data):
    if sum(p.stat().st_size for p in HERE.rglob('*') if p.is_file()) + len(data) > CAP:
        raise RuntimeError('independent evidence budget exceeded')
    path = HERE / name
    with path.open('xb') as stream:
        stream.write(data)
    path.chmod(0o600)
    return path


def load_core():
    folder = HERE / 'reviewed-modules'
    folder.mkdir(mode=0o700)
    pins = []
    for name in ('transport_core', 'transport_schema', 'transport_wire', 'transport_operators'):
        data = (REPO / 'tools' / (name + '.py')).read_bytes()
        path = emit('reviewed-modules/' + name + '.py', data)
        pins.append({'path':str(path), 'sha256':digest(data)})
    sys.path.insert(0, str(folder))
    import transport_core
    emit('pins.json', json.dumps({'modules':pins,'native_sha256':digest(NATIVE.read_bytes()),
         'oracle_sha256':digest(FROZEN.read_bytes())},sort_keys=True,indent=2).encode()+b'\n')
    return transport_core


def base(core):
    old = json.loads(FROZEN.read_text())['base_model']
    symbols = []
    for name in old['terms']:
        symbols.append({'id':name,'kind':'term','binding':{'kind':'name','name':name}})
    for row in old['predicates']:
        symbols.append(dict(row,kind='predicate',binding={'kind':'name','name':row['id']}))
    for row in old['domains']:
        symbols.append(dict(row,kind='domain',binding={'kind':'name','name':row['id']}))
    plan = {'schema':core.PLAN,'translation':'declared','symbols':symbols,'tree':{
        'schema':core.GRAMMAR,'nodes':[{'op':'pred','predicate':'q','terms':['a']}],'root':0}}
    rows=[{'predicate':r['predicate'],'terms':r['arguments'],'truth':r['truth']} for r in old['tuples']]
    return plan, {'schema':core.MODEL,'symbols':copy.deepcopy(symbols),'tuples':rows}


def record(identifier, expected, action, inputs):
    try:
        value = action()
        observed = 'ADMITTED'
        detail = value.hex() if type(value) is bytes else None
    except Exception as error:
        observed = 'REFUSED'
        detail = {'exception':type(error).__name__,'reason':str(error)[:1024]}
    RESULTS.append({'id':identifier,'expected':expected,'observed':observed,
                    'pass':observed == expected,'detail':detail,'input':inputs})


def schema_checks(core, p, m):
    cases = [
      ('old_plan',lambda v:v.update(schema='transport/core-plan/2')),
      ('future_plan',lambda v:v.update(schema='transport/core-plan/4')),
      ('old_grammar',lambda v:v['tree'].update(schema='transport/meaning/2')),
      ('future_grammar',lambda v:v['tree'].update(schema='transport/meaning/999')),
      ('extra_plan_field',lambda v:v.update(trusted=True)),
      ('translation_bool',lambda v:v.update(translation=True)),
      ('translation_dict',lambda v:v.update(translation={})),
      ('symbols_empty',lambda v:v.update(symbols=[])),
      ('symbol_collision',lambda v:v['symbols'][1].update(id='a')),
      ('symbol_wrong_role',lambda v:v['symbols'][0].update(kind='predicate')),
      ('symbol_bad_ident',lambda v:v['symbols'][0].update(id='a\u200b')),
      ('arity_bool',lambda v:v['symbols'][2].update(arity=True)),
      ('arity_three',lambda v:v['symbols'][2].update(arity=3)),
      ('name_control',lambda v:v['symbols'][0]['binding'].update(name='a\x00')),
      ('name_surrogate',lambda v:v['symbols'][0]['binding'].update(name='\ud800')),
      ('name_overcap',lambda v:v['symbols'][0]['binding'].update(name='a'*256)),
      ('duplicate_member',lambda v:v['symbols'][6].update(members=['a','a'])),
      ('unknown_member',lambda v:v['symbols'][6].update(members=['absent'])),
      ('wrong_role_member',lambda v:v['symbols'][6].update(members=['q'])),
      ('missing_nodes',lambda v:v['tree'].pop('nodes')),
      ('empty_nodes',lambda v:v['tree'].update(nodes=[])),
      ('bool_root',lambda v:v['tree'].update(root=False)),
      ('float_root',lambda v:v['tree'].update(root=0.0)),
      ('negative_root',lambda v:v['tree'].update(root=-1)),
      ('absent_root',lambda v:v['tree'].update(root=1)),
      ('unknown_predicate',lambda v:v['tree']['nodes'][0].update(predicate='missing')),
      ('wrong_role_predicate',lambda v:v['tree']['nodes'][0].update(predicate='d')),
      ('wrong_arity_predicate',lambda v:v['tree']['nodes'][0].update(terms=[])),
      ('unknown_term',lambda v:v['tree']['nodes'][0].update(terms=['missing'])),
      ('term_bool',lambda v:v['tree']['nodes'][0].update(terms=[False])),
      ('wrong_role_term',lambda v:v['tree']['nodes'][0].update(terms=['q'])),
      ('quantifier_binary',lambda v:v['tree']['nodes'].__setitem__(0,{'op':'all','predicate':'r','domain':'d'})),
      ('quantifier_nullary',lambda v:v['tree']['nodes'].__setitem__(0,{'op':'some','predicate':'e','domain':'d'})),
      ('quantifier_term_domain',lambda v:v['tree']['nodes'].__setitem__(0,{'op':'some','predicate':'q','domain':'a'})),
      ('extra_quantifier_body',lambda v:v['tree']['nodes'].__setitem__(0,{'op':'all','predicate':'q','domain':'d','body':0})),
      ('opaque_atom',lambda v:v['tree']['nodes'].__setitem__(0,{'op':'atom','symbol':'a'})),
      ('variable',lambda v:v['tree']['nodes'].__setitem__(0,{'op':'var','name':'a'})),
      ('clock',lambda v:v['tree']['nodes'].__setitem__(0,{'op':'within','args':[0]})),
      ('cycle',lambda v:v['tree']['nodes'].__setitem__(0,{'op':'not','args':[0]})),
      ('forward_ref',lambda v:v['tree']['nodes'].__setitem__(0,{'op':'not','args':[1]})),
      ('negative_ref',lambda v:v['tree']['nodes'].__setitem__(0,{'op':'not','args':[-1]})),
      ('bool_ref',lambda v:v['tree'].update(nodes=[v['tree']['nodes'][0],{'op':'not','args':[False]}],root=1)),
      ('unreachable_node',lambda v:v['tree'].update(nodes=[v['tree']['nodes'][0],v['tree']['nodes'][0]],root=1)),
    ]
    record('schema_valid','ADMITTED',lambda:core.plan(core.canonical(p),SOURCE),p)
    for name, mutate in cases:
        value=copy.deepcopy(p)
        mutate(value)
        record(name,'REFUSED',lambda:core.plan(core.canonical(value),SOURCE),value)
    for name,raw in [('duplicate_key',b'{"schema":"a","schema":"b"}'),('trailing',core.canonical(p)+b' x'),
                     ('float_json',core.canonical(p).replace(b'"root":0',b'"root":0.0')),
                     ('nan_json',core.canonical(p).replace(b'"root":0',b'"root":NaN')),
                     ('invalid_utf8',b'\xff'),('overcap_json',b' '*65537)]:
        record(name,'REFUSED',lambda:core.plan(raw,SOURCE),{'bytes':len(raw),'base64':base64.b64encode(raw).decode()})


def model_checks(core,p,m):
    cases=[('wrong_version',lambda v:v.update(schema='transport/finite-model/2')),
      ('symbols_swapped',lambda v:v['symbols'].reverse()),
      ('arity_swapped',lambda v:v['symbols'][2].update(arity=1)),
      ('tuple_unknown_predicate',lambda v:v['tuples'][0].update(predicate='absent')),
      ('tuple_wrong_role_predicate',lambda v:v['tuples'][0].update(predicate='a')),
      ('tuple_wrong_arity',lambda v:v['tuples'][0].update(terms=['a'])),
      ('tuple_unknown_term',lambda v:v['tuples'][2].update(terms=['absent'])),
      ('tuple_wrong_role_term',lambda v:v['tuples'][2].update(terms=['q'])),
      ('truth_bool',lambda v:v['tuples'][0].update(truth=True)),
      ('truth_numeric',lambda v:v['tuples'][0].update(truth=2)),
      ('truth_unknown',lambda v:v['tuples'][0].update(truth='true')),
      ('extra_row_field',lambda v:v['tuples'][0].update(trusted=True)),
      ('duplicate_exact_row',lambda v:v['tuples'].append(copy.deepcopy(v['tuples'][0]))),
      ('tuple_overcap',lambda v:v.update(tuples=[copy.deepcopy(v['tuples'][0]) for _ in range(257)]))]
    for name,mutate in cases:
        value=copy.deepcopy(m)
        mutate(value)
        record('model_'+name,'REFUSED',lambda:core.model(core.canonical(value),p['symbols'],SOURCE),value)
    span={'kind':'span','span':[0,1],'quote':'a'}
    for name,binding,expected in [('span_valid',span,'ADMITTED'),('span_bool',dict(span,span=[False,1]),'REFUSED'),
      ('span_wrong_quote',dict(span,quote='b'),'REFUSED'),('span_reversed',dict(span,span=[1,0]),'REFUSED')]:
        value=copy.deepcopy(p)
        value['symbols'][0]['binding']=binding
        record(name,expected,lambda:core.plan(core.canonical(value),SOURCE),value)
    for name,mutate in [('wire_bad_plan_version',lambda v:v.update(schema='wrong')),
                        ('wire_unknown_translation',lambda v:v.update(translation='may')),
                        ('wire_extra_field',lambda v:v.update(authorizes=True))]:
        value=copy.deepcopy(p)
        mutate(value)
        record(name,'REFUSED',lambda:core.wire(value,m,SOURCE),value)


def lower_expression(expression,nodes):
    op=expression[0]
    if op=='pred':
        node={'op':op,'predicate':expression[1],'terms':expression[2]}
    elif op in ('all','some'):
        node={'op':op,'predicate':expression[1],'domain':expression[2]}
    else:
        args=[]
        for child in expression[1:]:
            args.append(lower_expression(child,nodes))
        node={'op':op,'args':args}
    nodes.append(node)
    return len(nodes)-1


def native_case(core,p,m,name,expression,expected):
    value=copy.deepcopy(p)
    nodes=[]
    root=lower_expression(expression,nodes)
    value['tree'].update(nodes=nodes,root=root)
    checked=core.plan(core.canonical(value),SOURCE)
    frame=core.wire(checked,m,SOURCE)
    path=emit('frames/'+name+'.stc',frame)
    run=subprocess.run([str(NATIVE),str(path)],stdin=subprocess.DEVNULL,capture_output=True,timeout=3,check=False)
    error=None
    actual=None
    try:
        if run.returncode!=0 or run.stderr:
            raise RuntimeError('native refusal '+repr(run.stderr))
        actual=core.native_values(run.stdout,checked)[-1]
    except Exception as exc:
        error={'exception':type(exc).__name__,'reason':str(exc)}
    passed=actual is not None and all(actual[k]==v for k,v in expected.items())
    RESULTS.append({'id':name,'pass':passed,'expected':expected,'actual':actual,'error':error,
      'exit_code':run.returncode,'stdout':run.stdout.decode('ascii','backslashreplace'),
      'stderr':run.stderr.decode('ascii','backslashreplace'),'frame_sha256':digest(frame),
      'plan':value,'model':m})


def frozen_checks(core,p,m):
    frozen=json.loads(FROZEN.read_text())
    for op,rows in frozen['unary_truth_tables'].items():
        for i,(a,out) in enumerate(rows):
            model=copy.deepcopy(m)
            model['tuples']=[{'predicate':'e','terms':[],'truth':a}]
            expected={'truth':out,'outcome':'UNKNOWN','sort':'FACT'} if op=='not' else {
                'truth':'UNRESOLVED','outcome':out,'sort':'NORM'}
            native_case(core,p,model,'frozen_'+op+'_'+str(i),[op,['pred','e',[]]],expected)
    for op,rows in frozen['binary_truth_tables'].items():
        for i,(a,b,out) in enumerate(rows):
            model=copy.deepcopy(m)
            model['tuples']=[{'predicate':'e','terms':[],'truth':a},{'predicate':'x','terms':[],'truth':b}]
            native_case(core,p,model,'frozen_'+op+'_'+str(i),[op,['pred','e',[]],['pred','x',[]]],
                {'truth':out,'outcome':'UNKNOWN','sort':'FACT'})
    for i,row in enumerate(frozen['quantifier_folds']):
        model=copy.deepcopy(m)
        members=['a','b'][:len(row['instance_truths'])]
        for symbols in (p['symbols'],model['symbols']):
            next(s for s in symbols if s['id']=='d')['members']=members
        model['tuples']=[{'predicate':'q','terms':[term],'truth':truth} for term,truth in zip(members,row['instance_truths'],strict=True)]
        for op in ('all','some'):
            native_case(core,p,model,'frozen_'+op+'_'+str(i),[op,'q','d'],{'truth':row[op],'sort':'FACT','outcome':'UNKNOWN'})
    p,m=base(core)
    for row in frozen['evaluation_cases']:
        if row.get('model','present') is None:
            continue
        model=copy.deepcopy(m)
        for add in row.get('append_tuples',[]):
            model['tuples'].append({'predicate':add['predicate'],'terms':add['arguments'],'truth':add['truth']})
        if 'replace_tuple_truth' in row:
            item=row['replace_tuple_truth']
            next(r for r in model['tuples'] if r['predicate']==item['predicate'] and r['terms']==item['arguments'])['truth']=item['truth']
        expected={'truth':row['truth'],'outcome':row.get('outcome','UNKNOWN'),
                  'sort':'NORM' if row['tree'][0]=='must' else 'FACT'}
        native_case(core,p,model,'frozen_'+row['id'],row['tree'],expected)


def boundary_checks(core,p,m):
    for count,expect in [(256,'ADMITTED'),(257,'REFUSED')]:
        value=copy.deepcopy(p)
        value['tree']['nodes']=[{'op':'pred','predicate':'e','terms':[]}]
        value['tree']['nodes'].extend({'op':'not','args':[i-1]} for i in range(1,count))
        value['tree']['root']=count-1
        record('node_cap_'+str(count),expect,lambda:core.plan(core.canonical(value),SOURCE),value)
    for count,expect in [(64,'ADMITTED'),(65,'REFUSED')]:
        value=copy.deepcopy(p)
        value['symbols'].extend({'id':'t'+str(i),'kind':'term','binding':{'kind':'name','name':'t'+str(i)}} for i in range(count-len(value['symbols'])))
        record('symbol_cap_'+str(count),expect,lambda:core.plan(core.canonical(value),SOURCE),value)
    value=copy.deepcopy(p)
    value['symbols'].extend({'id':'t'+str(i),'kind':'term','binding':{'kind':'name','name':'t'+str(i)}} for i in range(16))
    terms=['t'+str(i) for i in range(16)]
    rows=[{'predicate':'r','terms':[a,b],'truth':'KNOWN_TRUE'} for a in terms for b in terms]
    model={'schema':core.MODEL,'symbols':value['symbols'],'tuples':rows}
    record('tuple_cap_256','ADMITTED',lambda:core.model(core.canonical(model),value['symbols'],SOURCE),model)
    model=copy.deepcopy(model)
    model['tuples'].append({'predicate':'r','terms':['a','b'],'truth':'KNOWN_TRUE'})
    record('tuple_cap_257','REFUSED',lambda:core.model(core.canonical(model),value['symbols'],SOURCE),model)


def main():
    resource.setrlimit(resource.RLIMIT_AS,(268435456,268435456))
    resource.setrlimit(resource.RLIMIT_CPU,(60,60))
    resource.setrlimit(resource.RLIMIT_FSIZE,(CAP,CAP))
    (HERE/'frames').mkdir(mode=0o700)
    native_pin=digest(NATIVE.read_bytes())
    core=load_core()
    p,m=base(core)
    schema_checks(core,p,m)
    model_checks(core,p,m)
    frozen_checks(core,p,m)
    p,m=base(core)
    boundary_checks(core,p,m)
    if digest(NATIVE.read_bytes())!=native_pin:
        raise RuntimeError('native executable changed during independent checks')
    failed=[r['id'] for r in RESULTS if not r['pass']]
    report={'schema':'semantic-core-independent-execution/1','status':'FAILED' if failed else 'PASS',
      'native_sha256':native_pin,'failed_cases':failed,'cases':RESULTS,
      'claims':{'execution':'TESTED','formal_proof':'NOT_ASSESSED','package_integration':'UNRUN',
                'missing_model_entrypoint':'UNRUN','source_entailment':'UNPROVEN'}}
    emit('results.json',json.dumps(report,ensure_ascii=True,sort_keys=True,indent=2).encode()+b'\n')
    print(json.dumps({'status':report['status'],'cases':len(RESULTS),'failed_cases':failed,'native_sha256':native_pin}))


if __name__=='__main__':
    main()
