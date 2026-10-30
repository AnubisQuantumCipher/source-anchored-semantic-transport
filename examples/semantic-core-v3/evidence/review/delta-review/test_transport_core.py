"""Independent schema and frozen truth-table regression controls.

Native checks explicitly skip unless TRANSPORT_CORE_NATIVE and
TRANSPORT_CORE_NATIVE_SHA256 are supplied. Expected tables predate the
implementation. Original failures and repair receipts remain preserved.
"""
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
import transport_core as core

CAP = 4194304
SOURCE = b'a b e x q r d empty'
RESULTS = []
HERE = None
NATIVE = None

FROZEN = json.loads(r'''{
  "base_model": {
    "domains": [
      {
        "id": "d",
        "members": [
          "a",
          "b"
        ]
      },
      {
        "id": "empty",
        "members": []
      }
    ],
    "predicates": [
      {
        "arity": 0,
        "id": "e"
      },
      {
        "arity": 0,
        "id": "x"
      },
      {
        "arity": 1,
        "id": "q"
      },
      {
        "arity": 2,
        "id": "r"
      }
    ],
    "terms": [
      "a",
      "b"
    ],
    "tuples": [
      {
        "arguments": [],
        "predicate": "e",
        "truth": "KNOWN_TRUE"
      },
      {
        "arguments": [],
        "predicate": "x",
        "truth": "KNOWN_FALSE"
      },
      {
        "arguments": [
          "a"
        ],
        "predicate": "q",
        "truth": "KNOWN_TRUE"
      },
      {
        "arguments": [
          "b"
        ],
        "predicate": "q",
        "truth": "KNOWN_FALSE"
      },
      {
        "arguments": [
          "a",
          "b"
        ],
        "predicate": "r",
        "truth": "KNOWN_TRUE"
      }
    ]
  },
  "binary_truth_tables": {
    "and": [
      [
        "UNRESOLVED",
        "UNRESOLVED",
        "UNRESOLVED"
      ],
      [
        "UNRESOLVED",
        "KNOWN_FALSE",
        "KNOWN_FALSE"
      ],
      [
        "UNRESOLVED",
        "KNOWN_TRUE",
        "UNRESOLVED"
      ],
      [
        "KNOWN_FALSE",
        "UNRESOLVED",
        "KNOWN_FALSE"
      ],
      [
        "KNOWN_FALSE",
        "KNOWN_FALSE",
        "KNOWN_FALSE"
      ],
      [
        "KNOWN_FALSE",
        "KNOWN_TRUE",
        "KNOWN_FALSE"
      ],
      [
        "KNOWN_TRUE",
        "UNRESOLVED",
        "UNRESOLVED"
      ],
      [
        "KNOWN_TRUE",
        "KNOWN_FALSE",
        "KNOWN_FALSE"
      ],
      [
        "KNOWN_TRUE",
        "KNOWN_TRUE",
        "KNOWN_TRUE"
      ]
    ],
    "if": [
      [
        "UNRESOLVED",
        "UNRESOLVED",
        "UNRESOLVED"
      ],
      [
        "UNRESOLVED",
        "KNOWN_FALSE",
        "UNRESOLVED"
      ],
      [
        "UNRESOLVED",
        "KNOWN_TRUE",
        "KNOWN_TRUE"
      ],
      [
        "KNOWN_FALSE",
        "UNRESOLVED",
        "KNOWN_TRUE"
      ],
      [
        "KNOWN_FALSE",
        "KNOWN_FALSE",
        "KNOWN_TRUE"
      ],
      [
        "KNOWN_FALSE",
        "KNOWN_TRUE",
        "KNOWN_TRUE"
      ],
      [
        "KNOWN_TRUE",
        "UNRESOLVED",
        "UNRESOLVED"
      ],
      [
        "KNOWN_TRUE",
        "KNOWN_FALSE",
        "KNOWN_FALSE"
      ],
      [
        "KNOWN_TRUE",
        "KNOWN_TRUE",
        "KNOWN_TRUE"
      ]
    ]
  },
  "evaluation_cases": [
    {
      "id": "tuple_true",
      "tree": [
        "pred",
        "q",
        [
          "a"
        ]
      ],
      "truth": "KNOWN_TRUE"
    },
    {
      "id": "tuple_false",
      "tree": [
        "pred",
        "q",
        [
          "b"
        ]
      ],
      "truth": "KNOWN_FALSE"
    },
    {
      "id": "ordered_tuple_not_commutative",
      "tree": [
        "pred",
        "r",
        [
          "b",
          "a"
        ]
      ],
      "truth": "UNRESOLVED"
    },
    {
      "id": "nullary",
      "tree": [
        "pred",
        "e",
        []
      ],
      "truth": "KNOWN_TRUE"
    },
    {
      "id": "missing_tuple",
      "tree": [
        "pred",
        "r",
        [
          "a",
          "a"
        ]
      ],
      "truth": "UNRESOLVED"
    },
    {
      "id": "universal_contains_false",
      "tree": [
        "all",
        "q",
        "d"
      ],
      "truth": "KNOWN_FALSE"
    },
    {
      "id": "existential_contains_true",
      "tree": [
        "some",
        "q",
        "d"
      ],
      "truth": "KNOWN_TRUE"
    },
    {
      "id": "empty_universal",
      "tree": [
        "all",
        "q",
        "empty"
      ],
      "truth": "KNOWN_TRUE"
    },
    {
      "id": "empty_existential",
      "tree": [
        "some",
        "q",
        "empty"
      ],
      "truth": "KNOWN_FALSE"
    },
    {
      "id": "must_true",
      "outcome": "SATISFIED",
      "tree": [
        "must",
        [
          "pred",
          "q",
          [
            "a"
          ]
        ]
      ],
      "truth": "UNRESOLVED"
    },
    {
      "id": "must_false",
      "outcome": "VIOLATED",
      "tree": [
        "must",
        [
          "pred",
          "q",
          [
            "b"
          ]
        ]
      ],
      "truth": "UNRESOLVED"
    },
    {
      "id": "must_missing",
      "outcome": "UNKNOWN",
      "tree": [
        "must",
        [
          "pred",
          "r",
          [
            "a",
            "a"
          ]
        ]
      ],
      "truth": "UNRESOLVED"
    },
    {
      "append_tuples": [
        {
          "arguments": [
            "a"
          ],
          "predicate": "q",
          "truth": "KNOWN_FALSE"
        }
      ],
      "id": "conflict",
      "outcome": "UNKNOWN",
      "tree": [
        "must",
        [
          "pred",
          "q",
          [
            "a"
          ]
        ]
      ],
      "truth": "UNRESOLVED"
    },
    {
      "append_tuples": [
        {
          "arguments": [
            "a"
          ],
          "predicate": "q",
          "truth": "UNRESOLVED"
        }
      ],
      "id": "explicit_unresolved_with_true",
      "outcome": "UNKNOWN",
      "tree": [
        "must",
        [
          "pred",
          "q",
          [
            "a"
          ]
        ]
      ],
      "truth": "UNRESOLVED"
    },
    {
      "id": "vacuous_event",
      "outcome": "SATISFIED",
      "replace_tuple_truth": {
        "arguments": [],
        "predicate": "e",
        "truth": "KNOWN_FALSE"
      },
      "tree": [
        "must",
        [
          "if",
          [
            "pred",
            "e",
            []
          ],
          [
            "pred",
            "q",
            [
              "b"
            ]
          ]
        ]
      ],
      "truth": "UNRESOLVED"
    },
    {
      "id": "known_exception",
      "outcome": "SATISFIED",
      "replace_tuple_truth": {
        "arguments": [],
        "predicate": "x",
        "truth": "KNOWN_TRUE"
      },
      "tree": [
        "must",
        [
          "if",
          [
            "and",
            [
              "pred",
              "e",
              []
            ],
            [
              "not",
              [
                "pred",
                "x",
                []
              ]
            ]
          ],
          [
            "pred",
            "q",
            [
              "b"
            ]
          ]
        ]
      ],
      "truth": "UNRESOLVED"
    },
    {
      "id": "unknown_guard_false_action",
      "outcome": "UNKNOWN",
      "replace_tuple_truth": {
        "arguments": [],
        "predicate": "e",
        "truth": "UNRESOLVED"
      },
      "tree": [
        "must",
        [
          "if",
          [
            "pred",
            "e",
            []
          ],
          [
            "pred",
            "q",
            [
              "b"
            ]
          ]
        ]
      ],
      "truth": "UNRESOLVED"
    },
    {
      "id": "unknown_guard_true_action",
      "outcome": "SATISFIED",
      "replace_tuple_truth": {
        "arguments": [],
        "predicate": "e",
        "truth": "UNRESOLVED"
      },
      "tree": [
        "must",
        [
          "if",
          [
            "pred",
            "e",
            []
          ],
          [
            "pred",
            "q",
            [
              "a"
            ]
          ]
        ]
      ],
      "truth": "UNRESOLVED"
    },
    {
      "id": "no_model",
      "model": null,
      "outcome": null,
      "status": "NOT_EVALUATED",
      "tree": [
        "must",
        [
          "pred",
          "q",
          [
            "a"
          ]
        ]
      ]
    }
  ],
  "quantifier_folds": [
    {
      "all": "KNOWN_TRUE",
      "instance_truths": [],
      "some": "KNOWN_FALSE"
    },
    {
      "all": "UNRESOLVED",
      "instance_truths": [
        "UNRESOLVED"
      ],
      "some": "UNRESOLVED"
    },
    {
      "all": "KNOWN_FALSE",
      "instance_truths": [
        "KNOWN_FALSE"
      ],
      "some": "KNOWN_FALSE"
    },
    {
      "all": "KNOWN_TRUE",
      "instance_truths": [
        "KNOWN_TRUE"
      ],
      "some": "KNOWN_TRUE"
    },
    {
      "all": "UNRESOLVED",
      "instance_truths": [
        "KNOWN_TRUE",
        "UNRESOLVED"
      ],
      "some": "KNOWN_TRUE"
    },
    {
      "all": "KNOWN_FALSE",
      "instance_truths": [
        "KNOWN_FALSE",
        "UNRESOLVED"
      ],
      "some": "UNRESOLVED"
    },
    {
      "all": "KNOWN_FALSE",
      "instance_truths": [
        "KNOWN_TRUE",
        "KNOWN_FALSE"
      ],
      "some": "KNOWN_TRUE"
    },
    {
      "all": "KNOWN_TRUE",
      "instance_truths": [
        "KNOWN_TRUE",
        "KNOWN_TRUE"
      ],
      "some": "KNOWN_TRUE"
    },
    {
      "all": "KNOWN_FALSE",
      "instance_truths": [
        "KNOWN_FALSE",
        "KNOWN_FALSE"
      ],
      "some": "KNOWN_FALSE"
    },
    {
      "all": "UNRESOLVED",
      "instance_truths": [
        "UNRESOLVED",
        "UNRESOLVED"
      ],
      "some": "UNRESOLVED"
    }
  ],
  "unary_truth_tables": {
    "must": [
      [
        "UNRESOLVED",
        "UNKNOWN"
      ],
      [
        "KNOWN_FALSE",
        "VIOLATED"
      ],
      [
        "KNOWN_TRUE",
        "SATISFIED"
      ]
    ],
    "not": [
      [
        "UNRESOLVED",
        "UNRESOLVED"
      ],
      [
        "KNOWN_FALSE",
        "KNOWN_TRUE"
      ],
      [
        "KNOWN_TRUE",
        "KNOWN_FALSE"
      ]
    ]
  }
}''')

SCHEMA_CASES = [
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

def base(core):
    old = FROZEN['base_model']
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
    cases = SCHEMA_CASES
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

def lower_expression(expression, nodes):
    """Convert fixed oracle fixtures iteratively; no semantic interpretation."""
    pending, positions = [(expression, False)], {}
    for _ in range(768):
        if not pending:
            return positions[id(expression)]
        item, ready = pending.pop()
        op = item[0]
        if op == 'pred':
            node = {'op': op, 'predicate': item[1], 'terms': item[2]}
        elif op in ('all', 'some'):
            node = {'op': op, 'predicate': item[1], 'domain': item[2]}
        elif ready:
            node = {'op': op, 'args': [positions[id(child)] for child in item[1:]]}
        else:
            pending.append((item, True))
            pending.extend((child, False) for child in reversed(item[1:]))
            continue
        if len(nodes) == 256:
            raise ValueError('independent fixture node bound')
        nodes.append(node)
        positions[id(item)] = len(nodes) - 1
    raise ValueError('independent fixture traversal bound')

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
    frozen=FROZEN
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

class CoreIndependentChecks(unittest.TestCase):
    def setUp(self):
        global HERE
        RESULTS.clear()
        self.temporary = tempfile.TemporaryDirectory(prefix='core-independent-test-')
        self.addCleanup(self.temporary.cleanup)
        HERE = Path(self.temporary.name)
        (HERE / 'frames').mkdir(mode=0o700)

    def check_results(self):
        self.assertTrue(RESULTS, 'no independent checks executed')
        for result in RESULTS:
            with self.subTest(case=result['id']):
                self.assertTrue(result['pass'], json.dumps(result, sort_keys=True))

    def test_schema_guards(self):
        value, finite = base(core)
        schema_checks(core, value, finite)
        model_checks(core, value, finite)
        boundary_checks(core, value, finite)
        self.check_results()

    def test_published_operator_dictionary_matches_frozen_oracle(self):
        dictionary = core.OPERATORS
        order = [row[0] for row in FROZEN['unary_truth_tables']['not']]
        self.assertEqual(dictionary['schema'], 'transport/core-operators/3')
        self.assertEqual(dictionary['truth_order'], order)
        self.assertEqual(set(dictionary['entries']),
                         {'pred', 'not', 'and', 'if', 'all', 'some', 'must'})
        for name in ('not_table', 'must_table'):
            self.assertEqual(len(dictionary[name]), len(order))
        for name in ('and_table', 'if_table'):
            self.assertEqual(len(dictionary[name]), len(order))
            self.assertTrue(all(len(row) == len(order) for row in dictionary[name]))
        for value, expected in FROZEN['unary_truth_tables']['not']:
            self.assertEqual(dictionary['not_table'][order.index(value)], expected)
        for value, expected in FROZEN['unary_truth_tables']['must']:
            self.assertEqual(dictionary['must_table'][order.index(value)], expected)
        for operator, rows in FROZEN['binary_truth_tables'].items():
            for left, right, expected in rows:
                with self.subTest(operator=operator, left=left, right=right):
                    self.assertEqual(dictionary[operator + '_table']
                                     [order.index(left)][order.index(right)], expected)
        self.assertEqual(dictionary['signatures'], {
            'pred': 'Predicate(Term*) -> Fact; exact declared arity 0..2',
            'not': 'Fact -> Fact', 'and': 'Fact,Fact -> Fact',
            'if': 'Fact,Fact -> Fact', 'must': 'Fact -> Norm',
            'all': 'UnaryPredicate,FiniteDomain -> Fact',
            'some': 'UnaryPredicate,FiniteDomain -> Fact'})
        self.assertEqual(dictionary['norm_truth'], 'UNRESOLVED')
        self.assertEqual(dictionary['fact_outcome'], 'UNKNOWN')
        self.assertEqual(dictionary['interpretation'], 'SUPPLIED_MODEL_ONLY_NOT_WORLD_TRUTH')
        self.assertEqual(dictionary['execution_authority'], 'NONE')

    def test_frozen_native_truth_tables(self):
        global NATIVE
        path = os.environ.get('TRANSPORT_CORE_NATIVE')
        expected = os.environ.get('TRANSPORT_CORE_NATIVE_SHA256')
        if path is None and expected is None:
            self.skipTest('native checks UNRUN: supply explicit path and SHA256')
        self.assertIsNotNone(path, 'native path and SHA256 must be supplied together')
        self.assertIsNotNone(expected, 'native path and SHA256 must be supplied together')
        NATIVE = Path(path)
        self.assertTrue(NATIVE.is_absolute(), 'native path must be absolute')
        self.assertEqual(digest(NATIVE.read_bytes()), expected)
        value, finite = base(core)
        frozen_checks(core, value, finite)
        self.assertEqual(digest(NATIVE.read_bytes()), expected, 'native changed during checks')
        self.check_results()


if __name__ == '__main__':
    unittest.main()
