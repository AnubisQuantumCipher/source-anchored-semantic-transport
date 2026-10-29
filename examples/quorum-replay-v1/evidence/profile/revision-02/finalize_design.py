"""Freeze design-only revision and explicitly retain incomplete oracle gates."""
import copy
import hashlib
import json
from pathlib import Path
P=Path('/dev/shm/semantic-transport-replay-integration-20261029')
O=P/'revision-02'
def read(p):
 return json.loads(p.read_bytes())
def emit(name,obj):
 raw=json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()+b'\n'
 (O/name).write_bytes(raw)
def pin(p):
 raw=p.read_bytes()
 return {'path':str(p),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
def refusal(replay,stage,reason):
 return {'schema':'quorum/replay-refusal/1','accepted_result':False,'replay':replay,'input_request':{'$mechanical':'verified exact REPLAY_REQUEST Pin'},'failed_stage':stage,'reasons':[{'code':reason,'detail':'','record_ids':[]}],'missing_target_keys':[],'missing_predecessor_ids':[],'dimension_status':'NOT_EVALUATED','diagnostic_result':None,'diagnostic_result_accepted':False,'previous_receipt':None,'authority':'NONE','freshness':'UNKNOWN'}
c=read(O/'contract.json')
c['arms']['comparison']='ClaimResult arrays compare exact canonical bytes: no arm field exists there. Compare entire ReplayResult after removing ONLY top-level request field; no recursive field-name exclusion or other normalization. Exact recovered main alias/bytes/Body and derived canonical source index also equal. Original vs transport request pins differ solely because actual package identities differ; all annotations/checker setup charged in both arms.'
c['candidate_decoder']={'path':'/home/sicarii/Projects/source-anchored-semantic-transport/evidence/semantic-handoff-v1/positive-02/transport/decoder','INSTALL':{'bytes':4891,'sha256':'75e1311f9e66c4aafd133d8b00e6e2029f5ae724e3750d13a4d8fb338e34da96'},'RUNTIME':{'bytes':3632,'sha256':'2dad376ffe96800b4c2ee80971bd95ea30d43d5eacd088d83a21ffa0fdf8af90'},'provenance':'Owner reported actual candidate and legacy3 exact match; this preparer has not independently executed full host qualification. No accepted host receipt inferred.'}
emit('contract.json',c)
a=read(P/'manual-oracle-recipes.json')
a['schema']='quorum/full-replay-manual-outcome-recipes/2'
a['status']='MANUAL_DESIGN_JUDGMENTS_WITH_EXPLICIT_LITERALIZATION_BLOCKERS_NOT_EXECUTABLE_ORACLE'
a['prior']=pin(P/'manual-oracle-recipes.json')
for case in a['cases']:
 if case['id']=='F08_MISSING_CHECKER_AND_GRAPH':
  case['prior_expected']=copy.deepcopy(case['expected'])
  case['expected']={'schema':'quorum/bootstrap-refusal/1','status':'REFUSED_HOST_PRECONDITION','authority':'NONE','reason':'CHECKER_FILE_IDENTITY'}
 if case['id']=='F12_DAG_AND_DECLARATION':
  case['prior_expected']=copy.deepcopy(case['expected'])
  case['expected']=refusal('REFUSED_CLOSED_SCHEMA','IDENTITY','DECLARATION_SOURCE_CLOSED_SCHEMA')
 if case['id']=='F05_VERSION_AND_RUNTIME':
  case['correction']='Actual host fully qualified first. Mutate Request.checker.runtime_descriptor.sha256 only, not actual runtime bytes, then mechanically repin Request; Body.tasks[0].version=V2. SCHEMA version refusal precedes replay runtime pin, not outer host failure.'
 if case['expected'].get('accepted_result') is True:
  case['expected']['exclusions']=sorted(case['expected']['exclusions']+['Positional REF role identity does not establish semantic relevance.'])
mutations={
 'F01_ORIGINAL_ACCEPT':[{'op':'select_arm','value':'original'},{'op':'semantic_base','path':str(P/'body.json')}],
 'F02_TRANSPORT_ACCEPT':[{'op':'select_arm','value':'transport'},{'op':'same_semantic_base','path':str(P/'body.json')}],
 'F03_BAD_UTF8_AND_STALE_PIN':[{'op':'replace_body_raw_hex','value':'ff'},{'op':'set_held_request_sha256','value':'0'*64}],
 'F04_BOUNDS_AND_UNKNOWN_RULE':[{'op':'set','path':'/rules/0/kind','value':'UNKNOWN_RULE'},{'op':'pad_record_objects_to','value':97,'literalization':'PENDING exact repeated Blob records; test must materialize before admission'}],
 'F05_VERSION_AND_RUNTIME':[{'op':'set','path':'/tasks/0/version','value':'V2'},{'op':'set_request','path':'/checker/runtime_descriptor/sha256','value':'0'*64}],
 'F06_REQUEST_PIN_AND_RECORD':[{'op':'set_held_request_sha256','value':'0'*64},{'op':'remove_request_record_pin_by_id','value':'RESPONSE'}],
 'F07_PACKAGE_AND_REFERENCE':[{'op':'set_request','path':'/package/sha256','value':'0'*64},{'op':'set','path':'/tasks/0/registry_id','value':'ABSENT'}],
 'F08_MISSING_CHECKER_AND_GRAPH':[{'op':'omit_qualified_file','path':'checker/tools/transport_quorum_replay.py'},{'op':'add_claim_dependency_cycle','literalization':'PENDING complete semantic cyclic records; host refusal independently fixed'}],
 'F09_RECORD_PIN_AND_READING':[{'op':'set_request_record_pin_sha256','id':'RESPONSE','value':'0'*64},{'op':'set','path':'/readings/0/provenance/id','value':'ABSENT'}],
 'F10_REFERENCE_AND_CYCLE':[{'op':'set','path':'/tasks/0/registry_id','value':'ABSENT'},{'op':'add_claim_dependency_cycle','literalization':'PENDING exact cyclic records'}],
 'F11_HISTORY_AND_WITHDRAWAL_CYCLE':[{'op':'append_history_related_id','value':'ABSENT','literalization':'PENDING exact History record/artifact tuple'},{'op':'withdrawal_self_cycle','literalization':'PENDING exact Withdrawal+heldpin tuple'}],
 'F12_DAG_AND_DECLARATION':[{'op':'replace_selected_original_hex','value':'7b','bind':'Rebind full source key, Selector fullrange quote, all affected records and Request pins mechanically; selected original remains fullscope matching declared Q_DECLARATION'},{'op':'add_claim_dependency_cycle','literalization':'PENDING exact cyclic records'}],
 'F13_WITHDRAWAL_DAG_AND_COUNT':[{'op':'withdrawal_self_cycle','literalization':'PENDING exact Withdrawal+heldpins'},{'op':'duplicate_reading','literalization':'PENDING exact duplicate group canonical records'}],
 'F14_IMPORT_MISMATCH':[{'op':'auxiliary_prior_result','value':'R02 expected semantic result with different fully materialized Request pin','literalization':'PENDING only approved mechanical identity derivation, no changed outcomes'},{'op':'set_receipt','path':'/validate_import','value':True}],
 'F15_IGNORED_CLAIMED_VERDICT':[{'op':'set_receipt','path':'/claimed_verdict','value':'UNTRUSTED_DIFFERENT_VERDICT'},{'op':'set_receipt','path':'/validate_import','value':False}]}
for case in a['cases']:
 case['exact_mutation_template']=mutations[case['id']]
 case['binding_rule']='After semantic changes, derive all actual source/Blob/record/manifest/request/package pins by canonical bytes only in typed DAG order; omit ONLY the explicit intentional stale pin mutation applied last. Never obtain expected outcome from checker. PENDING semantic records are a real blocker, not mechanically derivable source hashes.'
a['missing']='The listed PENDING semantic mutation records and full per-field error mapping are genuine blockers to implementation admission/full executable oracle. Mechanical future source/runtime/request pin fill does not resolve these semantic omissions. No complete fullReplay acceptance claim.'
emit('manual-oracle-recipes.json',a)
emit('remaining-blockers.json',{'schema':'quorum/full-replay-design-blockers/2','implementation_admission':'NOT_GRANTED','blockers':[{'id':'R01_TOTAL_ERROR_MAP','exact':'identity-subphases.json groups coarse typed target, static context and Reading reference errors. Freeze precise per-field errors/order from original protocol and existing owned helper phases, with literal multifault witnesses; current manual reason codes are not all identical to generic ledger codes.'},{'id':'R02_LITERAL_SEMANTIC_CONTROLS','exact':'F04,F08,F10,F11,F12,F13 pending exact semantic records. Materialize all actual bodies/source tuples/held event pins and expected complete envelopes BEFORE code, independent review. These are not permitted mechanical SHA-only fill.'},{'id':'R03_EXTERNAL_GRAMMAR_WORK','exact':'typed-content-inventory.json explicitly lists qualified legacy grammar classes but exact transport/handoff digest-site parity and charged field/scan work budget still need source-bound inspection. Do not claim global typed DAG/work closure until this is resolved.'},{'id':'R04_ACTUAL_HOST_QUALIFICATION','exact':'Owner candidate decoder found; actual SOURCE root/held manifest/full files qualification and source-frozen future orchestrator/bootstrap pins remain unavailable. Can derive hashes mechanically after source freeze only after design/oracle blockers resolve.'}],'completed_design_corrections':['Auxiliary import no Request cycle, joint source caps and identical-content exclusion','All main ordinary aliases exact Body SourceVersions and unique complete Request key set','Selected actual DeclarationSource read-ahead immediate IDENTITY failure','Positional syntactic role profile and separate bounded SourceDAG','Outer host vs replay Request mismatch phase distinction','Actual SOURCE manifest closure and preloaded/unknown transport module rejection','Exact top-level-only arm normalization'],'no_scope_expansion':'One coherent full orchestrator/bootstrap/two-arm item remains proposed. No additional component milestones, authority, model study or runtime implementation admitted.'})
files=[p for p in O.iterdir() if p.is_file() and p.suffix=='.json']
emit('design-freeze.json',{'schema':'quorum/full-replay-design-freeze/2','status':'FROZEN_DESIGN_WITH_EXPLICIT_IMPLEMENTATION_BLOCKERS_NOT_FULL_ORACLE','owner':'/root','files':[pin(p) for p in sorted(files)],'originals_unchanged':True,'product_edits':False,'candidate_execution':False,'mechanical_sha_only_fill_authorization':'Pending owner implementation/sourcefreeze admission; never expected semantic/outcome derivation','required_next':'Resolve remaining-blockers.json and independently review exact literal executable oracle before product implementation admission.'})
print(json.dumps(pin(O/'design-freeze.json'),sort_keys=True))
