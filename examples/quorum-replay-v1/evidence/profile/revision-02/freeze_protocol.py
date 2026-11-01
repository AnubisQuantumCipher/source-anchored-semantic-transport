"""Bind original protocol and finite fullReplay profile into exact new bytes."""
import hashlib
import json
from pathlib import Path
P=Path('/dev/shm/semantic-transport-replay-integration-20261029/revision-02')
B=Path('/dev/shm/semantic-transport-wire-20261029/revision-02/protocol-rules.json')
def C(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
def load(p):return json.loads(p.read_bytes())
def write(n,v):
 raw=C(v);(P/n).write_bytes(raw);return {'path':str(P/n),'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}
ledger=load(P/'identity-subphases-02.json')
ledger['identity'][10]['scope']='Every digest-bearing Body field full pin/key bytes check. Absent declared actual target=>REFUSED_MISSING_DEPENDENCY; target present stale sha/length=>REFUSED_INPUT_INTEGRITY. Correct full pin resolving actual wrong record class is deferred to REFERENCES, never assigned expected rank or silently accepted. Follow typed field inventory order.'
ledger['identity'][10]['replay']='REFUSED_MISSING_DEPENDENCY or REFUSED_INPUT_INTEGRITY as exact distinction above'
ledger['references'][0]['scope']='Correct-full-pin wrong semantic record kind/type closure first by typed field inventory, then canonical input array order under exhaustive frozen Context inventory; Guard/node/operand/history ordered exceptions retained.'
ledger['remaining_precision_blocker']='No grouped private error leakage: fixed public wrapper mapping and literal-control expected values apply. Existing fullwire target-missing/stale-pin/wrong-kind distinctions preserved. Private component outputs remain unchanged and are not fullwire acceptance.'
write('identity-subphases-final.json',ledger)
inv=load(P/'typed-content-inventory-02.json')
external=Path('/dev/shm/semantic-transport-replay-controls-20261029/external-closure-01/external-digest-inventory-02.json')
inv['external_digest_grammar']=load(external)['exact_digest_field_inventory']
inv['external_qualification']='Prior rooted SOURCE/INSTALL/RUNTIME qualification plus fresh owner verify_install receipt establishes actual expected installed bytes/source roster linkage; no rebuild/new source regeneration scope. Direct minimal adapter does not invoke historical frozen_manifest/bootstrap/session helpers.'
inv['rows'].extend([
 {'origin':'InstalledLauncher','fields':'MANIFEST_SHA256 literal operational read','actual_target':'actual complete INSTALL bytes','target_rank':'2','origin_rank':'3'},
 {'origin':'BundleSnapshot','fields':'install_manifest sha256 and files mapping incl installed launcher and runtime','actual_target':'INSTALL|Launcher|Runtime|ordinary installed file bytes','target_rank':'2|3|1|0','origin_rank':'4'},
 {'origin':'Transport stored annotations','fields':'anchor slice digest and dictionary digest','actual_target':'exact decoded source slice/dictionary bytes checked by qualified decoder','target_rank':'0','origin_rank':'B+5'}])
inv['resource_profile']['work']='No global vertex vector. Let L be sum actual bounded canonical metadata byte lengths for Body,Request,Envelope,index,checker descriptor, SOURCE,INSTALL,RUNTIME,bundle snapshot and five archive metadata entries plus each parsed DeclarationSource once. Each digest/containment occurrence consumes at least one distinct metadata byte; parse/field visits are bounded by each qualified raw parser. Stream every incidence once. Each target lookup scans at most96 addressable records or15 ordinary complete source keys; checker16/installer128/runtime32 fixed inventories remain separate. A conservative per-invocation candidate work allowance is L*(96+16+16+128+32+1)+15*15*15, charged for every incidence, candidate comparison, scan advance and sourceDAG matrix round. This is an explicit finite engineering bound, not a formal whole-runtime allocation proof. Path enumeration retains independently frozen work/path/output limits. Any accounting inconsistency/refusal cannot produce success. No arbitrary global guessed32-node bound.'
inv['status']='SOURCE_BOUND_TYPED_STREAMING_PLAN_WITH_QUALIFIED_EXTERNAL_GRAMMAR'
write('typed-content-inventory-final.json',inv)
c=load(P/'contract.json')
profile={k:c[k] for k in ('ordinary_sources','auxiliary_cycle_amendment','role_profile','full_phase_order','source_read_ahead','request_label','arms')}
profile['identity_reference_graph_ledger']=ledger
profile['typed_content_rank_inventory']=inv['rows']
profile['digest_field_inventory']=inv['external_digest_grammar']
profile['resource_rules']=inv['resource_profile']
profile['minimal_adapter']='Main source carriage only; Q_RECORDS is the identical actual Body bytes, no semantic overlay. Exact Body.SourceVersion alias-to-completekey plus bytes; ordinary original index noZIP; transport qualified Receiver exact share/archive/STS1+source metadata+recovered bytes. Historical handoff full session/bootstrap helpers not invoked. All same annotations/checker/setup costs counted.'
profile['outer_host']='Actual trusted preimport bootstrap byte pin/strict16checkerhelper descriptor/Python/qualified SOURCE+INSTALL+RUNTIME/native/import-origin checks are prerequisite. No caller boolean, no fullReplay phase on invalid host. Existing installed decoder source qualification does not discharge future QUORUM bootstrap execution.'
raw=write('protocol-rules.json',{'schema':'quorum/full-replay-protocol/1','base_protocol_rules':load(B),'full_replay_profile':profile})
if raw['bytes']>65536:raise ValueError('protocol size cap')
write('protocol-freeze.json',{'schema':'quorum/full-replay-protocol-freeze/1','protocol':raw,'base_protocol':{'bytes':len(B.read_bytes()),'sha256':hashlib.sha256(B.read_bytes()).hexdigest()},'literal_oracle':{'path':str(P/'literal-controls'/'oracle.json'),'sha256':hashlib.sha256((P/'literal-controls'/'oracle.json').read_bytes()).hexdigest()},'scope':'Source-bound contract/oracle preparation only; actual owner review/admission and future sourcefreeze mechanical pins still required. No runtime acceptedReplay by this preparer.'})
print(raw)
