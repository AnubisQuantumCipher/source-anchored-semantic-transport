"""Prefreeze review clarifications only; no product checker."""
import json,shutil
from pathlib import Path
p=Path('/dev/shm/semantic-transport-context-bindings-20261029')
def canon(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
shutil.copyfile(p/'contract.json',p/'contract-draft03.json')
c=json.loads((p/'contract.json').read_bytes());c['caps']['one_record_canonical_scratch_bytes']=65536;c['caps']['sort_key_scratch_bytes']=65536
c['caps']['work']='Only loops over shape-bounded lists: <=96 addressable records, <=16 Claim labels, <=8 Seats, <=32 Manifests with <=64 dependencies/16 selectors/16 sources/4 rules each. No recursion or unbounded cache. A sort may cache its finite key vector: aggregate canonical input-subtree sort-key bytes<=Body65536; record IDs/derived Claim IDs similarly bounded by contained record bytes. At most one sort key vector at a time; canonical complete-record scratch separately<=65536, output<=32768, all existing process-memory caps remain. This is not a one-key-at-a-time claim, and no arbitrary caller-selected tree is sorted. Bound before accumulating; overflow CONTEXT_SORT_KEY_BOUND at CONTEXT_ARRAY_ORDER, no partial result.'
for row in c['stage_order']:
 if row['stage']=='CONTEXT_REGISTRY':row['rule']=row['rule'].replace('Every body Seat lexical','Every body Seat in C(id) order')
 if row['stage']=='CONTEXT_TASK':
  row['rule']=row['rule'].replace('then lexical rows exact complete canonical ClaimKeys (CONTEXT_TASK_ROSTER_PIN), expected_seat_ids subset body Registry Seat IDs (CONTEXT_TASK_ROSTER_SEAT).','then rows in their already verified C(complete roster object) order, each row first exact complete canonical ClaimKey (CONTEXT_TASK_ROSTER_PIN), then that same row expected_seat_ids subset body Registry Seat IDs (CONTEXT_TASK_ROSTER_SEAT), before advancing to next row. No all-pin-first second pass.')
  row['rule']=row['rule'].replace('This exact source-set and context-subset policy includes sources needed by all Body fields and manifests, without adding inference.','This exact source-set policy covers every supplied Body.sources key and source validated by inherited/static checks. Deferred dynamic SourceKey targets (including Reading/RunEvidence fields) remain NOT_EVALUATED and may still fail later; no hidden all-Body dynamic closure claim.')
 if row['stage']=='CONTEXT_CLAIM_CONFLICTS':row['rule']=row['rule'].replace('every conflict_claims ClaimLabel','every conflict_claims ClaimLabel in its verified C(complete ClaimLabel) array order')
 if row['stage']=='CONTEXT_MANIFESTS':row['rule']=row['rule'].replace('Every supplied Manifest lexical','Every supplied Manifest in C(id) order')
c['success_shape']['records']+=' Index membership/type/hash is structural identity data only: noncontext Reading, RunEvidence, Provenance, Challenge, Withdrawal and History.related fields are not semantically/reference-qualified by appearing here.'
c['forbidden_substitution_controls']=[
 'Task.task_text full Pin of exact existing UpdateNotice/Provenance/Reading => CONTEXT_TASK_TEXT_TYPE; raw response Blob with fresh full pin => CONTEXT_TASK_TEXT_KIND.',
 'Manifest.prompt/settings full Pin of exact existing postassessment nonBlob record => CONTEXT_MANIFEST_PROMPT_TYPE / CONTEXT_MANIFEST_SETTINGS_TYPE, even if bytes/pin match perfectly; RAW_RESPONSE Blob with fresh pin => corresponding KIND error.',
 'Manifest.task postassessment Pin => CONTEXT_MANIFEST_TASK; ClaimKey naming absent/nonClaim id/revision => CONTEXT_MANIFEST_CLAIM; postassessment selector/dependency/rule/policy Pins => respective exact SET/POLICY error, no generic resolver salvage.',
 'Manifest added response/result/provenance/run fields or Registry digest fields => unchanged inherited closed-schema refusal; no unknown extension lane.',
 'Seat evidence complete SourceKey identifies only actual supplied original. Opaque original may contain bytes resembling or equal to a later record; typed binding can MATCH while temporal origin/independence stays UNKNOWN. No arbitrary semantic/parser/record-type inference from original contents.' ]
(p/'contract.json').write_bytes(canon(c))
a=json.loads((p/'design-addendum.json').read_bytes());a['review_clarifications']=['Roster checks run each existing C(row) in order: pin then same-row expected seats, before next row.','Claim conflict item checks preserve C(ClaimLabel) array order.','Sort may retain bounded canonical key vector<=Body64KiB; no false one-key scratch claim.','Index type/pins do not qualify deferred dynamic fields; Task exact source set does not claim all dynamic SourceKeys resolved.'];(p/'design-addendum.json').write_bytes(canon(a))
