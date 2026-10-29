import hashlib,json,shutil
from pathlib import Path
p=Path('/dev/shm/semantic-transport-impact-20261029')
def raw(v):return json.dumps(v,ensure_ascii=False,sort_keys=True,separators=(',',':')).encode()
shutil.copyfile(p/'contract.json',p/'contract-draft03.json')
c=json.loads((p/'contract.json').read_bytes());del c['success_shape']['task_selected_source_closure'];(p/'contract.json').write_bytes(raw(c))
shutil.copyfile(p/'base-preview.json',p/'base-preview-first.json')
f=json.loads((p/'base-preview.json').read_bytes())
for row in f['cases']:
 d=p/row['id'];shutil.copyfile(d/'expected.json',d/'expected-first.json')
 e=json.loads((d/'expected.json').read_bytes());del e['task_selected_source_closure'];(d/'expected.json').write_bytes(raw(e))
 x=(d/'expected.json').read_bytes();row['files']['expected.json']={'bytes':len(x),'sha256':hashlib.sha256(x).hexdigest()}
(p/'base-preview.json').write_bytes(raw(f))
s=(p/'prepare_oracle.py').read_text();s=s.replace(",task_selected_source_closure='NOT_EVALUATED'",'');(p/'prepare_oracle.py').write_text(s)
(p/'pre-freeze-correction.json').write_bytes(raw({'schema':'quorum/impact-pre-freeze-correction/1','finding':'I02 preview success envelope included redundant task_selected_source_closure absent from separately frozen independent32 controls.','resolution':'Remove redundant field from success_shape and literal success outputs. Keep full_reference_closure NOT_EVALUATED; full Task/Manifest/Reading/external replay gates remain required.','retained':['contract-draft03.json','base-preview-first.json','I01_NO_UPDATES/expected-first.json','I02_REPLACEMENT/expected-first.json'],'status':'PREPARATION_CORRECTION_NOT_RUNTIME_TEST'}))
