"""Aggregate retained independent observations, preserving every scope boundary."""
import copy
import hashlib
import json
from pathlib import Path

C=Path(__file__).parent
W=Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')


def pin(p):
    raw=p.read_bytes()
    return dict(path=str(p),bytes=len(raw),sha256=hashlib.sha256(raw).hexdigest())


def load(p):
    return json.loads(p.read_bytes())


def full_report(group,lane):
    path=C/f'final-{group}-{lane}-observations/first-run.json'
    report=load(path)
    if report['failures'] or report['unrun']:
        raise ValueError('Retained nonpass: '+str(path))
    for row in report['cases']:
        if not row['inputs_unchanged'] or not row['matches_frozen_both_streams_and_exit']:
            raise ValueError('Changed/mismatched observation')
    return report


runs=[]
for group in ('original-semantic14','transport14','host-cache15','review8','private-origin'):
    for lane in ('normal','opt1'):
        report=full_report(group,lane)
        runs.append(dict(group=group,lane=lane,cases=len(report['cases']),report=pin(C/f'final-{group}-{lane}-observations/first-run.json')))
parity=[]
for lane in ('normal','opt1'):
    first=full_report('original-semantic14',lane)['cases']
    second=full_report('transport14',lane)['cases']
    for a,b in zip(first,second,strict=True):
        x=load(Path(a['first_stdout']['path']));y=load(Path(b['first_stdout']['path']))
        for value in (x,y):
            value.pop('request',None);value.pop('input_request',None)
        if x!=y:
            raise ValueError('Cross-arm normalized mismatch '+a['id'])
        parity.append(dict(case=a['id'].split('__')[0],lane=lane,normalization='Only top request/input_request removed',equal=True))
for lane in ('normal','opt1'):
    evidence=load(C/f'final-core-{lane}-results.json')
    runner=load(C/f'final-core-{lane}-runner.json')
    if not evidence['passed'] or runner['exit_code'] or not runner['fresh_cache_empty']:
        raise ValueError('Pure core nonpass/cache drift')
    runs.append(dict(group='pure_core_synthetic_host',lane=lane,outputs=len(evidence['outputs']),report=pin(C/f'final-core-{lane}-results.json')))
    count=load(C/f'final-host-cache15-{lane}-H03_MODULE_COUNT.preentry.json')
    preload=load(C/f'final-host-cache15-{lane}-H02_PRELOADED_TRANSPORT.preentry.json')
    if count['module_count']!=513 or 'transport_untrusted_preload' not in preload['module_names']:
        raise ValueError('Instrumented exact state differs')
source_manifest=load(C/'final-original-semantic14-normal-manifest.json')
for row in source_manifest['source_pins']:
    if pin(Path(row['path']))!=row:
        raise ValueError('Source drift after all runs '+row['path'])
product=[pin(W/p) for p in ('tools/transport_quorum_replay.py','install/transport_quorum_bootstrap.py','install/test_quorum_replay.py')]
report=dict(schema='quorum/independent-full-replay-qualification/1',
 status='TESTED_SOURCE_BOUND_FINITE_PROFILE',product_pins=product,runs=runs,
 normalized_cross_arm_complete_results=parity,
 preentry_scope='H02/H03 instrumented pre-entry states only; exact specified key and total513 checked. H14 private _audit projection only; no public-host reachability claimed.',
 cache_scope='Ordinary copied helper source preserved with valid-timestamp normal/opt1 forged pycs. Exact F01 complete result succeeded; harmless forged exception not executed. No original cache removed.',
 retention=['Original P02 incorrect manual label6b08, first pure CI failures and approved one-field revision09a3 retained.','Initial shared-runtime-key alias contamination in fixture constructor, ten actual transport host refusals normal/optimized, incomplete concrete reviewer claim and independent reviewer-tool alias false flag all retained with diagnosis4508 and explicit corrected reviewf9eb.','Original host setup deviations and pending manifests retained; corrected exact FF bodies/descriptors, pre-entry state, copied missing/tampered member inventories separately frozen before execution.','Predecessor SourceFileLoader/pyc weakness source-only finding and ineligible old freeze preserved. Prior recipient-sidecar dependency and old pair observations preserved; source03 absence runs separately recorded.'],
 earlier_priority_receipt=pin(C/'source03-priority-and-core-independent-receipt.json'),
 code_resource_review=pin(C/'core-final-source-review.json'),
 public_preparation_review=pin(C/'public-U01-concrete-review.json'),
 assurance_limits=['Deterministic manual fixtures and bounded source/AST/resource review are TESTED/REVIEWED, not a whole-Python allocation theorem or formal proof.','Actual legacy reconstruction qualification is source/runtime identity evidence, not a new native build or whole-runtime proof.','Pure portable CI uses synthetic private host observations; host/ZIP observations above are separately executed CLI evidence.','No source authenticity, external model run independence, semantic completeness, claim truth, freshness, current authority, comparative economic benefit or whole-project acceptance established. All inherited gates remain.'],
 all_manifest_source_pins_verified_after_runs=True,
 remaining='Owner review/release and separately authorized actual U01 normal/optimized public bootstrap full-stream observations. No product edits performed by this reviewer.')
path=C/'final-independent-full-replay-review.json'
with path.open('xb') as stream:
    stream.write(json.dumps(report,sort_keys=True,separators=(',',':')).encode())
print(json.dumps(pin(path)))
