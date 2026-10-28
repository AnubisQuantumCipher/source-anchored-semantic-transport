"""Derive held six-hop public results locally; --check compares without writing."""
import argparse
import gzip
import io
import os
from pathlib import Path
import sys
import tarfile
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import public_support as S
import package_evidence

CRITERIA_SHA='0ac9855271f2f7ca3d6fa5ef7e426723f93ba2a42c84e40c95816db934018054'
PREFIX='examples/repeated-handoff-v1/results/'


def last_cumulative(report):
    result=None
    records=report.get('metadata',[])
    S.require(type(records) is list and len(records)<=512,'metadata record bound')
    for record in records:
        fields=record.get('fields',{})
        if record.get('kind')=='OBSERVED_USAGE_RECORD' and 'total_token_usage' in fields:
            usage=fields['total_token_usage']
            S.require(type(usage) is dict and len(usage)<=16,'cumulative field bound')
            S.require(all(type(v) is int and 0<=v<=9_223_372_036_854_775_807 for v in usage.values()),'cumulative count type/bound')
            result=dict(kind=record['kind'],line=record.get('line'),offset=record.get('offset'),fields=usage)
    return dict(status='UNKNOWN_NO_OBSERVED_CUMULATIVE_SNAPSHOT' if result is None else 'LAST_OBSERVED_CUMULATIVE_SNAPSHOT',
                observation=result,aggregation='NONE; cumulative updates never summed',
                ceiling='Client metadata only; not independent billing, per-request usage, context-window peak or semantic evidence.')


def hop(outputs,provenance,records,values,case):
    role=lambda name:case+'.'+name
    report=S.object_of(values,role('capture'))
    launch=S.object_of(values,role('launch'))
    source=S.object_of(values,role('source_assessment'))
    source_receipt=S.object_of(values,role('source_receipt'))
    protocol=S.object_of(values,role('protocol'))
    candidate,final=values[role('candidate')],values[role('final')]
    for name,data in (('candidate.json',candidate),('final.json',final)):
        S.require(not S.PRIVATE.search(data.decode('utf-8')),'private path in exact candidate/final')
        outputs['hops/'+case+'/'+name]=data
    S.require(source['candidate']==S.public_pin(records[role('candidate')]),'source candidate pin')
    S.require(source['final']==S.public_pin(records[role('final')]),'source final pin')
    S.require(source['capture_report']==S.public_pin(records[role('capture')]),'source capture pin')
    S.require(source['case']==case and source_receipt['case']==case,'source case identity')
    S.require(source_receipt['assessment_sha256']==records[role('source_assessment')]['sha256'],'source receipt basis')
    closure_lines=values[role('source_closure')].decode().splitlines()
    bound=[line.split('  ',1)[0] for line in closure_lines if line.endswith('  assessment.json')]
    S.require(bound==[records[role('source_assessment')]['sha256']],'source checksum closure basis')
    S.require(S.canonical(S.parse(candidate,S.CAP))==S.canonical(S.parse(final,S.CAP)),'candidate/final equality')
    S.require(source['criteria_unchanged'] is True,'source criteria changed')
    S.require(len(report['events'])<=512,'tool event count bound')
    allowed={'custom_tool_call','custom_tool_call_output','function_call','function_call_output'}
    S.require(all(e['kind'] in allowed for e in report['events']),'non-tool event forbidden')
    call_data=dict(capture=S.public_pin(records[role('capture')]),events=report['events'],
                   projection='Only captured tool calls and responses; no reasoning/raw turn context.',
                   completeness='See independently pinned protocol review; selected records alone do not prove hidden-access absence.')
    metadata=dict(requested={k:launch[k] for k in ('model','reasoning_effort','fork_turns')},
                  observed_model_settings=[r for r in report.get('metadata',[]) if r.get('kind')=='TURN_MODEL_METADATA'],
                  final_cumulative_usage=last_cumulative(report),predecessor=launch['predecessor'],
                  recorded_tool_call_events=len([e for e in report['events'] if e['kind'] in ('custom_tool_call','function_call')]),
                  timing='Only explicitly named scalar timings in tool responses/held evidence are observed; no timestamp subtraction, inferred units or campaign sums.',
                  backend_attestation='UNKNOWN',hidden_access='UNKNOWN',native_compaction='NOT_TESTED')
    evidence=dict(calls=call_data,metadata=metadata,prompt=launch['message'],
                  original_prompt_utf8=dict(bytes=len(launch['message'].encode()),sha256=S.sha(launch['message'].encode())),
                  source_assessment=source,source_receipt=source_receipt,protocol=protocol,
                  protocol_full_review=S.object_of(values,role('protocol_full')),
                  inputs={kind:S.public_pin(records[role(kind)]) for kind in S.PER_CASE})
    S.json_output(outputs,provenance,'hops/'+case+'/evidence.json',evidence)
    return dict(case=case,frozen_witness=source['frozen_witness'],exact_differences=source['exact_differences'],
                source_semantic_fidelity=source['source_semantic_fidelity'],contract_findings='Full wording retained in hops/'+case+'/evidence.json',
                candidate=S.public_pin(records[role('candidate')]),final=S.public_pin(records[role('final')]),
                raw_final_vs_candidate_equal=candidate==final,strict_json_objects_equal=True,
                raw_budget=source['raw_budget'],predecessor=source.get('predecessor_binding',launch['predecessor']),
                source_report_protocol_status_at_assessment=source['protocol_validity'],
                later_protocol=protocol,usage=metadata['final_cumulative_usage'],observed_model_settings=metadata['observed_model_settings'],
                observed_tool_calls=metadata['recorded_tool_call_events'])


def shared(outputs,provenance,records,values):
    for source in S.SOURCE_IDS:
        outputs['fixture/source/'+source.lower()+'.txt']=values['source_'+source.lower()]
    files={'criteria_freeze':'criteria-freeze.json','campaign_freeze':'campaign-freeze.json','task':'task.txt',
           'rubric':'rubric.md','expected':'expected.json','output_shape':'output-shape.json','source_index':'source-index.json'}
    for role,name in files.items():
        data=values[role]
        if name.endswith('.json'):
            S.json_output(outputs,provenance,'fixture/'+name,S.parse(data,S.CAP),S.public_pin(records[role]))
        else:
            changes=[]
            outputs['fixture/'+name]=S.redact_text(data.decode(),'',changes).encode()
            provenance['fixture/'+name]=dict(source=S.public_pin(records[role]),host_path_substitutions=changes)
    reviews={role:S.object_of(values,role) for role in ('source_obligations','source_preflight','source_preflight_receipt','protocol_full_review','protocol_receipt')}
    reviews['source_procedure']=values['source_procedure'].decode()
    S.json_output(outputs,provenance,'reviews.json',reviews)
    retained={role:dict(source=S.public_pin(records[role]),record=S.parse(values[role],S.CAP))
              for role in sorted(records) if role.startswith('failure_') or role.startswith('evidence.')}
    S.json_output(outputs,provenance,'retained.json',retained)


def derive(manifest,values):
    records=manifest['inputs']
    S.require(records['criteria_freeze']['sha256']==CRITERIA_SHA,'frozen source criteria identity')
    outputs,provenance={},{}
    package=package_evidence.inspect(values,records)
    package_evidence.add(outputs,values)
    shared(outputs,provenance,records,values)
    hops=[hop(outputs,provenance,records,values,case) for case in S.CASES]
    status='FROZEN_WITNESS_FAILURES_RETAINED_NO_ADVANTAGE_CLAIM' if any(h['frozen_witness']=='FAIL' for h in hops) else 'BOUNDED_FROZEN_WITNESS_RESULTS_NOT_FULL_ACCEPTANCE'
    receipt=dict(schema='repeated-public-results/1',status=status,
                 caveat='The null report shape/generic vocabulary and undisclosed field/category mappings leave output-contract underspecification. Frozen witness failures remain; a four-versus-five count is not improvement or consequential semantic error evidence.',
                 interpretation='Preserve source-meaning judgments and their limitations verbatim in per-hop assessments. Do not turn witness counts into a comparative score.',
                 hops=hops,dispatch_order=list(S.CASES),evidence={role:S.public_pin(record) for role,record in records.items()},
                 local_held_manifest_sha256=manifest['held_manifest_sha256'],
                 transported_package=package,
                 source_criteria='Frozen before first receiving outcome; exact private input pins and public transformed artifacts are distinct.',
                 protocol_scope='Full independently held review is separate from earlier source assessments whose pending-protocol fields are retained unchanged.',
                 token_limits='One last cumulative client observation per hop, no summing cumulative updates. No billing, per-request/window peak, monetary, energy, campaign-total or ratio claim.',
                 timing_limits='No timestamp arithmetic or undeclared-unit inference. Tool timing scalars remain observations, not causal performance proof.',
                 retention_limits='Source refresh was available and used; this does not isolate source-free retention or native compaction.',
                 unproved=['source truth/authentication','semantic completeness','whole-system semantics','hidden-access exclusion','OS isolation','backend attestation','causal superiority','population rates'],
                 raw_logs='Reasoning, raw turn context and complete raw client logs are not public; hashes do not make unavailable evidence inspectable.',
                 reproduction='Public closure and witness checks are self-contained. Regenerating privacy derivatives from original private provenance bytes additionally requires the externally held local inputs; original host paths are not recoverable from substitution digests.')
    S.json_output(outputs,provenance,'receipt.json',receipt)
    reproduction(outputs,provenance)
    outputs['privacy.json']=S.canonical(dict(schema='privacy-only-public-derivation/1',artifacts=provenance,
        policy='Metadata host-path substrings/keys replaced with SHA-256 tokens. Exact source/candidate/final/package bytes unchanged. The standard runtime library path in the exact ZIP and inspection code is public dependency data. All source judgments/statuses retained.'))+b'\n'
    closure={name:dict(bytes=len(data),sha256=S.sha(data)) for name,data in sorted(outputs.items())}
    outputs['public-source-closure.json']=S.canonical(dict(schema='repeated-public-closure/1',files=closure,
        identity='Caller must hold this closure digest externally; coherent replacement is not authentication.'))+b'\n'
    rollup=S.parse(outputs['receipt.json'],S.CAP)
    rollup['public_dataset']=dict(path=PREFIX,closure_sha256=S.sha(outputs['public-source-closure.json']))
    result={PREFIX+name:data for name,data in outputs.items()}
    result['receipts/repeated-handoff-1.json']=S.canonical(rollup)+b'\n'
    return result


def deliver(outputs,root,check):
    S.require(len(outputs)<=48,'output cardinality')
    for name,data in outputs.items():
        S.require(not Path(name).is_absolute() and '..' not in Path(name).parts,'output confinement')
        S.require(len(data)<=S.PUBLIC_CAP,'output byte bound')
        if not name.endswith('/meaning.zip'):
            matches=[m.group() for m in S.PRIVATE.finditer(data.decode('utf-8'))]
            S.require(all(path==os.path.join(os.sep,'usr','lib','libc.so.6') for path in matches),'output privacy bound')
        path=root/name
        S.require(not path.is_symlink(),'output symlink')
        if check or path.exists():
            S.require(S.read(path,S.CAP)==data,'derivative differs: '+name)
    dataset=root/PREFIX
    if dataset.exists():
        existing={PREFIX+name for name in S.inventory(dataset)}
        S.require(existing<=set(outputs),'unexpected files in dataset closure')
    if not check:
        for name,data in outputs.items():
            path=root/name
            path.parent.mkdir(parents=True,exist_ok=True)
            S.require(path.parent.resolve().is_relative_to(root.resolve()),'output parent escape')
            if not path.exists():
                S.write(path,data)


def reproduction(outputs,provenance):
    original=S.read(S.HERE/'trace_support.py',S.CAP)
    changes=[]
    public=S.redact_text(original.decode(),'',changes).encode()
    digest=S.sha(public)
    outputs['reproduce/trace_support.py']=public
    provenance['reproduce/trace_support.py']=dict(original_sha256=S.sha(original),host_path_substitutions=changes,
        limitation='Unused private session-root literal is redacted; all helper function definitions remain byte-identical. Public bootstrap guards are pinned to this derived helper, not falsely labelled original bytes.')
    for name in ('check_public.py','check_witness.py','public_support.py'):
        data=S.read(S.HERE/name,S.CAP)
        outputs['reproduce/'+name]=data.replace(S.SUPPORT_SHA.encode(),digest.encode())
    for name in ('prepare_public.py','seal_inputs.py','package_evidence.py'):
        outputs['reproduce/'+name]=S.read(S.HERE/name,S.CAP)


def size_observation(outputs):
    buffer=io.BytesIO()
    with tarfile.open(fileobj=buffer,mode='w',format=tarfile.GNU_FORMAT) as archive:
        for name,data in sorted(outputs.items()):
            entry=tarfile.TarInfo(name)
            entry.size=len(data)
            entry.mode=0o644
            entry.mtime=0
            archive.addfile(entry,io.BytesIO(data))
    compressed=gzip.compress(buffer.getvalue(),mtime=0)
    return dict(public_file_count=len(outputs),largest_public_file_bytes=max(len(v) for v in outputs.values()),
                public_only_gnu_tar_gzip_bytes=len(compressed),public_only_gnu_tar_gzip_sha256=S.sha(compressed),
                scope='Actual public-only deterministic GNU tar+gzip observation; NOT the final Git release archive. Existing release helper cap remains mandatory.')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expect-input-sha256',required=True)
    parser.add_argument('--output-root',type=Path,default=S.HERE/'staged')
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--dry-run',action='store_true')
    args=parser.parse_args()
    S.require(not(args.check and args.dry_run),'choose dry-run or check')
    S.limits()
    raw=S.read(S.HERE/'inputs.json',S.CAP)
    S.require(S.sha(raw)==args.expect_input_sha256,'held sealed input manifest differs')
    manifest=S.parse(raw,S.CAP)
    S.require(manifest['schema']=='repeated-public-sealed-inputs/1','sealed manifest schema')
    for name,digest in manifest['code'].items():
        S.require(S.sha(S.read(S.HERE/name,S.CAP))==digest,'derivation code changed after sealing')
    values=S.pinned(manifest['inputs'])
    outputs=derive(manifest,values)
    S.require(S.pinned(manifest['inputs'])==values,'inputs before/after mismatch')
    if not args.dry_run:
        deliver(outputs,args.output_root,args.check)
    else:
        S.require(len(outputs)<=48 and all(len(v)<=S.PUBLIC_CAP for v in outputs.values()),'dry-run output budget')
    S.require(S.pinned(manifest['inputs'])==values and S.read(S.HERE/'inputs.json',S.CAP)==raw,'inputs after output mismatch')
    print(S.canonical(dict(status='CHECKED_BYTE_IDENTICAL' if args.check else 'DRY_RUN_NO_OUTPUT_WRITES' if args.dry_run else 'PREPARED_NOT_PUBLISHED',
        closure_sha256=S.sha(outputs[PREFIX+'public-source-closure.json']),size_observation=size_observation(outputs),
        files={name:dict(bytes=len(data),sha256=S.sha(data)) for name,data in sorted(outputs.items())})).decode())


if __name__=='__main__':
    main()
