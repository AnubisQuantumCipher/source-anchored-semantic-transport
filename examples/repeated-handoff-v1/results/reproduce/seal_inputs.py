"""Snapshot complete input bytes only against an externally held manifest digest."""
import argparse
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import public_support as S


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--held',type=Path,required=True)
    parser.add_argument('--expect-held-sha256',required=True)
    args=parser.parse_args()
    S.limits()
    held=S.read(args.held,S.CAP)
    S.require(S.sha(held)==args.expect_held_sha256,'held final receipt manifest pin differs')
    declared=S.parse(held,S.CAP)
    S.require(declared['schema']=='repeated-public-held-inputs/1','held manifest schema')
    records=declared['inputs']
    values=S.pinned(records)
    snapshots={}
    for role,data in values.items():
        path=S.HERE/'snapshots'/role
        S.require(not path.exists(),'snapshot must be create-only')
        snapshots[role]=dict(path=str(path),bytes=len(data),sha256=S.sha(data))
    S.require(S.pinned(records)==values,'held source before/after differs')
    for role,data in values.items():
        path=Path(snapshots[role]['path'])
        path.parent.mkdir(parents=True,exist_ok=True)
        S.write(path,data)
    result=dict(schema='repeated-public-sealed-inputs/1',held_manifest_sha256=S.sha(held),
                inputs=snapshots,original_input_pins=records,source_before_after='MATCH',
                root_final_receipt_basis=declared.get('receipt_basis','UNSPECIFIED'),
                code={name:S.sha(S.read(S.HERE/name,S.CAP)) for name in ('seal_inputs.py','public_support.py','trace_support.py','prepare_public.py','check_public.py','check_witness.py','package_evidence.py')})
    S.require(S.pinned(records)==values,'source after snapshots differs')
    S.require(S.read(args.held,S.CAP)==held,'held manifest changed')
    S.write(S.HERE/'inputs.json',S.canonical(result)+b'\n')
    print(S.canonical(dict(status='SEALED_COMPLETE_INPUTS_ONLY',inputs_sha256=S.sha(S.read(S.HERE/'inputs.json',S.CAP)))).decode())


if __name__=='__main__':
    main()
