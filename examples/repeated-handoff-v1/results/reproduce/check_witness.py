"""Reproduce frozen witness differences and exact raw budgets; not source/protocol acceptance."""
import argparse
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,str(Path(__file__).resolve().parent))
import public_support as S


def differences(expected,actual):
    pending,found,visited=[('',expected,actual)],[],0
    while pending:
        path,wanted,got=pending.pop()
        visited+=1
        S.require(visited<=10_000,'comparison bound')
        if type(wanted) is dict and type(got) is dict:
            if set(wanted)!=set(got):
                found.append(dict(path=path,reason='OBJECT_KEYS',expected=list(wanted),actual=list(got)))
            pending.extend((path+'/'+key,wanted[key],got[key]) for key in wanted.keys()&got.keys())
        elif type(wanted) is list and type(got) is list:
            if path.startswith('/evidence/'):
                ok=all(type(x) is str for x in got) and set(wanted)<=set(got)
            elif path in ('/documentary_conditions','/pending_after_response'):
                ok=all(type(x) is str for x in got) and len(got)==len(set(got)) and set(wanted)==set(got)
            else:
                ok=S.canonical(wanted)==S.canonical(got)
            if not ok:
                found.append(dict(path=path,reason='REQUIRED_ARRAY_VALUES_OR_TYPES',expected=wanted,actual=got))
        elif type(wanted) is not type(got) or wanted!=got:
            found.append(dict(path=path,reason='FIXED_VALUE_OR_TYPE',expected=wanted,actual=got))
    return sorted(found,key=lambda entry:entry['path'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=Path(__file__).resolve().parent.parent)
    args=parser.parse_args()
    S.limits()
    expected=S.parse(S.read(args.root/'fixture/expected.json',S.CAP),S.CAP)
    reports=[]
    for case in S.CASES:
        root=args.root/'hops'/case
        candidate,final=(S.read(root/name,S.CAP) for name in ('candidate.json','final.json'))
        actual=S.parse(final,S.CAP)
        S.require(type(actual) is dict and type(S.parse(candidate,S.CAP)) is dict,'first JSON object')
        changes=differences(expected,actual)
        assessment=S.parse(S.read(root/'evidence.json',S.CAP),S.CAP)['source_assessment']
        S.require(changes==assessment['exact_differences'],'witness differences differ from frozen assessment')
        reports.append(dict(case=case,witness='FAIL' if changes else 'MATCH',differences=changes,
            candidate=dict(bytes=len(candidate),codepoints=len(candidate.decode()),sha256=S.sha(candidate)),
            final=dict(bytes=len(final),codepoints=len(final.decode()),sha256=S.sha(final)),
            raw_bytes_equal=candidate==final,strict_json_objects_equal=S.canonical(S.parse(candidate,S.CAP))==S.canonical(actual)))
    print(S.canonical(dict(status='CHECKED_FROZEN_WITNESS_REPRODUCTION',hops=reports,
        scope='Frozen exact witness only. Contract underspecification, complete source meaning and protocol conclusions remain the separately published judgments. No superiority follows.')).decode())


if __name__=='__main__':
    main()
