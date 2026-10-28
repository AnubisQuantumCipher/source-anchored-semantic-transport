"""Check a public artifact closure against its externally held SHA-256 digest."""
import argparse
import hashlib
import os
from pathlib import Path
import sys

HERE=Path(__file__).resolve().parent
CAP=4_194_304
SUPPORT_SHA='757d5d475bd31ac3a23bfc588253a0b8a3fac35ce0862a0cff6d6e6d299489f8'
with (HERE/'trace_support.py').open('rb') as stream:
    SUPPORT=stream.read(CAP+1)
if len(SUPPORT)>CAP or hashlib.sha256(SUPPORT).hexdigest()!=SUPPORT_SHA:
    raise ValueError('checked trace support differs')
sys.dont_write_bytecode=True
sys.path.insert(0,str(HERE))
from trace_support import read,parse,require,sha,canonical


def inventory(root):
    pending,files,visited=[root],set(),0
    while pending:
        directory=pending.pop()
        visited+=1
        require(visited<=64 and not directory.is_symlink(),'directory bound/symlink')
        with os.scandir(directory) as entries:
            for count,entry in enumerate(entries,1):
                require(count<=256 and not entry.is_symlink(),'directory entry bound/symlink')
                path=Path(entry.path)
                if entry.is_dir(follow_symlinks=False):
                    pending.append(path)
                else:
                    require(entry.is_file(follow_symlinks=False),'non-regular artifact')
                    files.add(str(path.relative_to(root)))
                require(len(pending)<=64 and len(files)<=48,'closure inventory bound')
    return files


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,default=HERE.parent)
    parser.add_argument('--expect-closure-sha256',required=True)
    args=parser.parse_args()
    data=read(args.root/'public-source-closure.json',CAP)
    require(sha(data)==args.expect_closure_sha256,'held public closure differs')
    closure=parse(data,CAP)
    require(closure['schema']=='repeated-public-closure/1','closure schema')
    files=closure['files']
    require(type(files) is dict and len(files)<=47,'file cardinality')
    require(inventory(args.root)==set(files)|{'public-source-closure.json'},'exact closure cardinality')
    total=0
    for name,pin in files.items():
        require(not Path(name).is_absolute() and '..' not in Path(name).parts,'path confinement')
        raw=read(args.root/name,CAP)
        require(len(raw)<1_048_576,'public per-file byte cap')
        total+=len(raw)
        require(total<=67_108_864,'public aggregate byte bound')
        require(len(raw)==pin['bytes'] and sha(raw)==pin['sha256'],'public file pin mismatch')
    print(canonical(dict(status='CHECKED_PUBLIC_BYTE_CLOSURE',closure_sha256=sha(data),
        scope='Exact published bytes only; not source truth, semantic completeness, whole-system acceptance or author authentication.')).decode())


if __name__=='__main__':
    main()
