"""Reproduce frozen independent accounting controls from verified portable data."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import zipfile

HERE=Path(__file__).resolve().parent
TESTS=HERE/'tests'
PINS={'fixtures-v4.zip':'42064259d509cc1fc1a19d566ed958bffba6a584d04628e3c62079859b9cbf6e',
      'fixtures-index.json':'ae4c771dc7686b86d69bc8dfcc5d282cbd8a933249da4a09bdfa90ee2f27806d',
      'run_independent_v5.py':'c3fdd2cac9cd76a4de9abd157f88643c91922b02dded8b4ad86d04fa1481c2af'}
CAP=4*1024*1024
TASK_CAP=8*1024*1024
NAME=re.compile(r'[A-Za-z0-9_.-]+\Z')
BOOTSTRAP="import hashlib,sys; p=sys.argv[1]; f=open(p,'rb'); b=f.read(131073); f.close(); h=sys.argv.pop(2); sys.argv.pop(1); sys.argv[0]=p; (len(b)<=131072 and hashlib.sha256(b).hexdigest()==h) or sys.exit('runner pin'); exec(compile(b,p,'exec'),{'__name__':'__main__','__file__':p})"


def need(condition,reason):
    if not condition:
        raise ValueError(reason)


def read(path,cap=CAP):
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as stream:
        before=os.fstat(stream.fileno())
        need(stat.S_ISREG(before.st_mode) and before.st_size<=cap,'unsafe or oversized source')
        raw=stream.read(cap+1)
        after=os.fstat(stream.fileno())
    identity=lambda info:(info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)
    need(len(raw)==before.st_size and len(raw)<=cap and identity(before)==identity(after),
         'source changed or exceeded cap while reading')
    return raw


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def verified_sources():
    sources={}
    for name,pin in PINS.items():
        raw=read(TESTS/name)
        need(digest(raw)==pin,'portable source pin: '+name)
        sources[name]=raw
    return sources,json.loads(sources['fixtures-index.json'])


def footprint(root):
    stack=[root];total=0;entries=0
    while stack:
        need(len(stack)<=2048,'capacity directory bound')
        current=stack.pop()
        with os.scandir(current) as entries_iterator:
            for entry in entries_iterator:
                entries+=1
                need(entries<=8192,'capacity entry bound')
                info=entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    stack.append(Path(entry.path))
                else:
                    total+=max(info.st_size,info.st_blocks*512)
    return total


def admit(parent,capacity,index,sources):
    parent=parent.resolve(strict=True);capacity=capacity.resolve(strict=True)
    need(parent.is_relative_to(capacity),'scratch parent outside capacity root')
    info=parent.stat()
    need(info.st_uid==os.geteuid() and stat.S_IMODE(info.st_mode)==0o700,'private scratch parent required')
    files=index['files']
    need(len(files)<=512,'portable member count')
    raw=sum(pin['bytes'] for pin in files.values())
    allocated=sum(((pin['bytes']+4095)//4096)*4096 for pin in files.values())
    reserve=allocated+524288
    need(raw<=CAP and reserve<=CAP,'portable staging exceeds4MiB')
    current=footprint(capacity)
    need(current+reserve+sum(map(len,sources.values()))<=TASK_CAP,
         'aggregate8MiB capacity: current='+str(current)+' reserve='+str(reserve))
    return parent,{'current_allocated_bytes':current,'stage_reserved_bytes':reserve,'stage_raw_bytes':raw}


def safe_name(name):
    parts=name.split('/')
    need(len(parts)<=4 and all(part not in ('','.','..') and NAME.fullmatch(part) for part in parts),'unsafe ZIP member')
    return parts


def extract_checked(stage,index,zip_bytes):
    files=index['files']
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        members=archive.infolist()
        need(len(members)==len(files) and len({v.filename for v in members})==len(members),'ZIP duplicate/count')
        need({v.filename for v in members}==set(files),'ZIP extra or missing member')
        for info in members:
            parts=safe_name(info.filename);pin=files[info.filename]
            mode=info.external_attr>>16
            need(stat.S_ISREG(mode) and not info.flag_bits&1,'ZIP special/encrypted member')
            need(info.compress_type in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED),'ZIP compression')
            need(info.file_size==pin['bytes'] and 0<info.file_size<=131072,'ZIP member size')
            with archive.open(info) as stream:
                raw=stream.read(pin['bytes']+1)
            need(len(raw)==pin['bytes'] and digest(raw)==pin['sha256'],'ZIP member identity')
            path=stage.joinpath(*parts);path.parent.mkdir(parents=True,exist_ok=True)
            with path.open('xb') as stream:
                need(stream.write(raw)==len(raw),'stage short write')
            need(read(path)==raw,'stage readback')
    need(footprint(stage)<=CAP,'stage footprint bound')


def run_mode(stage,index,optimized):
    module,cli=HERE/'accounting.py',HERE/'check.py'
    module_pin,cli_pin=digest(read(module)),digest(read(cli))
    command=[sys.executable,'-I','-S','-B']+(['-O'] if optimized else [])
    command+=['-Werror','-c',BOOTSTRAP,str(TESTS/'run_independent_v5.py'),PINS['run_independent_v5.py'],
        '--data-root',str(stage),'--expect-fixtures-sha256',index['fixture_manifest_sha256'],
        '--module',str(module),'--expect-module-sha256',module_pin,
        '--cli',str(cli),'--expect-cli-sha256',cli_pin,
        '--cli-stage',str(stage/('cli-optimized' if optimized else 'cli-normal'))]
    result=subprocess.run(command,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=30,check=False)
    need(len(result.stdout)<=131072 and len(result.stderr)<=131072,'test output cap')
    report=json.loads(result.stdout)
    destination=stage/('optimized.json' if optimized else 'normal.json')
    with destination.open('xb') as stream:
        need(stream.write(result.stdout)==len(result.stdout),'result short write')
    need(result.returncode==0 and not result.stderr,'independent controls failed: '+str(destination))
    need(report['status']=='TESTED','independent product status')
    need(footprint(stage)<=CAP,'stage footprint bound after tests')
    return {'mode':'optimized' if optimized else 'normal','report':str(destination),
            'report_sha256':digest(result.stdout),'core_pass':sum(v['status']=='PASS' for v in report['results']),
            'cli_pass':sum(v.get('cli',{}).get('status')=='PASS' for v in report['results']),
            'module_sha256':module_pin,'cli_sha256':cli_pin}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--scratch-parent',required=True,type=Path)
    parser.add_argument('--capacity-root',required=True,type=Path)
    args=parser.parse_args()
    sources,index=verified_sources()
    parent,allocation=admit(args.scratch_parent,args.capacity_root,index,sources)
    stage=Path(tempfile.mkdtemp(prefix='accounting-portable-',dir=parent))
    extract_checked(stage,index,sources['fixtures-v4.zip'])
    results=[run_mode(stage,index,False),run_mode(stage,index,True)]
    verified_sources()
    print(json.dumps({'status':'TESTED_PORTABLE_ACCOUNTING_CONTROLS','stage':str(stage),
                      'allocation':allocation,'results':results},sort_keys=True))


if __name__=='__main__':
    main()
