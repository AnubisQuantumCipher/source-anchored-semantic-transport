"""Bounded private-input pinning and privacy-only public transformations."""
import hashlib
import os
from pathlib import Path
import re
import resource
import sys

HERE=Path(__file__).resolve().parent
CAP=4_194_304
PUBLIC_CAP=1_048_575
TOTAL=67_108_864
SUPPORT_SHA='757d5d475bd31ac3a23bfc588253a0b8a3fac35ce0862a0cff6d6e6d299489f8'
CASES=('original-h1','transport-h1','transport-h2','original-h2','original-h3','transport-h3')
PRIVATE=re.compile(r'/(?:home|usr|srv|tmp|opt|etc|var|run)/(?:[^\s\"\'<>`;,\)\]\}])+')
SOURCE_IDS=('APPROVAL','CORRECTION','REVOCATION','WORK','UNRELATED','METRICS')
GLOBAL=('criteria_freeze','campaign_freeze','task','rubric','expected','output_shape','source_index',
        'source_obligations','source_procedure','source_preflight','source_preflight_receipt','source_preflight_closure',
        'protocol_full_review','protocol_receipt','failure_criteria_v1','failure_freeze0',
        'package_archive','package_share','package_lexicon','package_authoring')
PER_CASE=('capture','candidate','final','launch','source_assessment','source_receipt','source_closure','protocol','protocol_full')


def bootstrap():
    with (HERE/'trace_support.py').open('rb') as stream:
        raw=stream.read(CAP+1)
    if len(raw)>CAP or hashlib.sha256(raw).hexdigest()!=SUPPORT_SHA:
        raise ValueError('reviewed trace support pin differs')
    sys.dont_write_bytecode=True
    sys.path.insert(0,str(HERE))


bootstrap()
from trace_support import canonical,parse,read,require,sha,write


def limits():
    for kind,bound in ((resource.RLIMIT_AS,536_870_912),(resource.RLIMIT_CPU,30),
                       (resource.RLIMIT_FSIZE,CAP),(resource.RLIMIT_NOFILE,64)):
        _,hard=resource.getrlimit(kind)
        require(hard==resource.RLIM_INFINITY or hard>=bound,'host limit too narrow')
        resource.setrlimit(kind,(bound,bound))


def required_roles():
    roles=set(GLOBAL)
    roles.update('source_'+name.lower() for name in SOURCE_IDS)
    roles.update(case+'.'+kind for case in CASES for kind in PER_CASE)
    return roles


def validate_roles(records):
    require(type(records) is dict and len(records)<=128,'role cardinality')
    missing=required_roles()-set(records)
    require(not missing,'complete six-hop inputs missing: '+','.join(sorted(missing)))
    for role,record in records.items():
        require(re.fullmatch(r'[a-z0-9_.-]{1,100}',role) is not None,'role shape')
        require(role in required_roles() or role.startswith('evidence.'),'undeclared extra role')
        require(set(record)=={'path','bytes','sha256'},'input pin fields')
        require(type(record['bytes']) is int and 0<=record['bytes']<=CAP,'input byte bound')
        require(re.fullmatch(r'[0-9a-f]{64}',record['sha256']) is not None,'digest format')
        require(not record['path'].endswith('.jsonl'),'raw session logs forbidden')


def pinned(records):
    validate_roles(records)
    values,total={},0
    for role,record in records.items():
        data=read(Path(record['path']),CAP)
        total+=len(data)
        require(total<=TOTAL,'aggregate input byte budget')
        require(len(data)==record['bytes'] and sha(data)==record['sha256'],'input pin differs: '+role)
        values[role]=data
    return values


def public_pin(record):
    return {key:record[key] for key in ('bytes','sha256')}


def redact_text(value,route,changes):
    pieces,start,count=[],0,0
    for match in PRIVATE.finditer(value):
        count+=1
        require(count<=256,'path substitutions per string bound')
        digest=sha(match.group().encode('utf-8'))
        token='[HOST_PATH_SHA256:'+digest+']'
        pieces.extend((value[start:match.start()],token))
        changes.append(dict(location=route,original_string_sha256=digest,replacement=token))
        start=match.end()
    pieces.append(value[start:])
    return ''.join(pieces)


def privacy_copy(value):
    holder,changes=[None],[]
    pending,visited=[(holder,0,value,'',0)],0
    while pending:
        parent,key,item,route,depth=pending.pop()
        visited+=1
        require(visited<=100_000 and depth<=64,'privacy traversal bound')
        if type(item) is dict:
            require(len(item)<=1024,'object bound')
            target={}
            parent[key]=target
            for name,child in item.items():
                clean=redact_text(name,route+'/<key>',changes)
                require(clean not in target,'redaction key collision')
                target[clean]=None
                pointer=clean.replace('~','~0').replace('/','~1')
                pending.append((target,clean,child,route+'/'+pointer,depth+1))
        elif type(item) is list:
            require(len(item)<=32768,'array bound')
            target=[None]*len(item)
            parent[key]=target
            pending.extend((target,i,child,route+'/'+str(i),depth+1) for i,child in enumerate(item))
        elif type(item) is str:
            parent[key]=redact_text(item,route,changes)
        else:
            require(item is None or type(item) in (bool,int,float),'JSON scalar')
            parent[key]=item
        require(len(pending)<=100_000 and len(changes)<=16384,'privacy work bound')
    return holder[0],changes


def object_of(values,role):
    result=parse(values[role],CAP)
    require(type(result) is dict,'input object: '+role)
    return result


def json_output(outputs,provenance,name,value,source=None):
    clean,changes=privacy_copy(value)
    outputs[name]=canonical(clean)+b'\n'
    provenance[name]=dict(source=source,all_fields_preserved=True,host_path_substitutions=changes)


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
