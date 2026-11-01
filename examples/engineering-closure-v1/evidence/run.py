"""Bounded, source-frozen native proof/test campaign; never edits installed inputs."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time

W = Path('/home/sicarii/Work/semantic-transport-bound-evaluation-20261028')
P = Path('/dev/shm/semantic-transport-proof-closure-20261029')
L = Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/acceptance-v1-preflight-20261029/engineering-admission-01')
D = Path('/home/sicarii/Projects/source-anchored-semantic-transport/evidence/semantic-handoff-v1/positive-02/transport/decoder')
sys.path.insert(0, str(W / 'install'))
from transport_install_support import run_bounded


def need(condition, reason):
    if not condition:
        raise ValueError(reason)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def save(path, value):
    raw = json.dumps(value, sort_keys=True, indent=2).encode() + b'\n'
    need(len(raw) <= 2097152, 'evidence bound')
    with path.open('xb') as stream:
        need(stream.write(raw) == len(raw), 'short evidence write')


def files_snapshot(root, names):
    need(len(names) <= 128, 'file count bound')
    rows, total = {}, 0
    for name in names:
        path = root / name
        need(path.is_file() and not path.is_symlink(), 'regular input required')
        need(path.stat().st_size <= 4194304, 'input bound')
        raw = path.read_bytes()
        total += len(raw)
        need(total <= 16777216, 'aggregate input bound')
        rows[name] = pin(raw)
    return rows


def installed_snapshot():
    manifest = json.loads((D / 'INSTALL.json').read_bytes())
    names = ['INSTALL.json'] + [item['path'] for item in manifest['files']]
    result = files_snapshot(D, names)
    for item in manifest['files']:
        need(result[item['path']] == {key:item[key] for key in ('bytes','sha256')},
             'installed manifest mismatch')
    return result


def prepare():
    out = subprocess.run(['git','ls-files','src','evaluation','transport.gpr'],
                         cwd=W, capture_output=True, check=True, timeout=5)
    names = [x for x in out.stdout.decode().splitlines()
             if x.endswith(('.ads','.adb','.c','.gpr'))]
    source = files_snapshot(W, names)
    stage = P / 'source'
    stage.mkdir()
    for name in names:
        target = stage / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open('xb') as stream:
            raw = (W / name).read_bytes()
            need(pin(raw) == source[name], 'source changed during copy')
            need(stream.write(raw) == len(raw), 'short source copy')
    need(files_snapshot(stage, names) == source, 'copy mismatch')
    (P / 'tmp').mkdir()
    save(P / 'source-before.json', source)
    save(P / 'installed-before.json', installed_snapshot())
    return source


def configuration():
    root = '/home/sicarii/opt/gnat/'
    compiler = root+'gnat-aarch64-linux-16.1.0-1/bin'
    build = root+'gprbuild-aarch64-linux-26.0.0-1/bin'
    prover = root+'gnatprove-aarch64-linux-16.1.0-1/bin'
    env = dict(PATH=':'.join((compiler,build,prover,'/usr/bin','/bin')),
        GPR_PROJECT_PATH=root+'gnatprove-aarch64-linux-16.1.0-1/lib/gnat:'+root+'auxiliary/share/gpr',
        TMPDIR=str(P/'tmp'),LANG='C',LC_ALL='C',TZ='UTC',PYTHONDONTWRITEBYTECODE='1')
    args = ['-U','--level=2','--report=all','--warnings=error',
            '--checks-as-errors=on','--proof-warnings=on','-j1']
    projects = [('core','transport.gpr'),('evaluation','evaluation/transport_eval.gpr'),
                ('bound','evaluation/transport_bound_eval_proof.gpr')]
    commands = [(name+'-proof',[prover+'/gnatprove','-P',project]+args) for name,project in projects]
    builds = [('core','transport.gpr'),('evaluation','evaluation/transport_eval.gpr'),
              ('eval-checks','evaluation/tests/checks.gpr'),('bound-checks','evaluation/tests/bound_checks.gpr')]
    commands = [(name+'-build',[build+'/gprbuild','-p','-P',project,'-j1']) for name,project in builds]+commands
    commands += [('eval-tests',[str(P/'source/evaluation/tests/bin/transport_eval_checks')]),
                 ('bound-tests',[str(P/'source/evaluation/tests/bin/transport_bound_eval_checks')])]
    tools = [compiler+'/gcc',compiler+'/gnat',build+'/gprbuild',prover+'/gnatprove',
             root+'gnatprove-aarch64-linux-16.1.0-1/libexec/spark/bin/gnat2why',
             root+'gnatprove-aarch64-linux-16.1.0-1/libexec/spark/bin/cvc5',
             root+'gnatprove-aarch64-linux-16.1.0-1/libexec/spark/bin/z3',
             root+'gnatprove-aarch64-linux-16.1.0-1/libexec/spark/bin/alt-ergo']
    return env, commands, tools


def admit(source, env, commands, tools):
    tool_rows = {}
    for name in tools:
        path = Path(name).resolve(strict=True)
        need(path.stat().st_size <= 134217728, 'tool hash bound')
        tool_rows[str(path)] = pin(path.read_bytes())
    save(P/'tool-identities.json',tool_rows)
    admission = dict(schema='transport/native-closure-admission/1',
      source_commit='ce8950892e6dfb9f429111ab6d6bf01f31ee1661', source=source,
      source_snapshot=str(P/'source'), runner=pin((P/'run.py').read_bytes()),
      tool_identities=tool_rows, commands=commands, environment=env,
      budget='Uses remaining already prepaid tranche06 through 2026-10-29T12:14:00Z; no extra debit or refund.',
      scope_change='After completed reader increment, admit exact native proof and unchanged tests in the SAME development round. Supersedes tranche06 no-new-build task scope solely for these isolated commands. No guarantee or resource limit weakened; no installed rebuild or repinning.',
      authority='User active goal engineering gate plus execution amendment permits subsequent finite local items without a new question.',
      bounds=dict(each_command_wall_seconds=120, cpu_seconds=120, address_space_bytes=1073741824,
          per_file_bytes=33554432, each_stream_bytes=1048576, parallel_jobs=1,
          scratch_aggregate_bytes=268435456, scratch_file_count=8192),
      storage='Pinned /dev/shm working set; root below configured reserve. No disk build, cleanup or iPad dependency. Preserve raw results and source locally; off-host backup unverified.',
      oracle='Unmodified checked-in assertions/contracts and native deterministic fixtures. Every named -U scope must have exit zero, valid nonempty summary, zero justified/unproved, no Assume/Annotate. Source and installed bytes must match before/after.',
      baseline='Exact current native source and existing installed decoder unchanged; no human benefit or performance comparison claimed.',
      exclusions=['SPARK-Off native and IO','C file boundary','Python orchestration','compiler and host','semantic entailment/completeness','human benefit','external validation'],
      status='ADMITTED_NOT_EXECUTED')
    save(L/'native-proof-closure-admission-01.json',admission)
    save(P/'admission.json',admission)


def size_gate():
    count, total = 0, 0
    for root, dirs, files in os.walk(P):
        need(len(dirs) <= 8192 and len(files) <= 8192, 'directory bound')
        for name in files:
            count += 1
            total += (Path(root)/name).stat().st_size
            need(count <= 8192 and total <= 268435456, 'scratch bound')
    return dict(files=count, bytes=total)


def execute(label, command, env):
    need(time.time() < 1793275915, 'prepaid tranche lacks full command allowance')
    size_gate()
    print('START '+label, flush=True)
    result = run_bounded(command, P/'source', env)
    for stream in ('stdout','stderr'):
        raw = result.pop(stream)
        with (P/(label+'.'+stream)).open('xb') as output:
            need(output.write(raw) == len(raw), 'short log write')
        result[stream] = pin(raw)
    result['storage_after'] = size_gate()
    save(P/(label+'.json'),result)
    print(label+' '+result['status'], flush=True)
    return result


def main():
    source = prepare()
    env, commands, tools = configuration()
    admit(source,env,commands,tools)
    for label, command in commands:
        execute(label,command,env)
    save(P/'source-after.json',files_snapshot(W,list(source)))
    save(P/'copied-source-after.json',files_snapshot(P/'source',list(source)))
    save(P/'installed-after.json',installed_snapshot())
    need(json.loads((P/'installed-before.json').read_text()) == installed_snapshot(),
         'installed runtime changed')
    need(source == files_snapshot(W,list(source)), 'worktree native source changed')
    print('ALL_COMMANDS_RECORDED; proof gate assessment still required', flush=True)


if __name__ == '__main__':
    main()
