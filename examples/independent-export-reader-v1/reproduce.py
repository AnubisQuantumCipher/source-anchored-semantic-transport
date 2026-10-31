#!/usr/bin/env python3
"""Recheck frozen installed exports using only the independent consumer."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
READER = HERE.parents[1] / 'install/read_transport_export.py'
CASES = ('plain', 'typed', 'empty_text', 'source_bound', 'source_count')
CAP = 131072


def require(value, reason):
    if not value:
        raise ValueError(reason)


def read(path):
    require(path.is_file() and not path.is_symlink(), 'fixture regular file required')
    with path.open('rb') as stream:
        raw = stream.read(CAP + 1)
    require(len(raw) <= CAP, 'fixture byte bound')
    return raw


def save(path, raw):
    require(len(raw) <= CAP, 'result byte bound')
    with path.open('xb') as stream:
        require(stream.write(raw) == len(raw), 'result short write')


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def limits():
    for kind, cap in ((resource.RLIMIT_CPU,60), (resource.RLIMIT_AS,268435456),
                      (resource.RLIMIT_FSIZE,CAP)):
        resource.setrlimit(kind, (cap,cap))


def execute(case, label, args, optimized):
    command = [sys.executable,'-I','-S','-B','-Werror']
    if optimized:
        command.append('-O')
    command += [str(case / 'recipient/reader.py'), *args]
    start = time.monotonic_ns()
    with (case / (label + '.stdout')).open('xb') as out:
        with (case / (label + '.stderr')).open('xb') as err:
            result = subprocess.run(command, cwd=case / 'recipient',
                env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'},
                stdout=out, stderr=err, timeout=65, check=False, preexec_fn=limits)
    observation = {'argv':command,'exit_code':result.returncode,
                   'elapsed_ns':time.monotonic_ns()-start}
    save(case / (label + '.command.json'), canonical(observation))
    require(result.returncode == 0, 'reader refused: ' + str(case / label))
    require(read(case / (label + '.stderr')) == b'', 'reader stderr')
    stdout = read(case / (label + '.stdout'))
    require(stdout.endswith(b'\n'), 'reader response newline')
    return json.loads(stdout), observation


def prepare(case, name):
    fixture = HERE / 'fixtures' / name
    expected = json.loads(read(fixture / 'expected.json'))
    recipient = case / 'recipient'
    recipient.mkdir()
    export = recipient / 'export'
    export.mkdir()
    (export / 'sources').mkdir()
    save(recipient / 'reader.py', read(READER))
    paths = ['export.json', 'metadata.json', 'UNVERIFIED_AI_EXPLANATION.txt']
    require(1 <= len(expected['sources']) <= 16, 'oracle source count')
    paths += ['sources/' + row['id'] + '.bin' for row in expected['sources']]
    for relative in paths:
        save(export / relative, read(fixture / 'export' / relative))
    require(pin(read(export / 'export.json')) == expected['export'], 'held export pin')
    return fixture, expected, export


def compare_selected(case, fixture, expected, export, optimized):
    identity = expected['export']['sha256']
    common = ['--expect-export-sha256',identity]
    observations = []
    summary, observation = execute(case, 'inspect', ['inspect',str(export),*common], optimized)
    require(summary['status'] == 'VERIFIED_AGAINST_PINNED_EXPORT', 'inspect status')
    observations.append(observation)
    for row in expected['sources']:
        destination = case / ('recovered-' + row['id'] + '.bin')
        answer, observed = execute(case, 'recover-' + row['id'],
            ['recover',str(export),str(destination),'--source',row['id'],*common],optimized)
        require(answer['status'] == 'EXACT_PINNED_EXPORT_BYTES_RECOVERED', 'recover status')
        original = read(fixture / 'originals' / (row['id'] + '.bin'))
        require(read(destination) == original and pin(original) == {k:row[k] for k in ('bytes','sha256')},
                'original byte comparison failed')
        observations.append(observed)
    for action, original_path in [('explanation','original-explanation.txt'), ('metadata','producer-metadata.json')]:
        destination = case / ('recovered-' + action + '.bin')
        answer, observed = execute(case, action, [action,str(export),str(destination),*common],optimized)
        require(answer['status'] == 'EXACT_PINNED_EXPORT_BYTES_RECOVERED', 'selected status')
        require(read(destination) == read(fixture / original_path), 'selected byte comparison')
        observations.append(observed)
    return observations


def one_case(output, name, optimized):
    case = output / (name + ('-optimized' if optimized else '-normal'))
    case.mkdir()
    fixture, expected, export = prepare(case,name)
    observations = compare_selected(case,fixture,expected,export,optimized)
    rows = expected['sources']
    result = {'case':name,'optimized':optimized,'original_comparison':'EXACT_BYTES_PASS',
        'sources':rows,'explanation':expected['explanation'],'metadata':expected['metadata'],
        'expected_export_sha256':expected['export']['sha256'],'calls':observations,
        'reader':pin(read(READER)),'recipient_contents':'reader.py and pinned export only',
        'originals_visible_to_harness':True,'hostile_process_isolation':'NOT_CLAIMED',
        'source_authentication':'NOT_PROVIDED','narrative_fidelity':'NOT_ASSESSED'}
    save(case / 'comparison.json',canonical(result))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('output',type=Path,help='new results directory')
    args = parser.parse_args()
    output = args.output.absolute()
    output.mkdir()
    rows = []
    for optimized in (False,True):
        for name in CASES:
            rows.append(one_case(output,name,optimized))
    result = {'schema':'transport/independent-export-reproduction/1',
        'status':'EXACT_FROZEN_EXPORT_COMPARISONS_PASS','cases':rows,
        'scope':'Development fixtures produced by installed decoder; independent consumer executed.',
        'external_human_reproduction':'NOT_PERFORMED','product_acceptance':'NOT_ESTABLISHED'}
    save(output / 'results.json',canonical(result))
    print('PASS: independent consumer recovered frozen original, explanation and metadata bytes.')


if __name__ == '__main__':
    main()
