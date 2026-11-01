"""Fixed commands and clean environment for the one document build/proof profile."""
import os
from pathlib import Path
import time
from .common import TERMINAL_RESERVE, digest, json_new, need
from .process import admit_phase, phase
from .proof import proof_summary, source_gate


def commands(root, tools):
    return [('build', 120, [tools['gprbuild'], '-R', '-P',
            str(root / 'document_native/document_native.gpr'), '-j1', '-cargs:Ada', '-gnata']),
            ('proof', 300, [tools['gnatprove'], '-P', str(root / 'document_native/document_ledger_proof.gpr'),
             '-U', '--level=2', '--report=all', '--warnings=error', '-j1', '--prover=z3',
             '--timeout=1', '--counterexamples=off'])]


def environment(work, config):
    env = {'PATH': ':'.join(config['bins']) + ':/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
           'GPR_PROJECT_PATH': config['gpr_path'], 'TZ': 'UTC'}
    for key, name in (('HOME', 'home'), ('TMPDIR', 'tmp'), ('XDG_CACHE_HOME', 'cache'),
                      ('DOCUMENT_NATIVE_OBJ', 'obj'), ('DOCUMENT_NATIVE_BIN', 'bin'),
                      ('DOCUMENT_PROOF_OBJ', 'proof')):
        folder = work / name
        folder.mkdir(mode=0o700)
        env[key] = str(folder)
    return env


def run(work, config):
    root = Path(config['source_root'])
    pins = source_gate(root)
    env = environment(work, config)
    records, report, binary_hash, failure = [], None, None, None
    try:
        for label, seconds, argv in commands(root, config['tools']):
            deadline = admit_phase(seconds, config['global_deadline'], TERMINAL_RESERVE)
            record = phase(argv, seconds, deadline, work, label, env)
            records.append(record)
            need(record['returncode'] == 0, label + ' failed/deadline; raw evidence retained')
        report = proof_summary(work)
        binary_hash = digest(work / 'bin/document_native_decode')
        need(pins == source_gate(root), 'ledger source changed')
    except (ValueError, OSError, UnicodeError) as error:
        failure = type(error).__name__ + ':' + str(error)[:4096]
    result = {'status': 'BUILT_AND_LEDGER_PROOF_CHECKED' if failure is None else 'FAILED',
              'failure': failure, 'runs': records, 'proof': report, 'native_sha256': binary_hash,
              'ledger_source': pins, 'source_frame_ledger': 'PROVED' if failure is None else 'UNPROVEN',
              'native_execution': 'UNRUN', 'Python_orchestration': 'UNPROVEN',
              'English_semantics': 'UNPROVEN', 'whole_system': 'UNPROVEN'}
    json_new(work / 'worker-result.json', result)
    return result
