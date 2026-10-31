"""Explicit local integration of the frozen courier and grammar3 native evaluator.

Only caller-selected, digest-pinned executables run. Package data cannot select
a program, fetch a resource, or grant authority. Failed work directories remain.
"""
from pathlib import Path
import stat
import sys

import transport_core as core
from transport_core_language import parse_fragment, validate_translation
from transport_schema import canonical, fields, json_value, require, sha
from transport_install_support import read_regular, write_new, confined
from transport_core_process import run_bounded

CAP = 131072
ENV = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
       'PYTHONDONTWRITEBYTECODE': '1'}
MODULES = ('transport_core.py', 'transport_core_language.py', 'transport_core_bridge.py',
           'transport_core_cli.py', 'transport_core_process.py', 'transport_schema.py', 'transport_wire.py',
           'transport_requirement_language.py', 'transport_operators.py')
HERE = Path(__file__).resolve().parent


def pinned(path, expected, cap=4194304):
    require(type(expected) is str and len(expected) == 64 and
            all(c in '0123456789abcdef' for c in expected), 'CORE_PIN_FORMAT')
    raw = read_regular(path, cap)
    require(sha(raw) == expected, 'CORE_DEPENDENCY_IDENTITY')
    return raw


def runtime(decoder_sha, native_sha):
    require(sys.version_info[:2] == (3, 14), 'CORE_PYTHON_VERSION')
    files = {name: sha(read_regular(HERE / name, CAP)) for name in MODULES}
    files['install/transport_install_support.py'] = sha(read_regular(
        HERE.parent / 'install/transport_install_support.py', CAP))
    return {'schema': 'transport/core-runtime/1', 'python': '3.14', 'files': files,
            'decoder_launcher_sha256': decoder_sha, 'native_sha256': native_sha,
            'wire': 'STC3', 'external': 'Python standard library, Linux and libc; trusted caller-held code identity'}


def workspace(path):
    require(path.is_absolute() and '..' not in path.parts, 'CORE_ABSOLUTE_WORKSPACE')
    confined(path.parent, path.name)
    mode = path.parent.stat()
    require(stat.S_IMODE(mode.st_mode) == 0o700, 'CORE_PRIVATE_PARENT')
    path.mkdir(mode=0o700)
    require(stat.S_IMODE(path.stat().st_mode) == 0o700, 'CORE_PRIVATE_WORKSPACE')
    return path


def call(argv, root, label):
    result = run_bounded(argv, root, ENV, timeout=60, cap=CAP)
    for stream in ('stdout', 'stderr'):
        write_new(root / (label + '.' + stream), result[stream], CAP)
    record = {k: v for k, v in result.items() if k not in ('stdout', 'stderr')}
    record.update(argv=argv, streams={s: {'bytes': len(result[s]), 'sha256': sha(result[s])}
                                      for s in ('stdout', 'stderr')})
    write_new(root / (label + '.json'), canonical(record), CAP)
    require(result['status'] == 'SUCCESS' and result['exit_code'] == 0
            and result['stderr'] == b'', 'CORE_CHILD_REFUSED_' + label)
    return result['stdout']


def translation(source, value):
    parsed = parse_fragment(source)
    if parsed['status'] == 'IN_FRAGMENT':
        return validate_translation(source, value['tree'], value['symbols'])
    require(value['translation'] == 'declared', 'CORE_REQUIREMENT_NOT_IN_FRAGMENT')
    return parsed


def envelope(source, plan_raw, model_raw, dependencies):
    value = core.plan(plan_raw, source)
    translated = translation(source, value)
    if model_raw is not None:
        core.model(model_raw, value['symbols'], source)
    result = {'schema': 'transport/core-envelope/3', 'source_sha256': sha(source),
              'plan': value, 'operators': core.OPERATORS, 'runtime': dependencies,
              'model': None if model_raw is None else {'source': 'MODEL', 'sha256': sha(model_raw)},
              'translation': translated}
    return canonical(result)


def check_envelope(raw, source, model_raw, dependencies):
    value = json_value(raw, 65536)
    fields(value, {'schema', 'source_sha256', 'plan', 'operators', 'runtime', 'model', 'translation'})
    require(value['schema'] == 'transport/core-envelope/3', 'CORE_ENVELOPE_VERSION')
    require(value['runtime'] == dependencies, 'CORE_EVALUATOR_DEPENDENCY')
    require(value['source_sha256'] == sha(source), 'CORE_SOURCE_IDENTITY')
    require(value['operators'] == core.OPERATORS, 'CORE_OPERATOR_DICTIONARY')
    require(raw == envelope(source, canonical(value['plan']), model_raw, dependencies),
            'CORE_ENVELOPE_REGENERATION')
    return value


def courier_plan(source, payload, model_raw, value):
    inputs = [('SOURCE', 'Original source', source), ('CORE', 'Grammar 3 formula and keys', payload)]
    if model_raw is not None:
        inputs.append(('MODEL', 'Supplied finite structure, not world truth', model_raw))
    metadata = [{'id': n, 'label': label, 'media_type': 'application/octet-stream',
                 'provenance': 'Caller supplied bytes; no authentication or authority.'}
                for n, label, _ in inputs]
    reading = {'id': 'FORMAL_READING', 'label': 'Closed formula', 'status': 'proposed',
               'provenance': 'Declared formalization; model-relative evaluation is a separate procedure.',
               'text': core.display(value) + '\n' + canonical(core.OPERATORS).decode('utf-8'),
               'anchors': [{'source': 'CORE', 'span': [0, len(payload)]}]}
    plan = {'schema': 'transport/transport-plan/1', 'sources': metadata,
            'interpretations': [reading], 'uncertainties': [], 'relations': []}
    return plan, inputs


def encode(source, plan_raw, model_raw, decoder, decoder_sha, native, native_sha,
           root, budget=512, reference='attached:meaning.zip'):
    pinned(decoder, decoder_sha)
    pinned(native, native_sha)
    deps = runtime(decoder_sha, native_sha)
    payload = envelope(source, plan_raw, model_raw, deps)
    value = json_value(payload)['plan']
    plan, inputs = courier_plan(source, payload, model_raw, value)
    require(sum(len(raw) for _, _, raw in inputs) <= 65536, 'CORE_AGGREGATE_SOURCE_BOUND')
    write_new(root / 'courier-plan.json', canonical(plan), CAP)
    argv = [str(decoder), 'encode-plan', str(root / 'courier-plan.json'), str(root / 'product'),
            '--budget', str(budget), '--reference', reference]
    for name, _, raw in inputs:
        path = root / (name + '.bin')
        write_new(path, raw, CAP)
        argv.extend(('--source', name + '=' + str(path)))
    call(argv, root, 'encode')
    pair = root / 'product'
    result = decode(pair / 'share.txt', pair / 'meaning.zip', decoder, decoder_sha,
                    native, native_sha, root, 'roundtrip')
    for name, _, raw in inputs:
        require(read_regular(root / ('roundtrip-' + name + '.bin'), CAP) == raw,
                'CORE_EXACT_SOURCE_RECOVERY')
    return dict(result, pair=str(pair), exact_source_recovery='BYTE_COMPARISON_PASS',
                share_characters=len(read_regular(pair / 'share.txt', CAP).decode('utf-8')),
                character_convention='Unicode code points; no platform compliance claim',
                archive_bytes=len(read_regular(pair / 'meaning.zip', CAP)))


def recover(share, archive, decoder, root, label):
    inspection = json_value(call([str(decoder), 'inspect', str(share), '--archive', str(archive)],
                                 root, label + '-inspect'))
    ids = [s['id'] for s in inspection['sources']]
    require(ids in (['SOURCE', 'CORE'], ['SOURCE', 'CORE', 'MODEL']), 'CORE_PACKAGE_SOURCES')
    sources = {}
    for name in ids:
        path = root / (label + '-' + name + '.bin')
        call([str(decoder), 'recover', str(share), str(path), '--archive', str(archive),
              '--source', name], root, label + '-recover-' + name)
        sources[name] = read_regular(path, 65536)
    return sources, inspection['identity']


def evaluate(value, finite_model, source, native, native_sha, root, label):
    if finite_model is None:
        return {'status': 'NOT_EVALUATED', 'nodes': [], 'result': None}
    frame = core.wire(value, finite_model, source)
    path = root / (label + '.stc3')
    write_new(path, frame, CAP)
    pinned(native, native_sha)
    raw = call([str(native), str(path)], root, label + '-native')
    pinned(native, native_sha)
    require(read_regular(path, CAP) == frame, 'CORE_FRAME_CHANGED')
    values = core.native_values(raw, value)
    return {'status': 'EVALUATED_SUPPLIED_MODEL', 'nodes': values, 'result': values[-1],
            'frame_sha256': sha(frame), 'native_sha256': native_sha}


def decode(share, archive, decoder, decoder_sha, native, native_sha, root, label='receive'):
    pinned(decoder, decoder_sha)
    pinned(native, native_sha)
    held = (sha(read_regular(share, CAP)), sha(read_regular(archive, CAP)))
    sources, identity = recover(share, archive, decoder, root, label)
    source, payload, model_raw = sources['SOURCE'], sources['CORE'], sources.get('MODEL')
    deps = runtime(decoder_sha, native_sha)
    env = check_envelope(payload, source, model_raw, deps)
    finite = None if model_raw is None else core.model(model_raw, env['plan']['symbols'], source)
    result = evaluate(env['plan'], finite, source, native, native_sha, root, label)
    require(held == (sha(read_regular(share, CAP)), sha(read_regular(archive, CAP))), 'CORE_PAIR_CHANGED')
    pinned(decoder, decoder_sha)
    result.update(schema='transport/core-result/3', package_identity=identity,
                  source_sha256=sha(source), payload_sha256=sha(payload),
                  model_sha256=None if model_raw is None else sha(model_raw),
                  translation=env['translation']['status'], grammar=core.GRAMMAR,
                  semantic_scope='CLOSED_FORMULA_IN_SUPPLIED_FINITE_MODEL',
                  semantic_completeness='UNPROVEN', world_truth='NOT_CERTIFIED',
                  interpretation_entailment='NOT_CHECKED', execution_authority='NONE')
    write_new(root / (label + '-result.json'), canonical(result), CAP)
    return result
