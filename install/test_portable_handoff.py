"""Deterministic two-installation handoff observations; no model or sandbox claim."""

import argparse
import ast
import base64
import io
import json
from pathlib import Path
import stat
import sys
import zipfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from transport_install_layout import DIGEST, checked_json, exact_tree
from transport_install_support import canonical, confined, read_regular, require, run_bounded, sha, write_new

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
FIXTURES = ('emotion', 'controller', 'publication', 'attributed', 'recipe', 'opaque')
GROUPS = ('interpretations', 'uncertainties', 'relations')
PAIR = ('share.txt', 'meaning.zip')
MAX_COMMANDS, MAX_FIXTURE, MAX_PACKAGE = 96, 65536, 131072
UNIT_KEYS = ('id', 'source', 'interpretation', 'kind', 'context')
NEGATIVES = {'swapped-archive', 'changed-value', 'invalid-share', 'missing-archive', 'mismatched-runtime'}


def record(data):
    return {'bytes': len(data), 'sha256': sha(data)}


def bundle_snapshot(bundle):
    manifest_raw = read_regular(bundle / 'INSTALL.json')
    manifest = checked_json(manifest_raw)
    entries = manifest['files']
    require(type(entries) is list and 1 <= len(entries) <= 128, 'installation member bound')
    names = [item['path'] for item in entries]
    require(len(set(names)) == len(names), 'duplicate installation member')
    names += ['INSTALL.json', 'bin/semantic-transport']
    exact_tree(bundle, set(names))
    files, total = {}, 0
    for name in names:
        data = read_regular(confined(bundle, name))
        total += len(data)
        require(total <= 8388608, 'installation aggregate byte bound')
        files[name] = dict(record(data), mode=stat.S_IMODE((bundle / name).stat().st_mode))
    runtime_raw = read_regular(bundle / 'RUNTIME.json')
    runtime = checked_json(runtime_raw)
    require(runtime['schema'] == 'transport/runtime/1', 'unexpected runtime schema')
    require(type(runtime['files']) is list and 1 <= len(runtime['files']) <= 32, 'runtime file bound')
    runtime_files = {}
    for item in runtime['files']:
        name = item['path']
        require(name not in runtime_files and name in files, 'runtime membership mismatch')
        actual = {key: files[name][key] for key in ('bytes', 'sha256')}
        require(item == dict(actual, path=name), 'runtime actual file identity mismatch')
        runtime_files[name] = actual
    require('bin/transport_native' in runtime_files, 'runtime native member missing')
    return dict(path=str(bundle), install_manifest=record(manifest_raw),
                runtime_manifest=record(runtime_raw), runtime_files=runtime_files, files=files)


def compare_runtime(sender, receiver, expected):
    require(sender['path'] != receiver['path'], 'separate installation paths required')
    require(sender['runtime_manifest']['sha256'] == expected,
            'sender runtime differs from independently held expected identity; handoff NOT PERFORMED')
    require(sender['runtime_manifest'] == receiver['runtime_manifest']
            and sender['runtime_files'] == receiver['runtime_files'],
            'sender and receiver runtime identities differ; handoff NOT PERFORMED')
    return dict(status='MATCHED_ACTUAL_RUNTIME_FILES',
                independently_held_runtime_sha256=expected,
                runtime_manifest=sender['runtime_manifest'], runtime_files=sender['runtime_files'],
                install_manifests_equal=sender['install_manifest'] == receiver['install_manifest'],
                scope='Runtime identity compared separately from installation manifest identity')


def graph_signature(meaning):
    """Compare declared DAG structure, permitting codec node deduplication only."""
    nodes, signatures = meaning['nodes'], []
    require(type(nodes) is list and 1 <= len(nodes) <= 128, 'fixture node bound')
    for index, node in enumerate(nodes):
        arguments = node.get('args', [])
        require(type(arguments) is list and len(arguments) <= 16, 'fixture argument bound')
        require(all(type(arg) is int and 0 <= arg < index for arg in arguments), 'fixture DAG order')
        value = dict(node)
        if 'args' in value:
            value['args'] = [signatures[arg] for arg in arguments]
        signatures.append(sha(canonical(value)))
    root = meaning['root']
    require(type(root) is int and 0 <= root < len(nodes), 'fixture root bound')
    return dict(schema=meaning['schema'], root=signatures[root],
                nodes=sorted(set(signatures)), ambiguities=meaning['ambiguities'])


def expected_declarations(plan, sources):
    result = {}
    for group in GROUPS:
        entries = plan[group]
        require(type(entries) is list and len(entries) <= 64, 'fixture declaration bound')
        result[group] = []
        for item in entries:
            require(type(item['anchors']) is list and len(item['anchors']) <= 16, 'fixture anchor bound')
            anchors = []
            for anchor in item['anchors']:
                source = sources[anchor['source']]
                begin, end = anchor['span']
                require(type(begin) is int and type(end) is int
                        and 0 <= begin <= end <= len(source), 'fixture anchor span')
                anchors.append(dict(anchor, sha256=sha(source[begin:end])))
            result[group].append(dict(item, anchors=anchors))
    return result


def check_typed(view, plan):
    expected, actual = plan.get('meaning_units', []), view.get('meaning_units', [])
    require(len(expected) == len(actual) and len(expected) <= 16, 'typed unit count mismatch')
    signatures = []
    for declared, received in zip(expected, actual, strict=True):
        require(all(declared[key] == received[key] for key in UNIT_KEYS), 'typed unit metadata changed')
        expected_plan = declared['plan']
        require(received['lexicon'] == expected_plan['symbols'], 'typed literal values changed')
        left, right = graph_signature(expected_plan['meaning']), graph_signature(received['meaning'])
        require(left == right and received['grammar'] == left['schema'], 'typed condition structure changed')
        assurance = received['assurance']
        require(assurance['execution_authority'] == 'NONE'
                and assurance['interpretation_entailment'] == 'UNPROVEN'
                and assurance['context_adequacy'] == 'UNPROVEN', 'typed assurance escalated')
        signatures.append(dict(id=declared['id'], expected=left, received=right,
                               status='DECLARED_STRUCTURE_AND_LITERAL_VALUES_MATCH'))
    return signatures


def check_view(view, fixture):
    plan, sources = fixture['expected'], fixture['sources']
    declarations = expected_declarations(plan, sources)
    require(all(view[group] == declarations[group] for group in GROUPS), 'declared uncertainty or relation changed')
    expected_sources = [dict(item, **record(sources[item['id']])) for item in plan['sources']]
    require(view['sources'] == expected_sources, 'source declaration changed')
    require(view['assurance']['declarations'] == 'UNVERIFIED'
            and view['assurance']['interpretation_entailment'] == 'UNPROVEN'
            and view['assurance']['author_authentication'] == 'NOT_AUTHENTICATED', 'assurance escalated')
    return check_typed(view, plan)


def check_focus(value, view, fixture):
    require(value['schema'] == 'transport/focus/1' and value['identity'] == view['identity']
            and value['selected_unit'] == 'MEANING', 'focus identity mismatch')
    require(value['execution_authority'] == 'NONE' and value['context_adequacy'] == 'UNPROVEN'
            and value['dependency_closure'] == 'ALL_DECLARED_LINKS_CHECKED', 'focus assurance mismatch')
    for group in (*GROUPS, 'meaning_units', 'sources'):
        require(value[group] == view[group], 'focus dropped a declared dependency')
    anchors = {tuple((a['source'], *a['span'], a['sha256']))
               for group in GROUPS for item in view[group] for a in item['anchors']}
    require(len(anchors) <= 128 and len(value['source_excerpts']) == len(anchors), 'focus excerpt count')
    seen = set()
    for excerpt in value['source_excerpts']:
        begin, end = excerpt['span']
        key = (excerpt['source'], begin, end, excerpt['sha256'])
        require(key in anchors and key not in seen, 'focus unexpected or repeated excerpt')
        seen.add(key)
        original = fixture['sources'][excerpt['source']][begin:end]
        require(sha(original) == excerpt['sha256']
                and base64.b64decode(excerpt['bytes_base64'], validate=True) == original,
                'focus excerpt differs from original source')


def altered_archive(data):
    """Change one known fixture literal; retain the old binding for rejection."""
    require(len(data) <= MAX_PACKAGE, 'mutation input byte bound')
    destination, mutation = io.BytesIO(), None
    with zipfile.ZipFile(io.BytesIO(data), 'r', allowZip64=False) as source:
        members = source.infolist()
        require(len(members) == 5 and len({item.filename for item in members}) == 5, 'mutation member bound')
        with zipfile.ZipFile(destination, 'w', allowZip64=False) as output:
            for info in members:
                require(info.compress_type == zipfile.ZIP_STORED and 0 < info.file_size <= MAX_PACKAGE,
                        'mutation stored-member bound')
                raw = source.read(info)
                require(len(raw) == info.file_size, 'mutation member readback')
                if info.filename == 'codec.json':
                    require(raw.count(b'"100"') == 1, 'controller literal mutation precondition')
                    changed = raw.replace(b'"100"', b'"101"', 1)
                    mutation = dict(member=info.filename, before=record(raw), after=record(changed),
                                    old_literal='100', new_literal='101')
                    raw = changed
                output.writestr(info, raw)
    result = destination.getvalue()
    require(mutation is not None and len(result) <= MAX_PACKAGE, 'mutation output bound')
    return result, mutation


class Campaign:
    def __init__(self, args):
        self.args, self.evidence = args, args.evidence.absolute()
        self.implementation, self.implementation_paths, self.preflight = {}, {}, False
        for name, filename in (('harness', 'test_portable_handoff.py'),
                               ('support', 'transport_install_support.py'),
                               ('layout', 'transport_install_layout.py')):
            path = Path(__file__).parent / filename
            self.implementation[name] = record(read_regular(path))
            self.implementation_paths[str(path)] = self.implementation[name]
        self.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.commands, self.inputs, self.products, self.bundles = [], {}, {}, {}
        self.comparisons, self.controls, self.runtime = {}, {}, None
        for name in ('sender', 'recipient', 'inputs', 'negative'):
            (self.evidence / name).mkdir(mode=0o700)

    def input(self, path, target):
        data = read_regular(path, MAX_FIXTURE)
        self.inputs[str(path)] = record(data)
        write_new(target, data, MAX_FIXTURE)
        return data

    def command(self, name, bundle, cwd, arguments, refusal=None):
        require(len(self.commands) < MAX_COMMANDS, 'command count bound')
        argv = [str(bundle / 'bin/semantic-transport'), *map(str, arguments)]
        result = run_bounded(argv, cwd, ENVIRONMENT, timeout=30, cap=262144)
        entry = {key: value for key, value in result.items() if key not in ('stdout', 'stderr')}
        entry.update(name=name, cwd=str(cwd), environment=ENVIRONMENT, stdin='DEVNULL')
        for stream in ('stdout', 'stderr'):
            filename = f'{len(self.commands):03d}-{name}.{stream}.bin'
            write_new(self.evidence / filename, result[stream])
            entry[stream] = dict(record(result[stream]), file=filename)
        self.commands.append(entry)
        if refusal is not None:
            require(result['status'] == 'EXIT_NONZERO' and result['exit_code'] != 0
                    and b'REFUSED:' in result['stderr'] and refusal in result['stderr']
                    and not result['stdout'], name + ': explicit refusal required')
            self.controls[name] = dict(status='REFUSED_AS_REQUIRED', command=len(self.commands) - 1)
            return None
        require(result['status'] == 'SUCCESS' and result['exit_code'] == 0,
                name + ': ' + repr(result['stderr'][:512]))
        return checked_json(result['stdout'])

    def setup(self):
        for role in ('sender', 'receiver', 'mismatched'):
            bundle = getattr(self.args, role + '_bundle').absolute()
            self.bundles[role] = bundle_snapshot(bundle)
            for filename in ('INSTALL.json', 'RUNTIME.json'):
                write_new(self.evidence / (role + '-' + filename), read_regular(bundle / filename))
        self.runtime = compare_runtime(self.bundles['sender'], self.bundles['receiver'], self.args.expect_runtime_sha256)
        sender, receiver = self.args.sender_bundle, self.args.receiver_bundle
        require(not (sender / 'bin/transport_native').samefile(receiver / 'bin/transport_native'),
                'sender and receiver must have separate native files')
        require(self.bundles['mismatched']['runtime_manifest'] != self.bundles['sender']['runtime_manifest'],
                'negative runtime must differ')
        self.preflight = True
        for role, snapshot in self.bundles.items():
            result = self.command(role + '-check', Path(snapshot['path']), self.evidence, ['check'])
            require(result['status'] == 'INSTALLED_CONTENTS_CHECKED', 'installed status mismatch')

    def fixture(self, name):
        target = self.evidence / 'inputs' / name
        target.mkdir(mode=0o700)
        if name == 'opaque':
            directory = ROOT / 'fixtures/transport-general-v1'
            paths = {'OPAQUE': directory / 'opaque.bin', 'EMPTY': directory / 'empty.bin'}
            document_path = expected_path = directory / 'opaque-plan.json'
            action = 'encode-plan'
        else:
            directory = ROOT / 'examples/authoring-v1' / name
            source_id = 'RECIPE' if name == 'recipe' else 'SOURCE'
            paths = {source_id: directory / 'source.txt'}
            document_path = directory / 'authoring.json'
            group = 'transport-general-v1' if name == 'recipe' else 'semantic-examples-v1'
            expected_path = ROOT / 'fixtures' / group / (name + '-plan.json')
            action = 'encode'
        sources = {key: self.input(path, target / (key + '.original')) for key, path in paths.items()}
        self.input(document_path, target / 'document.json')
        expected = checked_json(self.input(expected_path, target / 'expected-plan.json'))
        require(len(expected['sources']) == len(sources) <= 2
                and {item['id'] for item in expected['sources']} == set(sources), 'fixture source IDs')
        arguments = [action, target / 'document.json', self.evidence / 'sender' / name, '--budget', '65536']
        for identifier in sources:
            arguments += ['--source', identifier + '=' + str(target / (identifier + '.original'))]
        encoded = self.command(name + '-encode', self.args.sender_bundle, target, arguments)
        require(encoded['status'] == 'MATCHED_PAIR_WRITTEN', 'sender encoding status')
        fixture = dict(sources=sources, expected=expected, source_paths=paths)
        self.products[name] = fixture
        return fixture

    def transfer(self, name):
        sender, recipient = self.evidence / 'sender' / name, self.evidence / 'recipient' / name
        recipient.mkdir(mode=0o700)
        files = {}
        for filename in PAIR:
            data = read_regular(sender / filename, MAX_PACKAGE)
            write_new(recipient / filename, data, MAX_PACKAGE)
            require(read_regular(recipient / filename, MAX_PACKAGE) == data, 'handoff copy mismatch')
            files[filename] = record(data)
        exact_tree(recipient, set(PAIR))
        self.comparisons[name] = dict(transferred=files, initial_recipient_members=list(PAIR),
            original_source_files_supplied=False, original_chat_supplied=False, recovery=[])
        return recipient

    def receive(self, name, fixture, recipient):
        common = ['share.txt', '--archive', 'meaning.zip']
        view = self.command(name + '-inspect', self.args.receiver_bundle, recipient, ['inspect', *common])
        validated = self.command(name + '-validate', self.args.receiver_bundle, recipient, ['validate', *common])
        require(view == validated, 'inspect and validate disagree')
        row = self.comparisons[name]
        row.update(package_identity=view['identity'], typed_structure=check_view(view, fixture),
                   declarations='MATCHED_RETAINED_FIXTURE_DECLARATIONS', uncertainty='DECLARED_RECORDS_PRESERVED')
        for identifier, original in fixture['sources'].items():
            output = identifier + '.recovered'
            value = self.command(name + '-recover-' + identifier, self.args.receiver_bundle, recipient,
                                 ['recover', 'share.txt', output, '--archive', 'meaning.zip', '--source', identifier])
            recovered = read_regular(recipient / output, MAX_FIXTURE)
            require(value['status'] == 'EXACT_OPAQUE_BYTES_RECOVERED' and recovered == original,
                    'recipient source-byte comparison failed')
            require(value['sha256'] == sha(original) and value['bytes'] == len(original), 'recovery receipt mismatch')
            row['recovery'].append(dict(source=identifier, original=record(original), recovered=record(recovered),
                                        byte_for_byte_equal=True, comparison_process='SEPARATE_HARNESS'))
        if fixture['expected'].get('meaning_units'):
            focused = self.command(name + '-focus', self.args.receiver_bundle, recipient,
                                   ['focus', *common, '--unit', 'MEANING'])
            check_focus(focused, view, fixture)
            row['focus'] = 'DECLARED_DEPENDENCIES_AND_SOURCE_EXCERPTS_MATCH'
        else:
            self.command(name + '-focus-untyped', self.args.receiver_bundle, recipient,
                         ['focus', *common, '--unit', 'MEANING'], b'no typed meaning units')
            row['focus'] = 'REFUSED_NO_TYPED_MEANING_UNITS'
        members = set(PAIR) | {identifier + '.recovered' for identifier in fixture['sources']}
        exact_tree(recipient, members)
        row['final_recipient_members'] = sorted(members)

    def negatives(self):
        directory = self.evidence / 'negative'
        controller = self.evidence / 'sender/controller'
        original = read_regular(controller / 'meaning.zip', MAX_PACKAGE)
        changed, mutation = altered_archive(original)
        inputs = {'share.txt': read_regular(controller / 'share.txt', MAX_PACKAGE),
                  'meaning.zip': original, 'changed-value.zip': changed,
                  'swapped.zip': read_regular(self.evidence / 'sender/recipe/meaning.zip', MAX_PACKAGE),
                  'invalid-share.txt': b'INVALID SHARE\n'}
        for filename, data in inputs.items():
            write_new(directory / filename, data, MAX_PACKAGE)
        self.controls['changed-value-input'] = mutation
        tests = [('swapped-archive', 'share.txt', 'swapped.zip'),
                 ('changed-value', 'share.txt', 'changed-value.zip'),
                 ('invalid-share', 'invalid-share.txt', 'meaning.zip'),
                 ('missing-archive', 'share.txt', 'missing.zip')]
        for name, share, archive in tests:
            self.command(name, self.args.receiver_bundle, directory,
                         ['validate', share, '--archive', archive], b'REFUSED:')
        self.command('mismatched-runtime', self.args.mismatched_bundle, directory,
                     ['validate', 'share.txt', '--archive', 'meaning.zip'], b'incompatible decoder dependency identity')

    def finish(self, error):
        unchanged, preserved, failures = {}, {}, []
        for role, before in self.bundles.items():
            try:
                if self.preflight:
                    self.command(role + '-final-check', Path(before['path']), self.evidence, ['check'])
                unchanged[role] = bundle_snapshot(Path(before['path'])) == before
            except (ValueError, OSError, KeyError, TypeError) as failure:
                unchanged[role] = False
                failures.append(str(failure)[:512])
        for path, value in (self.inputs | self.implementation_paths).items():
            try:
                preserved[path] = record(read_regular(Path(path))) == value
            except (ValueError, OSError) as failure:
                preserved[path] = False
                failures.append(str(failure)[:512])
        success = error is None and len(self.comparisons) == len(FIXTURES)
        success = success and len(unchanged) == 3 and all(unchanged.values()) and all(preserved.values())
        success = success and NEGATIVES.issubset(self.controls)
        result = dict(schema='transport/portable-handoff-observation/1', product='Source-Anchored Semantic Transport',
            status='TESTED_SCOPED' if success else 'FAILED', failure=error, final_check_errors=failures,
            caller_argv=sys.orig_argv, python=sys.version, environment=ENVIRONMENT,
            harness=self.implementation['harness'], support=self.implementation['support'],
            layout=self.implementation['layout'], runtime_preflight_completed=self.preflight,
            implementation_files_unchanged={path: preserved[path] for path in self.implementation_paths},
            installations=self.bundles, runtime_comparison=self.runtime, bundles_unchanged=unchanged,
            original_fixture_files=self.inputs,
            original_fixture_files_unchanged={path: preserved[path] for path in self.inputs},
            handoffs=self.comparisons, negative_controls=self.controls, commands=self.commands,
            model_tokens='UNPERFORMED', narrative_fidelity='UNPERFORMED', semantic_completeness='UNPROVEN',
            independent_build_provenance='EXTERNAL_BUILD_RECEIPTS_REQUIRED',
            limits=['Fresh decoder process per operation; no original source or chat supplied to recipient.',
                    'Recipient cwd contains transferred pair and subsequent recovered outputs; no OS sandbox is claimed.',
                    'Same host, user and external runtime; model independence is not established.',
                    'Graph comparison observes declared structure and literals; it does not prove interpretation truth.',
                    'No model/API trial, installation, build, publication or whole-system proof performed.',
                    'Trusted processes assumed not to escape their process group; launcher authentication is external.'])
        write_new(self.evidence / 'receipt.json', canonical(result) + b'\n')
        print(json.dumps(dict(status=result['status'], evidence=str(self.evidence), failure=error)))
        return 0 if success else 1


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for role in ('sender', 'receiver', 'mismatched'):
        parser.add_argument('--' + role + '-bundle', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True, help='New, create-only evidence directory')
    parser.add_argument('--expect-runtime-sha256', required=True, help='Independently held sender/receiver RUNTIME identity')
    args = parser.parse_args()
    require(DIGEST.fullmatch(args.expect_runtime_sha256) is not None, 'expected runtime SHA-256 required')
    for role in ('sender', 'receiver', 'mismatched'):
        setattr(args, role + '_bundle', getattr(args, role + '_bundle').absolute())
    return args


def main():
    campaign = Campaign(arguments())
    error = None
    try:
        for node in ast.walk(ast.parse(read_regular(Path(__file__)).decode())):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                require(node.end_lineno - node.lineno + 1 <= 60, 'function length bound: ' + node.name)
        campaign.setup()
        for name in FIXTURES:
            fixture = campaign.fixture(name)
            campaign.receive(name, fixture, campaign.transfer(name))
        campaign.negatives()
    except (ValueError, OSError, KeyError, TypeError, MemoryError, zipfile.BadZipFile) as failure:
        error = type(failure).__name__ + ': ' + str(failure)[:1024]
    return campaign.finish(error)


if __name__ == '__main__':
    raise SystemExit(main())
