"""Fixed local recipient protocol for Source-Anchored Semantic Transport."""

import argparse
import base64
import binascii
import fcntl
import os
import re
import resource
import signal
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import transport_recipient_process as process

MAX_CALLS = 32
MAX_LEDGER = 33_554_432
RESERVE = 4_194_304
MAX_FILES = 512
FILE_CAP = 4_194_304
HANDOFF_CAP = 16_777_216
LAUNCHER_WALL_SECONDS = 30
PAGE_BYTES = 4096
MAX_PAGES = 17
PAGE_RESPONSE_CAP = 32768
DOMAIN = re.compile(r'[A-Za-z][A-Za-z0-9_-]{0,47}\Z')
SOURCE = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
ROOT = Path(__file__).resolve().parent


def require(condition: bool, message: str) -> None:
    process.require(condition, message)


def arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--handoff', type=Path, required=True)
    parser.add_argument('--session', type=Path, required=True)
    parser.add_argument('--profile', choices=('full', 'paged'), default='full')
    actions = parser.add_subparsers(dest='action', required=True)
    actions.add_parser('describe')
    for name in ('inspect', 'validate', 'recover', 'view', 'page'):
        action = actions.add_parser(name)
        action.add_argument('domain')
        if name in ('recover', 'view', 'page'):
            action.add_argument('source')
        if name == 'page':
            action.add_argument('page_index')
    finish = actions.add_parser('finish')
    finish.add_argument('--data-base64')
    return parser.parse_args()


def json_read(path: Path) -> object:
    data = process.read(path, 1_048_576)
    value = process.json_value(data, 1_048_576)
    require(data == process.canonical(value), 'noncanonical or changed log JSON')
    return value


def json_write(path: Path, value: object) -> None:
    process.write(path, process.canonical(value), 1_048_576)


def inventory(root: Path, cap: int, count: int) -> list:
    require(root.is_dir() and not root.is_symlink(), 'regular directory required')
    result, size = [], 0
    for number, path in enumerate(root.rglob('*')):
        require(number < count * 2 and len(path.relative_to(root).parts) <= 8,
                'inventory directory/depth budget exceeded')
        require(not path.is_symlink(), 'symbolic links are unsupported')
        require(path.is_dir() or path.is_file(), 'special files are unsupported')
        if path.is_file():
            require(len(result) < count, 'inventory file count budget exceeded')
            data = process.read(path, FILE_CAP)
            size += len(data)
            require(size <= cap, 'aggregate stored byte budget exceeded')
            result.append({'path': str(path.relative_to(root)), 'bytes': len(data),
                           'sha256': process.sha(data)})
    return sorted(result, key=lambda item: item['path'])


def trusted_helpers() -> list:
    result = []
    for name in ('transport_recipient_runner.py', 'transport_recipient_process.py'):
        data = process.read(ROOT / name)
        result.append({'path': str(ROOT / name), 'bytes': len(data), 'sha256': process.sha(data),
                       'source_base64': base64.b64encode(data).decode('ascii')})
    executable = Path(sys.executable).resolve(strict=True)
    data = process.read(executable, FILE_CAP)
    result.append({'path': str(executable), 'bytes': len(data), 'sha256': process.sha(data)})
    return result


def handoff_identity(handoff: Path) -> dict:
    files = inventory(handoff, HANDOFF_CAP, 64)
    runtime = process.compatibility_runtime(handoff / 'decoder/tools')
    expected = {'decoder/RUNTIME.json'}
    for item in runtime['files']:
        expected.add('decoder/' + item['path'])
    domains = []
    for path in (handoff / 'inputs').iterdir():
        require(len(domains) < 16 and path.is_dir(), 'domain directory count exceeded')
        domains.append(path.name)
    domains.sort()
    require(1 <= len(domains) <= 16 and all(DOMAIN.fullmatch(name) for name in domains), 'invalid domain set')
    for name in domains:
        expected.update('inputs/' + name + '/' + leaf for leaf in ('share.txt', 'meaning.zip'))
    require({item['path'] for item in files} == expected, 'handoff must contain only decoder and matched pairs')
    return {'files': files, 'domains': domains, 'runtime': runtime}


def initialized(args: argparse.Namespace) -> tuple[Path, dict]:
    require(not args.handoff.is_symlink(), 'handoff root symbolic link is unsupported')
    handoff = args.handoff.resolve(strict=True)
    require(not args.session.is_symlink(), 'session root symbolic link is unsupported')
    session = args.session.resolve(strict=False)
    require(not session.is_relative_to(handoff) and not handoff.is_relative_to(session),
            'session must be outside and not contain handoff')
    identity = {'schema': 'transport/recipient-session/1', 'handoff': str(handoff),
                'profile': args.profile,
                'handoff_identity': handoff_identity(handoff), 'trusted_helpers': trusted_helpers(),
                'maximum_invocations': MAX_CALLS, 'maximum_stored_bytes': MAX_LEDGER,
                'launcher_limits': {'wall_seconds': LAUNCHER_WALL_SECONDS, 'address_bytes': 402_653_184,
                                    'cpu_seconds': 60, 'open_files': 64, 'file_bytes': 1_048_576},
                'boundary': 'Controlled subprocess protocol only; tool host and agent are not OS sandboxed.'}
    if not session.exists():
        require(args.action == 'describe', 'new session must begin with describe')
        session.mkdir(mode=0o700)
        for name in ('actions', 'recovered', 'metadata', 'home', 'tmp'):
            (session / name).mkdir(mode=0o700)
        json_write(session / 'SESSION.json', identity)
    require(json_read(session / 'SESSION.json') == identity, 'session handoff or helper identity mismatch')
    return session, identity


def artifact_inventory(session: Path) -> list:
    result = inventory(session / 'recovered', MAX_LEDGER, MAX_FILES)
    result = [dict(item, path='recovered/' + item['path']) for item in result]
    if (session / 'candidate.json').exists():
        data = process.read(session / 'candidate.json', process.REQUEST_CAP)
        result.append({'path': 'candidate.json', 'bytes': len(data), 'sha256': process.sha(data)})
    return sorted(result, key=lambda item: item['path'])


def verify_session(session: Path, expected_head: str | None = None) -> dict:
    require(not (session / 'TERMINAL_TIMEOUT.json').exists(), 'launcher timeout closed this session')
    files = inventory(session, MAX_LEDGER, MAX_FILES)
    directories = sorted((session / 'actions').iterdir())
    require(len(directories) <= MAX_CALLS, 'recipient invocation budget exhausted')
    previous = process.sha(process.read(session / 'SESSION.json', 1_048_576))
    identity, coverage = json_read(session / 'SESSION.json'), {}
    artifacts = []
    terminal_failure = False
    expected = {'SESSION.json', 'LOCK'}
    for number, directory in enumerate(directories, 1):
        require(directory.name == format(number, '04d') and directory.is_dir(), 'noncontiguous action log')
        record = json_read(directory / 'record.json')
        require(record['sequence'] == number and record['previous_sha256'] == previous, 'action hash chain mismatch')
        verify_action_members(directory, record)
        for key, filename in (('request_sha256', 'request.json'), ('stdin_sha256', 'stdin.bin'),
                              ('response_sha256', 'response.bin')):
            require(record[key] == process.sha(process.read(directory / filename, 1_048_576)), 'action log hash mismatch')
        request = json_read(directory / 'request.json')
        require(request.get('profile', 'full') == identity.get('profile', 'full'), 'action profile identity mismatch')
        for child in record['children']:
            verify_child(directory, child)
        verify_child_commands(session, identity, request, directory, record)
        verify_page_record(session, identity, request, directory, record, coverage)
        expected.update('actions/' + directory.name + '/' + name for name in action_files(record))
        for item in record['artifacts']:
            path = Path(item['path'])
            require(not path.is_absolute() and '..' not in path.parts
                    and (path.parts[0] == 'recovered' or str(path) == 'candidate.json'), 'unsafe artifact log path')
            data = process.read(session / item['path'], FILE_CAP)
            require(len(data) == item['bytes'] and process.sha(data) == item['sha256'], 'artifact hash mismatch')
        if identity.get('profile', 'full') == 'paged' and request['action'] == 'finish' and record['launcher_exit'] == 0:
            require_page_coverage(session, coverage, record['artifacts'])
        artifacts = record['artifacts']
        terminal_failure = terminal_failure or record['launcher_wall_timeout'] or not request['stdin_complete']
        previous = process.sha(process.read(directory / 'record.json', 1_048_576))
    require(artifacts == artifact_inventory(session), 'unlogged or changed recipient artifact')
    expected.update(item['path'] for item in artifacts)
    require({item['path'] for item in files} == expected, 'unexpected or missing session log file')
    require(expected_head is None or previous == expected_head, 'sealed external head mismatch')
    return {'actions': len(directories), 'head_sha256': previous,
            'stored_bytes': sum(item['bytes'] for item in files), 'terminal_failure': terminal_failure,
            'page_coverage': coverage}


def action_files(record: dict) -> set:
    result = {'request.json', 'stdin.bin', 'response.bin', 'record.json'}
    for child in record['children']:
        require(re.fullmatch(r'child-[0-9]{2}', child['directory']), 'invalid child log directory')
        result.update(child['directory'] + '/' + name for name in ('request.json', 'stdout.bin', 'stderr.bin', 'result.json'))
    return result


def verify_action_members(directory: Path, record: dict) -> None:
    children = {item['directory'] for item in record['children']}
    require(len(children) == len(record['children']) <= 2, 'duplicate or excess action child directory')
    require(children == {'child-' + format(index, '02d') for index in range(1, len(children) + 1)},
            'noncontiguous child log directories')
    expected = {'request.json', 'stdin.bin', 'response.bin', 'record.json'}
    observed = set()
    for number, path in enumerate(directory.iterdir()):
        require(number < 6, 'action directory entry budget exceeded')
        require(not path.is_symlink(), 'action symlink is unsupported')
        require((path.name in expected and path.is_file())
                or (path.name in children and path.is_dir()), 'unexpected action entry or orphan child directory')
        observed.add(path.name)
    require(observed == expected | children, 'missing action file or child directory')
    for name in children:
        require(re.fullmatch(r'child-[0-9]{2}', name), 'invalid child log directory')
        observed = set()
        for number, path in enumerate((directory / name).iterdir()):
            require(number < 4 and path.is_file() and not path.is_symlink(), 'unexpected nested child entry')
            observed.add(path.name)
        require(observed == {'request.json', 'stdout.bin', 'stderr.bin', 'result.json'},
                'incomplete or unexpected child log membership')


def check_chain(session: Path, details: dict | None = None) -> tuple[int, str]:
    value = verify_session(session)
    require(not value['terminal_failure'], 'prior timeout or incomplete request closed this session')
    require(value['actions'] < MAX_CALLS, 'recipient invocation budget exhausted')
    require(value['stored_bytes'] + RESERVE <= MAX_LEDGER, 'ledger storage reserve exhausted')
    if details is not None:
        details.update(value)
    return value['actions'] + 1, value['head_sha256']


def verify_child(directory: Path, child: dict) -> None:
    target = directory / child['directory']
    result_data = process.read(target / 'result.json', 1_048_576)
    require(process.sha(result_data) == child['sha256'], 'child result hash mismatch')
    result = process.json_value(result_data, 1_048_576)
    request = json_read(target / 'request.json')
    for key in ('argv', 'cwd', 'env', 'stdin_base64', 'stdin_bytes', 'limits'):
        require(result[key] == request[key], 'child invocation metadata mismatch')
    for stream in ('stdout', 'stderr'):
        data = process.read(target / (stream + '.bin'))
        require(process.sha(data) == result[stream + '_sha256'] and len(data) == result[stream + '_bytes'],
                'child stream log mismatch')


def child_command(handoff: Path, domain: str, action: str, source: str | None,
                  output: Path | None) -> list:
    pair = handoff / 'inputs' / domain
    command = [str(Path(sys.executable).resolve()), '-I', '-S', '-B', '-Werror',
               str(ROOT / 'transport_recipient_process.py'), '--child', str(handoff / 'decoder/tools'),
               action, str(pair / 'share.txt')]
    if output is not None:
        command.append(str(output))
    command += ['--archive', str(pair / 'meaning.zip')]
    if output is not None:
        command += ['--source', source]
    return command


def verify_child_commands(session: Path, identity: dict, request: dict, directory: Path, record: dict) -> None:
    actions = {'inspect': ['inspect'], 'validate': ['validate'], 'recover': ['inspect', 'recover']}
    expected = actions.get(request['action'], [])
    require(len(record['children']) <= len(expected), 'unexpected decoder child')
    require(record['launcher_exit'] != 0 or len(record['children']) == len(expected), 'missing successful decoder child')
    for number, child in enumerate(record['children']):
        action = expected[number]
        output = session / 'recovered' / request['domain'] / (request['source'] + '.bin') if action == 'recover' else None
        command = child_command(Path(identity['handoff']), request['domain'], action, request['source'], output)
        child_request = json_read(directory / child['directory'] / 'request.json')
        require(child_request['argv'] == command and child_request['cwd'] == str(session)
                and child_request['env'] == environment(session), 'undeclared child invocation')


def environment(session: Path) -> dict:
    return {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
            'HOME': str(session / 'home'), 'TMPDIR': str(session / 'tmp')}


def child_action(args: argparse.Namespace, session: Path, directory: Path,
                 children: list, action: str, output: Path | None = None) -> dict:
    target = directory / ('child-' + format(len(children) + 1, '02d'))
    target.mkdir()
    command = child_command(args.handoff.resolve(strict=True), args.domain, action, getattr(args, 'source', None), output)
    json_write(target / 'request.json', {'argv': command, 'cwd': str(session), 'env': environment(session),
               'stdin_base64': '', 'stdin_bytes': 0,
               'limits': dict(process.LIMITS, wall_seconds=process.WALL_SECONDS)})
    result = process.run_process(command, session, environment(session), target)
    json_write(target / 'result.json', result)
    children.append({'directory': target.name, 'sha256': process.sha(process.read(target / 'result.json', 1_048_576))})
    require(result['capture_accepted'], 'decoder child refused or exceeded process budget')
    return process.json_value(base64.b64decode(result['stdout_base64']))


def metadata(args: argparse.Namespace, session: Path, directory: Path, children: list) -> dict:
    value = child_action(args, session, directory, children, 'inspect')
    require(type(value) is dict and type(value.get('sources')) is list, 'invalid checked metadata')
    return value


def selected(value: dict, name: str) -> dict:
    matches = [item for item in value['sources'] if item['id'] == name]
    require(len(matches) == 1, 'unknown or ambiguous package/source identity')
    return matches[0]


def recover(args: argparse.Namespace, session: Path, directory: Path, children: list) -> dict:
    value = metadata(args, session, directory, children)
    source = selected(value, args.source)
    destination = session / 'recovered' / args.domain
    destination.mkdir(exist_ok=True)
    output = destination / (args.source + '.bin')
    require(not output.exists(), 'recovered source already exists')
    child_action(args, session, directory, children, 'recover', output)
    data = process.read(output, process.REQUEST_CAP)
    require(len(data) == source['bytes'] and process.sha(data) == source['sha256'], 'recovered byte identity mismatch')
    binding = {'domain': args.domain, 'source': args.source, 'source_metadata': source,
               'metadata': value, 'path': str(output.relative_to(session)), 'bytes': len(data), 'sha256': process.sha(data)}
    json_write(destination / (args.source + '.json'), binding)
    return {'status': 'RECOVERED_CHECKED_BYTES', 'domain': args.domain, 'source': args.source,
            'bytes': len(data), 'sha256': process.sha(data), 'path': str(output.relative_to(session))}


def recovered_source(session: Path, domain: str, name: str) -> tuple[dict, dict, bytes]:
    require(DOMAIN.fullmatch(domain) and SOURCE.fullmatch(name), 'invalid recovery identity')
    directory = session / 'recovered' / domain
    binding = json_read(directory / (name + '.json'))
    require(binding['domain'] == domain and binding['source'] == name, 'recovery binding mismatch')
    source = selected(binding['metadata'], name)
    data = process.read(directory / (name + '.bin'), process.REQUEST_CAP)
    require(len(data) == source['bytes'] and process.sha(data) == source['sha256'], 'view byte identity mismatch')
    return binding, source, data


def view(args: argparse.Namespace, session: Path) -> dict:
    binding, source, data = recovered_source(session, args.domain, args.source)
    result = {'domain': args.domain, 'source': args.source, 'source_metadata': source,
              'checked_metadata': binding['metadata'], 'opaque': True}
    if source['media_type'].lower().startswith('text/'):
        try:
            result['text'] = data.decode('utf-8', errors='strict')
            result['opaque'] = False
        except UnicodeError:
            result['reason'] = 'Declared text is not valid UTF-8; retained opaque.'
    return result


def page_spans(data: bytes) -> list:
    require(type(data) is bytes and len(data) <= process.REQUEST_CAP, 'page source byte bound exceeded')
    data.decode('utf-8', errors='strict')
    if not data:
        return [[0, 0]]
    result, begin = [], 0
    for _ in range(MAX_PAGES):
        end = min(begin + PAGE_BYTES, len(data))
        for _ in range(3):
            if end == len(data) or data[end] & 0xc0 != 0x80:
                break
            end -= 1
        require(begin < end and (end == len(data) or data[end] & 0xc0 != 0x80), 'UTF-8 page boundary failure')
        result.append([begin, end])
        if end == len(data):
            return result
        begin = end
    raise ValueError('finite page count bound exceeded')


def page_value(session: Path, domain: str, name: str, index: int) -> dict:
    binding, source, data = recovered_source(session, domain, name)
    require(source['media_type'].lower().startswith('text/'), 'binary source remains opaque; text pages unavailable')
    spans = page_spans(data)
    require(type(index) is int and 0 <= index < len(spans), 'page index outside source')
    begin, end = spans[index]
    part = data[begin:end]
    result = dict(status='SOURCE_PAGE', domain=domain, source=name, package_identity=binding['metadata']['identity'],
        source_identity={key: source[key] for key in ('bytes', 'sha256', 'media_type')},
        page_index=index, total_pages=len(spans), span=[begin, end], slice_sha256=process.sha(part),
        text=part.decode('utf-8', errors='strict'), more=index + 1 < len(spans), execution_authority='NONE')
    require(len(process.canonical(result)) + 1 <= PAGE_RESPONSE_CAP, 'serialized page response byte budget exceeded')
    return result


def verify_page_record(session: Path, identity: dict, request: dict, directory: Path,
                       record: dict, coverage: dict) -> None:
    if request['action'] != 'page' or record['launcher_exit'] != 0:
        return
    require(identity.get('profile', 'full') == 'paged', 'page outside paged profile')
    domain, source, index = request['domain'], request['source'], request['page_index']
    key = domain + ':' + source
    require(type(index) is int and index == coverage.get(key, 0), 'page log sequence is not contiguous')
    expected = page_value(session, domain, source, index)
    response = process.read(directory / 'response.bin')
    require(response == process.canonical(expected) + b'\n', 'page response identity, interval or source bytes mismatch')
    coverage[key] = index + 1


def page(args: argparse.Namespace, session: Path) -> dict:
    require(type(args.page_index) is str and re.fullmatch(r'(?:0|[1-9][0-9]?)', args.page_index),
            'page index must be canonical ASCII decimal')
    index = int(args.page_index)
    require(index == args.page_coverage.get(args.domain + ':' + args.source, 0), 'page request must be next contiguous index')
    return page_value(session, args.domain, args.source, index)


def require_page_coverage(session: Path, coverage: dict, artifacts: list) -> None:
    identities = {'.json': set(), '.bin': set()}
    for item in artifacts:
        path = Path(item['path'])
        if path.parts[0] != 'recovered':
            continue
        path = Path(*path.parts[1:])
        require(len(path.parts) == 2 and path.suffix in identities, 'unexpected recovered source binding path')
        identities[path.suffix].add((path.parts[0], path.stem))
    require(bool(identities['.json']) and identities['.json'] == identities['.bin'],
            'paged finish requires checked recovered source bindings')
    for domain, source in sorted(identities['.json']):
        _, metadata, data = recovered_source(session, domain, source)
        require(metadata['media_type'].lower().startswith('text/'), 'paged finish cannot claim binary source coverage')
        pages = page_spans(data)
        require(coverage.get(domain + ':' + source, 0) == len(pages), 'paged finish requires complete source byte coverage')


def finish_coverage(args: argparse.Namespace, session: Path) -> None:
    if args.profile == 'paged':
        require_page_coverage(session, args.page_coverage, artifact_inventory(session))


def finish(args: argparse.Namespace, session: Path, stdin: bytes) -> dict:
    finish_coverage(args, session)
    data = stdin
    if args.data_base64 is not None:
        require(not stdin and len(args.data_base64) <= 87_384, 'finish base64 or stdin budget exceeded')
        data = base64.b64decode(args.data_base64, validate=True)
        require(base64.b64encode(data).decode('ascii') == args.data_base64, 'noncanonical base64 request')
    value = process.json_value(data, process.REQUEST_CAP)
    require(type(value) is dict and set(value) == {'schema', 'narrative'}, 'closed narrative fields required')
    require(value['schema'] == 'transport/recipient-narrative/1' and type(value['narrative']) is str,
            'invalid narrative schema or text')
    value['narrative'].encode('utf-8', errors='strict')
    process.write(session / 'candidate.json', data, process.REQUEST_CAP)
    return {'status': 'FIRST_CANDIDATE_RECORDED', 'bytes': len(data), 'sha256': process.sha(data),
            'narrative_status': 'UNVERIFIED_RECIPIENT_DATA'}


def dispatch(args: argparse.Namespace, session: Path, identity: dict, directory: Path,
             children: list, stdin: bytes) -> dict:
    if args.action == 'describe':
        return {'name': 'Source-Anchored Semantic Transport', 'domains': identity['handoff_identity']['domains'],
                'commands': ['describe', 'inspect DOMAIN', 'validate DOMAIN', 'recover DOMAIN SOURCE',
                             'view DOMAIN SOURCE', 'page DOMAIN SOURCE PAGE_INDEX', 'finish --data-base64 DATA'],
                'profile': args.profile, 'page_bytes': PAGE_BYTES, 'page_response_bytes': PAGE_RESPONSE_CAP,
                'maximum_invocations': MAX_CALLS, 'maximum_stored_bytes': MAX_LEDGER,
                'finish_schema': {'schema': 'transport/recipient-narrative/1', 'narrative': 'STRING'},
                'boundary': identity['boundary']}
    if args.action == 'finish':
        return finish(args, session, stdin)
    require(DOMAIN.fullmatch(args.domain) and args.domain in identity['handoff_identity']['domains'], 'unknown domain')
    if args.action in ('recover', 'view', 'page'):
        require(SOURCE.fullmatch(args.source), 'invalid source identifier')
    if args.action in ('inspect', 'validate'):
        return child_action(args, session, directory, children, args.action)
    if args.action == 'recover':
        return recover(args, session, directory, children)
    if args.action == 'page':
        require(args.profile == 'paged', 'page requires explicit paged profile')
        return page(args, session)
    require(args.profile == 'full', 'full view is unavailable in paged profile')
    return view(args, session)


def invocation(args: argparse.Namespace, session: Path, identity: dict) -> tuple[bytes, int]:
    details = {}
    number, previous = check_chain(session, details)
    args.page_coverage = details['page_coverage']
    directory = session / 'actions' / format(number, '04d')
    directory.mkdir()
    started, children = time.perf_counter_ns(), []
    stdin_error = ''
    try:
        stdin = process.stdin_bytes(process.REQUEST_CAP if args.action == 'finish' else 0)
    except process.RequestError as error:
        stdin, stdin_error = error.data, str(error)
    process.write(directory / 'stdin.bin', stdin, process.REQUEST_CAP + 1)
    request = {'argv': sys.orig_argv, 'parsed_argv': sys.argv, 'cwd': str(Path.cwd()), 'stdin_base64': base64.b64encode(stdin).decode('ascii'),
               'launcher_start_ns': args.launcher_start_ns, 'launcher_deadline_ns': args.launcher_deadline_ns,
               'stdin_bytes': len(stdin), 'action': args.action, 'trusted_helpers': identity['trusted_helpers'],
               'domain': getattr(args, 'domain', None), 'source': getattr(args, 'source', None),
               'profile': args.profile, 'page_index': int(args.page_index) if args.action == 'page' and
               re.fullmatch(r'(?:0|[1-9][0-9]?)', args.page_index) else None,
               'stdin_complete': not stdin_error, 'stdin_error': stdin_error,
               'child_environment_policy': environment(session)}
    json_write(directory / 'request.json', request)
    wall_timeout = False
    try:
        require(not stdin_error, 'incomplete or over-budget request: ' + stdin_error)
        require(args.action == 'finish' or not stdin, 'stdin is data for finish only')
        response, code = dispatch(args, session, identity, directory, children, stdin), 0
    except (ValueError, OSError, MemoryError, UnicodeError, binascii.Error, KeyError, TypeError, IndexError) as error:
        wall_timeout = isinstance(error, TimeoutError)
        response, code = {'status': 'REFUSED', 'reason': str(error)[:512]}, 1
    data = process.canonical(response) + b'\n'
    process.write(directory / 'response.bin', data)
    record = {'schema': 'transport/recipient-action/1', 'sequence': number, 'previous_sha256': previous,
              'request_sha256': process.sha(process.read(directory / 'request.json', 1_048_576)),
              'stdin_sha256': process.sha(stdin), 'response_sha256': process.sha(data), 'children': children,
              'artifacts': artifact_inventory(session),
              'launcher_wall_timeout': wall_timeout,
              'launcher_exit': code, 'launcher_stderr_base64': '', 'latency_ns': time.perf_counter_ns() - started}
    json_write(directory / 'record.json', record)
    inventory(session, MAX_LEDGER, MAX_FILES)
    return data, code


def main() -> int:
    started = time.monotonic_ns()
    try:
        signal.signal(signal.SIGALRM, launcher_timeout)
        signal.setitimer(signal.ITIMER_REAL, LAUNCHER_WALL_SECONDS)
        resource.setrlimit(resource.RLIMIT_AS, (402_653_184,) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1_048_576,) * 2)
        args = arguments()
        args.launcher_start_ns = started
        args.launcher_deadline_ns = started + int(LAUNCHER_WALL_SECONDS * 1_000_000_000)
        session, identity = initialized(args)
        descriptor = os.open(session / 'LOCK', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, 'rb') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            data, code = invocation(args, session, identity)
        sys.stdout.buffer.write(data)
        return code
    except (ValueError, OSError, MemoryError, UnicodeError, KeyError, TypeError, IndexError) as error:
        marker = 'NOT_REQUIRED'
        if isinstance(error, TimeoutError) and 'session' in locals():
            marker = mark_terminal_timeout(session, started)
        sys.stdout.buffer.write(process.canonical({'status': 'PROTOCOL_BOUNDARY_REFUSAL', 'reason': str(error)[:512],
            'launcher_start_ns': started, 'launcher_wall_timeout': isinstance(error, TimeoutError),
            'terminal_marker': marker}) + b'\n')
        return 1
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)


def launcher_timeout(signum: int, frame: object) -> None:
    raise TimeoutError('launcher wall deadline exceeded')


def mark_terminal_timeout(session: Path, started: int) -> str:
    try:
        json_write(session / 'TERMINAL_TIMEOUT.json', {'reason': 'launcher wall deadline exceeded',
                                                     'launcher_start_ns': started})
        return 'WRITTEN'
    except OSError as error:
        return 'WRITE_FAILED: ' + str(error)[:256]


if __name__ == '__main__':
    sys.exit(main())
