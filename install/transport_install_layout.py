"""Fixed source closure and explicit generated identity substitutions; no semantic migration."""

import json
from pathlib import Path
import re

from transport_install_support import canonical, confined, read_regular, require, sha

CORE_MODULES = ('archive', 'author', 'cli', 'codec', 'codec_cli', 'corpus', 'formula',
                'graph', 'lexicon', 'meaning', 'operators', 'package', 'plan', 'readable',
                'references', 'requirement_language', 'schema', 'semantics', 'source_map',
                'structure', 'wire')
EXTENSIONS = {'transport_authoring.py': 'BASE_RUNTIME_SHA256',
              'transport_export.py': 'BASE_RUNTIME_SHA256', 'transport_mcp.py': 'BASE_RUNTIME',
              'transport_recipient_process.py': 'FROZEN_RUNTIME_SHA256'}
PROFILES = {
    'aarch64': dict(machine=183, interpreter='/lib/ld-linux-aarch64.so.1',
                    libraries=('/lib/ld-linux-aarch64.so.1', '/usr/lib/libc.so.6')),
    'x86_64': dict(machine=62, interpreter='/lib64/ld-linux-x86-64.so.2',
                   libraries=('/usr/lib/ld-linux-x86-64.so.2', '/usr/lib/libc.so.6')),
}
MAX_SOURCE_FILES = 128
MAX_SOURCE_BYTES = 4_194_304
DIGEST = re.compile(r'[0-9a-f]{64}\Z')
ADA_UNITS = ('buffers', 'decoder', 'graph_parse', 'graphs', 'io', 'paths',
             'temporal', 'temporal_format', 'temporal_parse')
BOOTSTRAP = ('transport_install.py', 'transport_install_build.py',
             'transport_install_check.py', 'transport_install_layout.py',
             'transport_install_support.py', 'prepare_source.py', 'launcher.py.in')


def input_names() -> set[str]:
    names = {'tools/transport_' + item + '.py' for item in CORE_MODULES}
    names |= {'tools/' + name for name in EXTENSIONS}
    names |= {'tools/transport_recipient_runner.py', 'transport.gpr', 'LICENSE', 'LICENSE-SCOPE.md'}
    names |= {'src/transport_' + unit + suffix for unit in ADA_UNITS for suffix in ('.ads', '.adb')}
    names |= {'src/transport_native.adb', 'src/transport_types.ads'}
    names |= {'install/' + name for name in BOOTSTRAP}
    return names


def record(name: str, data: bytes) -> dict:
    return dict(path=name, bytes=len(data), sha256=sha(data))


def checked_json(raw: bytes) -> dict:
    require(type(raw) is bytes and len(raw) <= MAX_SOURCE_BYTES, 'manifest byte budget exceeded')
    quoted, escaped, depth = False, False, 0
    for char in raw:
        if quoted:
            if escaped:
                escaped = False
            elif char == 92:
                escaped = True
            elif char == 34:
                quoted = False
        elif char == 34:
            quoted = True
        elif char in (91, 123):
            depth += 1
            require(depth <= 12, 'manifest depth exceeded')
        elif char in (93, 125):
            depth -= 1
            require(depth >= 0, 'malformed manifest')
    require(not quoted and depth == 0, 'truncated manifest')
    value = json.loads(raw, object_pairs_hook=unique)
    require(type(value) is dict, 'manifest object required')
    return value


def unique(pairs: list) -> dict:
    require(len(pairs) <= MAX_SOURCE_FILES and len(dict(pairs)) == len(pairs), 'duplicate or excess manifest fields')
    return dict(pairs)


def source_inputs(root: Path, expected: str) -> tuple[dict, dict]:
    require(type(expected) is str and DIGEST.fullmatch(expected) is not None, 'expected source digest required')
    raw = read_regular(confined(root, 'install/SOURCE.json'))
    require(sha(raw) == expected, 'source manifest does not match independently held digest')
    manifest = checked_json(raw)
    require(set(manifest) == {'schema', 'files', 'excluded', 'product'}, 'source manifest fields invalid')
    require(manifest['schema'] == 'transport/install-source/1', 'source manifest version incompatible')
    require(manifest['excluded'] == ['install/SOURCE.json'], 'source manifest exclusion changed')
    entries = manifest['files']
    require(type(entries) is list and 1 <= len(entries) <= MAX_SOURCE_FILES, 'source file count exceeded')
    files, total = {}, 0
    for item in entries:
        require(type(item) is dict and set(item) == {'path', 'bytes', 'sha256'}, 'invalid source record')
        require(type(item['bytes']) is int and type(item['sha256']) is str, 'invalid source record types')
        path = confined(root, item['path'])
        require(item['path'] not in files, 'duplicate source path')
        data = read_regular(path)
        require(len(data) == item['bytes'] and sha(data) == item['sha256'], 'source changed: ' + item['path'])
        total += len(data)
        require(total <= MAX_SOURCE_BYTES, 'aggregate source budget exceeded')
        files[item['path']] = data
    require(set(files) == input_names(), 'source input closure mismatch')
    return manifest, files


def replace_once(data: bytes, old: bytes, new: bytes) -> bytes:
    require(bool(old) and data.count(old) == 1, 'source identity assignment shape changed')
    return data.replace(old, new, 1)


def assignment(data: bytes, name: str, expected: str, new: str) -> bytes:
    require(DIGEST.fullmatch(expected) is not None and DIGEST.fullmatch(new) is not None, 'invalid generated digest')
    old = (name + " = '" + expected + "'").encode('ascii')
    result = replace_once(data, old, (name + " = '" + new + "'").encode('ascii'))
    require(len(re.findall(rb'^' + name.encode() + rb'\s*=', data, re.M)) == 1,
            'multiple source pin assignments')
    return result


def pin_value(data: bytes, name: str) -> str:
    found = re.findall(rb'^' + name.encode('ascii') + rb" = '([0-9a-f]{64})'$", data, re.M)
    require(len(found) == 1, 'expected source pin assignment missing')
    return found[0].decode('ascii')


def package_source(data: bytes, native_sha: str, architecture: str) -> bytes:
    require(architecture in PROFILES, 'unsupported build architecture')
    result = assignment(data, 'CORE_SHA256', pin_value(data, 'CORE_SHA256'), native_sha)
    if architecture != 'aarch64':
        changes = ((b"platform.machine() == 'aarch64'", b"platform.machine() == 'x86_64'"),
                   (b'requires Linux aarch64', b'requires Linux x86_64'),
                   (b"'platform': 'Linux-aarch64'", b"'platform': 'Linux-x86_64'"),
                   (b"LIBRARIES = ('/lib/ld-linux-aarch64.so.1', '/usr/lib/libc.so.6')",
                    ('LIBRARIES = ' + repr(PROFILES[architecture]['libraries'])).encode('ascii')))
        for old, new in changes:
            result = replace_once(result, old, new)
    return result


def launcher(template: bytes, manifest_sha: str, python: str) -> bytes:
    require(DIGEST.fullmatch(manifest_sha) is not None, 'invalid installation digest')
    require(type(python) is str and re.fullmatch(r'/[A-Za-z0-9_./+-]{1,240}', python) is not None,
            'unsafe Python executable path')
    return replace_once(replace_once(template, b'@MANIFEST@', manifest_sha.encode('ascii')),
                        b'@PYTHON@', python.encode('ascii'))


def generated(files: dict, native: bytes, architecture: str) -> dict:
    result = {name: data for name, data in files.items() if name.startswith('tools/')}
    result['tools/transport_package.py'] = package_source(result['tools/transport_package.py'], sha(native), architecture)
    result['bin/transport_native'] = native
    result['LICENSE'] = files['LICENSE']
    result['LICENSE-SCOPE.md'] = files['LICENSE-SCOPE.md']
    return result


def exact_tree(root: Path, expected: set[str]) -> None:
    pending, found, entries = [(root, '')], set(), 0
    for _ in range(128):
        if not pending:
            break
        directory, prefix = pending.pop()
        for entry in directory.iterdir():
            entries += 1
            require(entries <= 256, 'installed directory entry bound exceeded')
            name = prefix + entry.name
            require(not entry.is_symlink(), 'installed link refused')
            if entry.is_dir():
                require(name.count('/') < 4, 'installed directory depth exceeded')
                require(any(path.startswith(name + '/') for path in expected), 'unexpected installed directory')
                pending.append((entry, name + '/'))
            else:
                require(name in expected and entry.is_file(), 'unexpected installed entry: ' + name)
                found.add(name)
    require(not pending and found == expected, 'installed tree missing files or traversal bound exceeded')
