"""Reconstruct installed bytes from fixed sources and a declared native build identity."""

import os
from pathlib import Path
import platform
import stat
import sys

from transport_install_build import runtime_bytes
from transport_install_layout import (EXTENSIONS, PROFILES, assignment, checked_json, exact_tree,
                                      generated, launcher, pin_value, record)
from transport_install_support import canonical, confined, read_regular, require, sha, write_new


def external_records(python: str) -> list[dict]:
    profile = PROFILES[platform.machine()]
    require(Path(profile['interpreter']).resolve(strict=True) == Path(profile['libraries'][0]).resolve(strict=True),
            'declared loader does not resolve to ELF interpreter')
    names = [python, *profile['libraries']]
    result = []
    for name in names:
        resolved = Path(name).resolve(strict=True)
        result.append(dict(record(str(resolved), read_regular(resolved)), declared_path=name))
    return result


def manifest_bytes(contents: dict, source_sha: str, python: str) -> bytes:
    return canonical(dict(schema='transport/install/1', product='Source-Anchored Semantic Transport',
                          source_manifest_sha256=source_sha, architecture=platform.machine(), python=python,
                          files=[record(name, contents[name]) for name in sorted(contents)],
                          external=external_records(python), authentication='NOT_PROVIDED',
                          assurance='Build-specific identities checked; semantic completeness and compiler correctness unproved',
                          trusted_external='Python standard library, transitive runtime libraries, operating system and selected toolchain; MCP additionally trusts system site hooks and installed SDK contents, gated by versions only'))


def pin_extensions(contents: dict, runtime: bytes) -> dict:
    result = dict(contents, **{'RUNTIME.json': runtime})
    for filename, constant in EXTENSIONS.items():
        name = 'tools/' + filename
        result[name] = assignment(result[name], constant, pin_value(result[name], constant), sha(runtime))
    return result


def write_contents(stage: Path, contents: dict) -> None:
    require(len(contents) <= 128, 'installed file count exceeded')
    for name, data in contents.items():
        target = stage / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_new(confined(stage, name), data)
        if name.startswith('bin/'):
            target.chmod(0o700)


def assert_contents(root: Path, contents: dict) -> None:
    for name, data in contents.items():
        path = confined(root, name)
        require(read_regular(path) == data, 'generated contents changed: ' + name)
        mode = 0o700 if name.startswith('bin/') else 0o600
        require(stat.S_IMODE(path.stat().st_mode) == mode, 'installed file mode changed: ' + name)


def complete_stage(stage: Path, files: dict, native: bytes, source_sha: str,
                   env: dict, receipt: Path) -> str:
    initial = generated(files, native, platform.machine())
    # Execute only the already compared source-derived base before extension pinning.
    write_contents(stage, initial)
    assert_contents(stage, initial)
    runtime = runtime_bytes(stage, env, receipt, 'runtime-generate')
    contents = pin_extensions(initial, runtime)
    for name in EXTENSIONS:
        (stage / 'tools' / name).unlink()
        write_new(stage / 'tools' / name, contents['tools/' + name])
    write_new(stage / 'RUNTIME.json', runtime)
    python = str(Path(sys.executable).resolve(strict=True))
    manifest = manifest_bytes(contents, source_sha, python)
    write_new(stage / 'INSTALL.json', manifest)
    script = launcher(files['install/launcher.py.in'], sha(manifest), python)
    write_new(stage / 'bin/semantic-transport', script)
    (stage / 'bin/semantic-transport').chmod(0o700)
    return sha(manifest)


def verify_install(root: Path, files: dict, source_sha: str, expected: str,
                   env: dict, receipt: Path) -> dict:
    raw = read_regular(confined(root, 'INSTALL.json'))
    require(sha(raw) == expected, 'installation manifest differs from held identity')
    manifest = checked_json(raw)
    require(manifest['source_manifest_sha256'] == source_sha, 'installed source identity mismatch')
    native = read_regular(confined(root, 'bin/transport_native'))
    initial = generated(files, native, platform.machine())
    runtime = read_regular(confined(root, 'RUNTIME.json'))
    contents = pin_extensions(initial, runtime)
    python = str(Path(sys.executable).resolve(strict=True))
    require(raw == manifest_bytes(contents, source_sha, python), 'installation manifest regeneration mismatch')
    contents['INSTALL.json'] = raw
    contents['bin/semantic-transport'] = launcher(files['install/launcher.py.in'], expected, python)
    exact_tree(root, set(contents))
    assert_contents(root, contents)
    require(runtime == runtime_bytes(root, env, receipt, 'runtime-check'), 'base runtime regeneration mismatch')
    return dict(status='INSTALLATION_RECONSTRUCTION_CHECKED', manifest_sha256=expected,
                source_manifest_sha256=source_sha, native_sha256=sha(native),
                authentication='NOT_PROVIDED', semantic_completeness='UNPROVEN',
                scope='Exact generated files and current declared dependency identities; does not recompile native binary')
