"""One bounded native build on pinned repository source using a selected trusted toolchain."""

import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import struct
import stat
import sys

from transport_install_layout import PROFILES, record
from transport_install_support import canonical, read_regular, require, run_bounded, sha, write_new

RUNTIME_SCRIPT = ('import sys;sys.path.insert(0,sys.argv[1]);'
                  'import transport_package as p;from transport_schema import canonical;'
                  'sys.stdout.buffer.write(canonical(p.runtime_contract()))')


def tool_identity(path: Path) -> dict:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    digest, total = hashlib.sha256(), 0
    with os.fdopen(descriptor, 'rb') as stream:
        initial = os.fstat(stream.fileno())
        require(stat.S_ISREG(initial.st_mode) and initial.st_size <= 33_554_432,
                'tool executable exceeds regular-file budget')
        for _ in range(2049):
            block = stream.read(16384)
            if not block:
                break
            total += len(block)
            require(total <= 33_554_432, 'tool grew beyond byte budget')
            digest.update(block)
        final = os.fstat(stream.fileno())
        fields = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
        require(all(getattr(initial, field) == getattr(final, field) for field in fields)
                and total == final.st_size, 'tool changed during identity read')
    return dict(path=str(path), bytes=total, sha256=digest.hexdigest())


def command(argv: list[str], cwd: Path, env: dict, receipt: Path, label: str) -> bytes:
    result = run_bounded(argv, cwd, env)
    for stream in ('stdout', 'stderr'):
        data = result.pop(stream)
        write_new(receipt / (label + '.' + stream), data)
        result[stream] = record(label + '.' + stream, data)
    result['environment'] = env
    write_new(receipt / (label + '.json'), canonical(result))
    require(result['status'] == 'SUCCESS', 'command refused: ' + label + ': ' + result['status'])
    return read_regular(receipt / (label + '.stdout'))


def selected_tools(gprbuild: Path, compiler_bin: Path) -> tuple[dict, dict]:
    require(gprbuild.is_absolute() and compiler_bin.is_absolute(), 'absolute toolchain paths required')
    selected = {'gprbuild': gprbuild.resolve(strict=True)}
    for name in ('gcc', 'gnatbind', 'gnatlink', 'readelf'):
        selected[name] = (compiler_bin / name).resolve(strict=True)
    for path in selected.values():
        tool_identity(path)
        require(os.access(path, os.X_OK), 'selected tool is not executable')
    directories = (str(gprbuild.parent), str(compiler_bin), '/usr/bin', '/bin')
    require(all(':' not in item for item in directories), 'ambiguous tool search path')
    env = dict(PATH=':'.join(directories), LANG='C', LC_ALL='C', TZ='UTC',
               PYTHONDONTWRITEBYTECODE='1', SOURCE_DATE_EPOCH='0')
    for name, path in selected.items():
        resolved = shutil.which(name, path=env['PATH'])
        require(resolved is not None and Path(resolved).resolve() == path, 'tool search resolution mismatch')
    return selected, env


def tool_receipt(tools: dict, env: dict, cwd: Path, receipt: Path) -> dict:
    identities = {}
    for name, path in tools.items():
        version = command([str(path), '--version'], cwd, env, receipt, name + '-version')
        identities[name] = dict(tool_identity(path), version=version.decode('utf-8', 'strict'))
    machine = command([str(tools['gcc']), '-dumpmachine'], cwd, env, receipt, 'gcc-machine').strip().decode('ascii')
    require(machine.startswith(platform.machine() + '-'), 'compiler target differs from build host')
    return dict(drivers=identities, target=machine,
                boundary='Selected drivers hashed; complete compiler and standard-library closure trusted, not authenticated')


def copy_build_inputs(files: dict, scratch: Path) -> None:
    (scratch / 'src').mkdir(mode=0o700)
    for name, data in files.items():
        if name.startswith('src/') or name == 'transport.gpr':
            write_new(scratch / name, data)


def compile_native(files: dict, scratch: Path, tools: dict, env: dict, receipt: Path) -> bytes:
    copy_build_inputs(files, scratch)
    mapped = str(scratch) + '=/source/source-anchored-semantic-transport'
    args = [str(tools['gprbuild']), '-q', '-p', '-R', '-P', 'transport.gpr', '-j1',
            '-cargs:Ada', '-fdebug-prefix-map=' + mapped, '-ffile-prefix-map=' + mapped]
    command(args, scratch, env, receipt, 'compile')
    return read_regular(scratch / 'bin/transport_native')


def elf_closure(native: bytes, path: Path, tools: dict, env: dict, receipt: Path) -> dict:
    profile = PROFILES[platform.machine()]
    require(len(native) >= 64 and native[:6] == b'\x7fELF\x02\x01', 'ELF64 little-endian binary required')
    require(struct.unpack_from('<H', native, 18)[0] == profile['machine'], 'ELF machine mismatch')
    headers = command([str(tools['readelf']), '-lW', str(path)], path.parent, env, receipt, 'elf-programs')
    dynamic = command([str(tools['readelf']), '-dW', str(path)], path.parent, env, receipt, 'elf-dynamic')
    interpreters = re.findall(rb'Requesting program interpreter: ([^\]]+)\]', headers)
    require(interpreters == [profile['interpreter'].encode('ascii')], 'unexpected ELF interpreter')
    require(b'(RPATH)' not in dynamic and b'(RUNPATH)' not in dynamic, 'ELF search paths refused')
    needed = re.findall(rb'\(NEEDED\)[^\n]*Shared library: \[([^\]]+)\]', dynamic)
    allowed = {Path(name).name.encode('ascii') for name in profile['libraries']}
    require(len(needed) == len(set(needed)) and b'libc.so.6' in needed and set(needed) <= allowed,
            'undeclared ELF dynamic dependency')
    return dict(native_sha256=sha(native), interpreter=profile['interpreter'],
                needed=[name.decode('ascii') for name in needed], search_paths='ABSENT',
                boundary='Static ELF dependencies only; trusted loader environment and operating system remain outside proof')


def runtime_bytes(stage: Path, env: dict, receipt: Path, label: str) -> bytes:
    return command([sys.executable, '-I', '-S', '-B', '-Werror', '-c', RUNTIME_SCRIPT,
                    str(stage / 'tools')], stage, env, receipt, label)
