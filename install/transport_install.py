#!/usr/bin/env python3
"""Build or check a private, exact runtime bundle; no root, network or service installation."""

import argparse
import os
from pathlib import Path
import platform
import shutil
import stat
import sys
import tempfile

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from transport_install_build import compile_native, elf_closure, selected_tools, tool_receipt
from transport_install_check import complete_stage, verify_install
from transport_install_layout import PROFILES, source_inputs
from transport_install_support import atomic_publish, canonical, read_regular, require, sha, write_new

ROOT = Path(__file__).resolve().parents[1]
RESERVE = 10_000_000_000
OUTPUT_BUDGET = 134_217_728


def arguments() -> argparse.Namespace:
    require(1 <= len(sys.argv) <= 32 and all(len(arg) <= 4096 for arg in sys.argv), 'argument bound exceeded')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('build', 'check'))
    parser.add_argument('prefix', type=Path)
    parser.add_argument('--expect-source', required=True)
    parser.add_argument('--expect-install')
    parser.add_argument('--receipt', type=Path, required=True, help='New directory for immutable command logs and result')
    parser.add_argument('--gprbuild', type=Path)
    parser.add_argument('--compiler-bin', type=Path)
    return parser.parse_args()


def private_parent(path: Path) -> Path:
    require(path.is_absolute() and '..' not in path.parts and len(str(path)) < 2048, 'bounded absolute path required')
    parent = path.parent.resolve(strict=True)
    require(parent == path.parent, 'symlinked parent path refused')
    metadata = parent.stat()
    require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.geteuid()
            and stat.S_IMODE(metadata.st_mode) & 0o022 == 0, 'private user-owned parent required')
    return parent


def preflight(args: argparse.Namespace) -> dict:
    require(platform.system() == 'Linux' and platform.machine() in PROFILES, 'supported Linux architecture required')
    require(sys.version_info[:2] == (3, 14), 'Python 3.14 required')
    parent = private_parent(args.prefix)
    private_parent(args.receipt)
    require(not args.receipt.exists() and not args.receipt.is_symlink(), 'receipt destination already exists')
    if args.action == 'build':
        require(not args.prefix.exists() and not args.prefix.is_symlink(), 'installation destination already exists')
        require(args.gprbuild is not None and args.compiler_bin is not None, 'explicit trusted toolchain required')
        require(args.expect_install is None, 'build derives the installation identity')
    else:
        require(args.expect_install is not None, 'held installation identity required for check')
    free = shutil.disk_usage(parent).free
    require(free >= RESERVE + OUTPUT_BUDGET, 'free-space reserve and output budget required')
    return dict(free_bytes=free, reserve_bytes=RESERVE, output_budget_bytes=OUTPUT_BUDGET,
                python=sys.version, platform=platform.platform(), architecture=platform.machine())


def bounded_cleanup(root: Path, identity: tuple) -> None:
    metadata = root.lstat()
    require((metadata.st_dev, metadata.st_ino, metadata.st_uid) == identity, 'scratch identity changed; cleanup refused')
    pending, directories, files, total = [root], [], [], 0
    for _ in range(128):
        if not pending:
            break
        directory = pending.pop()
        directories.append(directory)
        for path in directory.iterdir():
            total += 1
            require(total <= 512 and not path.is_symlink(), 'scratch cleanup entry limit or symlink')
            require(len(path.relative_to(root).parts) <= 8, 'scratch cleanup depth exceeded')
            if path.is_dir():
                pending.append(path)
            else:
                require(path.is_file(), 'special scratch entry; cleanup refused')
                files.append(path)
    require(not pending, 'scratch cleanup traversal bound exceeded')
    for path in files:
        path.unlink()
    for path in reversed(directories):
        path.rmdir()


def private_directory(parent: Path, label: str) -> tuple[Path, tuple]:
    path = Path(tempfile.mkdtemp(prefix=label, dir=parent))
    metadata = path.lstat()
    require(stat.S_IMODE(metadata.st_mode) == 0o700 and metadata.st_uid == os.geteuid(), 'private stage required')
    return path, (metadata.st_dev, metadata.st_ino, metadata.st_uid)


def build(args: argparse.Namespace, files: dict, result: dict) -> dict:
    tools, env = selected_tools(args.gprbuild, args.compiler_bin)
    scratch, scratch_id = private_directory(args.prefix.parent, '.transport-build-')
    stage, stage_id = private_directory(args.prefix.parent, '.transport-install-')
    result['scratch'], result['stage'] = str(scratch), str(stage)
    published = False
    try:
        result['toolchain'] = tool_receipt(tools, env, scratch, args.receipt)
        native = compile_native(files, scratch, tools, env, args.receipt)
        result['elf'] = elf_closure(native, scratch / 'bin/transport_native', tools, env, args.receipt)
        identity = complete_stage(stage, files, native, args.expect_source, env, args.receipt)
        result['verification'] = verify_install(stage, files, args.expect_source, identity, env, args.receipt)
        atomic_publish(stage, args.prefix)
        published = True
        result.update(status='INSTALLED_BUILD_SPECIFIC_BUNDLE', install_manifest_sha256=identity,
                      prefix=str(args.prefix))
    finally:
        bounded_cleanup(scratch, scratch_id)
        if not published and stage.exists():
            bounded_cleanup(stage, stage_id)
    return result


def main() -> None:
    args = arguments()
    observation = preflight(args)
    _, files = source_inputs(ROOT, args.expect_source)
    args.receipt.mkdir(mode=0o700)
    result = dict(schema='transport/build-receipt/1', status='FAILED', environment=observation,
                  source_manifest_sha256=args.expect_source, action=args.action,
                  limits='Trusted nonescaping toolchain; direct-process limits, not aggregate descendant containment',
                  formal_proof='NOT_RUN; retained source proofs do not prove compiler or installer',
                  authentication='NOT_PROVIDED', semantic_completeness='UNPROVEN')
    try:
        if args.action == 'build':
            result = build(args, files, result)
        else:
            env = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', PYTHONDONTWRITEBYTECODE='1')
            result.update(verify_install(args.prefix, files, args.expect_source, args.expect_install, env, args.receipt))
    except (ValueError, OSError, KeyError, TypeError, MemoryError, RecursionError, KeyboardInterrupt) as error:
        result['error'] = type(error).__name__ + ': ' + str(error)[:512]
        raise
    finally:
        write_new(args.receipt / 'receipt.json', canonical(result))
    print(canonical(result).decode('utf-8'))


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, MemoryError, RecursionError, KeyboardInterrupt) as error:
        print('REFUSED: ' + type(error).__name__ + ': ' + str(error)[:512], file=sys.stderr)
        sys.exit(1)
