"""Single prepaid public observation; no retries, no tool-enabled model loop."""
import hashlib
import json
import os
from pathlib import Path
import resource
import selectors
import signal
import subprocess
import time

ROOT = Path(__file__).resolve().parent
CAP = 65536


def save(name, raw):
    fd = os.open(ROOT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        written = stream.write(raw)
    if written != len(raw):
        raise ValueError('SHORT_WRITE')


def limits():
    for kind, cap in ((resource.RLIMIT_CPU, 120),
                      (resource.RLIMIT_FSIZE, 4194304),
                      (resource.RLIMIT_NOFILE, 128)):
        soft, hard = resource.getrlimit(kind)
        finite = [x for x in (soft, hard, cap) if x != resource.RLIM_INFINITY]
        bound = min(finite)
        resource.setrlimit(kind, (bound, bound))


def collect(process):
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    status, deadline = 'COMPLETED', time.monotonic() + 120
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ, 'stdout')
        selector.register(process.stderr, selectors.EVENT_READ, 'stderr')
        while selector.get_map():
            if time.monotonic() >= deadline:
                status = 'TIMEOUT'
                break
            for key, _ in selector.select(timeout=min(0.2, max(0, deadline-time.monotonic()))):
                raw = os.read(key.fileobj.fileno(), 4096)
                if not raw:
                    selector.unregister(key.fileobj)
                    continue
                if sum(len(value) for value in buffers.values()) + len(raw) > CAP:
                    status = 'OUTPUT_BOUND'
                    break
                buffers[key.data].extend(raw)
            if status != 'COMPLETED':
                break
    return status, buffers


def main():
    settings = json.loads((ROOT / 'settings.json').read_bytes())['claude']
    prompt = (ROOT / 'prompt.txt').read_bytes()
    if len(prompt) > CAP or (ROOT / 'launch.json').exists():
        raise ValueError('BOUND_OR_ALREADY_LAUNCHED')
    argv = [settings['executable'], *settings['argv']]
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(('ANTHROPIC_', 'CLAUDE_'))}
    env.update(DISABLE_AUTOUPDATER='1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1')
    save('launch.json', json.dumps(dict(argv=argv, prompt_sha256=hashlib.sha256(prompt).hexdigest(),
        settings_sha256=hashlib.sha256((ROOT/'settings.json').read_bytes()).hexdigest(),
        runner_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        started_unix_ns=time.time_ns(), environment='Existing environment with ANTHROPIC_/CLAUDE_ overrides removed; updater/nonessential traffic disabled. No environment values retained.'),
        sort_keys=True).encode() + b'\n')
    start = time.monotonic_ns()
    process = subprocess.Popen(argv, cwd=ROOT, env=env, stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, preexec_fn=limits)
    status, buffers = 'RUNNER_EXCEPTION', {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        written = process.stdin.write(prompt)
        process.stdin.close()
        if written != len(prompt):
            raise ValueError('SHORT_STDIN')
        status, buffers = collect(process)
    finally:
        if status == 'COMPLETED':
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                status = 'EXIT_TIMEOUT'
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
        code = process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()
        for name, value in buffers.items():
            save('claude.' + name, bytes(value))
        save('run.json', json.dumps(dict(status=status, returncode=code,
            elapsed_ns=time.monotonic_ns()-start, child_peak_rss_kib=resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss,
            model_output_interpretation='NOT_ASSESSED', no_retry=True), sort_keys=True).encode()+b'\n')


if __name__ == '__main__':
    main()
