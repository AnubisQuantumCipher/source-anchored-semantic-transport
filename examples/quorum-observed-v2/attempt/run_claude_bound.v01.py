#!/usr/bin/env python3
"""One create-only observational call; transient cgroup, no persistent service."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parent
CAP = 65536
CONTROL = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
           "XDG_RUNTIME_DIR": "/run/user/1000",
           "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}
CHILD = {"HOME": "/home/sicarii", "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
         "DISABLE_AUTOUPDATER": "1", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1"}
GATE = ("import os,sys; b=os.read(0,1); "
        "sys.exit(125) if b!=b'G' else os.execv(sys.argv[1],sys.argv[1:])")
PROPERTIES = {"MemoryMax": "536870912", "MemorySwapMax": "0",
              "KillMode": "control-group", "TimeoutStopSec": "2",
              "LimitCPU": "120", "LimitFSIZE": "4194304", "LimitNOFILE": "128"}


def save(name, raw):
    if type(raw) is not bytes or len(raw) > 1048576:
        raise ValueError("bounded bytes required")
    fd = os.open(ROOT / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def close_registered(selector, stream):
    selector.unregister(stream)
    stream.close()


def write_ready(selector, stream, pending, offset):
    try:
        count = os.write(stream.fileno(), pending[offset:offset + 4096])
    except BlockingIOError:
        return offset
    except BrokenPipeError:
        close_registered(selector, stream)
        return len(pending)
    offset += count
    if offset == len(pending):
        close_registered(selector, stream)
    return offset


def collect(process, pending, deadline, cap):
    output, errors, offset, status = bytearray(), bytearray(), 0, "COMPLETE"
    with selectors.DefaultSelector() as selector:
        for stream, label in ((process.stdout, "out"), (process.stderr, "err")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        os.set_blocking(process.stdin.fileno(), False)
        if pending:
            selector.register(process.stdin, selectors.EVENT_WRITE, "in")
        else:
            process.stdin.close()
        for _ in range(20000):
            if not selector.get_map():
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                status = "TIMEOUT"
                break
            for key, _ in selector.select(min(0.05, remaining)):
                if key.data == "in":
                    offset = write_ready(selector, key.fileobj, pending, offset)
                    continue
                try:
                    chunk = os.read(key.fd, 4096)
                except BlockingIOError:
                    continue
                if not chunk:
                    close_registered(selector, key.fileobj)
                    continue
                target = output if key.data == "out" else errors
                space = cap - len(output) - len(errors)
                target.extend(chunk[:space])
                if len(chunk) > space:
                    status = "OUTPUT_LIMIT"
                    break
            if status != "COMPLETE":
                break
        else:
            status = "ITERATION_LIMIT"
        for key in list(selector.get_map().values()):
            close_registered(selector, key.fileobj)
    return {"status": status, "stdout": bytes(output), "stderr": bytes(errors),
            "input_bytes_sent": offset}


def reap_client(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        return process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        return None


def control(arguments, seconds=3):
    started = time.monotonic()
    process = subprocess.Popen(["/usr/bin/systemctl", "--user", *arguments],
        env=CONTROL, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, start_new_session=True)
    try:
        captured = collect(process, b"", started + seconds, 8192)
        try:
            code = process.wait(timeout=max(0.01, started + seconds - time.monotonic()))
        except subprocess.TimeoutExpired:
            code = None
        return captured, code
    finally:
        reap_client(process)


def properties(unit):
    captured, code = control(["show", unit, "--no-pager",
        "--property=LoadState,ActiveState,ControlGroup,MemoryMax,MemorySwapMax,KillMode"])
    values = {}
    if captured["status"] == "COMPLETE" and code == 0:
        for line in captured["stdout"].decode("utf-8", "strict").splitlines():
            key, separator, value = line.partition("=")
            if not separator or key in values:
                raise ValueError("malformed unit properties")
            values[key] = value
    return values, captured["status"], code


def ready(unit, deadline):
    observed = {}
    for _ in range(20):
        if time.monotonic() >= deadline:
            break
        observed, status, code = properties(unit)
        if observed.get("ControlGroup"):
            expected = {"MemoryMax": "536870912", "MemorySwapMax": "0",
                        "KillMode": "control-group", "ActiveState": "active"}
            if any(observed.get(key) != value for key, value in expected.items()):
                raise ValueError("unit limits/state not confirmed")
            return observed
        if status != "COMPLETE" or code not in (0, 1):
            raise ValueError("unit property query failed")
        time.sleep(0.05)
    raise ValueError("unit never reached verified state")


def empty_group(group):
    if not group or not group.startswith("/user.slice/") or ".." in group.split("/"):
        return False
    events = Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.events"
    try:
        with events.open("rb") as stream:
            raw = stream.read(1025)
    except FileNotFoundError:
        return True
    return len(raw) <= 1024 and b"populated 0" in raw.splitlines()


def cleanup(unit, group):
    stopped, stop_code = control(["stop", unit], 4)
    last, confirmed = {}, False
    for _ in range(20):
        last, status, code = properties(unit)
        inactive = last.get("ActiveState") in ("inactive", "failed")
        missing = last.get("LoadState") == "not-found"
        if status == "COMPLETE" and code == 0 and (inactive or missing):
            confirmed = empty_group(group)
            if confirmed:
                break
        time.sleep(0.05)
    return {"confirmed": confirmed, "unit_properties": last,
            "cgroup": group, "stop_exit": stop_code,
            "stop_capture_status": stopped["status"]}


def command(unit, argv, seconds):
    result = ["/usr/bin/systemd-run", "--user", "--quiet", "--pipe", "--wait",
              "--collect", "--unit=" + unit]
    for name, value in PROPERTIES.items():
        result.extend(["--property=" + name + "=" + value])
    result.extend(["--property=RuntimeMaxSec=" + str(seconds),
                   "/usr/bin/env", "-i"])
    result.extend(name + "=" + value for name, value in CHILD.items())
    return result + ["/usr/bin/python3", "-I", "-c", GATE, *argv]


def run_unit(argv, payload, seconds):
    if type(seconds) is not int or not 1 <= seconds <= 120:
        raise ValueError("invalid wall bound")
    if type(payload) is not bytes or len(payload) > CAP:
        raise ValueError("invalid input bound")
    if not argv or len(argv) > 64 or any(type(x) is not str or "\0" in x for x in argv):
        raise ValueError("invalid argv")
    unit = "semantic-observe-" + uuid.uuid4().hex + ".service"
    started = time.monotonic()
    process, observed, cleanup_result = None, {}, None
    capture = {"status": "NOT_STARTED", "stdout": b"", "stderr": b""}
    error, code = None, None
    try:
        process = subprocess.Popen(command(unit, argv, seconds), env=CONTROL,
            cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True)
        observed = ready(unit, started + seconds)
        capture = collect(process, b"G" + payload, started + seconds, CAP)
        try:
            code = process.wait(timeout=max(0.01, started + seconds - time.monotonic()))
        except subprocess.TimeoutExpired:
            capture["status"] = "TIMEOUT"
    except (OSError, ValueError, UnicodeError) as problem:
        error = type(problem).__name__ + ": " + str(problem)
        capture["status"] = "REFUSED"
    finally:
        cleanup_result = cleanup(unit, observed.get("ControlGroup", ""))
        if process is not None:
            reaped = reap_client(process)
            if code is None:
                code = reaped
    return {**capture, "exit": code, "error": error, "unit": unit,
            "verified_properties": observed, "cleanup": cleanup_result,
            "elapsed_seconds": time.monotonic() - started,
            "accepted_process": capture["status"] == "COMPLETE" and code == 0
                and cleanup_result["confirmed"] and error is None}


def main():
    settings_raw = (ROOT / "settings.json").read_bytes()
    prompt = (ROOT / "prompt.txt").read_bytes()
    settings = json.loads(settings_raw)["claude"]
    if len(prompt) > CAP or (ROOT / "launch.json").exists():
        raise ValueError("input bound or existing launch")
    argv = [settings["executable"], *settings["argv"]]
    launch = {"schema": "quorum/observed-bounded-launch/1", "argv": argv,
        "prompt_sha256": digest(prompt), "settings_sha256": digest(settings_raw),
        "runner_sha256": digest(Path(__file__).read_bytes()),
        "profile_sha256": digest((ROOT / "bounded-profile-addendum.json").read_bytes()),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    save("launch.json", canonical(launch))
    result = run_unit(argv, prompt, 120)
    save("claude.stdout", result.pop("stdout"))
    save("claude.stderr", result.pop("stderr"))
    save("run.json", canonical(result))
    return 0 if result["accepted_process"] else 1


if __name__ == "__main__":
    sys.exit(main())
