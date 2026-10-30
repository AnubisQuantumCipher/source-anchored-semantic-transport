"""Portable exact-byte formatter controls; stdlib only, no decoder or native build.

The twelve manual expectations precede implementation. Both interpreter modes use
fresh fixtures. Optional --evidence DIR retains complete first streams create-only.
These tests establish observed display behavior, not authentication or authority.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / "install/transport_public_share.py"
ORACLE = ROOT / "examples/public-share-v1/oracle.json"
ORACLE_SHA = "3a74b339dd2f6fb0c63f6c620f5544e1a919314f5a9091c0e8bc6a6b6fdb4391"
EVIDENCE = None


def pin(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def save(path, raw):
    with path.open("xb") as stream:
        if stream.write(raw) != len(raw):
            raise OSError("incomplete evidence write")


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode() + b"\n"


def capture(command):
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True,
                               env={"PATH": "/usr/bin:/bin", "LC_ALL": "C.UTF-8"})
    selector = selectors.DefaultSelector()
    buffers = [bytearray(), bytearray()]
    for index, stream in enumerate((process.stdout, process.stderr)):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ, index)
    start = time.monotonic()
    failure = None
    for unused in range(6000):
        if time.monotonic() - start > 30:
            failure = "TIMEOUT"
            break
        for key, unused_mask in selector.select(0.01):
            data = os.read(key.fileobj.fileno(), min(4096, 16385 - len(buffers[key.data])))
            if data:
                buffers[key.data].extend(data)
            else:
                selector.unregister(key.fileobj)
            if len(buffers[key.data]) > 16384:
                failure = "CAPTURE_BOUND"
                break
        if failure or (not selector.get_map() and process.poll() is not None):
            break
    else:
        failure = "CAPTURE_WORK_BOUND"
    if failure:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    code = process.wait(timeout=2)
    selector.close()
    process.stdout.close()
    process.stderr.close()
    return {"exit_code": code, "capture_failure": failure,
            "elapsed_monotonic_seconds": time.monotonic() - start}, bytes(buffers[0]), bytes(buffers[1])


def output_matches(case, destination):
    expected = case["expected_companion_hex"]
    if expected is None:
        expected = case["existing_output_hex"]
    if expected is None:
        return not destination.exists() and not destination.is_symlink()
    return (not destination.is_symlink() and destination.is_file()
            and destination.stat().st_size <= 131072
            and destination.read_bytes() == bytes.fromhex(expected))


def observe(case, lane, folder, source):
    canonical_root = folder / "canonical"
    canonical_root.mkdir()
    (folder / "external").mkdir()
    original = bytes.fromhex(case["input_raw_hex"])
    sentinel = b"canonical identity sentinel\n"
    input_path = canonical_root / "share.txt"
    manifest = canonical_root / "unchanged.manifest"
    save(input_path, original)
    save(manifest, sentinel)
    destination = folder / case["output_relative_to_case"]
    if case["existing_output_hex"] is not None:
        save(destination, bytes.fromhex(case["existing_output_hex"]))
    command = [str(Path(sys.executable).resolve())]
    if lane == "opt1":
        command.append("-O")
    command += ["-I", "-S", str(MODULE), "format", str(input_path),
                str(destination), "--budget", str(case["budget"])]
    if MODULE.read_bytes() != source:
        raise ValueError("formatter source changed before control")
    execution, stdout, stderr = capture(command)
    checks = {
        "complete_capture": execution["capture_failure"] is None,
        "exit": execution["exit_code"] == case["expected_exit_code"],
        "stdout": stdout == bytes.fromhex(case["expected_stdout_hex"]),
        "stderr": stderr == bytes.fromhex(case["expected_stderr_hex"]),
        "companion": output_matches(case, destination),
        "canonical_input": input_path.read_bytes() == original,
        "canonical_sentinel": manifest.read_bytes() == sentinel,
        "canonical_members": sorted(p.name for p in canonical_root.iterdir())
                             == ["share.txt", "unchanged.manifest"],
        "source_unchanged": MODULE.read_bytes() == source,
    }
    row = {"id": case["id"], "lane": lane, "command": command,
           "execution": execution, "checks": checks,
           "stdout": pin(stdout), "stderr": pin(stderr)}
    if EVIDENCE is not None:
        prefix = EVIDENCE / (case["id"] + "__" + lane)
        save(prefix.with_suffix(".stdout"), stdout)
        save(prefix.with_suffix(".stderr"), stderr)
        save(prefix.with_suffix(".json"), canonical(row))
    return row


class PublicShareControls(unittest.TestCase):
    def check_pure_refusal(self, case_id, raw, budget, reason):
        source = MODULE.read_bytes()
        namespace = {"__name__": "formatter_under_test", "__file__": str(MODULE)}
        exec(compile(source, str(MODULE), "exec"), namespace)
        with self.assertRaises(namespace["PublicShareError"]) as caught:
            namespace["public_text"](raw, budget)
        self.assertEqual(str(caught.exception), reason)
        self.assertEqual(MODULE.read_bytes(), source)
        if EVIDENCE is not None:
            save(EVIDENCE / (case_id + ".json"), canonical({
                "scope": "PURE_API_BOUNDARY_ONLY", "id": case_id,
                "input": pin(raw), "budget_type": type(budget).__name__,
                "budget": budget, "exception": type(caught.exception).__name__,
                "reason": str(caught.exception), "source": pin(source)}))

    def test_input_bound_precedes_invalid_utf8(self):
        self.check_pure_refusal("B01_INPUT_BEFORE_UTF8", b"\xff" * 131073,
                                131072, "PUBLIC_SHARE_INPUT_BOUND")

    def test_exact_input_cap_cannot_fit_inserted_cred(self):
        suffix = b"\nSTS1:" + b"0" * 64 + b"\nattached:meaning.zip"
        raw = b"A" * (131072 - len(suffix)) + suffix
        self.assertEqual(len(raw), 131072)
        self.check_pure_refusal("B02_OUTPUT_BYTE_BOUND", raw, 131072,
                                "PUBLIC_SHARE_BYTE_BOUND")

    def test_bool_budget_is_not_integer_budget(self):
        raw = b"Z\nSTS1:" + b"0" * 64 + b"\nattached:meaning.zip"
        self.check_pure_refusal("B03_BOOL_NOT_INT", raw, True,
                                "PUBLIC_SHARE_ARGUMENTS")

    def test_frozen_literals_normal_and_optimized(self):
        raw = ORACLE.read_bytes()
        self.assertLessEqual(len(raw), 65536)
        self.assertEqual(pin(raw)["sha256"], ORACLE_SHA)
        oracle = json.loads(raw)
        self.assertEqual(oracle["schema"], "transport/public-share-literal-oracle/1")
        self.assertEqual(len(oracle["cases"]), 12)
        source = MODULE.read_bytes()
        rows = []
        for lane in ("normal", "opt1"):
            for case in oracle["cases"]:
                with self.subTest(case=case["id"], lane=lane):
                    with tempfile.TemporaryDirectory(prefix="public-share-") as tmp:
                        row = observe(case, lane, Path(tmp), source)
                    rows.append(row)
                    self.assertTrue(all(row["checks"].values()), row)
        self.assertEqual(MODULE.read_bytes(), source)
        if EVIDENCE is not None:
            save(EVIDENCE / "report.json", canonical({
                "scope": "OBSERVED_DISPLAY_FORMATTER_ONLY",
                "oracle": pin(raw), "source": pin(source), "cases": rows}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--evidence", type=Path)
    args, remaining = parser.parse_known_args()
    EVIDENCE = args.evidence
    if EVIDENCE is not None:
        EVIDENCE.mkdir()
    unittest.main(argv=[sys.argv[0]] + remaining)
