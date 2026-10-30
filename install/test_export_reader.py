#!/usr/bin/env python3
"""Frozen-oracle development controls for the independent standard export reader.

No producer or reader source is consulted for fixture semantics. The source audit
reads only AST import/call names, at execution time, as a boundary control.
Evidence directories are create-only; subprocess stdout/stderr are retained.
These controls do not constitute external validation or formal proof.
"""
from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import unittest

def load_fixture_module():
    path = Path(__file__).resolve().with_name("export_reader_test_fixtures.py")
    spec = importlib.util.spec_from_file_location("independent_export_test_fixtures", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Fixture import specification absent")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_FIXTURES = load_fixture_module()
CAP = _FIXTURES.CAP
INSTRUCTION = _FIXTURES.INSTRUCTION
TEXT_PATH = _FIXTURES.TEXT_PATH
bounded_write = _FIXTURES.bounded_write
digest = _FIXTURES.digest
make_fixture = _FIXTURES.make_fixture
require = _FIXTURES.require

ORACLE_SHA256 = "038ec37d101605acfc910f89e948db9710dc69c364b05220564562c825e31dab"
DEFAULT_ORACLE = Path(__file__).resolve().parents[1] / "examples/independent-export-reader-v1/evidence/controls-oracle.json"
CLAIMS = {
    "metadata": "UNVERIFIED", "authentication": "NOT_PROVIDED", "authority": "NONE",
    "original_comparison": "NOT_PERFORMED", "producer_runtime": "NOT_EXECUTED",
    "raw_envelope": "NOT_RECONSTRUCTED", "semantic_completeness": "NOT_CLAIMED",
    "explanation_entailment": "UNPROVEN",
}
FORBIDDEN_IMPORTS = frozenset({
    "subprocess", "socket", "urllib", "http", "httpx", "requests", "ftplib",
    "smtplib", "imaplib", "poplib", "telnetlib", "webbrowser", "ctypes", "cffi",
    "multiprocessing", "importlib", "runpy",
})
FORBIDDEN_OS_CALLS = frozenset({
    "system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp",
    "execl", "execle", "execlp", "execlpe", "execv", "execve", "execvp", "execvpe",
    "spawnl", "spawnle", "spawnlp", "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
})


def bounded_read(path: Path, limit=CAP) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "Evidence input exceeded read budget: " + str(path))
    return data


def write_json_new(path: Path, value):
    raw = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode()
    require(len(raw) <= CAP, "Evidence record exceeded write budget")
    with path.open("xb") as stream:
        require(stream.write(raw) == len(raw), "Short evidence write")


def load_oracle(path: Path):
    raw = bounded_read(path)
    require(digest(raw) == ORACLE_SHA256, "Frozen control oracle pin mismatch")
    data = json.loads(raw)
    rows = data["rows"]
    require(isinstance(rows, list) and 1 <= len(rows) <= 200, "Oracle row budget invalid")
    identifiers = [row["id"] for row in rows]
    require(len(set(identifiers)) == len(identifiers), "Duplicate frozen control ID")
    return rows


def load_reader(path: Path):
    spec = importlib.util.spec_from_file_location("independent_reader_under_test", path)
    require(spec is not None and spec.loader is not None, "Reader import specification absent")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    require(callable(module.read_export), "Public read_export missing")
    require(issubclass(module.ExportReadError, Exception), "Public ExportReadError missing")
    return module


class BoundedText(io.TextIOBase):
    def __init__(self):
        self.parts = []
        self.size = 0

    def write(self, text):
        encoded = text.encode("utf-8", errors="replace")
        require(self.size + len(encoded) <= CAP, "Reader API printed beyond budget")
        self.size += len(encoded)
        self.parts.append(text)
        return len(text)


def alarm_failure(_signum, _frame):
    raise TimeoutError("Reader API call exceeded development-control time budget")


@contextlib.contextmanager
def api_deadline():
    previous = signal.signal(signal.SIGALRM, alarm_failure)
    signal.setitimer(signal.ITIMER_REAL, 5.0)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def child_limits():
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_FSIZE, (131072, 131072))
    resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def check_claims(result):
    require(isinstance(result, dict), "Public success result must be a mapping")
    require(result.get("authority") == "NONE", "Public authority ceiling missing")
    claims = result.get("claims")
    require(isinstance(claims, dict), "Claims mapping missing")
    for key, expected in CLAIMS.items():
        require(claims.get(key) == expected, "Claim ceiling mismatch for " + key)


def scan_import_boundary(source: bytes):
    tree = ast.parse(source, filename="read_transport_export.py")
    os_names = {"os"}
    nodes = list(ast.walk(tree))
    require(len(nodes) <= 50000, "Reader AST exceeded audit node budget")
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                check_import(alias.name)
                if alias.name == "os": os_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            require(node.level == 0 and node.module is not None, "Relative reader import forbidden")
            check_import(node.module)
            if node.module == "os":
                for alias in node.names:
                    require(alias.name not in FORBIDDEN_OS_CALLS, "Native process import forbidden")
        elif isinstance(node, ast.Call):
            call = node.func
            if isinstance(call, ast.Name):
                require(call.id not in {"eval", "exec", "compile", "__import__"}, "Dynamic source execution forbidden")
            if isinstance(call, ast.Attribute) and isinstance(call.value, ast.Name):
                require(not (call.value.id in os_names and call.attr in FORBIDDEN_OS_CALLS), "Native process call forbidden")
    return {"nodes": len(nodes), "status": "STATIC_IMPORT_BOUNDARY_CHECKED", "proof": "NOT_PROVED"}


def check_import(name: str):
    root = name.split(".")[0]
    require(root in sys.stdlib_module_names or root == "__future__", "Non-standard reader import: " + name)
    require(root not in FORBIDDEN_IMPORTS, "Forbidden reader import: " + name)


class IndependentReaderControls(unittest.TestCase):
    reader_path = None
    evidence_path = None
    rows = None
    reader = None

    @classmethod
    def setUpClass(cls):
        scan_import_boundary(bounded_read(cls.reader_path))
        cls.reader = load_reader(cls.reader_path)
        write_json_new(cls.evidence_path / "run.json", {
            "schema": "transport/reader-development-control-run/1", "kind": "DEVELOPMENT_NOT_HELDOUT",
            "reader_path": str(cls.reader_path), "reader_sha256": digest(bounded_read(cls.reader_path)),
            "oracle_sha256": ORACLE_SHA256, "python": sys.version,
            "optimization": sys.flags.optimize, "external_validation": "NOT_PERFORMED",
        })

    def api_call(self, fixture):
        output = BoundedText()
        with api_deadline(), contextlib.redirect_stdout(output):
            result = self.reader.read_export(str(fixture.root), fixture.pin)
        require(output.size == 0, "Data-only API emitted stdout")
        return result

    def api_rejection(self, fixture, evidence):
        codes = []
        for attempt in range(2):
            output = BoundedText()
            try:
                with api_deadline(), contextlib.redirect_stdout(output):
                    self.reader.read_export(str(fixture.root), fixture.pin)
            except self.reader.ExportReadError as error:
                code = getattr(error, "code", None)
                write_json_new(evidence / ("api-rejection-%d.json" % attempt), {
                    "exception": type(error).__name__, "code": code, "message": str(error)[:4096],
                    "stdout_bytes": output.size,
                })
                require(isinstance(code, str) and 0 < len(code) <= 256, "Refusal lacks stable bounded code")
                require(output.size == 0, "Rejected API call emitted successful stdout")
                codes.append(code)
            else:
                write_json_new(evidence / ("api-unexpected-success-%d.json" % attempt), {"unexpected": "ACCEPT"})
                self.fail("Expected ExportReadError; malformed export accepted")
        require(codes[0] == codes[1], "Identical refusal code is not stable")

    def run_cli(self, fixture, evidence, label, verb="inspect", output=None, source=None, pin=True):
        args = [sys.executable, "-I", "-S", "-B", "-Werror"]
        if sys.flags.optimize: args.append("-O")
        args.extend([str(self.reader_path), verb, str(fixture.root)])
        if output is not None: args.append(str(output))
        if source is not None: args.extend(["--source", source])
        if pin: args.extend(["--expect-export-sha256", fixture.pin])
        stdout_path, stderr_path = evidence / (label + ".stdout"), evidence / (label + ".stderr")
        env = {"PATH": os.defpath, "HOME": str(fixture.root.parent), "LC_ALL": "C.UTF-8",
               "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"}
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            result = subprocess.run(args, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr,
                                    cwd=fixture.root.parent, env=env, timeout=10, check=False,
                                    preexec_fn=child_limits)
        out, err = bounded_read(stdout_path), bounded_read(stderr_path)
        write_json_new(evidence / (label + ".process.json"), {
            "returncode": result.returncode, "stdout_bytes": len(out), "stderr_bytes": len(err),
            "verb": verb, "source": source, "pin_supplied": bool(pin),
        })
        return result.returncode, out, err

    def check_api_success(self, fixture, result):
        check_claims(result)
        require(result.get("status") == "VERIFIED_AGAINST_PINNED_EXPORT", "Wrong API success class")
        require(result.get("expected_export_sha256") == fixture.pin, "Expected external pin not retained")
        require(result.get("manifest") == fixture.manifest, "Validated manifest data changed")
        require(result.get("explanation_bytes") == fixture.text, "Explanation bytes changed")
        require(result.get("metadata_bytes") == fixture.metadata_bytes, "Raw metadata bytes changed")
        require(result.get("metadata") == json.loads(fixture.metadata_bytes), "Parsed metadata changed")
        actual = result.get("sources")
        require(isinstance(actual, list) and len(actual) == len(fixture.sources), "Source record count mismatch")
        for got, (identifier, original) in zip(actual, fixture.sources):
            require(got.get("id") == identifier, "Normative source order changed")
            require(got.get("path") == "sources/" + identifier + ".bin", "Source path changed")
            require(got.get("data") == original, "Original independently held source bytes changed")
            require(got.get("bytes") == len(original), "Recovered source length disagrees")
            require(got.get("sha256") == digest(original), "Recovered source digest disagrees")

    def check_cli_success(self, fixture, evidence):
        status, out, _err = self.run_cli(fixture, evidence, "inspect")
        require(status == 0, "Inspect refused a valid fixture")
        info = json.loads(out)
        check_claims(info)
        require(info.get("status") == "VERIFIED_AGAINST_PINNED_EXPORT", "Wrong CLI inspect status")
        require(out.endswith(b"\n") and len(out) <= CAP, "Inspect output boundary mismatch")
        require(b'"data"' not in out and INSTRUCTION.encode() not in out, "Inspect expanded opaque payload")
        for index, (identifier, original) in enumerate(fixture.sources):
            destination = fixture.root.parent / ("recovered-%02d.bin" % index)
            self.check_selected(fixture, evidence, "source-%02d" % index, "recover", destination, original, identifier)
        self.check_selected(fixture, evidence, "text", "explanation", fixture.root.parent / "text.bin", fixture.text)
        self.check_selected(fixture, evidence, "metadata", "metadata", fixture.root.parent / "metadata.bin", fixture.metadata_bytes)

    def check_selected(self, fixture, evidence, label, verb, destination, expected, identifier=None):
        status, out, _err = self.run_cli(fixture, evidence, label, verb, destination, identifier)
        require(status == 0, "Selected artifact recovery refused a valid fixture")
        result = json.loads(out)
        check_claims(result)
        require(result.get("status") == "EXACT_PINNED_EXPORT_BYTES_RECOVERED", "Wrong selected-output status class")
        require(bounded_read(destination) == expected, "Recovered file differs from separately held original bytes")
        require(destination.is_file() and not destination.is_symlink(), "Output is not a new regular file")

    def test_positive_controls(self):
        for row in self.rows:
            if row["kind"] != "positive": continue
            with self.subTest(case=row["id"]), tempfile.TemporaryDirectory(prefix="reader-control-", dir="/dev/shm") as temporary:
                evidence = self.evidence_path / row["id"]
                evidence.mkdir()
                fixture = make_fixture(Path(temporary), row)
                result = self.api_call(fixture)
                self.check_api_success(fixture, result)
                self.check_cli_success(fixture, evidence)
                require(not (Path(temporary) / "INSTRUCTION_EXECUTED").exists(), "Serialized instructions executed")
                write_json_new(evidence / "result.json", {"case": row["id"], "observed": "ACCEPT", "bytes": fixture.total_bytes()})

    def test_negative_controls(self):
        for row in self.rows:
            if row["kind"] != "negative": continue
            with self.subTest(case=row["id"]), tempfile.TemporaryDirectory(prefix="reader-control-", dir="/dev/shm") as temporary:
                evidence = self.evidence_path / row["id"]
                evidence.mkdir()
                fixture = make_fixture(Path(temporary), row)
                self.api_rejection(fixture, evidence)
                status, out, _err = self.run_cli(fixture, evidence, "inspect")
                require(status != 0 and out == b"", "Rejected inspect had zero exit or successful stdout")
                for verb in ("recover", "explanation", "metadata"):
                    destination = Path(temporary) / ("must-not-exist-" + verb + ".bin")
                    source = fixture.sources[0][0] if verb == "recover" else None
                    status, out, _err = self.run_cli(fixture, evidence, verb, verb, destination, source)
                    require(status != 0 and out == b"", "Rejected selected output had zero exit or successful stdout")
                    require(not os.path.lexists(destination), "Accepted output remained after refusal")
                require(not (Path(temporary) / "INSTRUCTION_EXECUTED").exists(), "Serialized instructions executed")
                write_json_new(evidence / "result.json", {"case": row["id"], "observed": "REJECT"})

    def test_cli_negative_controls(self):
        for row in self.rows:
            if row["kind"] != "cli_negative": continue
            with self.subTest(case=row["id"]), tempfile.TemporaryDirectory(prefix="reader-control-", dir="/dev/shm") as temporary:
                evidence = self.evidence_path / row["id"]
                evidence.mkdir()
                fixture = make_fixture(Path(temporary), row)
                self.run_output_refusal(fixture, row, evidence)
                write_json_new(evidence / "result.json", {"case": row["id"], "observed": "REJECT"})

    def run_output_refusal(self, fixture, row, evidence):
        mutation = row["mutation"]
        parent = fixture.root.parent
        destination = parent / "output.bin"
        original = b"EXISTING OUTPUT MUST SURVIVE\x00\xff"
        identifier = fixture.sources[0][0]
        verb = "recover"
        retained = None
        if mutation in ("existing_output", "metadata_existing", "text_existing"):
            bounded_write(destination, original)
            retained = destination
            verb = {"metadata_existing": "metadata", "text_existing": "explanation"}.get(mutation, "recover")
        elif mutation == "output_ancestor_symlink":
            actual = parent / "actual-output-parent"
            actual.mkdir()
            (parent / "alias-output-parent").symlink_to(actual, target_is_directory=True)
            destination = parent / "alias-output-parent" / "output.bin"
        elif mutation == "output_leaf_symlink":
            retained = parent / "existing-target.bin"
            bounded_write(retained, original)
            destination.symlink_to(retained)
        elif mutation == "output_fifo": os.mkfifo(destination)
        elif mutation == "unknown_source": identifier = "UNKNOWN"
        elif mutation == "uppercase_pin": fixture.pin = fixture.pin.upper()
        elif mutation == "short_pin": fixture.pin = "abcd"
        elif mutation == "missing_parent": destination = parent / "missing" / "output.bin"
        status, out, _err = self.run_cli(fixture, evidence, "refusal", verb, destination,
                                       identifier if verb == "recover" else None,
                                       pin=mutation != "missing_pin")
        require(status != 0 and out == b"", "CLI refusal must be nonzero with no success stdout")
        if retained is not None:
            require(bounded_read(retained) == original, "Existing output or referent was modified")
        elif mutation != "output_fifo":
            require(not os.path.lexists(destination), "Rejected command left accepted output")
        if mutation == "missing_parent": require(not destination.parent.exists(), "Reader created output directory")

    def test_static_import_boundary(self):
        rows = [row for row in self.rows if row["kind"] == "static"]
        require(len(rows) == 1, "Frozen import audit row missing")
        result = scan_import_boundary(bounded_read(self.reader_path))
        write_json_new(self.evidence_path / "static-import-boundary.json", result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reader", type=Path, default=Path(__file__).with_name("read_transport_export.py"))
    parser.add_argument("--oracle", type=Path, default=DEFAULT_ORACLE)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    args = parser.parse_args()
    require(args.reader.is_file(), "Reader file is absent")
    require(args.evidence_dir.parent.is_dir(), "Evidence parent must already exist")
    args.evidence_dir.mkdir(mode=0o700)
    IndependentReaderControls.reader_path = args.reader.resolve()
    IndependentReaderControls.evidence_path = args.evidence_dir.resolve()
    IndependentReaderControls.rows = load_oracle(args.oracle)
    unittest.main(argv=[sys.argv[0], "-v"], exit=True)


if __name__ == "__main__":
    main()
