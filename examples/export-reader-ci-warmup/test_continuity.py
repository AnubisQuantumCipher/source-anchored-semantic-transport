#!/usr/bin/env python3
"""Bounded continuity controls; never mutate frozen artifacts or execute warmup."""
import copy
import importlib.util
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("continuity_under_test", HERE / "check_continuity.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("checker import unavailable")
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def refused(name, function):
    try:
        function()
    except ValueError as error:
        return {"case": name, "status": "REFUSED", "reason": str(error)}
    raise RuntimeError("negative accepted: " + name)


def workflow_controls(original, current):
    variants = {
        "increased_timeout": current.replace(b"timeout-minutes: 5", b"timeout-minutes: 6"),
        "changed_import": current.replace(b"import argparse, ast", b"import socket, ast", 1),
        "removed_optimized_mode": current.replace(b"-B -O -Werror install/test", b"-B -Werror install/test"),
        "removed_normal_test": current.replace(b"install/test_export_reader.py --evidence-dir", b"install/check_source.py --evidence-dir", 1),
        "changed_reproduction": current.replace(b"independent-export-reader-v1/reproduce.py", b"independent-export-reader-v1/receipt.py"),
        "extra_command": current + b"          echo extra\n",
        "unapproved_whitespace": current + b"\n",
        "old_checker_command": current.replace(CHECK.NEW_CHECK, CHECK.OLD_CHECK),
        "missing_warmup": current.replace(CHECK.WARMUP, b""),
    }
    rows = []
    for name, value in variants.items():
        if value == current:
            raise RuntimeError("ineffective mutation: " + name)
        rows.append(refused(name, lambda value=value: CHECK.validate_workflow(original, value)))
    rows.append(refused("snapshot_changed", lambda: CHECK.validate_workflow(original + b"\n", current)))
    return rows


def receipt_variants(generated):
    variants = {}
    value = copy.deepcopy(generated)
    value["claims"]["semantic_fidelity"] = "PROVED"
    variants["claim_changed"] = value
    value = copy.deepcopy(generated)
    value["files"][1]["sha256"] = "0" * 64
    variants["other_source_pin_changed"] = value
    value = copy.deepcopy(generated)
    value["files"].pop()
    variants["inventory_file_removed"] = value
    value = copy.deepcopy(generated)
    value["files"].append({"path": "extra", "bytes": 0, "sha256": "0" * 64})
    variants["inventory_file_added"] = value
    value = copy.deepcopy(generated)
    value["files"].append(copy.deepcopy(value["files"][0]))
    variants["workflow_row_duplicated"] = value
    value = copy.deepcopy(generated)
    value["files"][0]["bytes"] += 1
    variants["workflow_row_wrong_pin"] = value
    value = copy.deepcopy(generated)
    value["observations"]["status"] = "ALTERED"
    variants["observation_changed"] = value
    return variants


def cache_loader_control():
    original = CHECK.importlib.util.spec_from_file_location
    invoked = []

    class TrapLoader:
        def create_module(self, spec):
            return None

        def exec_module(self, module):
            invoked.append("cached-loader-executed")
            raise RuntimeError("must execute pinned bytes instead")

    def trapped(name, path):
        spec = original(name, path)
        spec.loader = TrapLoader()
        return spec

    CHECK.importlib.util.spec_from_file_location = trapped
    try:
        module = CHECK.load_pinned_receipt()
        if invoked or not callable(module.expected):
            raise RuntimeError("pinned source loader mismatch")
    finally:
        CHECK.importlib.util.spec_from_file_location = original
    return {"case": "bytecode_loader_not_executed", "status": "PASS"}


def failure_controls():
    original_read = CHECK.read
    rows = []
    for name in CHECK.FAILURE_PINS:
        def altered(path, cap, name=name):
            raw = original_read(path, cap)
            return raw + b"\n" if path.name == name else raw

        CHECK.read = altered
        try:
            rows.append(refused("retained_failure_changed:" + name, CHECK.check_failures))
        finally:
            CHECK.read = original_read
    return rows


def main():
    current = CHECK.read(CHECK.ROOT / CHECK.WORKFLOW, 131072)
    original = CHECK.read(HERE / "original-workflow.yml", 131072)
    old = CHECK.read(CHECK.OLD / "receipt.json", 131072)
    result = CHECK.check()
    generated = CHECK.load_pinned_receipt().expected()
    rows = workflow_controls(original, current)
    for name, value in receipt_variants(generated).items():
        rows.append(refused(name, lambda value=value: CHECK.validate_receipt(value, old, original, current)))
    rows.append(refused("old_receipt_changed", lambda: CHECK.validate_receipt(generated, old + b"\n", original, current)))
    rows.append(refused("old_source_pin_changed", lambda: CHECK.pinned(b"changed", CHECK.RECEIPT_CODE_SHA)))
    rows.append(cache_loader_control())
    rows.extend(failure_controls())
    print(json.dumps({"status": "PASS", "optimization": sys.flags.optimize,
                      "positive": result, "controls": rows}, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
