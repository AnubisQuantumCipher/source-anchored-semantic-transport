#!/usr/bin/env python3
"""Bounded integrated negative controls; mutations are read overlays, never writes."""

import argparse
import ast
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SPEC = importlib.util.spec_from_file_location('quorum_continuity', HERE / 'check_continuity.py')
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def refused(action, expected):
    try:
        action()
    except ValueError as error:
        require(expected in str(error), 'Unexpected refusal: ' + str(error))
        return
    raise ValueError('Negative control accepted: ' + expected)


def changed_read(historical, root, name, raw, expected):
    original = CHECK.Reader.read

    def overlay(reader, selected_root, selected_name):
        value = original(reader, selected_root, selected_name)
        if selected_root == root and selected_name == name:
            return raw
        return value

    with mock.patch.object(CHECK.Reader, 'read', overlay):
        refused(lambda: CHECK.check(ROOT, historical), expected)


def negative_bytes(historical, manifest, rows):
    archive = next(row['path'] for row in rows if row['path'].endswith('.zip'))
    cases = [
        ('code', ROOT, 'tools/transport_quorum_replay.py', 'Current sealed input differs'),
        ('workflow', ROOT, '.github/workflows/quorum-replay.yml', 'Current transition pin'),
        ('README-outside-insertion', ROOT, 'README.md', 'Current transition pin'),
        ('old-receipt', ROOT, CHECK.RECEIPT, 'Sealed receipt pin differs'),
        ('archive', ROOT, archive, 'Current sealed input differs'),
        ('historical-archive', historical, archive, 'Historical input differs'),
        ('new-manifest', ROOT, CHECK.MANIFEST, 'Manifest pin differs'),
        ('new-checker', ROOT, CHECK.CHECKER, 'Continuity input differs'),
    ]
    for label, root, name, reason in cases:
        raw = CHECK.Reader().read(root, name) + b'\n'
        changed_read(historical, root, name, raw, reason)
        print('REFUSAL_CHECKED ' + label)
    transition = copy.deepcopy(manifest['intentional_mismatches']['README.md'])
    raw = CHECK.Reader().read(ROOT, 'README.md') + b'outside-dated-section\n'
    transition['current'] = CHECK.pin(raw)
    refused(lambda: CHECK.check_transition('README.md', raw, transition['historical'],
                                         transition), 'README original body')
    print('REFUSAL_CHECKED README-original-body-with-replacement-pin')


def negative_rosters(historical):
    original = CHECK.tree_paths
    for name in (CHECK.V1, CHECK.V2):
        def overlay(root, selected_name):
            value = original(root, selected_name)
            if root == ROOT and selected_name == name:
                return value | {name + '/unknown-input.json'}
            return value

        with mock.patch.object(CHECK, 'tree_paths', overlay):
            refused(lambda: CHECK.check(ROOT, historical), 'roster')
        print('REFUSAL_CHECKED unknown-' + Path(name).name + '-entry')
    original_sources = CHECK.owned_sources

    def sources_overlay(root, separate):
        return original_sources(root, separate) | {'tools/transport_quorum_unknown.py'}

    with mock.patch.object(CHECK, 'owned_sources', sources_overlay):
        refused(lambda: CHECK.check(ROOT, historical), 'QUORUM source roster differs')
    print('REFUSAL_CHECKED unknown-QUORUM-source')


def negative_empty_directory(historical):
    with tempfile.TemporaryDirectory(prefix='.quorum-continuity-',
                                     dir=historical.parent) as temporary:
        root = Path(temporary)
        (root / 'closed' / 'unknown-empty').mkdir(parents=True)
        (root / 'closed' / 'known.txt').write_bytes(b'known')
        refused(lambda: CHECK.tree_paths(root, 'closed'), 'Empty directory outside sealed tree')
    print('REFUSAL_CHECKED unknown-empty-directory')


def static_controls():
    for name in ('check_continuity.py', 'test_continuity.py'):
        raw = CHECK.Reader().read(ROOT, CHECK.V2 + '/' + name)
        tree = ast.parse(raw, filename=name)
        compile(tree, name, 'exec', dont_inherit=True)
        nodes = list(ast.walk(tree))
        require(len(nodes) <= 16384, 'Static syntax-node bound')
        for node in nodes:
            require(not isinstance(node, ast.Assert), 'Assertions cannot enforce refusal')
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                require(node.end_lineno - node.lineno + 1 <= 60, 'Function size bound')
    print('CHECKED source-syntax-no-assert-and-function-bounds')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--historical-root', type=Path, required=True)
    historical = parser.parse_args().historical_root.resolve()
    result = CHECK.check(ROOT, historical)
    require(result['status'] == 'CHECKED', 'Positive continuity control failed')
    reader = CHECK.Reader()
    manifest = CHECK.load_manifest(reader, ROOT)
    rows = CHECK.receipt_rows(reader, ROOT, manifest)
    negative_bytes(historical, manifest, rows)
    negative_rosters(historical)
    negative_empty_directory(historical)
    static_controls()
    print(json.dumps({'status': 'TESTED', 'negative_controls': 13,
                      'optimized': not __debug__, 'formal_proof': 'UNPROVEN',
                      'product_acceptance': False}, sort_keys=True))


if __name__ == '__main__':
    main()
