#!/usr/bin/env python3
"""Bounded complete syntax profiles and function-size controls; not formal proof."""

import ast
from pathlib import Path
import stat

ROOT = Path(__file__).resolve().parents[1]
CONTINUATION = ROOT / 'examples/checked-continuation-v1/check_response.py'
HELDOUT = ROOT / 'examples/heldout-release-v1'
QUORUM_GRAPH = ROOT / 'tools/transport_quorum_graph.py'
QUORUM_INPUT = {ROOT / 'tools' / name for name in
                ('transport_quorum_input.py', 'transport_quorum_shape.py',
                 'transport_quorum_source.py', 'transport_quorum_claim.py',
                 'transport_quorum_impact.py', 'transport_quorum_context.py',
                 'transport_quorum_reading.py')}
DOCUMENT_NAMES = ('build_document_decoder.py', 'package_document_decoder.py',
                  'transport_document.py', 'transport_document_io.py',
                  'transport_document_archive.py', 'transport_document_cli.py',
                  'transport_document_media.py', 'transport_document_ocr.py',
                  'transport_document_reading.py')


# Explicit additive adapters only; the original legacy and document budgets stay fixed.
TRANSPORT_EXTENSION_NAMES = ('transport_document_supervisor.py', 'transport_document_namespace.py',
                             'transport_workflow_cli.py', 'transport_workflow_endpoint.py',
                             'transport_workflow_mcp.py')
WORKFLOW_ATTEMPT_NAMES = ('transport_workflow_attempts.py', 'transport_workflow_capture.py',
                          'transport_workflow_catalog.py')


def extension_sources(selected, root, required=False):
    extension = {root / 'tools' / name for name in TRANSPORT_EXTENSION_NAMES}
    document = {root / 'tools' / name for name in DOCUMENT_NAMES}
    if len(extension) != 5 or extension.intersection(document):
        raise ValueError('fixed transport extension roster differs')
    present = extension.intersection(selected)
    if present != extension and (present or required):
        raise ValueError('declared transport extension roster missing')
    return sorted(present)


def attempt_sources(selected, root, required=False):
    attempt = {root / 'tools' / name for name in WORKFLOW_ATTEMPT_NAMES}
    document = {root / 'tools' / name for name in DOCUMENT_NAMES}
    extension = {root / 'tools' / name for name in TRANSPORT_EXTENSION_NAMES}
    if len(attempt) != 3 or attempt.intersection(document) or attempt.intersection(extension):
        raise ValueError('fixed workflow attempt roster differs')
    present = attempt.intersection(selected)
    if present != attempt and (present or required):
        raise ValueError('declared workflow attempt roster missing')
    return sorted(present)


def partition(selected, root=ROOT):
    document = {root / 'tools' / name for name in DOCUMENT_NAMES}
    if len(set(selected)) != len(selected):
        raise ValueError('duplicate static-analysis input')
    if not document.issubset(selected):
        raise ValueError('declared document source roster missing')
    extension = extension_sources(selected, root)
    attempt = attempt_sources(selected, root)
    classified = document.union(extension, attempt)
    legacy = [path for path in selected if path not in classified]
    if not 1 <= len(legacy) <= 128:
        raise ValueError('legacy source file bound exceeded')
    if len(document) != 9:
        raise ValueError('fixed document source file bound exceeded')
    profiles = [('legacy', legacy), ('document', sorted(document))]
    if extension:
        profiles.append(('transport-extension/1', extension))
    if attempt:
        profiles.append(('transport-workflow-attempt/1', attempt))
    return profiles


def sources():
    selected = sorted((ROOT / 'tools').glob('*.py')) + sorted((ROOT / 'install').glob('*.py'))
    selected.append(CONTINUATION)
    selected += sorted(HELDOUT.glob('*.py'))
    extension_sources(selected, ROOT, required=True)
    attempt_sources(selected, ROOT, required=True)
    return partition(selected)


def bounded_functions(path):
    return (path.parent.name == 'install' or path in (CONTINUATION, QUORUM_GRAPH)
            or path in QUORUM_INPUT or path.parent == HELDOUT
            or path == ROOT / 'tools' / path.name
            and path.name in DOCUMENT_NAMES + TRANSPORT_EXTENSION_NAMES + WORKFLOW_ATTEMPT_NAMES)


def analyze(paths):
    functions = 0
    for path in paths:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > 131072:
            raise ValueError('unsupported static-analysis input')
        with path.open('rb') as stream:
            raw = stream.read(131073)
        if len(raw) > 131072:
            raise ValueError('static-analysis input grew beyond byte bound')
        tree = ast.parse(raw, filename=str(path))
        compile(tree, str(path), 'exec', dont_inherit=True)
        for node in ast.walk(tree):
            if bounded_functions(path) and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
                if node.end_lineno - node.lineno + 1 > 60:
                    raise ValueError(str(path) + ':' + node.name + ': exceeds 60 lines')
    return {'files': len(paths), 'bounded_functions': functions}


def main() -> None:
    for label, paths in sources():
        result = analyze(paths)
        print('PASS: ' + label + ' parsed source files=' + str(result['files'])
              + '; bounded functions=' + str(result['bounded_functions']))


if __name__ == '__main__':
    main()
