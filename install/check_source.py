#!/usr/bin/env python3
"""Static syntax and local installer function-size control; not a formal verifier."""

import ast
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTINUATION = ROOT / 'examples/checked-continuation-v1/check_response.py'
HELDOUT = ROOT / 'examples/heldout-release-v1'
QUORUM_GRAPH = ROOT / 'tools/transport_quorum_graph.py'
QUORUM_INPUT = {ROOT / 'tools' / name for name in
                ('transport_quorum_input.py', 'transport_quorum_shape.py',
                 'transport_quorum_source.py', 'transport_quorum_claim.py',
                 'transport_quorum_impact.py', 'transport_quorum_context.py')}


def main() -> None:
    selected = sorted((ROOT / 'tools').glob('*.py')) + sorted((ROOT / 'install').glob('*.py'))
    selected.append(CONTINUATION)
    selected += sorted(HELDOUT.glob('*.py'))
    if not 1 <= len(selected) <= 128:
        raise ValueError('source file bound exceeded')
    functions = 0
    for path in selected:
        if path.is_symlink() or path.stat().st_size > 131072:
            raise ValueError('unsupported static-analysis input')
        tree = ast.parse(path.read_bytes())
        for node in ast.walk(tree):
            if (path.parent.name == 'install' or path in (CONTINUATION, QUORUM_GRAPH) or path in QUORUM_INPUT or path.parent == HELDOUT) and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                functions += 1
                if node.end_lineno - node.lineno + 1 > 60:
                    raise ValueError(str(path.relative_to(ROOT)) + ':' + node.name + ': exceeds 60 lines')
    print('PASS: parsed source files=' + str(len(selected)) + '; bounded installer functions=' + str(functions))


if __name__ == '__main__':
    main()
