#!/usr/bin/env python3
"""Negative controls for the single-field parent receipt exception."""
import copy
import importlib.util
from pathlib import Path

HERE = Path(__file__).absolute().parent


def load():
    path = HERE / 'prepare_receipt.py'
    specification = importlib.util.spec_from_file_location('_ci_delta_controls', path)
    module = importlib.util.module_from_spec(specification)
    with path.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError('CI delta source bound')
    exec(compile(raw, str(path), 'exec'), module.__dict__)
    return module


def main():
    module = load()
    reader = module.parent_reader()
    checked = reader.utility()
    parent = checked.json_value(module.pinned(module.PARENT / 'receipt.json', module.RECEIPT_SHA))
    current = copy.deepcopy(parent)
    old = parent['files'][module.KEY]
    new = {'bytes': 1, 'sha256': '0' * 64}
    current['files'][module.KEY] = new
    module.compare(parent, current, old, new)
    variants = []
    for key in tuple(parent):
        changed = copy.deepcopy(current)
        del changed[key]
        variants.append(changed)
    for key in tuple(parent['files']):
        changed = copy.deepcopy(current)
        del changed['files'][key]
        variants.append(changed)
    changed = copy.deepcopy(current)
    changed['extra'] = True
    variants.append(changed)
    changed = copy.deepcopy(current)
    changed['files']['extra'] = new
    variants.append(changed)
    changed = copy.deepcopy(current)
    changed['process_records']['local-01'] += 1
    variants.append(changed)
    changed = copy.deepcopy(current)
    changed['files']['native_workspace.py'] = new
    variants.append(changed)
    changed = copy.deepcopy(current)
    changed['process_records']['local-01'] = float(changed['process_records']['local-01'])
    variants.append(changed)
    changed = copy.deepcopy(current)
    changed['recorded_runs']['portable-O-01/receipt.json']['profile']['optimized'] = 1
    variants.append(changed)
    for changed in variants:
        try:
            module.compare(parent, changed, old, new)
        except ValueError:
            continue
        raise ValueError('CI delta accepted an unrelated change')
    try:
        module.compare(parent, parent, old, old)
    except ValueError:
        pass
    else:
        raise ValueError('CI delta accepted unchanged workflow')
    print('Single-field CI delta positive and negative controls pass')


if __name__ == '__main__':
    main()
