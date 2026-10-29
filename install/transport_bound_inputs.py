"""Load a prepared receiver using release-matched copied helpers as data only."""
from pathlib import Path
import sys

import transport_handoff_inputs as inputs
from transport_install_layout import exact_tree
from transport_install_support import read_regular, require, sha

HERE = Path(__file__).absolute().parent


def prepared_manifest(path, expected):
    raw = read_regular(path, inputs.REQUEST_CAP)
    require(sha(raw) == inputs.digest(expected), 'externally held manifest digest mismatch')
    value = inputs.json_value(raw)
    inputs.fields(value, ('schema', 'arm', 'helpers', 'python', 'content', 'sources',
                          'held_source_sha256', 'bundle', 'pair'))
    require(value['schema'] == inputs.SCHEMA and value['arm'] == 'transport', 'prepared transport manifest required')
    helpers = value['helpers']
    names = inputs.BOOTSTRAP + ('test_portable_handoff.py',)
    base = path.absolute().parent / 'helpers'
    require(type(helpers) is list and len(helpers) == len(names), 'prepared helper count differs')
    require({item['path'] for item in helpers} == {str(base / name) for name in names},
            'prepared helper origin closure differs')
    exact_tree(base, set(names) | {'transport_handoff_client.py'})
    for item in helpers:
        copied = inputs.checked_file(Path(item['path']), item)
        require(copied == read_regular(HERE / Path(item['path']).name), 'prepared helper differs from trusted release')
    require(read_regular(base / 'transport_handoff_client.py') == read_regular(HERE / 'transport_handoff_client.py'),
            'prepared client differs from trusted release')
    python = value['python']
    inputs.checked_file(Path(python['path']), python)
    require(Path(python['path']) == Path(sys.executable).resolve(), 'prepared Python executable differs')
    inputs.source_metadata(value)
    root, data = inputs.frozen_content(value)
    require(not path.absolute().is_relative_to(root), 'manifest must be outside content')
    return value, root, data
