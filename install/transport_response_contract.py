#!/usr/bin/env python3
"""Validate only a declarative JSON response shape against an externally held pin.

No verdict proves truth, entailment, task completion, source approval or current
authority. Imported helper/bootstrap bytes, Python and the host remain trusted.
"""

import argparse
from pathlib import Path
import resource
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).absolute().parent))
import transport_response_contract_model as model
from transport_install_support import canonical, read_regular, require, sha
from transport_install_layout import DIGEST

MAX_ERRORS, OUTPUT_BYTES = 16, 32768


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('CLI arguments: ' + message)


def unique_array(value, node):
    if not node['unique']:
        return True
    if node['unique_by'] is not None:
        key = node['unique_by']
        if not all(type(item) is dict and key in item and type(item[key]) is str for item in value):
            return False
        ids = [item[key] for item in value]
    else:
        if not all(item is None or type(item) in (str, int, bool) for item in value):
            return False
        ids = [(type(item).__name__, item) for item in value]
    return len(ids) == len(set(ids))


def children(value, node, path):
    kind = node['type']
    if kind == 'object':
        if type(value) is not dict or set(value) != {name for name, _ in node['fields']}:
            return [], 'OBJECT_TYPE_OR_KEYS'
        return [(index, value[name], path + '.' + name) for name, index in node['fields']], ''
    if type(value) is not list or not node['min_items'] <= len(value) <= node['max_items']:
        return [], 'ARRAY_TYPE_OR_LENGTH'
    if not unique_array(value, node):
        return [], 'ARRAY_UNIQUENESS_OR_ID_TYPE'
    return [(node['items'], item, path + '[' + str(index) + ']') for index, item in enumerate(value)], ''


def scalar(value, node):
    kind = node['type']
    if kind == 'string':
        if type(value) is not str or not node['min_bytes'] <= len(value.encode('utf-8')) <= node['max_bytes']:
            return 'STRING_TYPE_OR_BYTE_LENGTH'
        return '' if node['enum'] is None or value in node['enum'] else 'STRING_ENUM'
    if kind == 'integer':
        return '' if type(value) is int and node['min'] <= value <= node['max'] else 'INTEGER_TYPE_OR_RANGE'
    if kind == 'boolean':
        return '' if type(value) is bool else 'BOOLEAN_TYPE'
    require(kind == 'null', 'unsupported compiled scalar type')
    return '' if value is None else 'NULL_TYPE'


def validate(raw, compiled):
    value = model.safe_json(raw, model.CANDIDATE_BYTES, model.MAX_VALUES)
    nodes, root = compiled
    pending, errors, visited = [(root, value, '$')], [], 0
    for _ in range(model.MAX_VALUES):
        if not pending or len(errors) == MAX_ERRORS:
            break
        index, item, path = pending.pop()
        node = nodes[index]
        visited += 1
        require(len(path) <= 1024, 'validation path bound')
        if node['type'] in ('object', 'array'):
            more, error = children(item, node, path)
            pending.extend(reversed(more))
        else:
            error = scalar(item, node)
        if error:
            errors.append(dict(path=path, code=error))
        require(visited + len(pending) <= model.MAX_VALUES, 'validation value bound')
    require(not pending or bool(errors), 'validation step bound')
    return dict(status='STRUCTURAL_MISMATCH' if errors else 'STRUCTURALLY_CONFORMANT', errors=errors,
                inspection_complete=not pending, errors_truncated=bool(pending), values_visited=visited,
                scope='STRUCTURE_ONLY', semantics='NOT_ASSESSED', source_approval='NOT_ASSESSED',
                task_completion='NOT_ASSESSED', execution_authority='NONE')


def arguments():
    parser = Parser(description=__doc__)
    parser.add_argument('--contract', type=Path, required=True)
    parser.add_argument('--expect-contract-sha256', required=True)
    parser.add_argument('--candidate', type=Path, required=True)
    return parser.parse_args()


def main():
    try:
        resource.setrlimit(resource.RLIMIT_AS, (268435456, 1073741824))
        resource.setrlimit(resource.RLIMIT_CPU, (10, 20))
        resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_BYTES, 33554432))
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 128))
        args = arguments()
        expected = args.expect_contract_sha256
        require(type(expected) is str and DIGEST.fullmatch(expected) is not None, 'externally held contract SHA256 required')
        contract = read_regular(args.contract, model.CONTRACT_BYTES)
        require(sha(contract) == expected, 'externally held contract digest differs')
        compiled = model.compile_contract(contract)
        candidate = read_regular(args.candidate, model.CANDIDATE_BYTES)
        result = validate(candidate, compiled)
        require(read_regular(args.contract, model.CONTRACT_BYTES) == contract
                and read_regular(args.candidate, model.CANDIDATE_BYTES) == candidate, 'contract/candidate changed during validation')
        result.update(schema='transport/response-contract-verdict/1', contract_sha256=expected,
                      candidate_sha256=sha(candidate), candidate_bytes=len(candidate))
        status = 0 if result['status'] == 'STRUCTURALLY_CONFORMANT' else 1
    except (ValueError, OSError, UnicodeError, TypeError, KeyError, MemoryError, RecursionError) as error:
        result = dict(schema='transport/response-contract-verdict/1', status='REFUSED', reason=str(error)[:256],
                      scope='STRUCTURE_ONLY', semantics='NOT_ASSESSED', source_approval='NOT_ASSESSED', execution_authority='NONE')
        status = 2
    raw = canonical(result) + b'\n'
    require(len(raw) <= OUTPUT_BYTES, 'complete verdict including LF exceeds output bound')
    sys.stdout.buffer.write(raw)
    return status


if __name__ == '__main__':
    sys.exit(main())
