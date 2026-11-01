"""Strict source-roster-bound proof acceptance; not a semantic truth checker."""
import hashlib
import json
import re
from document_build.common import bounded_names, need, read_bytes
from transport_document_io import loads, unique_pairs, no_float

CATEGORIES = ('Data Dependencies', 'Flow Dependencies', 'Initialization', 'Non-Aliasing',
              'Run-time Checks', 'Assertions', 'Functional Contracts', 'LSP Verification',
              'Termination', 'Concurrency')
HEADER = 'SPARK Analysis results Total Flow Provers Justified Unproved'
DETAIL = re.compile(r'^  ([A-Za-z_][A-Za-z_0-9.]*) at (sentinel_policy\.(?:ads|adb)):(\d+) '
                    r'flow analyzed \((\d+) errors, (\d+) checks, (\d+) warnings and '
                    r'(\d+) pragma Assume statements\) and proved \((\d+) checks\)$')


def diagnostics(raw):
    need(len(raw) <= 1048576, 'tool diagnostic bound')
    text = raw.decode('ascii')
    need(not re.search(r'\b(?:warning:|error:|not proved|might fail)', text, re.I),
         'tool warning, error or unproved diagnostic')
    return text


def annotation(match):
    value = match.group(1)
    if re.fullmatch(r'[0-9]{1,3}%', value):
        need(int(value[:-1]) <= 100, 'proof percentage range')
    elif value != 'Z3':
        parts = value.split(', ')
        need(1 <= len(parts) <= 2, 'proof annotation count')
        names = []
        for part in parts:
            row = re.fullmatch(r'(Trivial|Z3) ([0-9]{1,3})%', part)
            need(row is not None and int(row.group(2)) <= 100, 'unsupported prover annotation')
            names.append(row.group(1))
        need(len(names) == len(set(names)), 'duplicate prover annotation')
    return ''


def cells(raw):
    cleaned = re.sub(r'\(([^()]*)\)', annotation, raw)
    parts = cleaned.split()
    need(len(parts) == 5, 'five proof table cells required')
    need(all(part == '.' or re.fullmatch(r'[0-9]{1,8}', part) for part in parts),
         'unsupported proof table cell')
    values = [0 if part == '.' else int(part) for part in parts]
    need(values[0] == sum(values[1:]), 'proof row conservation')
    need(values[3:] == [0, 0], 'justified or unproved checks refused')
    return values


def table(lines):
    headers = [i for i, line in enumerate(lines) if ' '.join(line.split()) == HEADER]
    totals = [i for i, line in enumerate(lines) if re.match(r'^Total\s+', line)]
    need(len(headers) == len(totals) == 1 and headers[0] < totals[0], 'proof header/Total count')
    for name in CATEGORIES:
        places = [i for i, line in enumerate(lines)
                  if line.lstrip() == name or line.lstrip().startswith((name + ' ', name + '\t'))]
        need(len(places) == 1 and headers[0] < places[0] < totals[0],
             'duplicate or misplaced proof category')
    rows = {}
    for line in lines[headers[0] + 1:totals[0]]:
        if not line.strip() or set(line.strip()) == {'-'}:
            continue
        matches = [name for name in CATEGORIES if line.startswith(name + ' ')]
        need(len(matches) == 1, 'unknown proof category')
        name = matches[0]
        need(name not in rows, 'duplicate proof category')
        rows[name] = cells(line[len(name):])
    need(set(rows) == set(CATEGORIES), 'missing proof category')
    total = cells(lines[totals[0]][len('Total'):])
    need(total == [sum(row[i] for row in rows.values()) for i in range(5)],
         'proof category totals disagree')
    need(total[0] > 0 and rows['Functional Contracts'][0] > 0, 'vacuous proof refused')
    return rows, total


def details(lines, roster, total):
    expected = {row['name']: row for row in roster['entities']}
    need(len(expected) == len(roster['entities']) and 1 <= len(expected) <= 64,
         'source entity roster bound or duplicate')
    units = [line for line in lines if line.startswith('in unit ')]
    count = str(len(expected))
    need(units == ['in unit sentinel_policy, ' + count +
                   ' subprograms and packages out of ' + count + ' analyzed'], 'unit coverage mismatch')
    need([line for line in lines if line.startswith('Analyzed ')] == ['Analyzed 1 unit'],
         'exactly one analyzed unit required')
    found = {}
    start = lines.index(units[0]) + 1
    for line in lines[start:]:
        if not line.strip():
            continue
        match = DETAIL.fullmatch(line)
        need(match is not None, 'unknown/truncated detailed proof row')
        name, file, number, errors, checks, warnings, assumes, proved = match.groups()
        need(name in expected and name not in found, 'unexpected or duplicate proof entity')
        row = expected[name]
        need((file, int(number)) == (row['file'], row['line']), 'source coordinate mismatch')
        need([errors, checks, warnings, assumes] == ['0'] * 4, 'unclean detailed flow result')
        need(int(proved) >= row['minimum_proved_checks'], 'source minimum proof obligations missing')
        need(not row.get('explicit_postcondition', False) or int(proved) > 0,
             'postcondition entity has no proved obligations')
        found[name] = int(proved)
    need(set(found) == set(expected), 'missing detailed proof entity')
    need(sum(found.values()) == total[2], 'detailed prover total disagreement')
    return found


def parse_proof(raw, roster):
    text = diagnostics(raw)
    need(roster['unit'] == 'sentinel_policy', 'fixed policy unit required')
    lines = text.splitlines()
    rows, total = table(lines)
    found = details(lines, roster, total)
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'categories': rows,
            'total': total[0], 'flow': total[1], 'prover': total[2],
            'justified': 0, 'unproved': 0, 'warnings': 0, 'assume': 0, 'entities': found,
            'scope': 'EXACT_SUPPLIED_SOURCE_ROSTER_POLICY_CONTRACTS_ONLY'}


def machine_json(raw):
    need(type(raw) is bytes and len(raw) <= 1048576, 'machine diagnostic byte bound')
    text = raw.decode('ascii')
    quoted, escaped, depth = False, False, 0
    for char in text:
        if quoted:
            if escaped:
                escaped = False
            elif char == '\\':
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in '[{':
            depth += 1
            need(depth <= 32, 'machine JSON depth bound')
        elif char in ']}':
            depth -= 1
            need(depth >= 0, 'machine JSON nesting')
    try:
        return json.loads(text, object_pairs_hook=unique_pairs,
            parse_float=lambda _token: 'UNUSED_TIMING_TOKEN', parse_constant=no_float)
    except (ValueError, RecursionError) as error:
        raise ValueError('machine diagnostic JSON refused') from error


def machine_diagnostics(raw, report):
    value = machine_json(raw)
    expected = {'assumptions', 'entities', 'flow', 'pragma_assume', 'progress',
        'proof', 'skip_flow_proof', 'skip_proof', 'spark', 'stop_reason', 'timings', 'warn_error'}
    need(type(value) is dict and set(value) == expected, 'machine diagnostic schema')
    for name in ('entities', 'spark', 'timings'):
        need(type(value[name]) is dict, 'machine map required')
    need(type(value['assumptions']) is list, 'machine modular assumption list')
    need(value['progress'] == 'PROGRESS_PROOF' and value['stop_reason'] == 'STOP_REASON_NONE',
         'machine proof incomplete')
    for name in ('warn_error', 'pragma_assume', 'skip_flow_proof', 'skip_proof'):
        need(type(value[name]) is list and not value[name], 'machine diagnostic or skip refused')
    for name, total in (('proof', report['prover']), ('flow', report['flow'])):
        rows = value[name]
        need(type(total) is int and type(rows) is list and len(rows) <= 4096
             and len(rows) == total, 'machine and text check counts disagree')
        for row in rows:
            need(type(row) is dict and row.get('severity') == 'info'
                 and row.get('suppressed', '') == ''
                 and row.get('how_proved') in ('prover', 'trivial', 'flow'),
                 'unaccepted machine check record')
    count = len(report['entities'])
    need(len(value['entities']) == count and len(value['spark']) == count,
         'machine and source entity counts disagree')
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'proof_records': len(value['proof']),
            'flow_records': len(value['flow']), 'entities': count, 'warn_error_records': 0,
            'scope': 'CONSERVATIVE_MACHINE_DIAGNOSTICS_WITH_TEXT_SOURCE_ROSTER'}


def source_gate(root):
    paths = sorted(bounded_names(root / 'sentinel_native', 16))
    need(1 <= len(paths) <= 16, 'fixed native profile source count')
    result = {}
    for path in paths:
        need(path.suffix in ('.ads', '.adb', '.gpr', '.py', '.md'), 'unsupported native profile entry')
        raw = read_bytes(path, 131072)
        if path.suffix in ('.ads', '.adb'):
            text = re.sub(r'--[^\n]*', '', raw.decode('ascii'))
            need(not re.search(r'\bpragma\s+(Assume|Annotate|Suppress)\b|'
                               r'\bAssertion_Policy\s*\([^)]*\bIgnore\b', text, re.I),
                 'source assumption, justification or suppression refused')
        if path.suffix == '.gpr':
            need(not re.search(rb'-gnat(?:p|ws)\b', raw), 'suppressed compiler checks/warnings')
        result[str(path.relative_to(root))] = hashlib.sha256(raw).hexdigest()
    for name in ('tools/build_sentinel_policy.py', 'tools/transport_document_io.py'):
        entry = root / name
        result[name] = hashlib.sha256(read_bytes(entry, 131072)).hexdigest()
    return result


def checked_roster(root, path, expected_sha):
    raw = read_bytes(path, 1048576)
    need(hashlib.sha256(raw).hexdigest() == expected_sha, 'caller-held proof roster identity mismatch')
    roster = loads(raw)
    need(set(roster) == {'schema', 'status', 'unit', 'sources', 'entities'}, 'proof roster fields')
    need(roster['schema'] == 'sentinel/proof-roster/1' and
         roster['status'] == 'SOURCE_DERIVED_FROZEN_BEFORE_PROVER' and
         roster['unit'] == 'sentinel_policy', 'actual source-derived proof roster required')
    required = {'sentinel_native/sentinel_policy.ads', 'sentinel_native/sentinel_policy.adb',
                'sentinel_native/sentinel_policy.gpr', 'sentinel_native/sentinel_policy_proof.gpr'}
    need(type(roster['sources']) is dict and set(roster['sources']) == required,
         'exact pure policy/GPR source pins required')
    current = source_gate(root)
    need(all(current[name] == digest for name, digest in roster['sources'].items()), 'proof source drift')
    need(type(roster['entities']) is list and 1 <= len(roster['entities']) <= 64, 'source roster entities')
    for row in roster['entities']:
        need(set(row) == {'name', 'file', 'line', 'minimum_proved_checks', 'explicit_postcondition'},
             'source roster entity fields')
        need(type(row['name']) is str and re.fullmatch(r'Sentinel_Policy(?:\.[A-Za-z_0-9]+)?',
             row['name']) is not None, 'source roster entity name')
        need(row['file'] in ('sentinel_policy.ads', 'sentinel_policy.adb') and
             type(row['line']) is int and 1 <= row['line'] <= 65536 and
             type(row['minimum_proved_checks']) is int and 0 <= row['minimum_proved_checks'] <= 1000000 and
             type(row['explicit_postcondition']) is bool, 'source roster entity type/bounds')
        need(not row['explicit_postcondition'] or row['minimum_proved_checks'] >= 1,
             'positive postcondition proof minimum required')
    need(any(row['explicit_postcondition'] for row in roster['entities']), 'no contract-bearing source entities')
    names = [row['name'] for row in roster['entities']]
    need(len(names) == len(set(names)), 'duplicate source proof entity')
    return roster
