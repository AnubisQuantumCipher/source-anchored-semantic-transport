"""Bounded portable verification of retained public evidence; no model or decoder execution."""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
CAP, TOTAL, COUNT = 1048576, 4194304, 512
HELD = {
 'trial/preflight/prelaunch-seal.json': '87745adc6a8b05b5533d4cff2f0722f6c3247379850a3b49774d468d00430fa5',
 'trial/receivers/transport/answer.json': 'e496c17a2f2d4eb94fc1744f0590f2685e43cf4a22c484a03376e42b825cfd13',
 'trial/preflight/oracle.json': 'd4ff2d766bdd32c9d0016eedd84433b7a1bc69f202c6533572b93684449d5375',
 'assessment/assessment.json': 'f57394413c88b7ba7362418c47ff5e68462b70f63b83c498356db7ceb97a7927',
 'first-failed/answer.json': '49b301e2ea0345f6757d60a7c556d880aff5706de0155175c017938c8d86deda',
 'observations/independent-postlaunch-review.json': '7a266e206686437cf09b6ac81003d575aab71411245617d2c280f4bc0c3aaf5d'}


def need(ok, reason):
    if type(ok) is not bool or not ok:
        raise ValueError(reason)


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}


def integer(value, expected):
    need(type(value) is int and value == expected, 'EXACT_INTEGER')


def read(path, cap=CAP):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        need(stat.S_ISREG(before.st_mode) and before.st_size <= cap, 'FILE_BOUND_TYPE')
        with os.fdopen(os.dup(descriptor), 'rb') as stream:
            raw = stream.read(cap + 1)
        need(len(raw) == before.st_size, 'FILE_CHANGED_OR_BOUND')
        return raw
    finally:
        os.close(descriptor)


def pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'DUPLICATE_JSON_KEY')
        result[key] = value
    return result


def invalid(unused):
    raise ValueError('NONFINITE_JSON')


def load(raw):
    need(type(raw) is bytes and len(raw) <= CAP, 'JSON_BOUND')
    depth, quoted, escaped = 0, False, False
    for char in raw.decode('utf-8'):
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
            need(depth <= 64, 'JSON_DEPTH')
        elif char in ']}':
            depth -= 1
            need(depth >= 0, 'JSON_STRUCTURE')
    need(depth == 0 and not quoted, 'JSON_TRUNCATED')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def unpack(raw):
    need(type(raw) is bytes and len(raw) <= TOTAL, 'ARCHIVE_BOUND')
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        plain = stream.read(TOTAL + 1)
    need(len(plain) <= TOTAL, 'EXPANSION_BOUND')
    files, total = {}, 0
    with tarfile.open(fileobj=io.BytesIO(plain), mode='r:') as bundle:
        for count, item in enumerate(bundle):
            need(count < COUNT, 'ENTRY_BOUND')
            path = PurePosixPath(item.name)
            need(not path.is_absolute() and '..' not in path.parts and '.' not in path.parts
                 and str(path) == item.name and '\\' not in item.name and len(item.name) <= 256,
                 'UNSAFE_ENTRY')
            need(item.isfile() and not item.issparse() and not item.pax_headers
                 and item.name not in files and 0 <= item.size <= CAP, 'ENTRY_TYPE_OR_DUPLICATE')
            total += item.size
            need(total <= TOTAL, 'PAYLOAD_BOUND')
            stream = bundle.extractfile(item)
            need(stream is not None, 'MISSING_ENTRY')
            with stream:
                value = stream.read(CAP + 1)
            need(len(value) == item.size, 'TRUNCATED_ENTRY')
            files[item.name] = value
    inventory = load(files['_inventory.json'])
    need(set(inventory) == set(files) - {'_inventory.json'}, 'INVENTORY_COVERAGE')
    for name, row in inventory.items():
        need({'bytes': row['bytes'], 'sha256': row['sha256']} == pin(files[name])
             and type(row['bytes']) is int, 'INVENTORY_PIN')
    return files


def held_inputs(files):
    for name, digest in HELD.items():
        need(pin(files[name])['sha256'] == digest, 'HELD_INPUT_CHANGED:' + name)
    seal = load(files['trial/preflight/prelaunch-seal.json'])
    for row in seal['files']:
        if row['type'] == 'file':
            name = 'trial/' + row['path']
            need(pin(files[name]) == {'bytes': row['bytes'], 'sha256': row['sha256']},
                 'PRELAUNCH_FILE_CHANGED:' + name)
    for row in seal['source_files']:
        name = 'source/comparison/receiving/' + Path(row['path']).name
        need(pin(files[name]) == {'bytes': row['bytes'], 'sha256': row['sha256']},
             'PRELAUNCH_SOURCE_CHANGED:' + name)
    return seal


def source_pins(files):
    result = {}
    for name, raw in files.items():
        if name.startswith('source/'):
            relative = name.removeprefix('source/')
            need(read(REPO / relative) == raw, 'CURRENT_SOURCE_CHANGED:' + relative)
            result[relative] = pin(raw)
    need('comparison/receiving/check_answer.py' in result and
         'comparison/receiving/trace_support.py' in result, 'CHECKER_DEPENDENCIES')
    return result


def capture(files, prefix, saved=None):
    report = load(files[prefix + '/report.json'])
    need(report['schema'] == 'transport/handoff-trace-capture/5' and
         report['status'] == 'CAPTURED_NOT_ASSESSED', 'CAPTURE_STATUS')
    allowed = {'report.json'}
    for event in report['events']:
        need(event['kind'] in ('custom_tool_call', 'custom_tool_call_output',
                              'function_call', 'function_call_output'), 'CAPTURE_EVENT_KIND')
        raw = files[prefix + '/' + event['path']]
        need(pin(raw) == {'bytes': event['bytes'], 'sha256': event['sha256']}, 'EVENT_PIN')
        need(load(raw)['payload']['type'] == event['kind'], 'RAW_EVENT_KIND')
        allowed.add(event['path'])
        if 'source' in event:
            row = event['source']
            need(pin(files[prefix + '/' + row['path']]) ==
                 {'bytes': row['bytes'], 'sha256': row['sha256']}, 'TOOL_SOURCE_PIN')
            allowed.add(row['path'])
    need(len(report['final_responses']) == 1, 'FINAL_COUNT')
    final = report['final_responses'][0]
    text = final['text'].encode('utf-8')
    row = final['text_file']
    need(final['plaintext_complete'] is True and files[prefix + '/' + row['path']] == text
         and pin(text) == {'bytes': row['bytes'], 'sha256': row['sha256']}, 'FINAL_BYTES')
    if saved is not None:
        need(text == saved and report['saved_candidate_used_as_final'] is False, 'FINAL_SUBSTITUTED')
        candidate = report['inputs']['candidate']
        need(base64.b64decode(candidate['base64'], validate=True) == saved, 'CANDIDATE_BYTES')
    allowed.add(row['path'])
    actual = {name.removeprefix(prefix + '/') for name in files if name.startswith(prefix + '/')}
    need(actual == allowed, 'UNDECLARED_CAPTURE_FILE')
    for row in report['metadata']:
        need(row['representation'] == 'WHITELISTED_FIELDS_NOT_RAW_RECORD', 'RAW_METADATA')
    models = [row['fields'] for row in report['metadata'] if row['kind'] == 'TURN_MODEL_METADATA']
    need(models == [{'effort': 'high', 'model': 'gpt-6.1-sol'}], 'OBSERVED_MODEL_CHANGED')
    return report


def exact_sources(files):
    oracle = load(files['trial/preflight/oracle.json'])
    need(len(oracle['sources']) == 12, 'SOURCE_SET')
    names = set()
    for row in oracle['sources']:
        name = row['id']
        need(name not in names, 'DUPLICATE_SOURCE')
        names.add(name)
        raw = base64.b64decode(row['raw_base64'], validate=True)
        need(pin(raw)['sha256'] == row['sha256'], 'ORACLE_BYTES')
        for prefix in ('trial/preflight/native-02/source-workspace/sources/',
                       'trial/receivers/transport/source-workspace/sources/'):
            need(files[prefix + name + '.bin'] == raw, 'SOURCE_RECOVERY_CHANGED')
    return oracle


def citations(files):
    sys.path.insert(0, str(REPO / 'comparison/receiving'))
    import check_answer
    answer = files['trial/receivers/transport/answer.json']
    result = check_answer.validate(answer, files['trial/preflight/oracle.json'])
    need(result == load(files['citation-check/stdout']) and result['status'] == 'PASS'
         and result['interpretation'] == 'NOT_ASSESSED', 'CITATION_CHECK_CHANGED')
    integer(result['citation_count'], 11)
    integer(result['required_span_count'], 11)
    return result


def assessment(files):
    report = load(files['assessment/assessment.json'])
    need(report['assessment_state'] ==
         'SOURCE_FINDINGS_RECORDED_WITH_MASKING_LIMITATION_INDEPENDENT_COMPLETION_NOT_ASSERTED'
         and report['independent_completion_claim'] == 'NOT_ASSERTED_DUE_TO_MASKING_LIMITATION'
         and report['benefit_claim'] == 'NONE' and report['aggregate_score'] == 'NOT_DEFINED'
         and report['comparative_result'] == 'NOT_ASSESSED', 'ASSESSMENT_LIMITS')
    need(any(row['id'] == 'L_MASKING_WORKFLOW_DISCLOSURE' for row in report['limitations']),
         'MASKING_LIMITATION_MISSING')
    required, forbidden = [], []
    for obligation in report['obligation_assessments']:
        required.extend(obligation['required_items'])
        forbidden.extend(obligation['forbidden_items'])
    need(all(row['status'] == 'SUPPORTED' for row in required) and
         all(row['status'] == 'NOT_OBSERVED' for row in forbidden), 'ASSESSMENT_FINDINGS')
    return {'required_items': len(required), 'forbidden_items': len(forbidden),
            'state': report['assessment_state'], 'independent_completion': 'NOT_ASSERTED',
            'limitations': report['limitations']}


def failures(files):
    first = load(files['first-failed/answer.json'])
    need(first['evidence'] == [] and 'WORKFLOW_PARENT_PRIVATE' in first['narrative'], 'FIRST_FAILURE')
    need(load(files['trial/preflight/native.stdout'])['reason'] == 'WORKFLOW_VALIDATION_OR_IO',
         'PROFILE_FAILURE_ERASED')
    native = load(files['trial/preflight/native-02/run.json'])
    integer(native['exit_code'], 0)
    need(native['status'] == 'SUCCESS', 'NATIVE_PREFLIGHT')
    review = load(files['observations/independent-postlaunch-review.json'])
    need(any(row['id'] == 'RECEIVER_SIDE_EFFECTING_ASSERT' and row['observed'] is True
             for row in review['findings']), 'ENGINEERING_FINDING_ERASED')
    need(load(files['observations/assessment-capture-scope.json'])['limits_changed'] is False,
         'ASSESSOR_CAPTURE_BOUND')
    return {'first_trial': 'FAILED_RETAINED', 'profile_mismatch': 'FAILED_RETAINED',
            'receiver_utility': 'OBSERVED_ENGINEERING_DISCIPLINE_FAILURE',
            'assessor_capture_first_attempt': 'REFUSED_RETAINED'}


def observations(files):
    seal = held_inputs(files)
    current = source_pins(files)
    oracle = exact_sources(files)
    receiver = capture(files, 'receiver-capture', files['trial/receivers/transport/answer.json'])
    capture(files, 'first-failed/capture', files['first-failed/answer.json'])
    assessor = capture(files, 'assessor-capture')
    return {'source_files': current, 'exact_source_entries': len(oracle['sources']),
            'citations': citations(files), 'assessment': assessment(files), 'failures': failures(files),
            'receiver_metadata': receiver['metadata'], 'assessor_metadata': assessor['metadata'],
            'usage_policy': 'Unaggregated observed records; no summed cumulative token counts.',
            'prelaunch_seal': pin(files['trial/preflight/prelaunch-seal.json']),
            'source_interpretation': 'NOT_PROVED', 'comparative_benefit': 'NOT_ESTABLISHED',
            'public_journal_authentication': 'NOT_ESTABLISHED', 'authority': 'NONE'}


def control_runs(folder):
    rows = []
    for variant in ('normal', 'optimized'):
        record = load(read(folder / ('checks/' + variant + '.json')))
        integer(record['exit_code'], 0)
        for name in ('receipt.py', 'test_receipt.py'):
            need(record['sources'][name] == pin(read(folder / name)), 'TEST_SOURCE_CHANGED')
        for stream in ('stdout', 'stderr'):
            raw = read(folder / ('checks/' + variant + '.' + stream))
            need(record[stream] == pin(raw), 'TEST_CAPTURE_CHANGED')
        stderr = read(folder / ('checks/' + variant + '.stderr')).decode('utf-8')
        need('Ran 24 tests in ' in stderr and stderr.endswith('\nOK\n'), 'TEST_RESULT')
        rows.append(record)
    return rows


def expected(folder=HERE):
    raw = read(folder / 'evidence.tar.gz', TOTAL)
    files = unpack(raw)
    result = observations(files)
    result['portable_controls'] = control_runs(folder)
    result.update(schema='transport/public-receiving-repair-receipt/2', status='CHECKED',
                  archive=pin(raw), archived_files=len(files),
                  archived_payload_bytes=sum(len(value) for value in files.values()))
    result['receipt_sources'] = {name: pin(read(folder / name)) for name in
                                 ('receipt.py', 'test_receipt.py', 'pack_evidence.py', 'README.md')}
    for name in ('share.txt', 'meaning.zip', 'answer.json'):
        location = 'input/content/' + name if name != 'answer.json' else name
        need(read(folder / name) == files['trial/receivers/transport/' + location],
             'VISIBLE_ARTIFACT_CHANGED:' + name)
        result['receipt_sources'][name] = pin(read(folder / name))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    result = expected()
    raw = json.dumps(result, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if args.check:
        need(read(HERE / 'receipt.json') == raw, 'RECEIPT_CHANGED')
    else:
        with (HERE / 'receipt.json').open('xb') as stream:
            need(stream.write(raw) == len(raw), 'SHORT_RECEIPT_WRITE')
    print(json.dumps({'status': 'CHECKED', 'files': result['archived_files'],
                      'archive': result['archive'], 'receipt': pin(raw)}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, EOFError, tarfile.TarError) as error:
        print('REFUSED: ' + str(error)[:240], file=sys.stderr)
        raise SystemExit(1)
