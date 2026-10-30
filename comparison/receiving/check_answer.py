#!/usr/bin/env python3
"""Bounded source membership and required-span coverage, never interpretation.

The caller authenticates the oracle pin independently. Python, local support and
the host are trusted integration components; source and oracle data execute no
code and grant no authority. API callers supply already admitted oracle bytes.
"""

import argparse
import base64
import hashlib
from pathlib import Path
import re
import resource
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import trace_support as support

ANSWER_CAP, ORACLE_CAP, NARRATIVE_CAP = 32768, 131072, 16384
SOURCE_CAP, COUNT_CAP, OUTPUT_CAP = 65536, 16, 65536
SOURCE_ID = re.compile(r'[A-Z][A-Z0-9_]{0,31}\Z')
DIGEST = re.compile(r'[0-9a-f]{64}\Z')


def require(condition, reason):
    if type(condition) is not bool or not condition:
        raise ValueError(reason)


def fields(value, names, label):
    require(type(value) is dict and set(value) == set(names), label + '_FIELDS')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def text(value, cap, label):
    require(type(value) is str, label + '_TYPE')
    raw = value.encode('utf-8', errors='strict')
    require(0 < len(raw) <= cap, label + '_BYTES')
    return raw


def digest(value, label):
    require(type(value) is str and DIGEST.fullmatch(value) is not None,
            label + '_DIGEST')
    return value


def source_record(value):
    fields(value, ('id', 'revision', 'raw_base64', 'sha256'), 'ORACLE_SOURCE')
    name = value['id']
    require(type(name) is str and SOURCE_ID.fullmatch(name) is not None,
            'ORACLE_SOURCE_ID')
    text(value['revision'], 256, 'ORACLE_REVISION')
    encoded = value['raw_base64']
    require(type(encoded) is str and len(encoded) <= ORACLE_CAP,
            'ORACLE_BASE64_BOUND')
    raw = base64.b64decode(encoded.encode('ascii'), validate=True)
    require(len(raw) <= SOURCE_CAP and base64.b64encode(raw).decode('ascii') == encoded,
            'ORACLE_BASE64_CANONICAL_OR_SOURCE_BOUND')
    require(sha(raw) == digest(value['sha256'], 'ORACLE_SOURCE'), 'ORACLE_SOURCE_HASH')
    return name, dict(revision=value['revision'], sha256=value['sha256'], raw=raw)


def span(value, sources, label):
    name, begin, end = value['source'], value['begin'], value['end']
    require(type(name) is str and name in sources, label + '_SOURCE')
    require(type(begin) is int and type(end) is int
            and 0 <= begin < end <= len(sources[name]['raw']), label + '_SPAN')
    selected = sources[name]['raw'][begin:end]
    selected.decode('utf-8', errors='strict')
    return name, begin, end, selected


def oracle(raw):
    value = support.parse(raw, ORACLE_CAP)
    fields(value, ('schema', 'sources', 'required_spans', 'obligations'), 'ORACLE')
    require(value['schema'] == 'transport/source-handoff-oracle/1', 'ORACLE_SCHEMA')
    entries = value['sources']
    require(type(entries) is list and 1 <= len(entries) <= COUNT_CAP, 'ORACLE_SOURCE_COUNT')
    require(type(value['obligations']) is list, 'ORACLE_OBLIGATIONS_DATA')
    sources, total = {}, 0
    for item in entries:
        name, record = source_record(item)
        require(name not in sources, 'ORACLE_DUPLICATE_SOURCE_ID')
        total += len(record['raw'])
        require(total <= SOURCE_CAP, 'ORACLE_AGGREGATE_SOURCE_BYTES')
        sources[name] = record
    required, seen = value['required_spans'], set()
    require(type(required) is list and len(required) <= COUNT_CAP, 'ORACLE_REQUIRED_COUNT')
    for item in required:
        fields(item, ('source', 'begin', 'end'), 'ORACLE_REQUIRED')
        name, begin, end, _ = span(item, sources, 'ORACLE_REQUIRED')
        key = name, begin, end
        require(key not in seen, 'ORACLE_DUPLICATE_REQUIRED_SPAN')
        seen.add(key)
    return sources, required


def citation(value, sources, seen):
    fields(value, ('source', 'revision', 'source_sha256', 'begin', 'end', 'quote'), 'CITATION')
    name, begin, end, selected = span(value, sources, 'CITATION')
    record = sources[name]
    require(type(value['revision']) is str and value['revision'] == record['revision'],
            'CITATION_REVISION')
    require(digest(value['source_sha256'], 'CITATION') == record['sha256'],
            'CITATION_SOURCE_HASH')
    require(text(value['quote'], SOURCE_CAP, 'CITATION_QUOTE') == selected,
            'CITATION_QUOTE_MISMATCH')
    key = name, begin, end
    require(key not in seen, 'CITATION_DUPLICATE_SPAN')
    seen.add(key)
    return dict(source=name, revision=record['revision'], begin=begin, end=end)


def validate(answer_bytes, oracle_bytes):
    """Return byte-membership and complete-containing-span results or refuse."""
    sources, required = oracle(oracle_bytes)
    answer = support.parse(answer_bytes, ANSWER_CAP)
    fields(answer, ('schema', 'narrative', 'evidence'), 'ANSWER')
    require(answer['schema'] == 'transport/source-handoff-answer/1', 'ANSWER_SCHEMA')
    text(answer['narrative'], NARRATIVE_CAP, 'NARRATIVE')
    evidence, seen = answer['evidence'], set()
    require(type(evidence) is list and 1 <= len(evidence) <= COUNT_CAP, 'EVIDENCE_COUNT')
    citations = [citation(item, sources, seen) for item in evidence]
    missing = []
    for item in required:
        revision = sources[item['source']]['revision']
        covered = any(link['source'] == item['source'] and link['revision'] == revision
                      and link['begin'] <= item['begin'] and item['end'] <= link['end']
                      for link in citations)
        if not covered:
            missing.append(dict(source=item['source'], revision=revision,
                                begin=item['begin'], end=item['end']))
    return dict(schema='transport/source-handoff-check/1',
        status='PASS' if not missing else 'MISSING_REQUIRED_EVIDENCE',
        source_membership='PASS', required_evidence='COMPLETE' if not missing else 'MISSING',
        missing_spans=missing, interpretation='NOT_ASSESSED', authority='NONE',
        answer_sha256=sha(answer_bytes), oracle_sha256=sha(oracle_bytes),
        citation_count=len(citations), required_span_count=len(required))


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('CLI_ARGUMENTS: ' + message[:160])


def arguments():
    parser = Parser(description=__doc__)
    parser.add_argument('--answer', type=Path, required=True)
    parser.add_argument('--oracle', type=Path, required=True)
    parser.add_argument('--expect-oracle-sha256', required=True)
    return parser.parse_args()


def limits():
    for kind, bound in ((resource.RLIMIT_AS, 268435456), (resource.RLIMIT_CPU, 30),
                        (resource.RLIMIT_FSIZE, 4194304), (resource.RLIMIT_NOFILE, 64)):
        _, hard = resource.getrlimit(kind)
        require(hard == resource.RLIM_INFINITY or hard >= bound, 'HOST_LIMIT_TOO_NARROW')
        resource.setrlimit(kind, (bound, bound))


def main():
    try:
        limits()
        args = arguments()
        expected = digest(args.expect_oracle_sha256, 'HELD_ORACLE')
        held = support.read(args.oracle, ORACLE_CAP)
        require(sha(held) == expected, 'HELD_ORACLE_MISMATCH')
        answer = support.read(args.answer, ANSWER_CAP)
        result = validate(answer, held)
        code = 0 if result['status'] == 'PASS' else 1
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, MemoryError,
            OverflowError, RecursionError) as error:
        result = dict(schema='transport/source-handoff-check/1', status='REFUSED',
            reason=str(error)[:256], source_membership='NOT_ESTABLISHED',
            required_evidence='NOT_ESTABLISHED', interpretation='NOT_ASSESSED', authority='NONE')
        code = 1
    raw = support.canonical(result) + b'\n'
    require(len(raw) <= OUTPUT_CAP, 'CHECKER_OUTPUT_BOUND')
    require(sys.stdout.buffer.write(raw) == len(raw), 'CHECKER_SHORT_OUTPUT')
    sys.stdout.buffer.flush()
    return code


if __name__ == '__main__':
    sys.exit(main())
