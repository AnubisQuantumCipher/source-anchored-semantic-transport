"""Concise artifact receipt; preserves original judgments and first observations."""
import hashlib
import json
from pathlib import Path

OUT = Path('/dev/shm/semantic-transport-source-controls-20261029')


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':'), allow_nan=False).encode('utf-8')


def pin(name):
    path = OUT / name
    raw = path.read_bytes()
    return {'path': str(path), 'bytes': len(raw),
            'sha256': hashlib.sha256(raw).hexdigest()}


original = json.loads((OUT / 'handwritten-expectations.json').read_bytes())
amendment = json.loads((OUT / 'handwritten-amendments.json').read_bytes())
observed = json.loads((OUT / 'stdlib-oracle-first-run.json').read_bytes())
rows = original['cases'] + amendment['cases']
report = {'scope': 'FOCUSED_PRE_IMPLEMENTATION_SOURCE_BLOB_SELECTOR_CONTROLS',
    'classification': 'TESTED_STDLIB_ONLY', 'product_implementation': 'UNINSPECTED_UNRUN',
    'case_count_observed': len(rows), 'oracle_discrepancies': observed['discrepancies'],
    'contract_history': 'Original46 expectations and initial contract bytes preserved. Owner-adopted contract amendments recorded additively in3 further pre-oracle expectations. No expected outcome was rewritten after oracle execution.',
    'case_index': [{'id': row['id'], 'expected': row['expected'],
                    'manual_rationale': row['manual_rationale'], 'raw_body': row['body_raw']} for row in rows],
    'coverage': ['Canonical base64 zero unused pad bits and final-LF pattern-search quirk.',
        'STRICT_UTF8 invalid byte, encoded surrogate, overlong form, truncated sequence, valid supplementary/NUL/replacement scalars.',
        'CANONICAL_JSON -0, literal and decoded duplicate keys, LF/whitespace/key order, escaped surrogate, invalid UTF8, BOM, float token, valid Unicode and scalar root.',
        'Source changed byte, truncated/appended bytes, declared length/digest, opaque invalidUTF8 and finalLF Ids.',
        'Self-bound unequal quote =>DIFFERS; quote length/hash and quote-integrity-before-range.',
        'Half-open slice equality, invalid/reversed/past-end/empty-nonempty-source ranges, empty-source nonprobative equality and nonempty-quote difference.',
        'Amended21-digit canonicalJSON resource lane and reserved Q_RECORDS source alias.'],
    'verified': 'Exact literal source/blob/quote bytes, hashes, strict base64 decoder and canonical reencoding, strict scalar UTF8, bounded canonicalJSON facts and exact byte-slice equality through local stdlib-only observations. Frozen raw candidates and original/amended expectations retain pins.',
    'unproved': ['Product behavior is UNRUN; complete output closed-shape/resource enforcement not evaluated.',
        'No full replay, external pin closure, graph/claim/manifest/reading verification.',
        'No source authentication, currentness, authority, semantic entailment or whole-system proof.'],
    'smallest_sound_next_step': 'Run exact frozen Body bytes and tuple recipes against the reviewed pinned component; retain first complete outputs, compare named refusals and selector statuses, and verify output shape/provenance limits independently.',
    'acceptance_evidence_required': 'Independent contract/code review, immutable implementation and fixture pins, first-output differential receipts, resource/negative controls and applicable static/proof evidence. This fixture result alone is not acceptance.',
    'artifacts': [pin(name) for name in ['pre-oracle-freeze.json', 'pre-oracle-amendments-freeze.json',
        'handwritten-expectations.json', 'handwritten-amendments.json',
        'original-contract-draft01.json', 'amended-contract-frozen.json',
        'stdlib-oracle-first-run.json', 'stdlib-oracle-first-run.log',
        'prepare.py', 'prepare-amendments.py', 'stdlib-oracle.py', 'summarize.py']]}
(OUT / 'report.json').write_bytes(encoded(report))
print(json.dumps({'report': pin('report.json'), 'cases': len(rows)}))
