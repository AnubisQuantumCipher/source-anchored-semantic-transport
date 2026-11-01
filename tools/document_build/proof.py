"""Fail-closed parser for the fixed document-frame-ledger proof profile."""
import hashlib
import re
from .common import need, read_bytes

EXPECTED = {'Document_Frame_Ledger': 0, 'Document_Frame_Ledger.Accept_Frame': 3,
            'Document_Frame_Ledger.Admissible': 0, 'Document_Frame_Ledger.Complete': 0,
            'Document_Frame_Ledger.Initialize': 1, 'Document_Frame_Ledger.Next_Length': 1,
            'Document_Frame_Ledger.Required_Frames': 1, 'Document_Frame_Ledger.Valid': 0}


def source_gate(root):
    pins = {}
    for name in ('document_frame_ledger.ads', 'document_frame_ledger.adb'):
        raw = read_bytes(root / 'document_native' / name)
        text = re.sub(r'--[^\n]*', '', raw.decode('ascii'))
        need(not re.search(r'\bpragma\s+(Assume|Annotate|Suppress)\b', text, re.I),
             'assumption, justification or assertion suppression refused')
        pins[name] = hashlib.sha256(raw).hexdigest()
    return pins


def parse_proof(raw):
    need(len(raw) <= 1_048_576, 'proof summary byte bound')
    text = raw.decode('ascii')
    totals = re.findall(r'^Total\s+(.+)$', text, re.M)
    need(len(totals) == 1, 'exactly one proof total required')
    cells = re.sub(r'\([^)]*\)', '', totals[0]).split()
    need(cells == ['16', '10', '6', '.', '.'], 'exact 16/10/6/0/0 proof total required')
    units = re.findall(r'^in unit ([a-z_]+), (\d+) subprograms and packages out of (\d+) analyzed$', text, re.M)
    need(units == [('document_frame_ledger', '8', '8')], 'exact ledger unit/full coverage required')
    need(re.findall(r'^Analyzed (\d+) unit$', text, re.M) == ['1'], 'one analyzed ledger unit required')
    rows = re.findall(r'^  (Document_Frame_Ledger(?:\.[A-Za-z_]+)?) at document_frame_ledger\.(?:ads|adb):\d+ '
                      r'flow analyzed \(0 errors, 0 checks, 0 warnings and 0 pragma Assume statements\) '
                      r'and proved \((\d+) checks\)$', text, re.M)
    need(len(rows) == 8 and len(dict(rows)) == 8, 'complete clean proof details required')
    need({name: int(count) for name, count in rows} == EXPECTED, 'exact subprogram proof counts required')
    need(not re.search(r'\b(?:warning:|error:|not proved|might fail)', text, re.I), 'proof diagnostic refused')
    return {'sha256': hashlib.sha256(raw).hexdigest(), 'total_row': totals[0],
            'total': 16, 'flow': 10, 'prover': 6, 'justified': 0, 'unproved': 0,
            'warnings': 0, 'assume': 0, 'units': ['document_frame_ledger'], 'details': dict(rows)}


def proof_summary(work):
    report = parse_proof(read_bytes(work / 'proof/gnatprove/gnatprove.out', 1_048_576))
    for name in ('build.stdout', 'build.stderr', 'proof.stdout', 'proof.stderr'):
        text = read_bytes(work / name).decode('utf8', 'replace')
        need(not re.search(r'\b(?:warning:|error:)', text, re.I), 'tool warning/error: ' + name)
    return report
