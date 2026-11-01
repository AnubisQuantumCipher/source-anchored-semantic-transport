"""Compile and execute contract-enabled boundary checks for the pure ledger."""
import hashlib
import json
import time
import qualify_native as qualify


def main():
    attempt = qualify.OUT / 'ledger-controls01'
    attempt.mkdir()
    mapping = qualify.sources(attempt / 'sources.zip')
    environment = qualify.environment(attempt)
    start = time.monotonic()
    build = ['gprbuild', '-P', str(qualify.ROOT / 'document_checks.gpr'), '-j1']
    records = []
    try:
        records.append(qualify.invoke(build, 120, start + 450, attempt,
                                      'build', environment))
        command = [str(attempt / 'bin/document_ledger_checks')]
        records.append(qualify.invoke(command, 60, start + 450, attempt,
                                      'checks', environment))
    finally:
        after = {p: hashlib.sha256((qualify.ROOT.parent / p).read_bytes()).hexdigest()
                 for p in mapping}
        receipt = {'sources': mapping, 'sources_unchanged': mapping == after,
                   'records': records, 'footprint': qualify.footprint()}
        (attempt / 'receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if mapping != after:
        raise ValueError('ledger test source changed')
    print('PASS: contract-enabled ledger boundary controls')


if __name__ == '__main__':
    main()
