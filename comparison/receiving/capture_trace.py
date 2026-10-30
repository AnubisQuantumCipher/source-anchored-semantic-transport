"""Phase-aware bounded capture; observed finals are never inferred from saved drafts."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import resource
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import trace_support as support


def pin(path, cap=1048576):
    data = support.read(path, cap)
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def arguments():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('rollout', 'output', 'candidate', 'interface', 'launch'):
        parser.add_argument('--' + name, required=True, type=Path)
    for name in ('expected-thread', 'expected-parent', 'expected-agent-path'):
        parser.add_argument('--' + name, required=True)
    return parser.parse_args()


def selected(record):
    payload = record.get('payload', {})
    if record.get('type') != 'response_item' or type(payload) is not dict:
        return None
    if payload.get('type') != 'message' or payload.get('role') != 'assistant':
        return None
    channel, phase = payload.get('channel'), payload.get('phase')
    if channel != 'final' and phase != 'final_answer':
        return None
    support.require(channel in (None, 'final') and phase in (None, 'final_answer'),
                    'conflicting final representation')
    timestamp = record.get('timestamp')
    support.require(timestamp is None or (type(timestamp) is str and len(timestamp) <= 128),
                    'final timestamp metadata bound')
    content = payload.get('content', [])
    support.require(type(content) is list and len(content) <= 16, 'final content count bound')
    parts = [item['text'] for item in content if type(item) is dict
             and item.get('type') in ('text', 'output_text') and type(item.get('text')) is str]
    return dict(timestamp=timestamp, text=''.join(parts),
                plaintext_complete=bool(parts) and len(parts) == len(content),
                channel=channel, phase=phase, plaintext_parts=len(parts),
                representation='WHITELISTED_PLAINTEXT_FINAL_PROJECTION')


def final_messages(path, folder):
    stream, before = support.opened(path, support.MAX_FILE)
    result, offset = [], 0
    with stream:
        for number in range(1, support.MAX_LINES + 1):
            raw = stream.readline(support.MAX_LINE + 1)
            if not raw:
                break
            support.require(len(raw) <= support.MAX_LINE and raw.endswith(b'\n'),
                            'final scan line bound or truncated JSONL terminator')
            value = support.parse(raw)
            support.require(type(value) is dict, 'source record must be an object')
            item = selected(value)
            if item is not None:
                support.require(len(result) < 8, 'final response count bound')
                data = item['text'].encode('utf-8')
                item.update(line=number, offset=offset, raw_record_sha256=support.sha(raw),
                            empty_plaintext=not bool(data),
                            text_file=support.write(folder / ('final-%02d.txt' % (len(result) + 1)), data))
                result.append(item)
            offset += len(raw)
        support.require(not stream.read(1), 'final scan line count bound')
        support.require(support.file_state(before) == support.file_state(os.fstat(stream.fileno()))
                        and offset == before.st_size, 'trace changed during final scan')
    return result


def final_state(finals):
    if not finals:
        return 'NO_OBSERVED_FINAL'
    if len(finals) > 1:
        return 'MULTIPLE_OBSERVED_FINALS_NO_SELECTION'
    return ('SINGLE_COMPLETE_PLAINTEXT_FINAL' if finals[0]['plaintext_complete']
            else 'SINGLE_INCOMPLETE_PLAINTEXT_FINAL')


def candidate_snapshot(path):
    try:
        raw = support.read(path, 32768)
    except FileNotFoundError:
        return {'status': 'MISSING', 'bytes': None, 'sha256': None, 'base64': None}
    try:
        valid = type(support.parse(raw, 32768)) is dict
    except (ValueError, TypeError, UnicodeError):
        valid = False
    return {'status': 'JSON_OBJECT' if valid else 'INVALID_JSON_OBJECT',
            'bytes': len(raw), 'sha256': support.sha(raw),
            'base64': base64.b64encode(raw).decode('ascii')}


def trial_inputs(args):
    return dict(candidate=candidate_snapshot(args.candidate),
                interface=pin(args.interface), launch=pin(args.launch))


def capture(args):
    support.require(support.UUID.fullmatch(args.expected_thread) is not None
                    and support.UUID.fullmatch(args.expected_parent) is not None, 'UUID shape')
    rollout = args.rollout.absolute()
    support.require(rollout.is_relative_to(support.SESSION_ROOT)
                    and args.expected_thread in rollout.name, 'explicit child trace required')
    support.require(not args.output.exists() and not args.output.is_symlink()
                    and not args.output.absolute().is_relative_to(support.SESSION_ROOT), 'new external capture required')
    inputs = trial_inputs(args)
    state, events, metadata = support.scan(args, args.output)
    finals = final_messages(rollout, args.output)
    support.require(pin(rollout, support.MAX_FILE)['sha256'] == state['file_after']['sha256'],
                    'trace changed during final capture')
    support.require(inputs == trial_inputs(args), 'trial inputs changed')
    report = dict(schema='transport/handoff-trace-capture/5', status='CAPTURED_NOT_ASSESSED',
                  source=state, events=events, metadata=metadata, final_responses=finals, inputs=inputs,
                  final_capture_state=final_state(finals), final_selection='NONE_ALL_OBSERVATIONS_RETAINED',
                  saved_candidate_used_as_final=False,
                  final_byte_definition='Exact UTF-8 of ordered observed plaintext text parts; no trimming, JSON regeneration or candidate substitution.',
                  launch_plaintext_dispatch='UNKNOWN_PENDING_OBSERVABLE_COMPARISON',
                  usage_policy='Record observations only; cumulative counts are not summed.',
                  limits=['No reasoning or raw turn-context content copied; raw final records are hashed rather than copied.',
                          'Incomplete plaintext and multiple finals require explicit separate protocol assessment.',
                          'Tool/protocol consistency and source fidelity require separate assessment.',
                          'No backend attestation, operating-system isolation or hidden-access guarantee.'])
    support.write(args.output / 'report.json', support.canonical(report) + b'\n')
    return report


def main():
    resource.setrlimit(resource.RLIMIT_AS, (536870912, 536870912))
    resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
    resource.setrlimit(resource.RLIMIT_FSIZE, (4194304, 4194304))
    args = arguments()
    try:
        report = capture(args)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, MemoryError) as error:
        print(json.dumps(dict(status='CAPTURE_REFUSED', reason=str(error)[:256])), file=sys.stderr)
        return 1
    print(json.dumps(dict(status=report['status'], output=str(args.output),
                         final_capture_state=report['final_capture_state'])))
    return 0


if __name__ == '__main__':
    sys.exit(main())
