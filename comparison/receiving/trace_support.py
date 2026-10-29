#!/usr/bin/env python3
"""Capture selected, lineage-checked Source-Anchored Semantic Transport tool events."""

import argparse
import base64
import hashlib
import json
import math
import os
import re
import resource
import stat
from pathlib import Path

MAX_FILE = 33_554_432
MAX_LINE = 1_048_576
MAX_LINES = 32_768
MAX_TOOLS = 256
MAX_OUTPUTS = 512
SESSION_ROOT = Path('/home/sicarii/.codex/sessions')
UUID = re.compile(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\Z')
CALLS = {'function_call', 'custom_tool_call'}
OUTPUTS = {'function_call_output', 'custom_tool_call_output'}
MODEL_KEYS = {'model', 'model_provider', 'model_slug', 'reasoning_effort', 'effort'}
USAGE_KEYS = {'input_tokens', 'cached_input_tokens', 'output_tokens', 'reasoning_output_tokens',
              'total_tokens', 'input_token_count', 'output_token_count'}
GROUP_KEYS = {'total_token_usage', 'last_token_usage', 'usage', 'token_usage',
              'thread_token_usage', 'turn_token_usage'}
MAX_COUNTER = 9223372036854775807


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise ValueError(reason)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: object) -> bytes:
    data = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'),
                      allow_nan=False).encode('ascii')
    require(len(data) <= 4 * MAX_LINE, 'report output bound exceeded')
    return data


def pairs(items: list) -> dict:
    require(len(items) <= 1024 and len(dict(items)) == len(items), 'duplicate/excess JSON fields')
    return dict(items)


def parse(data: bytes, cap: int = MAX_LINE) -> object:
    require(type(data) is bytes and len(data) <= cap, 'JSON byte bound exceeded')
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            require(depth <= 64, 'JSON depth bound exceeded')
        elif byte in (93, 125):
            depth -= 1
            require(depth >= 0, 'malformed JSON depth')
    require(not quoted and depth == 0, 'incomplete JSON framing')
    return json.loads(data.decode('utf-8'), object_pairs_hook=pairs,
                      parse_constant=lambda value: require(False, 'nonfinite JSON constant'))


def opened(path: Path, cap: int):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_size > cap:
        os.close(descriptor)
        raise ValueError('regular file or file byte bound failure')
    return os.fdopen(descriptor, 'rb'), info


def read(path: Path, cap: int) -> bytes:
    stream, _ = opened(path, cap)
    with stream:
        data = stream.read(cap + 1)
    require(len(data) <= cap, 'bounded file grew while reading')
    return data


def write(path: Path, data: bytes) -> dict:
    require(len(data) <= 4 * MAX_LINE, 'output byte bound exceeded')
    with path.open('xb') as stream:
        require(stream.write(data) == len(data), 'short output write')
        stream.flush()
        os.fsync(stream.fileno())
    require(read(path, 4 * MAX_LINE) == data, 'output readback mismatch')
    return {'path': path.name, 'bytes': len(data), 'sha256': sha(data)}


def file_state(info) -> dict:
    return {'device': info.st_dev, 'inode': info.st_ino, 'bytes': info.st_size,
            'mtime_ns': info.st_mtime_ns, 'ctime_ns': info.st_ctime_ns}


def lineage(first: bytes, args) -> dict:
    value = parse(first)
    require(type(value) is dict and value.get('type') == 'session_meta', 'first record must be session_meta')
    payload = value.get('payload')
    require(type(payload) is dict and payload.get('id') == args.expected_thread, 'thread identity mismatch')
    source = payload.get('source', {})
    require(type(source) is dict and type(source.get('subagent')) is dict, 'missing subagent source')
    spawn = source['subagent'].get('thread_spawn')
    require(type(spawn) is dict and spawn.get('parent_thread_id') == args.expected_parent,
            'parent identity mismatch')
    require(spawn.get('agent_path') == args.expected_agent_path, 'agent path mismatch')
    return {'thread_id': payload['id'], 'parent_thread_id': spawn['parent_thread_id'],
            'agent_path': spawn['agent_path'], 'identity_status': 'OBSERVED_RECORD_MATCH_ONLY'}


def metadata_string(value, field, cap, nullable=False):
    require((nullable and value is None) or
            (type(value) is str and 0 < len(value) <= cap),
            'recognized string/bound: ' + field)
    return value


def metadata_integer(value, field, nullable=False):
    require((nullable and value is None) or
            (type(value) is int and 0 <= value <= MAX_COUNTER),
            'recognized numeric value: ' + field)
    return value


def lifecycle_time(value, field):
    """Preserve typed observations; infer no units or timestamp conversion."""
    if type(value) is int:
        return metadata_integer(value, field)
    return metadata_string(value, field, 128, True)


def session_metadata(payload):
    fields = {key: metadata_string(payload[key], key, 256)
              for key in ('id', 'session_id', 'cli_version') if key in payload}
    if 'timestamp' in payload:
        fields['timestamp'] = metadata_string(payload['timestamp'], 'timestamp', 128, True)
    return {'kind': 'SESSION_METADATA', 'fields': fields}


def lifecycle_metadata(record, payload):
    fields = {'type': payload['type']}
    for key in ('started_at', 'completed_at'):
        if key in payload:
            fields[key] = lifecycle_time(payload[key], key)
    for key in ('duration_ms', 'time_to_first_token_ms'):
        if key in payload:
            fields[key] = metadata_integer(payload[key], key, True)
    if 'timestamp' in record:
        fields['timestamp'] = metadata_string(record['timestamp'], 'timestamp', 128, True)
    return {'kind': 'TASK_LIFECYCLE_METADATA', 'fields': fields}


def usage_group(value, field):
    require(value is None or type(value) is dict, 'recognized usage group: ' + field)
    if value is None:
        return None
    return {key: metadata_integer(value[key], field + '.' + key)
            for key in USAGE_KEYS if key in value}


def usage_metadata(payload):
    containers = [('', payload)]
    if 'info' in payload:
        require(payload['info'] is None or type(payload['info']) is dict,
                'recognized usage container: info')
        if payload['info'] is not None:
            containers.append(('info.', payload['info']))
    fields = {}
    for prefix, container in containers:
        for key in USAGE_KEYS | GROUP_KEYS:
            if key in container:
                require(key not in fields, 'ambiguous usage container: ' + key)
                fields[key] = (usage_group(container[key], prefix + key) if key in GROUP_KEYS
                               else metadata_integer(container[key], prefix + key))
    return {'kind': 'OBSERVED_USAGE_RECORD', 'fields': fields, 'aggregation': 'NONE'}


def whitelisted_metadata(record: dict) -> dict | None:
    outer, payload = record.get('type'), record.get('payload', {})
    if type(payload) is not dict:
        return None
    if outer == 'session_meta':
        return session_metadata(payload)
    if outer == 'turn_context':
        fields = {key: metadata_string(payload[key], key, 256)
                  for key in MODEL_KEYS if key in payload}
        return {'kind': 'TURN_MODEL_METADATA', 'fields': fields} if fields else None
    kind = payload.get('type')
    if outer == 'event_msg' and kind in ('task_started', 'task_complete'):
        return lifecycle_metadata(record, payload)
    if ((outer in ('token_usage_record', 'token_count') and kind in (None, outer))
            or (outer == 'event_msg' and kind == 'token_count')):
        return usage_metadata(payload)
    return None


def save_tool(folder: Path, raw: bytes, payload: dict, offset: int, number: int, prefix: str) -> dict:
    kind = payload['type']
    target = folder / ('line-' + format(number, '06d') + '.jsonl')
    record = dict(write(target, raw), line=number, offset=offset, prefix_sha256=prefix,
                  kind=kind, call_id=payload.get('call_id'), name=payload.get('name'))
    if kind in CALLS:
        value = payload.get('input') if kind == 'custom_tool_call' else payload.get('arguments')
        record['value'] = value
        if type(value) is str:
            record['source'] = write(folder / ('line-' + format(number, '06d') + '.source.txt'), value.encode('utf-8'))
    else:
        record['value'] = payload.get('output')
        if type(record['value']) is str:
            record['decoded_output'] = write(folder / ('line-' + format(number, '06d') + '.output.txt'),
                                             record['value'].encode('utf-8'))
    return record


def scan(args, folder: Path) -> tuple[dict, list, list]:
    stream, before = opened(args.rollout, MAX_FILE)
    events, metadata, digest, offset = [], [], hashlib.sha256(), 0
    with stream:
        first = stream.readline(MAX_LINE + 1)
        require(0 < len(first) <= MAX_LINE, 'first line bound')
        identity = lineage(first, args)
        folder.mkdir(mode=0o700)
        digest.update(first)
        offset = len(first)
        initial = whitelisted_metadata(parse(first))
        metadata.append(dict(initial, line=1, offset=0,
                             representation='WHITELISTED_FIELDS_NOT_RAW_RECORD'))
        for number in range(2, MAX_LINES + 1):
            raw = stream.readline(MAX_LINE + 1)
            if not raw:
                break
            require(len(raw) <= MAX_LINE and offset + len(raw) <= MAX_FILE, 'trace byte/line bound')
            record = parse(raw)
            require(type(record) is dict, 'trace record must be an object')
            payload = record.get('payload', {})
            if record.get('type') == 'response_item' and type(payload) is dict and payload.get('type') in CALLS | OUTPUTS:
                require(len(events) < MAX_TOOLS + MAX_OUTPUTS, 'tool event count bound')
                events.append(save_tool(folder, raw, payload, offset, number, digest.hexdigest()))
            else:
                selected = whitelisted_metadata(record)
                if selected is not None:
                    require(selected['kind'] != 'SESSION_METADATA', 'duplicate session metadata')
                    require(len(metadata) < 256, 'metadata event count bound')
                    metadata.append(dict(selected, line=number, offset=offset,
                                         representation='WHITELISTED_FIELDS_NOT_RAW_RECORD'))
            digest.update(raw)
            offset += len(raw)
        require(not stream.read(1), 'trace line count bound')
        after_scan = file_state(os.fstat(stream.fileno()))
    require(file_state(before) == after_scan and offset == before.st_size, 'trace changed during capture')
    after_data = read(args.rollout, MAX_FILE)
    after_info = args.rollout.stat(follow_symlinks=False)
    require(file_state(before) == file_state(after_info) and sha(after_data) == digest.hexdigest(),
            'trace changed after capture')
    state = dict(identity, source_path=str(args.rollout), file_before=dict(file_state(before), sha256=digest.hexdigest()),
                 file_after=dict(file_state(after_info), sha256=sha(after_data)))
    return state, events, metadata

