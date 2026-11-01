"""Host-pinned, read-only access to retained verification observations.

This adapter neither validates an archive nor establishes current key status.
Startup policy is supplied by the host; document/tool content cannot extend it.
"""
import os
from pathlib import Path

from sentinel_v1.common import (JOB_BYTES, METADATA, digest, fields,
    hash_checked, integer, parse, pin_checked, require)
from sentinel_v1.workflow_host import WorkflowHost, selected_parent
from sentinel_v1.workflow_store import file_checked, identifier, root_descriptor, snapshot
import transport_document as codec
import transport_document_io as document_io

ADMISSION_BYTES = 65536
REGISTRATIONS = 16
FIELDS = {
    'receive_verified': ('registration_id', 'admission_sha256'),
    'read_verified': ('registration_id', 'admission_sha256', 'start', 'end'),
}


def admission_bytes(path, held):
    """Read the exact hashed descriptor, with all ancestor symlinks refused."""
    hash_checked(held)
    parent = selected_parent(path)
    descriptor = None
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            | os.O_CLOEXEC, dir_fd=parent)
        before = os.fstat(descriptor)
        file_checked(before, ADMISSION_BYTES)
        pieces, count = [], 0
        for _ in range(ADMISSION_BYTES + 1):
            piece = os.read(descriptor, ADMISSION_BYTES + 1 - count)
            if not piece:
                break
            count += len(piece)
            require(count <= ADMISSION_BYTES, 'endpoint admission byte bound')
            pieces.append(piece)
        require(snapshot(before) == snapshot(os.fstat(descriptor))
            and count == before.st_size, 'endpoint admission changed')
        raw = b''.join(pieces)
        require(digest(raw) == held, 'endpoint admission identity')
        return raw
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def admission_checked(raw, root):
    value = parse(raw, ADMISSION_BYTES)
    fields(value, ('schema', 'root', 'native', 'decoder_runtime_sha256', 'registrations'))
    require(value['schema'] == 'sentinel/workflow-endpoint-admission/1'
        and value['root'] == str(root), 'endpoint admission root or version')
    require(type(value['native']) is str and len(os.fsencode(value['native'])) <= 4096,
            'endpoint native path type or bound')
    native = Path(value['native'])
    require(native.is_absolute() and '..' not in native.parts
        and len(native.parts) <= 256, 'endpoint explicit native path')
    hash_checked(value['decoder_runtime_sha256'])
    registrations = value['registrations']
    require(type(registrations) is dict and 1 <= len(registrations) <= REGISTRATIONS,
            'endpoint registration count')
    for name, registration in registrations.items():
        identifier(name)
        fields(registration, ('input_id', 'input', 'receipt'))
        identifier(registration['input_id'])
        for key in ('input', 'receipt'):
            pin_checked(registration[key])
            integer(registration[key]['bytes'], 1, METADATA)
    return value


def checked_arguments(operation, arguments):
    require(operation in FIELDS, 'endpoint operation')
    fields(arguments, FIELDS[operation])
    identifier(arguments['registration_id'])
    hash_checked(arguments['admission_sha256'])
    if operation == 'read_verified':
        integer(arguments['start'], 0, 2 ** 63 - 1)
        integer(arguments['end'], arguments['start'] + 1, 2 ** 63 - 1)
        require(arguments['end'] - arguments['start'] <= JOB_BYTES, 'endpoint span bound')
    return dict(arguments)


class Endpoint:
    """One immutable admission snapshot; each operation rechecks retained objects."""

    def __init__(self, root, admission, held):
        raw = admission_bytes(admission, held)
        value = admission_checked(raw, root)
        descriptor = root_descriptor(root)
        os.close(descriptor)
        self._raw, self._held = raw, held
        self.host = WorkflowHost(root, Path(value['native']))
        self._runtime(value)

    def _runtime(self, value):
        current = digest(document_io.canonical(codec.runtime(self.host.native)))
        require(current == value['decoder_runtime_sha256'], 'endpoint runtime identity')

    def call(self, operation, arguments):
        arguments = checked_arguments(operation, arguments)
        require(arguments['admission_sha256'] == self._held, 'endpoint admission mismatch')
        value = parse(self._raw, ADMISSION_BYTES)
        registrations = value['registrations']
        name = arguments['registration_id']
        require(name in registrations, 'endpoint registration not admitted')
        registration = registrations[name]
        self._runtime(value)
        receipt = self.host.inspect_registration(registration)
        require(receipt['decoder_runtime_sha256'] == value['decoder_runtime_sha256'],
                'endpoint receipt runtime mismatch')
        if operation == 'receive_verified':
            result = self._summary(registration, receipt)
        else:
            result = self.host.read(registration, arguments['start'], arguments['end'])
        self._runtime(value)
        result.update(admission_sha256=self._held, registration_id=name,
            claim_scope='RETAINED_HOST_OBSERVATION_NOT_INDEPENDENT_ATTESTATION',
            current_revocation='NOT_RECHECKED')
        return result

    def _summary(self, registration, receipt):
        return {'schema': 'sentinel/workflow-retained-receiving/1',
            'status': 'RETAINED_VERIFIED_READING_AVAILABLE', 'registration': registration,
            'source_verification': receipt, 'reading_bytes': receipt['reading']['bytes'],
            'max_selected_bytes': JOB_BYTES,
            'reconstruction': 'SOURCE_READING_AVAILABLE_NARRATION_NOT_PERFORMED',
            'verification_scope': 'RETAINED_VERIFIED_READING_BYTES_CURRENT_SIGNATURE_NOT_RECHECKED',
            'context_closure': 'NOT_CHECKED', 'qualification': 'NOT_QUALIFIED',
            'semantic_completeness': 'UNPROVEN', 'context_adequacy': 'UNPROVEN',
            'execution_authority': 'NONE'}
