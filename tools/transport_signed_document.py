"""Strict signed adapter; authenticated endorsement bytes are not semantic truth.

Only ZIP structure and manifest.json payload are read before native verification.
This is a logical entry-read boundary, not a statement about OS read-ahead.
Existing legacy transports remain separate and unmodified.
"""
from contextlib import contextmanager
import io
import os
from pathlib import Path
import sys
import tempfile
import zipfile

import transport_document as legacy
import transport_document_archive as archive_module
import transport_cli as publication
from manifest_signing import manifest as signing
from transport_document_io import (DocumentError, MAX_ARCHIVE, MAX_FRAMES, MAX_SOURCE,
    FRAME_SOURCE, canonical, digest, fields, file_digest, identity, integer,
    loaded_epoch, need, open_regular, pin, read_file, sha, write_new)

PROFILE = 'transport/signed-document-manifest/1'
MAX_SIGNED_METADATA = 8_388_608
MANIFEST_FIELDS = ('schema', 'transport', 'declared_reading')


def source_current():
    need(file_digest(__file__, MAX_SIGNED_METADATA)[0] == SOURCE_EPOCH,
         'signed adapter source changed after import')
    need(file_digest(publication.__file__, MAX_SIGNED_METADATA)[0] == PUBLICATION_EPOCH,
         'atomic publication helper changed after import')


def signed_manifest_checked(value):
    fields(value, MANIFEST_FIELDS)
    need(value['schema'] == PROFILE, 'signed document schema required; no downgrade')
    wrapper = value['transport']; fields(wrapper, ('body', 'package_id'))
    sha(wrapper['package_id'])
    need(digest(canonical(wrapper['body'])) == wrapper['package_id'], 'signed legacy body identity')
    legacy.body_checked(wrapper['body'])
    declaration = value['declared_reading']; body = wrapper['body']
    if declaration is None:
        need(body['reading'] is None, 'reading declaration missing')
    else:
        fields(declaration, ('record_pin', 'unit_count', 'claim_status', 'semantic_record_pin'))
        need(body['reading'] is not None, 'undeclared legacy reading')
        record_pin = declaration['record_pin']; fields(record_pin, ('bytes', 'sha256'))
        integer(record_pin['bytes'], 1, MAX_SIGNED_METADATA); sha(record_pin['sha256'])
        need(record_pin == body['entries']['reading.json'], 'signed reading record pin differs from body')
        integer(declaration['unit_count'], 0, legacy.reading_module.MAX_SEGMENTS)
        need(declaration['claim_status'] == 'DECLARED_UNPROVEN', 'reading truth claim unsupported')
        need(declaration['semantic_record_pin'] is None, 'semantic artifact delivery unsupported in strict profile1')
    return wrapper, declaration


def declared_record_checked(declaration, record):
    if declaration is None:
        need(record == legacy.reading_module.EMPTY, 'signed reading record missing')
    else:
        need(pin(canonical(record)) == declaration['record_pin'], 'signed complete reading record mismatch')
        need(len(record['segments']) == declaration['unit_count'], 'signed reading unit count mismatch')


def authenticated(raw, provider, public_key, registry_id, current_revocation):
    source_current()
    need(type(raw) is bytes and 0 < len(raw) <= MAX_SIGNED_METADATA, 'signed envelope byte bound')
    value = signing.verify_envelope(raw, provider, public_key, registry_id, current_revocation)
    wrapper, declaration = signed_manifest_checked(value)
    preimage = signing.signing_preimage(signing.parse(raw))
    return wrapper, declaration, digest(preimage)


def signed_share_for(envelope_raw, formula, reference):
    """Construct canonical pairing bytes; this function does not authenticate them."""
    envelope = signing.validate(signing.parse(envelope_raw))
    signed_manifest_checked(envelope['manifest'])
    need(type(formula) is str and 0 < len(formula.encode('utf-8')) <= MAX_SIGNED_METADATA,
         'signed formula byte bound')
    need(all(ord(c) >= 32 and ord(c) != 127 for c in formula), 'signed formula line')
    legacy.text(reference, 2048)
    identifier = digest(signing.signing_preimage(envelope))
    raw = (formula + '\nSTSD1:' + identifier + '\nPKG:' + reference + '\n').encode('utf-8')
    need(len(raw) <= MAX_SIGNED_METADATA, 'complete signed share byte bound')
    return raw


def share_checked(raw, held, identifier):
    sha(held)
    need(type(raw) is bytes and 0 < len(raw) <= MAX_SIGNED_METADATA and digest(raw) == held,
         'externally held complete signed share mismatch')
    try:
        lines = raw.decode('utf-8').split('\n')
    except UnicodeError as error:
        raise DocumentError('signed share UTF8 refused') from error
    need(len(lines) == 4 and lines[-1] == '' and lines[1] == 'STSD1:' + identifier
         and lines[2].startswith('PKG:'), 'canonical signed share profile or identity')
    formula, reference = lines[0], lines[2][4:]
    legacy.text(reference, 2048)
    need(bool(formula) and all(ord(c) >= 32 and ord(c) != 127 for c in formula), 'signed formula line')
    return formula, reference


class ManifestFacade:
    """Only virtualize the already-authenticated manifest; no global patching."""
    def __init__(self, archive, wrapper):
        self.archive = archive
        self.raw = canonical(wrapper)
        self.info = zipfile.ZipInfo('manifest.json')
        self.info.file_size = len(self.raw)

    def getinfo(self, name):
        return self.info if name == 'manifest.json' else self.archive.getinfo(name)

    def open(self, info):
        return io.BytesIO(self.raw) if info is self.info else self.archive.open(info)


def metadata_bound(archive):
    total = 0
    for name in archive_module.META_NAMES:
        total += archive.getinfo(name).file_size
        need(total <= MAX_SIGNED_METADATA, 'new signed profile complete metadata bound')


def verified_metadata(archive, names, share_raw, share_held, provider, trusted_public_key,
                      registry_id, current_revocation, native, work):
    metadata_bound(archive)
    envelope = archive_module.read_entry(archive, 'manifest.json', MAX_SIGNED_METADATA)
    wrapper, declaration, identifier = authenticated(envelope, provider, trusted_public_key,
                                                     registry_id, current_revocation)
    formula, reference = share_checked(share_raw, share_held, identifier)
    virtual_share = Path(work) / 'virtual-legacy-share.txt'
    write_new(virtual_share, (formula + '\nSTS1:' + wrapper['package_id'] + '\n').encode('utf-8'))
    facade = ManifestFacade(archive, wrapper)
    body, old_id, sections, record = legacy.verified_metadata(facade, names, virtual_share, native)
    need(old_id == wrapper['package_id'] and body == wrapper['body'], 'adapter body differs')
    declared_record_checked(declaration, record)
    return body, identifier, sections, record, declaration


def recover_frames(native, wire, recovered, body, sections, reading_wire, reading, record):
    expected = body['decoder']['native_sha256']
    legacy.run_native(native, wire, recovered, expected, body['source']['bytes'])
    legacy.recovered_checked(recovered, body, sections); wire.unlink()
    if body['reading'] is not None and body['reading']['mode'] == 'derived':
        derived = {'source': body['reading'], 'frames': body['reading']['frames']}
        legacy.run_native(native, reading_wire, reading, expected, body['reading']['bytes'])
        legacy.recovered_checked(reading, derived, []); reading_wire.unlink()
    elif body['reading'] is not None:
        os.link(recovered, reading, follow_symlinks=False)
    if body['reading'] is not None:
        legacy.reading_module.utf8_checked(reading, record)


@contextmanager
def validated(archive_path, share_path, share_held, provider, trusted_public_key,
              registry_id, current_revocation, native=None):
    native = legacy.native_path(native); root = legacy.scratch_root()
    with tempfile.TemporaryDirectory(prefix='signed-document-', dir=root) as folder:
        folder = Path(folder); wire, source = folder/'frames.ft01', folder/'source'
        reading_wire, reading = folder/'reading.ft01', folder/'reading.txt'
        with archive_module.opened(archive_path) as (archive, names):
            result = verified_metadata(archive, names, read_file(share_path, MAX_SIGNED_METADATA),
                share_held, provider, trusted_public_key, registry_id, current_revocation, native, folder)
            body, identifier, sections, record, declaration = result
            derived = body['reading'] is not None and body['reading']['mode'] == 'derived'
            frames = body['frames'] + (body['reading']['frames'] if derived else [])
            sizes = body['source']['bytes'] + (body['reading']['bytes'] if derived else 0)
            need_bytes = identity(archive.fp)[2] + sizes + 32 + sum(f['wire_bytes'] + 20 for f in frames)
            legacy.reserve(root, need_bytes + legacy.MAX_META)
            legacy.frame_stream(archive, body, wire)
            if derived:
                legacy.frame_stream(archive, {'source': body['reading'], 'frames': body['reading']['frames']}, reading_wire)
            write_new(folder/'reading.json', canonical(record))
        recover_frames(native, wire, source, body, sections, reading_wire, reading, record)
        yield source, body, identifier, sections, declaration


def result_for(body, identifier, trusted_public_key, registry_id, declaration):
    value = legacy.result_for(body, identifier)
    value.update({'profile': PROFILE, 'authentication': 'MLDSA87_ENDORSEMENT_VERIFIED_EXTERNAL_KEY_POLICY',
        'signed_preimage_sha256': identifier, 'legacy_transport_package_id': digest(canonical(body)),
        'public_key_sha256': digest(trusted_public_key), 'current_revocation_registry': registry_id,
        'declared_reading': declaration, 'semantic_record_pin_scope': 'UNSUPPORTED_MUST_BE_NULL',
        'human_authorship': 'UNPROVEN', 'current_action_authority': 'NONE',
        'signature_scope': 'ENDORSED_BYTES_NOT_TRUTH_OR_AUTHORITY'})
    return value


def decode_document(archive, share, share_held, output, provider, trusted_public_key,
                    registry_id, current_revocation, native=None):
    output = Path(output)
    need(not output.exists() and not output.is_symlink(), 'recovered destination already exists')
    with validated(archive, share, share_held, provider, trusted_public_key,
                   registry_id, current_revocation, native) as (recovered, body, identifier, _, declaration):
        legacy.reserve(output.parent, body['source']['bytes'])
        with tempfile.TemporaryDirectory(prefix='.signed-recovery-', dir=output.parent) as folder:
            stage = Path(folder)/'source'
            with open_regular(recovered, MAX_SOURCE) as source, stage.open('xb') as target:
                for _ in range(MAX_FRAMES + 1):
                    block = source.read(FRAME_SOURCE)
                    if not block:
                        break
                    need(target.write(block) == len(block), 'signed publication short write')
                target.flush(); os.fsync(target.fileno())
            need(file_digest(stage) == (body['source']['sha256'], body['source']['bytes']), 'signed publication mismatch')
            os.link(stage, output, follow_symlinks=False)
        return result_for(body, identifier, trusted_public_key, registry_id, declaration)


def copy_authenticated_archive(archive, target, envelope_raw, body):
    frames = body['frames'] + ([] if body['reading'] is None else body['reading']['frames'])
    expected = {frame['entry']: {'bytes': frame['wire_bytes'], 'sha256': frame['wire_sha256']} for frame in frames}
    for info in archive.infolist():
        raw = envelope_raw if info.filename == 'manifest.json' else archive_module.read_entry(archive, info.filename, legacy.MAX_META)
        if info.filename in expected:
            need(pin(raw) == expected[info.filename], 'source archive frame wire mismatch during sealing')
        archive_module.put(target, info.filename, raw)


def seal_existing_envelope(archive_path, legacy_share, envelope_raw, out_dir, reference, provider,
                           trusted_public_key, registry_id, current_revocation, native=None):
    """Repack only an externally signed exact manifest; never generates a key."""
    wrapper, declaration, identifier = authenticated(envelope_raw, provider, trusted_public_key,
                                                     registry_id, current_revocation)
    native = legacy.native_path(native); out_dir = Path(out_dir)
    need(not out_dir.exists() and not out_dir.is_symlink(), 'signed output directory already exists')
    with tempfile.TemporaryDirectory(prefix='.signed-seal-', dir=out_dir.parent) as folder:
        folder = Path(folder); bundle = folder/'bundle'; bundle.mkdir(mode=0o700)
        destination = bundle/'meaning.zip'
        with archive_module.opened(archive_path) as (archive, names):
            body, old_id, _, record = legacy.verified_metadata(archive, names, legacy_share, native)
            need(wrapper == {'body': body, 'package_id': old_id}, 'signed envelope belongs to another archive')
            declared_record_checked(declaration, record)
            total = len(envelope_raw) + sum(archive.getinfo(n).file_size for n in archive_module.META_NAMES - {'manifest.json'})
            need(total <= MAX_SIGNED_METADATA, 'signed total metadata capacity')
            legacy.reserve(out_dir.parent, identity(archive.fp)[2] + len(envelope_raw) + legacy.MAX_META)
            with zipfile.ZipFile(destination, 'x', compression=zipfile.ZIP_STORED, allowZip64=False) as target:
                copy_authenticated_archive(archive, target, envelope_raw, body)
            formula = legacy.formula_for(body['title'], legacy.loads(archive_module.read_entry(archive, 'structure.json', legacy.MAX_META))['sections'], record)
            share = signed_share_for(envelope_raw, formula, reference)
        write_new(bundle/'share.txt', share)
        receipt = result_for(body, identifier, trusted_public_key, registry_id, declaration)
        receipt.update({'status': 'SEALED_METADATA_CHECKED_NATIVE_RECOVERY_NOT_PERFORMED',
                        'checked_scope': 'ENDORSEMENT_AND_LEGACY_METADATA_ONLY',
                        'exact_recovery': 'NOT_PERFORMED',
                        'archive_bytes': destination.stat().st_size, 'share_sha256': digest(share)})
        write_new(bundle/'receipt.json', canonical(receipt))
        publication.rename_new(bundle, out_dir)
    return receipt


def sign_and_seal(archive_path, legacy_share, manifest_value, out_dir, reference, provider,
                  trusted_public_key, secret_key, registry_id, current_revocation,
                  native=None, declared_status='ACTIVE'):
    """Explicit operator key capability; the adapter never reads private key bytes."""
    source_current()
    need(type(provider) is signing.NativeProvider, 'sole pinned native signing provider required')
    value = signing.parse(signing.canonical(manifest_value))
    signed_manifest_checked(value)
    envelope = provider.sign_manifest(value, trusted_public_key, secret_key, registry_id,
                                      current_revocation, declared_status)
    return seal_existing_envelope(archive_path, legacy_share, envelope, out_dir, reference,
                                 provider, trusted_public_key, registry_id, current_revocation, native)


PUBLICATION_EPOCH = file_digest(publication.__file__, MAX_SIGNED_METADATA)[0]
SOURCE_EPOCH = loaded_epoch(__file__, sys._getframe().f_code)
