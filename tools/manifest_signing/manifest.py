"""Bounded canonical endorsement data. Verification grants no execution authority.

The caller supplies an independently admitted public key and current revocation
decision. An embedded key and seal-time declaration cannot supply either trust.
The manifest body belongs to the calling profile's closed schema validator.
"""
import hashlib
import fcntl
import json
import os
from pathlib import Path
import select
import stat
import struct
import subprocess
import time

SCHEMA = 'sast/manifest-endorsement/mldsa87/1'
ALGORITHM = 'ML-DSA-87'
DOMAIN = 'SAST-MANIFEST-MLDSA87-v1'
FIELDS = {'schema', 'algorithm', 'domain', 'signing_mode', 'manifest',
          'public_key', 'revocation', 'signature'}
PUBLIC_KEY_BYTES = 2592
SECRET_KEY_BYTES = 4896  # pinned mldsa_native.h MLDSA87_SECRETKEYBYTES
SIGNATURE_BYTES = 4627
SEAL_STATUSES = {'ACTIVE', 'REVOKED', 'COMPROMISED', 'UNKNOWN'}
MAX_BYTES = 8388608  # entire signed-profile metadata keeps this old total ceiling
MAX_SOURCE_FRAMES = 16384
MAX_READING_FRAMES = 512
FRAME_VALUE_NODES = 8  # closed row: one dictionary and seven scalar values
FIXED_VALUE_NODES = 81  # maximal closed envelope with empty frame arrays
MAX_NODES = FRAME_VALUE_NODES * (MAX_SOURCE_FRAMES + MAX_READING_FRAMES) + FIXED_VALUE_NODES
MAX_DEPTH = 32
TIMEOUT_SECONDS = 15


class ManifestError(ValueError):
    """Fail-closed endorsement boundary refusal."""


def need(condition, reason):
    if type(condition) is not bool or condition is not True:
        raise ManifestError(reason)


def string_cost(value, remaining):
    need(type(value) is str and len(value) <= MAX_BYTES, 'JSON string type or bound')
    cost = 2
    for character in value:
        code = ord(character)
        if character in ('"', '\\', '\b', '\f', '\n', '\r', '\t'):
            cost += 2
        elif code < 32 or 127 <= code <= 65535:
            cost += 6
        elif code > 65535:
            cost += 12
        else:
            cost += 1
        need(cost <= remaining, 'escaped JSON byte bound')
    need(cost <= remaining, 'escaped JSON byte bound')
    return cost


def bounded(value):
    pending = [(iter((value,)), 0)]
    used = 0
    encoded_bytes = 1  # final LF
    while pending:
        iterator, depth = pending[-1]
        try:
            item = next(iterator)
        except StopIteration:
            pending.pop()
            continue
        used += 1
        need(used <= MAX_NODES, 'manifest node bound')
        need(depth <= MAX_DEPTH, 'manifest nesting bound')
        children = None
        if type(item) is dict:
            need(len(item) <= MAX_NODES, 'object field bound')
            encoded_bytes += 2 + max(0, len(item) - 1) + len(item)
            for key, child in item.items():
                need(type(key) is str and len(key) <= 1024, 'object key')
                encoded_bytes += string_cost(key, MAX_BYTES - encoded_bytes)
            children = iter(item.values())
        elif type(item) is list:
            need(len(item) <= MAX_NODES, 'array bound')
            encoded_bytes += 2 + max(0, len(item) - 1)
            children = iter(item)
        elif type(item) is str:
            encoded_bytes += string_cost(item, MAX_BYTES - encoded_bytes)
        elif type(item) is int:
            need(-9223372036854775808 <= item <= 9223372036854775807, 'integer bound')
            encoded_bytes += len(str(item))
        else:
            need(item is None or type(item) is bool, 'unsupported JSON value')
            encoded_bytes += len(str(item).lower())
        need(encoded_bytes <= MAX_BYTES, 'aggregate JSON byte bound')
        if children is not None:
            need(len(pending) <= MAX_DEPTH, 'iterator stack bound before allocation')
            pending.append((children, depth + 1))


def canonical(value):
    bounded(value)
    try:
        raw = json.dumps(value, sort_keys=True, ensure_ascii=True,
                         separators=(',', ':'), allow_nan=False).encode('ascii') + b'\n'
    except (ValueError, TypeError, UnicodeError) as error:
        raise ManifestError('manifest serialization refused') from error
    need(len(raw) <= MAX_BYTES, 'manifest byte bound')
    return raw


def no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def parse(raw):
    need(type(raw) is bytes and 0 < len(raw) <= MAX_BYTES, 'manifest byte bound')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=no_duplicates)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ManifestError('manifest JSON refused') from error
    need(canonical(value) == raw, 'noncanonical manifest bytes')
    return value


def hex_bytes(value, length, label):
    need(type(value) is str and len(value) == length * 2, label + ' length')
    need(all(c in '0123456789abcdef' for c in value), label + ' encoding')
    return bytes.fromhex(value)


def validate(envelope, unsigned=False):
    need(type(envelope) is dict and set(envelope) == FIELDS, 'closed envelope fields')
    need(envelope['schema'] == SCHEMA, 'endorsement schema')
    need(envelope['algorithm'] == ALGORITHM, 'ML-DSA-87 required')
    need(envelope['domain'] == DOMAIN, 'manifest domain')
    need(envelope['signing_mode'] == 'hedged', 'hedged signing required')
    need(type(envelope['manifest']) is dict, 'manifest body object')
    hex_bytes(envelope['public_key'], PUBLIC_KEY_BYTES, 'public key')
    revocation = envelope['revocation']
    need(type(revocation) is dict and set(revocation) == {'seal_status', 'registry_id'},
         'closed revocation fields')
    need(type(revocation['seal_status']) is str and
         revocation['seal_status'] in SEAL_STATUSES, 'seal key status')
    hex_bytes(revocation['registry_id'], 32, 'revocation registry pin')
    if unsigned:
        need(envelope['signature'] is None, 'explicit unsigned slot')
    else:
        hex_bytes(envelope['signature'], SIGNATURE_BYTES, 'signature')
    canonical(envelope)
    return envelope


def signing_preimage(envelope):
    need(type(envelope) is dict, 'envelope object')
    bounded(envelope)
    unsigned = envelope.copy()
    unsigned['signature'] = None
    validate(unsigned, unsigned=True)
    return canonical(unsigned)


def unsigned_envelope(manifest, public_key, registry_id, declared_status='ACTIVE'):
    need(type(public_key) is bytes and len(public_key) == PUBLIC_KEY_BYTES, 'public key')
    bounded(manifest)
    value = {'schema': SCHEMA, 'algorithm': ALGORITHM, 'domain': DOMAIN,
             'signing_mode': 'hedged', 'manifest': parse(canonical(manifest)),
             'public_key': public_key.hex(), 'revocation': {
                 'seal_status': declared_status, 'registry_id': registry_id},
             'signature': None}
    validate(value, unsigned=True)
    return value


def open_secret_key(explicit_source):
    """Caller explicitly supplies a key; never resolve a key from a package."""
    try:
        if type(explicit_source) is int:
            need(3 <= explicit_source <= 4095, 'explicit secret key descriptor bound')
            descriptor = os.dup(explicit_source)
        else:
            need(isinstance(explicit_source, (str, Path)), 'explicit key path or FD required')
            need(len(str(explicit_source)) <= 4096, 'secret key path bound')
            descriptor = os.open(explicit_source, os.O_RDONLY | os.O_NONBLOCK |
                                 os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError as error:
        raise ManifestError('explicit secret key open refused') from error
    try:
        information = os.fstat(descriptor)
        need(stat.S_ISREG(information.st_mode) and information.st_uid == os.geteuid(),
             'secret key regular file or owner mismatch')
        need(information.st_mode & 0o7777 & ~0o600 == 0, 'secret key permission scope')
        need(information.st_size == SECRET_KEY_BYTES, 'ML-DSA-87 secret key exact length')
        need(descriptor <= 4095, 'inherited secret key FD bound')
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


class NativeProvider:
    """Invoke one independently pinned executable; never select alternatives."""
    def __init__(self, executable, expected_sha256):
        self.executable = Path(executable).absolute()
        hex_bytes(expected_sha256, 32, 'provider binary pin')
        self.expected_sha256 = expected_sha256
        descriptor = self.open_verified()
        os.close(descriptor)

    def open_verified(self):
        try:
            source = os.open(self.executable, os.O_RDONLY | os.O_NONBLOCK |
                             os.O_NOFOLLOW | os.O_CLOEXEC)
        except OSError as error:
            raise ManifestError('provider file open refused') from error
        descriptor = None
        try:
            information = os.fstat(source)
            need(stat.S_ISREG(information.st_mode) and information.st_size <= 8388608,
                 'provider regular file or binary bound')
            descriptor = os.memfd_create('sast-pinned-provider',
                                        os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
            digest = hashlib.sha256()
            used = 0
            for _ in range(129):
                block = os.read(source, 65536)
                if not block:
                    break
                used += len(block)
                need(used <= 8388608, 'provider binary read bound')
                digest.update(block)
                need(os.write(descriptor, block) == len(block), 'provider snapshot write')
            else:
                raise ManifestError('provider binary read bound')
            need(digest.hexdigest() == self.expected_sha256, 'provider binary identity mismatch')
            fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE |
                        fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
            return descriptor
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            raise
        finally:
            os.close(source)

    def verify(self, public_key, signature, preimage):
        need(len(public_key) == PUBLIC_KEY_BYTES and len(signature) == SIGNATURE_BYTES,
             'provider material lengths')
        need(0 < len(preimage) <= MAX_BYTES, 'provider message bound')
        data = public_key + signature + struct.pack('>I', len(preimage)) + preimage
        descriptor = self.open_verified()
        try:
            result = subprocess.run(['/proc/self/fd/' + str(descriptor), 'verify'], input=data,
                                    capture_output=True, timeout=TIMEOUT_SECONDS,
                                    pass_fds=(descriptor,), env={'LC_ALL': 'C'}, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ManifestError('provider unavailable or deadline') from error
        finally:
            os.close(descriptor)
        need(result.returncode == 0 and result.stdout == b'' and result.stderr == b'',
             'signature verification refused')

    def sign_manifest(self, manifest, public_key, secret_key, registry_id,
                      current_revocation, declared_status='ACTIVE'):
        """Sign using an explicit operator-provided key, never mint an identity.

        Secret bytes stay outside Python: the provider imports the inherited FD,
        validates its key/public-key consistency, signs, self-verifies and wipes.
        Key admission, registry freshness and human identity remain caller policy.
        """
        need(type(current_revocation) is str and current_revocation == 'NOT_REVOKED',
             'signing requires independent current key admission')
        envelope = unsigned_envelope(manifest, public_key, registry_id, declared_status)
        preimage = signing_preimage(envelope)
        key_descriptor = open_secret_key(secret_key)
        descriptor = None
        try:
            descriptor = self.open_verified()
            data = public_key + struct.pack('>I', len(preimage)) + preimage
            result = subprocess.run(['/proc/self/fd/' + str(descriptor),
                                     'sign-admitted-key-fd', str(key_descriptor)],
                                    input=data, capture_output=True, timeout=TIMEOUT_SECONDS,
                                    pass_fds=(descriptor, key_descriptor),
                                    env={'LC_ALL': 'C'}, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ManifestError('admitted key signing provider failed or deadline') from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            os.close(key_descriptor)
        need(result.returncode == 0 and result.stderr == b'' and
             len(result.stdout) == SIGNATURE_BYTES, 'admitted key signing refused')
        envelope['signature'] = result.stdout.hex()
        validate(envelope)
        return canonical(envelope)

    def ephemeral_test_seal(self, manifest, registry_id):
        """Local tests only; key exists solely inside one provider process."""
        descriptor = self.open_verified()
        try:
            process = subprocess.Popen(['/proc/self/fd/' + str(descriptor), 'ephemeral-test-sign'],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, pass_fds=(descriptor,),
                                       env={'LC_ALL': 'C'})
        finally:
            os.close(descriptor)
        try:
            public_key = read_public_key(process.stdout)
            envelope = unsigned_envelope(manifest, public_key, registry_id)
            preimage = signing_preimage(envelope)
            data = struct.pack('>I', len(preimage)) + preimage
            signature, error = process.communicate(data, timeout=TIMEOUT_SECONDS)
            need(process.returncode == 0 and error == b'' and len(signature) == SIGNATURE_BYTES,
                 'ephemeral test signing refused')
            envelope['signature'] = signature.hex()
            validate(envelope)
            return canonical(envelope), public_key
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ManifestError('ephemeral test provider deadline') from error
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=TIMEOUT_SECONDS)


def read_public_key(stream):
    deadline = time.monotonic() + TIMEOUT_SECONDS
    result = bytearray()
    for _ in range(PUBLIC_KEY_BYTES):
        remaining = deadline - time.monotonic()
        need(remaining > 0 and len(select.select([stream], [], [], remaining)[0]) > 0,
             'test public key deadline')
        block = os.read(stream.fileno(), PUBLIC_KEY_BYTES - len(result))
        need(len(block) > 0, 'test public key truncated')
        result.extend(block)
        if len(result) == PUBLIC_KEY_BYTES:
            return bytes(result)
    raise ManifestError('test public key read bound')


def verify_envelope(raw, provider, trusted_public_key, registry_id, current_revocation):
    """Return signed body only after external trust/revocation and signature checks.

    The independent caller owns key admission and fresh registry evaluation.
    NOT_REVOKED must not be inferred from the embedded seal-time declaration.
    """
    need(type(provider) is NativeProvider, 'sole pinned native provider required')
    need(type(current_revocation) is str and current_revocation == 'NOT_REVOKED',
         'current revocation UNKNOWN or REVOKED')
    hex_bytes(registry_id, 32, 'independently pinned revocation registry')
    need(type(trusted_public_key) is bytes and len(trusted_public_key) == PUBLIC_KEY_BYTES,
         'independently admitted public key required')
    envelope = validate(parse(raw))
    need(envelope['revocation']['seal_status'] == 'ACTIVE', 'seal key inactive or compromised')
    need(envelope['public_key'] == trusted_public_key.hex(), 'untrusted embedded key')
    need(envelope['revocation']['registry_id'] == registry_id, 'revocation registry mismatch')
    signature = hex_bytes(envelope['signature'], SIGNATURE_BYTES, 'signature')
    provider.verify(trusted_public_key, signature, signing_preimage(envelope))
    return parse(canonical(envelope['manifest']))
