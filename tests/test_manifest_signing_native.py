"""Additive signing contract and actual mldsa-native provider controls."""
import json
import fcntl
from contextlib import contextmanager
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from manifest_signing import manifest as m

REGISTRY = 'a' * 64
BODY = {'profile': 'local-signing-test/1', 'frames': [
    {'path': 'frame001.bin', 'bytes': 4, 'sha256': 'b' * 64}],
    'semantic_completeness': 'UNPROVEN', 'execution_authority': 'NONE'}


@contextmanager
def ephemeral_key(provider):
    """Private key never enters Python: test process writes caller-owned memfd."""
    key_fd = os.memfd_create('SAST-TEST-ONLY-key', os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    descriptor = None
    try:
        os.fchmod(key_fd, 0o600)
        os.ftruncate(key_fd, m.SECRET_KEY_BYTES)
        descriptor = provider.open_verified()
        result = subprocess.run(['/proc/self/fd/' + str(descriptor), 'TEST-ONLY-keygen-to-fd',
                                 str(key_fd)], input=b'', capture_output=True, timeout=15,
                                pass_fds=(descriptor, key_fd), env={'LC_ALL': 'C'})
        m.need(result.returncode == 0 and result.stderr == b'' and
               len(result.stdout) == m.PUBLIC_KEY_BYTES, 'test-only key generation failed')
        fcntl.fcntl(key_fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE |
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        yield key_fd, result.stdout
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(key_fd)


class CanonicalContract(unittest.TestCase):
    def fifo_refusal(self, operation):
        script = (
            'import sys\n'
            'sys.path.insert(0, sys.argv[1])\n'
            'from manifest_signing.manifest import NativeProvider, open_secret_key, ManifestError\n'
            'try:\n'
            '    if sys.argv[3] == "secret": open_secret_key(sys.argv[2])\n'
            '    else: NativeProvider(sys.argv[2], "0" * 64)\n'
            'except ManifestError:\n'
            '    print("REFUSED")\n'
            'else:\n'
            '    raise SystemExit("FIFO was accepted")\n')
        build = os.environ.get('SAST_MLDSA87_BUILD')
        directory = Path(build).parent if build else Path('/dev/shm')
        with tempfile.TemporaryDirectory(prefix='sast-fifo-', dir=directory) as temporary:
            fifo = Path(temporary) / 'no-peer-fifo'
            os.mkfifo(fifo, 0o600)
            tools = str(Path(__file__).resolve().parents[1] / 'tools')
            command = [sys.executable, *(['-O'] if sys.flags.optimize else []),
                       '-c', script, tools, str(fifo), operation]
            started = time.monotonic()
            try:
                result = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True,
                                        timeout=2, check=False, env={'LC_ALL': 'C'})
            except subprocess.TimeoutExpired:
                self.fail('no-peer FIFO blocked before regular-file refusal; child killed/reaped')
            self.assertLess(time.monotonic() - started, 2)
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'REFUSED\n')
            self.assertEqual(result.stderr, b'')

    def test_operator_secret_fifo_without_peer_refuses_promptly(self):
        self.fifo_refusal('secret')

    def test_provider_fifo_without_peer_refuses_promptly(self):
        self.fifo_refusal('provider')

    def test_null_slot_binds_all_other_fields(self):
        envelope = m.unsigned_envelope(BODY, bytes(m.PUBLIC_KEY_BYTES), REGISTRY)
        raw = m.signing_preimage(envelope)
        self.assertIn(b'"signature":null', raw)
        self.assertEqual(m.parse(raw), envelope)
        for field in ('manifest', 'public_key', 'revocation', 'domain', 'schema',
                      'algorithm', 'signing_mode'):
            self.assertIn(('"' + field + '":').encode('ascii'), raw)

    def test_noncanonical_duplicate_and_malformed_refused(self):
        for raw in (b'{"x":1,"x":2}\n', b'{ "x":1}\n', b'{"x":1.0}\n',
                    b'{"x":NaN}\n', b'{"x":9223372036854775808}\n',
                    b'[' * 2000 + b']' * 2000, b'\xff', b''):
            with self.subTest(raw=raw[:40]):
                with self.assertRaises(m.ManifestError):
                    m.parse(raw)

    def test_closed_fields_and_modes(self):
        envelope = m.unsigned_envelope(BODY, bytes(m.PUBLIC_KEY_BYTES), REGISTRY)
        for field, value in (('unexpected', True), ('algorithm', 'ML-DSA-65'),
                             ('signing_mode', 'deterministic'), ('domain', 'wrong'),
                             ('schema', 'legacy/1')):
            changed = dict(envelope, **{field: value})
            with self.assertRaises(m.ManifestError):
                m.validate(changed, unsigned=True)

    def test_aggregate_escaped_budget_and_cycles_refused(self):
        for value in ([('\U0001f600' * (m.MAX_BYTES // 12 + 1))],
                      ['x' * (m.MAX_BYTES // 2 + 1)] * 2,
                      {'k': ['x' * m.MAX_BYTES] * 32}):
            with self.assertRaises(m.ManifestError):
                m.canonical(value)
        cycle = []
        cycle.append(cycle)
        with self.assertRaises(m.ManifestError):
            m.canonical(cycle)

    def test_duck_provider_and_nonbool_gate_refused(self):
        class Fake:
            def verify(self, *args):
                return None
        with self.assertRaises(m.ManifestError):
            m.verify_envelope(b'{}\n', Fake(), bytes(m.PUBLIC_KEY_BYTES),
                              REGISTRY, 'NOT_REVOKED')
        for truthy in (1, [True], 'yes'):
            with self.assertRaises(m.ManifestError):
                m.need(truthy, 'not bool')

    def test_string_encoding_budget_matches_canonical_encoder(self):
        value = ''.join(chr(i) for i in range(256)) + '\U0010ffff\ud800\udfff'
        encoded = json.dumps(value, ensure_ascii=True).encode('ascii')
        self.assertEqual(m.string_cost(value, m.MAX_BYTES), len(encoded))

    def test_node_depth_and_exact_byte_bound(self):
        with self.assertRaises(m.ManifestError):
            m.canonical([0] * m.MAX_NODES)
        nested = None
        for _ in range(m.MAX_DEPTH + 2):
            nested = [nested]
        with self.assertRaises(m.ManifestError):
            m.canonical(nested)
        exact = 'x' * (m.MAX_BYTES - 3)
        self.assertEqual(len(m.canonical(exact)), m.MAX_BYTES)
        with self.assertRaises(m.ManifestError):
            m.canonical(exact + 'x')


@unittest.skipUnless(os.environ.get('SAST_MLDSA87_BUILD'), 'native build not admitted/configured')
class ActualNativeProvider(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = Path(os.environ['SAST_MLDSA87_BUILD'])
        cls.receipt = json.loads((cls.build / 'build-receipt.json').read_text())
        cls.provider = m.NativeProvider(cls.build / 'sast-mldsa87-provider',
                                       cls.receipt['binary_sha256'])
        cls.raw, cls.key = cls.provider.ephemeral_test_seal(BODY, REGISTRY)

    def checked(self, raw, key=None, registry=REGISTRY, current='NOT_REVOKED'):
        return m.verify_envelope(raw, self.provider, key or self.key, registry, current)

    def test_positive_and_fresh_ephemeral_test_keys(self):
        self.assertEqual(self.checked(self.raw), BODY)
        self.assertEqual(self.receipt['upstream_commit'],
                         '17ebc1aa493265515a92239c76507ae28777cd4a')
        self.assertEqual(self.receipt['material_sizes_from_upstream_header'],
                         {'PUBLICKEYBYTES': m.PUBLIC_KEY_BYTES,
                          'SECRETKEYBYTES': m.SECRET_KEY_BYTES, 'BYTES': m.SIGNATURE_BYTES})
        second, second_key = self.provider.ephemeral_test_seal(BODY, REGISTRY)
        self.assertNotEqual(second_key, self.key)
        self.assertNotEqual(second, self.raw)

    def test_full_canonical_manifest_above_old_one_mib_cap(self):
        body = {'schema': 'TEST-ONLY-large-canonical/1', 'padding': 'x' * 1048577}
        raw, key = self.provider.ephemeral_test_seal(body, REGISTRY)
        self.assertGreater(len(m.signing_preimage(m.parse(raw))), 1048576)
        self.assertEqual(self.checked(raw, key=key), body)

    def test_same_key_hedged_signatures_differ_and_verify(self):
        descriptor = self.provider.open_verified()
        process = subprocess.Popen(['/proc/self/fd/' + str(descriptor),
                                    'ephemeral-test-sign-twice'], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   pass_fds=(descriptor,), env={'LC_ALL': 'C'})
        os.close(descriptor)
        try:
            key = m.read_public_key(process.stdout)
            preimage = m.canonical(BODY)
            output, error = process.communicate(struct.pack('>I', len(preimage)) + preimage,
                                                timeout=15)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(error, b'')
            self.assertEqual(len(output), m.SIGNATURE_BYTES * 2)
            first, second = output[:m.SIGNATURE_BYTES], output[m.SIGNATURE_BYTES:]
            self.assertNotEqual(first, second)
            self.provider.verify(key, first, preimage)
            self.provider.verify(key, second, preimage)
        finally:
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=15)

    def test_every_envelope_binding_tamper(self):
        original = m.parse(self.raw)
        changes = [('manifest', dict(BODY, execution_authority='GRANTED')),
                   ('revocation', {'seal_status': 'ACTIVE',
                                   'registry_id': 'c' * 64}),
                   ('public_key', ('00' if original['public_key'][:2] != '00' else '01')
                    + original['public_key'][2:]),
                   ('signature', ('00' if original['signature'][:2] != '00' else '01')
                    + original['signature'][2:])]
        for field, value in changes:
            changed = dict(original, **{field: value})
            with self.subTest(field=field):
                with self.assertRaises(m.ManifestError):
                    self.checked(m.canonical(changed))

    def test_external_wrong_key_revocation_and_registry_refused(self):
        wrong = bytearray(self.key)
        wrong[0] ^= 1
        for key, registry, current in ((bytes(wrong), REGISTRY, 'NOT_REVOKED'),
                                     (self.key, 'd' * 64, 'NOT_REVOKED'),
                                     (self.key, REGISTRY, 'UNKNOWN'),
                                     (self.key, REGISTRY, 'REVOKED')):
            with self.assertRaises(m.ManifestError):
                self.checked(self.raw, key, registry, current)

    def test_direct_native_tamper_wrong_key_and_framing(self):
        envelope = m.parse(self.raw)
        signature = bytes.fromhex(envelope['signature'])
        preimage = m.signing_preimage(envelope)
        with self.assertRaises(m.ManifestError):
            self.provider.verify(self.key, signature, preimage + b'x')
        wrong = bytearray(self.key)
        wrong[0] ^= 1
        with self.assertRaises(m.ManifestError):
            self.provider.verify(bytes(wrong), signature, preimage)
        valid = self.key + signature + struct.pack('>I', len(preimage)) + preimage
        for data in (b'', valid[:-1], valid + b'x',
                     self.key + signature + b'\xff\xff\xff\xff'):
            result = subprocess.run([str(self.provider.executable), 'verify'],
                                    input=data, capture_output=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')

    def test_native_binary_pin_required(self):
        with self.assertRaises(m.ManifestError):
            m.NativeProvider(self.provider.executable, '0' * 64)

    def test_replaced_binary_and_final_symlink_refused(self):
        with tempfile.TemporaryDirectory(dir=self.build.parent) as temporary:
            copied = Path(temporary) / 'provider'
            copied.write_bytes(self.provider.executable.read_bytes())
            copied.chmod(0o700)
            checked = m.NativeProvider(copied, self.receipt['binary_sha256'])
            copied.write_bytes(b'changed')
            with self.assertRaises(m.ManifestError):
                checked.open_verified()
            link = Path(temporary) / 'link'
            link.symlink_to(self.provider.executable)
            with self.assertRaises(m.ManifestError):
                m.NativeProvider(link, self.receipt['binary_sha256'])

    @unittest.skipUnless(os.environ.get('SAST_MLDSA87_RNG_FAULT_ROOT'), 'RNG fault builds absent')
    def test_os_rng_failure_at_keygen_and_signing(self):
        fault_root = Path(os.environ['SAST_MLDSA87_RNG_FAULT_ROOT'])
        for calls in (0, 1):
            fault = fault_root / ('rng-fault-' + str(calls))
            receipt = json.loads((fault / 'build-receipt.json').read_text())
            provider = m.NativeProvider(fault / 'sast-mldsa87-provider', receipt['binary_sha256'])
            with self.subTest(fail_after_calls=calls):
                with self.assertRaises(m.ManifestError):
                    provider.ephemeral_test_seal(BODY, REGISTRY)

    def test_input_bounds_and_algorithm_substitution(self):
        original = m.parse(self.raw)
        for field, value in (('algorithm', 'ML-DSA-44'), ('algorithm', 'Ed25519'),
                             ('signature', original['signature'][:-2]),
                             ('public_key', original['public_key'].upper()),
                             ('signature', None), ('extra', 1)):
            with self.subTest(field=field, value=str(value)[:24]):
                with self.assertRaises(m.ManifestError):
                    self.checked(m.canonical(dict(original, **{field: value})))
        with self.assertRaises(m.ManifestError):
            self.checked(b' ' * (m.MAX_BYTES + 1))

    def test_production_signer_api_with_ephemeral_memfd_only(self):
        with ephemeral_key(self.provider) as (key_fd, public_key):
            raw = self.provider.sign_manifest(BODY, public_key, key_fd, REGISTRY,
                                              'NOT_REVOKED')
            self.assertEqual(self.checked(raw, key=public_key), BODY)
            second = self.provider.sign_manifest(BODY, public_key, key_fd, REGISTRY,
                                                 'NOT_REVOKED')
            self.assertNotEqual(raw, second)
            wrong = bytearray(public_key)
            wrong[0] ^= 1
            with self.assertRaises(m.ManifestError):
                self.provider.sign_manifest(BODY, bytes(wrong), key_fd, REGISTRY,
                                            'NOT_REVOKED')
        with self.assertRaises(OSError):
            os.fstat(key_fd)

    def test_signed_revocation_status_enum_and_external_compromise(self):
        with ephemeral_key(self.provider) as (key_fd, public_key):
            for status in ('REVOKED', 'COMPROMISED', 'UNKNOWN'):
                raw = self.provider.sign_manifest(BODY, public_key, key_fd, REGISTRY,
                                                  'NOT_REVOKED', declared_status=status)
                envelope = m.parse(raw)
                self.provider.verify(public_key, bytes.fromhex(envelope['signature']),
                                     m.signing_preimage(envelope))
                with self.assertRaises(m.ManifestError):
                    self.checked(raw, key=public_key)
            with self.assertRaises(m.ManifestError):
                self.provider.sign_manifest(BODY, public_key, key_fd, REGISTRY,
                                            'COMPROMISED')
            with self.assertRaises(m.ManifestError):
                self.provider.sign_manifest(BODY, public_key, key_fd, REGISTRY,
                                            'NOT_REVOKED', declared_status='BOGUS')
        with self.assertRaises(m.ManifestError):
            self.checked(self.raw, current='COMPROMISED')

    def test_malformed_secret_key_and_path_policy(self):
        with tempfile.TemporaryDirectory(dir=self.build.parent) as temporary:
            malformed = Path(temporary) / 'SYNTHETIC-INVALID-zero-key'
            malformed.write_bytes(bytes(m.SECRET_KEY_BYTES))
            malformed.chmod(0o600)
            with self.assertRaises(m.ManifestError):
                self.provider.sign_manifest(BODY, self.key, malformed, REGISTRY, 'NOT_REVOKED')
            malformed.chmod(0o644)
            with self.assertRaises(m.ManifestError):
                m.open_secret_key(malformed)
            malformed.chmod(0o600)
            link = Path(temporary) / 'link'
            link.symlink_to(malformed)
            with self.assertRaises(m.ManifestError):
                m.open_secret_key(link)
            malformed.write_bytes(b'badlength')
            with self.assertRaises(m.ManifestError):
                m.open_secret_key(malformed)

    @unittest.skipUnless(os.environ.get('SAST_MLDSA87_RNG_FAULT_ROOT'), 'RNG fault builds absent')
    def test_imported_signing_rng_failure_refuses(self):
        root = Path(os.environ['SAST_MLDSA87_RNG_FAULT_ROOT']) / 'rng-fault-0'
        receipt = json.loads((root / 'build-receipt.json').read_text())
        fault = m.NativeProvider(root / 'sast-mldsa87-provider', receipt['binary_sha256'])
        with ephemeral_key(self.provider) as (key_fd, public_key):
            with self.assertRaises(m.ManifestError):
                fault.sign_manifest(BODY, public_key, key_fd, REGISTRY, 'NOT_REVOKED')


if __name__ == '__main__':
    unittest.main()
