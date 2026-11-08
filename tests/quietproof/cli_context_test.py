#!/usr/bin/env python3
"""CLI defaults remain concrete transcript fields and exact policy expectations."""
import hashlib
import argparse
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time
import unittest

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('binary')
parser.add_argument('--rpc-enabled', choices=('ON', 'OFF'), required=True)
args = parser.parse_args()
BINARY = args.binary
RPC_ENABLED = args.rpc_enabled == 'ON'
sys.argv = [sys.argv[0]]
CLAIM = '01' + '00' * 31 + ':0:7:' + '04' + '00' * 19


def context(wire):
    offset = 6  # QPS1, version, network
    fields = []
    for _ in range(2):
        size = struct.unpack_from('>H', wire, offset)[0]
        offset += 2
        fields.append(wire[offset:offset + size].decode())
        offset += size
    return (*fields, wire[offset:offset + 32], wire[offset + 32:offset + 64])


class ContextTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.request = self.root / 'request.qpr'

    def test_native_unavailable_preserves_old_input_precedence(self):
        native = ('{"error":"native_unavailable","message":"Native Bitcoin Core RPC '
                  'support is unavailable in this build"}\n')
        malformed = ('{"claims_checked":0,"exit_code":65,"result":"malformed_statement",'
                     '"total_sats":0}\n')
        inputs = [self.root / 'missing.qpf']
        for name, data in [('old-v1.qpf', b'QPE1\x01'), ('old-v2.qpf', b'QPE1\x02'),
                           ('ordinary.qpf', b'ordinary invalid data')]:
            path = self.root / name
            path.write_bytes(data)
            inputs.append(path)
        if not RPC_ENABLED:
            # A large old input must be rejected without full read/allocation.
            sparse = self.root / 'large-old.qpf'
            with sparse.open('wb') as stream:
                stream.write(b'QPE1\x02')
                stream.truncate(256 * 1024 * 1024)
            inputs.append(sparse)
            fifo = self.root / 'ordinary-fifo.qpf'
            os.mkfifo(fifo, 0o600)  # No writer: an eager full read would block.
            inputs.append(fifo)
        nonce = self.root / 'nonces'
        for path in inputs:
            with self.subTest(path=path.name):
                result = subprocess.run([BINARY, 'verify', str(path), '--proof-mode', 'key-knowledge', '--nonce-store', str(nonce)],
                                        text=True, capture_output=True, timeout=10)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (65, malformed, '') if RPC_ENABLED else (64, '', native))
                self.assertFalse(nonce.exists())
        # Network validation preceded the original RPC-OFF gate; numeric policy
        # validation followed it. Keep both precedences and exact usage output.
        usage = subprocess.run([BINARY, 'verify'], text=True, capture_output=True, timeout=10)
        for options in (['--network', 'not-a-network'], ['--unknown-option', '1']):
            result = subprocess.run([BINARY, 'verify', str(inputs[0]), '--proof-mode', 'key-knowledge', '--nonce-store', str(nonce), *options],
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (usage.returncode, usage.stdout, usage.stderr))
        result = subprocess.run([BINARY, 'verify', str(inputs[0]), '--proof-mode', 'key-knowledge', '--nonce-store', str(nonce),
                                 '--min-confirmations', 'invalid'], text=True, capture_output=True, timeout=10)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (usage.returncode, usage.stdout, usage.stderr) if RPC_ENABLED else (64, '', native))

    def test_private_receipt_rejected_before_provider(self):
        # Deliberately private-looking sentinel; filename cannot select a parser.
        proof = self.root / 'renamed-receipt.qpf'
        sentinel = 'PRIVATE-WITNESS-MUST-NOT-BE-ECHOED'
        proof.write_bytes(b'QPA1' + sentinel.encode())
        minimal = self.root / 'receipt-magic-only.qpf'
        minimal.write_bytes(b'QPA1')
        large = self.root / 'large-private.qpf'
        with large.open('wb') as stream:
            stream.write(b'QPA1')
            stream.truncate(256 * 1024 * 1024)
        tripwire = self.root / 'provider-called'
        provider = self.root / 'bitcoin-cli'
        provider.write_text('#!/bin/sh\ntouch "' + str(tripwire) + '"\nexit 1\n')
        provider.chmod(0o700)
        nonce = self.root / 'nonces'
        for path in (proof, minimal, large):
            for args in ([], ['--bitcoin-cli', str(provider)]):
                result = subprocess.run([BINARY, 'verify', str(path),
                                         '--proof-mode', 'key-knowledge', '--nonce-store', str(nonce), *args],
                                        text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 65, result.stderr)
                self.assertEqual(json.loads(result.stdout)['result'], 'malformed_statement')
                warning = ('--bitcoin-cli selects the deprecated legacy backend; '
                           'use native Bitcoin Core RPC for new integrations.\n') if args else ''
                self.assertEqual(result.stderr, warning + 'private_receipt_input\n')
                self.assertNotIn(sentinel, result.stdout + result.stderr)
                self.assertFalse(tripwire.exists())
                self.assertFalse(nonce.exists())

    def test_v3_format_never_selects_signature_acceptance(self):
        frozen = Path(__file__).resolve().parents[2] / 'spec/signature-profile-v1.json'
        statement = bytes.fromhex(json.loads(frozen.read_text())['vectors'][0]['request_hex'])
        # Synthetic circuit identity/proof: transport fixture only, unapproved.
        proof = self.root / 'v3.qpf'
        proof.write_bytes(b'QPE1\x03' + struct.pack('>I', len(statement)) + statement +
                          struct.pack('>QBHH', 1800000100, 1, 1, 1) +
                          bytes(range(1, 33)) + struct.pack('>IIII', 1, 4, 128, 1) + b'\x01')
        tripwire = self.root / 'provider-called'
        provider = self.root / 'bitcoin-cli'
        provider.write_text('#!/bin/sh\ntouch "' + str(tripwire) + '"\nexit 1\n')
        provider.chmod(0o700)
        nonce = self.root / 'nonces'
        for args in ([], ['--bitcoin-cli', str(provider)]):
            result = subprocess.run([BINARY, 'verify', str(proof), '--proof-mode', 'key-knowledge', '--nonce-store', str(nonce), *args],
                                    text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 66, result.stderr)
            self.assertEqual(json.loads(result.stdout)['result'], 'unsupported')
            self.assertFalse(tripwire.exists())
            self.assertFalse(nonce.exists())

    def create(self, *args):
        return subprocess.run([
            BINARY, 'challenge', 'create', '--proof-mode', 'key-knowledge', '--network', 'signet',
            '--claim', CLAIM, '--output', str(self.request), *args,
        ], text=True, capture_output=True, timeout=10)

    def test_omitted_fields_and_empty_message(self):
        before = int(time.time())
        result = self.create()
        self.assertEqual(result.returncode, 0, result.stderr)
        info = json.loads(result.stdout)
        self.assertLessEqual(before, info['request_created_at'])
        self.assertLessEqual(info['request_created_at'], int(time.time()))
        inspected = subprocess.run([BINARY, 'inspect', str(self.request)],
                                   text=True, capture_output=True, check=True, timeout=10)
        timestamps = json.loads(inspected.stdout)
        self.assertEqual(timestamps['request_created_at'], info['request_created_at'])
        self.assertEqual(timestamps['not_before'], info['request_created_at'])
        self.assertGreater(timestamps['expires_at'], info['request_created_at'])
        self.assertEqual((info['verifier'], info['purpose']), ('unscoped', 'proof-of-funds'))
        verifier, purpose, nonce, digest = context(self.request.read_bytes())
        self.assertEqual((verifier, purpose), ('unscoped', 'proof-of-funds'))
        tag = hashlib.sha256(b'BIP0322-signed-message').digest()
        self.assertEqual(digest, hashlib.sha256(tag + tag).digest())
        self.assertNotEqual(nonce, bytes(32))
        self.request.unlink()
        result = self.create('--message', '')
        self.assertEqual(result.returncode, 0, result.stderr)
        other = context(self.request.read_bytes())
        self.assertEqual(other[3], digest)
        self.assertNotEqual(other[2], nonce)

    def test_independent_overrides(self):
        for args, expected in [
            (['--verifier', 'auditor.example'], ('auditor.example', 'proof-of-funds', b'')),
            (['--purpose', 'proof-of-control'], ('unscoped', 'proof-of-control', b'')),
            (['--message', 'Control check'], ('unscoped', 'proof-of-funds', b'Control check')),
        ]:
            with self.subTest(args=args):
                result = self.create(*args)
                self.assertEqual(result.returncode, 0, result.stderr)
                verifier, purpose, _, digest = context(self.request.read_bytes())
                self.assertEqual((verifier, purpose), expected[:2])
                tag = hashlib.sha256(b'BIP0322-signed-message').digest()
                self.assertEqual(digest, hashlib.sha256(tag + tag + expected[2]).digest())
                self.request.unlink()

    def test_explicit_invalid_fields_are_not_defaulted(self):
        for args in [
            ['--verifier', ''], ['--purpose', ''], ['--purpose', 'anything'],
            ['--purpose', 'bridge-authorization'],
            ['--verifier', 'one', '--verifier', 'two'],
        ]:
            with self.subTest(args=args):
                self.assertNotEqual(self.create(*args).returncode, 0)
                self.assertFalse(self.request.exists())

    def verify_fixture(self, *args):
        # Deliberately unsupported digest: test policy routing, never proof acceptance.
        statement = self.request.read_bytes()
        proof = self.root / 'fixture.qpf'
        proof.write_bytes(b'QPE1\x01' + struct.pack('>I', len(statement)) + statement +
                          b'\x01' + bytes(31) + struct.pack('>IIII', 1, 4, 128, 1) + b'\x01')
        nonce = self.root / 'nonces'
        result = subprocess.run([
            BINARY, 'verify', str(proof), '--bitcoin-cli', '/bin/false',
            '--proof-mode', 'key-knowledge', '--nonce-store', str(nonce), *args,
        ], text=True, capture_output=True, timeout=60)
        self.assertFalse(nonce.exists())
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(result.returncode, 64, result.stderr)
        return json.loads(result.stdout)['result']

    def test_default_verifier_policy_is_exact(self):
        self.assertEqual(self.create().returncode, 0)
        self.assertEqual(self.verify_fixture(), 'unsupported')
        self.assertEqual(self.verify_fixture('--verifier', 'auditor.example'), 'invalid_proof')
        self.assertEqual(self.verify_fixture('--purpose', 'proof-of-control'), 'invalid_proof')

    def test_named_context_requires_explicit_matching_policy(self):
        self.assertEqual(self.create('--verifier', 'auditor.example',
                                     '--purpose', 'proof-of-control').returncode, 0)
        self.assertEqual(self.verify_fixture(), 'invalid_proof')
        self.assertEqual(self.verify_fixture('--verifier', 'auditor.example'), 'invalid_proof')
        self.assertEqual(self.verify_fixture('--verifier', 'auditor.example',
                                             '--purpose', 'proof-of-control'), 'unsupported')


    def create_claims(self, claims, *args):
        arguments = [BINARY, 'challenge', 'create', '--proof-mode', 'key-knowledge', '--network', 'signet',
                     '--output', str(self.request)]
        for claim in claims:
            arguments += ['--claim', claim]
        return subprocess.run(arguments + list(args), text=True, capture_output=True, timeout=10)

    def inspect(self, path=None):
        result = subprocess.run([BINARY, 'inspect', str(path or self.request)],
                                text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(result.stderr)
        return json.loads(result.stdout)

    def test_explicit_p2wpkh_preserves_legacy_bytes(self):
        self.assertEqual(self.create_claims([CLAIM]).returncode, 0)
        legacy = self.request.read_bytes()
        self.request.unlink()
        parts = CLAIM.split(':')
        explicit = ':'.join(parts[:3] + ['p2wpkh', parts[3]])
        self.assertEqual(self.create_claims([explicit]).returncode, 0)
        typed = self.request.read_bytes()
        # Only the random nonce and wall-clock fields may change.
        offset = 6
        for _ in range(2):
            offset += 2 + struct.unpack_from('>H', legacy, offset)[0]
        def fixed(wire):
            return wire[:offset] + wire[offset + 32:offset + 64] + wire[offset + 80:]
        self.assertEqual(fixed(legacy), fixed(typed))
        self.assertEqual(typed[4], 1)
        info = self.inspect()
        self.assertEqual(info['statement_version'], 1)
        self.assertEqual(info['script_kinds'], ['p2wpkh'])
        self.assertIsNone(info['proof_created_at'])

    def test_mixed_claims_are_typed_and_sorted(self):
        key_hash = '04' + '00' * 19
        p2pkh = '02' + '00' * 31 + ':3:9:p2pkh:' + key_hash
        result = self.create_claims([p2pkh, CLAIM])
        self.assertEqual(result.returncode, 0, result.stderr)
        wire = self.request.read_bytes()
        self.assertEqual(wire[4], 2)
        expected = (bytes.fromhex('01' + '00' * 31) + struct.pack('>IQ', 0, 7) +
                    b'\x00' + bytes.fromhex(key_hash) + bytes.fromhex('02' + '00' * 31) +
                    struct.pack('>IQ', 3, 9) + b'\x01' + bytes.fromhex(key_hash))
        self.assertEqual(wire[-len(expected):], expected)
        info = self.inspect()
        self.assertEqual(info['statement_version'], 2)
        self.assertEqual(info['script_kinds'], ['p2wpkh', 'p2pkh'])
        self.assertEqual(info['claims'], 2)
        self.assertEqual(info['request_created_at'], info['not_before'])
        self.assertIsNone(info['proof_created_at'])

    def test_typed_optional_context_combinations(self):
        claim = CLAIM.rsplit(':', 1)[0] + ':p2pkh:' + CLAIM.rsplit(':', 1)[1]
        for mask in range(8):
            args = []
            for bit, option, value in [(1, '--verifier', 'auditor.example'),
                                       (2, '--purpose', 'proof-of-control'),
                                       (4, '--message', 'Typed ownership')]:
                if mask & bit:
                    args += [option, value]
            with self.subTest(mask=mask):
                result = self.create_claims([claim], *args)
                self.assertEqual(result.returncode, 0, result.stderr)
                info = self.inspect()
                self.assertEqual(info['statement_version'], 2)
                self.assertEqual(info['script_kinds'], ['p2pkh'])
                verifier, purpose, _, digest = context(self.request.read_bytes())
                self.assertEqual(verifier, 'auditor.example' if mask & 1 else 'unscoped')
                self.assertEqual(purpose, 'proof-of-control' if mask & 2 else 'proof-of-funds')
                tag = hashlib.sha256(b'BIP0322-signed-message').digest()
                message = b'Typed ownership' if mask & 4 else b''
                self.assertEqual(digest, hashlib.sha256(tag + tag + message).digest())
                self.request.unlink()

    def test_malformed_typed_claims(self):
        prefix, key_hash = CLAIM.rsplit(':', 1)
        for claim in [prefix, CLAIM + ':extra', prefix + ':p2pkh:' + key_hash + ':extra',
                      prefix + ':p2pkh', prefix + '::' + key_hash,
                      prefix + ':P2PKH:' + key_hash, prefix + ':p2sh:' + key_hash,
                      prefix + ':p2pkh:', prefix + ':p2pkh:' + key_hash[:-2],
                      prefix + ':p2pkh:' + key_hash + '00', prefix + ':p2pkh:' + 'z' * 40,
                      'bad:0:7:p2pkh:' + key_hash,
                      '01' + '00' * 31 + ':4294967296:7:p2pkh:' + key_hash]:
            with self.subTest(claim=claim):
                result = self.create_claims([claim])
                self.assertEqual(result.returncode, 64)
                self.assertFalse(result.stdout)
                self.assertFalse(self.request.exists())

    def test_duplicate_outpoints_across_kinds_and_address_exclusion(self):
        prefix, key_hash = CLAIM.rsplit(':', 1)
        typed = prefix + ':p2pkh:' + key_hash
        for claims, args, expected in [([CLAIM, typed], [], 65),
                                       ([typed, typed], [], 65),
                                       ([typed], ['--address', 'bcrt1qfixture'], 64)]:
            with self.subTest(claims=claims):
                result = self.create_claims(claims, *args)
                self.assertEqual(result.returncode, expected)
                self.assertFalse(result.stdout)
                self.assertFalse(self.request.exists())

    def test_uncompressed_p2pkh_and_invalid_keys_are_rejected_privately(self):
        # Public secp256k1 generator fixture, scalar 1. Its uncompressed hash
        # differs from HASH160(02 || x), which is the supported circuit relation.
        public_key = bytes.fromhex(
            '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798'
            '483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8')
        key_hash = hashlib.new('ripemd160', hashlib.sha256(public_key).digest()).hexdigest()
        self.assertEqual(key_hash, '91b24bf9f5288532960ac687abb035127b1d28a5')
        claim = CLAIM.rsplit(':', 1)[0] + ':p2pkh:' + key_hash
        self.assertEqual(self.create_claims([claim]).returncode, 0)
        proof = self.root / 'unsupported.qpf'
        for secret, diagnostic in [('0' * 63 + '1', 'uncompressed'),
                                   ('0' * 64, 'nonzero'), ('private-key-fixture', 'Invalid key input')]:
            with self.subTest(diagnostic=diagnostic):
                result = subprocess.run([BINARY, 'prove', '--proof-mode', 'key-knowledge', '--request', str(self.request),
                                         '--output', str(proof)], input=secret + '\n',
                                        text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 65)
                self.assertFalse(result.stdout)
                self.assertIn(diagnostic, result.stderr)
                self.assertNotIn(secret, result.stdout + result.stderr)
                self.assertFalse(proof.exists())

    def test_typed_envelope_inspection_reports_both_timestamps(self):
        claim = CLAIM.rsplit(':', 1)[0] + ':p2pkh:' + CLAIM.rsplit(':', 1)[1]
        self.assertEqual(self.create_claims([claim]).returncode, 0)
        request = self.inspect()
        statement = self.request.read_bytes()
        proof = self.root / 'inspection-only.qpf'
        # Unsupported digest/payload: parsing and inspection only, no proof acceptance.
        proof_time = request['request_created_at'] + 1
        proof.write_bytes(b'QPE1\x02' + struct.pack('>I', len(statement)) + statement +
                          struct.pack('>Q', proof_time) + b'\x01' + bytes(31) +
                          struct.pack('>IIII', 1, 4, 128, 1) + b'\x01')
        info = self.inspect(proof)
        self.assertEqual(info['statement_version'], 2)
        self.assertEqual(info['script_kinds'], ['p2pkh'])
        self.assertEqual(info['request_created_at'], request['request_created_at'])
        self.assertEqual(info['proof_created_at'], proof_time)

    def test_signature_request_never_reads_key_or_contacts_wallet(self):
        fixture = json.loads((Path(__file__).resolve().parents[2] /
                              'spec/signature-profile-v1.json').read_text())
        original = bytes.fromhex(fixture['vectors'][0]['request_hex'])
        for mutate, expected, diagnostic in [
                (None, 66, 'signature_mode_disabled'),
                ((6, 0), 65, 'invalid or unsupported signature request'),
                ((8, 2), 66, 'invalid or unsupported signature request'),
                ((9, 2), 66, 'invalid or unsupported signature request')]:
            wire = bytearray(original)
            if mutate:
                wire[mutate[0]] = mutate[1]
            self.request.write_bytes(wire)
            output = self.root / 'never-created.qpf'
            for wallet in ([], ['--rpc-wallet', 'must-not-contact', '--address', 'invalid']):
                with self.subTest(mutate=mutate, wallet=bool(wallet)):
                    result = subprocess.run([BINARY, 'prove', '--proof-mode', 'key-knowledge', '--request', str(self.request),
                                             '--output', str(output), *wallet],
                                            input='', text=True, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertIn(diagnostic, result.stderr)
                    self.assertNotIn('key input', result.stderr.lower())
                    self.assertFalse(result.stdout)
                    self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
