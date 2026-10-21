#!/usr/bin/env python3
"""CLI defaults remain concrete transcript fields and exact policy expectations."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

BINARY = sys.argv.pop(1)
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

    def create(self, *args):
        return subprocess.run([
            BINARY, 'challenge', 'create', '--network', 'signet',
            '--claim', CLAIM, '--output', str(self.request), *args,
        ], text=True, capture_output=True, timeout=10)

    def test_omitted_fields_and_empty_message(self):
        result = self.create()
        self.assertEqual(result.returncode, 0, result.stderr)
        info = json.loads(result.stdout)
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
            '--nonce-store', str(nonce), *args,
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


if __name__ == '__main__':
    unittest.main()
