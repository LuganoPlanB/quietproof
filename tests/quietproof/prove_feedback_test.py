#!/usr/bin/env python3
"""Exercise key diagnostics and interactive feedback without completing a proof."""
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time
import unittest

BINARY = sys.argv.pop(1)
KEY = '0' * 63 + '1'  # Public test vector, never use for funds.


class ProveFeedbackTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        request = str(Path(self.directory.name) / 'request.qpr')
        subprocess.run([
            BINARY, 'challenge', 'create', '--network', 'signet',
            '--verifier', 'example.org', '--purpose', 'proof-of-control', '--message', 'test',
            '--claim', '01' + '00' * 31 + ':0:7:751e76e8199196d454941c45d1b3a323f1433bd6',
            '--output', request,
        ], check=True, capture_output=True)
        self.command = [BINARY, 'prove', '--request', request, '--output',
                        str(Path(self.directory.name) / 'proof.qpf')]

    def rejected(self, text, diagnostic):
        result = subprocess.run(self.command, input=text, text=True,
                                capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 65)
        self.assertIn(diagnostic, result.stderr)
        self.assertNotIn('Generating proof', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_existing_output_rejected_before_key_input(self):
        output = Path(self.command[-1])
        for kind in ('file', 'directory', 'dangling-symlink'):
            with self.subTest(kind=kind):
                if kind == 'file':
                    output.write_bytes(b'preserve me')
                elif kind == 'directory':
                    output.mkdir()
                else:
                    output.symlink_to(output.parent / 'missing')
                process = subprocess.Popen(self.command, stdin=subprocess.PIPE,
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                try:
                    # Keep stdin open: the command must fail without asking for a key.
                    self.assertEqual(process.wait(timeout=5), 74)
                    stdout, stderr = process.communicate()
                    self.assertIn(b'Output destination already exists', stderr)
                    self.assertNotIn(b'Generating proof', stderr)
                    if kind == 'file':
                        self.assertEqual(output.read_bytes(), b'preserve me')
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate()
                    if kind == 'directory':
                        output.rmdir()
                    else:
                        output.unlink()

    def test_malformed_and_eof(self):
        for value in ['tb1qnotaprivatekey\n', '', '\n']:
            with self.subTest(value=value):
                self.rejected(value, 'expected 64 hexadecimal characters')

    def test_invalid_scalar(self):
        for value in ['0' * 64, 'f' * 64]:
            with self.subTest(value=value):
                self.rejected(value + '\n', 'Invalid private key: scalar')

    def test_wrong_key(self):
        self.rejected('0' * 63 + '2\n', 'Private keys do not match the request')

    def test_interactive_feedback_without_echo(self):
        master, slave = pty.openpty()
        process = subprocess.Popen(self.command, stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        received = bytearray()

        def read_until(marker):
            deadline = time.monotonic() + 30
            while marker not in received:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0, 'Timed out waiting for feedback')
                if select.select([master], [], [], remaining)[0]:
                    received.extend(os.read(master, 4096))

        try:
            read_until(b'Key 1/1: ')
            self.assertIn(b'Input is hidden', received)
            os.write(master, (KEY + '\n').encode())
            read_until(b'Keys validated. Generating proof;')
            read_until(b'Proof phase: building circuit')
            self.assertIn(b'Key input received. Checking keys', received)
            self.assertNotIn(KEY.encode(), received)
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            os.close(master)


if __name__ == '__main__':
    unittest.main()
