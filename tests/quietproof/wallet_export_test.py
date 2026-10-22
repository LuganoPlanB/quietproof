#!/usr/bin/env python3
"""Native wallet proving against a loopback fixture; public scalar-one only."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.parse import unquote

BINARY = sys.argv.pop(1)
KEY = '0' * 63 + '1'
PROGRAM = '751e76e8199196d454941c45d1b3a323f1433bd6'
ADDRESS = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        req = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        method = req['method']
        self.server.calls.append((method, req['params'], self.path))
        mode = self.server.mode
        status = 200
        if method == 'getblockchaininfo':
            value = {'chain': 'main' if mode == 'network' else 'signet',
                     'blocks': 100, 'bestblockhash': '11' * 32}
        elif method == 'validateaddress':
            script = '0014' + ('aa' * 20 if mode == 'address' else PROGRAM)
            if mode == 'p2pkh':
                script = '76a914' + PROGRAM + '88ac'
            value = {'isvalid': True, 'scriptPubKey': script, 'address': ADDRESS}
        elif method == 'exportaddresskey':
            value = {'private_key_hex': KEY, 'compressed': True}
            if mode == 'wrong-key': value['private_key_hex'] = '0' * 63 + '2'
            if mode == 'zero': value['private_key_hex'] = '0' * 64
            if mode == 'length': value['private_key_hex'] = '1'
            if mode == 'hex': value['private_key_hex'] = 'z' * 64
            if mode == 'uncompressed': value['compressed'] = False
            if mode == 'type': value['compressed'] = 1
            if mode == 'extra': value['unexpected'] = KEY
        else:
            value = None
        payload = {'jsonrpc': '2.0', 'id': req['id'], 'result': value}
        if method == 'exportaddresskey' and mode in ('missing', 'locked'):
            payload.pop('result')
            payload['error'] = {'code': -32601 if mode == 'missing' else -13,
                                'message': 'server-secret-' + KEY}
            status = 500
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class WalletExportTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.mode = 'ok'
        self.server.calls = []
        thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        cookie = self.root / 'cookie'
        cookie.write_text('__cookie__:fixture')
        cookie.chmod(0o600)
        request = self.root / 'request'
        subprocess.run([BINARY, 'challenge', 'create', '--network', 'signet',
                        '--verifier', 'example.org', '--purpose', 'proof-of-control', '--message', 'fixture',
                        '--claim', '01' + '00' * 31 + ':0:7:' + PROGRAM,
                        '--output', str(request)], check=True, capture_output=True)
        self.command = [BINARY, 'prove', '--request', str(request), '--output', str(self.root / 'proof'),
                        '--rpc-wallet', 'wallet / one', '--address', ADDRESS,
                        '--rpc-url', f'http://127.0.0.1:{self.server.server_port}',
                        '--rpc-cookie', str(cookie)]

    def test_failures_never_prove_or_leak(self):
        for mode in ('network', 'address', 'p2pkh', 'missing', 'locked', 'wrong-key',
                     'zero', 'length', 'hex', 'uncompressed', 'type', 'extra'):
            with self.subTest(mode=mode):
                self.server.mode = mode
                self.server.calls.clear()
                result = subprocess.run(self.command, input='', text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 65, result.stderr)
                self.assertNotIn(KEY, result.stdout + result.stderr)
                self.assertNotIn('server-secret', result.stderr)
                self.assertNotIn('Generating proof', result.stderr)
                self.assertFalse((self.root / 'proof').exists())
                methods = [c[0] for c in self.server.calls]
                self.assertNotIn('listdescriptors', methods)
                if mode in ('network', 'address', 'p2pkh'):
                    self.assertNotIn('exportaddresskey', methods)
                else:
                    self.assertEqual(methods, ['getblockchaininfo', 'validateaddress', 'exportaddresskey'])
                if mode == 'missing': self.assertIn('protected stdin', result.stderr)

    def test_matching_key_reaches_prover_without_stdin(self):
        process = subprocess.Popen(self.command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        observed = bytearray()
        try:
            deadline = time.monotonic() + 30
            while b'Generating proof' not in observed:
                self.assertLess(time.monotonic(), deadline, observed.decode())
                self.assertIsNone(process.poll(), observed.decode())
                if select.select([process.stderr], [], [], 0.2)[0]:
                    observed.extend(__import__('os').read(process.stderr.fileno(), 4096))
            self.assertNotIn(KEY.encode(), observed)
            method, params, path = self.server.calls[-1]
            self.assertEqual((method, params, unquote(path)), ('exportaddresskey', [ADDRESS], '/wallet/wallet / one'))
            self.assertEqual(len(self.server.calls), 3)
        finally:
            process.terminate()
            process.communicate(timeout=10)

    def test_multiple_key_request_rejected_before_rpc(self):
        request = self.root / 'two-keys'
        subprocess.run([BINARY, 'challenge', 'create', '--network', 'signet',
                        '--verifier', 'example.org', '--purpose', 'proof-of-control', '--message', 'fixture',
                        '--claim', '01' + '00' * 31 + ':0:7:' + PROGRAM,
                        '--claim', '02' + '00' * 31 + ':0:7:' + 'aa' * 20,
                        '--output', str(request)], check=True, capture_output=True)
        command = self.command.copy()
        command[command.index('--request') + 1] = str(request)
        result = subprocess.run(command, input='', text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 65)
        self.assertIn('one distinct', result.stderr)
        self.assertEqual(self.server.calls, [])

    def test_rpc_options_require_explicit_wallet_and_address(self):
        for option in ('--rpc-wallet', '--address'):
            command = self.command.copy()
            i = command.index(option)
            del command[i:i+2]
            result = subprocess.run(command, input='', text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 64)
            self.assertEqual(self.server.calls, [])


if __name__ == '__main__':
    unittest.main()
