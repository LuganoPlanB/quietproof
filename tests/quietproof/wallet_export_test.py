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
P2PKH_ADDRESS = 'mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r'
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
            value = {'chain': 'main' if mode == 'network' else getattr(self.server, 'chain', 'signet'),
                     'blocks': 100, 'bestblockhash': '11' * 32}
        elif method == 'validateaddress':
            script = '0014' + ('aa' * 20 if mode == 'address' else PROGRAM)
            if mode == 'p2pkh' or req['params'][0] in (P2PKH_ADDRESS, '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'):
                script = '76a914' + ('aa' * 20 if mode == 'address' else PROGRAM) + '88ac'
            value = {'isvalid': True, 'scriptPubKey': script, 'address': ADDRESS}
        elif method == 'gettxout':
            value = {'bestblock': '11' * 32, 'confirmations': 10,
                     'value': 0.00000007,
                     'scriptPubKey': {'hex': '76a914' + PROGRAM + '88ac'}}
        elif method == 'listwallets':
            value = {'no-wallet': [], 'many-wallets': ['one', 'two'],
                     'bad-wallets': {}, 'bad-name': [7]}.get(mode, ['wallet / one'])
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
        # Core emits fixed decimal BTC amounts, not Python's scientific notation.
        data = json.dumps(payload).replace('7e-08', '0.00000007').encode()
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

    def test_existing_outputs_rejected_before_rpc(self):
        output = self.root / 'proof'
        output.write_bytes(b'preserve me')
        challenge = [BINARY, 'challenge', 'create', '--network', 'signet',
                     '--verifier', 'example.org', '--purpose', 'proof-of-control',
                     '--message', 'fixture', '--address', ADDRESS,
                     '--output', str(output)]
        for option in ('--rpc-url', '--rpc-cookie'):
            i = self.command.index(option)
            challenge.extend(self.command[i:i+2])
        for command in (self.command, challenge):
            with self.subTest(command=command[1]):
                result = subprocess.run(command, input='', text=True,
                                        capture_output=True, timeout=5)
                self.assertEqual(result.returncode, 74, result.stderr)
                self.assertIn('Output destination already exists', result.stderr)
                self.assertEqual(self.server.calls, [])
                self.assertEqual(output.read_bytes(), b'preserve me')

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

    def assert_reaches_prover(self, command, call_count, address=ADDRESS):
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
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
            self.assertEqual((method, params, unquote(path)), ('exportaddresskey', [address], '/wallet/wallet / one'))
            self.assertEqual(len(self.server.calls), call_count)
        finally:
            process.terminate()
            process.communicate(timeout=10)

    def test_multiple_key_request_rejected_before_rpc(self):
        request = self.root / 'two-keys'
        result = subprocess.run([BINARY, 'challenge', 'create', '--network', 'signet',
                        '--verifier', 'example.org', '--purpose', 'proof-of-control', '--message', 'fixture',
                        '--claim', '01' + '00' * 31 + ':0:7:' + PROGRAM,
                        '--claim', '02' + '00' * 31 + ':0:7:' + 'aa' * 20,
                        '--output', str(request)], text=True, capture_output=True)
        self.assertEqual(result.returncode, 65)
        self.assertFalse(request.exists())
        self.assertEqual(self.server.calls, [])

    def automatic_command(self):
        command = self.command.copy()
        for option in ('--rpc-wallet', '--address'):
            i = command.index(option)
            del command[i:i+2]
        return command + ['--network', 'signet']

    def test_explicit_key_reaches_prover(self):
        self.assert_reaches_prover(self.command, 3)

    def test_automatic_wallet_and_address(self):
        self.assert_reaches_prover(self.automatic_command(), 4)
        self.assertEqual([c[0] for c in self.server.calls],
                         ['getblockchaininfo', 'validateaddress', 'listwallets', 'exportaddresskey'])

    def typed_command(self, kinds, explicit=False, network="signet"):
        request = self.root / ('request-' + network + '-'.join(kinds))
        command = [BINARY, 'challenge', 'create', '--network', network,
                   '--output', str(request)]
        for i, kind in enumerate(kinds):
            command += ['--claim', f'{i+1:02x}' + '00' * 31 + ':0:7:' + kind + ':' + PROGRAM]
        subprocess.run(command, check=True, capture_output=True)
        command = self.automatic_command()
        command[-1] = network
        command[command.index('--request') + 1] = str(request)
        if explicit:
            command += ['--address', P2PKH_ADDRESS]
        return command

    def test_p2pkh_wallet_address(self):
        for explicit in (False, True):
            with self.subTest(explicit=explicit):
                # Use separate requests because output overwrite is forbidden.
                kinds = ['p2pkh'] * (2 if explicit else 1)
                self.server.calls.clear()
                self.assert_reaches_prover(self.typed_command(kinds, explicit), 4, P2PKH_ADDRESS)
                self.assertEqual(self.server.calls[1][1], [P2PKH_ADDRESS])

    def test_mixed_same_key_prefers_p2pkh(self):
        self.assert_reaches_prover(self.typed_command(['p2wpkh', 'p2pkh']), 4, P2PKH_ADDRESS)

    def test_mixed_explicit_p2wpkh_address(self):
        command = self.typed_command(['p2pkh', 'p2wpkh']) + ['--address', ADDRESS]
        self.assert_reaches_prover(command, 4)

    def test_p2pkh_export_failures(self):
        command = self.typed_command(['p2pkh'])
        for mode in ('address', 'uncompressed', 'wrong-key', 'locked', 'missing'):
            with self.subTest(mode=mode):
                self.server.mode = mode
                self.server.calls.clear()
                result = subprocess.run(command, input='', text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode, 65, result.stderr)
                self.assertNotIn(KEY, result.stdout + result.stderr)
                self.assertNotIn('server-secret', result.stderr)
                self.assertNotIn('Generating proof', result.stderr)
                self.assertFalse((self.root / 'proof').exists())
                if mode == 'address':
                    self.assertNotIn('exportaddresskey', [c[0] for c in self.server.calls])

    def test_p2pkh_network_addresses(self):
        for network, chain, address in (
            ('mainnet', 'main', '1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH'),
            ('testnet', 'test', P2PKH_ADDRESS),
            ('testnet4', 'testnet4', P2PKH_ADDRESS),
            ('regtest', 'regtest', P2PKH_ADDRESS),
        ):
            with self.subTest(network=network):
                self.server.chain = chain
                self.server.calls.clear()
                self.assert_reaches_prover(self.typed_command(['p2pkh'], network=network), 4, address)

    def test_p2pkh_wallet_proof_round_trip(self):
        command = self.typed_command(['p2pkh', 'p2pkh'])
        result = subprocess.run(command, input='', text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(KEY, result.stdout + result.stderr)
        self.assertEqual(self.server.calls[-1][1], [P2PKH_ADDRESS])
        verify = [BINARY, 'verify', str(self.root / 'proof'), '--network', 'signet',
                  '--nonce-store', str(self.root / 'nonces')]
        for option in ('--rpc-url', '--rpc-cookie'):
            i = command.index(option)
            verify += command[i:i+2]
        result = subprocess.run(verify, text=True, capture_output=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertEqual(json.loads(result.stdout)['total_sats'], 14)

    def test_p2pkh_rejects_unclaimed_kind_before_export(self):
        command = self.typed_command(['p2pkh']) + ['--address', ADDRESS]
        result = subprocess.run(command, input='', text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 65, result.stderr)
        self.assertNotIn('exportaddresskey', [c[0] for c in self.server.calls])

    def test_wallet_selection_failures(self):
        for mode in ('no-wallet', 'many-wallets', 'bad-wallets', 'bad-name'):
            with self.subTest(mode=mode):
                self.server.mode = mode
                self.server.calls.clear()
                result = subprocess.run(self.automatic_command(), input='', text=True,
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 65, result.stderr)
                self.assertNotIn('exportaddresskey', [c[0] for c in self.server.calls])
                self.assertFalse((self.root / 'proof').exists())

    def test_network_option_mismatch_before_rpc(self):
        command = self.automatic_command()
        command[-1] = 'mainnet'
        result = subprocess.run(command, input='', text=True, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 65)
        self.assertIn('Network does not match', result.stderr)
        self.assertEqual(self.server.calls, [])


if __name__ == '__main__':
    unittest.main()
