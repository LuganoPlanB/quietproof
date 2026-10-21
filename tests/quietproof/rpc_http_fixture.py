#!/usr/bin/env python3
"""Exercise the real libcurl adapter against isolated adversarial HTTP peers."""
import argparse
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time


class Server(ThreadingHTTPServer):
    daemon_threads = True
    scenario = 'ok'

    def __init__(self, address, sink_url=''):
        self.records = []
        self.sink_url = sink_url
        super().__init__(address, Handler)


class Handler(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def handle(self):
        # Adversarial truncation/timeouts deliberately make curl close sockets.
        try:
            super().handle()
        except ConnectionResetError:
            pass

    def do_POST(self):
        mode = self.server.scenario
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        self.server.records.append((self.path, self.headers, body))
        try:
            if mode in ('timeout', 'scan-timeout', 'scan-deadline'):
                time.sleep(0.35)
            if mode.startswith(('discovery-', 'wallet-')):
                request = json.loads(body)
                block = '0123456789abcdef' * 4
                method = request['method']
                if method == 'getblockchaininfo':
                    result = json.dumps({'chain': 'regtest', 'blocks': 101,
                                         'bestblockhash': block}).encode()
                elif method == 'validateaddress':
                    result = json.dumps({'isvalid': mode != 'discovery-invalid',
                                         'address': 'bcrt1qfixture',
                                         'scriptPubKey': ('5120' + 'a' * 64 if mode == 'discovery-unsupported'
                                                          else '0014' + 'a' * 40)}).encode()
                elif method == 'listunspent':
                    if mode == 'wallet-redirect':
                        self.send_response(302)
                        self.send_header('Location', self.server.sink_url)
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                        return
                    if mode == 'wallet-auth':
                        self.send_response(401)
                        self.send_header('Content-Length', '0')
                        self.end_headers()
                        return
                    result = (b'[{"txid":"' + b'11' * 32 + b'","vout":0,'
                              b'"confirmations":2,"spendable":false,"safe":false,'
                              b'"scriptPubKey":"0014' + b'a' * 40 + b'","amount":0.00000001}]')
                elif method == 'scantxoutset':
                    if mode == 'discovery-timeout':
                        time.sleep(0.35)
                    if mode == 'discovery-slow':
                        time.sleep(1.1)
                    coins = [] if mode == 'discovery-empty' else [{
                        'txid': '11' * 32, 'vout': 0, 'height': 99,
                        'scriptPubKey': '0014' + 'a' * 40, 'amount': 'MONEY_TOKEN'}]
                    if mode in ('discovery-16', 'discovery-17'):
                        coins = [dict(coins[0], txid=f'{index:064x}')
                                 for index in range(int(mode.split('-')[1]), 0, -1)]
                    result = json.dumps({'success': mode != 'discovery-incomplete',
                                         'bestblock': block, 'height': 100,
                                         'unspents': coins}).encode().replace(b'"MONEY_TOKEN"', b'0.00000001')
                else:
                    assert method == 'gettxout'
                    result = (b'{"bestblock":"' + block.encode() +
                              b'","confirmations":3,"value":0.00000001,'
                              b'"scriptPubKey":{"hex":"0014' + b'a' * 40 + b'"}}')
                payload = (b'{"jsonrpc":"2.0","id":' + json.dumps(request['id']).encode() +
                           (b',"error":{"code":-8,"message":"server-secret"}}'
                            if (mode == 'discovery-busy' and method == 'scantxoutset') or
                               (mode == 'wallet-missing' and method == 'listunspent')
                            else b',"result":' + result + b'}'))
                if mode == 'wallet-missing' and method == 'listunspent':
                    payload = payload.replace(b'"code":-8', b'"code":-18')
                self.send_response(500 if mode == 'wallet-missing' and method == 'listunspent' else 200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if mode.startswith('provider-'):
                request = json.loads(body)
                block = '0123456789abcdef' * 4
                if request['method'] == 'getblockchaininfo':
                    result = json.dumps({'chain': 'regtest', 'blocks': 100,
                                         'bestblockhash': block}).encode()
                elif mode == 'provider-null':
                    result = b'null'
                else:
                    result = (b'{"bestblock":"' + block.encode() +
                              b'","confirmations":2,"value":0.00000001,'
                              b'"scriptPubKey":{"hex":"0014' + b'a' * 40 + b'"}}')
                payload = (b'{"jsonrpc":"2.0","id":' + json.dumps(request['id']).encode() +
                           b',"result":' + result + b'}')
                self.send_response(200)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if mode.startswith('rpc-'):
                request = json.loads(body)
                identifier = request['id']
                status = 500 if mode in ('rpc-error500', 'rpc-success500') else 200
                envelope = {'jsonrpc': '2.0', 'id': identifier, 'result': None}
                if mode in ('rpc-error', 'rpc-error500'):
                    envelope.pop('result')
                    envelope['error'] = {'code': -8, 'message': 'server-secret'}
                if mode == 'rpc-wrongid':
                    envelope['id'] = 'other'
                payload = json.dumps(envelope).encode()
                if mode in ('rpc-ok', 'rpc-money-scan', 'rpc-money-wallet', 'rpc-exponent'):
                    value = b'1e-8' if mode == 'rpc-exponent' else b'0.00000001'
                    result = b'{"value":' + value + b'}'
                    if mode == 'rpc-money-scan':
                        result = b'{"unspents":[{"amount":' + value + b'}]}'
                    elif mode == 'rpc-money-wallet':
                        result = b'[{"amount":' + value + b'}]'
                    payload = b'{"jsonrpc":"2.0","id":' + json.dumps(identifier).encode() + b',"result":' + result + b'}'
                if mode == 'rpc-duplicate':
                    payload = b'{"jsonrpc":"2.0","id":' + json.dumps(identifier).encode() + b',"result":{"x":1,"x":2}}'
                if mode == 'rpc-batch':
                    payload = b'[' + payload + b']'
                if mode == 'rpc-trailing':
                    payload += b' true'
                if mode == 'rpc-badutf8':
                    payload = payload.replace(b'null', b'"\xff"')
                if mode == 'rpc-deep':
                    payload = payload.replace(b'null', b'[' * 64 + b'0' + b']' * 64)
                self.send_response(status)
                self.send_header('Content-Length', str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)
                return
            if mode == 'redirect':
                self.send_response(302)
                self.send_header('Location', self.server.sink_url)
                payload = b'server-secret'
            elif mode == 'auth':
                self.send_response(401)
                self.send_header('WWW-Authenticate', 'Basic realm="fixture"')
                payload = b'server-secret'
            elif mode.startswith('status-'):
                self.send_response(int(mode.split('-')[1]))
                payload = b'{"jsonrpc":"2.0","id":"fixture","error":{"code":-1,"message":"server-secret"}}'
            else:
                self.send_response(200)
                payload = b'fixture-response'
            if mode == 'compression':
                self.send_header('Content-Encoding', 'gzip')
            if mode == 'folded-compression':
                self.send_header('Content-Encoding', 'identity\r\n gzip')
            if mode == 'identity':
                self.send_header('cOnTeNt-EnCoDiNg', ' identity ')
            if mode == 'large-headers':
                self.send_header('X-Large', 'a' * (32 * 1024))
            if mode == 'large-chunked':
                self.send_header('Transfer-Encoding', 'chunked')
                self.end_headers()
                for _ in range(65):
                    block = b'a' * 16384
                    self.wfile.write(b'4000\r\n' + block + b'\r\n')
                self.wfile.write(b'0\r\n\r\n')
                return
            if mode in ('large-body', 'exact-body'):
                payload = b'a' * (1024 * 1024 + (1 if mode == 'large-body' else 0))
                # No Content-Length: enforce the cap while streaming to EOF.
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(payload)
                self.close_connection = True
                return
            if mode == 'truncated':
                self.send_header('Content-Length', str(len(payload) + 100))
                self.send_header('Connection', 'close')
                self.close_connection = True
            else:
                self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass


def cli_main(binary, enabled):
    """Check the public CLI contract without private keys or expensive proofs."""
    checks = 0
    with tempfile.TemporaryDirectory(prefix='quietproof-cli-rpc-') as directory:
        root = Path(directory)
        cookie = root / '.cookie'
        cookie.write_text('__cookie__:cookie-secret\n')
        cookie.chmod(0o600)
        origin = Server(('127.0.0.1', 0))
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        common = ['--network', 'regtest', '--address', 'bcrt1qfixture',
                  '--rpc-url', f'http://127.0.0.1:{origin.server_port}/',
                  '--rpc-cookie', str(cookie)]
        metadata = ['--verifier', 'auditor.example', '--purpose', 'proof-of-funds',
                    '--message', 'fixture']

        def run(arguments, expected=0, machine_failure=False):
            nonlocal checks
            result = subprocess.run([str(binary)] + arguments, capture_output=True,
                                    text=True, timeout=15)
            assert result.returncode == expected, f'CLI check {checks}: expected {expected}, got {result.returncode}'
            assert 'cookie-secret' not in result.stdout + result.stderr
            assert 'server-secret' not in result.stdout + result.stderr
            if expected and not machine_failure:
                assert not result.stdout, 'failure emitted successful JSON'
            checks += 1
            return result

        def challenge(path, extra=(), expected=0, args=None):
            result = run(['challenge', 'create'] + (common if args is None else args) +
                         metadata + ['--output', str(path)] + list(extra), expected)
            if expected:
                assert not path.exists(), 'failed challenge created output'
                assert not list(root.glob(path.name + '.tmp.*')), 'temporary request leaked'
            return result

        def diagnostic(mode='discovery-ok', extra=()):
            origin.scenario = mode
            result = run(['utxos'] + common + list(extra))
            value = json.loads(result.stdout)
            assert value['network'] == 'regtest'
            assert value['source'] == ('wallet' if '--rpc-wallet' in extra else 'scan')
            assert value['count'] == len(value['outputs'])
            assert value['observed_block'] == '0123456789abcdef' * 4
            assert value['observed_height'] == (101 if value['current_rechecked'] or value['source'] == 'wallet' else 100)
            assert value['current_rechecked'] == value['challenge_compatible']
            assert all(type(o['amount_sats']) is int and o['amount_sats'] == 1 and
                       o['program'] == 'a' * 40 and o['vout'] == 0 for o in value['outputs'])
            return value, result

        try:
            origin.scenario = 'discovery-ok'
            if not enabled:
                for command in (['utxos'] + common,
                                ['challenge', 'create'] + common + metadata + ['--output', str(root / 'off.qpr')]):
                    result = run(command, 64)
                    assert json.loads(result.stderr)['error'] == 'native_unavailable'
                assert not origin.records and not (root / 'off.qpr').exists()
            else:
                value, result = diagnostic()
                assert value['challenge_compatible'] and value['outputs'][0]['confirmations'] == 3
                assert value['scan_height'] == 100 and value['scan_block'] == value['observed_block']
                assert 'node-global scan' in result.stderr
                assert not value['incompatibility']
                request = root / 'address.qpr'
                challenge(request)
                assert request.stat().st_mode & 0o777 == 0o600
                inspected = json.loads(run(['inspect', str(request)]).stdout)
                assert inspected['network'] == 'regtest' and inspected['claims'] == 1
                assert inspected['expires_at'] - inspected['not_before'] == 300
                original = request.read_bytes()
                # Compare exact statement encoding with manual claims, masking only
                # the fresh nonce and clock fields generated independently.
                manual_equivalent = root / 'equivalent.qpr'
                run(['challenge', 'create', '--network', 'regtest', '--claim',
                     '11' * 32 + ':0:1:' + 'a' * 40] + metadata +
                    ['--output', str(manual_equivalent)])
                equivalent = manual_equivalent.read_bytes()
                nonce_offset = 6 + 2 + len('auditor.example') + 2 + len('proof-of-funds')
                def fixed_fields(wire):
                    return (wire[:nonce_offset] + wire[nonce_offset + 32:nonce_offset + 64] +
                            wire[nonce_offset + 80:])
                assert fixed_fields(original) == fixed_fields(equivalent), 'address claims changed statement bytes'
                assert original[nonce_offset + 80:nonce_offset + 82] == b'\x00\x00', 'discovery introduced snapshot/bridge'

                run(['challenge', 'create'] + common + metadata + ['--output', str(request)], 74)
                assert request.read_bytes() == original, 'request overwritten'
                for mode, count in (('discovery-empty', 0), ('discovery-16', 16), ('discovery-17', 17)):
                    before = len(origin.records)
                    value, _ = diagnostic(mode)
                    assert value['count'] == count
                    assert value['challenge_compatible'] == (count == 16)
                    assert bool(value['incompatibility']) == (count != 16)
                    txids = [o['txid'] for o in value['outputs']]
                    assert txids == sorted(txids), 'outpoints not canonical'
                    if count != 16:
                        assert len(origin.records) - before == 3, 'incompatible discovery performed rechecks'
                    rejected = challenge(root / f'count-{count}.qpr', expected=0 if count == 16 else 65)
                    if count != 16:
                        assert json.loads(rejected.stderr.splitlines()[-1])['error'] == (
                            'no_eligible_outputs' if count == 0 else 'incompatible_discovery')
                value, _ = diagnostic(extra=['--min-confirmations', '3'])
                assert value['count'] == 0 and value['excluded_below_min_confirmations'] == 1
                challenge(root / 'excluded.qpr', ['--min-confirmations', '3'], 65)
                value, result = diagnostic('wallet-ok', ['--rpc-wallet', 'watch /?'])
                assert value['source'] == 'wallet' and value['scan_height'] is None
                assert not result.stderr and value['scan_block'] is None
                wallet_request = next(json.loads(body) for _, _, body in reversed(origin.records)
                                      if json.loads(body)['method'] == 'listunspent')
                assert wallet_request['params'] == [1, 9999999, ['bcrt1qfixture'], False]
                assert any(path == '/wallet/' + ''.join(f'%{b:02X}' for b in b'watch /?')
                           for path, _, _ in origin.records)
                for mode, category, code in (('discovery-invalid', 'invalid_address', 65),
                                             ('discovery-unsupported', 'unsupported_script', 65),
                                             ('discovery-busy', 'scan_busy', 74),
                                             ('discovery-incomplete', 'scan_incomplete', 74),
                                             ('auth', 'authentication', 74)):
                    origin.scenario = mode
                    result = challenge(root / f'{mode}.qpr', expected=code)
                    assert json.loads(result.stderr.splitlines()[-1])['error'] == category
                origin.scenario = 'discovery-slow'
                result = challenge(root / 'timeout.qpr', ['--rpc-scan-timeout', '1'], 74)
                assert json.loads(result.stderr.splitlines()[-1])['error'] == 'timeout'
                result = challenge(root / 'wrong-network.qpr', expected=65,
                                   args=['--network', 'mainnet'] + common[2:])
                assert json.loads(result.stderr.splitlines()[-1])['error'] == 'wrong_network'
                slow = root / 'slow.qpr'
                challenge(slow, ['--expires-in', '1'])
                finished = int(time.time())
                value = json.loads(run(['inspect', str(slow)]).stdout)
                assert value['not_before'] >= finished - 1, 'challenge lifetime consumed during scan'
                assert value['expires_at'] - value['not_before'] == 1
                # Cookie overrides an unusable datadir; datadir uses the selected network subdir.
                origin.scenario = 'discovery-ok'
                diagnostic(extra=['--rpc-datadir', '/nonexistent-fixture-dir'])
                (root / 'regtest').mkdir()
                (root / 'regtest' / '.cookie').write_bytes(cookie.read_bytes())
                (root / 'regtest' / '.cookie').chmod(0o600)
                no_cookie = common[:-2] + ['--rpc-datadir', str(root)]
                challenge(root / 'datadir.qpr', args=no_cookie)
                for extra in (['--min-confirmations', '0'], ['--min-confirmations', ''],
                              ['--rpc-timeout', '0'], ['--rpc-timeout', '18446744073709551615'],
                              ['--rpc-timeout', ''], ['--rpc-scan-timeout', '0'],
                              ['--rpc-wallet', ''], ['--rpc-cookie', ''],
                              ['--address', 'bcrt1qduplicate']):
                    before = len(origin.records)
                    challenge(root / 'bad-option.qpr', extra, 64)
                    assert len(origin.records) == before, 'invalid options contacted Core'
                before = len(origin.records)
                run(['prove', '--request', str(request), '--output', str(root / 'proof.qpf')], 65)
                assert len(origin.records) == before, 'prove contacted Core'
            # Offline paths must remain independent of native configuration in either build.
            manual = ['challenge', 'create', '--network', 'regtest', '--claim',
                      '01' + '00' * 31 + ':0:7:' + '04' + '00' * 19] + metadata
            before = len(origin.records)
            run(manual + ['--output', str(root / 'manual.qpr')])
            for name, value in (('--rpc-url', common[5]), ('--rpc-cookie', str(cookie)),
                                ('--rpc-datadir', str(root)), ('--rpc-timeout', '1'),
                                ('--rpc-scan-timeout', '1'), ('--rpc-wallet', 'watch'),
                                ('--min-confirmations', '1'), ('--address', 'bcrt1qfixture')):
                run(manual + [name, value, '--output', str(root / 'reject.qpr')], 64)
            assert not (root / 'reject.qpr').exists() and len(origin.records) == before
            # The envelope is syntactically valid with an unsupported proof identity.
            # Shipping cryptographic verification is never bypassed by this fixture.
            statement = (root / 'manual.qpr').read_bytes()
            proof = root / 'unsupported.qpf'
            u32 = lambda n: n.to_bytes(4, 'big')
            proof.write_bytes(b'QPE1\x01' + u32(len(statement)) + statement +
                              b'\x01' + b'\x00' * 31 +
                              u32(1) + u32(4) + u32(128) + u32(1) + b'\x01')
            nonce = root / 'nonces'
            nonce.write_bytes(b'fixture-existing-record\n')
            nonce.chmod(0o600)
            original_nonce = nonce.read_bytes()
            sentinel = root / 'bitcoin-cli'
            called = root / 'subprocess-called'
            sentinel.write_text('#!/bin/sh\n: > "' + str(called) + '"\nexit 1\n')
            sentinel.chmod(0o700)
            verify_args = ['--verifier', 'auditor.example', '--purpose', 'proof-of-funds',
                           '--nonce-store', str(nonce)]
            env = os.environ.copy()
            env['PATH'] = str(root) + os.pathsep + env.get('PATH', '')

            def verify(extra=(), expected=66, result_name='unsupported', legacy=False, path=proof):
                nonlocal checks
                args = ['verify', str(path)] + verify_args + list(extra)
                if legacy:
                    args += ['--bitcoin-cli', str(sentinel)]
                result = subprocess.run([str(binary)] + args, capture_output=True,
                                        text=True, timeout=20, env=env)
                assert result.returncode == expected, f'verify check {checks}: expected {expected}, got {result.returncode}'
                if result_name is None:
                    assert not result.stdout
                else:
                    value = json.loads(result.stdout)
                    assert value == {'result': result_name, 'exit_code': expected,
                                     'total_sats': 0, 'claims_checked': 0}
                assert not called.exists(), 'unexpected legacy process invocation'
                assert nonce.read_bytes() == original_nonce, 'failure consumed nonce'
                assert 'cookie-secret' not in result.stdout + result.stderr
                assert len(origin.records) == before, 'local verification failure contacted Core'
                checks += 1
                return result

            # Explicit legacy remains usable in either build and preserves result JSON.
            result = verify(legacy=True)
            assert 'deprecated legacy backend' in result.stderr
            for flag, value in (('--rpc-url', common[5]), ('--rpc-cookie', str(cookie)),
                                ('--rpc-datadir', str(root)), ('--rpc-timeout', '1')):
                verify([flag, value], 64, None, legacy=True)
            for flag, value in (('--rpc-wallet', 'watch'), ('--rpc-scan-timeout', '1')):
                verify([flag, value], 64, None)
            if enabled:
                result = verify()
                assert 'verification network: regtest' in result.stderr
                assert 'deprecated' not in result.stderr
                verify(['--network', 'signet'], 67, 'invalid_proof')
                verify(['--network', 'regtest', '--verifier', 'different'], 64, None)
                # A local policy rejection occurs before proof machinery or cookie reads.
                saved_verifier = verify_args[1]
                verify_args[1] = 'different-verifier'
                verify(['--rpc-cookie', '/missing-fixture-cookie'], 67, 'invalid_proof')
                verify_args[1] = saved_verifier
                verify(['--network', 'invalid'], 64, None)
                verify(['--rpc-timeout', '0'], 64, None)
                verify(['--rpc-url', common[5], '--rpc-cookie', str(cookie)])
                missing = root / 'missing.qpf'
                verify(expected=65, result_name='malformed_statement', path=missing)
            else:
                result = verify(expected=64, result_name=None)
                assert json.loads(result.stderr)['error'] == 'native_unavailable'
            assert not called.exists() and nonce.read_bytes() == original_nonce

        finally:
            origin.shutdown()
            origin.server_close()
    print(f'CLI RPC {"ON" if enabled else "OFF"}: {checks} contract checks passed')


def api_driver_main(binary, full_proof=False):
    """Exercise the public-API test driver against the installed package without proof authorization shortcuts."""
    checks = 0
    with tempfile.TemporaryDirectory(prefix='quietproof-api-driver-') as directory:
        root = Path(directory)
        cookie = root / '.cookie'
        cookie.write_text('__cookie__:cookie-secret\n')
        cookie.chmod(0o600)
        origin = Server(('127.0.0.1', 0))
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        endpoint = [str(cookie), f'http://127.0.0.1:{origin.server_port}/']
        def run(args, expected=0, key_input=''):
            nonlocal checks
            result = subprocess.run([str(binary)] + args, input=key_input,
                                    capture_output=True, text=True, timeout=120 if full_proof else 30)
            assert result.returncode == expected, f'API driver check {checks}: expected {expected}, got {result.returncode}'
            assert 'cookie-secret' not in result.stdout + result.stderr
            assert 'server-secret' not in result.stdout + result.stderr
            if key_input.strip():
                assert key_input.strip() not in result.stdout + result.stderr, 'key input was echoed'
            checks += 1
            return result
        try:
            origin.scenario = 'discovery-ok'
            result = run(['discover', 'regtest', 'bcrt1qfixture'] + endpoint)
            assert 'outputs=1 challenge_compatible=1' in result.stdout
            assert '11' * 32 + ':0:1:' + 'a' * 40 in result.stdout
            request = root / 'request.qpr'
            run(['challenge', 'regtest', 'bcrt1qfixture', str(request)] + endpoint)
            original = request.read_bytes()
            assert original.startswith(b'QPS1\x01\x03') and b'example.org' in original
            assert request.stat().st_mode & 0o777 == 0o600
            run(['challenge', 'regtest', 'bcrt1qfixture', str(request)] + endpoint, 74)
            assert request.read_bytes() == original
            for mode, count in (('discovery-empty', 0), ('discovery-17', 17)):
                origin.scenario = mode
                result = run(['discover', 'regtest', 'bcrt1qfixture'] + endpoint)
                assert f'outputs={count} challenge_compatible=0' in result.stdout
                rejected = root / f'{mode}.qpr'
                run(['challenge', 'regtest', 'bcrt1qfixture', str(rejected)] + endpoint, 65)
                assert not rejected.exists()
            for mode in ('auth', 'discovery-busy', 'discovery-incomplete'):
                origin.scenario = mode
                rejected = root / f'{mode}.qpr'
                run(['challenge', 'regtest', 'bcrt1qfixture', str(rejected)] + endpoint, 74)
                assert not rejected.exists()
            # Prove has no RPC/configuration arguments and reaches protected input
            # handling with Core unavailable. Invalid scalars fail before heavy work.
            origin.shutdown()
            origin.server_close()
            before = len(origin.records)
            output = root / 'proof.qpf'
            for key in ('', 'not-a-key\n', '0' * 65 + '\n', '01' * 31 + '\n'):
                run(['prove', str(request), str(output)], 65, key)
            run(['prove', str(request), str(output)], 67, '0' * 64 + '\n')
            # A terminal must hide input and restore its previous echo flags.
            import pty
            import select
            import termios
            master, slave = pty.openpty()
            original_flags = termios.tcgetattr(slave)
            process = subprocess.Popen([str(binary), 'prove', str(request), str(output)],
                                       stdin=slave, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                assert select.select([process.stderr], [], [], 5)[0], 'key prompt missing'
                prompt = os.read(process.stderr.fileno(), 256)
                assert b'hexadecimal key' in prompt
                assert not termios.tcgetattr(slave)[3] & termios.ECHO, 'key input echo enabled'
                os.write(master, b'0' * 64 + b'\n')
                stdout, stderr = process.communicate(timeout=10)
                assert process.returncode == 67 and not stdout
                assert b'0' * 64 not in stderr
                assert termios.tcgetattr(slave)[3] == original_flags[3], 'terminal flags not restored'
                checks += 1
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
                os.close(master)
                os.close(slave)

            assert not output.exists() and not list(root.glob('*.tmp.*'))
            run(['prove', str(request), str(output), '--secret', '01'], 64)
            proof = root / 'unsupported.qpf'
            u32 = lambda n: n.to_bytes(4, 'big')
            proof.write_bytes(b'QPE1\x01' + u32(len(original)) + original +
                              b'\x01' + b'\x00' * 31 + u32(1) + u32(4) +
                              u32(128) + u32(1) + b'\x01')
            nonce = root / 'nonces'
            nonce.write_bytes(b'untouched-fixture-record\n')
            nonce.chmod(0o600)
            original_nonce = nonce.read_bytes()
            run(['verify', 'signet', str(proof), str(nonce)] + endpoint, 67)
            result = run(['verify', 'regtest', str(proof), str(nonce)] + endpoint, 66)
            assert result.stdout.strip() == 'unsupported'
            assert nonce.read_bytes() == original_nonce and len(origin.records) == before
            if full_proof:
                # Public scalar-one fixture; the final 20 statement bytes are
                # the sole claim's program. No signing key enters argv or env.
                matching = root / 'matching.qpr'
                matching.write_bytes(original[:-20] + bytes.fromhex(
                    '751e76e8199196d454941c45d1b3a323f1433bd6'))
                run(['prove', str(matching), str(output)], key_input='0' * 63 + '1\n')
                assert output.stat().st_mode & 0o777 == 0o600
                assert output.read_bytes().startswith(b'QPE1\x02')
                assert len(origin.records) == before, 'offline proof used RPC'
                result = run(['verify', 'regtest', str(output), str(nonce)] + endpoint, 5)
                assert result.stdout.strip() == 'state_inconclusive'
                failure_peer = Server(('127.0.0.1', 0))
                failure_peer.scenario = 'auth'
                threading.Thread(target=failure_peer.serve_forever, daemon=True).start()
                try:
                    result = run(['verify', 'regtest', str(output), str(nonce), str(cookie),
                                  f'http://127.0.0.1:{failure_peer.server_port}/'], 5)
                    assert result.stdout.strip() == 'state_inconclusive'
                    assert len(failure_peer.records) == 1, 'proof did not reach authenticated RPC'
                    assert json.loads(failure_peer.records[0][2])['method'] == 'getblockchaininfo'
                finally:
                    failure_peer.shutdown()
                    failure_peer.server_close()
                assert nonce.read_bytes() == original_nonce, 'failed real-proof verification consumed nonce'
        finally:
            origin.shutdown()
            origin.server_close()
    print(f'Installed-package API driver: {checks} contract checks passed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--cli', action='store_true')
    parser.add_argument('--cli-off', action='store_true')
    parser.add_argument('--api-driver', action='store_true')
    parser.add_argument('--api-driver-proof', action='store_true')
    args = parser.parse_args()
    if args.api_driver or args.api_driver_proof:
        return api_driver_main(args.binary, args.api_driver_proof)
    if args.cli or args.cli_off:
        return cli_main(args.binary, not args.cli_off)
    checks = 0

    def run(arguments, env=None):
        nonlocal checks
        result = subprocess.run([str(args.binary)] + arguments, env=env,
                                capture_output=True, text=True, timeout=8)
        # Only test-owned labels are printable; request/auth/body stay in memory.
        if result.returncode:
            raise RuntimeError(result.stderr.strip())
        if 'cookie-secret' in result.stdout + result.stderr or 'server-secret' in result.stdout + result.stderr:
            raise RuntimeError('credential/body appeared in diagnostics')
        checks += 1

    run([])
    servers = []
    try:
        sink = Server(('127.0.0.1', 0))
        servers.append(sink)
        proxy = Server(('127.0.0.1', 0))
        servers.append(proxy)
        origin = Server(('127.0.0.1', 0), f'http://127.0.0.1:{sink.server_port}/')
        servers.append(origin)
        for server in servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with tempfile.TemporaryDirectory(prefix='quietproof-http-') as directory:
            cookie = Path(directory) / '.cookie'
            cookie.write_text('__cookie__:cookie-secret\n')
            cookie.chmod(0o600)
            home = Path(directory) / 'home'
            home.mkdir()
            (home / '.netrc').write_text('machine 127.0.0.1 login netrc-user password netrc-secret\n')
            (home / '.netrc').chmod(0o600)
            env = os.environ.copy()
            proxy_url = f'http://127.0.0.1:{proxy.server_port}/'
            for name in ('http_proxy', 'https_proxy', 'all_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY'):
                env[name] = proxy_url
            env['NO_PROXY'] = env['no_proxy'] = ''
            env['HOME'] = str(home)
            url = f'http://127.0.0.1:{origin.server_port}/'
            modes = ('ok', 'identity', 'auth', 'status-403', 'status-404', 'status-500',
                     'redirect', 'compression', 'folded-compression', 'timeout', 'scan-timeout', 'scan-deadline',
                     'large-body', 'large-chunked', 'large-headers', 'truncated', 'exact-body')
            expected_auth = 'Basic ' + base64.b64encode(b'__cookie__:cookie-secret').decode()
            for mode in modes:
                origin.scenario = mode
                count = len(origin.records)
                run(['--http', url, str(cookie), mode], env)
                assert len(origin.records) == count + 1, 'request was retried or omitted'
                path, headers, payload = origin.records[-1]
                assert path == '/', 'unexpected request path'
                assert headers.get('Authorization') == expected_auth, 'Basic cookie auth missing'
                assert headers.get_content_type() == 'application/json', 'wrong content type'
                assert headers.get('Accept-Encoding') == 'identity', 'compression requested'
                decoded = json.loads(payload)
                assert decoded == {'jsonrpc': '2.0', 'id': 'fixture', 'method': 'getblockchaininfo', 'params': []}
            for mode in ('rpc-ok', 'rpc-null', 'rpc-money-scan', 'rpc-money-wallet',
                         'rpc-error', 'rpc-error500', 'rpc-success500', 'rpc-wrongid',
                         'rpc-duplicate', 'rpc-batch', 'rpc-trailing', 'rpc-badutf8',
                         'rpc-deep', 'rpc-exponent'):
                origin.scenario = mode
                count = len(origin.records)
                run(['--rpc', url, str(cookie), mode], env)
                expected_count = 2 if mode == 'rpc-ok' else 1
                assert len(origin.records) == count + expected_count, 'RPC was retried or omitted'
                for index, (path, headers, payload) in enumerate(origin.records[count:], 1):
                    request = json.loads(payload)
                    assert request['id'] == str(index) and isinstance(request['id'], str), 'RPC ID sequence/type'
                    assert request['params'] == ['quoted"\\\ninput'], 'RPC parameter escaping'
                    assert path == '/' and headers.get('Authorization') == expected_auth
            for mode in ('provider-ok', 'provider-null'):
                origin.scenario = mode
                count = len(origin.records)
                run(['--provider', url, str(cookie), mode], env)
                methods = ['getblockchaininfo', 'gettxout']
                if mode == 'provider-ok':
                    methods.append('getblockchaininfo')
                methods *= 2  # Direct Lookup then fresh public-provider verification.
                records = origin.records[count:]
                assert len(records) == len(methods), 'provider request count'
                for index, ((path, headers, payload), method) in enumerate(zip(records, methods), 1):
                    params = ['03' + '00' * 31, 0, True] if method == 'gettxout' else []
                    assert json.loads(payload) == {'jsonrpc': '2.0', 'id': str(index),
                                                   'method': method, 'params': params}
                    assert path == '/' and headers.get('Authorization') == expected_auth
            for mode in ('discovery-ok', 'discovery-empty', 'discovery-invalid',
                         'discovery-unsupported', 'discovery-busy', 'discovery-incomplete',
                         'discovery-timeout'):
                origin.scenario = mode
                count = len(origin.records)
                run(['--discover', url, str(cookie), mode], env)
                methods = ['getblockchaininfo', 'validateaddress']
                if mode not in ('discovery-invalid', 'discovery-unsupported'):
                    methods += ['scantxoutset']
                if mode == 'discovery-ok':
                    methods += ['getblockchaininfo', 'gettxout', 'getblockchaininfo']
                records = origin.records[count:]
                assert len(records) == len(methods), 'discovery retried or omitted request'
                for index, ((path, headers, payload), method) in enumerate(zip(records, methods), 1):
                    request = json.loads(payload)
                    assert request['method'] == method and request['id'] == str(index)
                    params = (['bcrt1qfixture'] if method == 'validateaddress' else
                              ['start', ['addr(bcrt1qfixture)']] if method == 'scantxoutset' else
                              ['11' * 32, 0, True] if method == 'gettxout' else [])
                    assert request['params'] == params
                    assert path == '/' and headers.get('Authorization') == expected_auth
            wallet_names = {'wallet-dot': '.', 'wallet-dotdot': '..', 'wallet-unicode': 'é/財布'}
            for mode in ('wallet-ok', 'wallet-dot', 'wallet-dotdot', 'wallet-unicode',
                         'wallet-missing', 'wallet-redirect', 'wallet-auth'):
                origin.scenario = mode
                count = len(origin.records)
                run(['--wallet', url, str(cookie), mode], env)
                methods = ['getblockchaininfo', 'validateaddress', 'listunspent']
                if mode not in ('wallet-missing', 'wallet-redirect', 'wallet-auth'):
                    methods += ['getblockchaininfo', 'gettxout', 'getblockchaininfo']
                records = origin.records[count:]
                assert len(records) == len(methods), 'wallet fallback, retry or omitted request'
                name = wallet_names.get(mode, 'watch /../?x#%@:123')
                wallet_path = '/wallet/' + ''.join(f'%{byte:02X}' for byte in name.encode())
                for index, ((path, headers, payload), method) in enumerate(zip(records, methods), 1):
                    request = json.loads(payload)
                    assert request['method'] == method and request['id'] == str(index)
                    params = (['bcrt1qfixture'] if method == 'validateaddress' else
                              [1, 9999999, ['bcrt1qfixture'], False] if method == 'listunspent' else
                              ['11' * 32, 0, True] if method == 'gettxout' else [])
                    assert request['params'] == params, 'wallet unsafe/filter/truncation arguments'
                    assert path == (wallet_path if method == 'listunspent' else '/')
                    assert headers.get('Authorization') == expected_auth
            origin.scenario = 'ok'
            run(['--rotate' , url, str(cookie)], env)
            old_auth = origin.records[-2][1].get('Authorization')
            new_auth = origin.records[-1][1].get('Authorization')
            assert old_auth == expected_auth and new_auth == 'Basic ' + base64.b64encode(b'__cookie__:rotated-secret').decode()
            # Binding without listening keeps this local port reserved/refusing.
            with socket.socket() as refused:
                refused.bind(('127.0.0.1', 0))
                run(['--http', f'http://127.0.0.1:{refused.getsockname()[1]}/', str(cookie), 'refused'], env)
            try:
                class IPv6Server(Server):
                    address_family = socket.AF_INET6
                ipv6 = IPv6Server(('::1', 0))
            except OSError:
                raise RuntimeError('IPv6 loopback is required for this adapter gate') from None
            servers.append(ipv6)
            threading.Thread(target=ipv6.serve_forever, daemon=True).start()
            run(['--http', f'http://[::1]:{ipv6.server_port}/', str(cookie), 'ok'], env)
            assert len(ipv6.records) == 1, 'IPv6 request omitted'
            assert not sink.records, 'redirect destination received a request or credentials'
            assert not proxy.records, 'environment proxy received a request or credentials'
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
    print(f'RPC transport passed: {checks} adapter executions; redirect/proxy isolation and IPv6 checked')


if __name__ == '__main__':
    main()
