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
                    coins = [] if mode == 'discovery-empty' else [{
                        'txid': '11' * 32, 'vout': 0, 'height': 99,
                        'scriptPubKey': '0014' + 'a' * 40, 'amount': 'MONEY_TOKEN'}]
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    args = parser.parse_args()
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
