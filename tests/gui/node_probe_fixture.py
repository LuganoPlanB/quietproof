"""Synthetic RPC probe transcripts; every request is checked against a nonsecret allowlist."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import unquote


class ProbeServer(ThreadingHTTPServer):
    def __init__(self):
        super().__init__(('127.0.0.1', 0), ProbeHandler)
        self.scenario = 'success'
        self.script = '0014' + '11' * 20
        self.calls = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.active = 0
        self.condition = threading.Condition()
        self.violation = None

    def idle(self):
        with self.condition:
            assert self.condition.wait_for(lambda: self.active == 0, 3), 'in-flight RPC remained'


class ProbeHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        server = self.server
        with server.condition:
            server.active += 1
        try:
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            method = body['method']
            params = body['params']
            with server.condition:
                server.calls.append((method, self.path, params))
            allowed = {'getnetworkinfo', 'getblockchaininfo', 'help', 'listwallets',
                       'validateaddress', 'getwalletinfo', 'getaddressinfo'}
            assert method in allowed, 'secret or unexpected RPC method'
            if method == 'help':
                assert params == ['exportaddresskey'], 'unexpected help target'
            scenario = server.scenario
            if scenario in ('async', 'shutdown') and method == 'getnetworkinfo':
                server.entered.set()
                assert server.release.wait(5), 'held fixture operation not released'
            if scenario == 'timeout':
                time.sleep(.4)
            if scenario == 'budget' and method in ('getwalletinfo', 'getaddressinfo'):
                time.sleep(.08)
            auth = 'Basic ' + base64.b64encode(b'__cookie__:synthetic-cookie').decode()
            if scenario == 'unauthorized' or self.headers.get('Authorization') != auth:
                self.send_response(401)
                self.end_headers()
                return
            error = None
            script = server.script
            if scenario == 'wrong-script':
                script = '0014' + '22' * 20
            if method == 'getnetworkinfo':
                result = {'version': 'invalid' if scenario == 'malformed-version' else 310100}
            elif method == 'getblockchaininfo':
                result = {'chain': 'main' if scenario == 'wrong-chain' else 'regtest',
                          'initialblockdownload': scenario == 'syncing'}
                if scenario == 'malformed-chain':
                    result['initialblockdownload'] = 'not-a-boolean'
            elif method == 'help':
                result = 'help: unknown command: exportaddresskey' if scenario == 'unsupported' else 'exportaddresskey "address"\nSynthetic nonsecret help'
                if scenario == 'malformed-help':
                    result = {}
                if scenario == 'unsupported-rpc':
                    error = {'code': -32601, 'message': 'server-private-diagnostic'}
            elif method == 'listwallets':
                result = ['primary']
                if scenario in ('multiple', 'selected', 'missing-selection'):
                    result = ['primary', 'second']
                elif scenario == 'empty-wallet':
                    result = ['']
                elif scenario == 'malformed-wallets':
                    result = ['primary', 'primary']
                elif scenario == 'many-wallets':
                    result = [f'wallet-{i}' for i in range(17)]
                elif scenario == 'no-wallets':
                    result = []
            elif method == 'validateaddress':
                result = {'isvalid': True, 'scriptPubKey': script}
            elif method == 'getwalletinfo':
                assert self.path.startswith('/wallet/'), 'wallet method lacked explicit endpoint'
                assert unquote(self.path[len('/wallet/'):]) in ('primary', 'second', ''), 'wrong wallet endpoint'
                result = {'private_keys_enabled': scenario != 'disabled-keys',
                          'descriptors': scenario != 'legacy-wallet',
                          'external_signer': scenario == 'external-signer'}
                if scenario == 'malformed-wallet-info':
                    result['private_keys_enabled'] = 'not-a-boolean'
            else:
                assert self.path.startswith('/wallet/'), 'address method lacked wallet endpoint'
                result = {'ismine': scenario != 'not-mine', 'iswatchonly': scenario == 'watch-only',
                          'scriptPubKey': script}
                if scenario == 'malformed-address':
                    result['ismine'] = 'not-a-boolean'
                if scenario == 'wallet-script-mismatch':
                    result['scriptPubKey'] = '0014'+'22'*20
            envelope = {'jsonrpc': '2.0', 'id': body['id']}
            envelope['error' if error else 'result'] = error if error else result
            payload = json.dumps(envelope).encode()
            self.send_response(500 if error else 200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass  # Expected when timeout closes a request.
        except Exception as error:
            server.violation = str(error)
        finally:
            with server.condition:
                server.active -= 1
                server.condition.notify_all()


def line(process):
    assert select.select([process.stdout], [], [], 6)[0], 'driver handshake timeout'
    return process.stdout.readline().strip()


def main():
    executable = Path(sys.argv[1]).resolve()
    artifacts = Path(sys.argv[2]).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    scenarios = ('success', 'refused', 'timeout', 'unauthorized', 'wrong-chain', 'syncing',
                 'malformed-version', 'malformed-chain', 'malformed-wallets', 'many-wallets',
                 'multiple', 'selected', 'missing-selection', 'watch-only', 'disabled-keys',
                 'not-mine', 'unsupported', 'unsupported-rpc', 'wrong-script', 'empty-wallet',
                 'p2pkh', 'no-request', 'unsupported-request', 'no-wallets', 'budget', 'invalid-budget',
                 'malformed-help', 'malformed-wallet-info', 'malformed-address',
                 'wallet-script-mismatch', 'legacy-wallet', 'external-signer', 'async', 'shutdown')
    assertions = 0
    with tempfile.TemporaryDirectory(prefix='quietproof-probe-') as directory:
        cookie = Path(directory) / '.cookie'
        cookie.write_text('__cookie__:synthetic-cookie\n')
        cookie.chmod(0o600)
        server = ProbeServer()
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        process = None
        try:
            for scenario in scenarios:
                server.idle()
                server.scenario, server.calls = scenario, []
                server.violation = None
                server.entered.clear()
                server.release.clear()
                server.script = ('76a914' + '11' * 20 + '88ac') if scenario == 'p2pkh' else '0014' + '11' * 20
                url = f'http://127.0.0.1:{server.server_port}/'
                refused = socket.socket()
                if scenario == 'refused':
                    refused.bind(('127.0.0.1', 0))
                    url = f'http://127.0.0.1:{refused.getsockname()[1]}/'
                command = [str(executable), url, str(cookie), scenario]
                try:
                    if scenario in ('async', 'shutdown'):
                        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                   stderr=subprocess.PIPE, text=True)
                        assert line(process) == 'started'
                        assert server.entered.wait(3), 'worker did not enter held HTTP call'
                        process.stdin.write('x')
                        process.stdin.flush()
                        observed = line(process)
                        assert observed == ('held-rejection' if scenario == 'async' else 'closing'), observed
                        assert process.poll() is None and not server.release.is_set(), 'held operation settled early'
                        server.release.set()
                        if scenario == 'async':
                            process.stdin.write('x')
                            process.stdin.flush()
                        stdout, stderr = process.communicate(timeout=6)
                        code = process.returncode
                        process = None
                    else:
                        result = subprocess.run(command, capture_output=True, text=True, timeout=6)
                        stdout, stderr, code = result.stdout, result.stderr, result.returncode
                    (artifacts / (scenario + '.log')).write_text(stdout + stderr)
                    assert code == 0, (scenario, stderr)
                    count = re.search(r'Node probe: (\d+) checks passed', stdout)
                    assert count, (scenario, stdout)
                    assertions += int(count[1])
                    server.idle()
                    assert not server.violation, (scenario, server.violation)
                    assert 'synthetic-cookie' not in stdout + stderr
                    assert 'server-private-diagnostic' not in stdout + stderr
                    methods = [call[0] for call in server.calls]
                    if scenario == 'wrong-chain':
                        assert 'validateaddress' not in methods and 'getaddressinfo' not in methods
                    if scenario == 'wrong-script':
                        assert 'getwalletinfo' not in methods
                    if scenario == 'invalid-budget':
                        assert not methods
                    (artifacts / (scenario + '.json')).write_text(json.dumps(server.calls, indent=2))
                finally:
                    server.release.set()
                    refused.close()
                    if process:
                        process.communicate(timeout=6)
                        process = None
                    server.idle()
        finally:
            server.release.set()
            if process:
                process.communicate(timeout=6)
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)
            assert not thread.is_alive() and server.active == 0, 'fixture cleanup incomplete'
    print(f'Node probe mock: {len(scenarios)} scenarios, {assertions} C++ checks passed; held=0 in-flight=0; no unlock/export calls')


if __name__ == '__main__':
    main()
