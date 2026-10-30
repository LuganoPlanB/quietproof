"""Synthetic wallet sessions. Evidence contains method names/paths, never secrets."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
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


PROGRAM = '751e76e8199196d454941c45d1b3a323f1433bd6'
HELD = ('wallet-switch', 'request-switch', 'close', 'cancel-after-unlock', 'worker-cancel', 'worker-close', 'export-preflight-cancel')
SCENARIOS = ('locked', 'prompt', 'unlocked', 'unencrypted', 'became-unlocked',
             'unnamed', 'wrong-password', 'retry', 'unsupported', 'unsupported-unlock',
             'watch-only', 'wrong-chain', 'wrong-script', 'wrong-wallet-script',
             'missing-wallet', 'no-selection', 'no-approval', 'network-config',
             'unsupported-script', 'expired', 'expires-after-probe', 'cancel-before',
             'bad-key', 'out-of-range-key', 'wrong-key', 'malformed-export',
             'uncompressed-export', 'unsupported-export', 'export-failure', 'export-disconnect',
             'export-timeout', 'export-partial-timeout', 'unlock-disconnect', 'unlock-timeout', 'unlock-malformed',
             'relock-failure', 'lock-timeout', 'lock-malformed', 'unauthorized',
             'malformed-state', 'p2pkh', 'worker-success', 'worker-retry', *HELD)


class Server(ThreadingHTTPServer):
    def __init__(self):
        super().__init__(('127.0.0.1', 0), Handler)
        self.condition = threading.Condition()
        self.active = 0
        self.entered = threading.Event()
        self.release = threading.Event()
        self.calls = []
        self.violation = None
        self.unlocks = 0
        self.states = 0

    def idle(self):
        with self.condition:
            assert self.condition.wait_for(lambda: self.active == 0, 4), 'fixture cleanup left an in-flight operation'


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        s = self.server
        with s.condition:
            s.active += 1
        try:
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            method, params, scenario = body['method'], body['params'], s.scenario
            # Sanitize before retaining any transcript, including error cases.
            s.calls.append({'method': method, 'path': self.path,
                            'parameter_count': len(params)})
            allowed = {'getnetworkinfo', 'getblockchaininfo', 'help', 'listwallets',
                       'validateaddress', 'getwalletinfo', 'getaddressinfo',
                       'walletpassphrase', 'walletlock', 'exportaddresskey'}
            assert method in allowed, 'unexpected RPC'
            wallet = '' if scenario == 'unnamed' else 'primary'
            if method in ('getwalletinfo', 'getaddressinfo', 'walletpassphrase', 'walletlock', 'exportaddresskey'):
                assert self.path.startswith('/wallet/'), 'missing explicit wallet endpoint'
                actual = unquote(self.path[8:])
                probe_only = method in ('getwalletinfo', 'getaddressinfo')
                assert actual == wallet or (probe_only and ((scenario == 'unnamed' and actual == 'secondary') or (scenario == 'missing-wallet' and actual == 'absent'))), 'cleanup/export changed selected wallet'
            script = ('76a914' + PROGRAM + '88ac') if scenario == 'p2pkh' else '0014' + PROGRAM
            error, result = None, None
            if scenario == 'unauthorized':
                self.send_response(401)
                self.end_headers()
                return
            if method == 'getnetworkinfo':
                result = {'version': 310100}
            elif method == 'getblockchaininfo':
                result = {'chain': 'main' if scenario == 'wrong-chain' else 'regtest',
                          'initialblockdownload': False, 'blocks': 1, 'bestblockhash': 'ab' * 32}
            elif method == 'help':
                assert params == ['exportaddresskey'], 'only Roots export provider'
                result = 'exportaddresskey "address"'
                if scenario == 'unsupported':
                    error = -32601
            elif method == 'listwallets':
                result = ['absent'] if scenario == 'missing-wallet' else [wallet]
                # Empty name must remain explicit even with another loaded wallet.
                if scenario == 'unnamed':
                    result = ['', 'secondary']
            elif method == 'validateaddress':
                if scenario == 'export-preflight-cancel' and s.unlocks == 1:
                    s.entered.set()
                    assert s.release.wait(5), 'held export preflight was not released'
                result = {'isvalid': True, 'scriptPubKey': '0014' + '22' * 20 if scenario == 'wrong-script' else script}
            elif method == 'getwalletinfo':
                # Probe visits all wallets. The unnamed scenario's second wallet
                # is never eligible and must never be unlocked/exported/relocked.
                s.states += 1
                result = {'private_keys_enabled': True, 'descriptors': True, 'external_signer': False}
                if scenario == 'unnamed' and unquote(self.path[8:]) == 'secondary':
                    result['private_keys_enabled'] = False
                if scenario != 'unencrypted':
                    result['unlocked_until'] = 9999999999 if scenario == 'unlocked' or (scenario == 'became-unlocked' and s.states >= 2) else 0
                if scenario == 'malformed-state':
                    result['unlocked_until'] = 'invalid'
            elif method == 'getaddressinfo':
                result = {'ismine': True, 'iswatchonly': scenario == 'watch-only',
                          'scriptPubKey': '0014' + '22' * 20 if scenario == 'wrong-wallet-script' else script}
            elif method == 'walletpassphrase':
                s.unlocks += 1
                assert len(params) == 2 and len(params[0]) == 12 and params[1] == 15, 'bounded single lease'
                if scenario in HELD and scenario != 'export-preflight-cancel':
                    s.entered.set()
                    assert s.release.wait(5), 'held unlock was not released'
                if scenario == 'wrong-password' or (scenario in ('retry','worker-retry') and s.unlocks == 1):
                    error = -14
                elif scenario == 'unsupported-unlock':
                    error = -32601
                elif scenario == 'unlock-disconnect':
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                elif scenario == 'unlock-timeout':
                    time.sleep(.4)
                elif scenario == 'unlock-malformed':
                    result = True
            elif method == 'walletlock':
                assert params == [], 'unexpected cleanup parameters'
                if scenario == 'relock-failure':
                    error = -1
                elif scenario == 'lock-timeout':
                    time.sleep(.4)
                elif scenario == 'lock-malformed':
                    result = True
            elif method == 'exportaddresskey':
                if scenario == 'export-failure':
                    error = -13
                elif scenario == 'unsupported-export':
                    error = -32601
                elif scenario == 'export-disconnect':
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                elif scenario == 'export-timeout':
                    time.sleep(.4)
                # Generate synthetic key only in memory. Never serialize it into
                # test reports/transcripts, error messages, stdout or process args.
                value = 0 if scenario == 'bad-key' else (2**256-1) if scenario == 'out-of-range-key' else 2 if scenario == 'wrong-key' else 1
                result = {'private_key_hex': format(value, '064x'), 'compressed': True}
                if scenario == 'uncompressed-export':
                    result['compressed'] = False
                if scenario == 'malformed-export':
                    result.pop('private_key_hex')
            if error:
                payload = {'jsonrpc': '2.0', 'id': body['id'],
                           'error': {'code': error, 'message': 'server-private-diagnostic'}}
            else:
                payload = {'jsonrpc': '2.0', 'id': body['id'], 'result': result}
            data = json.dumps(payload).encode()
            self.send_response(500 if error else 200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            if scenario == 'export-partial-timeout' and method == 'exportaddresskey':
                self.wfile.write(data[:-2])
                self.wfile.flush()
                s.partial_sent = True
                time.sleep(.4)
                return
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception:
            s.violation = 'RPC transcript assertion failed; private diagnostics suppressed'
        finally:
            with s.condition:
                s.active -= 1
                s.condition.notify_all()


def line(process):
    assert select.select([process.stdout], [], [], 6)[0], 'driver handshake deadline'
    return process.stdout.readline().strip()


def main():
    executable, artifacts = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    artifacts.mkdir(parents=True, exist_ok=True)
    assertions = 0
    summary = []
    with tempfile.TemporaryDirectory(prefix='quietproof-wallet-session-') as directory:
        cookie = Path(directory) / '.cookie'
        cookie.write_text('__cookie__:' + ''.join(chr(97+i) for i in range(12)))
        cookie.chmod(0o600)
        server = Server()
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        process = None
        try:
            for scenario in SCENARIOS:
                server.idle()
                server.scenario = scenario
                server.calls, server.violation = [], None
                server.states, server.unlocks = 0, 0
                server.partial_sent = False
                server.entered.clear(); server.release.clear()
                command = [str(executable), f'http://127.0.0.1:{server.server_port}/', str(cookie), scenario]
                try:
                    if scenario in HELD:
                        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                                   stderr=subprocess.PIPE, text=True)
                        assert line(process) == 'started'
                        assert server.entered.wait(4), 'unlock gate precondition absent'
                        process.stdin.write('x'); process.stdin.flush()
                        assert line(process) == 'invalidated'
                        assert process.poll() is None and not server.release.is_set(), 'held unlock settled prematurely'
                        server.release.set()
                        process.stdin.write('x'); process.stdin.flush()
                        stdout, stderr = process.communicate(timeout=8)
                        code = process.returncode
                        process = None
                    else:
                        value = subprocess.run(command,capture_output=True,text=True,timeout=8)
                        stdout, stderr, code = value.stdout, value.stderr, value.returncode
                    # Only test assertion counts and authored generic failure
                    # messages are admitted to durable evidence.
                    count = re.search(r'Wallet session: (\d+) checks passed',stdout)
                    assert code == 0 and count, f'{scenario}: driver assertion failure'
                    assertions += int(count[1])
                    server.idle()
                    assert not server.violation, f'{scenario}: transcript violation'
                    methods = [x['method'] for x in server.calls]
                    no_access = ('prompt','unsupported','watch-only','wrong-chain','wrong-script',
                                 'wrong-wallet-script','missing-wallet','no-selection','no-approval',
                                 'network-config','unsupported-script','expired','expires-after-probe',
                                 'cancel-before','unauthorized','malformed-state')
                    if scenario in no_access:
                        assert not set(methods) & {'walletpassphrase','exportaddresskey','walletlock'}, f'{scenario}: premature key access'
                    if scenario in ('unlocked','unencrypted','became-unlocked'):
                        assert 'walletpassphrase' not in methods and 'walletlock' not in methods, 'preexisting unlock changed'
                    if scenario in ('wrong-password','unsupported-unlock'):
                        assert methods.count('walletpassphrase') == 1 and 'walletlock' not in methods, 'rejected unlock ownership wrong'
                    if scenario in HELD:
                        assert methods[-1] == 'walletlock' and 'exportaddresskey' not in methods, 'cancellation cleanup wrong'
                    if scenario == 'unnamed':
                        assert methods.count('listwallets') == 1, 'explicit unnamed export auto-selected wallet'
                    assert methods.count('walletpassphrase') <= (2 if scenario in ('retry','worker-retry') else 1), 'unlock silently retried'
                    if 'exportaddresskey' in methods:
                        assert methods.index('validateaddress') < methods.index('exportaddresskey'), 'export preceded matching'
                    if scenario == 'export-partial-timeout':
                        assert server.partial_sent, 'partial response precondition absent'
                    summary.append({'scenario':scenario,'exit':code,'checks':int(count[1]),
                                    'held_precondition':scenario in HELD,'remaining_operations':server.active,
                                    'partial_response_sent':server.partial_sent,'calls':server.calls})
                finally:
                    server.release.set()
                    if process:
                        try:
                            process.communicate(input='xx',timeout=8)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.communicate(timeout=2)
                        process = None
                    server.idle()
        finally:
            server.release.set()
            server.idle()
            server.shutdown(); server.server_close(); thread.join(timeout=4)
            assert not thread.is_alive(), 'fixture thread did not settle'
    (artifacts/'summary.json').write_text(json.dumps({'scenarios':summary,'checks':assertions,
                                                    'held_operations':0,'in_flight_operations':0},indent=2)+'\n')
    print(f'Wallet sessions: {len(summary)} scenarios, {assertions} checks passed; held=0 in-flight=0')


if __name__ == '__main__':
    main()
