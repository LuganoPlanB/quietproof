#!/usr/bin/env python3
"""Opt-in, isolated Core 28/30 acceptance. No downloads or default node access.

Only the disposable scalar 1 fixture is used. Core never receives its secret;
the BIP143 spend is signed locally below using Python integers. This arithmetic
is test-only, variable-time and unsuitable for production keys.
"""
import argparse
import base64
import concurrent.futures
import hashlib
import hmac
import http.client
import http.server
import json
import os
from pathlib import Path
import re
import resource
import socket
import struct
import subprocess
import tempfile
import threading
import time
from urllib.parse import quote


SECRET = '00' * 31 + '01'  # Published, disposable regtest fixture, never a real key.
PUBKEY = bytes.fromhex('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
PROGRAM = hashlib.new('ripemd160', hashlib.sha256(PUBKEY).digest()).digest()
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
FIELD = 2**256 - 2**32 - 977
GENERATOR = (int.from_bytes(PUBKEY[1:], 'big'),
             0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    xx, yy = right
    if x == xx and (y != yy or y == 0):
        return None
    slope = ((3 * x * x) * pow(2 * y, -1, FIELD) if left == right else
             (yy - y) * pow(xx - x, -1, FIELD)) % FIELD
    rx = (slope * slope - x - xx) % FIELD
    return rx, (slope * (x - rx) - y) % FIELD


def multiply(scalar):
    out, point = None, GENERATOR
    while scalar:
        if scalar & 1:
            out = point_add(out, point)
        point = point_add(point, point)
        scalar >>= 1
    return out


def sign_fixture(digest):
    # RFC6979 HMAC-SHA256, low-S DER, disposable scalar 1 only.
    key, value = bytes(32), b'\x01' * 32
    seed = bytes.fromhex(SECRET) + (int.from_bytes(digest, 'big') % ORDER).to_bytes(32, 'big')
    for marker in (b'\x00', b'\x01'):
        key = hmac.new(key, value + marker + seed, hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()
    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        nonce = int.from_bytes(value, 'big')
        if 0 < nonce < ORDER:
            r = multiply(nonce)[0] % ORDER
            s = (pow(nonce, -1, ORDER) * (int.from_bytes(digest, 'big') + r)) % ORDER
            if r and s:
                break
        key = hmac.new(key, value + b'\x00', hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()
    def der_integer(number):
        raw = number.to_bytes((number.bit_length() + 7) // 8, 'big')
        if raw[0] & 0x80:
            raw = b'\x00' + raw
        return b'\x02' + bytes([len(raw)]) + raw
    parts = der_integer(r) + der_integer(min(s, ORDER - s))
    return b'\x30' + bytes([len(parts)]) + parts + b'\x01'


def spend_fixture(txid, vout, amount_sats, destination_script):
    outpoint = bytes.fromhex(txid)[::-1] + struct.pack('<I', vout)
    sequence, version, locktime = bytes.fromhex('fdffffff'), struct.pack('<I', 2), bytes(4)
    script = bytes.fromhex(destination_script)
    require(len(script) < 253 and amount_sats > 1000, 'invalid spend fixture')
    output = struct.pack('<Q', amount_sats - 1000) + bytes([len(script)]) + script
    script_code = b'\x19\x76\xa9\x14' + PROGRAM + b'\x88\xac'
    preimage = (version + sha256d(outpoint) + sha256d(sequence) + outpoint + script_code +
                struct.pack('<Q', amount_sats) + sequence + sha256d(output) + locktime +
                struct.pack('<I', 1))
    signature = sign_fixture(sha256d(preimage))
    witness = b'\x02' + bytes([len(signature)]) + signature + bytes([len(PUBKEY)]) + PUBKEY
    return (version + b'\x00\x01\x01' + outpoint + b'\x00' + sequence + b'\x01' +
            output + witness + locktime).hex()


class Node:
    def __init__(self, binaries, directory):
        self.binaries, self.directory = binaries, directory
        self.directory.mkdir(mode=0o700)
        with socket.socket() as bound:
            bound.bind(('127.0.0.1', 0))
            self.port = bound.getsockname()[1]
        self.url = f'http://127.0.0.1:{self.port}/'
        self.cookie = directory / 'regtest/.cookie'
        self.process = None
        self.log = None

    def start(self):
        require(self.process is None, 'node already owned')
        self.log = (self.directory / 'process.log').open('ab')
        self.process = subprocess.Popen([
            str(self.binaries / 'bitcoind'), '-regtest', '-server=1',
            '-datadir=' + str(self.directory), f'-rpcport={self.port}',
            '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', '-listen=0',
            '-connect=0', '-dnsseed=0', '-discover=0', '-natpmp=0',
            '-fallbackfee=0.0002', '-printtoconsole=0'], stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            require(self.process.poll() is None, 'owned bitcoind exited during startup')
            try:
                if self.call('getblockchaininfo')['chain'] == 'regtest':
                    return
            except (OSError, ValueError, RuntimeError, http.client.HTTPException):
                pass
            time.sleep(0.1)
        raise RuntimeError('owned bitcoind readiness deadline exceeded')

    def call(self, method, *params, wallet=None):
        require(self.process is not None and self.process.poll() is None, 'node not owned/running')
        credentials = self.cookie.read_bytes().strip()
        connection = http.client.HTTPConnection('127.0.0.1', self.port, timeout=30)
        path = '/' if wallet is None else '/wallet/' + quote(wallet, safe='')
        try:
            connection.request('POST', path, json.dumps({
                'jsonrpc': '2.0', 'id': 'harness', 'method': method, 'params': list(params)}),
                {'Content-Type': 'application/json',
                 'Authorization': 'Basic ' + base64.b64encode(credentials).decode()})
            response = connection.getresponse()
            data = response.read(1024 * 1024)
            result = json.loads(data)
            if response.status != 200 or 'error' in result:
                # Do not log response bodies, credentials or untrusted messages.
                code = result.get('error', {}).get('code')
                raise RuntimeError(f'test setup RPC {method} failed, HTTP {response.status}, code {code}')
            return result['result']
        finally:
            connection.close()

    def stop(self):
        if self.process is None:
            return
        try:
            if self.process.poll() is None:
                try:
                    self.call('stop')
                except (OSError, RuntimeError, ValueError, http.client.HTTPException):
                    self.process.terminate()
                try:
                    self.process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=10)
            require(self.process.poll() is not None, 'owned bitcoind was not reaped')
        finally:
            self.process = None
            self.log.close()


class TipRace:
    """Loopback proxy; advance/reorganize the real node between Lookup calls."""
    def __init__(self, node, miner):
        self.calls = 0
        self.reorg = False
        self.error = None
        race = self
        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_POST(self):
                try:
                    request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    result = node.call(request['method'], *request['params'])
                    if request['method'] == 'gettxout':
                        before = node.call('getbestblockhash')
                        height = node.call('getblockcount')
                        timestamp = node.call('getblockheader', before)['time']
                        node.call('invalidateblock', before)
                        # Ensure a genuinely different block even if the two
                        # templates would otherwise use the same wall second.
                        node.call('setmocktime', timestamp + 1)
                        try:
                            replacement = node.call('generatetoaddress', 1, miner)[0]
                        finally:
                            node.call('setmocktime', 0)
                        require(node.call('getblockcount') == height and replacement != before,
                                'same-height reorg did not occur')
                        race.reorg = True
                    race.calls += 1
                    body = json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}).encode()
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except Exception as error:
                    race.error = type(error).__name__
                    if isinstance(error, RuntimeError):
                        race.error = str(error)  # Harness-authored, no raw RPC text.
                    self.send_error(500)
        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.url = f'http://127.0.0.1:{self.server.server_port}/'
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


def preflight(directory, major):
    require(directory is not None and directory.is_absolute(), f'explicit Core {major} directory required')
    for name in ('bitcoind', 'bitcoin-cli'):
        executable = directory / name
        require(executable.is_file() and os.access(executable, os.X_OK),
                f'Core {major} {name} unavailable')
        # Core's portable spelling is -version. Even preflight is isolated:
        # older releases may process settings before handling unknown options.
        with tempfile.TemporaryDirectory(prefix='quietproof-version-') as version_dir:
            command = [str(executable), '-version', '-regtest', '-datadir=' + version_dir]
            if name == 'bitcoind':
                command.append('-nosettings')
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        first = result.stdout.splitlines()[0] if result.stdout else ''
        # Fork versions cannot be substituted for the required Core compatibility gate.
        require(result.returncode == 0 and re.search(rf'Bitcoin Core .*version v{major}\.\d', first),
                f'{name} is not Bitcoin Core {major}')
        print(f'preflight: {first}', flush=True)


def workflow(args, major, root):
    node = Node(getattr(args, f'core{major}'), root / f'core{major}')
    checks = 0
    env = os.environ.copy()
    sentinel = root / f'sentinel{major}'
    sentinel.mkdir(mode=0o700)
    marker = sentinel / 'called'
    # PATH has only a sentinel, so native execution cannot find a real bitcoin-cli.
    trap = sentinel / 'bitcoin-cli'
    trap.write_text('#!/bin/sh\n: > "' + str(marker) + '"\nexit 99\n')
    trap.chmod(0o700)
    env['PATH'] = str(sentinel)

    def run(label, command, expected=0, secret=False, result=None):
        nonlocal checks
        started = time.monotonic()
        completed = subprocess.run([str(c) for c in command], input=SECRET + '\n' if secret else None,
                                   capture_output=True, text=True, timeout=1800, env=env)
        require(completed.returncode == expected,
                f'{label}: exit {completed.returncode}, expected {expected}')
        if result is not None:
            actual = (json.loads(completed.stdout)['result'] if command[0] == args.cli
                      else completed.stdout.strip())
            require(actual == result, f'{label}: unexpected result')
        require(not marker.exists(), 'native path invoked bitcoin-cli sentinel')
        checks += 1
        print(f'Core {major}: {label}: PASS ({time.monotonic() - started:.3f}s)', flush=True)
        return completed.stdout

    def rpc_flags(url=None, cookie=None):
        return ['--rpc-url', url or node.url, '--rpc-cookie', cookie or node.cookie]

    def verify(proof, store, extra=(), native=True, url=None, cookie=None):
        return [args.cli, 'verify', proof, '--verifier', 'example.org', '--purpose',
                'proof-of-funds', '--nonce-store', store] + (rpc_flags(url, cookie) if native else []) + list(extra)

    def request(label):
        path = root / f'{major}-{label}.qpr'
        run(label, [args.cli, 'challenge', 'create', '--network', 'regtest', '--address', address,
                    '--verifier', 'example.org', '--purpose', 'proof-of-funds', '--message',
                    'Proof of control', '--expires-in', '86400', '--output', path] + rpc_flags())
        require(path.stat().st_mode & 0o777 == 0o600, 'request mode must be 0600')
        return path

    try:
        # 1. Isolated funding node; external public fixture independently derived in C++.
        node.start()
        program = run('Longfellow fixture', [args.driver, 'fixture']).strip()
        require(program == PROGRAM.hex(), 'Longfellow/Python program mismatch')
        descriptor = node.call('getdescriptorinfo', f'wpkh({PUBKEY.hex()})')['descriptor']
        address = node.call('deriveaddresses', descriptor)[0]
        node.call('createwallet', 'funding')
        miner = node.call('getnewaddress', '', 'bech32', wallet='funding')
        node.call('generatetoaddress', 101, miner)
        txid = node.call('sendtoaddress', address, 1, wallet='funding')
        node.call('generatetoaddress', 2, miner)
        # 2. Scan and public-only named-wallet discovery agree, no key import/export.
        scan = json.loads(run('native scan', [args.cli, 'utxos', '--network', 'regtest',
                              '--address', address] + rpc_flags()))
        require(scan['count'] == 1 and scan['current_rechecked'] and scan['challenge_compatible'],
                'unexpected funded discovery')
        output = scan['outputs'][0]
        require(output['txid'] == txid and output['amount_sats'] == 100000000 and
                output['program'] == program, 'funding output mismatch')
        node.call('createwallet', 'watch /fixture', True, True)
        imported = node.call('importdescriptors', [{'desc': descriptor, 'timestamp': 0}],
                             wallet='watch /fixture')
        require(all(item['success'] for item in imported), 'public watch import failed')
        wallet = json.loads(run('watch-only wallet', [args.cli, 'utxos', '--network', 'regtest',
                                '--address', address, '--rpc-wallet', 'watch /fixture'] + rpc_flags()))
        require(wallet['outputs'] == scan['outputs'], 'wallet/scan disagreement')
        wallet_info = node.call('getwalletinfo', wallet='watch /fixture')
        require(wallet_info['private_keys_enabled'] is False, 'watch wallet has private keys')
        # 3. Independent CLI and C++ requests and real proofs, with Core stopped.
        cli_request = request('cli-challenge')
        race_request = request('race-challenge')
        spend_request = request('fresh-spend-challenge')
        cpp_request = root / f'{major}-cpp.qpr'
        run('C++ challenge', [args.api_driver, 'challenge', 'regtest', address,
                              cpp_request, node.cookie, node.url])
        run('request no-overwrite', [args.api_driver, 'challenge', 'regtest', address,
                                     cpp_request, node.cookie, node.url], 74)
        previous_cookie = node.cookie.read_bytes()
        node.stop()
        cpp_proof = root / f'{major}-cpp.qpf'
        run('cpp offline real proof', [args.api_driver, 'prove', cpp_request, cpp_proof], secret=True)
        require(cpp_proof.stat().st_mode & 0o777 == 0o600, 'proof mode must be 0600')
        node.start()
        require(previous_cookie != node.cookie.read_bytes(), 'cookie did not rotate')
        # Verify the API driver's fixed 300s challenge before other expensive proofs.
        run('C++ valid current', [args.api_driver, 'verify', 'regtest', cpp_proof,
                                  root / f'{major}-cpp.nonces', node.cookie, node.url], result='valid_current')
        node.stop()
        proofs = {'cpp': cpp_proof}
        for label, source, executable in [('cli', cli_request, args.cli),
                                          ('race', race_request, args.cli),
                                          ('spend', spend_request, args.cli)]:
            proof = root / f'{major}-{label}.qpf'
            command = ([executable, 'prove', '--request', source, '--output', proof]
                       if executable == args.cli else [executable, 'prove', source, proof])
            run(f'{label} offline real proof', command, secret=True)
            require(proof.stat().st_mode & 0o777 == 0o600, 'proof mode must be 0600')
            proofs[label] = proof
        node.start()
        require(previous_cookie != node.cookie.read_bytes(), 'cookie did not rotate')
        # 4. Stable native success and native/legacy evidence/result equivalence.
        run('CLI valid current', verify(proofs['cli'], root / f'{major}-cli.nonces'), result='valid_current')
        wrapper = root / f'{major}-legacy'
        import shlex
        wrapper.write_text('#!/bin/sh\nexec ' + shlex.quote(str(node.binaries / 'bitcoin-cli')) +
                           ' -datadir=' + shlex.quote(str(node.directory)) +
                           f' -rpcport={node.port} "$@"\n')
        wrapper.chmod(0o700)
        run('legacy valid current', verify(proofs['cli'], root / f'{major}-legacy.nonces',
                                          ['--bitcoin-cli', wrapper], native=False), result='valid_current')
        lookup = [args.driver, 'lookup', 'regtest', node.url, node.cookie,
                  output['txid'], output['vout'], 'parity', wrapper]
        run('C++ evidence parity', lookup)
        # 5. Replay fails and concurrent verifications authorize precisely once.
        run('replay', verify(proofs['cli'], root / f'{major}-cli.nonces'), 67, result='invalid_proof')
        race_store = root / f'{major}-race.nonces'
        command = verify(proofs['race'], race_store)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: subprocess.run([str(c) for c in command],
                                capture_output=True, text=True, timeout=1800, env=env), range(2)))
        require(sorted(r.returncode for r in results) == [0, 67], 'replay race lacks single winner')
        require(sorted(json.loads(r.stdout)['result'] for r in results) == ['invalid_proof', 'valid_current'],
                'replay race results differ')
        require(len(race_store.read_text().splitlines()) == 1, 'replay race appended multiple nonces')
        checks += 1
        print(f'Core {major}: concurrent replay: PASS (one winner, one nonce record)', flush=True)
        # 6. Local policy, wrong node chain, cookie, stopped node, actual same-height reorg.
        untouched = root / f'{major}-unconsumed.nonces'
        run('minimum confirmations', verify(proofs['spend'], untouched,
                                            ['--min-confirmations', '1000']), 4, result='stale_snapshot')
        run('wrong expected network', verify(proofs['spend'], untouched,
                                              ['--network', 'signet']), 67, result='invalid_proof')
        run('wrong Core chain', [args.api_driver, 'discover', 'signet', address,
                                 node.cookie, node.url], 74)
        invalid_cookie = root / f'{major}-invalid.cookie'
        invalid_cookie.write_text('invalid:credential')
        invalid_cookie.chmod(0o600)
        run('invalid cookie', verify(proofs['spend'], untouched, cookie=invalid_cookie),
            5, result='state_inconclusive')
        # Retain an owner-only cookie to exercise connection refusal, rather
        # than failing the cookie read when Core deletes its cookie at shutdown.
        stopped_cookie = root / f'{major}-stopped.cookie'
        stopped_cookie.write_bytes(node.cookie.read_bytes())
        stopped_cookie.chmod(0o600)
        node.stop()
        run('stopped node', verify(proofs['spend'], untouched, cookie=stopped_cookie),
            5, result='state_inconclusive')
        node.start()
        with TipRace(node, miner) as tip_race:
            run('same-height reorg', verify(proofs['spend'], untouched, url=tip_race.url),
                5, result='state_inconclusive')
            require(tip_race.reorg and tip_race.calls >= 3,
                    'live tip race not exercised: ' + str(tip_race.error))
        require(not untouched.exists(), 'failed evidence consumed nonce')
        # 7. Fresh unconsumed proof is valid immediately before the external spend.
        run('fresh proof pre-spend control', verify(proofs['spend'], root / f'{major}-control.nonces'),
            result='valid_current')
        require(not untouched.exists(), 'spend proof test nonce already consumed')
        # Reuse the public funding destination. No wallet must auto-load after
        # restart, and the proof key remains entirely outside Core.
        script = node.call('validateaddress', miner)['scriptPubKey']
        raw = spend_fixture(output['txid'], output['vout'], output['amount_sats'], script)
        accepted = node.call('testmempoolaccept', [raw])[0]
        require(accepted['allowed'], 'locally signed external-key spend rejected')
        node.call('sendrawtransaction', raw)
        run('mempool spend inconclusive', verify(proofs['spend'], untouched), 5, result='state_inconclusive')
        require(not untouched.exists(), 'mempool failure consumed nonce')
        node.call('generatetoaddress', 1, miner)
        run('mined spend inconclusive', verify(proofs['spend'], untouched), 5, result='state_inconclusive')
        require(not untouched.exists(), 'mined failure consumed nonce')
        # 8. Private files, no subprocess sentinel hit, and owned-node cleanup.
        for store in root.glob(f'{major}-*.nonces'):
            require(store.stat().st_mode & 0o777 == 0o600, 'nonce store mode must be 0600')
        require(not marker.exists(), 'native path invoked bitcoin-cli')
    finally:
        node.stop()
    print(f'Core {major}: {checks} checks passed; owned child reaped', flush=True)
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--not-enabled', action='store_true')
    parser.add_argument('--core28', type=Path)
    parser.add_argument('--core30', type=Path)
    for name in ('cli', 'api_driver', 'driver'):
        parser.add_argument('--' + name.replace('_', '-'), type=Path)
    args = parser.parse_args()
    if args.not_enabled:
        print('SKIP: explicit opt-in and Core 28/30 executables required')
        return 77
    for major in (28, 30):
        preflight(getattr(args, f'core{major}'), major)
    for name in ('cli', 'api_driver', 'driver'):
        path = getattr(args, name)
        require(path is not None and path.is_absolute() and os.access(path, os.X_OK),
                f'explicit built {name} executable required')
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix='quietproof-regtest-') as directory:
        root = Path(directory)
        total = sum(workflow(args, major, root) for major in (28, 30))
    require(not root.exists(), 'isolated datadir cleanup failed')
    print(f'PASS: {total} checks, Core 28/30, {time.monotonic() - started:.3f}s, '
          f'child peak RSS {resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss} KiB; directories removed')
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print(f'FAIL: {error}', flush=True)
        raise SystemExit(1)
