#!/usr/bin/env python3
"""Exercise production signature RPC authority against hostile peers and Core32.

Only public requests/configuration and witness-free results enter diagnostics.
Signed receipts stay in temporary owner-only files and are independently checked.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import bitcoin_core_signing_regtest as core
import signing_reference as ref


def mathematical_result(request, odd=False):
    profile = ref.virtual_profile(request)
    r = ref.GENERATOR[0]
    secret = ref.ORDER - 1 if odd else 1
    s = (int.from_bytes(profile['z'], 'big') + r * secret) % ref.ORDER
    s = min(s, ref.ORDER - s)
    key = bytes([3 if odd else 2]) + r.to_bytes(32, 'big')
    signature = core.encode_signature(r, s)
    tx = core.replace_unlock(profile['tx'], request['signing_kind'], signature, key)
    return dict(profile=profile, tx=tx, signature=signature, pubkey=key, r=r, s=s)


class Peer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self):
        super().__init__(('127.0.0.1', 0), Handler)
        self.records = []
        self.errors = []
        self.node = None
        self.scenario = 'ok'
        self.result = None
        self.profile = None
        self.wallet = ''


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        server = self.server
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        method, params = request['method'], request['params']
        server.records.append((method, self.path))
        try:
            if method not in ('getblockchaininfo', 'getwalletinfo', 'getaddressinfo', 'signrawtransactionwithwallet'):
                server.errors.append('forbidden production adapter RPC')
                raise RuntimeError('forbidden production adapter RPC')
            if method != 'getblockchaininfo' and (not self.path.startswith('/wallet/') or
                    unquote(self.path[len('/wallet/'):]) != server.wallet):
                server.errors.append('wallet selection changed')
                raise RuntimeError('wallet selection changed')
            if method == 'signrawtransactionwithwallet':
                p = server.profile
                expected = [p['unsigned'].hex(), [{'txid': p['parent_id'][::-1].hex(), 'vout': 0,
                            'scriptPubKey': p['script'].hex(), 'amount': 0}], 'ALL']
                if params != expected:
                    server.errors.append('unsafe signing arguments blocked before forwarding')
                    raise RuntimeError('unsafe signing arguments blocked before forwarding')
            if server.scenario == 'timeout':
                time.sleep(0.15)
            if server.scenario == 'disconnect':
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            if server.node is not None:
                value = server.node.call(method, *params, wallet=None if method == 'getblockchaininfo' else server.wallet)
            elif method == 'getblockchaininfo':
                value = {'chain': 'signet' if server.scenario == 'wrong-chain' else 'regtest',
                         'blocks': 101, 'bestblockhash': '12' * 32}
            elif method == 'getwalletinfo':
                value = {'private_keys_enabled': server.scenario != 'watch-only',
                         'external_signer': server.scenario == 'external-signer'}
                if server.scenario == 'locked':
                    value['unlocked_until'] = 0
                if server.scenario == 'negative-unlock':
                    value['unlocked_until'] = -1
                if server.scenario == 'boolean-unlock':
                    value['unlocked_until'] = True
                if server.scenario == 'bad-wallet-info':
                    value['private_keys_enabled'] = 1
            elif method == 'getaddressinfo':
                value = {'ismine': server.scenario != 'missing-key',
                         'scriptPubKey': ('0014' + '00' * 20 if server.scenario == 'wrong-script'
                                          else server.profile['script'].hex())}
                if server.scenario == 'bad-address-info':
                    value['ismine'] = 1
            else:
                value = server.result
            response = {'jsonrpc': '2.0', 'id': request['id'], 'result': value}
            if server.scenario == 'rpc-error' and method == 'signrawtransactionwithwallet':
                response = {'jsonrpc': '2.0', 'id': request['id'],
                            'error': {'code': -13, 'message': 'server-secret-never-print'}}
        except Exception:
            # Deliberately redact exceptions, which can contain wallet witnesses.
            if server.node is None:
                server.errors.append('fixture or unsafe request failure')
            response = {'jsonrpc': '2.0', 'id': request['id'],
                        'error': {'code': -18, 'message': 'server-secret-never-print'}}
        data = json.dumps(response).encode()
        try:
            self.send_response(200)
            self.send_header('Content-Length', str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', type=Path, required=True)
    parser.add_argument('--disabled', action='store_true')
    parser.add_argument('--core32', type=Path)
    parser.add_argument('--oracle', type=Path)
    args = parser.parse_args()
    if args.core32:
        core.validate_inputs(args.core32, args.oracle)
    requests = [v['request'] for v in core.public_profiles()['vectors']]
    count = 0
    with tempfile.TemporaryDirectory(prefix='quietproof-signature-rpc-') as temp:
        root = Path(temp)
        cookie = root / 'cookie'
        cookie.write_text('fixture:cookie-secret-never-print')
        cookie.chmod(0o600)
        peer = Peer()
        thread = threading.Thread(target=peer.serve_forever, daemon=True)
        thread.start()

        def run(request, expected=True, *, raw=None, stop_at=0, wallet='selected /?', **options):
            nonlocal count
            count += 1
            peer.records.clear()
            peer.errors.clear()
            peer.wallet = wallet
            peer.profile = ref.virtual_profile(request)
            output = root / f'{count}.qpa'
            config = dict(request=(ref.request_bytes(request) if raw is None else raw).hex(),
                          url=f'http://127.0.0.1:{peer.server_port}/', cookie=str(cookie),
                          wallet=wallet, output=str(output), stop_at=stop_at, **options)
            source = root / 'config.json'
            source.write_text(json.dumps(config))
            result = subprocess.run([str(args.driver), str(source)], capture_output=True, timeout=10)
            if result.returncode != (0 if expected else 2):
                raise RuntimeError(f'adapter case {count}: wrong exit {result.returncode}; status {result.stdout.decode().strip()}; RPC records {peer.records}; fixture errors {peer.errors}')
            if any(marker in result.stdout + result.stderr for marker in
                   (b'cookie-secret', b'server-secret', peer.result.get('hex', '').encode() if isinstance(peer.result, dict) and peer.result.get('hex') else b'never-matches-secret')):
                raise RuntimeError(f'adapter case {count}: private diagnostic disclosure')
            if peer.errors:
                raise RuntimeError(f'adapter case {count}: outgoing RPC contract mismatch')
            if not expected:
                if output.exists():
                    raise RuntimeError(f'adapter case {count}: partial receipt')
                return list(peer.records)
            if output.stat().st_mode & 0o777 != 0o600:
                raise RuntimeError('private receipt permissions')
            receipt = output.read_bytes()
            p = peer.profile
            if len(receipt) < 44 or receipt[:8] != b'QPA1\x01\x01\x00\x01' or receipt[8:40] != p['d']:
                raise RuntimeError('receipt framing/digest disagreement')
            if struct.unpack('>I', receipt[40:44])[0] != len(receipt) - 44:
                raise RuntimeError('receipt length disagreement')
            if args.oracle:
                ref.validate_signed_response(request, {'complete': True, 'hex': receipt[44:].hex()}, args.oracle)
            else:
                tx = ref.parse_transaction(receipt[44:])
                signature, key, _, _ = ref.extract_unlock(tx, request['signing_kind'])
                tx['inputs'][0].update(script=b'', witness=())
                if ref.serialize(tx) != p['unsigned'] or ref.hash160(key) != bytes.fromhex(request['claims'][0]['program']) or not ref.integer_verify(p['z'], signature, key):
                    raise RuntimeError('independent receipt verification failed')
            return list(peer.records)

        try:
            if args.disabled:
                for request in requests:
                    if run(request, False):
                        raise RuntimeError('disabled adapter contacted wallet')
            elif args.core32:
                with core.Node(args.core32) as node:
                    peer.node = node
                    # Only the actual isolated Core owner-only cookie is used.
                    cookie = node.cookie
                    for odd in (False, True):
                        fixture, coins = core.mature_fixture(node, 'production-odd' if odd else 'production-even', odd)
                        for source in requests:
                            request = core.request_for_coins(fixture, coins, source['signing_kind'])
                            before = core.state_snapshot(node, fixture['wallet'])
                            trace = run(request, wallet=fixture['wallet'])
                            if [m for m, _ in trace] != ['getblockchaininfo', 'getwalletinfo', 'getaddressinfo', 'signrawtransactionwithwallet']:
                                raise RuntimeError('unexpected production signing trace')
                            if core.state_snapshot(node, fixture['wallet']) != before:
                                raise RuntimeError('production signing changed funds state')
                    watch = core.fixture_wallet(node, 'watch-only', watch_only=True)
                    only = core.fixture_wallet(node, 'wpkh-only', kinds=(0,))
                    absent = core.fixture_wallet(node, 'absent-key', True)
                    for wallet in (watch['wallet'], only['wallet'], absent['wallet'], 'not-loaded'):
                        trace = run(requests[0], False, wallet=wallet)
                        if any(m == 'signrawtransactionwithwallet' for m, _ in trace):
                            raise RuntimeError('unsupported wallet reached signing')
                    node.call('encryptwallet', 'disposable-fixture-password', wallet='production-even')
                    trace = run(requests[0], False, wallet='production-even')
                    if any(m == 'signrawtransactionwithwallet' for m, _ in trace):
                        raise RuntimeError('locked wallet reached signing')
            else:
                for source in requests:
                    for odd in (False, True):
                        request = copy.deepcopy(source)
                        key = bytes([3 if odd else 2]) + ref.GENERATOR[0].to_bytes(32, 'big')
                        for claim in request['claims']:
                            claim['program'] = ref.hash160(key).hex()
                        result = mathematical_result(request, odd)
                        peer.scenario = 'ok'
                        peer.result = {'complete': True, 'hex': ref.serialize(result['tx']).hex()}
                        run(request)
                        for _, response in core.malformed_responses(result, request['signing_kind']):
                            peer.result = response
                            run(request, False)
                    peer.result = {'complete': True, 'hex': ref.serialize(mathematical_result(source)['tx']).hex()}
                    for scenario in ('watch-only', 'external-signer', 'locked', 'negative-unlock', 'boolean-unlock', 'missing-key', 'wrong-script',
                                     'wrong-chain', 'bad-wallet-info', 'bad-address-info', 'rpc-error', 'timeout', 'disconnect'):
                        peer.scenario = scenario
                        trace = run(source, False, timeout_ms=30 if scenario == 'timeout' else 3000)
                        if scenario not in ('rpc-error',) and any(m == 'signrawtransactionwithwallet' for m, _ in trace):
                            raise RuntimeError('unsupported wallet/transport reached signing')
                    peer.scenario = 'ok'
                    for stop_at in range(1, 6):
                        run(source, False, stop_at=stop_at)
                    real_spend = copy.deepcopy(peer.profile['tx'])
                    claim = source['claims'][0]
                    real_spend['inputs'][0]['outpoint'] = bytes.fromhex(claim['txid_display'])[::-1] + ref.integer(claim['vout'], 4)
                    real_spend['outputs'][0].update(amount=claim['amount_sats'], script=b'\x51')
                    other_network = copy.deepcopy(source)
                    other_network['network'] = 2
                    for raw in (b'', ref.request_bytes(source) + b'\x00', b'x' * 4097,
                                peer.profile['unsigned'], peer.profile['parent'], ref.serialize(real_spend),
                                ref.request_bytes(other_network)):
                        if run(source, False, raw=raw):
                            raise RuntimeError('invalid/raw transaction input reached RPC')
                    run(source, False, null_output=True)
                    if run(source, False, wallet='bad\nwallet'):
                        raise RuntimeError('invalid wallet reached RPC')
                    if run(source, False, wallet='x' * 1025):
                        raise RuntimeError('oversized wallet reached RPC')
                    # Explicit unnamed wallet is supported without listwallets.
                    run(source, wallet='')
        finally:
            peer.shutdown()
            peer.server_close()
            thread.join(timeout=2)
    print(json.dumps({'executed': count, 'failed': 0, 'skipped': 0, 'total': count,
                      'production_core': bool(args.core32), 'disabled': args.disabled}, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('signature RPC qualification failed; private diagnostics suppressed', file=sys.stderr)
        if isinstance(error, RuntimeError):
            print(str(error), file=sys.stderr)
        raise SystemExit(1)
