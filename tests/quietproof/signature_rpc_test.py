#!/usr/bin/env python3
"""Exercise production signature RPC authority against hostile peers and Core32.

Only public requests/configuration and witness-free results enter diagnostics.
Signed receipts stay in temporary owner-only files and are independently checked.
"""
import argparse
import base64
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
    legacy = request.get('profile',1) == 2
    profile = ref.bitcoin_message_profile(request) if legacy else ref.virtual_profile(request)
    r = ref.GENERATOR[0]
    secret = ref.ORDER - 1 if odd else 1
    s = (int.from_bytes(profile['z'], 'big') + r * secret) % ref.ORDER
    high = s > ref.ORDER//2
    s = min(s, ref.ORDER - s)
    key = bytes([3 if odd else 2]) + r.to_bytes(32, 'big')
    signature = core.encode_signature(r, s)
    if legacy:
        compact = bytes([31+int(high)])+r.to_bytes(32,'big')+s.to_bytes(32,'big')
        return dict(profile=profile,compact=compact,signature=signature,pubkey=key,r=r,s=s)
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
        self.pubkey = None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        server = self.server
        request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        method, params = request['method'], request['params']
        server.records.append((method, self.path))
        try:
            legacy = server.profile.get('legacy',False)
            signing_method = 'signmessage' if legacy else 'signrawtransactionwithwallet'
            if method not in ('getblockchaininfo', 'getwalletinfo', 'getaddressinfo', signing_method):
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
            if method == 'signmessage':
                if params != [server.profile['address'],server.profile['message'].decode('ascii')]:
                    server.errors.append('wrong signmessage address/exact message')
                    raise RuntimeError('unsafe message arguments')
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
                if legacy:
                    value.update(iscompressed=True,pubkey=server.pubkey.hex())
                    if server.scenario=='uncompressed-key': value['iscompressed']=False
                    if server.scenario=='bad-key': value['pubkey']='04'+server.pubkey[1:].hex()
                    if server.scenario=='wrong-key': value['pubkey']=('03' if server.pubkey[0]==2 else '02')+server.pubkey[1:].hex()
                    if server.scenario=='missing-pubkey': value.pop('pubkey')
                    if server.scenario=='watch-only-address': value['iswatchonly']=True
                    if server.scenario=='bad-compressed-flag': value['iscompressed']=1
            else:
                value = server.result
            response = {'jsonrpc': '2.0', 'id': request['id'], 'result': value}
            if server.scenario in ('rpc-error','unsupported-method','unsupported-key') and method == signing_method:
                response = {'jsonrpc': '2.0', 'id': request['id'],
                            'error': {'code': {'rpc-error':-13,'unsupported-method':-32601,'unsupported-key':-5}[server.scenario], 'message': 'server-secret-never-print'}}
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
            legacy = request.get('profile',1)==2
            peer.profile = ref.bitcoin_message_profile(request) if legacy else ref.virtual_profile(request)
            if legacy:
                peer.profile.update(legacy=True,address=ref.p2pkh_address(request['network'],bytes.fromhex(request['claims'][0]['program'])))
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
                   (b'cookie-secret', b'server-secret', peer.result.encode() if isinstance(peer.result,str) and peer.result else peer.result.get('hex', '').encode() if isinstance(peer.result, dict) and peer.result.get('hex') else b'never-matches-secret')):
                raise RuntimeError(f'adapter case {count}: private diagnostic disclosure')
            if peer.errors:
                raise RuntimeError(f'adapter case {count}: outgoing RPC contract mismatch')
            if not expected:
                if output.exists():
                    raise RuntimeError(f'adapter case {count}: partial receipt')
                if legacy and peer.scenario in ['locked','rpc-error','watch-only','external-signer','unsupported-method','unsupported-key']:
                    category=int(result.stdout.decode().split()[1])
                    if category != (16 if peer.scenario in ['locked','rpc-error'] else 18):
                        raise RuntimeError('legacy wallet error category changed')
                return list(peer.records)
            if output.stat().st_mode & 0o777 != 0o600:
                raise RuntimeError('private receipt permissions')
            receipt = output.read_bytes()
            p = peer.profile
            if len(receipt) < 45 or receipt[:9] != b'QPA1\x04\x01\x00'+bytes([2 if legacy else 1,1]) or receipt[9:41] != p['d']:
                raise RuntimeError('receipt framing/digest disagreement')
            if struct.unpack('>I', receipt[41:45])[0] != len(receipt) - 45:
                raise RuntimeError('receipt length disagreement')
            if legacy:
                compact=base64.b64decode(peer.result,validate=True)
                if receipt[45:]!=compact or not ref.integer_verify(p['z'],core.encode_signature(
                        int.from_bytes(compact[1:33],'big'),int.from_bytes(compact[33:],'big')),peer.pubkey):
                    raise RuntimeError('independent compact receipt verification failed')
            elif args.oracle:
                ref.validate_signed_response(request, {'complete': True, 'hex': receipt[45:].hex()}, args.oracle)
            else:
                tx = ref.parse_transaction(receipt[45:])
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
                if run(core.public_profiles()['legacy_vectors'][0]['request'],False):
                    raise RuntimeError('disabled legacy adapter contacted wallet')
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
                legacy_source=copy.deepcopy(core.public_profiles()['legacy_vectors'][0]['request'])
                for odd in [False,True]:
                    request=copy.deepcopy(legacy_source)
                    for claim in request['claims']:
                        claim['program']=ref.hash160(bytes([3 if odd else 2])+ref.GENERATOR[0].to_bytes(32,'big')).hex()
                    result=mathematical_result(request,odd);peer.pubkey=result['pubkey'];peer.result=base64.b64encode(result['compact']).decode();peer.scenario='ok'
                    trace=run(request)
                    if [m for m,_ in trace]!=['getblockchaininfo','getwalletinfo','getaddressinfo','signmessage']:
                        raise RuntimeError('legacy profile did not select exactly signmessage')
                    original=peer.result
                    compact=result['compact']
                    high=compact[:33]+(ref.ORDER-int.from_bytes(compact[33:],'big')).to_bytes(32,'big')
                    wrong=copy.deepcopy(request);wrong['nonce']='42'*32
                    wrong_signature=base64.b64encode(mathematical_result(wrong,odd)['compact']).decode()
                    for value in [None,{},'',original+'\n','A'*88,base64.b64encode(high).decode(),
                                  base64.b64encode(bytes([27])+compact[1:]).decode(),wrong_signature]:
                        peer.result=value;run(request,False)
                    peer.result=original
                    for scenario in ['watch-only','external-signer','locked','missing-key','wrong-script','wrong-chain',
                                     'bad-wallet-info','bad-address-info','uncompressed-key','bad-key','wrong-key',
                                     'missing-pubkey','watch-only-address','bad-compressed-flag','rpc-error','unsupported-method','unsupported-key']:
                        peer.scenario=scenario;trace=run(request,False)
                        if scenario not in ['rpc-error','unsupported-method','unsupported-key'] and any(m=='signmessage' for m,_ in trace):
                            raise RuntimeError('unsupported legacy wallet reached signmessage')
                    peer.scenario='ok'
                    for stop_at in range(1,6): run(request,False,stop_at=stop_at)
                peer.scenario='ok'
                run(legacy_source,False,raw=ref.request_bytes(legacy_source)[:4]+b'\x03'+ref.request_bytes(legacy_source)[5:])
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
