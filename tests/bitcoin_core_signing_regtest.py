#!/usr/bin/env python3
"""Opt-in stock Core 32.1 qualification in fresh, disposable regtest nodes.

This is test support, not the shipping wallet adapter. Never accesses default
datadirs, exports keys, downloads binaries, or connects to a production network.
Diagnostics intentionally omit RPC bodies, cookie credentials and witnesses.
"""
import argparse
import base64
import copy
import http.client
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import tempfile
import threading
import time
import traceback
import unittest
from unittest.mock import patch
from urllib.parse import quote

from signing_reference import (GENERATOR, ORDER, digest_preimage, extract_unlock, hash160, integer,
                               integer_verify, oracle_verify, parse_transaction, script_for,
                               serialize, sha256d, tagged, validate_signed_response, virtual_profile)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def validate_binary(path, program):
    require(path.is_file() and os.access(path, os.X_OK), f'missing executable: {program}')
    try:
        # Even the daemon version probe can initialize settings: isolate it.
        with tempfile.TemporaryDirectory(prefix='quietproof-core32-version-') as directory:
            options = ['-nosettings'] if program == 'bitcoind' else []
            result = subprocess.run([str(path), '-regtest', '-datadir=' + directory,
                                     *options, '-version'], capture_output=True,
                                    timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError(f'binary version probe failed: {program}') from error
    first_line = result.stdout.decode('utf-8', errors='replace').splitlines()
    pattern = (r'Bitcoin Core daemon version v32\.1\.0(?: |$)' if program == 'bitcoind'
               else r'Bitcoin Core RPC client version v32\.1\.0(?: |$)')
    require(result.returncode == 0 and first_line and re.match(pattern, first_line[0]),
            f'expected stock Core 32.1: {program}')


def validate_inputs(core, oracle):
    for name in ('bitcoind', 'bitcoin-cli'):
        validate_binary(core / name, name)
    require(oracle.is_file() and os.access(oracle, os.X_OK), 'missing signing oracle')
    try:
        result = subprocess.run([str(oracle), '--self-test'], capture_output=True,
                                timeout=5, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError('oracle probe failed') from error
    require(result.returncode == 0 and result.stdout == b'oracle: 7 checks passed\n',
            'oracle self-test failed')


class Node:
    """Own exactly one subprocess and an internally allocated temporary datadir."""
    def __init__(self, core, *, port=None, startup_timeout=20, rpc_timeout=3,
                 cleanup_timeout=10):
        self.core = core
        self.temp = tempfile.TemporaryDirectory(prefix='quietproof-core32-')
        self.directory = Path(self.temp.name)
        self.cookie = self.directory / 'regtest' / '.cookie'
        if port is None:
            with socket.socket() as bound:
                bound.bind(('127.0.0.1', 0))
                port = bound.getsockname()[1]
        self.port = port
        self.startup_timeout = startup_timeout
        self.rpc_timeout = rpc_timeout
        self.cleanup_timeout = cleanup_timeout
        self.process = None
        self.ready = False
        self.log = None
        self.trace = []  # Operation names only; never arguments or responses.
        self.phase = 'setup'

    def __enter__(self):
        try:
            self.start()
        except BaseException:
            self.close()
            raise
        return self

    def __exit__(self, *_):
        self.close()

    def start(self):
        require(self.process is None, 'node already started')
        # Fail before contacting an occupied port, even if another Core owns it.
        try:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', self.port))
        except OSError as error:
            raise RuntimeError('RPC port occupied') from error
        self.log = (self.directory / 'process.log').open('wb')
        self.process = subprocess.Popen([
            str(self.core / 'bitcoind'), '-regtest', '-server=1', '-daemon=0',
            '-datadir=' + str(self.directory), f'-rpcport={self.port}',
            '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1',
            '-listen=0', '-connect=0', '-dnsseed=0', '-discover=0', '-natpmp=0',
            '-listenonion=0', '-networkactive=0', '-fallbackfee=0.0002',
            '-acceptnonstdtxn=0',
            '-printtoconsole=0'], stdout=self.log, stderr=self.log)
        deadline = time.monotonic() + self.startup_timeout
        while time.monotonic() < deadline:
            require(self.process.poll() is None, 'owned node exited during startup')
            try:
                if self.call('getblockchaininfo')['chain'] == 'regtest':
                    self.ready = True
                    return
            except (OSError, ValueError, RuntimeError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        raise RuntimeError('node startup deadline exceeded')

    def call(self, method, *params, wallet=None):
        require(self.process is not None and self.process.poll() is None,
                'RPC requires owned running node')
        credentials = self.cookie.read_bytes().strip()
        connection = http.client.HTTPConnection('127.0.0.1', self.port,
                                                timeout=self.rpc_timeout)
        path = '/' if wallet is None else '/wallet/' + quote(wallet, safe='')
        self.trace.append((self.phase, method))
        try:
            connection.request('POST', path, json.dumps({
                'jsonrpc': '2.0', 'id': 'core32-test', 'method': method,
                'params': list(params)}), {'Content-Type': 'application/json',
                'Authorization': 'Basic ' + base64.b64encode(credentials).decode()})
            response = connection.getresponse()
            body = response.read(1024 * 1024 + 1)
            require(len(body) <= 1024 * 1024, 'RPC response exceeds test bound')
            data = json.loads(body)
            require(isinstance(data, dict), 'malformed RPC envelope')
            error = data.get('error')
            if response.status != 200 or error:
                code = error.get('code') if isinstance(error, dict) else None
                if not isinstance(code, int) or isinstance(code, bool) or not -32768 <= code <= 32767:
                    code = None
                raise RuntimeError(f'RPC {method} failed (HTTP {response.status}, code {code})')
            require(data.get('id') == 'core32-test' and 'result' in data,
                    'malformed RPC envelope')
            return data['result']
        except (OSError, ValueError, http.client.HTTPException):
            raise RuntimeError(f'RPC {method} transport failed') from None
        finally:
            connection.close()

    def close(self):
        forced = False
        early_shutdown = False
        try:
            if self.process is not None and self.process.poll() is None:
                try:
                    self.call('stop')
                except (OSError, RuntimeError):
                    # During early startup the cookie/RPC service may not yet
                    # exist. Core handles SIGTERM as a graceful shutdown too.
                    early_shutdown = not self.ready
                    self.process.terminate()
                try:
                    self.process.wait(timeout=self.cleanup_timeout)
                except subprocess.TimeoutExpired:
                    forced = True
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=self.cleanup_timeout)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait(timeout=5)
        finally:
            if self.log is not None:
                self.log.close()
            self.temp.cleanup()
        require(not forced, 'node cleanup required forced termination')
        if self.process is not None:
            require(self.process.returncode == 0 or
                    (early_shutdown and self.process.returncode == -signal.SIGTERM),
                    'node exited unsuccessfully')


def disposable_wif(scalar):
    # Public, intentionally disposable scalars 1 and n-1, only during setup.
    payload = b'\xef' + integer(scalar, 32, 'big') + b'\x01'
    encoded = payload + sha256d(payload)[:4]
    value, result = int.from_bytes(encoded, 'big'), ''
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    while value:
        value, digit = divmod(value, 58)
        result = alphabet[digit] + result
    return result


def fixture_wallet(node, name, odd=False, *, kinds=(0, 1), watch_only=False):
    node.call('createwallet', name, watch_only, True, '', False, True)
    scalar = ORDER - 1 if odd else 1
    public = bytes.fromhex(('03' if odd else '02') +
                           '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')
    addresses = {}
    for kind, wrapper in ((0, 'wpkh'), (1, 'pkh')):
        if kind not in kinds:
            continue
        descriptor = f'{wrapper}({public.hex() if watch_only else disposable_wif(scalar)})'
        info = node.call('getdescriptorinfo', descriptor)
        imported = node.call('importdescriptors', [{
            'desc': descriptor + '#' + info['checksum'], 'timestamp': 'now'}], wallet=name)
        require(len(imported) == 1 and imported[0].get('success') is True,
                'disposable descriptor import failed')
        address = node.call('deriveaddresses', info['descriptor'])[0]
        owned = node.call('getaddressinfo', address, wallet=name)
        require(owned['ismine'] is True and owned['scriptPubKey'] == script_for(kind, hash160(public)).hex(),
                'actual descriptor ownership does not match selected kind')
        addresses[kind] = address
    return {'wallet': name, 'public': public, 'program': hash160(public), 'addresses': addresses}


def state_snapshot(node, wallet):
    utxo = node.call('gettxoutsetinfo', 'muhash')
    return {'utxo': {k: utxo[k] for k in ('height', 'bestblock', 'txouts', 'total_amount', 'muhash')},
            'unspent': node.call('listunspent', 0, 9999999, [], True, wallet=wallet),
            'locked': node.call('listlockunspent', wallet=wallet),
            'mempool': sorted(node.call('getrawmempool'))}


def authorize(node, request, wallet, oracle):
    """Test-only adapter: accept a typed request; construct every signing argument."""
    profile = virtual_profile(request)
    synthetic = profile['tx']['inputs'][0]['outpoint']
    for claim in request['claims']:
        require(bytes.fromhex(claim['txid_display'])[::-1] + integer(claim['vout'], 4) != synthetic,
                'real claim used as virtual input')
    prevouts = [{'txid': profile['parent_id'][::-1].hex(), 'vout': 0,
                 'scriptPubKey': profile['script'].hex(), 'amount': 0}]
    try:
        node.phase = 'ownership'
        info = node.call('getwalletinfo', wallet=wallet)
        require(info.get('private_keys_enabled') is True, 'wallet has no private signing keys')
        address = node.call('decodescript', profile['script'].hex()).get('address')
        require(isinstance(address, str), 'selected script has no address')
        owned = node.call('getaddressinfo', address, wallet=wallet)
        require(owned.get('ismine') is True and owned.get('scriptPubKey') == profile['script'].hex(),
                'wallet does not own selected script kind')
        node.phase = 'observe-before'
        before = state_snapshot(node, wallet)
        offset = len(node.trace)
        try:
            node.phase = 'signing'
            response = node.call('signrawtransactionwithwallet', profile['unsigned'].hex(),
                                 prevouts, 'ALL', wallet=wallet)
        finally:
            require(node.trace[offset:] == [('signing', 'signrawtransactionwithwallet')],
                    'unexpected signing operation')
            node.phase = 'observe-after'
            after = state_snapshot(node, wallet)
            require(before == after, 'signing changed real UTXO/wallet/mempool state')
    finally:
        node.phase = 'setup'
    return validate_signed_response(request, response, oracle)


def public_profiles():
    return json.loads((Path(__file__).resolve().parents[1] /
                       'spec/signature-profile-v1.json').read_text())


def encode_signature(r, s, flag=1):
    def der_integer(value):
        raw = integer(value, max(1, (value.bit_length() + 7) // 8), 'big')
        if raw[0] & 128:
            raw = b'\x00' + raw
        return b'\x02' + bytes([len(raw)]) + raw
    raw = der_integer(r) + der_integer(s)
    return b'\x30' + bytes([len(raw)]) + raw + bytes([flag])


def replace_unlock(tx, kind, signature, public):
    changed = copy.deepcopy(tx)
    item = changed['inputs'][0]
    item['script'], item['witness'] = b'', ()
    if kind == 1:
        item['script'] = bytes([len(signature)]) + signature + bytes([len(public)]) + public
    else:
        item['witness'] = (signature, public)
    return changed


def malformed_responses(result, kind):
    """Mutations of a real stock-wallet response; names contain no witness."""
    tx, signature, public = result['tx'], result['signature'], result['pubkey']
    encoded = serialize(tx).hex()
    cases = []
    def raw(name, value):
        cases.append((name, {'complete': True, 'hex': value.hex()}))
    def transaction(name, change):
        changed = copy.deepcopy(tx)
        change(changed)
        raw(name, serialize(changed))
    def unlocking(name, sig=signature, key=public):
        raw(name, serialize(replace_unlock(tx, kind, sig, key)))
    for name, value in [('null-response', None), ('array-response', []), ('missing-complete', {'hex': encoded}),
                        ('incomplete', {'complete': False, 'hex': encoded}),
                        ('numeric-complete', {'complete': 1, 'hex': encoded}),
                        ('missing-hex', {'complete': True}), ('null-hex', {'complete': True, 'hex': None}),
                        ('odd-hex', {'complete': True, 'hex': encoded + '0'}),
                        ('nonhex', {'complete': True, 'hex': 'zz'}),
                        ('oversized', {'complete': True, 'hex': '00' * 4097}),
                        ('errors-with-complete', {'complete': True, 'hex': encoded, 'errors': [{'error': 'injected'}]})]:
        cases.append((name, value))
    transaction('changed-version', lambda t: t.update(version=1))
    transaction('changed-locktime', lambda t: t.update(locktime=1))
    transaction('changed-sequence', lambda t: t['inputs'][0].update(sequence=1))
    transaction('changed-outpoint', lambda t: t['inputs'][0].update(outpoint=bytes(36)))
    transaction('changed-vout', lambda t: t['inputs'][0].update(outpoint=t['inputs'][0]['outpoint'][:32] + integer(1, 4)))
    transaction('changed-output-amount', lambda t: t['outputs'][0].update(amount=1))
    transaction('changed-output-script', lambda t: t['outputs'][0].update(script=b'\x51'))
    transaction('extra-input', lambda t: t['inputs'].append(copy.deepcopy(t['inputs'][0])))
    transaction('extra-output', lambda t: t['outputs'].append({'amount': 0, 'script': b'\x6a'}))
    raw('truncated', serialize(tx)[:-1])
    raw('trailing-bytes', serialize(tx) + b'\x00')
    count_offset = 6 if kind == 0 else 4
    raw('nonminimal-input-count', serialize(tx)[:count_offset] + b'\xfd\x01\x00' + serialize(tx)[count_offset + 1:])
    for flag in (0, 2, 3, 129):
        unlocking('sighash-' + str(flag), signature[:-1] + bytes([flag]))
    unlocking('high-S', encode_signature(result['r'], ORDER - result['s']))
    unlocking('zero-r', encode_signature(0, result['s']))
    unlocking('zero-s', encode_signature(result['r'], 0))
    unlocking('order-r', encode_signature(ORDER, result['s']))
    unlocking('order-s', encode_signature(result['r'], ORDER))
    unlocking('wrong-key-parity', key=bytes([public[0] ^ 1]) + public[1:])
    unlocking('uncompressed-key', key=b'\x04' + integer(GENERATOR[0], 32, 'big') + integer(GENERATOR[1], 32, 'big'))
    unlocking('DER-wrong-tag', b'\x31' + signature[1:])
    unlocking('DER-wrong-length', signature[:1] + bytes([signature[1] + 1]) + signature[2:])
    unlocking('DER-trailing', signature[:-1] + b'\x00\x01')
    unlocking('DER-empty-integer', b'\x30\x05\x02\x00\x02\x01\x01\x01')
    unlocking('DER-negative-integer', b'\x30\x06\x02\x01\x80\x02\x01\x01\x01')
    unlocking('DER-redundant-zero', b'\x30\x07\x02\x02\x00\x01\x02\x01\x01\x01')
    if kind == 1:
        transaction('extra-scriptSig-push', lambda t: t['inputs'][0].update(script=t['inputs'][0]['script'] + b'\x00'))
        transaction('PUSHDATA1-signature', lambda t: t['inputs'][0].update(script=b'\x4c' + t['inputs'][0]['script']))
        transaction('unexpected-witness', lambda t: t['inputs'][0].update(witness=(b'',)))
    else:
        transaction('nonempty-scriptSig', lambda t: t['inputs'][0].update(script=b'\x00'))
        transaction('extra-witness-item', lambda t: t['inputs'][0].update(witness=t['inputs'][0]['witness'] + (b'',)))
        transaction('missing-witness', lambda t: t['inputs'][0].update(witness=()))
        transaction('reversed-witness', lambda t: t['inputs'][0].update(witness=(public, signature)))
        raw('unknown-witness-flag', serialize(tx)[:5] + b'\x02' + serialize(tx)[6:])
        witness_offset = len(serialize(tx, witness=False)) - 4 + 2
        raw('nonminimal-witness-count', serialize(tx)[:witness_offset] + b'\xfd\x02\x00' + serialize(tx)[witness_offset + 1:])
    return cases


def authorization_artifacts(node):
    return sorted(str(p.relative_to(node.directory)) for p in node.directory.rglob('*')
                  if p.suffix in ('.qpa', '.qpf'))


SCRIPT_SIGNATURE_FAILURE = ('mempool-script-verify-flag-failed '
                            '(Signature must be zero for failed CHECK(MULTI)SIG operation)')
SIGHASH_NAMES = {1: 'ALL', 2: 'NONE', 3: 'SINGLE', 129: 'ALL|ANYONECANPAY'}


def mature_fixture(node, name, odd=False):
    fixture = fixture_wallet(node, name, odd)
    for kind in (1, 0):
        node.call('generatetoaddress', 103, fixture['addresses'][kind])
    available = node.call('listunspent', 101, 9999999, [], True, wallet=name)
    coins = {}
    for kind in (0, 1):
        selected = sorted((c for c in available if c['scriptPubKey'] ==
                           script_for(kind, fixture['program']).hex()), key=lambda c: (c['txid'], c['vout']))[:2]
        require(len(selected) == 2, 'missing mature real-spend fixture coins')
        coins[kind] = []
        for coin in selected:
            actual = node.call('gettxout', coin['txid'], coin['vout'], True)
            require(actual is not None and actual['confirmations'] >= 101 and actual['coinbase'] is True and
                    actual['scriptPubKey']['hex'] == coin['scriptPubKey'] and
                    actual['value'] == coin['amount'] and coin['spendable'] is True,
                    'real-spend fixture is not an owned mature output')
            coins[kind].append({**coin, 'kind': kind, 'amount_sats': round(coin['amount'] * 100000000)})
    return fixture, coins


def request_for_coins(fixture, coins, kind):
    request = copy.deepcopy(next(v['request'] for v in public_profiles()['vectors']
                                 if v['request']['signing_kind'] == kind))
    request['snapshot'] = None
    request['claims'] = sorted(({'txid_display': coins[k][0]['txid'], 'vout': coins[k][0]['vout'],
                                'amount_sats': coins[k][0]['amount_sats'], 'script_kind': k,
                                'program': fixture['program'].hex()} for k in (0, 1)),
                              key=lambda c: (c['txid_display'], c['vout']))
    return request


def real_spend_templates(coins, kind, program):
    def transaction(inputs):
        return {'version': 2, 'locktime': 0,
                'inputs': [{'outpoint': bytes.fromhex(c['txid'])[::-1] + integer(c['vout'], 4),
                            'script': b'', 'sequence': 0xFFFFFFFD, 'witness': ()} for c in inputs],
                'outputs': [{'amount': sum(c['amount_sats'] for c in inputs) - 1000,
                             'script': script_for(0, program)}]}
    first, alternate = [coins[kind][0]], [coins[kind][1]]
    base = transaction(first)
    split = copy.deepcopy(base)
    amount = split['outputs'][0]['amount']
    split['outputs'] = [{'amount': amount // 2, 'script': script_for(0, program)},
                        {'amount': amount - amount // 2, 'script': script_for(1, program)}]
    mixed = first + [coins[1 - kind][0]]
    return [('base', base, first, 1), ('alternate-outpoint', transaction(alternate), alternate, 1),
            ('changed-outputs', split, first, 1), ('added-mixed-input', transaction(mixed), mixed, 1),
            ('sighash-NONE', base, first, 2), ('sighash-SINGLE', base, first, 3),
            ('sighash-ANYONECANPAY', base, first, 129)]


def mempool_probe(node, tx, *, allowed, rejection=None):
    raw = serialize(tx)
    result = node.call('testmempoolaccept', [raw.hex()])
    require(isinstance(result, list) and len(result) == 1 and isinstance(result[0], dict),
            'malformed testmempoolaccept response')
    result = result[0]
    require(result.get('txid') == sha256d(serialize(tx, witness=False))[::-1].hex() and
            result.get('wtxid') == sha256d(raw)[::-1].hex() and 'package-error' not in result,
            'testmempoolaccept response does not identify submitted transaction')
    require(result.get('allowed') is allowed, 'unexpected Core acceptance result')
    if allowed:
        require('reject-reason' not in result and 'reject-details' not in result,
                'contradictory Core acceptance response')
    else:
        require(result.get('reject-reason') == rejection, 'unexpected Core rejection cause')
    return result


def unsigned_fields(tx):
    stripped = copy.deepcopy(tx)
    for item in stripped['inputs']:
        item['script'], item['witness'] = b'', ()
    return serialize(stripped)


def verify_real_input(tx, coin, index, program, public, oracle, flag):
    signature, actual_public, _, _ = extract_unlock(tx, coin['kind'], index, allowed_sighashes=(flag,))
    require(actual_public == public and hash160(actual_public) == program, 'real-spend control uses wrong key')
    digest = sha256d(digest_preimage(tx, coin['kind'], program, coin['amount_sats'], index, flag))
    require(integer_verify(digest, signature, actual_public, sighash=flag) and
            oracle_verify(oracle, digest, signature, actual_public),
            'real-spend control signature verification failed')
    return digest


def transplant_pair(node, fixture, virtual, template, spent, flag, oracle, case_id, baseline_digest):
    wallet, program, public = fixture['wallet'], fixture['program'], fixture['public']
    node.phase = 'nonspending-observe-before'
    before, files = state_snapshot(node, wallet), authorization_artifacts(node)
    offset = len(node.trace)
    try:
        node.phase = 'real-control-signing'
        prevouts = [{'txid': c['txid'], 'vout': c['vout'], 'scriptPubKey': c['scriptPubKey'],
                     'amount': c['amount']} for c in spent]
        response = node.call('signrawtransactionwithwallet', serialize(template).hex(), prevouts,
                             SIGHASH_NAMES[flag], wallet=wallet)
        require(isinstance(response, dict) and response.get('complete') is True and not response.get('errors'),
                'real-spend positive control signing incomplete')
        control = parse_transaction(bytes.fromhex(response['hex']))
        require(unsigned_fields(control) == serialize(template), 'wallet changed real-spend control template')
        digests = [verify_real_input(control, coin, index, program, public, oracle, flag)
                   for index, coin in enumerate(spent)]
        node.phase = 'real-control-acceptance'
        mempool_probe(node, control, allowed=True)
        require(digests[0] != virtual['profile']['z'], 'real-spend digest equals virtual digest')
        if '/base' not in case_id:
            require(digests[0] != baseline_digest, 'changed template did not change independent digest')
        # Preserve the public key and every other input's proper wallet
        # signature. Only the virtual DER signature is substituted; the
        # explicit sighash-mutation cases also change its trailing flag.
        signature = virtual['signature'][:-1] + bytes([flag])
        negative = replace_unlock(control, spent[0]['kind'], signature, public)
        require(negative['inputs'][1:] == control['inputs'][1:] and
                unsigned_fields(negative) == unsigned_fields(control), 'transplant changed template or other input')
        extracted, extracted_public, _, _ = extract_unlock(negative, spent[0]['kind'], allowed_sighashes=(flag,))
        require(extracted == signature and extracted[:-1] == virtual['signature'][:-1] and
                extracted_public == virtual['pubkey'], 'virtual signature transplant was not delivered')
        actual_digest = sha256d(digest_preimage(negative, spent[0]['kind'], program,
                                               spent[0]['amount_sats'], sighash=flag))
        require(actual_digest == digests[0] and
                not integer_verify(actual_digest, extracted, extracted_public, sighash=flag) and
                not oracle_verify(oracle, actual_digest, extracted, extracted_public),
                'transplant did not independently fail ECDSA')
        for index, coin in enumerate(spent[1:], 1):
            verify_real_input(negative, coin, index, program, public, oracle, flag)
        node.phase = 'transplant-negative'
        result = mempool_probe(node, negative, allowed=False, rejection=SCRIPT_SIGNATURE_FAILURE)
        require(node.trace[offset:] == [('real-control-signing', 'signrawtransactionwithwallet'),
                                       ('real-control-acceptance', 'testmempoolaccept'),
                                       ('transplant-negative', 'testmempoolaccept')],
                'unexpected non-spending check operation')
    finally:
        node.phase = 'nonspending-observe-after'
        require(before == state_snapshot(node, wallet), 'non-spending checks changed funds state')
        require(files == authorization_artifacts(node), 'non-spending checks wrote authorization artifacts')
        node.phase = 'setup'
    return {'id': case_id, 'positive_allowed': True, 'positive_verified_inputs': len(spent),
            'negative_substitution_delivered': True, 'digest_differs_from_virtual': True,
            'python_rejects': True, 'oracle_rejects': True, 'sighash': flag,
            'negative_reason': result['reject-reason'], 'other_inputs_preserved': True, 'state_unchanged': True}


class MalformedResponseRejected(RuntimeError):
    """Only the observed validator may attribute rejection to a delivered mutation."""


class HarnessTests(unittest.TestCase):
    core = None
    oracle = None
    qualification = []
    negative_cases = []
    malformed_validation = {'source_validated': 0, 'delivered': 0, 'validator_calls': 0, 'rejected': 0}
    regression_checks = []
    nonspending_cases = []
    virtual_rejections = []

    def test_real_spend_transplants_with_positive_controls(self):
        for odd in (False, True):
            with Node(self.core) as node:
                fixture, coins = mature_fixture(node, 'transplants', odd)
                for source in (0, 1):
                    virtual = authorize(node, request_for_coins(fixture, coins, source), fixture['wallet'], self.oracle)
                    for target in (0, 1):
                        templates = real_spend_templates(coins, target, fixture['program'])
                        baseline = sha256d(digest_preimage(templates[0][1], target, fixture['program'],
                                                          templates[0][2][0]['amount_sats']))
                        for name, template, spent, flag in templates:
                            case = f'parity-{int(odd)}/source-{source}/target-{target}/{name}'
                            with self.subTest(case=case):
                                row = transplant_pair(node, fixture, virtual, template, spent, flag,
                                                      self.oracle, case, baseline)
                                self.nonspending_cases.append(row)

    def test_nonspending_rejects_wrong_attribution(self):
        with Node(self.core) as node:
            fixture, coins = mature_fixture(node, 'attribution')
            virtual = authorize(node, request_for_coins(fixture, coins, 1), fixture['wallet'], self.oracle)
            _, template, spent, flag = real_spend_templates(coins, 1, fixture['program'])[0]
            baseline = sha256d(digest_preimage(template, 1, fixture['program'], spent[0]['amount_sats']))
            original = node.call
            observed = {'positive': 0, 'script_rejections_delivered_as_missing_inputs': 0}
            def wrong_cause(method, *params, **kwargs):
                result = original(method, *params, **kwargs)
                if node.phase == 'real-control-acceptance':
                    require(result[0].get('allowed') is True, 'attribution regression lacks accepted control')
                    observed['positive'] += 1
                elif node.phase == 'transplant-negative':
                    require(result[0].get('reject-reason') == SCRIPT_SIGNATURE_FAILURE,
                            'attribution regression lacks original script rejection')
                    result = copy.deepcopy(result)
                    result[0]['reject-reason'] = 'missing-inputs'
                    observed['script_rejections_delivered_as_missing_inputs'] += 1
                return result
            credited_before = len(self.nonspending_cases)
            with patch.object(node, 'call', side_effect=wrong_cause):
                with self.assertRaisesRegex(RuntimeError, 'unexpected Core rejection cause'):
                    row = transplant_pair(node, fixture, virtual, template, spent, flag, self.oracle,
                                          'attribution-regression/base', baseline)
                    self.nonspending_cases.append(row)
            require(observed == {'positive': 1, 'script_rejections_delivered_as_missing_inputs': 1} and
                    len(self.nonspending_cases) == credited_before, 'wrong rejection cause received transplant credit')
            self.regression_checks.append({'id': 'nonspending-wrong-cause-not-credited',
                                           **observed, 'transplants_credited': 0})

    def test_virtual_parent_child_rejection(self):
        with Node(self.core) as node:
            fixture = fixture_wallet(node, 'virtual-rejection')
            for vector in public_profiles()['vectors']:
                virtual = authorize(node, vector['request'], fixture['wallet'], self.oracle)
                parent = parse_transaction(virtual['profile']['parent'])
                changed_child = copy.deepcopy(virtual['tx'])
                changed_child['version'] = 2
                # Clear relay-version and minimum non-witness-size checks to
                # isolate the nonexistent synthetic parent. This deliberately
                # modified child is not evidence of signature non-spending.
                changed_child['outputs'][0]['script'] = b'\x6a\x04test'
                node.phase = 'virtual-observe-before'
                before = state_snapshot(node, fixture['wallet'])
                offset = len(node.trace)
                try:
                    node.phase = 'virtual-rejection'
                    for name, tx, reason in (('parent-coinbase', parent, 'coinbase'),
                                             ('child-version', virtual['tx'], 'version'),
                                             ('relay-shaped-child-missing-parent', changed_child, 'missing-inputs')):
                        mempool_probe(node, tx, allowed=False, rejection=reason)
                        self.virtual_rejections.append({'kind': vector['request']['signing_kind'],
                                                        'id': name, 'reason': reason,
                                                        'spend_signature_evidence': False})
                    require(node.trace[offset:] == [('virtual-rejection', 'testmempoolaccept')] * 3,
                            'unexpected virtual rejection operation')
                finally:
                    node.phase = 'virtual-observe-after'
                    require(before == state_snapshot(node, fixture['wallet']), 'virtual checks changed funds state')
                    node.phase = 'setup'

    def expect_authorization_failure(self, node, request, wallet, name, *,
                                     expected_reason=None, signing_calls=1,
                                     expected_error=RuntimeError, record=True):
        node.phase = 'test-observe-before'
        before = state_snapshot(node, wallet)
        files = authorization_artifacts(node)
        offset = len(node.trace)
        sentinel = object()
        result = sentinel
        try:
            result = authorize(node, request, wallet, self.oracle)
        except RuntimeError as error:
            require(isinstance(error, expected_error), 'authorization failed at an unintended boundary')
            message = str(error)
            require(0 < len(message.encode()) <= 160 and not re.search('[0-9a-fA-F]{48,}', message) and
                    node.cookie.read_text().strip() not in message,
                    'unsafe authorization failure diagnostic')
            require(expected_reason is None or expected_reason in message,
                    'authorization failed for an unintended reason: ' + name)
        else:
            raise RuntimeError('negative authorization case succeeded: ' + name)
        require(result is sentinel, 'partial authorization result returned')
        node.phase = 'test-observe-after'
        require(before == state_snapshot(node, wallet), 'failed authorization changed funds state')
        require(files == authorization_artifacts(node), 'failed authorization wrote a partial artifact')
        operations = [method for phase, method in node.trace[offset:] if phase == 'signing']
        require(operations == ['signrawtransactionwithwallet'] * signing_calls,
                'unexpected failure operation count')
        observation = {'gettxoutsetinfo', 'listunspent', 'listlockunspent', 'getrawmempool'}
        allowed = {'ownership': {'getwalletinfo', 'decodescript', 'getaddressinfo'},
                   'signing': {'signrawtransactionwithwallet'}, 'observe-before': observation,
                   'observe-after': observation, 'test-observe-after': observation}
        require(all(phase in allowed and method in allowed[phase]
                    for phase, method in node.trace[offset:]), 'unexpected failure workflow RPC')
        require(node.phase == 'test-observe-after', 'unexpected phase after failed authorization')
        node.phase = 'setup'
        if record:
            self.negative_cases.append(name)

    def expect_malformed_response(self, node, request, wallet, name, mutation):
        original_call, validator = node.call, validate_signed_response
        observed = {'source_validated': 0, 'delivered': 0, 'validator_calls': 0, 'rejected': 0}
        replacement = None
        def altered(method, *params, **kwargs):
            nonlocal replacement
            response = original_call(method, *params, **kwargs)
            if node.phase == 'signing':
                # An actual complete, canonical, cryptographically valid stock
                # response is a precondition for this individual mutation.
                validator(request, response, self.oracle)
                observed['source_validated'] += 1
                replacement = copy.deepcopy(mutation)
                observed['delivered'] += 1
                return replacement
            return response
        def delivered_validator(actual_request, response, oracle):
            require(observed['source_validated'] == observed['delivered'] == 1 and
                    observed['validator_calls'] == 0 and response is replacement and
                    actual_request is request and oracle == self.oracle,
                    'malformed-response delivery precondition failed')
            observed['validator_calls'] += 1
            try:
                return validator(actual_request, response, oracle)
            except RuntimeError as error:
                observed['rejected'] += 1
                raise MalformedResponseRejected(str(error)) from None
        with patch.object(node, 'call', side_effect=altered), patch.dict(
                globals(), {'validate_signed_response': delivered_validator}):
            self.expect_authorization_failure(node, request, wallet, name,
                                              expected_error=MalformedResponseRejected, record=False)
        require(all(count == 1 for count in observed.values()), 'malformed-response evidence incomplete')
        for field, count in observed.items():
            self.malformed_validation[field] += count
        self.negative_cases.append(name)

    def test_unsupported_wallets(self):
        with Node(self.core) as node:
            good = fixture_wallet(node, 'good')
            wrong = fixture_wallet(node, 'wrong', odd=True)
            watch = fixture_wallet(node, 'watch', watch_only=True)
            only_wpkh = fixture_wallet(node, 'only-wpkh', kinds=(0,))
            locked = fixture_wallet(node, 'locked')
            # Verify real signing capability before deliberately locking it.
            authorize(node, public_profiles()['vectors'][0]['request'], locked['wallet'], self.oracle)
            node.call('encryptwallet', 'public disposable regtest passphrase', wallet=locked['wallet'])
            require(node.call('getwalletinfo', wallet=locked['wallet'])['unlocked_until'] == 0,
                    'locked-wallet setup did not lock wallet')
            node.call('createwallet', 'missing-key', False, True, '', False, True)
            for vector in public_profiles()['vectors']:
                kind, request = vector['request']['signing_kind'], vector['request']
                for name, wallet in (('locked', locked['wallet']), ('watch-only', watch['wallet']),
                                     ('wrong-wallet', wrong['wallet']), ('missing-key', 'missing-key')):
                    with self.subTest(case=name, kind=kind):
                        reason = ('code -13' if name == 'locked' else 'no private signing keys' if name == 'watch-only'
                                  else 'does not own selected script kind')
                        self.expect_authorization_failure(node, request, wallet, f'wallet/{name}/kind-{kind}',
                                                          expected_reason=reason,
                                                          signing_calls=1 if name == 'locked' else 0)
            pkh = public_profiles()['vectors'][0]['request']
            self.expect_authorization_failure(node, pkh, only_wpkh['wallet'], 'wallet/wpkh-only/kind-1',
                                              expected_reason='does not own selected script kind', signing_calls=0)
            # A supported kind remains usable; no pkh alias was inferred.
            authorize(node, public_profiles()['vectors'][1]['request'], only_wpkh['wallet'], self.oracle)
            require(node.call('getwalletinfo', wallet=locked['wallet'])['unlocked_until'] == 0,
                    'authorization unlocked locked wallet')
            require(all(method not in ('walletpassphrase', 'dumpprivkey', 'dumpwallet', 'sendrawtransaction',
                                       'fundrawtransaction', 'walletcreatefundedpsbt')
                        for phase, method in node.trace if phase != 'setup'), 'unsafe authorization RPC')
            require(good['program'] == only_wpkh['program'], 'wpkh-only fixture used a different key')

    def test_RPC_error_diagnostics(self):
        with Node(self.core) as node:
            marker = 'public-disposable-witness-marker' * 4
            for name, body in (('array-envelope', b'[]'),
                               ('oversized-error-code', json.dumps({'error': {'code': 10**100}}).encode()),
                               ('untrusted-error-code', json.dumps({'error': {'code': marker, 'message': marker}}).encode())):
                with patch('http.client.HTTPConnection') as connection:
                    response = connection.return_value.getresponse.return_value
                    response.status, response.read.return_value = 500, body
                    try:
                        node.call('getblockchaininfo')
                    except RuntimeError as error:
                        require(len(str(error).encode()) <= 160 and
                                marker not in ''.join(traceback.format_exception(error)),
                                'RPC envelope diagnostic exposed untrusted data')
                    else:
                        raise RuntimeError('malformed RPC envelope succeeded')
                    self.negative_cases.append('transport/' + name)
            with patch('http.client.HTTPConnection') as connection:
                connection.return_value.getresponse.side_effect = http.client.BadStatusLine(marker)
                try:
                    node.call('getblockchaininfo')
                except RuntimeError as error:
                    require(len(str(error).encode()) <= 160 and
                            marker not in ''.join(traceback.format_exception(error)),
                            'RPC transport diagnostic exposed untrusted data')
                else:
                    raise RuntimeError('malformed HTTP status succeeded')
                self.negative_cases.append('transport/untrusted-status-line')

    def test_malformed_signing_responses(self):
        with Node(self.core) as node:
            fixture = fixture_wallet(node, 'malformed')
            for vector in public_profiles()['vectors']:
                request, kind = vector['request'], vector['request']['signing_kind']
                result = authorize(node, request, fixture['wallet'], self.oracle)
                for name, mutation in malformed_responses(result, kind):
                    with self.subTest(case=name, kind=kind):
                        self.expect_malformed_response(node, request, fixture['wallet'],
                                                       f'response/{name}/kind-{kind}', mutation)

    def test_undelivered_response_failure_is_not_credited(self):
        with Node(self.core) as node:
            fixture = fixture_wallet(node, 'undelivered')
            request = public_profiles()['vectors'][0]['request']
            positive = authorize(node, request, fixture['wallet'], self.oracle)
            mutation = malformed_responses(positive, 1)[0][1]
            original_call, validator = node.call, validate_signed_response
            observed = {'rpc_failures': 0, 'validator_calls': 0}
            def unrelated_failure(method, *params, **kwargs):
                response = original_call(method, *params, **kwargs)
                if node.phase == 'signing':
                    observed['rpc_failures'] += 1
                    raise RuntimeError('injected unrelated RPC failure')
                return response
            def counted_validator(*args):
                observed['validator_calls'] += 1
                return validator(*args)
            credited_before = len(self.negative_cases)
            with patch.object(node, 'call', side_effect=unrelated_failure), patch.dict(
                    globals(), {'validate_signed_response': counted_validator}):
                with self.assertRaisesRegex(RuntimeError, 'unintended boundary'):
                    self.expect_malformed_response(node, request, fixture['wallet'],
                                                   'undelivered-response-regression', mutation)
            require(observed == {'rpc_failures': 1, 'validator_calls': 0} and
                    len(self.negative_cases) == credited_before,
                    'undelivered response incorrectly credited as parser rejection')
            self.regression_checks.append({'id': 'undelivered-response-failure-is-not-credited',
                                           **observed, 'negative_cases_credited': 0})

    def test_outgoing_zero_amount_and_ALL(self):
        with Node(self.core) as node:
            fixture = fixture_wallet(node, 'arguments')
            original = node.call
            for vector in public_profiles()['vectors']:
                request = vector['request']
                expected = virtual_profile(request)
                observed = []
                def checked(method, *params, **kwargs):
                    if node.phase == 'signing':
                        require(method == 'signrawtransactionwithwallet' and len(params) == 3,
                                'unexpected outgoing signing RPC')
                        require(params[0] == expected['unsigned'].hex() and params[2] == 'ALL',
                                'unexpected outgoing transaction/sighash')
                        require(params[1] == [{'txid': expected['parent_id'][::-1].hex(), 'vout': 0,
                                              'scriptPubKey': expected['script'].hex(), 'amount': 0}],
                                'unexpected synthetic prevout/amount')
                        observed.append(True)
                    return original(method, *params, **kwargs)
                with patch.object(node, 'call', side_effect=checked):
                    authorize(node, request, fixture['wallet'], self.oracle)
                require(observed == [True], 'outgoing signing arguments were not observed')

    def test_nonzero_P2WPKH_amount(self):
        with Node(self.core) as node:
            fixture = fixture_wallet(node, 'nonzero-amount')
            request = public_profiles()['vectors'][1]['request']
            expected = virtual_profile(request)
            original = node.call
            captured = []
            def changed_amount(method, *params, **kwargs):
                if node.phase == 'signing':
                    altered = copy.deepcopy(params[1])
                    altered[0]['amount'] = 1  # One disposable synthetic BTC; must not be used by authorize.
                    response = original(method, params[0], altered, params[2], **kwargs)
                    captured.append(response)
                    return response
                return original(method, *params, **kwargs)
            with patch.object(node, 'call', side_effect=changed_amount):
                self.expect_authorization_failure(node, request, fixture['wallet'], 'amount/nonzero-P2WPKH')
            require(len(captured) == 1 and captured[0].get('complete') is True,
                    'Core did not actually sign the nonzero-amount control')
            tx = parse_transaction(bytes.fromhex(captured[0]['hex']))
            signature, public = tx['inputs'][0]['witness']
            wrong_digest = sha256d(digest_preimage(expected['tx'], 0, fixture['program'], amount=100000000))
            require(wrong_digest != expected['z'], 'amount did not change witness digest')
            require(integer_verify(wrong_digest, signature, public) and
                    oracle_verify(self.oracle, wrong_digest, signature, public),
                    'nonzero-amount positive verification control failed')
            require(not integer_verify(expected['z'], signature, public) and
                    not oracle_verify(self.oracle, expected['z'], signature, public),
                    'nonzero amount unexpectedly verified against zero-amount digest')

    def test_independent_frozen_profiles(self):
        for vector in public_profiles()['vectors']:
            with self.subTest(profile=vector['name']):
                profile = virtual_profile(vector['request'])
                # Compare independent construction, not copied serialized fields.
                for field, expected in (('request', 'request_hex'), ('d', 'd'),
                                        ('message', 'application_message_hex'),
                                        ('m', 'application_message_hash'),
                                        ('script', 'selected_script_pubkey'), ('parent', 'to_spend_hex'),
                                        ('parent_id', 'to_spend_txid_raw'), ('unsigned', 'to_sign_unsigned_hex'),
                                        ('preimage', 'sighash_preimage_hex'), ('z', 'z')):
                    require(profile[field].hex() == vector[expected],
                            'independent reference disagrees with frozen profile: ' + field)
                commitment = tagged('BIP0322-signed-message', vector['request']['user_message_utf8'].encode())
                require(commitment.hex() == vector['request']['bip322_message_hash'],
                        'user-message commitment disagrees with frozen profile')

    def test_stock_wallet_frozen_profiles(self):
        with Node(self.core) as node:
            fixture = fixture_wallet(node, 'frozen')
            for vector in public_profiles()['vectors']:
                result = authorize(node, vector['request'], fixture['wallet'], self.oracle)
                require(result['pubkey'] == fixture['public'], 'unexpected fixture key')
                self.qualification.append({'case': 'frozen', 'kind': vector['request']['signing_kind'],
                                           'parity': 'even', 'integer_and_oracle': True,
                                           'state_unchanged': True})

    def test_stock_wallet_both_parities_mixed_real_claims(self):
        for odd in (False, True):
            with self.subTest(parity='odd' if odd else 'even'):
                with Node(self.core) as node:
                    fixture = fixture_wallet(node, 'mixed', odd)
                    # Setup only: mine mature outputs for BOTH imported descriptors.
                    for kind in (1, 0):
                        node.call('generatetoaddress', 101, fixture['addresses'][kind])
                    coins = node.call('listunspent', 101, 9999999, [], True, wallet=fixture['wallet'])
                    claims = []
                    for kind in (0, 1):
                        coin = next((c for c in coins if c['scriptPubKey'] ==
                                     script_for(kind, fixture['program']).hex()), None)
                        require(coin is not None and coin['spendable'] is True,
                                'missing mature owned fixture output')
                        claims.append({'txid_display': coin['txid'], 'vout': coin['vout'],
                                       'amount_sats': round(coin['amount'] * 100000000),
                                       'script_kind': kind, 'program': fixture['program'].hex()})
                    claims.sort(key=lambda c: (c['txid_display'], c['vout']))
                    for kind in (0, 1):
                        request = copy.deepcopy(public_profiles()['vectors'][kind]['request'])
                        request['signing_kind'], request['claims'] = kind, claims
                        if request['snapshot'] is not None:
                            request['snapshot'] = {'hash_display': node.call('getbestblockhash'),
                                                   'height': node.call('getblockcount')}
                        result = authorize(node, request, fixture['wallet'], self.oracle)
                        require(result['pubkey'] == fixture['public'], 'unexpected fixture key parity')
                        self.qualification.append({'case': 'mixed-real-claims', 'kind': kind,
                                                   'parity': 'odd' if odd else 'even',
                                                   'claims': 2, 'integer_and_oracle': True,
                                                   'state_unchanged': True})

    def test_fresh_descriptor_wallet(self):
        with Node(self.core) as node:
            require(node.call('getnetworkinfo')['networkactive'] is False,
                    'network unexpectedly active')
            self.assertEqual(node.call('listwallets'), [])
            node.call('createwallet', 'qualification')
            info = node.call('getwalletinfo', wallet='qualification')
            self.assertTrue(info['descriptors'])
            for kind in ('legacy', 'bech32'):
                address = node.call('getnewaddress', '', kind, wallet='qualification')
                self.assertTrue(node.call('getaddressinfo', address,
                                          wallet='qualification')['ismine'])
            directory = node.directory
            process = node.process
        self.assertEqual(process.returncode, 0)
        self.assertFalse(directory.exists())

    def test_missing_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, 'missing executable'):
                validate_inputs(Path(directory), self.oracle)

    def test_missing_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / 'bitcoind').symlink_to(self.core / 'bitcoind')
            with self.assertRaisesRegex(RuntimeError, 'missing executable: bitcoin-cli'):
                validate_inputs(Path(directory), self.oracle)

    def test_wrong_binary(self):
        for name in ('bitcoind', 'bitcoin-cli'):
            with self.subTest(program=name):
                with self.assertRaisesRegex(RuntimeError, 'expected stock Core 32.1'):
                    validate_binary(Path('/usr/bin/true'), name)

    def test_missing_oracle(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, 'missing signing oracle'):
                validate_inputs(self.core, Path(directory) / 'absent')

    def test_wrong_oracle(self):
        with self.assertRaisesRegex(RuntimeError, 'oracle self-test failed'):
            validate_inputs(self.core, Path('/usr/bin/true'))

    def test_occupied_port(self):
        with socket.socket() as occupied:
            occupied.bind(('127.0.0.1', 0))
            occupied.listen()
            node = Node(self.core, port=occupied.getsockname()[1])
            with self.assertRaisesRegex(RuntimeError, 'RPC port occupied'):
                with node:
                    self.fail('occupied port accepted')
            self.assertIsNone(node.process)
            self.assertFalse(node.directory.exists())

    def test_startup_timeout_cleanup(self):
        node = Node(self.core, startup_timeout=0)
        with self.assertRaisesRegex(RuntimeError, 'startup deadline'):
            with node:
                self.fail('zero startup deadline accepted')
        self.assertIsNotNone(node.process.returncode)
        self.assertFalse(node.directory.exists())

    def test_rpc_timeout(self):
        with Node(self.core, rpc_timeout=0.1) as node:
            # A local stalled HTTP peer proves bounded request failure without
            # relying on Core load or production endpoints.
            with socket.socket() as stalled:
                stalled.bind(('127.0.0.1', 0))
                stalled.listen()
                stalled.settimeout(2)
                stop = threading.Event()
                def serve():
                    try:
                        with stalled.accept()[0] as peer:
                            peer.settimeout(2)
                            peer.recv(8192)
                            stop.wait(2)
                    except TimeoutError:
                        pass
                worker = threading.Thread(target=serve)
                worker.start()
                original_port = node.port
                try:
                    node.port = stalled.getsockname()[1]
                    with self.assertRaisesRegex(RuntimeError, 'transport failed'):
                        node.call('getblockchaininfo')
                finally:
                    node.port = original_port
                    stop.set()
                    worker.join(timeout=3)
                self.assertFalse(worker.is_alive())

    def test_cleanup_after_body_failure(self):
        node = Node(self.core)
        with self.assertRaisesRegex(RuntimeError, 'injected body failure'):
            with node:
                raise RuntimeError('injected body failure')
        self.assertEqual(node.process.returncode, 0)
        self.assertFalse(node.directory.exists())

    def test_cleanup_failure_is_failure_and_reaps(self):
        node = Node(self.core, rpc_timeout=0.1, cleanup_timeout=0.1)
        try:
            node.start()
            os.kill(node.process.pid, signal.SIGSTOP)
            with self.assertRaisesRegex(RuntimeError, 'cleanup required forced termination'):
                node.close()
        finally:
            if node.process is None or node.process.poll() is None:
                node.close()
        self.assertIsNotNone(node.process.returncode)
        self.assertFalse(node.directory.exists())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core32', required=True, type=Path)
    parser.add_argument('--oracle', required=True, type=Path)
    args = parser.parse_args()
    try:
        validate_inputs(args.core32, args.oracle)
    except RuntimeError as error:
        print(f'Core32 qualification prerequisite failure: {error}', file=__import__('sys').stderr)
        return 1
    HarnessTests.core, HarnessTests.oracle = args.core32, args.oracle
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(HarnessTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({'executed': result.testsRun, 'failed': len(result.failures) + len(result.errors),
                      'skipped': len(result.skipped), 'total': result.testsRun,
                      'qualification': HarnessTests.qualification,
                      'negative_cases': HarnessTests.negative_cases,
                      'malformed_validation': HarnessTests.malformed_validation,
                      'regression_checks': HarnessTests.regression_checks,
                      'nonspending_cases': HarnessTests.nonspending_cases,
                      'virtual_rejections': HarnessTests.virtual_rejections}, sort_keys=True))
    return 0 if result.wasSuccessful() and result.testsRun and not result.skipped else 1


if __name__ == '__main__':
    raise SystemExit(main())
