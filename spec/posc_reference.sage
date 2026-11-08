#!/usr/bin/env sage
# Copyright (C) 2026 Plan-B Foundation
# SPDX-License-Identifier: GPL-3.0-or-later
"""PoSC (Proof of Signature Custody): independent Sage mathematical oracle.

Public inputs are the exact 32 digest bytes z and 20 HASH160 bytes h. The
private mathematical witness is (Q,r,s), not a signing scalar. Sage supplies
the group operations; no production gadget, witness builder, signature library
or Python signature reference is imported. Only the older Sage oracle's
independent SHA-256/RIPEMD-160 compression functions are shared.

This evaluates a relation, not a proof system or its witness wires. Frozen
request/profile cross-checks exercise digest binding outside the circuit.
All generated witnesses are disposable PUBLIC test data.
"""
import argparse
import copy
import importlib.machinery
import importlib.util
import json
from math import isqrt
from pathlib import Path
import sys

from sage.all import EllipticCurve, GF, Integer, is_prime
from sage.env import SAGE_VERSION

ROOT = Path(__file__).resolve().parents[1]
P = Integer(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F)
N = Integer(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
F = GF(P)
E = EllipticCurve(F, [0, 7])
G = E(F(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798),
      F(0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8))
O = E(0)

loader = importlib.machinery.SourceFileLoader('posc_hash_reference', str(ROOT / 'spec/pokc_reference.sage'))
spec = importlib.util.spec_from_loader(loader.name, loader)
hashes = importlib.util.module_from_spec(spec)
previous_bytecode_setting = sys.dont_write_bytecode
sys.dont_write_bytecode = True
try:
    loader.exec_module(hashes)
finally:
    sys.dont_write_bytecode = previous_bytecode_setting
sha256, ripemd160, tagged_hash = hashes.sha256, hashes.ripemd160, hashes.tagged_hash


def require(condition, message):
    if not condition:
        raise ValueError(message)


def number(value, width, endian='big'):
    require(0 <= value < 2 ** (8 * width), 'integer width')
    return int(value).to_bytes(width, endian)


def sec(point):
    require(point != O, 'infinite key')
    return bytes([2 + int(Integer(point[1]) % 2)]) + number(Integer(point[0]), 32)


def hash160(point):
    return ripemd160(sha256(sec(point)))


def affine(raw):
    require(raw is not None, 'infinite key')
    x, y = (Integer(int(raw[k], 16)) for k in ('x', 'y'))
    # Validate INTEGER coordinates before coercion into GF(p).
    require(0 <= x < P and 0 <= y < P, 'noncanonical key')
    require((y * y - x * x * x - 7) % P == 0, 'off-curve key')
    return E(F(x), F(y))


def point_json(point):
    return None if point == O else {k: format(int(point[i]), '064x') for i, k in enumerate(('x', 'y'))}


def ecdsa(digest, q, r, s):
    """The full low-S secp256k1 relation, including e=0 and x(R)=r+n."""
    result = {'valid': False}
    try:
        require(len(digest) == 32, 'digest width')
        key = affine(q)
        r, s = Integer(r), Integer(s)
        require(1 <= r < N, 'r range')
        require(1 <= s <= N // 2, 's range/low-S')
        e = Integer(int.from_bytes(digest, 'big')) % N
        inverse = s.inverse_mod(N)
        nonce = (e * inverse % N) * G + (r * inverse % N) * key
        result.update(e=format(int(e), 'x'), R=point_json(nonce))
        require(nonce != O, 'infinite verification point')
        x = Integer(nonce[0])
        require(x % N == r, 'ECDSA x mismatch')
        # Check the equivalent equation used by the projective production
        # circuit through a separate Sage group expression.
        require(e * G + r * key - s * nonce == O, 'group equation')
        result.update(valid=True, branch='r' if x == r else 'r+n',
                      compressed_sec=sec(key).hex(), h=hash160(key).hex())
    except ValueError as error:
        result['reason'] = str(error)
    return result


def relation(digest, public_hash, q, r, s):
    result = ecdsa(digest, q, r, s)
    if result['valid'] and (len(public_hash) != 20 or bytes.fromhex(result['h']) != public_hash):
        result.update(valid=False, reason='HASH160 binding')
    return result


def request_bytes(request):
    """Bounded typed request encoding; no wall clock or chain-state claims."""
    claims = request['claims']
    require(request['network'] in range(5) and request['signing_kind'] in (0, 1), 'network/kind')
    procedure, version = request['profile'], request['profile_version']
    require(procedure in (1, 2) and version == 1, 'profile/version')
    require(procedure != 2 or request['signing_kind'] == 1, 'profile/kind')
    require(1 <= len(claims) <= 16, 'claim count')
    require(request['signing_kind'] in [c['script_kind'] for c in claims], 'selected kind absent')
    require(len({c['program'] for c in claims}) == 1, 'different key hashes')
    order = [(bytes.fromhex(c['txid_display']), c['vout']) for c in claims]
    require(order == sorted(set(order)), 'claim ordering/duplicates')
    require(sum(c['amount_sats'] for c in claims) <= 2100000000000000, 'sum range')
    def text(value):
        raw = value.encode('utf-8')
        require(1 <= len(raw) <= 256 and all(ord(c) >= 32 and ord(c) != 127 for c in value), 'text')
        return number(len(raw), 2) + raw
    result = b'QPS1\x04' + bytes([request['network'], 1])
    result += number(procedure, 2) + bytes([version, request['signing_kind']])
    result += text(request['verifier']) + text(request['purpose'])
    for name in ('nonce', 'bip322_message_hash'):
        raw = bytes.fromhex(request[name])
        require(len(raw) == 32 and any(raw), 'commitment')
        result += raw
    require(request['not_before'] < request['expires_at'], 'validity interval')
    result += number(request['not_before'], 8) + number(request['expires_at'], 8)
    snapshot = request['snapshot']
    result += bytes([snapshot is not None])
    if snapshot is not None:
        block = bytes.fromhex(snapshot['hash_display'])
        require(len(block) == 32 and any(block), 'snapshot')
        result += block + number(snapshot['height'], 4)
    result += b'\x00' + number(len(claims), 2)
    for claim in claims:
        txid, program = bytes.fromhex(claim['txid_display']), bytes.fromhex(claim['program'])
        require(len(txid) == 32 and any(txid) and len(program) == 20, 'claim bytes')
        require(claim['script_kind'] in (0, 1), 'script kind')
        require(1 <= claim['amount_sats'] <= 2100000000000000, 'amount')
        result += txid + number(claim['vout'], 4) + number(claim['amount_sats'], 8)
        result += bytes([claim['script_kind']]) + program
    require(len(result) <= 4096, 'request size')
    return result


def profile(request):
    """Frozen one-input, zero-valued BIP-322-style virtual transaction only."""
    raw = request_bytes(request)
    digest = tagged_hash('QuietProof/statement/v4', raw)
    message = b'quietproof:signature:v4:' + digest.hex().encode('ascii')
    require(request['profile'] == 1, 'BIP322 profile required')
    message_hash = tagged_hash('BIP0322-signed-message', message)
    h = bytes.fromhex(request['claims'][0]['program'])
    script_code = b'\x76\xa9\x14' + h + b'\x88\xac'
    selected = script_code if request['signing_kind'] == 1 else b'\x00\x14' + h
    def sized(value):
        require(len(value) < 253, 'fixed profile script size')
        return bytes([len(value)]) + value
    def double(value):
        return sha256(sha256(value))
    zero4, zero8 = bytes(4), bytes(8)
    parent = (zero4 + b'\x01' + bytes(32) + b'\xff' * 4 + sized(b'\x00\x20' + message_hash)
              + zero4 + b'\x01' + zero8 + sized(selected) + zero4)
    parent_id = double(parent)
    outpoint = parent_id + zero4
    output = zero8 + b'\x01\x6a'
    unsigned = zero4 + b'\x01' + outpoint + b'\x00' + zero4 + b'\x01' + output + zero4
    if request['signing_kind'] == 1:
        preimage = zero4 + b'\x01' + outpoint + sized(script_code) + zero4 + b'\x01' + output + zero4
    else:
        preimage = (zero4 + double(outpoint) + double(zero4) + outpoint + sized(script_code)
                    + zero8 + zero4 + double(output) + zero4)
    preimage += b'\x01\x00\x00\x00'  # SIGHASH_ALL, never a selectable arbitrary digest
    return {'request_hex': raw.hex(), 'd': digest.hex(), 'application_message_hex': message.hex(),
            'application_message_hash': message_hash.hex(), 'selected_script_pubkey': selected.hex(),
            'script_code': script_code.hex(), 'to_spend_hex': parent.hex(),
            'to_spend_txid_raw': parent_id.hex(), 'to_sign_unsigned_hex': unsigned.hex(),
            'sighash_preimage_hex': preimage.hex(), 'z': double(preimage).hex()}


def signed_case(name, z, scalar=1, nonce=2):
    """PUBLIC fixture construction only; the relation itself takes no scalar."""
    key, point = scalar * G, nonce * G
    r = Integer(point[0]) % N
    s = ((Integer(z) % N + r * scalar) * Integer(nonce).inverse_mod(N)) % N
    s = min(s, N - s)
    require(r != 0 and s != 0, 'degenerate public fixture')
    return {'id': name, 'z': number(z, 32).hex(), 'h': hash160(key).hex(),
            'Q': point_json(key), 'r': format(int(r), 'x'), 's': format(int(s), 'x')}


def build_document(corpus_path, profile_path):
    require(is_prime(P) and is_prime(N) and N * G == O, 'secp256k1 domains')
    require(E.discriminant() != 0 and (N - 1) * G == -G, 'group anchors')
    # G has prime order N. Hasse's bound contains just one positive multiple
    # of N, establishing #E=N and cofactor one without an expensive point count.
    hasse_bound = 2 * isqrt(int(P)) + 2
    require(0 < P + 1 - hasse_bound <= N <= P + 1 + hasse_bound < 2 * N, 'cofactor-one Hasse bound')
    require(sec(2 * G).hex() == '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5', '2G anchor')
    corpus = json.loads(corpus_path.read_text())
    require(Integer(int(corpus['domains']['p'], 16)) == P and Integer(int(corpus['domains']['n'], 16)) == N, 'corpus domains')
    cases, ids = [], set()
    def add(case, expected=None):
        case = copy.deepcopy(case)
        require(case['id'] not in ids, 'duplicate case')
        ids.add(case['id'])
        verdict = relation(bytes.fromhex(case['z']), bytes.fromhex(case['h']), case['Q'],
                           int(case['r'], 16), int(case['s'], 16))
        if expected is not None:
            require(verdict['valid'] == expected, 'unexpected decision: ' + case['id'])
        case['expected'] = verdict
        q = case['Q']
        case['circuit_input_representable'] = (q is not None and len(bytes.fromhex(case['z'])) == 32
            and len(bytes.fromhex(case['h'])) == 20
            and all(0 <= int(v, 16) < 2**256 for v in (q['x'], q['y'], case['r'], case['s'])))
        cases.append(case)
        return case
    for row in corpus['relation_cases']:
        case = {k: row[k] for k in ('id', 'z', 'Q', 'r', 's')}
        q = row['Q']
        # An invalid raw point still has a well-defined 33-byte SEC-shaped
        # hash if x fits; arithmetic must reject it before any field reduction.
        if q is not None and 0 <= int(q['x'], 16) < 2**256:
            encoded = bytes([2 + (int(q['y'], 16) % 2)]) + number(int(q['x'], 16), 32)
            case['h'] = ripemd160(sha256(encoded)).hex()
        else:
            case['h'] = bytes(20).hex()
        checked = add(case, row['expected']['valid'])
        if checked['expected']['valid']:
            require(checked['expected']['R'] == {k: format(int(v, 16), '064x') for k, v in row['expected']['R'].items()}, 'Sage/Python R mismatch')
            require(checked['expected']['branch'] == row['expected']['x_branch'], 'Sage/Python branch mismatch')
    for value, label in [(0, 'zero'), (N, 'n'), (P, 'p'), (2**256 - 1, 'max')]:
        for scalar, suffix in [(1, 'G'), (N - 1, 'minus_G')]:
            add(signed_case('sage_' + label + '_' + suffix, value, scalar), True)
    # Construct the rare r+n branch mathematically, without nonce searching.
    for candidate in range(1, 1025):
        k = Integer(candidate)
        require(N + k < P, 'rare branch search bound')
        if (F(N + k)**3 + 7).is_square():
            break
    else:
        raise ValueError('no rare branch fixture within deterministic bound')
    y = Integer((F(N + k)**3 + 7).sqrt())
    nonce_point = E(F(N + k), F(min(y, P - y)))
    key = k.inverse_mod(N) * (nonce_point - G)
    rare = {'id': 'sage_constructed_rare', 'z': number(1, 32).hex(), 'h': hash160(key).hex(),
            'Q': point_json(key), 'r': format(int(k), 'x'), 's': '1'}
    add(rare, True)
    baseline = signed_case('baseline', 0)
    for byte in range(20):
        case = copy.deepcopy(baseline); case['id'] = 'sage_wrong_hash_' + str(byte)
        h = bytearray.fromhex(case['h']); h[byte] ^= 1; case['h'] = h.hex(); add(case, False)
    for byte in range(32):
        case = copy.deepcopy(baseline); case['id'] = 'sage_wrong_digest_' + str(byte)
        z = bytearray.fromhex(case['z']); z[byte] ^= 1; case['z'] = z.hex(); add(case, False)
    opposite = copy.deepcopy(baseline); opposite.update(id='sage_opposite_parity_wrong_hash', Q=point_json(-G)); add(opposite, False)
    profiles = []
    for row in json.loads(profile_path.read_text())['vectors']:
        derived = profile(row['request'])
        require(all(derived[k] == row[k] for k in derived), 'frozen signing profile: ' + row['name'])
        case = signed_case('sage_profile_' + row['name'], int(derived['z'], 16))
        require(case['h'] == row['request']['claims'][0]['program'], 'profile key HASH160')
        add(case, True)
        bindings = []
        for field in ['nonce', 'purpose', 'network', 'amount_sats', 'vout']:
            request = copy.deepcopy(row['request'])
            if field == 'nonce':
                value = bytearray.fromhex(request[field]); value[0] ^= 1; request[field] = value.hex()
            elif field == 'purpose': request[field] += '!'
            elif field == 'network': request[field] = (request[field] + 1) % 5
            else: request['claims'][0][field] += 1
            changed = profile(request)
            require(changed['d'] != derived['d'] and changed['z'] != derived['z'], 'request binding')
            mutation = copy.deepcopy(case); mutation.update(id=case['id'] + '_changed_' + field, z=changed['z'])
            add(mutation, False)
            bindings.append({'field': field, 'd': changed['d'], 'z': changed['z']})
        profiles.append({'name': row['name'], **derived, 'binding_changes': bindings})
    return {'format': 'quietproof-posc-sage-v1', 'name': 'PoSC (Proof of Signature Custody)',
            'sage_version': SAGE_VERSION, 'domains': {'p': format(int(P), 'x'), 'n': format(int(N), 'x')},
            'profile_wire_version': 4,
            'scope': 'Independent mathematical relation and fixed public request/digest derivation; not a circuit-wire or proof-system soundness theorem.',
            'public_test_data': True, 'cases': cases, 'profiles': profiles,
            'malformed_serialization_cases_outside_relation': [c['id'] for c in corpus['malformed_cases']]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', type=Path)
    parser.add_argument('--emit', action='store_true')
    parser.add_argument('--corpus', type=Path, default=ROOT / 'spec/signature-vectors.json')
    parser.add_argument('--profiles', type=Path, default=ROOT / 'spec/signature-profile-v1.json')
    args = parser.parse_args()
    require(SAGE_VERSION == '10.6', 'PoSC reference requires SageMath 10.6')
    document = build_document(args.corpus, args.profiles)
    if args.check:
        expected = json.loads(args.check.read_text())
        # This descriptive fixture provenance is not mathematical output. It
        # never substitutes for executing this independent Sage check.
        expected.pop('generation_note', None)
        require(document == expected, 'PoSC Sage fixture mismatch')
    if args.emit:
        print(json.dumps(document, indent=2, sort_keys=True))
    else:
        print(json.dumps({'model': document['name'], 'cases': len(document['cases']),
            'accepted': sum(c['expected']['valid'] for c in document['cases']),
            'profiles': len(document['profiles']), 'failed': 0}, sort_keys=True))


if __name__ == '__main__':
    main()
