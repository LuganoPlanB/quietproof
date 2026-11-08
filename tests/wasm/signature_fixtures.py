#!/usr/bin/env python3
"""Generate distinct public browser proofs from independent native test signatures."""
import argparse
import copy
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import signing_reference as ref
import bitcoin_core_signing_regtest as core


def public_request(path):
    """Read a browser-issued public request with an independent bounded codec."""
    raw = path.read_bytes()
    assert len(raw) <= 4096
    position = 0
    def take(size):
        nonlocal position
        assert 0 <= size <= len(raw) - position
        value = raw[position:position + size]
        position += size
        return value
    def number(size):
        return int.from_bytes(take(size), 'big')
    def text():
        return take(number(2)).decode('utf-8')
    assert take(7) == b'QPS1\x04\x00\x01'  # mainnet v4 PoSC
    profile_id, profile_version = number(2), number(1)
    request = dict(network=0, profile=profile_id, profile_version=profile_version, signing_kind=number(1), verifier=text(), purpose=text(),
                   nonce=take(32).hex(), bip322_message_hash=take(32).hex(),
                   not_before=number(8), expires_at=number(8), snapshot=None)
    assert number(1) == 0 and number(1) == 0  # no snapshot or extensions
    count = number(2)
    assert count == 16
    request['claims'] = [dict(txid_display=take(32).hex(), vout=number(4),
                              amount_sats=number(8), script_kind=number(1), program=take(20).hex())
                         for _ in range(count)]
    assert position == len(raw)
    assert ref.request_bytes(request) == raw  # independent canonical byte equality
    return request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--disabled', action='store_true')
    parser.add_argument('--largest-only', action='store_true',
                        help='Generate a distinct real maximum-16-claim proof without rewriting prior fixtures')
    parser.add_argument('--request-file', type=Path,
                        help='Prove an actual browser-issued public max16 mainnet request with test key 1')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    profile = json.loads((Path(__file__).resolve().parents[2] / 'spec/signature-profile-v1.json').read_text())
    cases = []
    now = int(time.time())
    key = bytes([2]) + ref.GENERATOR[0].to_bytes(32, 'big')  # disposable scalar 1
    selected = [('signature-max16', 0, 1, True)] if args.largest_only else [
        ('signature-p2pkh', 1, 2, False), ('signature-p2pkh-bip322', 1, 1, False),
        ('signature-p2wpkh', 0, 1, False), ('signature-mixed', 0, 1, True)]
    for name, kind, procedure, mixed in selected:
        vectors = profile['legacy_vectors'] if procedure == 2 else profile['vectors']
        request = copy.deepcopy(next(v['request'] for v in vectors if v['request']['signing_kind'] == kind))
        request.update(network=0, snapshot=None, not_before=now - 60, expires_at=now + 21600)
        if not mixed:
            request['claims'] = [c for c in request['claims'] if c['script_kind'] == kind][:1]
        if args.largest_only:
            template = request['claims'][0]
            request['claims'] = [{**template, 'txid_display': f'{i + 1:064x}', 'vout': 0,
                                  'amount_sats': 50000 + i * 1000, 'script_kind': i % 2}
                                 for i in range(16)]
        for claim in request['claims']:
            claim['program'] = ref.hash160(key).hex()
        if args.request_file:
            assert not args.disabled and args.largest_only
            request = public_request(args.request_file)
            kind = request['signing_kind']
            procedure = request['profile']
            assert all(c['program'] == ref.hash160(key).hex() for c in request['claims'])
        derived = ref.bitcoin_message_profile(request) if procedure == 2 else ref.virtual_profile(request)
        r = ref.GENERATOR[0]
        s = (int.from_bytes(derived['z'], 'big') + r) % ref.ORDER
        if procedure == 2:
            # Disposable scalar=1, nonce=1: recovery parity is inverted by low-S.
            recovery = (ref.GENERATOR[1] & 1) ^ int(s > ref.ORDER // 2)
            signed = bytes([31 + recovery]) + r.to_bytes(32, 'big') + min(s, ref.ORDER-s).to_bytes(32, 'big')
        else:
            signature = core.encode_signature(r, min(s, ref.ORDER - s))
            assert ref.integer_verify(derived['z'], signature, key)
            signed = ref.serialize(core.replace_unlock(derived['tx'], kind, signature, key))
        receipt = struct.pack('>4sBBHB32sI', b'QPA1', 4, 1, procedure, 1, derived['d'], len(signed)) + signed
        cases.append(dict(name=name, request=derived['request'].hex(), receipt=receipt.hex()))
    # The private authorisation input is temporary, owner-only, and never placed
    # among the browser's public fixtures. Only .qpr/.qpf and provenance survive.
    with tempfile.TemporaryDirectory(prefix='signature-witness-') as temporary:
        path = Path(temporary) / 'private.json'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as stream:
            json.dump(cases, stream)
        command = [args.driver, str(path), str(args.output)]
        if args.disabled:
            command.append('--disabled')
        subprocess.run(command, check=True, timeout=7100)


if __name__ == '__main__':
    main()
