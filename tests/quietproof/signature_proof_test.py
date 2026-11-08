#!/usr/bin/env python3
"""Create private independent disposable signatures; run scalar-free proof APIs."""
import argparse
import copy
import hashlib
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
from bitcoin_message_test import legacy


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--driver', required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--disabled', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    profile = json.loads((root/'spec/signature-profile-v1.json').read_text())
    args.work.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='signature-proof-', dir=args.work))
    os.chmod(directory, 0o700)
    now = int(time.time())
    cases = []
    for name, kind, odd, mixed in [('p2pkh', 1, False, False), ('p2wpkh', 0, True, False),
                                   ('mixed', 0, False, True)]:
        request = copy.deepcopy(next(v['request'] for v in profile['vectors'] if v['request']['signing_kind'] == kind))
        request['not_before'], request['expires_at'] = now - 60, now + 21600
        key = bytes([3 if odd else 2]) + ref.GENERATOR[0].to_bytes(32, 'big')
        if not mixed:
            request['claims'] = [c for c in request['claims'] if c['script_kind'] == kind][:1]
        for claim in request['claims']:
            claim['program'] = ref.hash160(key).hex()
        derived = ref.virtual_profile(request)
        # Independent test signer. Only the resulting receipt, never d/k,
        # reaches the C++ prover process. Material stays owner-only on disk.
        d = ref.ORDER - 1 if odd else 1
        r = ref.GENERATOR[0]
        s = (int.from_bytes(derived['z'], 'big') + r*d) % ref.ORDER
        s = min(s, ref.ORDER-s)
        signature = core.encode_signature(r, s)
        assert ref.integer_verify(derived['z'], signature, key)
        tx = core.replace_unlock(derived['tx'], kind, signature, key)
        signed = ref.serialize(tx)
        receipt = struct.pack('>4sBBHB32sI', b'QPA1', 4, 1, 1, 1, derived['d'], len(signed)) + signed
        cases.append({'name': name, 'request': derived['request'].hex(), 'receipt': receipt.hex(),
                      'z': derived['z'].hex(), 'h': ref.hash160(key).hex()})
    for name, scalar in [('legacy_even', 1), ('legacy_odd', ref.ORDER - 1)]:
        template = copy.deepcopy(profile['legacy_vectors'][0]['request'])
        template.update(not_before=now-60, expires_at=now+21600)
        _, vector = legacy(template, scalar)
        cases.append({'name':name,'request':vector['request'],'receipt':vector['receipt'],
                      'z':vector['z'],'h':ref.hash160(bytes.fromhex(vector['key'])).hex()})
    path = directory/'private-fixtures.json'
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        json.dump({'cases': cases}, stream)
    malformed = directory/'malformed-private-fixture.json'
    fd = os.open(malformed, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write('{"receipt":"QUIETPROOF_PRIVATE_DIAGNOSTIC_SENTINEL')
    diagnostic = subprocess.run([args.driver, str(malformed), str(directory)],
                                capture_output=True, text=True, timeout=10)
    assert diagnostic.returncode == 1 and not diagnostic.stdout
    assert diagnostic.stderr == 'signature proof test: private fixture parse failure\n'
    print('private fixture diagnostic checks=1 failed=0', flush=True)
    command = [args.driver, str(path), str(directory)]
    if args.disabled:
        command.append('--disabled')
    # Inherit stdout so phase progress is observable; the driver emits no
    # receipts, signatures, keys, advice or fixture contents on either stream.
    result = subprocess.run(command, timeout=7100)
    print(json.dumps({'privateFixture': str(path), 'bytes': path.stat().st_size,
                      'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                      'mode': oct(path.stat().st_mode & 0o777), 'cases': len(cases),
                      'disabled': args.disabled}), flush=True)
    return result.returncode


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception:
        sys.exit('signature proof fixture or execution failed')
