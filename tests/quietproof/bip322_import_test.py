#!/usr/bin/env python3
"""Offline external-signature CLI contract; independent disposable test signatures."""
import argparse
import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

import signature_rpc_test as reference
core, ref = reference.core, reference.ref


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--disabled', action='store_true')
    args = parser.parse_args()
    count = 0
    with tempfile.TemporaryDirectory(prefix='bip322-import-') as directory:
        work = Path(directory)
        request_path, signature_path = work/'request.qpr', work/'signature'
        output = work/'receipt.qpa'
        mode = []  # External signing/import is a first-class default operation.

        def run(command, expected=0):
            nonlocal count
            count += 1
            result = subprocess.run([str(args.cli), *map(str, command)], capture_output=True, timeout=15)
            if result.returncode != expected:
                raise RuntimeError(f'case {count}: exit {result.returncode}, expected {expected}')
            if signature_path.exists() and len(signature_path.read_bytes()) > 30:
                assert signature_path.read_bytes().strip() not in result.stdout + result.stderr
            assert not list(work.glob('*.tmp.*'))
            return result

        def import_signature(data, form='bip322-simple', expected=65, extra=()):
            output.unlink(missing_ok=True)
            signature_path.unlink(missing_ok=True)
            signature_path.write_bytes(data)
            signature_path.chmod(0o600)
            result = run(['import-signature', *mode, '--request', request_path,
                          '--signature-input', signature_path, '--signature-format', form,
                          '--receipt-output', output, *extra], expected)
            if expected:
                assert not output.exists()
            else:
                assert output.stat().st_mode & 0o777 == 0o600
            return result

        for kind in (0, 1):
            request = copy.deepcopy(core.public_profiles()['vectors'][kind]['request'])
            request['signing_kind'] = kind
            request['network'] = 2 # signet, independent public test-address vectors below.
            key = b'\x02' + ref.GENERATOR[0].to_bytes(32, 'big')
            for claim in request['claims']:
                claim['program'] = ref.hash160(key).hex()
                claim['script_kind'] = kind
            request['not_before'], request['expires_at'] = int(time.time())-30, int(time.time())+3600
            signed = reference.mathematical_result(request)
            profile = signed['profile']
            request_path.write_bytes(profile['request'])
            material = work/f'message-{kind}'
            exported = run(['signing-material', *mode, '--request', request_path, '--output', material],
                           66 if args.disabled else 0)
            if args.disabled:
                import_signature(b'smpAAAA', expected=66)
                continue
            summary = json.loads(exported.stdout)
            assert material.read_bytes() == profile['message']
            assert len(material.read_bytes()) == 88 and not material.read_bytes().endswith(b'\n')
            assert summary['statement_digest'] == profile['d'].hex()
            assert request['network'] == 2
            assert summary['address'] == ('tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx' if kind == 0
                                          else 'mrCDrCybB6J1vRfbwM5hemdJz73FwDBC8r')
            run(['signing-material', *mode, '--request', request_path, '--output', material], 74)
            def encoded(tx, simple=False):
                if simple:
                    witness = tx['inputs'][0]['witness']
                    raw = ref.compact(len(witness)) + b''.join(ref.varbytes(v) for v in witness)
                else:
                    raw = ref.serialize(tx)
                return (b'smp' if simple else b'ful') + base64.b64encode(raw)
            full = encoded(signed['tx'])
            for value in (full, full[3:]):
                import_signature(value, 'bip322-full', 0)
            # Byte-for-byte receipt body remains the imported signature transaction.
            assert output.read_bytes()[44:] == ref.serialize(signed['tx'])
            for value in (b'ful'+base64.b64encode(ref.serialize(signed['tx'])+b'\x00'),
                          b'ful'+base64.b64encode(b'\x02'+ref.serialize(signed['tx'])[1:])):
                import_signature(value, 'bip322-full')
            if kind == 1:
                import_signature(encoded(signed['tx'], True), expected=66)
                continue
            simple = encoded(signed['tx'], True)
            for value in (simple, simple[3:]):
                import_signature(value, expected=0)
                assert output.read_bytes()[44:] == ref.serialize(signed['tx'])
            wrapper = dict(network=summary['network'], address=summary['address'], scriptKind='p2wpkh',
                           messageSha256=hashlib.sha256(profile['message']).hexdigest(),
                           format='bip322-simple', signature=simple.decode())
            import_signature(json.dumps(wrapper).encode(), 'sparrow-json', 0)
            for field, value in [('network','testnet4'), ('address','wrong'), ('scriptKind','p2pkh'),
                                 ('messageSha256','00'*32)]:
                bad = dict(wrapper, **{field:value})
                import_signature(json.dumps(bad).encode(), 'sparrow-json')
            for form in ('standard', 'electrum', 'bip137', 'bip322-full-psbt'):
                import_signature(json.dumps(dict(wrapper, format=form)).encode(), 'sparrow-json', 66)
            import_signature(simple, extra=['--address', 'wrong'])
            import_signature(simple, extra=['--network', 'mainnet'])
            for mutation in ('nonce', 'network', 'verifier', 'purpose', 'program'):
                altered = copy.deepcopy(request)
                if mutation == 'nonce': altered['nonce'] = 'af'*32
                elif mutation == 'network': altered['network'] = (request['network'] + 1) % 5
                elif mutation == 'program':
                    for claim in altered['claims']: claim['program'] = 'af'*20
                elif mutation == 'purpose': altered['purpose'] = 'proof-of-control'
                else: altered['verifier'] = 'another-verifier'
                request_path.write_bytes(ref.request_bytes(altered))
                import_signature(simple)
            request_path.write_bytes(profile['request'])
            for data in [b'', b'smp', b'ful'+simple[3:], b'smp!!!!', simple+b'\n', simple+b'AAAA',
                         b'smpA===', b'smpAB==', b'smpAAF=', b'smpAAAA====', b'smp'+b'A'*232,
                         b'smp'+base64.b64encode(b'\x00'), b'smp'+base64.b64encode(b'\xfd\x02\x00'),
                         b'smp'+base64.b64encode(b'\x02\xff'+bytes(100))]:
                import_signature(data, expected=65 if data else 74)
            # Exercise DER, sighash, scalar/key and canonical witness rules through
            # the user interface, using a fresh independent serialization each time.
            for change in ('high-s', 'wrong-key', 'sighash', 'bad-der', 'nonminimal-count', 'trailing'):
                tx = copy.deepcopy(signed['tx'])
                signature, pubkey = tx['inputs'][0]['witness']
                if change == 'high-s': signature = core.encode_signature(signed['r'], ref.ORDER-signed['s'])
                elif change == 'wrong-key': pubkey = bytes([pubkey[0]^1])+pubkey[1:]
                elif change == 'sighash': signature = signature[:-1]+b'\x81'
                elif change == 'bad-der': signature = b'\x31'+signature[1:]
                tx['inputs'][0]['witness'] = (signature, pubkey)
                data = encoded(tx, True)
                if change == 'nonminimal-count': data = b'smp'+base64.b64encode(b'\xfd\x02\x00'+base64.b64decode(data[3:])[1:])
                if change == 'trailing': data = b'smp'+base64.b64encode(base64.b64decode(data[3:])+b'\x00')
                import_signature(data)
            for malformed in (b'{}', b'{', b'[]', b'null'):
                import_signature(malformed, 'sparrow-json')
            # Owner-only regular bounded input, no symlinks/FIFOs or replacements.
            import_signature(simple, expected=0)
            command = ['import-signature', *mode, '--request', request_path,
                       '--signature-input', signature_path, '--signature-format', 'bip322-simple',
                       '--receipt-output', output]
            run(command, 74)
            output.unlink()
            signature_path.chmod(0o644)
            run(command, 74)
            signature_path.unlink()
            target = work/'private-target'; target.write_bytes(simple); target.chmod(0o600)
            signature_path.symlink_to(target)
            run(command, 74)
            signature_path.unlink(); os.mkfifo(signature_path)
            # Do not read a FIFO in the diagnostic-disclosure assertion above.
            result = subprocess.run([str(args.cli), *map(str, command)], capture_output=True, timeout=5)
            count += 1; assert result.returncode == 74
            signature_path.unlink()
            import_signature(bytes(16385), expected=74)
    print(f'{count} offline BIP322 import/export CLI checks passed; no RPC or wallet credentials')


if __name__ == '__main__':
    main()
