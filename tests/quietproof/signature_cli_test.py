#!/usr/bin/env python3
"""Explicit CLI authorisation/delegation, private files and real proof workflows."""
import argparse
import copy
import json
import os
from pathlib import Path
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time

import signature_rpc_test as adapter
core, ref = adapter.core, adapter.ref


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', type=Path, required=True)
    parser.add_argument('--rpc', choices=('ON', 'OFF'), required=True)
    parser.add_argument('--disabled', action='store_true')
    parser.add_argument('--fault', type=Path)
    parser.add_argument('--proof-verifier', type=Path)
    parser.add_argument('--core32', type=Path)
    parser.add_argument('--oracle', type=Path)
    args = parser.parse_args()
    count, proofs = 0, 0
    mode = ['--proof-mode', 'signature-possession']
    with tempfile.TemporaryDirectory(prefix='quietproof-signature-cli-') as temp:
        root = Path(temp)
        base = copy.deepcopy(core.public_profiles()['vectors'][0]['request'])
        base['not_before'], base['expires_at'] = int(time.time()) - 60, int(time.time()) + 3600
        request_path, receipt_path, output = root/'request.qpr', root/'receipt.qpa', root/'proof.qpf'
        cookie = root/'cookie'
        cookie.write_text('fixture:cookie-secret-never-print')
        cookie.chmod(0o600)
        peer = adapter.Peer()
        thread = threading.Thread(target=peer.serve_forever, daemon=True)
        thread.start()
        endpoint = ['--rpc-url', f'http://127.0.0.1:{peer.server_port}/', '--rpc-cookie', str(cookie)]
        node = None

        def fixture(request):
            peer.profile = ref.virtual_profile(request)
            result = adapter.mathematical_result(request)
            peer.result = {'complete': True, 'hex': ref.serialize(result['tx']).hex()}
            peer.wallet = 'selected /?'
            peer.scenario = 'ok'
            peer.records.clear()
            peer.errors.clear()
            request_path.write_bytes(peer.profile['request'])
            signed = bytes.fromhex(peer.result['hex'])
            receipt = struct.pack('>4sBBH32sI', b'QPA1', 1, 1, 1, peer.profile['d'], len(signed)) + signed
            receipt_path.write_bytes(receipt)
            receipt_path.chmod(0o600)

        def run(command, expected=0, env=None, timeout=15):
            nonlocal count
            count += 1
            result = subprocess.run([str(args.cli), *map(str, command)], input=b'PRIVATE-STDIN-MUST-NOT-BE-USED\n',
                                    capture_output=True, timeout=timeout, env=env)
            require(result.returncode == expected, f'CLI case {count}: unexpected exit {result.returncode}, expected {expected}')
            for marker in (b'cookie-secret', b'server-secret', b'PRIVATE-STDIN', bytes.fromhex(peer.result['hex']).hex().encode() if peer.result else b'never-matches-secret'):
                require(marker not in result.stdout + result.stderr, f'CLI case {count}: private diagnostic disclosure')
            require(not peer.errors, 'CLI used unsafe production RPC arguments')
            require(not list(root.glob('*.tmp.*')), 'partial output survived')
            return result

        def claim_options(request):
            result = []
            for claim in request['claims']:
                result += ['--claim', f"{claim['txid_display']}:{claim['vout']}:{claim['amount_sats']}:{'p2pkh' if claim['script_kind'] else 'p2wpkh'}:{claim['program']}"]
            return result

        def create(kind=1, target=None, extra=()):
            return ['challenge', 'create', '--network', 'regtest', '--verifier', base['verifier'],
                    '--purpose', base['purpose'], '--expires-in', '3600', '--message', 'CLI delegation',
                    '--output', str(target or root/'created.qpr'), *claim_options(base), *extra,
                    *mode, '--signing-kind', 'p2pkh' if kind else 'p2wpkh']

        def prove(extra=()):
            return ['prove', *mode, '--request', request_path, '--output', output, *extra]

        def authorize(target=None, extra=()):
            return ['authorize', *mode, '--request', request_path, '--receipt-output', target or root/'exported.qpa',
                    '--rpc-wallet', peer.wallet, *endpoint, *extra]

        try:
            fixture(base)
            help_result = run(['--help'])
            require(all(s in help_result.stdout for s in (b'private authorisation capability', b'delegate', b'.qpf is public', b'signing time')), 'help claim/delegation wording')
            if args.disabled:
                run(create(), 66)
                run(prove(['--receipt-input', receipt_path]), 66)
                run(authorize(), 66)
                require(not peer.records and not output.exists(), 'disabled mode used wallet or wrote output')
            elif args.proof_verifier:
                # A complete real proof is verified with the independently
                # retained request by a wallet-free cryptographic-only driver.
                if args.core32:
                    core.validate_inputs(args.core32, args.oracle)
                    node = core.Node(args.core32).__enter__()
                    wallet, coins = core.mature_fixture(node, 'cli-production')
                    base = core.request_for_coins(wallet, coins, 1)
                    base['not_before'], base['expires_at'] = int(time.time()) - 60, int(time.time()) + 3600
                    fixture(base)
                    peer.node, peer.wallet = node, wallet['wallet']
                    before = core.state_snapshot(node, wallet['wallet'])
                    # Export the request's private capability independently of
                    # the online proof flow; use a fresh destination.
                    run(authorize())
                    exported = root/'exported.qpa'
                    require(exported.stat().st_mode & 0o777 == 0o600, 'exported receipt mode')
                    ref.validate_signed_response(base, {'complete': True, 'hex': exported.read_bytes()[44:].hex()}, args.oracle)
                    peer.records.clear()
                    result = run(prove(['--rpc-wallet', peer.wallet, *endpoint]), timeout=1800)
                    require([method for method, _ in peer.records] == ['getblockchaininfo', 'getwalletinfo',
                            'getaddressinfo', 'signrawtransactionwithwallet'], 'CLI proof used unexpected wallet authority')
                    require(core.state_snapshot(node, wallet['wallet']) == before, 'CLI signing/proving changed funds state')
                else:
                    # Offline native prover has only public .qpr and private
                    # .qpa; the peer is stopped, and RPC OFF has no transport.
                    base['signing_kind'] = 0
                    fixture(base)
                    peer.shutdown()
                    cookie.unlink()
                    delegated_env = {'PATH': os.environ.get('PATH', '/usr/bin:/bin'),
                                     'HOME': str(root/'no-wallet-home'), 'LANG': 'C'}
                    result = run(prove(['--receipt-input', receipt_path]), timeout=1800, env=delegated_env)
                    require(not peer.records, 'offline proving attempted RPC')
                require(json.loads(result.stdout)['proof_mode'] == 'signature-possession', 'proof mode result')
                require(output.read_bytes()[:5] == b'QPE1\x03', 'new public envelope')
                require(all(p in result.stderr for p in (b'Receipt validated', b'building signature circuit',
                        b'committing signature proof', b'proving signature possession')), 'signature proof phase feedback')
                checked = subprocess.run([str(args.proof_verifier), str(request_path), str(output)],
                                         capture_output=True, timeout=1800)
                require(checked.returncode == 0, 'CLI public proof cryptography verification failed')
                count += 1
                proofs += 1
            else:
                created = root/'created.qpr'
                result = run(create())
                summary = json.loads(result.stdout)
                require(summary['audience'] == base['verifier'] and summary['purpose'] == base['purpose'] and
                        summary['network'] == 'regtest' and summary['total_sats'] == sum(c['amount_sats'] for c in base['claims']) and
                        summary['expires_at'] > int(time.time()), 'request summary fields')
                require(created.read_bytes()[:5] == b'QPS1\x03' and created.stat().st_mode & 0o777 == 0o600, 'signature request bytes/permissions')
                expected = copy.deepcopy(base)
                wire = created.read_bytes()
                offset = 10
                for _ in range(2):
                    size = int.from_bytes(wire[offset:offset+2], 'big')
                    offset += 2+size
                expected['nonce'] = wire[offset:offset+32].hex()
                expected['not_before'], expected['expires_at'] = summary['request_created_at'], summary['expires_at']
                expected['bip322_message_hash'] = ref.tagged('BIP0322-signed-message', b'CLI delegation').hex()
                require(wire == ref.request_bytes(expected), 'CLI canonical request differs from independent reference')
                witness_request = root/'wpkh.qpr'
                run(create(kind=0, target=witness_request))
                require(witness_request.read_bytes()[9] == 0, 'selected witness signing kind was not encoded')
                run(create(), 74)
                run(create(extra=['--proof-mode', 'signature-possession']), 64)
                old = root/'scalar.qpr'
                scalar = ['challenge', 'create', '--network', 'regtest', '--output', old, *claim_options(base)]
                run(scalar)
                require(old.read_bytes()[4] == 2, 'typed key-knowledge default changed')
                run(['prove', *mode, '--request', old, '--output', output, '--receipt-input', receipt_path], 65)
                run(['prove', '--request', request_path, '--output', output], 66)
                run(prove(), 64)
                run(prove(['--receipt-input', receipt_path, '--rpc-wallet', peer.wallet]), 64)
                run(prove(['--receipt-input', receipt_path, *endpoint]), 64)
                run(prove(['--receipt-input', receipt_path, '--network', 'signet']), 65)
                if args.rpc == 'ON':
                    exported = root/'exported.qpa'
                    result = run(authorize())
                    require(json.loads(result.stdout)['private'] is True and exported.read_bytes() == receipt_path.read_bytes(), 'receipt export mismatch')
                    require(exported.stat().st_mode & 0o777 == 0o600, 'private export permissions')
                    run(authorize(), 74)
                    for key in ('audience', 'purpose', 'network', 'total_sats', 'expires_at'):
                        require(('"'+key+'"').encode() in result.stderr, 'missing authorisation display field')
                    peer.scenario = 'missing-key'
                    run(authorize(root/'missing-key.qpa'), 65)
                    peer.scenario = 'ok'
                    peer.result = {'complete': False, 'hex': peer.result['hex']}
                    run(authorize(root/'incomplete.qpa'), 65)
                    fixture(base)
                    for sig in (signal.SIGINT, signal.SIGTERM):
                        peer.scenario = 'timeout'
                        peer.records.clear()
                        child = subprocess.Popen([str(args.cli), *map(str, authorize(root/'interrupted.qpa'))], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                        try:
                            deadline = time.monotonic() + 5
                            while not peer.records and child.poll() is None and time.monotonic() < deadline:
                                time.sleep(0.01)
                            require(peer.records, 'interruption RPC gate was not reached')
                            child.send_signal(sig)
                            child.communicate(timeout=5)
                            require(child.returncode == -sig, 'interrupted signer did not settle')
                            count += 1
                            require(not (root/'interrupted.qpa').exists() and not list(root.glob('*.tmp.*')), 'interruption left partial receipt')
                        finally:
                            if child.poll() is None:
                                child.kill(); child.communicate(timeout=5)
                        time.sleep(0.2) # Settle the bounded delayed peer before changing its fixture.
                    while time.time() % 1 < 0.8:
                        time.sleep(0.01)
                    expiring = copy.deepcopy(base)
                    expiring['expires_at'] = int(time.time()) + 1
                    fixture(expiring)
                    peer.scenario = 'timeout'
                    run(authorize(root/'expired-during-signing.qpa'), 65)
                    require(not (root/'expired-during-signing.qpa').exists(), 'expired authorisation exported')
                    fixture(base)
                else:
                    run(authorize(), 64)
                for permissions in (0o644, 0o640, 0o606):
                    receipt_path.chmod(permissions)
                    run(prove(['--receipt-input', receipt_path]), 74)
                receipt_path.chmod(0o600)
                symlink = root/'symlink.qpa'
                symlink.symlink_to(receipt_path)
                fifo = root/'fifo.qpa'
                os.mkfifo(fifo, 0o600)
                oversized = root/'large.qpa'
                oversized.write_bytes(b'QPA1'+b'x'*4093); oversized.chmod(0o600)
                for path in (symlink, fifo, root, root/'missing.qpa', oversized):
                    run(prove(['--receipt-input', path]), 74)
                bad = bytearray(receipt_path.read_bytes()); bad[8] ^= 1
                receipt_path.write_bytes(bad)
                run(prove(['--receipt-input', receipt_path]), 65)
                require(not output.exists(), 'invalid receipt produced proof')
                fixture(base)
                for expiry in (int(time.time()) - 1, int(time.time()) + 7200):
                    changed = copy.deepcopy(base)
                    if expiry < time.time():
                        changed['expires_at'] = expiry
                    else:
                        changed['not_before'], changed['expires_at'] = expiry, expiry+3600
                    fixture(changed)
                    run(prove(['--receipt-input', receipt_path]), 65)
                    if args.rpc == 'ON':
                        run(authorize(root/'expired.qpa'), 65)
                    require(not peer.records, 'invalid validity window reached wallet')
                fixture(base)
                if args.fault:
                    for fault, expected in [('io',74), ('race',74), ('term',-signal.SIGTERM), ('int',-signal.SIGINT)]:
                        target = root/f'{fault}.qpr'
                        env = dict(os.environ, LD_PRELOAD=str(args.fault), QUIETPROOF_TEST_FILE_FAULT=fault)
                        run(create(target=target), expected, env=env)
                        require(target.read_bytes() == b'retained' if fault == 'race' else not target.exists(), 'fault output cleanup/replacement failure')
                # Interrupt after the real prover announces its first phase;
                # no witness appears in argv, stdin, diagnostics or temp files.
                child = subprocess.Popen([str(args.cli), *map(str, prove(['--receipt-input', receipt_path]))],
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
                try:
                    deadline = time.monotonic()+10
                    announced = False
                    import select
                    while child.poll() is None and time.monotonic() < deadline:
                        if select.select([child.stderr], [], [], 0.1)[0]:
                            line = child.stderr.readline()
                            if b'building signature circuit' in line:
                                announced = True; break
                    require(announced, 'proof interruption phase was not reached')
                    child.terminate(); child.communicate(timeout=5)
                    require(child.returncode == -signal.SIGTERM and not output.exists() and not list(root.glob('*.tmp.*')), 'proof interruption cleanup failed')
                    count += 1
                finally:
                    if child.poll() is None:
                        child.kill(); child.communicate(timeout=5)
        finally:
            peer.shutdown()
            peer.server_close()
            thread.join(timeout=2)
            if node is not None:
                node.close()
    print(json.dumps({'executed': count, 'failed': 0, 'skipped': 0, 'total': count, 'proofs_verified': proofs,
                      'disabled': args.disabled, 'rpc': args.rpc, 'core': bool(args.core32)}, sort_keys=True))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        print('signature CLI qualification failed; private diagnostics suppressed', file=sys.stderr)
        if isinstance(error, RuntimeError):
            print(str(error), file=sys.stderr)
        raise SystemExit(1)
