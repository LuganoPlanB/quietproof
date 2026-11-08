#!/usr/bin/env python3
"""Opt-in installed Sparrow -> offline Quietproof import integration (no chain claims)."""
import argparse
import base64
import json
from pathlib import Path
import subprocess
import sys
import tempfile

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cli', 'sparrow', 'jdk', 'cache'):
        parser.add_argument('--'+name, type=Path, required=True)
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    commands = 0
    def run(command, expected=0):
        nonlocal commands
        commands += 1
        result = subprocess.run(list(map(str, command)), capture_output=True, timeout=120)
        if result.returncode != expected:
            raise RuntimeError(f'integration operation {commands}: exit {result.returncode}, expected {expected}; private diagnostics suppressed')
        return result
    with tempfile.TemporaryDirectory(prefix='sparrow-import-') as directory:
        work = Path(directory)
        base = [sys.executable, source/'scripts/sparrow_signer.py', '--sparrow', args.sparrow.resolve(),
                '--jdk', args.jdk.resolve(), '--cache', args.cache.resolve(), '--network', 'signet']
        owned = {}
        for kind in ('p2wpkh', 'p2pkh', 'p2tr'):
            wallet = work/kind
            owned[kind] = json.loads(run([*base, 'create', '--wallet-dir', wallet, '--script-kind', kind]).stdout)['address']
        # Decode only this helper's P2WPKH program to construct a disposable
        # offline claim. This is test fixture construction, never production IO.
        alphabet = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'
        digits = owned['p2wpkh'].split('1')[1][1:-6]
        program = int(''.join(f'{alphabet.index(c):05b}' for c in digits), 2).to_bytes(20, 'big')
        claim = '11'*32 + ':0:1000:p2wpkh:' + program.hex()
        request, message = work/'request.qpr', work/'message.txt'
        mode = ['--proof-mode', 'signature-possession']
        run([args.cli, 'challenge', 'create', *mode, '--network', 'signet', '--signing-kind', 'p2wpkh',
             '--claim', claim, '--expires-in', '3600', '--verifier', 'sparrow-integration-test', '--output', request])
        exported = json.loads(run([args.cli, 'signing-material', *mode, '--request', request,
                                  '--address', owned['p2wpkh'], '--output', message]).stdout)
        assert exported['address'] == owned['p2wpkh'] and message.stat().st_size == 88
        def sign(kind, form, name):
            path = work/name
            run([*base, 'sign', '--wallet-dir', work/kind, '--script-kind', kind, '--format', form,
                 '--address', owned[kind], '--message', message, '--output', path])
            return path
        def import_file(path, form, name, expected):
            destination = work/name
            run([args.cli, 'import-signature', *mode, '--request', request, '--network', 'signet',
                 '--signature-input', path, '--signature-format', form, '--receipt-output', destination], expected)
            assert destination.exists() == (expected == 0)
            return destination
        signed = sign('p2wpkh', 'bip322-simple', 'simple.json')
        receipt = import_file(signed, 'sparrow-json', 'simple.qpa', 0)
        raw = work/'simple.txt'
        raw.write_text(json.loads(signed.read_text())['signature']); raw.chmod(0o600)
        assert import_file(raw, 'bip322-simple', 'raw.qpa', 0).read_bytes() == receipt.read_bytes()
        # Retain plausible JSON metadata after signing different bytes: native
        # ECDSA must reject even when assertions have been rewritten to agree.
        message.write_bytes(message.read_bytes()+b'\n')
        changed = sign('p2wpkh', 'bip322-simple', 'newline.json')
        wrapper = json.loads(changed.read_text())
        wrapper['messageSha256'] = json.loads(signed.read_text())['messageSha256']
        changed.write_text(json.dumps(wrapper))
        import_file(changed, 'sparrow-json', 'bad-newline.qpa', 65)
        for form in ('standard', 'electrum', 'bip137'):
            compact = sign('p2pkh', form, form+'.json')
            # Unsupported encoding is explicit; a P2WPKH request also rejects
            # mismatched P2PKH metadata before considering the scheme.
            raw.write_text(json.loads(compact.read_text())['signature'])
            import_file(raw, form, form+'.qpa', 66)
        # Bundled Schnorr production is independently observed; the existing
        # ECDSA profile rejects its one-item witness as malformed.
        taproot = sign('p2tr', 'bip322-simple', 'taproot.json')
        witness = json.loads(taproot.read_text())['signature']
        assert base64.b64decode(witness[3:], validate=True)[0] == 1
        raw.write_text(witness)
        import_file(raw, 'bip322-simple', 'taproot.qpa', 65)
    print(f'{commands} installed Sparrow/offline import operations passed; P2WPKH success, legacy/P2TR rejected; no chain verification claimed')


if __name__ == '__main__':
    main()
