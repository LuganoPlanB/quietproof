#!/usr/bin/env python3
"""Install hash-pinned Core 32.1 binaries and test-only oracle source in a new directory."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import tempfile
import urllib.request


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--archives', type=Path, help='Existing directory containing both pinned archives')
    args = parser.parse_args()
    pins = json.loads(Path(__file__).with_name('core32-pins.json').read_text())
    destination = args.destination.resolve()
    if destination.exists():
        parser.error('destination must not exist; existing installations are never overwritten')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='quietproof-core32-', dir=destination.parent) as temporary:
        temporary = Path(temporary)
        archives = []
        for name, expected in pins['archives'].items():
            archive = args.archives / name if args.archives else temporary / name
            if not args.archives:
                with urllib.request.urlopen(pins['baseUrl'] + name, timeout=120) as response, archive.open('wb') as stream:
                    shutil.copyfileobj(response, stream)
            with archive.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != expected:
                    parser.error(f'Core archive SHA256 mismatch: {name}; nothing installed')
            archives.append(archive)
        # Authenticate both archives before extracting either. No node is started.
        stage = temporary / 'install'
        for archive, folder in zip(archives, ['binary', 'source']):
            with tarfile.open(archive) as bundle:
                bundle.extractall(stage / folder, filter='data')
        if not (stage / 'binary/bitcoin-32.1/bin/bitcoind').is_file() or not (
                stage / 'source/bitcoin-32.1/src/secp256k1/CMakeLists.txt').is_file():
            parser.error('unexpected Core archive layout')
        (stage / 'quietproof-install.json').write_text(json.dumps(pins, sort_keys=True, indent=2) + '\n')
        stage.rename(destination)
    print(f'Installed pinned Core {pins["version"]} binaries and test-only source; no node started')


if __name__ == '__main__':
    main()
