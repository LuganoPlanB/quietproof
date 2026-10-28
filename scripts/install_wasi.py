#!/usr/bin/env python3
"""Install the checksum-pinned Linux x86_64 WASI SDK into a new directory."""
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
    parser.add_argument('--archive', type=Path, help='Use an already downloaded archive')
    args = parser.parse_args()
    pins = json.loads(Path(__file__).with_name('build-pins.json').read_text())
    destination = args.destination.resolve()
    if destination.exists():
        parser.error('destination must not exist; existing installations are never overwritten')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='quietproof-wasi-', dir=destination.parent) as temporary:
        temporary = Path(temporary)
        archive = args.archive or temporary / pins['wasiArchive']
        if not args.archive:
            with urllib.request.urlopen(pins['wasiUrl'], timeout=120) as response, archive.open('wb') as output:
                shutil.copyfileobj(response, output)
        with archive.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        if digest != pins['wasiSha256']:
            parser.error('WASI SDK archive SHA256 mismatch; nothing installed')
        extracted = temporary / 'extracted'
        with tarfile.open(archive) as bundle:
            bundle.extractall(extracted, filter='data')
        roots = list(extracted.iterdir())
        if len(roots) != 1 or not (roots[0] / 'bin/clang++').is_file():
            parser.error('unexpected WASI SDK archive layout')
        if (roots[0] / 'VERSION').read_text().splitlines()[0] != pins['wasiVersion']:
            parser.error('unexpected WASI SDK version')
        (roots[0] / 'quietproof-install.json').write_text(json.dumps(pins, sort_keys=True, indent=2) + '\n')
        roots[0].rename(destination)
    print(f'Installed WASI SDK {pins["wasiVersion"]}; SHA256 {digest}')


if __name__ == '__main__':
    main()
