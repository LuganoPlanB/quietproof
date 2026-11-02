#!/usr/bin/env python3
"""Install the checksum-pinned Dyne x86_64 musl toolchain into a new directory."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request

PINS = Path(__file__).with_name('musl-pins.json')


def install(destination, archive=None):
    pins = json.loads(PINS.read_text())
    destination = destination.resolve()
    if destination.exists():
        raise ValueError('destination must not exist; existing installations are never overwritten')
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='quietproof-musl-', dir=destination.parent) as temporary:
        temporary = Path(temporary)
        downloaded = archive or temporary / pins['archive']
        if archive is None:
            with urllib.request.urlopen(pins['url'], timeout=120) as response, downloaded.open('wb') as stream:
                shutil.copyfileobj(response, stream)
        with downloaded.open('rb') as stream:
            if hashlib.file_digest(stream, 'sha256').hexdigest() != pins['sha256']:
                raise ValueError('musl archive SHA256 mismatch; nothing installed')
        extracted = temporary / 'extracted'
        with tarfile.open(downloaded) as bundle:
            bundle.extractall(extracted, filter='data')
        stage = extracted / 'dyne'
        if list(extracted.iterdir()) != [stage] or any(not (stage / name).is_file() for name in [
                'gcc-musl/bin/x86_64-linux-musl-gcc', 'gcc-musl/bin/x86_64-linux-musl-g++',
                'x86_64-linux-musl/include/curl/curl.h', 'x86_64-linux-musl/lib/libcurl.a']):
            raise ValueError('unexpected musl archive layout; nothing installed')
        compiler = stage / 'gcc-musl/bin/x86_64-linux-musl-g++'
        target = subprocess.check_output([compiler, '-dumpmachine'], text=True).strip()
        if target != 'x86_64-linux-musl':
            raise ValueError('unexpected musl compiler target; nothing installed')
        version = subprocess.check_output([compiler, '--version'], text=True).splitlines()[0]
        (stage / 'quietproof-install.json').write_text(json.dumps(
            {**pins, 'target': target, 'compiler': version}, sort_keys=True, indent=2) + '\n')
        stage.rename(destination)
    print(f'Installed Dyne musl {pins["version"]}; SHA256 {pins["sha256"]}; {version}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, required=True)
    parser.add_argument('--archive', type=Path, help='Use an already downloaded archive (checksum still required)')
    args = parser.parse_args()
    try:
        install(args.destination, args.archive)
    except (ValueError, tarfile.TarError) as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
