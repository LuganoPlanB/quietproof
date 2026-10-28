#!/usr/bin/env python3
"""Check a CI site's identity and recorded scope before Pages uploads it."""
import argparse
import hashlib
import json
from pathlib import Path


def validate(directory, sha, base):
    directory = directory.resolve()
    provenance = json.loads((directory / 'build-provenance.json').read_text())
    if provenance['sourceCommit'] != sha or provenance['base'] != base:
        raise ValueError('Artifact source commit or Pages base differs from the selected run')
    if provenance['dirtyReviewBuild']:
        raise ValueError('Cannot deploy an artifact from a dirty review build')
    scope = provenance['qualification']
    if scope['mode'] != 'smoke' or scope['status'] != 'passed':
        raise ValueError('Artifact did not pass fast CI')
    if any(scope[key] is not False for key in [
            'fullBrowserSuite', 'resourceBenchmark', 'nativeProofTests', 'wasmProofVerification']):
        raise ValueError('Unexpected qualification scope for the CI artifact')
    manifest = json.loads((directory / 'asset-manifest.json').read_text())
    if 'build-provenance.json' not in manifest:
        raise ValueError('Artifact manifest does not bind its provenance')
    for name, expected in manifest.items():
        path = (directory / name).resolve()
        if not path.is_relative_to(directory) or not path.is_file():
            raise ValueError(f'Invalid artifact path: {name}')
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError(f'Artifact checksum mismatch: {name}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('sha')
    parser.add_argument('base')
    args = parser.parse_args()
    validate(args.directory, args.sha, args.base)
    print('Checked CI artifact: exact source, base, checksums and fast qualification scope')


if __name__ == '__main__':
    main()
