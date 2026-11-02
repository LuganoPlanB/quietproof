#!/usr/bin/env python3
"""Run the independent PoSC model with Sage 10.6 or the pinned official image."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
IMAGE = 'docker.io/sagemath/sagemath@sha256:19995db6194f4a4bab18ce9a88556fd15b9ed5e916b4504fefe618a7796ddbdb'
FIXTURE = 'tests/quietproof/testdata/posc_sage_vectors.json'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--emit', action='store_true', help='Emit fresh public vectors instead of checking the committed fixture')
    args = parser.parse_args()
    model = ['-python', 'spec/posc_reference.sage']
    model += ['--emit'] if args.emit else ['--check', FIXTURE]
    configured = os.environ.get('POSC_SAGE_BIN')
    if configured and not os.access(configured, os.X_OK):
        parser.error('POSC_SAGE_BIN must be an executable SageMath 10.6 installation')
    executable = configured or shutil.which('sage')
    if executable:
        result = subprocess.run([executable, '--version'], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.startswith('SageMath version 10.6,'):
            return subprocess.call([executable, *model], cwd=ROOT)
        if configured:
            parser.error('POSC_SAGE_BIN must be an executable SageMath 10.6 installation')
    if not shutil.which('docker'):
        parser.error('SageMath 10.6 or Docker is required; no mathematical checks were run')
    return subprocess.call(['docker', 'run', '--rm', '--platform', 'linux/amd64',
        '--network', 'none', '--read-only', '--env', 'HOME=/tmp',
        '--tmpfs', '/tmp:rw,nosuid,nodev,noexec,size=64m',
        '--volume', str(ROOT) + ':/workspace:ro', '--workdir', '/workspace',
        IMAGE, 'sage', *model])


if __name__ == '__main__':
    sys.exit(main())
