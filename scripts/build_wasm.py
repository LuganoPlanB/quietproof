#!/usr/bin/env python3
"""Cross-build the pinned SDK and Quietproof in separate WASI-only roots."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess

SDK_COMMIT = 'd2b0fc515f8663e38c79a28e8900ce8438e0106e'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-source', type=Path, required=True)
    parser.add_argument('--work-dir', type=Path, required=True)
    parser.add_argument('--wasi-sdk', type=Path,
                        default=Path(os.environ.get('WASI_SDK_PATH', '/opt/wasi-sdk')))
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    source = Path(__file__).resolve().parents[1]
    sdk = args.sdk_source.resolve()
    work = args.work_dir.resolve()
    wasi = args.wasi_sdk.resolve()
    actual = subprocess.check_output(['git', '-C', str(sdk), 'rev-parse', 'HEAD'],
                                     text=True).strip()
    if actual != SDK_COMMIT:
        parser.error(f'SDK must be pinned to {SDK_COMMIT}; found {actual}')
    if subprocess.run(['git', '-C', str(sdk), 'diff', '--quiet', 'HEAD']).returncode:
        parser.error('SDK tracked sources must be clean')
    if not (wasi / 'bin/clang++').is_file():
        parser.error(f'WASI clang++ missing below {wasi}')
    work.mkdir(parents=True, exist_ok=True)
    toolchain = source / 'cmake/toolchains/wasi.cmake'
    prefix = work / 'sdk-prefix'
    common = ['-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DBUILD_TESTING=OFF',
              f'-DCMAKE_TOOLCHAIN_FILE={toolchain}', f'-DWASI_SDK_PATH={wasi}']
    if shutil.which('ccache'):
        common += ['-DCMAKE_CXX_COMPILER_LAUNCHER=ccache']

    def run(*command):
        subprocess.run(command, check=True)

    run('cmake', '-S', str(sdk), '-B', str(work / 'sdk-build'), *common,
        '-DLONGFELLOW_ZK_BUILD_TESTING=OFF', f'-DCMAKE_INSTALL_PREFIX={prefix}')
    run('cmake', '--build', str(work / 'sdk-build'), '--parallel', str(args.jobs))
    run('cmake', '--install', str(work / 'sdk-build'))
    run('cmake', '-S', str(source), '-B', str(work / 'quietproof-build'), *common,
        f'-DCMAKE_PREFIX_PATH={prefix}',
        f'-DCMAKE_FIND_ROOT_PATH={prefix};{wasi / "share/wasi-sysroot"}',
        '-DQUIETPROOF_BUILD_CLI=OFF',
        '-DQUIETPROOF_BUILD_RPC=OFF', '-DQUIETPROOF_BUILD_WASM=ON')
    run('cmake', '--build', str(work / 'quietproof-build'), '--parallel', str(args.jobs))
    run('node', str(source / 'scripts/inspect_wasm.mjs'),
        str(work / 'quietproof-build/quietproof.wasm'))


if __name__ == '__main__':
    main()
