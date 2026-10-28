#!/usr/bin/env python3
"""Build, test and package the Linux x86_64 release using dyne/musl-action's toolchain."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def run(*args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def output(*args):
    return subprocess.check_output([str(arg) for arg in args], text=True).strip()


def verify_binary(binary):
    header = output('readelf', '-h', binary)
    if 'ELF64' not in header or 'Advanced Micro Devices X86-64' not in header:
        raise RuntimeError('Release binary must be ELF64 x86_64')
    if 'INTERP' in output('readelf', '-l', binary):
        raise RuntimeError('Release binary has a dynamic interpreter')
    if '(NEEDED)' in output('readelf', '-d', binary):
        raise RuntimeError('Release binary depends on shared libraries')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--sdk-source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', args.version):
        parser.error('--version must be a stable semantic version without v')
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    sdk, work, destination = args.sdk_source.resolve(), args.work.resolve(), args.output.resolve()
    pin = json.loads((ROOT / 'scripts/build-pins.json').read_text())['longfellowCommit']
    if output('git', '-C', sdk, 'rev-parse', 'HEAD') != pin:
        parser.error(f'SDK source must be pinned to {pin}')
    run('git', '-C', sdk, 'diff', '--exit-code', 'HEAD')
    cc = Path(os.environ.get('CC', '/opt/dyne/gcc-musl/bin/x86_64-linux-musl-gcc'))
    cxx = Path(os.environ.get('CXX', '/opt/dyne/gcc-musl/bin/x86_64-linux-musl-g++'))
    if output(cxx, '-dumpmachine') != 'x86_64-linux-musl':
        parser.error('CXX must target x86_64-linux-musl')
    prefix = work / 'sdk-prefix'
    musl = cxx.resolve().parents[2] / 'x86_64-linux-musl'
    common = ['-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release',
              f'-DCMAKE_C_COMPILER={cc}', f'-DCMAKE_CXX_COMPILER={cxx}',
              f'-DCMAKE_FIND_ROOT_PATH={prefix};{musl}',
              '-DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER',
              '-DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY',
              '-DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY',
              '-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=ONLY',
              '-DCMAKE_EXE_LINKER_FLAGS=-static',
              '-DCMAKE_CXX_FLAGS_RELEASE=-O3 -DNDEBUG -fstack-protector-all -D_FORTIFY_SOURCE=2 -fno-strict-overflow']
    if shutil.which('ccache'):
        common += ['-DCMAKE_CXX_COMPILER_LAUNCHER=ccache']
    run('cmake', '-S', sdk, '-B', work / 'sdk-build', *common,
        '-DBUILD_TESTING=OFF', '-DLONGFELLOW_ZK_BUILD_TESTING=OFF',
        f'-DCMAKE_INSTALL_PREFIX={prefix}')
    run('cmake', '--build', work / 'sdk-build', '--target', 'longfellow-zk-static',
        '--parallel', args.jobs)
    # The pinned SDK unconditionally installs its shared library on Linux.
    # Consume only its real static target and source headers in this build;
    # do not build a shared library against the static-only musl runtime.
    package = prefix / 'lib/cmake/LongfellowZK'
    package.mkdir(parents=True, exist_ok=True)
    archive_path = work / 'sdk-build/liblongfellow-zk.a'
    if any(']==]' in str(path) for path in [archive_path, sdk]):
        parser.error('CMake paths cannot contain ]==]')
    (package / 'LongfellowZKConfig.cmake').write_text(
        'add_library(LongfellowZK::static STATIC IMPORTED)\n'
        'set_target_properties(LongfellowZK::static PROPERTIES\n'
        f'  IMPORTED_LOCATION [==[{archive_path}]==]\n'
        f'  INTERFACE_INCLUDE_DIRECTORIES [==[{sdk / "src"}]==]\n'
        '  INTERFACE_COMPILE_FEATURES cxx_std_20)\n')
    build = work / 'quietproof-build'
    run('cmake', '-S', ROOT, '-B', build, *common,
        f'-DCMAKE_PREFIX_PATH={prefix};{musl}', '-DCURL_USE_STATIC_LIBS=TRUE',
        f'-DQUIETPROOF_VERSION={args.version}', '-DBUILD_TESTING=ON',
        '-DQUIETPROOF_BUILD_CLI=ON', '-DQUIETPROOF_BUILD_RPC=ON',
        '-DQUIETPROOF_BUILD_WASM=OFF')
    run('cmake', '--build', build, '--parallel', args.jobs)
    # Package consumers need their own toolchain setup; proof-heavy and live
    # node/browser qualification remain in the separate project release gates.
    run('ctest', '--test-dir', build, '--output-on-failure', '--parallel', args.jobs,
        '-LE', 'proof-heavy', '-E', '^quietproof-package-test$')
    binary = build / 'quietproof'
    verify_binary(binary)
    if output(binary, '--version') != f'QuietProof {args.version}':
        raise RuntimeError('Binary version does not match the release')
    run(binary, '--help', stdout=subprocess.DEVNULL)

    name = f'quietproof-v{args.version}-linux-x86_64-musl'
    stage = work / name
    (stage / 'bin').mkdir(parents=True, exist_ok=True)
    shutil.copy2(binary, stage / 'bin/quietproof')
    for name_in_source in ['COPYING', 'README.md']:
        shutil.copy2(ROOT / name_in_source, stage / name_in_source)
    shutil.copytree(ROOT / 'LICENSES', stage / 'LICENSES', dirs_exist_ok=True)
    shutil.copy2(sdk / 'LICENSE', stage / 'LICENSES/LongfellowZK.txt')
    manifest = {'version': args.version, 'target': 'x86_64-linux-musl',
                'sourceCommit': output('git', '-C', ROOT, 'rev-parse', 'HEAD'),
                'sourceDirty': bool(output('git', '-C', ROOT, 'status', '--porcelain', '--untracked-files=no')),
                'longfellowCommit': pin, 'compiler': output(cxx, '--version').splitlines()[0],
                'rpc': True, 'static': True,
                'binarySha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
    (stage / 'release.json').write_text(json.dumps(manifest, indent=2) + '\n')
    destination.mkdir(parents=True, exist_ok=True)
    archive = destination / f'{name}.tar.gz'
    with tarfile.open(archive, 'w:gz') as bundle:
        bundle.add(stage, arcname=name)
    (destination / f'{name}.tar.gz.sha256').write_text(
        f'{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n')
    print(f'Packaged static release: {archive}')


if __name__ == '__main__':
    main()
