#!/usr/bin/env python3
"""Check host separation and fail-closed cross-build configuration contracts."""
import argparse
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cross-work', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--native-prefix', type=Path, required=True)
    parser.add_argument('--wasi-sdk', type=Path, default=Path('/opt/wasi-sdk'))
    args = parser.parse_args()
    source = Path(__file__).resolve().parents[2]
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    cross = args.cross_work.resolve()
    passed = 0

    def run(name, command, failure=None):
        nonlocal passed
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=240)
        (work / f'{name}.log').write_text(result.stdout)
        if failure is None:
            assert result.returncode == 0, f'{name}: see {work / (name + ".log")}'
        else:
            assert result.returncode != 0 and failure in ' '.join(result.stdout.split()), name
        passed += 1

    run('library-configure', ['cmake', '-S', str(source), '-B', str(work / 'library'),
        '-G', 'Ninja', '-DBUILD_TESTING=OFF', '-DQUIETPROOF_BUILD_CLI=OFF',
        '-DQUIETPROOF_BUILD_RPC=OFF', '-DCMAKE_DISABLE_FIND_PACKAGE_Threads=TRUE',
        '-DCMAKE_DISABLE_FIND_PACKAGE_CURL=TRUE',
        f'-DCMAKE_PREFIX_PATH={args.native_prefix.resolve()}'])
    run('library-build', ['cmake', '--build', str(work / 'library')])
    run('library-install', ['cmake', '--install', str(work / 'library'),
                            '--prefix', str(work / 'library-prefix')])
    assert not (work / 'library/quietproof').exists()
    assert not (work / 'library-prefix/bin/quietproof').exists()
    for option in ['QUIETPROOF_BUILD_CLI', 'QUIETPROOF_BUILD_RPC', 'BUILD_TESTING']:
        run(option, ['cmake', '-S', str(source), '-B', str(work / option),
            f'-DCMAKE_TOOLCHAIN_FILE={source / "cmake/toolchains/wasi.cmake"}',
            f'-DWASI_SDK_PATH={args.wasi_sdk.resolve()}', f'-D{option}=ON'],
            failure='WASI requires')
    run('native-reactor-rejected', ['cmake', '-S', str(source),
        '-B', str(work / 'native-reactor'), '-DQUIETPROOF_BUILD_WASM=ON'],
        failure='QUIETPROOF_BUILD_WASM requires')
    run('surface', ['node', str(source / 'scripts/inspect_wasm.mjs'),
                    str(cross / 'quietproof-build/quietproof.wasm')])
    # Required package searches would fail here, even on hosts with native
    # CURL/Threads available. The existing cross cache retains WASI roots.
    run('cross-no-host-deps', ['cmake', '-S', str(source),
        '-B', str(cross / 'quietproof-build'),
        '-DCMAKE_DISABLE_FIND_PACKAGE_Threads=TRUE',
        '-DCMAKE_DISABLE_FIND_PACKAGE_CURL=TRUE'])
    ninja = (cross / 'quietproof-build/build.ninja').read_text()
    assert 'quietproof_main.cc' not in ninja
    assert 'bitcoin_rpc.cc' not in ninja
    assert str(cross / 'sdk-prefix/lib/liblongfellow-zk.a') in ninja
    rules = (cross / 'quietproof-build/CMakeFiles/rules.ninja').read_text()
    assert '--target=wasm32-wasip1' in rules
    # Verify the installed archive actually contains WebAssembly object code.
    archive = cross / 'sdk-prefix/lib/liblongfellow-zk.a'
    ar = str(args.wasi_sdk / 'bin/llvm-ar')
    member = subprocess.check_output([ar, 't', str(archive)], text=True).splitlines()[0]
    obj = subprocess.check_output([ar, 'p', str(archive), member])
    assert obj[:4] == b'\0asm', 'native object contamination'
    passed += 1
    print(f'{passed} build contract checks passed; 0 failed')


if __name__ == '__main__':
    main()
