#!/usr/bin/env python3
"""Check host separation and fail-closed cross-build configuration contracts."""
import argparse
import json
import os
from pathlib import Path
import shlex
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

    def run(name, command, failure=None, env=None):
        nonlocal passed
        result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=240, env=env)
        (work / f'{name}.log').write_text(result.stdout)
        if failure is None:
            assert result.returncode == 0, f'{name}: see {work / (name + ".log")}'
        else:
            assert result.returncode != 0 and failure in ' '.join(result.stdout.split()), name
        passed += 1

    # A working /opt installation can hide a lost -DWASI_SDK_PATH during
    # compiler checks. Inspect real nested probes through a distinct SDK path.
    sdk = work / 'custom-sdk'
    if not sdk.exists():
        sdk.symlink_to(args.wasi_sdk.resolve(), target_is_directory=True)
    assert sdk.is_symlink() and sdk.resolve() == args.wasi_sdk.resolve()
    probe = work / 'custom-sdk-source'
    probe.mkdir(exist_ok=True)
    (probe / 'CMakeLists.txt').write_text('''cmake_minimum_required(VERSION 3.20)
project(CustomSdkProbe LANGUAGES CXX)
try_compile(CUSTOM_SDK_FEATURE_WORKS "${CMAKE_BINARY_DIR}/feature-probe"
    "${CMAKE_CURRENT_SOURCE_DIR}/probe.cc")
if(NOT CUSTOM_SDK_FEATURE_WORKS)
    message(FATAL_ERROR "WASI C++ feature probe failed")
endif()
''')
    (probe / 'probe.cc').write_text('''#include <vector>
#ifndef __wasi__
#error Expected a WASI compiler
#endif
static_assert(sizeof(void*) == 4);
int main() { std::vector<int> values(1); return values.front(); }
''')
    probe_build = work / 'custom-sdk-build'
    probe_env = {k: v for k, v in os.environ.items()
                 if k not in ('WASI_SDK_PATH', 'WASI_SDK_PREFIX')}
    run('custom-sdk-try-compile', ['cmake', '--debug-trycompile', '-S', str(probe),
        '-B', str(probe_build), '-G', 'Ninja',
        f'-DCMAKE_TOOLCHAIN_FILE={source / "cmake/toolchains/wasi.cmake"}',
        f'-DWASI_SDK_PATH={sdk}',
        '-DCMAKE_TRY_COMPILE_PLATFORM_VARIABLES=QUIETPROOF_SDK_PROBE_SENTINEL',
        '-DQUIETPROOF_SDK_PROBE_SENTINEL:STRING=preserved'], env=probe_env)
    # An explicit feature-probe directory also keeps its cache separate from
    # compiler ABI probes on CMake versions predating CMakeScratch directories.
    nested = sorted(p for p in probe_build.rglob('CMakeCache.txt')
                    if p.parent != probe_build)
    assert len(nested) >= 2, 'compiler ABI and explicit feature probes must execute'
    observations = []
    for cache in nested:
        values = {line.split(':', 1)[0]: line.split('=', 1)[1]
                  for line in cache.read_text().splitlines()
                  if line and not line.startswith(('#', '//')) and '=' in line}
        # Ask Ninja to expand its launcher placeholders into actual commands;
        # generated probe caches do not necessarily cache the compiler.
        commands = subprocess.check_output(
            ['ninja', '-C', str(cache.parent), '-t', 'commands'], text=True)
        tokens = [token for line in commands.splitlines() for token in shlex.split(line)]
        compilers = [token for token in tokens
                     if Path(token).name == 'clang++']
        sysroots = [token.split('=', 1)[1] for token in tokens
                    if token.startswith('--sysroot=')]
        assert compilers, 'nested probe must compile with the WASI C++ compiler'
        observations.append({'cache': str(cache), 'sdk': values.get('WASI_SDK_PATH'),
                             'compilers': compilers,
                             'sysroots': sysroots,
                             'sentinel': values.get('QUIETPROOF_SDK_PROBE_SENTINEL')})
    (work / 'custom-sdk-probes.json').write_text(
        json.dumps(observations, sort_keys=True, indent=2) + '\n')
    for observation in observations:
        assert observation['sdk'] == str(sdk), (
            f'nested probe lost configured SDK: {observation}')
        assert all(Path(compiler).resolve() == (args.wasi_sdk / 'bin/clang++').resolve()
                   for compiler in observation['compilers']), observation
        assert observation['sysroots'] and all(
            Path(root).resolve() == (args.wasi_sdk / 'share/wasi-sysroot').resolve()
            for root in observation['sysroots']), observation
        assert observation['sentinel'] == 'preserved', observation

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
