#!/usr/bin/env python3
"""Build, install, and consume the optional package in isolated build trees."""
import argparse
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--prefix-path', default='')
    parser.add_argument('--generator', default='Ninja')
    parser.add_argument('--curl-static', action='store_true')
    parser.add_argument('--rpc-enabled', choices=('ON', 'OFF'), default='ON')
    args = parser.parse_args()
    args.work.mkdir(parents=True, exist_ok=True)
    checks = 0
    curl_options = []
    if args.curl_static:
        # Use a curl package exporting an archive and its dependency closure.
        # The consumer asserts actual .a selection: older FindCURL modules can
        # otherwise silently select a shared library despite this option.
        curl_options = ['-DCURL_USE_STATIC_LIBS=TRUE']

    def run(name, command, expect_failure=None):
        nonlocal checks
        result = subprocess.run(command, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, timeout=240)
        (args.work / (name + '.log')).write_text(result.stdout)
        if expect_failure is None:
            if result.returncode:
                raise RuntimeError(f'{name} failed; see {args.work / (name + ".log")}')
        elif not result.returncode or expect_failure not in ' '.join(result.stdout.split()):
            raise RuntimeError(f'{name} did not reject as expected; see log')
        checks += 1

    launcher = []
    # Preserve a caller's explicit launcher; otherwise use available ccache.
    import shutil
    if os.environ.get('CMAKE_CXX_COMPILER_LAUNCHER'):
        launcher = ['-DCMAKE_CXX_COMPILER_LAUNCHER=' +
                    os.environ['CMAKE_CXX_COMPILER_LAUNCHER']]
    elif shutil.which('ccache'):
        launcher = ['-DCMAKE_CXX_COMPILER_LAUNCHER=ccache']

    modes = (False, True) if args.rpc_enabled == 'ON' else (False,)
    for enabled in modes:
        mode = 'on' if enabled else 'off'
        build = args.work / ('build-' + mode)
        install = args.work / ('install-' + mode)
        configure = ['cmake', '-S', str(args.source), '-B', str(build),
                     '-G', args.generator, '-DCMAKE_BUILD_TYPE=Release',
                     '-DBUILD_TESTING=OFF',
                     '-DCMAKE_PREFIX_PATH=' + args.prefix_path,
                     '-DCMAKE_INSTALL_PREFIX=' + str(install),
                     '-DQUIETPROOF_BUILD_RPC=' + mode.upper()] + launcher
        if not enabled:
            configure += ['-DCMAKE_DISABLE_FIND_PACKAGE_CURL=TRUE']
        elif args.curl_static:
            configure += curl_options
        run('configure-' + mode, configure)
        run('build-' + mode, ['cmake', '--build', str(build), '--parallel', '2'])
        run('install-' + mode, ['cmake', '--install', str(build)])
        prefixes = str(install) + ';' + args.prefix_path
        core = args.work / ('core-' + mode)
        run('core-configure-' + mode, [
            'cmake', '-S', str(args.source / 'tests/cmake/core-consumer'),
            '-B', str(core), '-G', args.generator,
            '-DCMAKE_PREFIX_PATH=' + prefixes,
            '-DCMAKE_DISABLE_FIND_PACKAGE_CURL=TRUE'] + launcher)
        run('core-build-' + mode, ['cmake', '--build', str(core), '--parallel', '2'])
        run('core-run-' + mode, [str(core / 'core-consumer')])
        rpc = args.work / ('rpc-' + mode)
        rpc_configure = ['cmake', '-S', str(args.source / 'tests/cmake/rpc-consumer'),
                         '-B', str(rpc), '-G', args.generator,
                         '-DCMAKE_BUILD_TYPE=Release',
                         '-DINSTALLED_RPC_EXAMPLE=' + str(install / 'share/doc/LongfellowZKQuietProof/examples/bitcoin_rpc.cc'),
                         '-DCMAKE_PREFIX_PATH=' + prefixes] + launcher
        if args.curl_static:
            rpc_configure += curl_options + ['-DEXPECT_STATIC_CURL=TRUE']
        run('rpc-configure-' + mode, rpc_configure,
            expect_failure=None if enabled else 'built without the rpc component')
        if enabled:
            run('rpc-build', ['cmake', '--build', str(rpc), '--parallel', '2'])
            run('rpc-run', [str(rpc / 'rpc-consumer')])
            run('example-fixture', [os.sys.executable,
                str(args.source / 'tests/quietproof/rpc_http_fixture.py'),
                str(rpc / 'bitcoin-rpc-example'), '--example'])
    print(f'Package matrix passed: {checks} checks (RPC {args.rpc_enabled}, core isolation, component consumption)')


if __name__ == '__main__':
    main()
