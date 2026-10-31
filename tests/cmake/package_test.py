#!/usr/bin/env python3
"""Install isolated packages and exercise explicit optional components."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--prefix-path', default='')
    parser.add_argument('--generator', default='Ninja')
    parser.add_argument('--curl-static', action='store_true')
    parser.add_argument('--rpc-enabled', choices=('ON', 'OFF'), default='ON')
    parser.add_argument('--signature-enabled', choices=('ON', 'OFF'), default='OFF')
    args = parser.parse_args()
    args.source, args.work = args.source.resolve(), args.work.resolve()
    args.work.mkdir(parents=True, exist_ok=True)
    checks, commands = [], []

    def record():
        (args.work / 'results.json').write_text(json.dumps(
            {'commands': commands, 'checks': checks}, indent=2) + '\n')

    def check(name, condition):
        checks.append({'name': name, 'passed': bool(condition)})
        record()
        if not condition:
            raise RuntimeError(name)

    def run(name, command, expect_failure=None):
        started = datetime.now(timezone.utc).isoformat()
        result = subprocess.run([str(x) for x in command], cwd=args.source,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, timeout=240)
        log = args.work / (name + '.log')
        log.write_text(result.stdout)
        passed = (result.returncode == 0 if expect_failure is None else
                  result.returncode != 0 and expect_failure in ' '.join(result.stdout.split()))
        commands.append({'name': name, 'command': [str(x) for x in command],
                         'cwd': str(args.source), 'startedUTC': started,
                         'endedUTC': datetime.now(timezone.utc).isoformat(),
                         'exit': result.returncode, 'expectedFailure': expect_failure,
                         'passed': passed, 'log': str(log),
                         'sha256': hashlib.sha256(log.read_bytes()).hexdigest()})
        record()
        if not passed:
            raise RuntimeError(f'{name} failed; see {log}')

    launcher = []
    if os.environ.get('CMAKE_CXX_COMPILER_LAUNCHER'):
        launcher = ['-DCMAKE_CXX_COMPILER_LAUNCHER=' + os.environ['CMAKE_CXX_COMPILER_LAUNCHER']]
    elif shutil.which('ccache'):
        launcher = ['-DCMAKE_CXX_COMPILER_LAUNCHER=ccache']
    # Registries must not rescue a missing component or dependency. These two
    # packages are deliberately unavailable even for signature-enabled builds.
    isolated = ['-DCMAKE_FIND_USE_PACKAGE_REGISTRY=OFF',
                '-DCMAKE_FIND_USE_SYSTEM_PACKAGE_REGISTRY=OFF',
                '-DCMAKE_EXPORT_NO_PACKAGE_REGISTRY=ON',
                '-DCMAKE_DISABLE_FIND_PACKAGE_LongfellowZKECDSA=TRUE',
                '-DCMAKE_DISABLE_FIND_PACKAGE_libsecp256k1=TRUE']
    common = ['-G', args.generator, '-DCMAKE_BUILD_TYPE=Release'] + isolated + launcher
    curl_options = ['-DCURL_USE_STATIC_LIBS=TRUE'] if args.curl_static else []
    rpc_modes = (False, True) if args.rpc_enabled == 'ON' else (False,)
    signature_modes = (False, True) if args.signature_enabled == 'ON' else (False,)
    installations = {}
    package_relative = Path('lib/cmake/LongfellowZKQuietProof')
    signature_export = 'LongfellowZKQuietProofSignatureTargets.cmake'
    header_relative = Path('include/longfellow-zk-quietproof/circuit')

    def consumer(name, kind, install, extra=(), expected=None):
        build = args.work / name
        run(name + '-configure', ['cmake', '-S', args.source / 'tests/cmake' / kind,
            '-B', build, *common, '-DCMAKE_PREFIX_PATH=' + str(install) + ';' + args.prefix_path,
            '-DLongfellowZKQuietProof_DIR=' + str(install / package_relative), *extra], expected)
        if expected is None:
            run(name + '-build', ['cmake', '--build', build, '--parallel', '2'])
            run(name + '-run', [build / kind])
        return build

    for signature in signature_modes:
        for rpc in rpc_modes:
            mode = f'rpc-{int(rpc)}-signature-{int(signature)}'
            build, install = args.work / ('build-' + mode), args.work / ('install-' + mode)
            options = ['-DQUIETPROOF_BUILD_RPC=' + ('ON' if rpc else 'OFF')]
            # Omission checks the ordinary default. Fresh work trees make this
            # independent of an earlier ON cache; CTest reuses the same mode.
            if signature:
                options += ['-DQUIETPROOF_BUILD_SIGNATURE_MODE=ON']
            if rpc:
                options += curl_options
            else:
                options += ['-DCMAKE_DISABLE_FIND_PACKAGE_CURL=TRUE']
            run(mode + '-configure', ['cmake', '-S', args.source, '-B', build, *common,
                '-DBUILD_TESTING=OFF', '-DCMAKE_INSTALL_LIBDIR=lib',
                '-DCMAKE_PREFIX_PATH=' + args.prefix_path,
                '-DCMAKE_INSTALL_PREFIX=' + str(install), *options])
            cache = (build / 'CMakeCache.txt').read_text()
            check(mode + '-capability-cache',
                  'QUIETPROOF_BUILD_SIGNATURE_MODE:BOOL=' + ('ON' if signature else 'OFF') in cache)
            run(mode + '-build', ['cmake', '--build', build, '--parallel', '2'])
            run(mode + '-install', ['cmake', '--install', build])
            installations[(rpc, signature)] = install
            for name in ('bitcoin_ecdsa.h', 'bitcoin_ecdsa_witness.h', 'signature_possession.h',
                         'signature_possession_circuit.h', 'signature_possession_witness.h'):
                check(mode + '-header-' + name, (install / header_relative / name).exists() == signature)
            check(mode + '-export', (install / package_relative / signature_export).exists() == signature)
            exports = '\n'.join(p.read_text() for p in (install / package_relative).glob('*.cmake'))
            check(mode + '-no-oracle-export', not any(token in exports for token in
                  ('LongfellowZKECDSA', 'libsecp256k1', 'signing-oracle')))
            check(mode + '-no-oracle-install', not any('oracle' in p.name or 'secp256k1' in p.name
                  for p in install.rglob('*') if p.is_file()))
            consumer('core-' + mode, 'core-consumer', install,
                     ['-DCMAKE_DISABLE_FIND_PACKAGE_CURL=TRUE'])
            rpc_build = consumer('rpc-' + mode, 'rpc-consumer', install,
                ['-DRPC_API_DRIVER_SOURCE=' + str(args.source / 'tests/quietproof/rpc_api_driver.cc'),
                 *curl_options, *(['-DEXPECT_STATIC_CURL=TRUE'] if args.curl_static else [])],
                None if rpc else 'built without the rpc component')
            if rpc:
                run('api-fixture-' + mode, [os.sys.executable,
                    args.source / 'tests/quietproof/rpc_http_fixture.py',
                    rpc_build / 'quietproof-rpc-api-driver', '--api-driver'])
            consumer('signature-' + mode, 'signature-consumer', install,
                     ['-DCMAKE_DISABLE_FIND_PACKAGE_CURL=TRUE'],
                     None if signature else 'built without the signature component')
            if signature and rpc:
                consumer('combined-' + mode, 'signature-consumer', install,
                         ['-DWITH_RPC=ON', *curl_options])

    probe_source = args.work / 'component-probe'
    probe_source.mkdir(exist_ok=True)
    (probe_source / 'CMakeLists.txt').write_text(
        'cmake_minimum_required(VERSION 3.20)\nproject(ComponentProbe LANGUAGES CXX)\n'
        'if(OPTIONAL_COMPONENT)\n'
        '  find_package(LongfellowZKQuietProof CONFIG REQUIRED OPTIONAL_COMPONENTS ${COMPONENT})\n'
        '  if(LongfellowZKQuietProof_${COMPONENT}_FOUND)\n'
        '    message(FATAL_ERROR "Unavailable optional component reported present")\n'
        '  endif()\nelse()\n'
        '  find_package(LongfellowZKQuietProof CONFIG REQUIRED COMPONENTS ${COMPONENT})\n'
        'endif()\n')

    def probe(name, install, component, expected, extra=()):
        run(name, ['cmake', '-S', probe_source, '-B', args.work / name, *common,
            '-DLongfellowZKQuietProof_DIR=' + str(install / package_relative),
            '-DCMAKE_PREFIX_PATH=' + str(install) + ';' + args.prefix_path,
            '-DCOMPONENT=' + component, *extra], expected)

    off = installations[(False, False)]
    probe('unknown-component', off, 'unknown', 'Unknown LongfellowZKQuietProof component: unknown')
    probe('optional-unavailable', off, 'signature', None, ['-DOPTIONAL_COMPONENT=ON'])
    probe('missing-base-sdk', off, '', 'CMAKE_DISABLE_FIND_PACKAGE_LongfellowZK is enabled',
          ['-DCMAKE_DISABLE_FIND_PACKAGE_LongfellowZK=TRUE'])
    if args.signature_enabled == 'ON':
        on = installations[(False, True)]
        probe('signature-missing-base-sdk', on, 'signature', 'CMAKE_DISABLE_FIND_PACKAGE_LongfellowZK is enabled',
              ['-DCMAKE_DISABLE_FIND_PACKAGE_LongfellowZK=TRUE'])
        # A later prefix containing the ON package cannot rescue the selected
        # OFF package, even with a leftover export from an earlier installation.
        stale = args.work / 'stale-off'
        shutil.copytree(off, stale, dirs_exist_ok=True)
        shutil.copy2(on / package_relative / signature_export, stale / package_relative / signature_export)
        probe('stale-export-off', stale, 'signature', 'built without the signature component',
              ['-DCMAKE_PREFIX_PATH=' + str(stale) + ';' + str(on) + ';' + args.prefix_path])
        removed = args.work / 'removed-signature'
        shutil.copytree(on, removed, dirs_exist_ok=True)
        (removed / package_relative / signature_export).unlink()
        for name in ('bitcoin_ecdsa.h', 'bitcoin_ecdsa_witness.h', 'signature_possession.h',
                     'signature_possession_circuit.h', 'signature_possession_witness.h'):
            (removed / header_relative / name).unlink()
        consumer('core-after-signature-removal', 'core-consumer', removed,
                 ['-DCMAKE_DISABLE_FIND_PACKAGE_CURL=TRUE'])
        probe('removed-signature-required', removed, 'signature', 'its export was removed')
    if args.rpc_enabled == 'ON':
        probe('rpc-missing-curl', installations[(True, False)], 'rpc', 'CMAKE_DISABLE_FIND_PACKAGE_CURL is enabled',
              ['-DCMAKE_DISABLE_FIND_PACKAGE_CURL=TRUE'])
    print(f'Package matrix passed: {len(commands)} commands, {len(checks)} checks, '
          f'{len(installations)} installations; 0 failed, 0 skipped')


if __name__ == '__main__':
    main()
