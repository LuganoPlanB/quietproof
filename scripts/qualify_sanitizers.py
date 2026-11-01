#!/usr/bin/env python3
"""Run signature parsers and the prior independent arithmetic corpus with ASan/UBSan."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess


# This is the established L3 arithmetic corpus/advice evaluation, not the
# user-waived L5.3 integrated malicious proof-generation qualification.
TARGETS = ['quietproof-signature-codec-test', 'quietproof-signature-statement-test',
           'quietproof-signature-envelope-test', 'quietproof-signature-receipt-driver',
           'quietproof-browser-codec-test', 'quietproof-ecdsa-prototype']
TESTS = ['quietproof-signature-codec-test', 'quietproof-signature-codec-reference-test',
         'quietproof-signature-statement-test', 'quietproof-signature-envelope-test',
         'quietproof-signature-receipt-test', 'quietproof-browser-codec-test',
         'quietproof-ecdsa-constraint-test', 'quietproof-ecdsa-advice-test']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True, help='New, nonexistent directory')
    parser.add_argument('--jobs', type=int, default=2)
    args = parser.parse_args()
    if args.jobs < 1:
        parser.error('--jobs must be positive')
    source = Path(__file__).resolve().parents[1]
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=False)
    common = ['-G', 'Ninja', '-DCMAKE_BUILD_TYPE=RelWithDebInfo', '-DBUILD_TESTING=ON',
        '-DCMAKE_CXX_COMPILER=clang++', '-DQUIETPROOF_BUILD_RPC=OFF',
        '-DQUIETPROOF_BUILD_SIGNATURE_MODE=ON', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
        '-DCMAKE_CXX_FLAGS=-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer',
        '-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined',
        '-DCMAKE_DISABLE_FIND_PACKAGE_libsecp256k1=TRUE',
        '-DCMAKE_DISABLE_FIND_PACKAGE_LongfellowZKECDSA=TRUE',
        '-DCMAKE_PREFIX_PATH=' + str(args.prefix.resolve())]
    if shutil.which('ccache'):
        common += ['-DCMAKE_CXX_COMPILER_LAUNCHER=ccache']
    subprocess.run(['cmake', '-S', source, '-B', work, *common], check=True)
    subprocess.run(['cmake', '--build', work, '--parallel', str(args.jobs), '--target', *TARGETS], check=True)
    selected = '^(' + '|'.join(TESTS) + ')$'
    environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    subprocess.run(['ctest', '--test-dir', work, '--output-on-failure', '--no-tests=error',
        '--parallel', '1', '--output-junit', work / 'sanitizers.xml', '-R', selected],
        env=environment, check=True)
    import xml.etree.ElementTree as ET
    cases = list(ET.parse(work / 'sanitizers.xml').getroot().iter('testcase'))
    if {c.attrib['name'] for c in cases} != set(TESTS) or any(
            c.find('skipped') is not None or c.find('failure') is not None or c.find('error') is not None for c in cases):
        raise RuntimeError('Sanitizer selection incomplete, failed or skipped')
    (work / 'scope.json').write_text(json.dumps({'tests': TESTS, 'instrumentation': 'ASan+UBSan',
        'scope': 'Application parsers and header arithmetic; prebuilt base SDK archive is not instrumented',
        'waiver': 'Original L5.3 integrated attacks remain unexecuted/unqualified'}, indent=2) + '\n')
    print(f'Sanitizers: {len(cases)} passed; 0 failed; 0 skipped')


if __name__ == '__main__':
    main()
