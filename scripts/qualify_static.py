#!/usr/bin/env python3
"""Run serial native/browser gates against the packaged static artifact locally or in CI."""
import argparse
from datetime import datetime, timezone
from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import threading

ROOT = Path(__file__).resolve().parents[1]


def now():
    return datetime.now(timezone.utc).isoformat()


def record_artifact_scope(output, mode, not_run):
    """Attach successful selected-gate scope without claiming omitted gates."""
    path = output / 'build-provenance.json'
    provenance = json.loads(path.read_text())
    provenance['qualification'] = {
        'mode': mode, 'status': 'passed', 'fullBrowserSuite': mode == 'full',
        'resourceBenchmark': mode == 'full', 'nativeProofTests': mode == 'full',
        'wasmProofVerification': mode == 'full', 'notRun': not_run,
    }
    path.write_text(json.dumps(provenance, sort_keys=True, indent=2) + '\n')
    assets = output / 'asset-manifest.json'
    hashes = json.loads(assets.read_text())
    hashes[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    assets.write_text(json.dumps(hashes, sort_keys=True, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=['full', 'smoke'], default='full',
                        help='Full release gates (default), or fast CI without proof generation/verification')
    parser.add_argument('--cross-work', type=Path, required=True)
    parser.add_argument('--sdk-source', type=Path, required=True)
    parser.add_argument('--native-on', type=Path, required=True)
    parser.add_argument('--native-off', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True, help='New, nonexistent directory')
    parser.add_argument('--base', default='/')
    parser.add_argument('--allow-dirty', action='store_true')
    parser.add_argument('--source-addition', action='append', default=[])
    args = parser.parse_args()
    args.evidence = args.evidence.resolve()
    args.evidence.mkdir(parents=True, exist_ok=False)
    native, offline, cross = args.native_on.resolve(), args.native_off.resolve(), args.cross_work.resolve()
    wasm = cross / 'quietproof-build/quietproof.wasm'
    output = ROOT / 'docs/.vitepress/dist'
    not_run = [{'name': name, 'status': 'not_run_by_selected_mode',
                'reason': 'Fast CI omits expensive qualification; run --mode full explicitly or on schedule'}
               for name in ['native-proof-heavy', 'wasm-proof-verification', 'provider-browser',
                            'fixtures', 'full-browser', 'resources', 'reproducibility']] if args.mode == 'smoke' else []
    manifest = {'schema': 2, 'mode': args.mode, 'notRun': not_run,
                'startedAt': now(), 'cwd': str(ROOT), 'checks': [],
                'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                'environment': {key: os.environ[key] for key in ['QUIETPROOF_WEBKIT_EXECUTABLE', 'PLAYWRIGHT_BROWSERS_PATH'] if key in os.environ},
                'status': 'running', 'servers': []}
    manifest_path = args.evidence / 'qualification.json'

    def save():
        manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + '\n')

    environment = dict(os.environ, QUIETPROOF_WASM=str(wasm),
                       QUIETPROOF_WASM_FIXTURES=str(native / 'tests/wasm-real'),
                       QUIETPROOF_NATIVE_CLI=str(native / 'quietproof'),
                       QUIETPROOF_VERIFY_FIXTURES=str(args.evidence / 'fixtures'))
    for key, folder in [('QUIETPROOF_REQUEST_SCREENSHOTS', 'request'), ('QUIETPROOF_VERIFY_SCREENSHOTS', 'verify'),
                        ('QUIETPROOF_SECURITY_SCREENSHOTS', 'security'), ('QUIETPROOF_ACCESSIBILITY_EVIDENCE', 'accessibility'),
                        ('QUIETPROOF_HISTORY_ARTIFACTS', 'history'), ('QUIETPROOF_WORKFLOW_ARTIFACTS', 'workflow'),
                        ('QUIETPROOF_ROUNDTRIP_ARTIFACTS', 'matrix')]:
        environment[key] = str(args.evidence / folder)
    # Capture only declared path/config inputs. Inherited QUIETPROOF_* variables
    # could include native credentials and must never be copied into evidence.
    recorded_environment = {
        'QUIETPROOF_WASM', 'QUIETPROOF_WASM_FIXTURES', 'QUIETPROOF_NATIVE_CLI',
        'QUIETPROOF_VERIFY_FIXTURES', 'QUIETPROOF_REQUEST_SCREENSHOTS',
        'QUIETPROOF_VERIFY_SCREENSHOTS', 'QUIETPROOF_SECURITY_SCREENSHOTS',
        'QUIETPROOF_ACCESSIBILITY_EVIDENCE', 'QUIETPROOF_HISTORY_ARTIFACTS',
        'QUIETPROOF_WORKFLOW_ARTIFACTS', 'QUIETPROOF_ROUNDTRIP_ARTIFACTS',
        'QUIETPROOF_WEBKIT_EXECUTABLE', 'QUIETPROOF_SITE_ORIGIN', 'QUIETPROOF_SECURITY_BASE',
        'QUIETPROOF_ARTIFACT_DIR', 'QUIETPROOF_FEASIBILITY_REPORT', 'QUIETPROOF_FEASIBILITY_SITE',
        'QUIETPROOF_HOSTING_ARTIFACTS',
    }

    def run(name, command, timeout=7200):
        command = list(map(str, command))
        path = args.evidence / (name + '.log')
        check = {'name': name, 'command': command, 'cwd': str(ROOT), 'startedAt': now(),
                 'environment': {k: environment[k] for k in sorted(recorded_environment) if k in environment}, 'log': str(path)}
        manifest['checks'].append(check)
        save()
        print(f'{name}: started', flush=True)
        with path.open('w') as log:
            process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=log, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            try:
                status = process.wait(timeout=timeout)
            except BaseException:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                check.update(exit=process.returncode, completedAt=now(), interrupted=True)
                save()
                raise
        text = path.read_text()
        counts = {key: int(value) for key, value in re.findall(r'^(?:# |ℹ )(tests|pass|fail|cancelled|skipped) (\d+)$', text, re.M)}
        ctest = re.search(r'(\d+)% tests passed, (\d+) tests failed out of (\d+)', text)
        if ctest:
            counts = {'total': int(ctest[3]), 'fail': int(ctest[2]), 'pass': int(ctest[3]) - int(ctest[2])}
        check.update(exit=status, counts=counts or None, completedAt=now(),
                     logSha256=hashlib.sha256(path.read_bytes()).hexdigest(), logBytes=path.stat().st_size)
        save()
        print(f'{name}: exit={status}; counts={counts or "build/contract"}', flush=True)
        if status:
            raise RuntimeError(f'{name} failed; see {path}')
        if counts and (counts.get('fail', 0) or counts.get('cancelled', 0) or not counts.get('pass')):
            raise RuntimeError(f'{name} did not execute a passing suite')

    def packaged_build(base, name):
        command = ['python3', 'scripts/build_static.py', '--cross-work', cross,
                   '--sdk-source', args.sdk_source.resolve(), '--base', base]
        if args.allow_dirty:
            command.append('--allow-dirty')
        for path in args.source_addition:
            command.extend(['--source-addition', path])
        run(name, command)

    def snapshot():
        return {str(p.relative_to(output)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in sorted(output.rglob('*')) if p.is_file()}

    def browser_checks(base, full):
        class Handler(SimpleHTTPRequestHandler):
            def do_GET(self):
                if not self.path.startswith(base):
                    self.send_error(404)
                    return
                self.path = '/' + self.path[len(base):]
                if '?' not in self.path and not Path(self.translate_path(self.path)).suffix and self.path != '/':
                    self.path += '.html'
                super().do_GET()

            def log_message(self, *_):
                pass

        server = ThreadingHTTPServer(('127.0.0.1', 0), partial(Handler, directory=str(output)))
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        origin = f'http://127.0.0.1:{server.server_port}'
        record = {'origin': origin, 'base': base, 'startedAt': now(), 'stoppedAt': None}
        manifest['servers'].append(record)
        save()
        environment.update(QUIETPROOF_SITE_ORIGIN=origin + base.rstrip('/'),
                           QUIETPROOF_SECURITY_BASE='', QUIETPROOF_ARTIFACT_DIR=str(output),
                           QUIETPROOF_HOSTING_ARTIFACTS=str(args.evidence / 'hosting' / ('root' if base == '/' else 'subpath')))
        try:
            run('hosting-' + ('root' if base == '/' else 'subpath'),
                ['node', '--test', '--test-concurrency=1', 'tests/static/hosting.browser.test.mjs'])
            run('security-' + ('root' if base == '/' else 'subpath'),
                ['node', '--test', '--test-concurrency=1', 'web/security.browser.test.mjs'])
            if full:
                files = sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'web').rglob('*.browser.test.mjs')
                               if p.name != 'security.browser.test.mjs' and
                               p.relative_to(ROOT).as_posix() != 'web/features/provider/verification.browser.test.mjs')
                run('full-browser', ['node', '--test', '--test-concurrency=1', *files], timeout=10800)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)
            record['stoppedAt'] = now()
            save()

    save()
    try:
        old = native / 'tests/wasm-real'
        if old.exists():
            shutil.copytree(old, args.evidence / 'previous-wasm-real')
        native_build = ['cmake', '--build', native, '--parallel', '2']
        if args.mode == 'smoke':
            native_build += ['--target', 'quietproof-cli', 'quietproof-rpc-test',
                             'compressed-key-sha256-test', 'key-ownership-test', 'ripemd160-test',
                             'quietproof-protocol-test', 'quietproof-challenge-test',
                             'quietproof-browser-codec-test', 'quietproof-integration-test',
                             'pokc-sage-test', 'quietproof-progress-test', 'p2sh-multisig-test']
        run('native-on-build', native_build)
        run('native-off-build', ['cmake', '--build', offline, '--target', 'quietproof-cli', '--parallel', '2'])
        native_tests = ['ctest', '--test-dir', native, '--output-on-failure', '--no-tests=error',
                        '--parallel', '1', '--timeout', '1800', '-E', '^quietproof-regtest-rpc-test$']
        if args.mode == 'smoke':
            native_tests += ['-LE', 'proof-heavy']
        run('native-on', native_tests)
        run('native-off', ['ctest', '--test-dir', offline, '--output-on-failure', '--no-tests=error',
                          '--parallel', '1', '--timeout', '600', '-R', '^quietproof-(package-test|cli-test|cli-rpc-test|prove-feedback-test)$'])
        if args.mode == 'full':
            run('fixtures', [native / 'quietproof-browser-fixtures', args.evidence / 'fixtures'])
        if args.mode == 'full':
            run('wasm-browser', ['npm', 'run', 'test:wasm'])
            # Use fresh native proof fixtures before the long full-web matrix.
            run('provider-browser', ['node', '--test', '--test-concurrency=1',
                                     'web/features/provider/verification.browser.test.mjs'])
        else:
            run('wasm-browser-fast', ['node', '--test', '--test-concurrency=1', '--test-timeout=60000',
                '--test-skip-pattern=^(real proof stages|browser time and phase failures)',
                'tests/wasm/browser.test.mjs'])
        units = sorted(str(p.relative_to(ROOT)) for parent in [ROOT / 'web', ROOT / 'tests/wasm']
                       for p in parent.rglob('*.test.mjs') if not p.name.endswith('.browser.test.mjs') and p.name != 'browser.test.mjs')
        run('units', ['node', '--test', '--test-concurrency=1', *units])
        run('site', ['npm', 'run', 'test:site'])
        run('packaging', ['python3', '-m', 'unittest', 'discover', '-s', 'tests/static', '-p', 'test_*.py'])
        packaged_build('/', 'root-build-a')
        if args.mode == 'full':
            first = snapshot()
            packaged_build('/', 'root-build-b')
            second = snapshot()
            comparison = {'first': first, 'second': second, 'identical': first == second}
            (args.evidence / 'reproducibility.json').write_text(json.dumps(comparison, sort_keys=True, indent=2) + '\n')
            if first != second:
                raise RuntimeError('static rebuild bytes differ; see reproducibility.json')
        browser_checks('/', args.mode == 'full')
        if args.mode == 'full':
            environment.update(QUIETPROOF_WASM_FIXTURES=str(args.evidence / 'fixtures'),
                               QUIETPROOF_FEASIBILITY_REPORT=str(args.evidence / 'resources.json'),
                               QUIETPROOF_FEASIBILITY_SITE=str(output))
            run('resources', ['node', 'tests/wasm/feasibility.mjs'])
        packaged_build('/quietproof/', 'subpath-build')
        browser_checks('/quietproof/', False)
        if args.base != '/quietproof/':
            packaged_build(args.base, 'final-build')
        record_artifact_scope(output, args.mode, not_run)
        manifest['artifact'] = snapshot()
        manifest['status'] = 'passed'
    except BaseException as error:
        manifest['status'] = 'failed'
        manifest['failure'] = {'type': type(error).__name__, 'message': str(error)}
        raise
    finally:
        manifest['completedAt'] = now()
        save()


if __name__ == '__main__':
    main()
