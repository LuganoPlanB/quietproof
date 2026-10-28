"""Exercise selected qualification commands and provenance without running crypto."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('qualify_static', ROOT / 'scripts/qualify_static.py')
qualification = importlib.util.module_from_spec(spec)
spec.loader.exec_module(qualification)


class QualificationTests(unittest.TestCase):
    def exercise(self, mode=None, fail_full=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'web/features/provider').mkdir(parents=True)
            for name in ['web/exhaustive.browser.test.mjs', 'web/security.browser.test.mjs',
                         'web/features/provider/verification.browser.test.mjs', 'web/unit.test.mjs']:
                (root / name).touch()
            commands = []
            output = root / 'docs/.vitepress/dist'

            class Server:
                server_port = 12345
                def __init__(self, *args):
                    pass
                def serve_forever(self):
                    pass
                def shutdown(self):
                    pass
                def server_close(self):
                    pass

            class Process:
                def __init__(self, command, **kwargs):
                    commands.append(command)
                    self.returncode = 9 if fail_full and 'web/exhaustive.browser.test.mjs' in command else 0
                    if 'scripts/build_static.py' in command:
                        output.mkdir(parents=True, exist_ok=True)
                        (output / 'reactor.wasm').write_bytes(b'controlled artifact')
                        (output / 'build-provenance.json').write_text(json.dumps({
                            'qualification': {'mode': None, 'status': 'not_run'}}))
                        hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in output.iterdir() if p.name != 'asset-manifest.json'}
                        (output / 'asset-manifest.json').write_text(json.dumps(hashes))
                    kwargs['stdout'].write('# tests 1\n# pass 1\n# fail 0\n')
                def wait(self, timeout):
                    return self.returncode

            args = ['qualify_static.py', '--cross-work', str(root / 'cross'),
                    '--sdk-source', str(root / 'sdk'), '--native-on', str(root / 'native'),
                    '--native-off', str(root / 'offline'), '--evidence', str(root / 'evidence')]
            if mode is not None:
                args += ['--mode', mode]
            with patch.object(qualification, 'ROOT', root), patch('sys.argv', args), \
                 patch.object(qualification.subprocess, 'check_output', return_value='fixture-head'), \
                 patch.object(qualification.subprocess, 'Popen', Process), \
                 patch.object(qualification, 'ThreadingHTTPServer', Server), \
                 contextlib.redirect_stdout(io.StringIO()):
                if fail_full:
                    with self.assertRaisesRegex(RuntimeError, 'full-browser failed'):
                        qualification.main()
                else:
                    qualification.main()
            report = json.loads((root / 'evidence/qualification.json').read_text())
            provenance = json.loads((output / 'build-provenance.json').read_text())
            hashes = json.loads((output / 'asset-manifest.json').read_text())
            self.assertEqual(hashes, {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                      for p in output.iterdir() if p.name != 'asset-manifest.json'})
            self.assertTrue(all(server['stoppedAt'] for server in report['servers']))
            return commands, report, provenance

    def test_smoke_keeps_focused_commands_and_records_exhaustive_omissions(self):
        commands, report, provenance = self.exercise('smoke')
        self.assertEqual(report['mode'], 'smoke')
        names = {check['name'] for check in report['checks']}
        self.assertTrue({'native-on', 'native-off', 'wasm-browser-fast',
                         'units', 'site', 'packaging', 'hosting-root', 'security-root',
                         'hosting-subpath', 'security-subpath'} <= names)
        self.assertEqual({entry['name'] for entry in report['notRun']},
                         {'native-proof-heavy', 'wasm-proof-verification', 'provider-browser',
                          'fixtures', 'full-browser', 'resources', 'reproducibility'})
        self.assertFalse({'wasm-browser', 'provider-browser', 'root-build-b'} & names)
        native = next(c for c in commands if c[0] == 'ctest' and '-R' not in c)
        self.assertEqual(native[native.index('-LE') + 1], 'proof-heavy')
        build = commands[0]
        self.assertIn('--target', build)
        self.assertFalse({'pokc-test', 'quietproof-browser-verifier-test', 'quietproof-browser-fixtures'} & set(build))
        wasm = next(c for c in commands if 'tests/wasm/browser.test.mjs' in c)
        self.assertIn('--test-skip-pattern=^(real proof stages|browser time and phase failures)', wasm)
        self.assertTrue(all(entry['status'] == 'not_run_by_selected_mode' for entry in report['notRun']))
        self.assertFalse(any('web/exhaustive.browser.test.mjs' in command or
                             'tests/wasm/feasibility.mjs' in command for command in commands))
        scope = provenance['qualification']
        self.assertEqual(scope['mode'], 'smoke')
        self.assertFalse(scope['fullBrowserSuite'])
        self.assertFalse(scope['resourceBenchmark'])
        self.assertFalse(scope['nativeProofTests'])
        self.assertFalse(scope['wasmProofVerification'])

    def assert_full(self, mode):
        commands, report, provenance = self.exercise(mode)
        self.assertEqual(report['mode'], 'full')
        self.assertEqual(report['notRun'], [])
        self.assertTrue(any('web/exhaustive.browser.test.mjs' in command for command in commands))
        self.assertTrue(any('tests/wasm/feasibility.mjs' in command for command in commands))
        self.assertTrue(provenance['qualification']['fullBrowserSuite'])
        self.assertTrue(provenance['qualification']['resourceBenchmark'])
        self.assertTrue(provenance['qualification']['nativeProofTests'])
        self.assertTrue(provenance['qualification']['wasmProofVerification'])
        native = next(c for c in commands if c[0] == 'ctest' and '-R' not in c)
        self.assertNotIn('-LE', native)
        self.assertTrue(any('web/features/provider/verification.browser.test.mjs' in c for c in commands))
        self.assertTrue(any(c[:3] == ['npm', 'run', 'test:wasm'] for c in commands))

    def test_explicit_full_selects_matrix_and_resources(self):
        self.assert_full('full')

    def test_local_default_remains_full(self):
        self.assert_full(None)

    def test_failed_full_run_does_not_mark_artifact_qualified(self):
        _, report, provenance = self.exercise('full', fail_full=True)
        self.assertEqual(report['status'], 'failed')
        self.assertEqual(provenance['qualification'], {'mode': None, 'status': 'not_run'})

    def test_unknown_mode_rejected_before_evidence_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / 'evidence'
            arguments = ['qualify_static.py', '--cross-work', '.', '--sdk-source', '.',
                         '--native-on', '.', '--native-off', '.', '--evidence', str(evidence), '--mode', 'unknown']
            with patch('sys.argv', arguments), contextlib.redirect_stderr(io.StringIO()), \
                 self.assertRaises(SystemExit) as result:
                qualification.main()
            self.assertEqual(result.exception.code, 2)
            self.assertFalse(evidence.exists())


class ExhaustiveFixtureTests(unittest.TestCase):
    def test_harness_import_uses_explicit_wasm_without_ignored_development_copy(self):
        # Import/fixture initialization only: no browser or proving cases selected.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'web/adversarial').mkdir(parents=True)
            (root / 'docs/.vitepress/dist').mkdir(parents=True)
            for name in ['node_modules', 'tests']:
                (root / name).symlink_to(ROOT / name, target_is_directory=True)
            for name in ['features', 'wasm']:
                (root / 'web' / name).symlink_to(ROOT / 'web' / name, target_is_directory=True)
            (root / 'web/adversarial/fixtures.mjs').symlink_to(ROOT / 'web/adversarial/fixtures.mjs')
            for name in ['tool.html', 'verify.html']:
                (root / 'docs/.vitepress/dist' / name).write_text('controlled page')
            (root / 'package-lock.json').write_text('{}')
            cli, wasm = root / 'native-cli', root / 'explicit.wasm'
            cli.write_bytes(b'controlled native identity')
            wasm.write_bytes(b'controlled reactor identity')
            self.assertFalse((root / 'docs/public/wasm/quietproof.wasm').exists())
            environment = dict(os.environ, QUIETPROOF_WASM=str(wasm),
                               QUIETPROOF_NATIVE_CLI=str(cli), QUIETPROOF_ROUNDTRIP_ARTIFACTS=str(root / 'evidence'))
            for name in ['roundtrips.browser.test.mjs', 'same-key-mixed.browser.test.mjs']:
                with self.subTest(harness=name):
                    target = root / 'web/adversarial' / name
                    target.write_bytes((ROOT / 'web/adversarial' / name).read_bytes())
                    result = subprocess.run(['node', '--test', '--test-name-pattern=^fixture-import-only$', str(target)],
                                            env=environment, capture_output=True, text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
