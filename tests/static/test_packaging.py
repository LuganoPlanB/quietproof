import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('build_static', ROOT / 'scripts/build_static.py')
packaging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaging)


class PackagingTests(unittest.TestCase):
    def test_sources_are_byte_reproducible_and_exclude_coordination_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'code.cc').write_text('public source\n')
            (root / 'private.org').write_text('coordination\n')
            with patch.object(packaging, 'git', return_value='code.cc\0'):
                files = packaging.archive_sources(root, root / 'a.tgz', ['private.org'])
                packaging.archive_sources(root, root / 'b.tgz', ['private.org'])
            self.assertEqual((root / 'a.tgz').read_bytes(), (root / 'b.tgz').read_bytes())
            self.assertEqual(files, {'code.cc': hashlib.sha256(b'public source\n').hexdigest()})
            with tarfile.open(root / 'a.tgz') as archive:
                self.assertEqual(archive.getnames(), ['code.cc'])
                self.assertEqual(archive.extractfile('code.cc').read(), b'public source\n')

    def test_missing_corresponding_source_fails(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(packaging, 'git', return_value='missing.cc'):
            root = Path(temporary)
            with self.assertRaisesRegex(ValueError, 'Corresponding source missing'):
                packaging.archive_sources(root, root / 'a.tgz')

    def test_bad_toolchain_archive_never_installs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / 'bad.tar.gz'
            archive.write_bytes(b'not the pinned archive')
            destination = root / 'installation'
            result = subprocess.run(['python3', str(ROOT / 'scripts/install_wasi.py'), '--archive',
                                     str(archive), '--destination', str(destination)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('SHA256 mismatch', result.stderr)
            self.assertFalse(destination.exists())
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['bad.tar.gz'])

    def test_installer_never_overwrites_existing_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'keep').write_text('untouched')
            result = subprocess.run(['python3', str(ROOT / 'scripts/install_wasi.py'),
                                     '--destination', str(root)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('must not exist', result.stderr)
            self.assertEqual((root / 'keep').read_text(), 'untouched')

    def test_static_build_rejects_unsafe_base_and_source_paths_before_build(self):
        for extra in [['--base', '//evil/'], ['--base', '/path/../'],
                      ['--source-addition', '../secret'], ['--source-addition', '.gestalt/x.org']]:
            result = subprocess.run(['python3', str(ROOT / 'scripts/build_static.py'), '--cross-work', '.',
                                     '--sdk-source', '.', *extra], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('error:', result.stderr)

    def test_qualification_records_failure_without_inherited_credentials(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / 'bin'
            binary.mkdir()
            stub = binary / 'cmake'
            stub.write_text('#!/bin/sh\nprintf "controlled build failure\\n"\nexit 7\n')
            stub.chmod(0o755)
            evidence = root / 'evidence'
            environment = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ['PATH'],
                               QUIETPROOF_RPC_PASSWORD='PUBLIC_TEST_SENTINEL_NEVER_CAPTURE')
            result = subprocess.run(['python3', str(ROOT / 'scripts/qualify_static.py'),
                '--cross-work', str(root / 'cross'), '--sdk-source', str(root / 'sdk'),
                '--native-on', str(root / 'native'), '--native-off', str(root / 'offline'),
                '--evidence', str(evidence)], env=environment, capture_output=True, text=True, timeout=15)
            self.assertNotEqual(result.returncode, 0)
            text = (evidence / 'qualification.json').read_text()
            manifest = json.loads(text)
            self.assertEqual(manifest['status'], 'failed')
            self.assertEqual(manifest['checks'][0]['exit'], 7)
            self.assertEqual(manifest['servers'], [])
            self.assertNotIn('PUBLIC_TEST_SENTINEL_NEVER_CAPTURE', text)
            self.assertNotIn('QUIETPROOF_RPC_PASSWORD', text)

    def test_cross_build_rejects_cached_compiler_from_another_installation(self):
        spec = importlib.util.spec_from_file_location('build_wasm', ROOT / 'scripts/build_wasm.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wasi = root / 'wasi'
            (wasi / 'bin').mkdir(parents=True)
            (wasi / 'bin/clang++').touch()
            (wasi / 'VERSION').write_text('34.0\n')
            cache = root / 'work/sdk-build/CMakeFiles/3.25.1/CMakeCXXCompiler.cmake'
            cache.parent.mkdir(parents=True)
            cache.write_text('set(CMAKE_CXX_COMPILER "/another/install/bin/clang++")\n')
            arguments = ['build_wasm.py', '--sdk-source', str(root), '--wasi-sdk', str(wasi),
                         '--work-dir', str(root / 'work')]
            with patch('sys.argv', arguments), patch.object(builder.subprocess, 'check_output', return_value=builder.SDK_COMMIT), \
                 patch.object(builder.subprocess, 'run', return_value=SimpleNamespace(returncode=0)) as commands, \
                 patch('sys.stderr', new_callable=io.StringIO) as stderr:
                with self.assertRaises(SystemExit) as result:
                    builder.main()
                self.assertEqual(result.exception.code, 2)
                self.assertIn('another compiler installation', stderr.getvalue())
                self.assertEqual(commands.call_count, 1, 'only SDK cleanliness checked; no CMake build started')


if __name__ == '__main__':
    unittest.main()
