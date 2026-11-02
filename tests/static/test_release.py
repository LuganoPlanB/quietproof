"""Release entry points preserve explicit capability and authenticated install boundaries."""
import contextlib
import importlib.util
import io
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import tarfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]


class CoreInstallTests(unittest.TestCase):
    def test_bad_archive_never_installs_or_extracts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pins = json.loads((ROOT / 'scripts/core32-pins.json').read_text())
            for name in pins['archives']:
                (root / name).write_bytes(b'invalid archive')
            result = subprocess.run(['python3', str(ROOT / 'scripts/install_core32.py'),
                '--destination', str(root / 'install'), '--archives', str(root)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Core archive SHA256 mismatch', result.stderr)
            self.assertFalse((root / 'install').exists())
            self.assertEqual(set(p.name for p in root.iterdir()), set(pins['archives']))

    def test_existing_destination_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'keep').write_text('untouched')
            result = subprocess.run(['python3', str(ROOT / 'scripts/install_core32.py'),
                '--destination', str(root)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('must not exist', result.stderr)
            self.assertEqual((root / 'keep').read_text(), 'untouched')


class MuslCapabilityTests(unittest.TestCase):
    def test_both_capabilities_reach_cmake_without_optional_ecdsa_package(self):
        spec = importlib.util.spec_from_file_location('musl', ROOT / 'scripts/build_musl_release.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        class StopAfterConfigure(Exception):
            pass
        for enabled in (False, True):
            with self.subTest(signature=enabled), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                commands = []
                def output(*args):
                    if '-dumpmachine' in args:
                        return 'x86_64-linux-musl'
                    return json.loads((ROOT / 'scripts/build-pins.json').read_text())['longfellowCommit']
                def run(*command, **kwargs):
                    commands.append(list(command))
                    if command[:3] == ('cmake', '-S', builder.ROOT):
                        raise StopAfterConfigure()
                arguments = ['build_musl_release.py', '--sdk-source', str(root),
                    '--work', str(root / 'work'), '--output', str(root / 'dist'), '--version', '0.1.0']
                if enabled:
                    arguments.append('--signature-mode')
                with patch('sys.argv', arguments), patch.object(builder, 'run', side_effect=run), \
                     patch.object(builder, 'output', side_effect=output):
                    with self.assertRaises(StopAfterConfigure):
                        builder.main()
                configure = commands[-1]
                self.assertIn('-DQUIETPROOF_BUILD_SIGNATURE_MODE=' + ('ON' if enabled else 'OFF'), configure)
                self.assertIn('-DQUIETPROOF_ENABLE_CLI_PRELOAD_TEST=OFF', configure)
                self.assertFalse(any('LongfellowZKECDSA' in str(arg) for c in commands for arg in c))


class MuslInstallTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('install_musl', ROOT / 'scripts/install_musl.py')
        self.installer = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.installer)

    def test_bad_digest_never_extracts_or_executes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / 'bad.tar.xz'
            archive.write_bytes(b'not an authenticated archive')
            with patch.object(self.installer.tarfile, 'open') as extract, \
                 patch.object(self.installer.subprocess, 'check_output') as execute:
                with self.assertRaisesRegex(ValueError, 'SHA256 mismatch'):
                    self.installer.install(root / 'install', archive)
                extract.assert_not_called()
                execute.assert_not_called()
            self.assertEqual(list(root.iterdir()), [archive])

    def test_existing_destination_is_preserved_without_download(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            keep = root / 'keep'
            keep.write_text('unchanged')
            with patch.object(self.installer.urllib.request, 'urlopen') as download:
                with self.assertRaisesRegex(ValueError, 'must not exist'):
                    self.installer.install(root)
                download.assert_not_called()
            self.assertEqual(keep.read_text(), 'unchanged')

    def exercise_archive(self, members, expected):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive = root / 'controlled.tar.xz'
            with tarfile.open(archive, 'w:xz') as bundle:
                for member in members:
                    bundle.addfile(member, io.BytesIO(b'x' * member.size) if member.isfile() else None)
            pins = json.loads(self.installer.PINS.read_text())
            pins['sha256'] = hashlib.sha256(archive.read_bytes()).hexdigest()
            with patch.object(self.installer.json, 'loads', return_value=pins), \
                 patch.object(self.installer.subprocess, 'check_output') as execute:
                with self.assertRaises(expected):
                    self.installer.install(root / 'install', archive)
                execute.assert_not_called()
            self.assertFalse((root / 'install').exists())
            self.assertFalse((root / 'escape').exists())
            self.assertEqual(list(root.iterdir()), [archive])

    def test_traversal_archive_is_rejected_even_with_matching_digest(self):
        self.exercise_archive([tarfile.TarInfo('../escape')], tarfile.FilterError)

    def test_escaping_symlink_is_rejected_even_with_matching_digest(self):
        link = tarfile.TarInfo('dyne/escape')
        link.type = tarfile.SYMTYPE
        link.linkname = '../../escape'
        self.exercise_archive([link], tarfile.FilterError)

    def test_wrong_layout_is_rejected_without_compiler_execution(self):
        self.exercise_archive([tarfile.TarInfo('unexpected')], ValueError)

    def test_release_installs_pinned_artifact_for_both_matrix_variants(self):
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        self.assertIn('signature: [false, true]', workflow)
        self.assertIn('python3 quietproof/scripts/install_musl.py --destination "$RUNNER_TEMP/dyne"', workflow)
        self.assertNotIn('uses: dyne/musl-action@', workflow)
        self.assertIn('CC: ${{ steps.musl.outputs.CC }}', workflow)
        self.assertIn('CXX: ${{ steps.musl.outputs.CXX }}', workflow)
        triggers = workflow.split('permissions:', 1)[0]
        self.assertIn('      - scripts/install_musl.py', triggers)
        self.assertIn('      - scripts/musl-pins.json', triggers)


if __name__ == '__main__':
    unittest.main()
