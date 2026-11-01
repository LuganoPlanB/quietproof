"""Release entry points preserve explicit capability and authenticated install boundaries."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
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


if __name__ == '__main__':
    unittest.main()
