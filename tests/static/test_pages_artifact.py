"""Pages must deploy only the unchanged artifact from the selected CI run."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('pages', ROOT / 'scripts/check_pages_artifact.py')
pages = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pages)


class PagesArtifactTests(unittest.TestCase):
    def artifact(self, directory, **changes):
        provenance = {
            'sourceCommit': 'tested-sha', 'base': '/quietproof/', 'dirtyReviewBuild': False,
            'qualification': {'mode': 'smoke', 'status': 'passed', 'fullBrowserSuite': False,
                              'resourceBenchmark': False, 'nativeProofTests': False,
                              'wasmProofVerification': False},
        }
        provenance.update(changes)
        (directory / 'build-provenance.json').write_text(json.dumps(provenance))
        (directory / 'index.html').write_text('checked site')
        manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()
                    if p.name != 'asset-manifest.json'}
        (directory / 'asset-manifest.json').write_text(json.dumps(manifest))

    def test_accepts_exact_checked_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.artifact(root)
            pages.validate(root, 'tested-sha', '/quietproof/')

    def test_wrong_source_base_or_dirty_artifacts_are_rejected(self):
        for changes in [{'sourceCommit': 'another-sha'}, {'base': '/'}, {'dirtyReviewBuild': True}]:
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.artifact(root, **changes)
                with self.assertRaises(ValueError):
                    pages.validate(root, 'tested-sha', '/quietproof/')

    def test_unqualified_or_mislabelled_scope_is_rejected(self):
        for key, value in [('mode', 'full'), ('status', 'failed'), ('nativeProofTests', True),
                           ('wasmProofVerification', True), ('fullBrowserSuite', True),
                           ('resourceBenchmark', True)]:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.artifact(root)
                provenance = json.loads((root / 'build-provenance.json').read_text())
                provenance['qualification'][key] = value
                self.artifact(root, qualification=provenance['qualification'])
                with self.assertRaises(ValueError):
                    pages.validate(root, 'tested-sha', '/quietproof/')

    def test_changed_or_unbound_provenance_and_assets_are_rejected(self):
        for name in ['index.html', 'build-provenance.json']:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                self.artifact(root)
                with (root / name).open('a') as file:
                    file.write(' ')
                with self.assertRaises(ValueError):
                    pages.validate(root, 'tested-sha', '/quietproof/')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.artifact(root)
            (root / 'asset-manifest.json').write_text('{}')
            with self.assertRaises(ValueError):
                pages.validate(root, 'tested-sha', '/quietproof/')

    def test_manifest_cannot_reach_outside_artifact(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.artifact(root)
            manifest = json.loads((root / 'asset-manifest.json').read_text())
            manifest['../outside'] = 'untrusted'
            (root / 'asset-manifest.json').write_text(json.dumps(manifest))
            with self.assertRaises(ValueError):
                pages.validate(root, 'tested-sha', '/quietproof/')


if __name__ == '__main__':
    unittest.main()
