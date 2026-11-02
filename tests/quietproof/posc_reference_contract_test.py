#!/usr/bin/env python3
"""Detect stale, corrupted or misclassified independent PoSC reference data."""
import copy
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('posc_fixture_contract', Path(__file__).with_name('posc_sage_vector_test.py'))
reference = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reference)
FIXTURE = ROOT / 'tests/quietproof/testdata/posc_sage_vectors.json'


class PoSCReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = json.loads(FIXTURE.read_text())

    def rejected(self, document, message):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary) / 'changed.json'
            fixture.write_text(json.dumps(document))
            with self.assertRaisesRegex(ValueError, message):
                reference.validate_fixture(fixture)

    def test_all_sage_rows_have_independent_python_agreement(self):
        document, rows, expected, unrepresentable = reference.validate_fixture(FIXTURE)
        self.assertEqual(len(document['cases']), 134)
        self.assertEqual(len(rows), 131)
        self.assertEqual(sum(expected.values()), 43)
        self.assertEqual(unrepresentable, ['Q_infinity', 'Q_x_p_alias', 'Q_y_p_alias'])
        self.assertEqual({c['expected']['branch'] for c in document['cases'] if c['expected']['valid']}, {'r', 'r+n'})

    def test_corrupted_public_hash_cannot_keep_positive_decision(self):
        document = copy.deepcopy(self.document)
        row = next(c for c in document['cases'] if c['expected']['valid'])
        row['h'] = bytes(20).hex()
        self.rejected(document, 'Sage/Python mismatch')

    def test_high_s_cannot_keep_positive_decision(self):
        document = copy.deepcopy(self.document)
        row = next(c for c in document['cases'] if c['expected']['valid'])
        row['s'] = format(int(document['domains']['n'], 16) - int(row['s'], 16), 'x')
        self.rejected(document, 'Sage/Python mismatch')

    def test_corrupted_nonce_point_metadata_is_detected(self):
        document = copy.deepcopy(self.document)
        row = next(c for c in document['cases'] if c['expected']['valid'])
        row['expected']['R']['x'] = '0'
        self.rejected(document, 'arithmetic metadata mismatch')

    def test_infinity_is_not_a_compiled_constraint_rejection(self):
        document = copy.deepcopy(self.document)
        next(c for c in document['cases'] if c['id'] == 'Q_infinity')['circuit_input_representable'] = True
        self.rejected(document, 'input classification')

    def test_duplicate_and_missing_corpus_rows_are_detected(self):
        document = copy.deepcopy(self.document)
        document['cases'].append(copy.deepcopy(document['cases'][0]))
        self.rejected(document, 'duplicate case')
        document = copy.deepcopy(self.document)
        document['cases'].pop(0)
        self.rejected(document, 'missing independent corpus cases')

    def test_incomplete_sage_composition_matrix_is_detected(self):
        document = copy.deepcopy(self.document)
        document['cases'].pop()
        self.rejected(document, 'missing/extra PoSC composition cases')


class PoSCRunnerTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('posc_runner', ROOT / 'scripts/run_posc_sage.py')
        self.runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.runner)

    def test_container_is_pinned_offline_and_read_only(self):
        with patch.dict(self.runner.os.environ, {}, clear=True), \
             patch.object(self.runner.shutil, 'which', side_effect=lambda name: '/usr/bin/docker' if name == 'docker' else None), \
             patch.object(self.runner.subprocess, 'call', return_value=0) as execute, \
             patch.object(sys, 'argv', ['run_posc_sage.py']):
            self.assertEqual(self.runner.main(), 0)
        command = execute.call_args.args[0]
        self.assertIn(self.runner.IMAGE, command)
        self.assertEqual(command[command.index('--network') + 1], 'none')
        self.assertIn('--read-only', command)
        self.assertTrue(command[command.index('--volume') + 1].endswith(':/workspace:ro'))
        self.assertNotIn('--privileged', command)
        self.assertEqual(command[-2:], ['--check', self.runner.FIXTURE])

    def test_explicit_wrong_version_does_not_fall_back(self):
        with patch.dict(self.runner.os.environ, {'POSC_SAGE_BIN': '/fake/sage'}, clear=True), \
             patch.object(self.runner.os, 'access', return_value=True), \
             patch.object(self.runner.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'SageMath version 10.5, Release Date', '')), \
             patch.object(self.runner.subprocess, 'call') as execute, \
             patch.object(sys, 'argv', ['run_posc_sage.py']), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                self.runner.main()
            self.assertEqual(error.exception.code, 2)
            execute.assert_not_called()

    def test_no_runtime_fails_without_claiming_a_mathematical_pass(self):
        with patch.dict(self.runner.os.environ, {}, clear=True), \
             patch.object(self.runner.shutil, 'which', return_value=None), \
             patch.object(self.runner.subprocess, 'call') as execute, \
             patch.object(sys, 'argv', ['run_posc_sage.py']), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                self.runner.main()
            self.assertEqual(error.exception.code, 2)
            execute.assert_not_called()


if __name__ == '__main__':
    unittest.main()
