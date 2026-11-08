#!/usr/bin/env python3
"""Detect stale, corrupted or misclassified independent PoSC reference data."""
import copy
import ast
import contextlib
import hashlib
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

    def test_fixture_contains_only_deterministic_model_fields(self):
        # CI compares the fixture byte-for-byte with fresh Sage output.
        # Historical generation provenance belongs in external evidence.
        self.assertEqual(set(self.document), {
            'cases', 'domains', 'format', 'malformed_serialization_cases_outside_relation',
            'name', 'profile_wire_version', 'profiles', 'public_test_data', 'sage_version', 'scope',
        })

    def test_all_sage_rows_have_independent_python_agreement(self):
        document, rows, expected, unrepresentable = reference.validate_fixture(FIXTURE)
        self.assertEqual(len(document['cases']), 134)
        self.assertEqual(len(rows), 131)
        self.assertEqual(sum(expected.values()), 43)
        self.assertEqual(unrepresentable, ['Q_infinity', 'Q_x_p_alias', 'Q_y_p_alias'])
        self.assertEqual({c['expected']['branch'] for c in document['cases'] if c['expected']['valid']}, {'r', 'r+n'})

    def test_public_v4_profile_source_matches_frozen_bytes(self):
        # These functions use only Python-compatible integer/byte operations.
        # This checks the public digest model without claiming a Sage run.
        tree = ast.parse((ROOT / 'spec/posc_reference.sage').read_text())
        functions = ast.Module(body=[node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name in
            ('require', 'number', 'request_bytes', 'profile')], type_ignores=[])
        def sha256(value):
            return hashlib.sha256(value).digest()
        def tagged_hash(tag, value):
            prefix = sha256(tag.encode('ascii'))
            return sha256(prefix + prefix + value)
        namespace = {'sha256': sha256, 'tagged_hash': tagged_hash}
        exec(compile(functions, 'spec/posc_reference.sage', 'exec'), namespace)
        vectors = json.loads((ROOT / 'spec/signature-profile-v1.json').read_text())['vectors']
        for stored, vector in zip(self.document['profiles'], vectors):
            derived = namespace['profile'](vector['request'])
            self.assertTrue(all(value == stored[key] == vector[key]
                                for key, value in derived.items()))
            for binding in stored['binding_changes']:
                request = copy.deepcopy(vector['request'])
                field = binding['field']
                if field == 'nonce':
                    value = bytearray.fromhex(request[field])
                    value[0] ^= 1
                    request[field] = value.hex()
                elif field == 'purpose':
                    request[field] += '!'
                elif field == 'network':
                    request[field] = (request[field] + 1) % 5
                else:
                    request['claims'][0][field] += 1
                changed = namespace['profile'](request)
                self.assertEqual((changed['d'], changed['z']), (binding['d'], binding['z']))

    def test_v3_profile_bytes_cannot_keep_v4_fixture_identity(self):
        document = copy.deepcopy(self.document)
        wire = bytearray.fromhex(document['profiles'][0]['request_hex'])
        wire[4] = 3
        document['profiles'][0]['request_hex'] = wire.hex()
        self.rejected(document, 'profile mismatch')

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
