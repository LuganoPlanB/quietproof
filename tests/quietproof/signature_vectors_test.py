#!/usr/bin/env python3
"""Contracts for the public, independent ECDSA reference and corpus runner."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "scripts/generate_signature_vectors.py"
FIXTURE = ROOT / "spec/signature-vectors.json"
SPEC = importlib.util.spec_from_file_location("signature_vectors", GENERATOR)
ref = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ref)


def point(value):
    return None if value is None else (int(value["x"], 16), int(value["y"], 16))


class SignatureVectorsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.document = ref.corpus()
        cls.cases = {case["id"]: case for case in cls.document["relation_cases"]}

    def test_domains_and_known_double(self):
        self.assertEqual(ref.P, 2 ** 256 - 2 ** 32 - 977)
        self.assertNotEqual(ref.P, ref.N)
        self.assertIsNone(ref.multiply(ref.N, ref.G))
        # A fixed external arithmetic anchor, not generated via the code under test.
        self.assertEqual(ref.compressed(ref.add(ref.G, ref.G)).hex(),
                         "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")

    def test_complete_group_operations(self):
        self.assertEqual(ref.add(None, ref.G), ref.G)
        self.assertEqual(ref.add(ref.G, None), ref.G)
        self.assertIsNone(ref.add(ref.G, ref.negate(ref.G)))
        self.assertIsNone(ref.multiply(0, ref.G))
        self.assertEqual(ref.multiply(ref.N - 1, ref.G), ref.negate(ref.G))
        for name in ("cancel_G", "cancel_minus_G"):
            self.assertEqual(self.cases[name]["expected"]["reason"], "R_infinity")
            self.assertIsNone(self.cases[name]["expected"]["R"])
        doubled = self.cases["equal_verification_addends"]["expected"]
        self.assertTrue(doubled["valid"])
        self.assertEqual(doubled["u"], doubled["v"])
        self.assertEqual(point(doubled["R"])[0], ref.multiply(2, ref.G)[0])

    def test_digest_is_big_endian_reduced_mod_n(self):
        for case in self.cases.values():
            self.assertEqual(int(case["expected"]["e"], 16), int(case["z"], 16) % ref.N)
        self.assertEqual(self.cases["digest_zero_G"]["expected"]["e"], "0")
        self.assertEqual(self.cases["digest_n_G"]["expected"]["e"], "0")
        self.assertEqual(self.cases["digest_p_G"]["expected"]["e"], format(ref.P - ref.N, "x"))
        self.assertNotEqual(self.cases["digest_p_G"]["expected"]["e"], "0")
        self.assertEqual(self.cases["digest_max256_G"]["expected"]["e"], format(2 ** 256 - 1 - ref.N, "x"))

    def test_both_branches_and_point_parities(self):
        valid = [case for case in self.cases.values() if case["expected"]["valid"]]
        self.assertEqual({case["expected"]["x_branch"] for case in valid}, {"r", "r+n"})
        self.assertEqual({point(case["Q"])[1] % 2 for case in valid}, {0, 1})
        self.assertEqual({point(case["expected"]["R"])[1] % 2 for case in valid}, {0, 1})
        rare = [case for case in valid if "rare_branch" in case["tags"]]
        self.assertEqual(len(rare), 10)
        self.assertEqual({point(case["expected"]["R"])[1] % 2 for case in rare}, {0, 1})
        for case in rare:
            r = int(case["r"], 16)
            self.assertEqual(point(case["expected"]["R"])[0], ref.N + r)
            self.assertLess(ref.N + r, ref.P)
            self.assertEqual(r, self.document["rare_branch_k"])

    def test_wrapped_branch_is_rejected_after_arithmetic(self):
        case = self.cases["wrapped_r_plus_n"]
        r, nonce = int(case["r"], 16), point(case["expected"]["R"])
        self.assertEqual(r + ref.N, ref.P + 1)
        self.assertEqual(nonce[0], (r + ref.N) % ref.P)
        self.assertNotEqual(nonce[0] % ref.N, r)
        self.assertEqual(case["oracle_class"], "cryptographic_rejection")

    def test_scalar_aliases_would_accept_without_range_constraints(self):
        aliases = [case for case in self.cases.values() if "scalar_alias" in case["tags"]]
        self.assertEqual(len(aliases), 4)
        for case in aliases:
            r, s = int(case["r"], 16), int(case["s"], 16)
            result = ref.evaluate(bytes.fromhex(case["z"]), point(case["Q"]), r % ref.N, s % ref.N)
            self.assertTrue(result["valid"])
            self.assertEqual(result["x_branch"], "r+n")
            self.assertFalse(case["expected"]["valid"])
            self.assertEqual(case["oracle_class"], "scalar_range_rejection")
            if r >= ref.N:
                self.assertEqual(point(result["R"])[0], r)

    def test_range_and_high_s_are_not_encoding_errors(self):
        for case in self.cases.values():
            if case["oracle_class"] not in ("scalar_range_rejection", "low_s_rejection"):
                continue
            r, s = ref.parse_der(bytes.fromhex(case["oracle_input"]["der"]))
            self.assertEqual((r, s), (int(case["r"], 16), int(case["s"], 16)))
            if case["expected"]["reason"] == "high_s":
                q, e = point(case["Q"]), int(case["expected"]["e"], 16)
                inv = pow(s, -1, ref.N)
                nonce = ref.add(ref.multiply(e * inv % ref.N, ref.G),
                                ref.multiply(r * inv % ref.N, q))
                self.assertEqual(nonce[0] % ref.N, r)
                self.assertTrue(ref.evaluate(bytes.fromhex(case["z"]), q, r, ref.N - s)["valid"])

    def test_invalid_points_do_not_get_silently_reencoded(self):
        unencodable = [case for case in self.cases.values() if case["oracle_input"] is None]
        self.assertEqual(len(unencodable), 7)
        for case in unencodable:
            self.assertFalse(case["expected"]["valid"])
            self.assertEqual(case["oracle_class"], "not_encodable")
            self.assertIsNotNone(case["oracle_unavailable_reason"])
            with self.assertRaises(ValueError):
                ref.compressed(point(case["Q"]))
        for case in self.document["malformed_cases"]:
            self.assertFalse(case["expected"]["valid"])
            self.assertEqual(case["oracle_class"], "malformed_input_rejection")

    def test_fixture_bytes_are_deterministic(self):
        self.assertEqual(FIXTURE.read_bytes(), (json.dumps(self.document, indent=2) + "\n").encode())
        result = subprocess.run([sys.executable, str(GENERATOR)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, FIXTURE.read_bytes())

    def test_check_detects_semantic_or_byte_change(self):
        with tempfile.TemporaryDirectory(prefix="signature-vectors-") as directory:
            changed = Path(directory) / "changed.json"
            for data in (FIXTURE.read_bytes().replace(b'"valid": true', b'"valid": false', 1),
                         FIXTURE.read_bytes() + b"\n"):
                changed.write_bytes(data)
                result = subprocess.run([sys.executable, str(GENERATOR), "--check", str(changed)],
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 1)
                self.assertIn(b"signature vectors differ", result.stderr)

    def test_oracle_execution_failure_is_not_a_rejection(self):
        for result in (subprocess.CompletedProcess([], 2, b"invalid\n", b""),
                       subprocess.CompletedProcess([], 0, b"", b""),
                       subprocess.CompletedProcess([], 0, b"valid\n", b"warning")):
            with patch.object(ref.subprocess, "run", return_value=result), self.assertRaises(ValueError):
                ref.check_oracle(self.document, Path("unused"))
        with patch.object(ref.subprocess, "run", side_effect=subprocess.TimeoutExpired("unused", 5)):
            with self.assertRaisesRegex(ValueError, "oracle execution failed"):
                ref.check_oracle(self.document, Path("unused"))

    def test_oracle_requires_positive_and_crypto_negative_controls(self):
        for selected in ([], [self.cases["Q_infinity"]]):
            with self.assertRaisesRegex(ValueError, "positive and cryptographic-negative controls"):
                ref.check_oracle({"relation_cases": selected, "malformed_cases": []}, Path("unused"))


if __name__ == "__main__":
    unittest.main()
