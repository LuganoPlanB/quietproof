#!/usr/bin/env python3
"""Specification controls; not a production circuit, signing or Core RPC test."""

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODULE_SPEC = importlib.util.spec_from_file_location(
    "signature_profile", ROOT / "scripts/generate_signature_profile.py")
PROFILE = importlib.util.module_from_spec(MODULE_SPEC)
MODULE_SPEC.loader.exec_module(PROFILE)
FIXTURE = json.loads((ROOT / "spec/signature-profile-v1.json").read_text())


class SignatureProfileTest(unittest.TestCase):
    def test_v4_legacy_procedure_is_explicit_and_request_bound(self):
        vector = FIXTURE['legacy_vectors'][0]
        request = vector['request']
        encoded, _ = PROFILE.serialize_request(request)
        self.assertEqual(encoded.hex(), vector['request_hex'])
        self.assertEqual(encoded[:11], b'QPS1\x04\x03\x01\x00\x02\x01\x01')
        digest = PROFILE.tagged_hash('QuietProof/statement/v4', encoded)
        self.assertEqual(digest.hex(), vector['d'])
        message = b'quietproof:signature:v4:' + digest.hex().encode('ascii')
        self.assertEqual(len(message), 88)
        self.assertEqual(message.decode('ascii'), vector['application_message_ascii'])
        preimage = b'\x18Bitcoin Signed Message:\n\x58' + message
        self.assertEqual(preimage.hex(), vector['legacy_preimage_hex'])
        self.assertEqual(hashlib.sha256(hashlib.sha256(preimage).digest()).hexdigest(), vector['legacy_z'])
        self.assertNotEqual(vector['d'], FIXTURE['vectors'][0]['d'])
        for profile, version, kind in [(0, 1, 1), (3, 1, 1), (2, 2, 1), (2, 1, 0)]:
            invalid = dict(request, profile=profile, profile_version=version, signing_kind=kind)
            with self.subTest(profile=profile, version=version, kind=kind), self.assertRaises(ValueError):
                PROFILE.serialize_request(invalid)

    def test_published_bip322_controls(self):
        # BIP-322 basic-test-vectors.json at the revision pinned in the spec.
        public_key = bytes.fromhex("02c7f12003196442943d8588e01aee840423cc54fc1521526a3b85c2b0cbd58872")
        program = hashlib.new("ripemd160", hashlib.sha256(public_key).digest()).digest()
        for message, expected_m, expected_spend, expected_sign in [
            (b"", "c90c269c4f8fcbe6880f72a721ddfbf1914268a794cbb21cfafee13770ae19f1",
             "c5680aa69bb8d860bf82d4e9cd3504b55dde018de765a91bb566283c545a99a7",
             "1e9654e951a5ba44c8604c4de6c67fd78a27e81dcadcfe1edf638ba3aaebaed6"),
            (b"Hello World", "f0eb03b1a75ac6d9847f55c624a99169b5dccba2a31f5b23bea77ba270de0a7a",
             "b79d196740ad5217771c1098fc4a4b51e0535c32236c71f1ea4d61a2d603352b",
             "88737ae86f2077145f93cc4b153ae9a1cb8d56afa511988c149c5c8c9d93bddf"),
        ]:
            with self.subTest(message=message):
                message_hash = PROFILE.tagged_hash("BIP0322-signed-message", message)
                self.assertEqual(message_hash.hex(), expected_m)
                spend, sign, _, _ = PROFILE.virtual_transactions(message_hash, b"\x00\x14" + program)
                self.assertEqual(PROFILE.sha256d(spend)[::-1].hex(), expected_spend)
                self.assertEqual(PROFILE.sha256d(sign)[::-1].hex(), expected_sign)

    def test_published_bip143_control(self):
        # BIP-143 Native P2WPKH SIGHASH_ALL example, not our synthetic transaction.
        prevouts = bytes.fromhex(
            "fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000"
            "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000")
        outputs = bytes.fromhex(
            "202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac"
            "9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac")
        preimage = PROFILE.bip143_preimage(
            1, prevouts, bytes.fromhex("eeffffffffffffff"), prevouts[36:],
            bytes.fromhex("76a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac"),
            600_000_000, 0xffffffff, outputs, 0x11)
        expected_preimage = (
            "0100000096b827c8483d4e9b96712b6713a7b68d6e8003a781feba36c31143470b4efd37"
            "52b0a642eea2fb7ae638c36f6252b6750293dbe574a806984b8e4d8548339a3b"
            "ef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000"
            "1976a9141d0f172a0ecb48aee1be1f2687d2963ae33f71a188ac0046c32300000000ffffffff"
            "863ef3e1a92afbfdb97f31ad0fc7683ee943e9abcf2501590ff8f6551f47e5e51100000001000000")
        self.assertEqual(preimage.hex(), expected_preimage)
        self.assertEqual(PROFILE.sha256d(preimage).hex(),
                         "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670")

    def test_exact_message_and_byte_order(self):
        for vector in FIXTURE["vectors"]:
            with self.subTest(kind=vector["name"]):
                message = vector["application_message_ascii"].encode("ascii")
                self.assertEqual(len(message), 88)
                self.assertEqual(message, b"quietproof:signature:v4:" + vector["d"].encode("ascii"))
                raw = bytes.fromhex(vector["to_spend_txid_raw"])
                self.assertEqual(raw[::-1].hex(), vector["to_spend_txid_display"])
                self.assertNotEqual(raw, raw[::-1])
                self.assertEqual(vector["to_sign_input_outpoint_wire"], raw.hex() + "00000000")
                self.assertNotEqual(vector["application_message_hash"], vector["request"]["bip322_message_hash"])
                self.assertTrue(vector["request_hex"].startswith("51505331040301000101"))

    def test_every_encoded_byte_and_field_is_bound(self):
        for vector in FIXTURE["vectors"]:
            with self.subTest(kind=vector["name"]):
                fields = vector["fields"]
                covered = [i for field in fields for i in range(field["offset"], field["offset"] + field["size"])]
                self.assertEqual(covered, list(range(vector["request_size"])))
                self.assertEqual(vector["byte_mutation_count"], vector["request_size"])
                self.assertEqual(len(vector["field_mutations"]), len(fields))
                for mutation in vector["field_mutations"]:
                    self.assertNotEqual(mutation["d"], vector["d"])
                    self.assertNotEqual(mutation["z"], vector["z"])
                self.assertNotEqual(vector["valid_selected_kind_change"]["z"], vector["z"])

    def test_virtual_shape_and_zero_synthetic_amount(self):
        for vector in FIXTURE["vectors"]:
            with self.subTest(kind=vector["name"]):
                spend = bytes.fromhex(vector["to_spend_hex"])
                sign = bytes.fromhex(vector["to_sign_unsigned_hex"])
                self.assertEqual(spend[:5], bytes(4) + b"\x01")
                self.assertEqual(spend[5:41], bytes(32) + b"\xff" * 4)
                self.assertEqual(spend[41:44], b"\x22\x00\x20")
                self.assertEqual(spend[44:76].hex(), vector["application_message_hash"])
                self.assertEqual(spend[76:90], bytes(4) + b"\x01" + bytes(8) + bytes([len(bytes.fromhex(vector["selected_script_pubkey"]))]))
                self.assertEqual(spend[90:-4].hex(), vector["selected_script_pubkey"])
                self.assertEqual(spend[-4:], bytes(4))
                self.assertEqual(len(sign), 61)
                self.assertEqual(sign[:5], bytes(4) + b"\x01")
                self.assertEqual(sign[5:41].hex(), vector["to_sign_input_outpoint_wire"])
                self.assertEqual(sign[41:], b"\x00" + bytes(4) + b"\x01" + bytes(8) + b"\x01\x6a" + bytes(4))
                preimage = bytes.fromhex(vector["sighash_preimage_hex"])
                self.assertEqual(preimage[-4:], b"\x01\x00\x00\x00")
                self.assertEqual(len(preimage), 90 if vector["name"] == "p2pkh" else 182)
                if vector["name"] == "p2wpkh":
                    self.assertEqual(preimage[104:130].hex(), "19" + vector["script_code"])
                    self.assertEqual(preimage[130:138], bytes(8))

    def test_fixture_request_rejects_invalid_claims_and_alias(self):
        base = FIXTURE["vectors"][0]["request"]
        changed = copy.deepcopy(base)
        changed["claims"] = changed["claims"][:1]  # Only wpkh present; pkh selection cannot alias.
        with self.assertRaises(ValueError):
            PROFILE.serialize_request(changed)
        for change in ("duplicate", "second_hash", "overflow", "bridge", "unknown_kind"):
            changed = copy.deepcopy(base)
            if change == "duplicate":
                changed["claims"][1] = copy.deepcopy(changed["claims"][0])
            elif change == "second_hash":
                changed["claims"][1]["program"] = "01" * 20
            elif change == "overflow":
                changed["claims"][0]["amount_sats"] = PROFILE.MAX_MONEY
            elif change == "bridge":
                changed["purpose"] = "bridge-authorization"
            else:
                changed["claims"][1]["script_kind"] = 2
            with self.subTest(change=change), self.assertRaises(ValueError):
                PROFILE.serialize_request(changed)

    def test_compactsize_boundaries(self):
        for value, expected in [(0, "00"), (252, "fc"), (253, "fdfd00"),
                                (65535, "fdffff"), (65536, "fe00000100"),
                                (2**32, "ff0000000001000000")]:
            self.assertEqual(PROFILE.compact_size(value).hex(), expected)
        for value in (-1, 2**64):
            with self.assertRaises(ValueError):
                PROFILE.compact_size(value)

    def test_frozen_fixture_and_corruption_rejection(self):
        command = [sys.executable, str(ROOT / "scripts/generate_signature_profile.py"), "--check"]
        result = subprocess.run(command + [str(ROOT / "spec/signature-profile-v1.json")], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        corrupted = copy.deepcopy(FIXTURE)
        corrupted["vectors"][0]["z"] = "00" * 32
        with tempfile.TemporaryDirectory(prefix="quietproof-profile-") as directory:
            path = Path(directory) / "corrupted.json"
            path.write_text(json.dumps(corrupted, indent=2) + "\n")
            result = subprocess.run(command + [str(path)], capture_output=True)
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"fixture differs", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
