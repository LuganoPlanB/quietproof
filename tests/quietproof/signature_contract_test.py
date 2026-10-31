#!/usr/bin/env python3
"""Test-only specification models; no production parser, wallet or authorisation."""

import hashlib
import json
from pathlib import Path
import struct
import unittest


ROOT = Path(__file__).resolve().parents[2]
FIXTURE = json.loads((ROOT / "spec/signature-profile-v1.json").read_text())
SPEC = (ROOT / "spec/quietproof-signature-v1.md").read_text()
RECEIPT_HEADER = struct.Struct(">4sBBH32sI")


def tagged_hash(tag, data):
    th = hashlib.sha256(tag.encode("ascii")).digest()
    return hashlib.sha256(th + th + data).digest()


def dispatch(envelope, statement, mode, profile, family, circuit=1,
             rate=4, queries=128, enabled=True):
    """Decision-table model only. A supported tuple never establishes proof validity."""
    if (envelope not in (1, 2, 3) or statement not in (1, 2, 3) or
            mode not in (None, 0, 1) or profile not in (None, 1) or
            family not in (None, 1) or (circuit, rate, queries) != (1, 4, 128)):
        return "unsupported"
    if envelope in (1, 2):
        if (statement == 3 or (envelope == 1 and statement == 2) or
                any(v is not None for v in (mode, profile, family))):
            return "malformed_statement"
        return "dispatch_only"
    if statement != 3 or (mode, profile, family) != (1, 1, 1):
        return "malformed_statement"
    return "dispatch_only" if enabled else "unsupported:signature_mode_disabled"


def transcript_binding(vector, mock_digest, created_at):
    # mock_digest is deliberately not an approved or deployed circuit identity.
    h = bytes.fromhex(vector["request"]["claims"][0]["program"])
    return (b"QPE1" + struct.pack(">BBHH", 3, 1, 1, 1) +
            bytes.fromhex(vector["d"]) + h + bytes.fromhex(vector["z"]) +
            mock_digest + struct.pack(">IIIQ", 1, 4, 128, created_at))


def receipt_frame(body, digest, version=1, mode=1, profile=1):
    return RECEIPT_HEADER.pack(b"QPA1", version, mode, profile, digest, len(body)) + body


def inspect_receipt_framing(data, expected_digest, enabled=True):
    """Bounds/header model ONLY: no transaction, DER or ECDSA authorisation check."""
    if not RECEIPT_HEADER.size <= len(data) <= 4096:
        return "malformed_receipt"
    magic, version, mode, profile, digest, size = RECEIPT_HEADER.unpack_from(data)
    if magic != b"QPA1" or not 1 <= size <= 4052 or size != len(data) - 44:
        return "malformed_receipt"
    if version != 1 or mode not in (0, 1) or profile != 1:
        return "unsupported"
    if mode == 0:
        return "malformed_receipt"
    if not enabled:
        return "unsupported:signature_mode_disabled"
    if digest != expected_digest:
        return "invalid_authorization"
    return "framing_only"  # MUST NOT be interpreted as a valid receipt.


def classify_public_magic(data):
    if data[:4] == b"QPA1":
        return "malformed_statement:private_receipt_input"
    if data[:4] not in (b"QPE1", b"QPM1"):
        return "malformed_statement"
    return "parser_selection_only"


class SignatureContractTest(unittest.TestCase):
    def test_allowed_qpe_matrix_preserves_old_tuples(self):
        for envelope, statement in [(1, 1), (2, 1), (2, 2)]:
            for enabled in (False, True):
                self.assertEqual(dispatch(envelope, statement, None, None, None,
                                          enabled=enabled), "dispatch_only")
        self.assertEqual(dispatch(3, 3, 1, 1, 1), "dispatch_only")

    def test_cross_mode_and_unknown_tuple_reviews(self):
        malformed = [(1, 2, None, None, None), (1, 3, 1, 1, 1),
                     (2, 3, 1, 1, 1), (3, 1, 1, 1, 1), (3, 2, 1, 1, 1),
                     (3, 3, 0, 1, 1), (3, 3, None, 1, 1),
                     (2, 2, 1, 1, 1)]
        unsupported = [(4, 3, 1, 1, 1), (3, 4, 1, 1, 1), (3, 3, 2, 1, 1),
                       (3, 3, 1, 2, 1), (3, 3, 1, 1, 2)]
        for item in malformed:
            with self.subTest(item=item):
                self.assertEqual(dispatch(*item), "malformed_statement")
        for item in unsupported:
            with self.subTest(item=item):
                self.assertEqual(dispatch(*item), "unsupported")
        for parameter, value in [("circuit", 2), ("rate", 8), ("queries", 64)]:
            self.assertEqual(dispatch(3, 3, 1, 1, 1, **{parameter: value}), "unsupported")

    def test_disabled_new_mode_has_no_legacy_fallback(self):
        self.assertEqual(dispatch(3, 3, 1, 1, 1, enabled=False),
                         "unsupported:signature_mode_disabled")
        self.assertEqual(dispatch(3, 1, 1, 1, 1, enabled=False), "malformed_statement")

    def test_envelope_overhead_and_profile_receipt_size_arithmetic(self):
        # Empty variable sections: magic, version, size, time, mode/profile/family,
        # digest, circuit version/rate/queries/proof size. No mock proof is accepted.
        self.assertEqual(struct.calcsize(">4sBIQBHH32sIIII"), 70)
        self.assertEqual(70 + 4096 + 128 * 1024 * 1024, 134221894)
        for der_size in (8, 71):
            sig_size = der_size + 1
            pkh_tx_size = 61 + 1 + sig_size + 1 + 33
            wpkh_tx_size = 61 + 2 + 1 + 1 + sig_size + 1 + 33
            self.assertEqual(pkh_tx_size, 105 if der_size == 8 else 168)
            self.assertEqual(wpkh_tx_size, 108 if der_size == 8 else 171)
            self.assertLessEqual(44 + wpkh_tx_size, 215)

    def test_transcript_exact_layout_and_every_byte_binding(self):
        for vector in FIXTURE["vectors"]:
            with self.subTest(kind=vector["name"]):
                binding = transcript_binding(vector, bytes(range(1, 33)), 1_800_000_100)
                self.assertEqual(len(binding), 146)
                self.assertEqual(binding[:10].hex(), "51504531030100010001")
                self.assertEqual(binding[10:42].hex(), vector["d"])
                self.assertEqual(binding[42:62].hex(), vector["request"]["claims"][0]["program"])
                self.assertEqual(binding[62:94].hex(), vector["z"])
                self.assertEqual(binding[94:126], bytes(range(1, 33)))
                self.assertEqual(binding[126:138].hex(), "000000010000000400000080")
                seed = tagged_hash("QuietProof/signature/transcript/v1", binding)
                for offset in range(len(binding)):
                    changed = bytearray(binding)
                    changed[offset] ^= 1
                    self.assertNotEqual(seed, tagged_hash("QuietProof/signature/transcript/v1", changed))
                for old_tag in ("PoKC/transcript/v1", "PoKC/transcript/v2",
                                "QuietProof/P2SH-2of3/proof/v1"):
                    self.assertNotEqual(seed, tagged_hash(old_tag, binding))

    def test_receipt_framing_size_and_endianness_only(self):
        digest = bytes.fromhex(FIXTURE["vectors"][0]["d"])
        self.assertEqual(RECEIPT_HEADER.size, 44)
        # Opaque zero bodies below are NOT transactions or valid authorisation receipts.
        for size in (1, 4052):
            frame = receipt_frame(bytes(size), digest)
            self.assertEqual(len(frame), 44 + size)
            self.assertEqual(frame[:8].hex(), "5150413101010001")
            self.assertEqual(frame[8:40], digest)
            self.assertEqual(frame[40:44], size.to_bytes(4, "big"))
            self.assertEqual(inspect_receipt_framing(frame, digest), "framing_only")
        for size in (0, 4053):
            self.assertEqual(inspect_receipt_framing(receipt_frame(bytes(size), digest), digest),
                             "malformed_receipt")

    def test_receipt_truncation_lengths_suffix_and_magic(self):
        digest = bytes.fromhex(FIXTURE["vectors"][0]["d"])
        frame = receipt_frame(bytes(17), digest)
        for length in range(len(frame)):
            self.assertEqual(inspect_receipt_framing(frame[:length], digest), "malformed_receipt")
        self.assertEqual(inspect_receipt_framing(frame + b"\x00", digest), "malformed_receipt")
        for offset in (0, 40, 41, 42, 43):
            changed = bytearray(frame)
            changed[offset] ^= 1
            self.assertEqual(inspect_receipt_framing(changed, digest), "malformed_receipt")

    def test_receipt_ids_request_mismatch_and_disabled(self):
        digest = bytes.fromhex(FIXTURE["vectors"][0]["d"])
        for args in ({"version": 2}, {"mode": 2}, {"profile": 2}):
            self.assertEqual(inspect_receipt_framing(receipt_frame(b"\x00", digest, **args), digest),
                             "unsupported")
        frame = receipt_frame(b"\x00", digest)
        self.assertEqual(inspect_receipt_framing(frame, bytes(32)), "invalid_authorization")
        self.assertEqual(inspect_receipt_framing(frame, digest, enabled=False),
                         "unsupported:signature_mode_disabled")

    def test_public_receipt_mistake_rejected_by_magic(self):
        # A .qpf filename cannot turn QPA1 into a proof; no witness is echoed.
        self.assertEqual(classify_public_magic(b"QPA1private bytes"),
                         "malformed_statement:private_receipt_input")
        self.assertEqual(classify_public_magic(b"QPM1"), "parser_selection_only")
        self.assertEqual(classify_public_magic(b"QPE1"), "parser_selection_only")

    def test_normative_schema_anchors_and_no_production_digest(self):
        for anchor in ["fixed overhead is 70 bytes", "134221894", "exactly 146 bytes",
                       "header is exactly 44 bytes", "1..4052", "4096 bytes for the complete file",
                       "No production value of `I`", "53 field elements", "locally approved exact",
                       "QuietProof/signature/circuit/v1", "QuietProof/signature/transcript/v1",
                       "private_receipt_input", "signature_mode_disabled", "`malformed_receipt`",
                       "`invalid_authorization`"]:
            self.assertIn(anchor, SPEC)


if __name__ == "__main__":
    unittest.main(verbosity=2)
