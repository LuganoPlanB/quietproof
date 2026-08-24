#!/usr/bin/env python3
"""Keep required normative specification anchors from silently disappearing."""

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
text = (ROOT / "spec/quietproof-v1.md").read_text(encoding="utf-8")
required = [
    "## 1. Conventions and constants",
    "## 2. Network identifiers",
    "## 3. Circuit input layout and identity",
    "## 4. Canonical statement encoding",
    "## 7. Verification and result selection",
    "program = RIPEMD160(SHA256(SEC))",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",
    "invalid_proof",
    "valid_current",
    "testnet3",
    "testnet4",
    "signet",
    'TaggedHash("QuietProof/statement/v1"',
    "2,100,000,000,000,000",
]
missing = [anchor for anchor in required if anchor not in text]
if missing:
    print("missing specification anchors: " + ", ".join(missing), file=sys.stderr)
    sys.exit(1)

order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
prime = "fffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"
source_text = "\n".join(
    (ROOT / path).read_text(encoding="utf-8").lower()
    for path in ("scripts/generate_pokc_vectors.py", "spec/pokc_reference.sage")
)
if order not in source_text or prime not in source_text:
    print("repository secp256k1 constants no longer match the normative specification", file=sys.stderr)
    sys.exit(1)

statement_source = (ROOT / "include/quietproof/statement.h").read_text(encoding="utf-8")
required_source = [
    "kTestnet3 = 1",
    "kSignet = 2",
    "kRegtest = 3",
    "kTestnet4 = 4",
    'QuietProofTaggedHash("QuietProof/statement/v1"',
    "kQuietProofMaxStatementBytes = 4096",
]
missing_source = [anchor for anchor in required_source if anchor not in statement_source]
if missing_source:
    print("statement implementation no longer matches normative anchors: " +
          ", ".join(missing_source), file=sys.stderr)
    sys.exit(1)
