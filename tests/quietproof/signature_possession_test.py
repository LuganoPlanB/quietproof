#!/usr/bin/env python3
"""Independent HASH160 targets and raw/advice attacks on composed constraints.

Only case identities and decisions are printed. All inputs are disposable public
reference tuples; no receipt/native preverification or secret scalar is used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--circuit", type=Path, required=True)
    args = parser.parse_args()
    corpus = json.loads((ROOT / "spec/signature-vectors.json").read_text())
    p = int(corpus["domains"]["p"], 16)
    rows, expected, unrepresentable = [], {}, []

    def key_hash(x, y):
        sec = bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
        return hashlib.new("ripemd160", hashlib.sha256(sec).digest()).hexdigest()

    def add(name, raw, valid, mutation="none", target=None):
        assert name not in expected
        x, y = (int(raw[i], 16) for i in (1, 2))
        target = key_hash(x, y) if target is None else target
        rows.append(" ".join([name, *raw, target, mutation]))
        expected[name] = valid

    valid_cases = []
    for case in corpus["relation_cases"]:
        q = case["Q"]
        if q is None or any(int(q[c], 16) >= 2**256 for c in ("x", "y")):
            unrepresentable.append(case["id"])
            continue
        raw = [case["z"], q["x"], q["y"], case["r"], case["s"]]
        valid = case["expected"]["valid"]
        add(case["id"], raw, valid)
        if valid:
            valid_cases.append(raw)
        if case["id"] == "wrapped_r_plus_n":
            add(case["id"] + "_branch_one", raw, False, "branch_one")
        if case["id"].startswith("rare_r_n_plus_k"):
            add(case["id"] + "_branch_zero", raw, False, "branch_zero")

    y = pow(8, (p + 1) // 4, p)
    add("small_x_control", ["0", "1", f"{y:x}", "1", "1"], True)
    add("small_x_p_alias", ["0", f"{p+1:x}", f"{y:x}", "1", "1"], False)
    baseline = valid_cases[0]
    x, y = (int(baseline[i], 16) for i in (1, 2))
    honest_hash = key_hash(x, y)
    for i in range(20):
        wrong = bytearray.fromhex(honest_hash)
        wrong[i] ^= 1
        add(f"wrong_hash_{i}", baseline, False, target=wrong.hex())
    for i in range(32):
        raw = baseline.copy()
        changed = int(raw[0], 16) ^ (1 << (8 * i))
        raw[0] = f"{changed:064x}"
        add(f"wrong_digest_{i}", raw, False, target=honest_hash)
    # Whole valid key/hash/trace substitution defeats a composition with an
    # independent private SEC key. Test both opposite parity and different x.
    others = [(x, p-y)]
    others.extend((int(v[1], 16), int(v[2], 16)) for v in valid_cases
                  if int(v[1], 16) != x)
    assert len(others) > 1
    for i, (ox, oy) in enumerate(others[:2]):
        add(f"coherent_hash_key_splice_{i}", baseline, False,
            f"sha_splice {ox:x} {oy:x}", key_hash(ox, oy))
    other_signature = next(v for v in valid_cases if v[3:] != baseline[3:])
    add("signature_key_splice", baseline[:3] + other_signature[3:], False)
    add("affine_infinity_placeholder", [baseline[0], "0", "0", *baseline[3:]], False)

    # Mutate actual input slots after honest advice, leaving all dependent
    # values untouched. Cover all coordinate/scalar bit positions, all table
    # and trace coordinates, and every packed SHA advice element.
    private_start, ecdsa_size = 53, 1805
    for i in range(ecdsa_size + 1472):
        add(f"private_input_{i}", baseline, False, f"add {private_start+i}")
    for i in range(1, 53):
        add(f"public_plucker_{i}", baseline, False, f"add {i}")
    for i in range(4 + 255):
        offset = 1027 + 3*i if i < 4 else 1039 + 3*(i-4)
        add(f"zero_projective_{i}", baseline, False, f"zero_point {private_start+offset}")

    print(f"intended cases={len(expected)} accepted={sum(expected.values())} "
          f"constraint_rejected={len(expected)-sum(expected.values())}", flush=True)
    result = subprocess.run([str(args.circuit.resolve())], input="\n".join(rows) + "\n",
                            text=True, capture_output=True, timeout=1750)
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    if result.returncode:
        raise RuntimeError(f"constraint process failed: exit {result.returncode}")
    observed = {}
    for line in result.stdout.splitlines():
        if line.startswith("case "):
            _, name, status = line.split()
            if name in observed or status not in ("accepted", "constraint_rejected"):
                raise RuntimeError("duplicate/unrecognized constraint result")
            observed[name] = status == "accepted"
    if observed != expected:
        failures = sorted(n for n in set(expected) | set(observed) if expected.get(n) != observed.get(n))
        raise RuntimeError(f"composed constraint mismatch: {failures}")
    print(json.dumps({"executed": len(expected), "accepted": sum(expected.values()),
                      "constraint_rejected": len(expected)-sum(expected.values()),
                      "failed": 0, "skipped": 0, "unrepresentable_reference_rows": unrepresentable,
                      "coverage": "compiled assertions; no native prevalidation"}, sort_keys=True))


if __name__ == "__main__":
    main()
