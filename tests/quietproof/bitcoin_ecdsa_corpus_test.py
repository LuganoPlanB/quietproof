#!/usr/bin/env python3
"""Feed all exactly representable corpus tuples to compiled ECDSA constraints.

Malformed serialized objects and >256-bit/infinite affine tuples have no exact
circuit input representation. They are accounted separately, never counted as
constraint rejection. No native cryptographic preverification runs here.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prototype", type=Path, required=True)
    args = parser.parse_args()
    corpus = json.loads((ROOT / "spec/signature-vectors.json").read_text())
    rows, expected, not_representable = [], {}, []
    for case in corpus["relation_cases"]:
        q = case["Q"]
        if q is None or any(int(q[c], 16) >= 2 ** 256 for c in ("x", "y")):
            not_representable.append(case["id"])
            continue
        raw = [case["z"], q["x"], q["y"], case["r"], case["s"]]
        rows.append(" ".join([case["id"], *raw, "none"]))
        expected[case["id"]] = case["expected"]["valid"]
        # Override advice after generation. These tuples satisfy the group
        # equation and base-field x equality, so the integer ranges must reject.
        mutation = ("branch_one" if case["id"] == "wrapped_r_plus_n" else
                    "branch_zero" if case["id"].startswith("rare_r_n_plus_k") else None)
        if mutation:
            name = case["id"] + "_malicious_branch"
            rows.append(" ".join([name, *raw, mutation]))
            expected[name] = False

    # Discriminating p-alias: x=1 has a point and p+1 fits in 256 bits. e=0,
    # r=s=1 makes R=Q; reducing x before validation would accept the alias.
    p = int(corpus["domains"]["p"], 16)
    y = pow(8, (p + 1) // 4, p)
    assert y * y % p == 8
    for name, x, valid in (("small_x_control", 1, True), ("small_x_p_alias", p + 1, False)):
        rows.append(f"{name} 0 {x:x} {y:x} 1 1 none")
        expected[name] = valid
    result = subprocess.run([str(args.prototype.resolve()), "--stream"], input="\n".join(rows) + "\n",
                            text=True, capture_output=True, timeout=120)
    # CTest's complete same-run log retains every case, including failures.
    print(result.stdout, end="")
    print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"constraint process failed ({result.returncode}): {result.stderr[-1000:]}")
    observed = {}
    for line in result.stdout.splitlines():
        if line.startswith("case "):
            _, name, status = line.split()
            if name in observed or status not in ("accepted", "constraint_rejected"):
                raise RuntimeError("unexpected/duplicate constraint result")
            observed[name] = status == "accepted"
    if observed != expected:
        failures = sorted(name for name in set(expected) | set(observed) if expected.get(name) != observed.get(name))
        raise RuntimeError(f"actual compiled constraint mismatch: {failures}")
    assert len(expected) > 0 and any(expected.values()) and not all(expected.values())
    print(json.dumps({"compiled_constraint_cases": len(expected), "accepted": sum(expected.values()),
                      "constraint_rejected": len(expected) - sum(expected.values()), "failed": 0, "skipped": 0,
                      "relation_without_exact_input": not_representable,
                      "malformed_wire_without_circuit_input": [c["id"] for c in corpus["malformed_cases"]]},
                     sort_keys=True))


if __name__ == "__main__":
    main()
