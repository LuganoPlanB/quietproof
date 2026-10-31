#!/usr/bin/env python3
"""Deterministic public Bitcoin ECDSA fixtures, never production cryptography.

Only Python integer arithmetic is used. No SDK, application code, signing
library, wallet, randomness or Sage is involved. Scalars/nonces below are public
test data. The optional external oracle is L2's test-only libsecp256k1 verifier.
"""

import argparse
from collections import Counter
import json
from pathlib import Path
import subprocess


# Coordinate arithmetic is modulo P; scalar arithmetic is modulo N. These are
# different primes. A digest is a 256-bit big-endian integer reduced modulo N.
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def on_curve(point):
    return (point is not None and 0 <= point[0] < P and 0 <= point[1] < P
            and (point[1] ** 2 - point[0] ** 3 - 7) % P == 0)


def negate(point):
    return None if point is None else (point[0], -point[1] % P)


def add(left, right):
    """Complete affine group law, including identity, inverse and doubling."""
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        slope = 3 * x1 * x1 * pow(2 * y1, -1, P) % P
    else:
        slope = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def multiply(scalar, point):
    # Do not reduce here: N*G == infinity is a real reference sanity check.
    require(scalar >= 0, "negative multiplier")
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def lift_x(x, parity):
    require(0 <= x < P and parity in (0, 1), "noncanonical point encoding")
    square = (x ** 3 + 7) % P
    y = pow(square, (P + 1) // 4, P)
    require(y * y % P == square, "x has no curve point")
    if y % 2 != parity:
        y = P - y
    point = (x, y)
    require(on_curve(point), "invalid lifted point")
    return point


def compressed(point):
    require(on_curve(point), "cannot encode an invalid affine point")
    return bytes([2 + point[1] % 2]) + point[0].to_bytes(32, "big")


def parse_compressed(raw):
    require(len(raw) == 33 and raw[0] in (2, 3), "compressed key shape")
    return lift_x(int.from_bytes(raw[1:], "big"), raw[0] & 1)


def der_signature(r, s):
    def integer(value):
        require(value >= 0, "negative DER fixture scalar")
        raw = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
        if raw[0] & 128:
            raw = b"\x00" + raw
        return b"\x02" + bytes([len(raw)]) + raw
    body = integer(r) + integer(s)
    return b"\x30" + bytes([len(body)]) + body


def parse_der(raw):
    # Encoding only: 0, N and N+1 have valid DER encodings but invalid ranges.
    require(8 <= len(raw) <= 72 and raw[:1] == b"\x30"
            and raw[1] == len(raw) - 2, "DER sequence")
    values, cursor = [], 2
    for _ in range(2):
        require(cursor + 2 <= len(raw) and raw[cursor] == 2, "DER integer tag")
        size = raw[cursor + 1]
        cursor += 2
        require(1 <= size <= 33 and cursor + size <= len(raw), "DER integer length")
        encoded = raw[cursor:cursor + size]
        require(not encoded[0] & 128, "negative DER integer")
        require(size == 1 or encoded[0] != 0 or encoded[1] & 128,
                "nonminimal DER integer")
        values.append(int.from_bytes(encoded, "big"))
        cursor += size
    require(cursor == len(raw), "trailing DER bytes")
    return tuple(values)


def point_json(point):
    return None if point is None else {"x": format(point[0], "x"), "y": format(point[1], "x")}


def evaluate(digest, q, r, s):
    """Frozen low-S relation, with rejection stage and the actual nonce point."""
    result = {"valid": False, "reason": None, "e": None, "u": None, "v": None,
              "R": None, "x_branch": None}
    if len(digest) != 32:
        result["reason"] = "digest_length"
        return result
    e = int.from_bytes(digest, "big") % N
    result["e"] = format(e, "x")
    if q is None:
        result["reason"] = "Q_infinity"
    elif not (0 <= q[0] < P and 0 <= q[1] < P):
        result["reason"] = "Q_noncanonical"
    elif not on_curve(q):
        result["reason"] = "Q_off_curve"
    elif not 1 <= r < N:
        result["reason"] = "r_range"
    elif not 1 <= s < N:
        result["reason"] = "s_range"
    elif s > N // 2:
        result["reason"] = "high_s"
    else:
        inv = pow(s, -1, N)
        u, v = e * inv % N, r * inv % N
        nonce = add(multiply(u, G), multiply(v, q))
        result.update(u=format(u, "x"), v=format(v, "x"), R=point_json(nonce))
        if nonce is None:
            result["reason"] = "R_infinity"
        elif nonce[0] % N != r:
            result["reason"] = "x_mismatch"
        else:
            result.update(valid=True, reason="accepted",
                          x_branch="r" if nonce[0] < N else "r+n")
    return result


def evaluate_wire(digest, der, key):
    if len(digest) != 32:
        return {"valid": False, "reason": "digest_encoding"}
    try:
        q = parse_compressed(key)
    except ValueError:
        return {"valid": False, "reason": "public_key_encoding"}
    try:
        r, s = parse_der(der)
    except ValueError:
        return {"valid": False, "reason": "signature_encoding"}
    return evaluate(digest, q, r, s)


def classification(reason):
    if reason == "accepted":
        return "accepted"
    if reason in ("R_infinity", "x_mismatch"):
        return "cryptographic_rejection"
    if reason in ("r_range", "s_range"):
        return "scalar_range_rejection"
    if reason == "high_s":
        return "low_s_rejection"
    return "malformed_input_rejection"


def relation_case(name, z, q, r, s, expected, tags, construction):
    digest = z.to_bytes(32, "big")
    result = evaluate(digest, q, r, s)
    require(result["reason"] == expected, f"{name}: expected {expected}, got {result['reason']}")
    # SEC carries x and parity only. Never substitute a different valid point
    # for an invalid raw tuple (e.g. a y+p alias or an off-curve y value).
    wire = ({"z": digest.hex(), "der": der_signature(r, s).hex(),
             "Q_compressed": compressed(q).hex()} if on_curve(q) else None)
    return {"id": name, "tags": tags, "construction": construction,
            "z": digest.hex(), "Q": point_json(q), "r": format(r, "x"),
            "s": format(s, "x"), "expected": result, "oracle_input": wire,
            "oracle_class": classification(result["reason"]) if wire else "not_encodable",
            "oracle_unavailable_reason": None if wire else
            "Invalid affine tuple has no exact canonical compressed SEC encoding; relation-only case."}


def sign_fixture(z, d, k):
    q, nonce = multiply(d, G), multiply(k, G)
    r = nonce[0] % N
    s = (z % N + r * d) * pow(k, -1, N) % N
    require(r != 0 and s != 0, "degenerate public signing fixture")
    return q, r, min(s, N - s)


def corpus():
    require(P != N and N < P < 2 * N and on_curve(G) and multiply(N, G) is None,
            "curve/domain sanity check")
    cases = []

    def append(name, z, q, r, s, expected="accepted", tags=(), construction="direct tuple"):
        case = relation_case(name, z, q, r, s, expected, list(tags), construction)
        cases.append(case)
        return case

    boundaries = [("zero", 0), ("one", 1), ("n_minus_one", N - 1), ("n", N),
                  ("n_plus_one", N + 1), ("p_minus_one", P - 1), ("p", P),
                  ("p_plus_one", P + 1), ("max256", 2 ** 256 - 1)]
    for label, z in boundaries:
        for q_label, d in (("G", 1), ("minus_G", N - 1)):
            q, r, s = sign_fixture(z, d, 2)
            append(f"digest_{label}_{q_label}", z, q, r, s,
                   tags=("digest_boundary", q_label), construction="public d=1 or n-1, nonce k=2; normalize s")

    # Deterministically choose a small x-offset, not a random nonce/discrete log.
    # Q = r^-1(sR-eG) makes the verification equation hold for x(R)=N+k.
    rare_k = next(k for k in range(1, 100) if pow(((N + k) ** 3 + 7) % P, (P - 1) // 2, P) == 1)
    for parity in (0, 1):
        for label, z in (("zero", 0), ("one", 1), ("n", N), ("p", P), ("max256", 2 ** 256 - 1)):
            nonce = lift_x(N + rare_k, parity)
            q = multiply(pow(rare_k, -1, N), add(nonce, negate(multiply(z % N, G))))
            case = append(f"rare_x_{label}_R_parity_{parity}", z, q, rare_k, 1,
                          tags=("rare_branch", "R_even" if parity == 0 else "R_odd"),
                          construction="x(R)=n+k<p; s=1; r=k; Q=r^-1(sR-eG)")
            require(case["expected"]["R"] == point_json(nonce), "rare branch reconstruction")
            require(case["expected"]["x_branch"] == "r+n", "missing rare branch")
            if z == 0:
                append(f"rare_r_n_plus_k_R_parity_{parity}", z, q, N + rare_k, 1,
                       "r_range", ("scalar_alias", "rare_branch"),
                       "replace r=k by r=n+k: rQ unchanged mod n and raw x(R)=r; range check must reject")
                append(f"rare_s_n_plus_one_R_parity_{parity}", z, q, rare_k, N + 1,
                       "s_range", ("scalar_alias", "rare_branch"),
                       "replace s=1 by s=n+1: inverse unchanged mod n; range check must reject")

    # Construct exact low-S edges without searching for signatures with that s.
    for s in (1, N // 2):
        nonce, e = multiply(3, G), 7
        r = nonce[0] % N
        q = multiply(pow(r, -1, N), add(multiply(s, nonce), negate(multiply(e, G))))
        append(f"low_s_edge_{'one' if s == 1 else 'half_n'}", e, q, r, s,
               tags=("low_s_boundary",), construction="R=3G; e=7; Q=r^-1(sR-eG)")
        append(f"high_s_twin_{'n_minus_one' if s == 1 else 'half_n_plus_one'}", e, q, r, N - s,
               "high_s", ("high_s",), "ECDSA-equivalent s -> n-s of preceding low-S case")

    q, r, s = sign_fixture(1, 1, 1)
    baseline = append("ordinary_G_nonce_one", 1, q, r, s,
                      tags=("ordinary_branch",), construction="public d=1, k=1, z=1")
    double_r = multiply(2, G)[0] % N
    append("equal_verification_addends", double_r, G, double_r, min(double_r, N - double_r),
           tags=("equal_addends", "G"), construction="e=r=x(2G); Q=G; low-S s=min(r,n-r); uG=vQ")
    for field in ("r", "s"):
        for label, value in (("zero", 0), ("n", N), ("n_plus_one", N + 1), ("max256", 2 ** 256 - 1)):
            append(f"{field}_{label}", 1, q, value if field == "r" else r,
                   value if field == "s" else s, f"{field}_range", ("scalar_boundary",),
                   f"replace {field} in ordinary_G_nonce_one; DER is structurally canonical")
    append("wrong_digest", 2, q, r, s, "x_mismatch", ("cryptographic_negative",), "change z only")
    append("wrong_key_parity", 1, negate(q), r, s, "x_mismatch",
           ("cryptographic_negative", "key_parity"), "change Q parity only")
    append("wrong_r", 1, q, r + 1, s, "x_mismatch", ("cryptographic_negative",), "increment r")
    append("wrong_s", 1, q, r, s + 1, "x_mismatch", ("cryptographic_negative",), "increment s")
    append("cancel_G", N - 1, G, 1, 1, "R_infinity", ("cancelling_sum", "G"),
           "eG+rQ=(n-1)G+G=infinity; all input ranges valid")
    append("cancel_minus_G", 1, negate(G), 1, 1, "R_infinity", ("cancelling_sum", "minus_G"),
           "eG+rQ=G-G=infinity; all input ranges valid")
    append("Q_infinity", 1, None, r, s, "Q_infinity", ("invalid_point",))
    append("Q_zero_tuple", 1, (0, 0), r, s, "Q_off_curve", ("invalid_point",))
    append("Q_off_curve_y", 1, (G[0], G[1] + 1), r, s, "Q_off_curve", ("invalid_point",))
    for name, point in (("x_p", (P, G[1])), ("y_p", (G[0], P)),
                        ("x_p_alias", (G[0] + P, G[1])), ("y_p_alias", (G[0], G[1] + P))):
        append(f"Q_{name}", 1, point, r, s, "Q_noncanonical", ("invalid_point", "p_boundary"))

    # A putative r+n branch may not wrap modulo p. Force the computed R to x=1
    # while r=p-n+1, so a faulty (r+n)%p comparison would accept this tuple.
    wrapped_r = P - N + 1
    wrapped_q = multiply(pow(wrapped_r, -1, N), add(lift_x(1, 0), negate(G)))
    wrapped_case = append("wrapped_r_plus_n", 1, wrapped_q, wrapped_r, 1, "x_mismatch",
                          ("r_plus_n_no_p_wrap",),
                          "R=lift_x(1,even); r=p-n+1; s=e=1; Q=r^-1(R-G); r+n=p+1 must not wrap")
    require(wrapped_case["expected"]["R"]["x"] == "1", "wrapped branch attack must reach x=1")

    raw = baseline["oracle_input"]
    digest, der, key = (bytes.fromhex(raw[name]) for name in ("z", "der", "Q_compressed"))
    malformed = []

    def malformed_case(name, z_raw=digest, der_raw=der, key_raw=key, reason="signature_encoding"):
        result = evaluate_wire(z_raw, der_raw, key_raw)
        require(result["reason"] == reason, f"{name}: malformed-input classification")
        malformed.append({"id": name, "oracle_input": {"z": z_raw.hex(), "der": der_raw.hex(),
                                                       "Q_compressed": key_raw.hex()},
                          "expected": result, "oracle_class": "malformed_input_rejection"})

    malformed_case("digest_short", z_raw=digest[:-1], reason="digest_encoding")
    malformed_case("digest_long", z_raw=digest + b"\x00", reason="digest_encoding")
    malformed_case("SEC_infinity", key_raw=b"\x00", reason="public_key_encoding")
    malformed_case("SEC_bad_prefix", key_raw=b"\x04" + key[1:], reason="public_key_encoding")
    malformed_case("SEC_uncompressed", key_raw=b"\x04" + G[0].to_bytes(32, "big") + G[1].to_bytes(32, "big"),
                   reason="public_key_encoding")
    malformed_case("SEC_x_p", key_raw=b"\x02" + P.to_bytes(32, "big"), reason="public_key_encoding")
    malformed_case("SEC_x_max256", key_raw=b"\x03" + b"\xff" * 32, reason="public_key_encoding")
    malformed_case("SEC_nonresidue_x_zero", key_raw=b"\x02" + bytes(32), reason="public_key_encoding")
    malformed_case("SEC_truncated", key_raw=key[:-1], reason="public_key_encoding")
    malformed_case("DER_empty", der_raw=b"")
    malformed_case("DER_trailing", der_raw=der + b"\x00")
    malformed_case("DER_truncated", der_raw=der[:-1])
    malformed_case("DER_negative_r", der_raw=bytes.fromhex("3006020180020101"))
    malformed_case("DER_nonminimal_r", der_raw=bytes.fromhex("300702020001020101"))
    malformed_case("DER_bad_tag", der_raw=b"\x31" + der[1:])

    require(len({c["id"] for c in cases + malformed}) == len(cases) + len(malformed), "duplicate IDs")
    valid = [c for c in cases if c["expected"]["valid"]]
    require({c["expected"]["x_branch"] for c in valid} == {"r", "r+n"}, "both branches required")
    for field in ("Q", "R"):
        points = [c[field] if field == "Q" else c["expected"][field] for c in valid]
        require({int(point["y"], 16) % 2 for point in points} == {0, 1}, f"both {field} parities required")
    return {"format": "quietproof-signature-vectors-v1",
            "status": "public deterministic test fixtures; not wallet authorisations or circuit evidence",
            "integer_encoding": "unsigned hexadecimal without 0x; z is exactly 32 big-endian bytes; null point is infinity",
            "domains": {"p": format(P, "x"), "n": format(N, "x"), "G": point_json(G),
                        "coordinate_arithmetic": "mod p, but Q coordinates must be canonical before arithmetic",
                        "scalar_arithmetic": "mod n; e=BE256(z) mod n; 1<=r<n; 1<=s<=floor(n/2)",
                        "nonce_point": "finite R=s^-1(eG+rQ); x(R)=r OR x(R)=r+n<p; no p wrap"},
            "oracle_contract": {"binary": "quietproof-signing-oracle (L2, test-only libsecp256k1 0.8.1)",
                                "argv": ["z hex", "strict DER hex (no sighash byte)", "compressed SEC hex"],
                                "not_encodable": "Explicit relation-only cases, not skipped or executed oracle tests",
                                "rejections": "Malformed/range/low-S cases are not cryptographic negatives; only canonical in-range inputs reach the ECDSA equation"},
            "rare_branch_k": rare_k, "relation_cases": cases, "malformed_cases": malformed}


def check_oracle(document, oracle):
    counts = Counter()
    for case in document["relation_cases"] + document["malformed_cases"]:
        wire = case["oracle_input"]
        if wire is None:
            counts["relation_only_not_encodable"] += 1
            continue
        args = [str(oracle), wire["z"], wire["der"], wire["Q_compressed"]]
        try:
            result = subprocess.run(args, capture_output=True, timeout=5, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise ValueError(f"{case['id']}: oracle execution failed") from None
        valid = case["expected"]["valid"]
        require(result.returncode == (0 if valid else 1)
                and result.stdout == (b"valid\n" if valid else b"invalid\n") and not result.stderr,
                f"{case['id']}: oracle disagrees or failed (exit {result.returncode})")
        counts[case["oracle_class"]] += 1
    require(counts["accepted"] > 0 and counts["cryptographic_rejection"] > 0,
            "oracle must execute positive and cryptographic-negative controls")
    counts["executed"] = sum(counts.values()) - counts["relation_only_not_encodable"]
    counts["failed"], counts["skipped"] = 0, 0
    return dict(sorted(counts.items()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", type=Path)
    group.add_argument("--output", type=Path)
    parser.add_argument("--oracle", type=Path, help="execute the L2 native verification oracle on every encodable case")
    args = parser.parse_args()
    try:
        document = corpus()
        text = json.dumps(document, indent=2) + "\n"
        if args.check:
            require(args.check.read_bytes() == text.encode("utf-8"), "signature vectors differ; inspect before regenerating")
            print(f"Signature vectors match: {len(document['relation_cases'])} relation cases, "
                  f"{len(document['malformed_cases'])} malformed cases")
        if args.oracle:
            print("Oracle agreement: " + json.dumps(check_oracle(document, args.oracle.resolve()), sort_keys=True))
        if args.output:
            args.output.write_text(text, encoding="utf-8")
        elif not args.check and not args.oracle:
            print(text, end="")
    except (OSError, ValueError) as error:
        parser.exit(1, f"signature vectors: {error}\n")


if __name__ == "__main__":
    main()
