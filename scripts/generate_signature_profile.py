#!/usr/bin/env python3
"""Public specification fixtures only: no wallet, signer or production codec."""

import argparse
import copy
import hashlib
import json
from pathlib import Path


BIPS_REVISION = "5aadddb511a5dcfe4599531bd8ae5e5b96d0f793"
MAX_MONEY = 2_100_000_000_000_000
PUBLIC_SEC = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"


def sha256(data):
    return hashlib.sha256(data).digest()


def sha256d(data):
    return sha256(sha256(data))


def tagged_hash(tag, data):
    tag_digest = sha256(tag.encode("ascii"))
    return sha256(tag_digest + tag_digest + data)


def compact_size(value):
    if value < 0 or value > 0xffffffffffffffff:
        raise ValueError("CompactSize out of range")
    if value < 253:
        return bytes([value])
    if value <= 0xffff:
        return b"\xfd" + value.to_bytes(2, "little")
    if value <= 0xffffffff:
        return b"\xfe" + value.to_bytes(4, "little")
    return b"\xff" + value.to_bytes(8, "little")


def varbytes(data):
    return compact_size(len(data)) + data


def p2pkh(program):
    return b"\x76\xa9\x14" + program + b"\x88\xac"


def script_for(kind, program):
    if kind not in (0, 1) or len(program) != 20:
        raise ValueError("unsupported script")
    return b"\x00\x14" + program if kind == 0 else p2pkh(program)


def serialize_request(request):
    """Encode the deliberately small public-fixture model, recording all fields."""
    if (request["network"] not in range(5) or
            request.get("profile", 1) not in (1, 2) or
            request.get("profile_version", 1) != 1 or
            (request.get("profile", 1) == 2 and request["signing_kind"] != 1) or
            request["purpose"] not in ("proof-of-control", "proof-of-funds") or
            request["signing_kind"] not in (0, 1) or
            not 0 <= request["not_before"] < request["expires_at"] < 2**64):
        raise ValueError("invalid request header")
    claims = request["claims"]
    if not 1 <= len(claims) <= 16:
        raise ValueError("claim count")
    keys = [(bytes.fromhex(c["txid_display"]), c["vout"]) for c in claims]
    if keys != sorted(set(keys)):
        raise ValueError("unsorted/duplicate outpoints")
    if (len({c["program"] for c in claims}) != 1 or
            request["signing_kind"] not in {c["script_kind"] for c in claims} or
            any(not 1 <= c["amount_sats"] <= MAX_MONEY for c in claims) or
            sum(c["amount_sats"] for c in claims) > MAX_MONEY):
        raise ValueError("claim relation")
    encoded = bytearray()
    fields = []

    def field(name, data):
        fields.append({"field": name, "offset": len(encoded), "size": len(data)})
        encoded.extend(data)

    def integer(name, value, size):
        field(name, value.to_bytes(size, "big"))

    def fixed_hex(name, value, size, nonzero=False):
        data = bytes.fromhex(value)
        if len(data) != size or (nonzero and not any(data)):
            raise ValueError(name)
        field(name, data)

    def text(name, value, maximum):
        data = value.encode("utf-8")
        if not 1 <= len(data) <= maximum or any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError(name)
        integer(name + ".length", len(data), 2)
        field(name, data)

    field("magic", b"QPS1")
    integer("statement_version", 4, 1)
    integer("network", request["network"], 1)
    integer("mode", 1, 1)
    integer("profile", request.get("profile", 1), 2)
    integer("profile_version", request.get("profile_version", 1), 1)
    integer("signing_kind", request["signing_kind"], 1)
    text("verifier", request["verifier"], 256)
    text("purpose", request["purpose"], 64)
    fixed_hex("nonce", request["nonce"], 32, True)
    fixed_hex("bip322_message_hash", request["bip322_message_hash"], 32, True)
    integer("not_before", request["not_before"], 8)
    integer("expires_at", request["expires_at"], 8)
    snapshot = request["snapshot"]
    integer("snapshot_present", int(snapshot is not None), 1)
    if snapshot is not None:
        fixed_hex("snapshot.hash_display", snapshot["hash_display"], 32, True)
        integer("snapshot.height", snapshot["height"], 4)
    integer("bridge_present", 0, 1)
    integer("claim_count", len(claims), 2)
    for index, claim in enumerate(claims):
        prefix = f"claims[{index}]."
        fixed_hex(prefix + "txid_display", claim["txid_display"], 32, True)
        integer(prefix + "vout", claim["vout"], 4)
        integer(prefix + "amount_sats", claim["amount_sats"], 8)
        integer(prefix + "script_kind", claim["script_kind"], 1)
        script_for(claim["script_kind"], bytes.fromhex(claim["program"]))
        fixed_hex(prefix + "program", claim["program"], 20)
    if len(encoded) > 4096:
        raise ValueError("request too large")
    return bytes(encoded), fields


def virtual_transactions(message_hash, script):
    zero4, zero8 = bytes(4), bytes(8)
    to_spend = (zero4 + b"\x01" + bytes(32) + b"\xff" * 4 +
                varbytes(b"\x00\x20" + message_hash) + zero4 +
                b"\x01" + zero8 + varbytes(script) + zero4)
    outpoint = sha256d(to_spend) + zero4  # raw hash bytes, not displayed txid
    output = zero8 + b"\x01\x6a"
    to_sign = zero4 + b"\x01" + outpoint + b"\x00" + zero4 + b"\x01" + output + zero4
    return to_spend, to_sign, outpoint, output


def bip143_preimage(version, prevouts, sequences, outpoint, script_code,
                    amount, sequence, outputs, locktime):
    return (version.to_bytes(4, "little") + sha256d(prevouts) + sha256d(sequences) +
            outpoint + varbytes(script_code) + amount.to_bytes(8, "little") +
            sequence.to_bytes(4, "little") + sha256d(outputs) +
            locktime.to_bytes(4, "little") + b"\x01\x00\x00\x00")


def _signing_values(encoded, kind, program):
    """Internal byte construction; also used for deliberately invalid mutations."""
    d = tagged_hash("QuietProof/statement/v4", encoded)
    message = b"quietproof:signature:v4:" + d.hex().encode("ascii")
    message_hash = tagged_hash("BIP0322-signed-message", message)
    script = script_for(kind, program)
    to_spend, to_sign, outpoint, output = virtual_transactions(message_hash, script)
    script_code = p2pkh(program)
    if kind == 1:
        preimage = (bytes(4) + b"\x01" + outpoint + varbytes(script_code) + bytes(4) +
                    b"\x01" + output + bytes(4) + b"\x01\x00\x00\x00")
    else:
        preimage = bip143_preimage(0, outpoint, bytes(4), outpoint, script_code,
                                  0, 0, output, 0)
    return {
        "d": d.hex(), "application_message_ascii": message.decode("ascii"),
        "application_message_hex": message.hex(), "application_message_hash": message_hash.hex(),
        "selected_script_pubkey": script.hex(), "script_code": script_code.hex(),
        "to_spend_hex": to_spend.hex(), "to_spend_txid_raw": sha256d(to_spend).hex(),
        "to_spend_txid_display": sha256d(to_spend)[::-1].hex(),
        "to_sign_unsigned_hex": to_sign.hex(), "to_sign_input_outpoint_wire": outpoint.hex(),
        "sighash_preimage_hex": preimage.hex(), "z": sha256d(preimage).hex(),
        "bip143_components": None if kind else {
            "hash_prevouts": sha256d(outpoint).hex(),
            "hash_sequence": sha256d(bytes(4)).hex(), "hash_outputs": sha256d(output).hex(),
        },
    }


def derive_request(request):
    """Valid fixture path: all signing inputs come from the expected request."""
    encoded, fields = serialize_request(request)
    program = bytes.fromhex(request["claims"][0]["program"])
    return encoded, fields, _signing_values(encoded, request["signing_kind"], program)


def make_vector(kind):
    program = hashlib.new("ripemd160", sha256(bytes.fromhex(PUBLIC_SEC))).hexdigest()
    request = {
        "network": 3, "verifier": "auditor.example", "purpose": "proof-of-funds",
        "signing_kind": kind, "profile": 1, "profile_version": 1,
        "nonce": bytes(range(1, 33)).hex(),
        "user_message_utf8": "public specification fixture; never wallet funds",
        "not_before": 1_800_000_000, "expires_at": 1_800_000_600,
        "snapshot": None if kind == 1 else {"hash_display": bytes(range(64, 96)).hex(), "height": 321},
        "claims": [
            {"txid_display": bytes(range(32)).hex(), "vout": 0x01020304,
             "amount_sats": 123456, "script_kind": 0, "program": program},
            {"txid_display": bytes(range(32, 64)).hex(), "vout": 7,
             "amount_sats": 654321, "script_kind": 1, "program": program},
        ],
    }
    request["bip322_message_hash"] = tagged_hash(
        "BIP0322-signed-message", request["user_message_utf8"].encode("utf-8")).hex()
    encoded, fields, values = derive_request(request)
    mutations = []
    for field in fields:
        changed = bytearray(encoded)
        changed[field["offset"]] ^= 1
        # Deliberately hash even malformed byte mutations to measure binding only.
        modified = _signing_values(changed, kind, bytes.fromhex(program))
        mutations.append({**field, "mutation": "xor first byte with 01; digest sensitivity only",
                          "d": modified["d"], "z": modified["z"]})
    byte_results = []
    for offset in range(len(encoded)):
        changed = bytearray(encoded)
        changed[offset] ^= 1
        modified = _signing_values(changed, kind, bytes.fromhex(program))
        if modified["d"] == values["d"] or modified["z"] == values["z"]:
            raise ValueError("mutation failed to change request binding")
        byte_results.append(bytes.fromhex(modified["d"] + modified["z"]))
    # A valid kind change must also reconstruct the other selected script/preimage.
    other = copy.deepcopy(request)
    other["signing_kind"] ^= 1
    _, _, other_values = derive_request(other)
    binding = (b"QPE1\x04\x01\x00\x01\x01\x00\x01" + bytes.fromhex(values["d"]) +
               bytes.fromhex(program) + bytes.fromhex(values["z"]) + bytes(range(1, 33)) +
               (1).to_bytes(4, "big") + (4).to_bytes(4, "big") + (128).to_bytes(4, "big") +
               (1_800_000_100).to_bytes(8, "big"))
    assert len(binding) == 147
    return {"name": "p2wpkh" if kind == 0 else "p2pkh", "request": request,
            "request_hex": encoded.hex(), "request_size": len(encoded), **values,
            "fields": fields, "field_mutations": mutations,
            "byte_mutation_count": len(byte_results),
            "byte_mutation_result_sha256": sha256(b"".join(byte_results)).hex(),
            "transcript_binding_hex": binding.hex(),
            "transcript_seed": tagged_hash("QuietProof/signature/transcript/v4", binding).hex(),
            "valid_selected_kind_change": {"d": other_values["d"], "z": other_values["z"]}}


def corpus():
    legacy_request = copy.deepcopy(make_vector(1)["request"])
    legacy_request["profile"] = 2
    encoded, fields = serialize_request(legacy_request)
    digest = tagged_hash("QuietProof/statement/v4", encoded)
    message = b"quietproof:signature:v4:" + digest.hex().encode("ascii")
    preimage = varbytes(b"Bitcoin Signed Message:\n") + varbytes(message)
    legacy = {"name": "p2pkh-bitcoin-message", "request": legacy_request,
              "request_hex": encoded.hex(), "request_size": len(encoded), "fields": fields,
              "d": digest.hex(), "application_message_ascii": message.decode("ascii"),
              "legacy_preimage_hex": preimage.hex(), "legacy_z": sha256d(preimage).hex()}
    return {"format": "quietproof-signature-profile-v1", "status": "public specification fixtures; no signer or production implementation",
            "generator": "scripts/generate_signature_profile.py (stdlib hashlib, direct byte construction)",
            "provenance": {"bips_revision": BIPS_REVISION,
                           "bip0322_sha256": "bdf1e930211356666e11d4961acff7a1675a280fba7b57377b48a1fb2f1b45b9",
                           "bip0143_sha256": "62bc71351563e68baeb12643c68355d217953ae9eb6a6e68b2b0323275b6beec",
                           "core_version": "32.1", "core_source_archive_sha256": "a5f2f61e32cf7f790641c9ec306a3c88ca7b5a556946956b1f35ffd7e27813f9"},
            "request_version": 4, "public_test_sec": PUBLIC_SEC,
            "vectors": [make_vector(1), make_vector(0)], "legacy_vectors": [legacy]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--check", type=Path)
    group.add_argument("--output", type=Path)
    args = parser.parse_args()
    text = json.dumps(corpus(), indent=2) + "\n"
    if args.check:
        if args.check.read_text(encoding="utf-8") != text:
            parser.exit(1, "signature profile fixture differs; inspect the profile before regenerating\n")
        print("Signature profile fixtures match: 2 profiles; every request byte mutation changes d and z")
    elif args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
