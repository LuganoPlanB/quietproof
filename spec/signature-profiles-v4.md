# PoSC v4 signing profiles

For wallet selection and executed transport/proof coverage see the
[Sparrow matrix](../docs/guide/sparrow.md#observed-compatibility) and
[stock Core workflow](../docs/guide/core-signing.md).

This is the sole supported PoSC request, receipt and proof contract. Superseded
v3 requests/proofs and their v1 private receipts must be reissued; they are not
converted or accepted. PoKC v1/v2 remains a separate explicit proof mode.

## Closed procedure table

| Wire ID | Procedure version | Stable name | Allowed signer | Signature transport |
| --- | --- | --- | --- | --- |
| 1 | 1 | `bip322-ecdsa-v1` | P2WPKH or compressed P2PKH | Simple/Full for P2WPKH; Full for P2PKH |
| 2 | 1 | `bitcoin-message-ecdsa-v1` | compressed P2PKH only | canonical Base64 compact65-byte Bitcoin Signed Message |

Zero and all other IDs/versions are unsupported. P2WPKH kind is0 and P2PKH
kind is1. Address kind, procedure, transport, serialization version and circuit
identity are distinct. Raw Base64/helper JSON do not select a procedure.
Producer defaults are P2WPKH/BIP322 and P2PKH/Bitcoin Signed Message; explicit
P2PKH/BIP322 Full remains available. Ambiguous mixed-kind claims require an
explicit signer and procedure. Every claim retains the same compressed-key
HASH160; this contract does not aggregate unrelated signing keys.

## Request bytes and authority

`QPS1 || 04 || network:u8 || mode:u8=1 || profile:u16be || profile_version:u8=1
|| signer_kind:u8 || common_v2_payload` is canonical. The common payload is the
existing v2 statement after its six-byte magic/version/network prefix, with
the same bounded fields, sorted unique outpoints and strict UTF-8/canonical
length rules. The whole request remains at most4096bytes. No duplicate fields,
unknown flags, trailing bytes, bridge authorization or unsupported tuples are
permitted. Network is explicit; testnet3/testnet4/signet address prefixes are
insufficient to choose it. No v3 decoder or alias is a migration path.

All integers below are unsigned big endian; lengths count bytes. This is a
positional record with no optional extension fields or TLV field IDs. The
profile IDs in the table above are the only procedure IDs. After the fixed
11-byte header, the exact common payload order is:

| Field | Encoding and bound |
| --- | --- |
| verifier | `length:u16 || UTF-8`, 1..256 bytes |
| purpose | `length:u16 || UTF-8`, 1..64 bytes; exactly `proof-of-control` or `proof-of-funds` |
| nonce | 32 bytes, not all zero |
| user message commitment (`bip322_message_hash`) | 32 bytes, not all zero; distinct from the derived signing-message hash |
| not_before, expires_at | two `u64` values, `not_before < expires_at` |
| snapshot_present | `u8`, exactly 0 or 1 |
| snapshot (only when present) | nonzero 32-byte block hash in RPC/display order, then height `u32` |
| bridge_present | `u8`, exactly 0; no bridge payload is allowed |
| claim_count | `u16`, 1..16 |
| each claim | txid:32 in RPC/display order, vout:`u32`, amount_sats:`u64`, script_kind:`u8`, compressed-key HASH160:20 |

Text must be canonical UTF-8 without overlong sequences, surrogate code points,
code points above U+10FFFF, ASCII controls below U+0020, or U+007F. No Unicode
normalization is applied. Claims sort strictly by txid bytes then numeric vout;
duplicate outpoints are invalid. Each amount is 1..2,100,000,000,000,000 sats,
and their sum cannot exceed that bound. Every claim has one of the two known
script kinds and the same HASH160; the selected signer kind must occur among
the claims. The signing address is the network/kind encoding of that HASH160,
not an additional independently mutable text field. Mainnet, testnet3, signet,
regtest and testnet4 network IDs are respectively 0, 1, 2, 3 and 4.

The request digest is `TaggedHash("QuietProof/statement/v4", canonical_request)`.
The exact application message is88ASCII bytes:
`quietproof:signature:v4:` followed by64lowercase hex characters of that digest.
The prefix is24bytes. There is no newline, whitespace normalization or BOM.

For BIP322, derive the existing fixed `to_spend`/`to_sign` transactions and
SIGHASH_ALL digest from those bytes. P2WPKH uses BIP143; P2PKH Full uses legacy
transaction SIGHASH_ALL. For Bitcoin Signed Message, derive double-SHA256 of
`CompactSize(24) || "Bitcoin Signed Message:\n" || CompactSize(88) || message`.
These are different signing procedures and cannot share an authorization.
All hash inputs are reconstructed from the independently retained request;
neither a signature wrapper nor proof metadata may supply an authoritative z.

## Private receipt and public proof

The current private receipt framing is `QPA1 || 04 || mode:u8=1 || profile:u16be
|| profile_version:u8=1 || request_digest:32 || payload_length:u32be || payload`.
It is bounded to4096bytes and stored with the existing owner-only, exclusive
private IO. BIP322 payload is its canonical finalized fixed transaction. The
legacy payload is exactly65 bytes: `header:u8 || r:32be || s:32be`. Its receipt
is exactly110 bytes. Accept headers31..34 only: `31 + recovery_id`, where the
low recovery bit selects the parity of R and the high bit selects x(R)=r+n
rather than r. Require `1 <= r < n` and `1 <= s <= floor(n/2)`; reject high-S
without normalization or a recovery-header rewrite. Recover
`Q = r^-1(sR - (uint256_be(z) mod n)G)`, reject infinity/noncanonical/off-curve
points and require `HASH160(compressed_SEC(Q))` to equal the request signer.
The existing native ECDSA check independently validates the resulting Q/r/s.
The receipt preserves the exact validated compact bytes. No BIP322 transaction
or synthetic prevout is constructed for the Bitcoin Signed Message procedure.

The `bitcoin-message` transport is canonical padded RFC4648 Base64 of that
65-byte payload (exactly88 characters), without a prefix, newline, whitespace,
alternate alphabet or nonzero padding bits. `sparrow-json` is a local wrapper:
its network/address/script kind/message SHA256 are assertions against the
retained request and exact exported message. Optional `signingProfile` and
`profileVersion` assertions must also match. For a legacy request, Sparrow
`standard`, `electrum` and `bip137` labels name compact transports; they still
must contain compressed-P2PKH headers31..34. Wrappers cannot change the profile.
Uncompressed headers27..30 and SegWit-labelled headers35..42 are unsupported.
This strict low-S policy agrees with the inspected stock Drongo ECKey.signEcdsa
canonicalization; live installed-wallet qualification is a separate gate.
Unknown/unsupported procedures fail closed without another signer or proof mode.

Public proof framing is `QPE1 || 04 || request_length:u32be || request ||
proof_created_at:u64be || mode:u8 || profile:u16be || profile_version:u8 ||
circuit_family:u16be || circuit_digest:32 || circuit_version:u32be || rate:u32be
|| queries:u32be || proof_length:u32be || proof`. Fixed overhead is71bytes.
Both profile fields must equal the retained request's validated tuple. Old
versions and unknown tuples are rejected before proof allocation/parsing.

The transcript binding is147bytes: `QPE1 || 04 || mode:u8 || profile:u16be ||
profile_version:u8 || family:u16be || request_digest:32 || h:20 || z:32 ||
circuit_digest:32 || circuit_version:u32be || rate:u32be || queries:u32be ||
proof_created_at:u64be`, hashed with domain
`QuietProof/signature/transcript/v4`. The verifier reconstructs h/z itself.

Every supported procedure maps to the exact same approved ECDSA/HASH160
arithmetic circuit: family1, circuit version1, rate4, queries128, public inputs53,
digest `85fc9626e74e1944e736237c5f71220f982b05a3f786c491cf35ef2e56547d32`.
One request yields one ordinary PoSC proof. No procedure selects executable
circuits, arbitrary digests, aggregation or in-circuit message hashing.

Retained expected request, network/audience/purpose/time/quantity checks,
current chain evidence and durable nonce acceptance remain mandatory. PoSC
proves custody of an authorizing signature, including delegated custody.

Reference semantics: [BIP322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki),
[BIP137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki), and
[Core v30 message signing](https://github.com/bitcoin/bitcoin/blob/v30.0/src/common/signmessage.cpp).
The Core source link documents message semantics; it does not identify an
installed binary version. Local wallet qualification records its actual version.
