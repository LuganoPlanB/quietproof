# QuietProof signature-possession v1

Status: **implemented optional profile; local qualification has explicit limits**.
This document specifies an additive, explicitly selected mode. It does not
change the implemented [key-knowledge protocol](quietproof-v1.md), its proof
meaning, APIs, wire bytes, circuit identities, defaults or GUI behaviour.
Sections 7 through 11 freeze the signing profile and public byte fixtures.
Sections 12 through 15 freeze envelope dispatch, transcript and private receipt
rules. Production codecs, native wallet/receipt/proof verification and public
WASM/browser support implement this contract. Stock Core32.1 isolated regtest
and retained current-source cohorts support the documented scope. Original L5.3
integrated malicious fresh-proof/advice attacks were user-waived and remain
unexecuted/unqualified; no external audit or universal formal theorem is claimed.

The independent [PoSC (Proof of Signature Custody) Sage model](README.md#posc-signature-custody)
checks the ECDSA/HASH160 mathematical relation and frozen request/digest
derivation against Python vectors and actual C++ constraints. This reference
name does not introduce another wire mode or change circuit identity.

## 1. Claim and scope

For the verifier's independently issued, retained expected request, the new
mode proves knowledge of a signature authorising **that exact request** under
a compressed secp256k1 public key `Q` whose HASH160 is the claimed public hash
`h`. The signature and `Q` are private circuit witnesses. The independently
derived ECDSA digest `z` and exact `h` are public circuit inputs. A transcript
commitment to `z` alone MUST NOT replace its constrained public input.

The relation requires a finite, canonical, on-curve `Q`, its canonical
compressed SEC encoding, `HASH160(SEC_compressed(Q)) = h`, and a valid strict
low-S ECDSA signature for `z`. Native witness validation is additional defence;
it MUST NOT replace arithmetic constraints on that relation.

This is **signature knowledge**, not knowledge of the private scalar. It does
not establish exclusive control, legal ownership, reserved funds, solvency,
all holdings, or when the wallet signed. An authorised signature may be handed
to another prover for the same request. The verifier cannot infer that the
person producing the proof is the wallet's operator.

Initial scope is 1..16 sorted, unique real outpoints sharing one compressed-key
HASH160. Supported scripts are compressed-key P2PKH and native P2WPKH; one
request may contain both kinds for that hash. The selected signing kind MUST
occur among the request's claims and actually be available in the wallet.
A `wpkh` descriptor does not imply a `pkh` alias or permission to change kinds.
Stock Bitcoin Core 32.1 descriptor wallets are the locally qualified signing
target; other wallet/version combinations need their own evidence.

Taproot, wrapped SegWit, uncompressed keys, multiple independent keys,
multisignature signature circuits, private amounts, hardware signers, general
Script/BIP-322 verification, PSBT/UI signing, hosted proving and transaction
broadcast are outside this profile. Existing support in other modes is
unaffected. Signature mode MUST NOT authorise a bridge operation.

## 2. Wallet, prover and verifier boundaries

| Component | Required responsibility | Information it receives |
| --- | --- | --- |
| Request issuer/verifier | Issue a fresh unpredictable nonce; retain the expected canonical request and independent chain/replay policy. | Public claims, network, verifier, purpose, validity window, optional snapshot and user-message commitment. |
| Trusted wallet adapter | Validate the request and construct/check only the fixed virtual signing transaction before requesting wallet authorisation. Require the selected wallet script, compressed key, strict DER, low-S and `SIGHASH_ALL`. | Request, wallet identity, resulting signature and public key; no private-key export. |
| Bitcoin Core wallet | Keep the scalar within the wallet and sign the validated virtual transaction. | Synthetic signing transaction and explicit zero-valued virtual prevout. |
| Native prover | Reconstruct the expected signing digest, validate a local/private receipt, then prove the signature/HASH160 relation. | Expected request, `Q`, signature and constrained advice; no scalar required. |
| Public verifier | Require exact expected-request equality, supported mode/profile/circuit identity, valid proof, independently checked real outputs and final replay/expiry acceptance. | Public request and proof; no receipt, `Q` or signature required. |
| Chain provider | Supply explicitly qualified current or authenticated historical output evidence under the verifier's policy. | Real outpoints and chain constraints; no secret witness required. |

No signing failure or unsupported wallet may trigger key export, free-digest
signing, a different signing kind, or a fallback into another proof mode. The
adapter MUST NOT accept a caller-supplied raw transaction or arbitrary digest,
fund a transaction, broadcast, or automatically unlock a wallet on this path.
Existing explicit export workflows retain their separate behaviour.

## 3. Delegation, privacy and freshness

The wallet operator can prove locally or export a private `.qpa` authorisation
receipt to an offline or delegated native prover. The receipt reveals `Q` and
the signature to its holder. It is a **private authorisation capability**:
any holder can produce new proofs for the authorised request, within its
expiry and the verifier's replay policy, without knowing the scalar.
Copying a receipt does not create a new request or a new nonce.

Receipts MUST NOT be published, uploaded to a public verification page,
embedded in a `.qpf`, or included in public logs/fixtures. Public fixtures use
only deliberately public test material. Receipt import is a local native
witness workflow; a public proof is a separate QuietProof ZK envelope, not a
standard BIP-322 proof-of-funds export.

A public proof hides `Q`, the signature and advice under the proof system's
zero-knowledge assumptions. Outpoints, key hashes, amounts and request fields
remain public and linkable. A chain provider can also observe queried
outpoints. Earlier on-chain spends or key reuse may already disclose `Q`;
hiding it in a new proof cannot undo that exposure or promise anonymity.

A fresh verifier nonce binds authorisation to a request. Request validity
times and any prover-supplied proof timestamp are local-clock assertions,
not trusted timestamps. Neither a newly produced proof nor a new timestamp
establishes when a reused authorised signature was created. Atomic nonce
consumption limits acceptance at the verifier; it cannot prevent a receipt
holder from computing multiple proofs or racing another holder.

## 4. Funds and non-spending invariants

Cryptographic validity alone says nothing about whether a real output exists
or is unspent. The verifier MUST independently check every real claimed
outpoint, exact kind-selected script, network and amount, then calculate the
checked sum under explicit confirmation and chain/snapshot policy. Current
and historical results remain distinct. Provider failure or missing evidence
is inconclusive, never sufficient evidence of funds.

Report an **unspent quantity** under that policy. An immediately-spendable
label additionally requires maturity checks. Chain observations neither
reserve funds nor create an atomic mempool snapshot; spending or a reorg can
change the result. No liabilities are checked, so this is not solvency.
After proof and chain work, acceptance MUST atomically check final expiry and
consume the verifier nonce. A stale request MUST NOT become acceptable because
verification started before expiry.

The native signature verifier defaults to `kValidatedCurrentNode`. It checks
`getblockchaininfo.initialblockdownload = false` and requires Core32's **last**
`getchainstates.chainstates` entry to match the observed block hash/height and
have boolean `validated = true`. A validated background entry does not qualify
an unvalidated active snapshot. Missing, malformed or unavailable readiness is
inconclusive. Readiness observations bracket all output lookups; every lookup
and both observations must agree on one tip. `gettxout` includes mempool spends
(`include_mempool = true`); null remains ambiguous between spent and missing.

Maximum tip age defaults are explicit: mainnet 7,200 seconds; testnet3,
testnet4 and signet 86,400 seconds; isolated regtest 3,600 seconds. A tip more
than 7,200 seconds ahead of the verifier clock also fails. Local callers may
select a different positive maximum age (`--max-tip-age` in the CLI); no proof
field changes this policy. These are observation requirements, not a guarantee
that all peer or mempool information is current.

`kQualifiedCurrentProvider` is an explicit alternative that can report checked
quantity but always remains inconclusive for native validated-node acceptance.
`kRecordedHistoricalSnapshot` instead requires the request's recorded snapshot
hash/height and a historical provider; it applies that recorded policy without
current-tip age or IBD checks. A snapshot request cannot silently select this
trust policy. All successful observations still need final expiry/nonce checks.
Native output labels the amount `unspent_quantity`, never immediately spendable.
Optional boolean `gettxout.coinbase` metadata distinguishes an immature coinbase
(fewer than 100 confirmations) from unknown maturity; its absence cannot support
a maturity claim. Neither signature possession nor this label reserves outputs.

Signature verification uses an injectable `QuietProofClock` (system UTC by
default), rather than the scalar API's fixed `policy.now`. It samples time
after proof verification and after every chain operation; tip age is evaluated
at that operation's completion time. Request expiry during either stage fails
before acceptance. The signature verifier also requires an explicit
`QuietProofFinalAcceptanceStore`; advisory `nonce_seen` and old `consume_nonce`
callbacks cannot authorize it. The native CLI supplies
`QuietProofNonceFileAcceptanceStore` for the selected `--nonce-store` file.

The file operation acquires `flock`, rechecks file ownership/type/permissions,
reads the bounded canonical records, then samples the clock **under that lock**
before checking `[not_before, expires_at)`, rejecting replay and appending the
nonce. The nonce record remains the same lowercase 64-hex line used by scalar
verification, so a shared file shares replay policy across modes. There is no
eviction or retention reduction. A corrupt/truncated/full store fails closed;
the original scalar operation retains its existing contract. Write/fsync failure
never accepts and may leave the nonce recorded, requiring a fresh request.

Results record `verification_started_at`, `proof_checked_at`,
`chain_observed_at` and `accepted_at` separately (null when unavailable).
`accepted_at` is the validity decision time inside the store transaction;
durability/return may complete later. These timestamps do not establish signing
time or turn chain/mempool observations into an atomic snapshot. Qualified
current-provider evidence remains inconclusive and never consumes a nonce.

The opt-in native `quietproof-signature-funds-regtest-test` exercises production
CLI request creation, stock Core32 authorisation, online and RPC-disabled
delegated proving, actual-node funds checks and final nonce acceptance for both
profiles over mixed claims. Its separate disposable fixture spend checks
mempool and confirmed-spend rejection; product signing/proving is audited for
unchanged funds state. Scalar compatibility uses the existing protected-stdin
workflow with a matching descriptor fixture, without requiring a custom key
export RPC from stock Core. Private receipts are removed; retained test artifacts
contain public requests, proofs and bounded qualification evidence only.

Signing uses fixed BIP-322-style virtual `to_spend` and `to_sign` transactions.
All values are zero; the sole `to_sign` input references the synthetic
`to_spend` output. **Real claimed outpoints occur only inside the committed
request, never as transaction inputs.** Synthetic values never enter the
reported sum. The application message binds the entire canonical request,
including verifier, purpose, network, nonce, validity times, typed claims,
amounts, optional snapshot and user-message commitment.

The fixed signature MUST NOT authorise a real spend under the normal hash and
ECDSA assumptions. The production adapter has isolated Core32 transplant-negative evidence with
valid-spend positive controls (56 cases) and digest/shape review. This evidence
has the recorded test scope; version-zero relay rejection alone is insufficient. Nothing on this path funds or broadcasts a
transaction. Delegation/replay of the same authorised request remains possible
subject to expiry and nonce policy.

## 5. Two-mode compatibility

| Contract | Existing key-knowledge modes | Optional signature-possession mode |
| --- | --- | --- |
| Knowledge claim | Private scalar and existing constrained relation. | Request-bound signature and `Q`; no scalar-knowledge claim. |
| Formats and identity | Existing statement/envelope versions, bytes, golden vectors, circuit digests and proof parameters retain their meaning. | Separate explicit mode/profile, version dispatch, circuit identity and transcript domain; no cross-mode reinterpretation. |
| Selection | Existing APIs, CLI commands, defaults and GUI behaviour remain unchanged. | Explicit selection required; no bridge use or automatic fallback. |
| Build capability | Base SDK remains sufficient for existing consumers. | `QUIETPROOF_BUILD_SIGNATURE_MODE` defaults OFF; disabled capability must reject new-mode use explicitly. |
| Native witness path | Existing private-key workflows remain separate. | Wallet signing or local/private receipt import; no key-export fallback. |
| Browser and GUI | Existing workflows remain operational. | Implemented browser request creation/public verification only; no new native GUI signing workflow. |

The profile is additive; the byte rules below remain frozen. See the native
workflow and measured resource record linked from the rendered profile page.
Native CLI `inspect` does not support v3 requests/proofs; browser bounded metadata
inspection is separate from cryptographic verification. Public browser inputs
are `.qpr`/`.qpf` only; private `.qpa`, proving and wallet RPC stay native.

## 6. Required claim review cases

| Case | Required interpretation |
| --- | --- |
| Honest local prover, matching request and qualified unspent outputs | Signature knowledge plus the independently checked unspent sum may be accepted only after final expiry/nonce checks. |
| Delegated receipt holder | Same signature claim may be accepted; private-scalar knowledge, wallet operation and exclusive control MUST NOT be inferred. |
| Changed verifier/nonce/claim/amount/policy field or expired request | Original signature cannot authorise a changed canonical request; expiry rejects even an otherwise valid proof. |
| Spent output | Signature proof may remain cryptographically valid; the requested funds claim fails under the relevant chain observation. |
| Provider timeout, missing output evidence, inconsistent tips or unavailable historical state | Inconclusive chain result; do not report a valid funds sum. |
| Receipt submitted as a public proof | Reject the format; never treat receipt disclosure as a public ZK proof. |

## 7. Canonical signature request v3

This section allocates statement version `03`, mode `01` =
`signature-possession`, and profile `0001` = `core-ecdsa-bip322-v1`.
Mode `00` is reserved for key knowledge but is not valid in a v3 statement.
Existing statement versions `01` and `02` have implicit key-knowledge meaning;
their bytes, hashes, APIs and default selection MUST remain unchanged.
The existing script-kind allocation is reused: `00` = native P2WPKH,
`01` = compressed-key P2PKH. Unknown IDs MUST NOT select another relation.
These allocations are independent of any future circuit-version number.

All request integers are unsigned **big-endian**. Text lengths count UTF-8
bytes, not characters; shortest-form UTF-8 with no C0 controls or U+007F is
required. There is no Unicode normalisation. The canonical `.qpr` consists of
the following bytes in this exact order, with no trailing bytes:

| Field | Bytes/rule |
| --- | --- |
| magic | ASCII `QPS1` (`51505331`) |
| statement version | `u8 = 03` |
| network | `u8`: `00` mainnet, `01` testnet3, `02` signet, `03` regtest, `04` testnet4 |
| mode | `u8 = 01` |
| profile | `u16 = 0001` |
| selected signing kind | `u8 = 00` or `01`; MUST occur in claims and be available in the authorising wallet |
| verifier | `u16(byte length) || UTF-8`, 1..256 bytes |
| purpose | `u16(byte length) || UTF-8`, exactly `proof-of-control` or `proof-of-funds` |
| nonce | 32 bytes, not all zero; freshly generated by verifier |
| user-message commitment | 32-byte `bip322_message_hash`, not all zero; section 8 |
| not-before, expiry | two `u64` Unix seconds, `not_before < expires_at` |
| snapshot present | `u8 = 00` or `01` |
| snapshot | only if present: 32-byte block hash in RPC/display order, not all zero, then `u32` height |
| bridge present | `u8 = 00`; no bridge fields permitted |
| claim count | `u16`, 1..16 |
| each claim | `txid_display:32 || vout:u32 || amount_sats:u64 || script_kind:u8 || h:20` |

The entire canonical request is at most 4096 bytes. Every real claim has a
nonzero txid, amount 1..2,100,000,000,000,000 satoshis and supported script kind.
The checked sum MUST NOT exceed that same maximum. Claims MUST be strictly
sorted by lexicographic displayed txid bytes, then numeric vout; duplicate
outpoints are malformed regardless of script kind. All claims MUST share the
same exact `h`. A missing snapshot emits no hash/height; absent in-memory
snapshot values are zero. Presence flags must be canonical `00` or `01`.

Only these committed fields and the fixed profile determine signing. External
provider selection, confirmation/maturity policy and minimum acceptable sum
remain independently retained verifier policy; they neither change `z` nor
override a committed request field. A verifier can impose additional policy
and reject a request, but MUST NOT silently rewrite it, its kind, snapshot,
amounts or validity window. A different requested policy encoded in any
request field requires a new request/signature. No caller-selected signing
parameter, arbitrary message/digest, or wallet descriptor alias may affect
the derivation below.

## 8. Request commitment and application message

Let `S` be the exact validated canonical request bytes from section 7.
`TaggedHash(tag,m) = SHA256(SHA256(ASCII(tag)) || SHA256(ASCII(tag)) || m)`.
Hashes in this section are 32 raw digest bytes, not Bitcoin display txids.

```text
d = TaggedHash("QuietProof/statement/v3", S)
M = ASCII("quietproof:signature:v1:") || ASCII(lowercase_hex(d))
m = TaggedHash("BIP0322-signed-message", M)
```

`M` has exactly 88 bytes: the 24-byte prefix and 64 lowercase hex digits.
There is no newline, NUL, BOM, length prefix or surrounding whitespace.
The user-message commitment already in `S` is separately
`TaggedHash("BIP0322-signed-message", user_message_bytes)`, preserving the
existing field's meaning. It is **not** `m` and MUST NOT be replaced by `m`,
`d`, `M` or `z`. User message bytes are supplied as-is; text input uses UTF-8
without an implicit newline or normalisation. Only their hash enters `S`.
No derived signing value is inserted into its source request: there is no
circular serialisation. A verifier MUST derive `d,M,m,z` from its own expected
request, never accept a free digest from the proof/receipt/caller.

## 9. Fixed virtual transactions and sighashes

Let `h` be the common claim hash and `kind` the selected signing kind. Use
exactly one of these scripts; address strings and network address prefixes
are not serialised into Bitcoin transactions:

```text
P2WPKH: 00 14 || h
P2PKH:  76 a9 14 || h || 88 ac
```

Bitcoin integers here are **little-endian**, unlike the request. `CS(n)` is
minimal Bitcoin CompactSize: one byte for 0..252; `fd || u16le(n)` for
253..65535; `fe || u32le(n)` for 65536..2^32-1; otherwise `ff || u64le(n)`.
Nonminimal lengths, truncation, extra fields and trailing bytes are rejected.
`V(b) = CS(len(b)) || b`; `H2(b) = SHA256(SHA256(b))`. Hash outputs in a
transaction/preimage are raw digest bytes; an RPC/display txid is their
byte reversal. Never reverse `d,m,z` or a script hash. The displayed real
claim txids do not become transaction inputs in either order.

Both transactions have version zero, locktime zero, one input, one output
and sequence zero. `to_spend` has no witness:

```text
00000000                         # version
01 || zero[32] || ffffffff        # null outpoint
22 || 00 20 || m                 # scriptSig length 34, OP_0, minimal PUSH32
00000000                         # sequence
01 || zero[8] || V(selected_script)
00000000                         # locktime
```

Let `t = H2(to_spend)` in raw digest order,
`O = t || 00000000` (synthetic output index zero),
`T = zero[8] || 01 6a` (zero value and one-byte OP_RETURN script).
The unsigned `to_sign` has no witness marker and is exactly:

```text
00000000 || 01 || O || 00 || 00000000 || 01 || T || 00000000
```

Only its unlocking data may change after signing. The adapter MUST construct
and validate this shape **before** `signrawtransactionwithwallet`, supply the
explicit virtual prevout script and amount zero, and request `"ALL"`.
It MUST require `complete: true`, then recheck every unsigned field and exact
unlocking shape. No fee output, funding, additional real input, change,
locktime, alternate sequence or extra witness is permitted.

For P2PKH the final transaction uses legacy serialisation with no witness.
The sole scriptSig is exactly two minimal direct pushes:
`len(DER||01) || DER||01 || 21 || SEC_compressed(Q)`.
For P2WPKH the scriptSig is empty; the signed transaction has marker/flag
`00 01`, followed by the same input/output fields, then exactly one witness
stack `02 || V(DER||01) || 21 || SEC_compressed(Q)`, then locktime.
The public key is exactly 33 bytes. The sole accepted sighash byte is `01`;
no `NONE`, `SINGLE`, `ANYONECANPAY` or alternative flag is permitted.

Let `C = 76 a9 14 || h || 88 ac` in **both** signing kinds. For P2PKH,
legacy `SIGHASH_ALL` input zero replaces the empty scriptSig with `C`:

```text
Plegacy = 00000000 || 01 || O || 19 || C || 00000000 ||
          01 || T || 00000000 || 01000000
z = H2(Plegacy)
```

There are no other inputs to blank and no OP_CODESEPARATOR to remove.
For native P2WPKH use BIP-143, including the **zero synthetic amount**, and
the P2PKH-form `scriptCode`, never the witness program itself:

```text
HP = H2(O)
HS = H2(00000000)
HO = H2(T)
Pwitness = 00000000 || HP || HS || O || 19 || C || zero[8] ||
           00000000 || HO || 00000000 || 01000000
z = H2(Pwitness)
```

`z` is the resulting 32-byte digest in SHA output order, interpreted as a
big-endian ECDSA integer in section 10. Neither a real claimed amount nor a
caller-supplied prevout is used. P2PKH and P2WPKH have distinct request kind
bytes, virtual scripts and signing algorithms even if they share `h`.
This is a restricted use of BIP-322 virtual transactions, not its general
Script verification, legacy compact-message-signature format or proof-of-funds
variant. No `smp`, `ful` or `pof` wrapper is added to a QuietProof proof.

## 10. Complete signature relation and encoding

```text
p = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
E: y^2 = x^3 + 7 over F_p (cofactor 1)
G.x = 79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
G.y = 483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
```

`Q` MUST be a finite point on `E`, with integer coordinates in `[0,p-1]`.
Its SEC encoding is `02 + (Q.y mod 2) || uint256_be(Q.x)` with exactly
33 bytes, constrained prefix/parity and canonical x/y representations. Reject
infinity, off-curve points, coordinates equal only modulo `p`, and invalid
compressed x/parity decoding. `HASH160` means RIPEMD160(SHA256(SEC)).

The exact ECDSA relation is:

```text
1 <= r < n
1 <= s <= floor(n/2)
e = uint256_be(z) mod n
R = (s^-1 mod n) * (eG + rQ)
R != infinity
r = integer_x(R) mod n
```

The integer `e` may be zero, and digest integers `n..2^256-1` reduce modulo
`n`. No division by `e` or assumption `e != 0` is permitted. `s^-1` is in the
scalar field, never the base field. Both possible x branches MUST be covered:
`x(R)=r` or `x(R)=r+n` when the latter is below `p` (since `p<2n`). Requiring
`x(R)=r` alone is incomplete. Both point parities and exceptional additions
and doublings must follow the group law, including intermediate infinity,
`Q=G`, `Q=-G`, and zero-scalar multiplication. Reject final infinity. Advice
for range, carry, inverse, parity and point operations must be constrained;
host-side rejection is not circuit soundness evidence.

The adapter/receipt parser requires strict DER: `30 L 02 LR R 02 LS S`,
with exact one-byte lengths, positive nonempty minimally encoded big-endian
integers, no redundant leading zero, no negative value and no trailing bytes.
A single leading zero is required precisely when necessary to prevent a sign
bit. `L=4+LR+LS` and the complete DER length is `L+2`; general strict DER is
8..72 bytes, narrowed by the low-S requirement to at most 71. The following
single `01` byte is the sighash flag, outside DER. Zero, `r>=n`, `s>=n` and
high-S are rejected; a parser MUST NOT silently normalise high-S or rewrite a
receipt. Compressed keys and low-S are mandatory for both supported kinds.

## 11. Pinned references and public fixtures

The reference inputs below were retrieved successfully at this exact bitcoin/bips
revision: `5aadddb511a5dcfe4599531bd8ae5e5b96d0f793`.

| Source | SHA256 of exact retrieved file |
| --- | --- |
| [BIP-322 v2.1.0](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0322.mediawiki) | `bdf1e930211356666e11d4961acff7a1675a280fba7b57377b48a1fb2f1b45b9` |
| [BIP-143](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0143.mediawiki) | `62bc71351563e68baeb12643c68355d217953ae9eb6a6e68b2b0323275b6beec` |
| [BIP-322 basic vectors](https://github.com/bitcoin/bips/blob/5aadddb511a5dcfe4599531bd8ae5e5b96d0f793/bip-0322/basic-test-vectors.json) | `a9184da5687b9cb7a1863807f4a8f4d743ec07d4f683f707cb85ce72f5b33f47` |

Legacy `SIGHASH_ALL` semantics were also checked against
[Core v32.1 `src/script/interpreter.cpp`](https://github.com/bitcoin/bitcoin/blob/v32.1/src/script/interpreter.cpp),
`CTransactionSignatureSerializer` and `SignatureHash`. Reproducible source input
is the official `bitcoin-32.1.tar.gz` with SHA256
`a5f2f61e32cf7f790641c9ec306a3c88ca7b5a556946956b1f35ffd7e27813f9`,
verified against the release's signed checksums. Mutable branch links are not
fixture pins.

[`signature-profile-v1.json`](signature-profile-v1.json) is generated by
[`generate_signature_profile.py`](../scripts/generate_signature_profile.py)
using Python standard-library integer/byte operations and `hashlib`. It contains
two public mixed-claim requests, with/without snapshot, selecting P2PKH/P2WPKH.
The public test key is the standard generator; the real-looking outpoints
and amounts are fabricated examples, not chain evidence or funds. There are
no wallet secrets, live signatures or authorisation receipts in this fixture.

Each fixture includes full request bytes and field offsets, `d`, exact `M`,
`m`, selected script, virtual transaction bytes, raw/display synthetic txid,
sighash preimage/components and `z`. For each encoded field, an XOR-01 mutation
of its first byte records changed `d,z`; all request bytes are also mutated
individually and checked. Some mutations are malformed/unsupported requests:
these are **digest sensitivity checks only**, never an acceptance oracle.
They keep the original script/kind while measuring the changed request
commitment. A separate valid selected-kind change reconstructs the new script
and sighash. Production parsers must reject invalid/cross-mode requests before
derivation. The generator's byte record includes every header, length,
presence flag and claim byte; no derived value is serialised back into `S`.

```sh
python3 scripts/generate_signature_profile.py --check spec/signature-profile-v1.json
python3 tests/quietproof/signature_profile_test.py
```

The focused tests include published BIP-322 transaction/hash and BIP-143
preimage/digest controls. Production codec/reference tests and isolated Core32 signing/non-spending
controls now cross-check this profile. The synthetic specification models alone
remain insufficient evidence of production behaviour or circuit soundness.

## 12. Exact dispatch and circuit identity contract

The following are the only allowed combinations. An implicit value is a
description of an old format, **not an added byte**. Old encoders, hashes and
defaults MUST NOT acquire mode/profile/family fields.

| Format / envelope | Statement | Mode | Profile | Circuit family / version | Transcript |
| --- | --- | --- | --- | --- | --- |
| `QPE1`, envelope `01` | `QPS1`, statement `01` | key knowledge, implicit | none, implicit | existing single-key PoKC / 1, exact existing digest | `PoKC/transcript/v1`, existing bytes |
| `QPE1`, envelope `02` | `QPS1`, statement `01` or `02` | key knowledge, implicit | none, implicit | existing single-key PoKC / 1, exact existing digest | `PoKC/transcript/v2`, existing bytes |
| `QPE1`, envelope `03` | `QPS1`, statement `03` | `01`, signature possession | `0001` | `0001`, signature ECDSA/HASH160 / 1, locally pinned new digest | `QuietProof/signature/transcript/v1`, section 13 |
| `QPM1`, existing separate format | none | existing P2SH 2-of-3 independent key knowledge, implicit | none, implicit | existing P2SH family / 1, exact existing digest | existing `QuietProof/P2SH-2of3/proof/v1` |

The existing `QPM1` layout, `QuietProof/P2SH-2of3/circuit/v1` identity domain,
proof semantics and verification APIs are unchanged. It is not a signature
mode, a v3 statement or a `QPE1` envelope. All existing formats retain rate 4
and 128 queries. Statement-v2 P2WPKH-only requests remain v2 on re-encoding.
Statement v2 in envelope v1 is still malformed. No v3 scalar variant, mixed
mode envelope, signature bridge purpose, unknown profile/kind or automatic
cross-mode fallback is allowed.

For envelope v3 only, allocate circuit family `0001` =
`signature-ecdsa-hash160`, circuit version `00000001`, rate `00000004` and
queries `00000080`. Family IDs in this new namespace do not renumber old
implicit families. Its field is `Fp256k1Base` with Longfellow `SECP_ID`; its
public input layout is exactly 53 field elements:

```text
[ constant one | h[0] ... h[19] | z[0] ... z[31] ]
```

Each byte uses the existing `BitPluckerEncoder<Field,8>` representation and is
constrained by the matching eight-bit plucker. Byte order is the HASH160/SHA
output stream order. Private `Q,r,s` and all advice are allocated after the
public inputs. This layout is independent of selected script kind; the outer
request/digest construction selects `z`. Circuit constraints are section 10,
not the private-scalar relation or the SDK gadget's narrower assumptions.

Let `C` be the exact Longfellow `CircuitWriter<Fp256k1Base>` serialisation using
`SECP_ID`. The new circuit digest algorithm is:

```text
I = TaggedHash("QuietProof/signature/circuit/v1",
    family:u16be || circuit_version:u32be || rate:u32be || queries:u32be ||
    len(C):u64be || C)
```

No production value of `I` may be selected by an untrusted caller. The approved
production value is pinned by `PoKSigExpectedCircuitDigest`
in `include/poksig/proof.h` and checked by the independent circuit-identity test.
The serialized-circuit SHA256 is
`07d62ac962dd0f484828c4075bc64fde3575396b28946bdef52931c6f4234d51`;
that serialization hash is distinct from the tagged identity `I`. An implementation MUST compare `I` to its locally approved exact
digest before proof parsing/verification; a nonzero caller-supplied digest is
not a trust anchor. Existing circuit digest algorithms and golden identities
are unchanged. Changing the relation/layout/parameters changes its identity
and requires explicit qualification; version 1 never permits relaxed ranges,
high-S, an unconstrained digest or fewer security queries. Preserve proof-system
security checks and CRT/convolution-capacity guards; unsupported resources or
parameters MUST fail explicitly.

### 12.1 Envelope-v3 wire format

All envelope integers are unsigned big-endian. There are no optional fields:

```text
magic:4 = ASCII("QPE1")
envelope_version:u8 = 03
statement_size:u32
statement_bytes[statement_size]          # canonical v3 S, section 7
proof_created_at:u64
mode:u8 = 01
profile:u16 = 0001
circuit_family:u16 = 0001
circuit_digest:32 = I
circuit_version:u32 = 00000001
rate:u32 = 00000004
queries:u32 = 00000080
proof_size:u32
proof_bytes[proof_size]
```

Envelope mode/profile MUST exactly match the statement; the duplication is a
consistency check, never a second source of authority. There is no serialised
`h,z` or receipt in the envelope: derive them from the retained expected
request. The outer verifier MUST require byte-for-byte equality of embedded
and expected canonical requests, then use the expected `h,z` as public inputs.

`statement_size` is 1..4096; `proof_size` is 1..134217728 (128 MiB) and MUST
equal the exact remaining length. The fixed overhead is 70 bytes; enforce the
whole envelope cap of 134221894 bytes before nested allocation, with checked
length arithmetic. Reject zero circuit digests, trailing bytes and malformed
known fields. These new bounds do not alter existing envelope limits.
`proof_created_at` is nonzero and satisfies
`not_before <= proof_created_at < expires_at` and `proof_created_at <= now`.
It records local prover start, not signing time or trusted timestamp evidence.
Final expiry/nonce acceptance remains mandatory after expensive verification.

## 13. Signature transcript

Use the following exact fixed-width binding, with no length prefixes, NULs or
other fields. Numeric fields are big-endian, as in the envelope:

```text
B = ASCII("QPE1") || 03 || 01 || 0001 || 0001 ||
    d[32] || h[20] || z[32] || I[32] ||
    circuit_version:u32 || rate:u32 || queries:u32 || proof_created_at:u64
seed = TaggedHash("QuietProof/signature/transcript/v1", B)
```

The leading bytes are magic, envelope version, mode, profile and family, in
that order. `B` is exactly 146 bytes. `d,h,z` MUST be recomputed from the
expected request; `I` and parameters MUST match the locally pinned circuit.
This seed initialises the normal proof-system transcript. Proof bytes, their
length, the receipt and private witnesses are not included in the seed; they
would introduce circularity or disclose witnesses. No old transcript seed is
used as an inner seed. The legacy `PoKC/transcript/v1`,
`PoKC/transcript/v2` and P2SH domains/bytes remain exactly unchanged.
Binding `z` here additionally does not remove its constrained public input.

## 14. Private `.qpa` authorisation receipt

Receipts are **binary, private native witness input**, with exactly this
layout. Header integers are unsigned big-endian; the nested signed transaction
uses Bitcoin serialisation from section 9, with its little-endian integers and
minimal CompactSize lengths.

```text
magic:4 = ASCII("QPA1")
receipt_version:u8 = 01
mode:u8 = 01
profile:u16 = 0001
statement_digest:32 = d
signed_tx_size:u32
signed_to_sign[signed_tx_size]
```

The header is exactly 44 bytes. Enforce **4096 bytes for the complete file**
before allocation, not merely for the body. Preliminary transaction length
is 1..4052 and MUST equal the exact remaining bytes; the fixed profile imposes
its tighter signed-transaction shape/size rules. With strict DER and low-S,
the signed transaction is 105..168 bytes for P2PKH or 108..171 for P2WPKH;
the complete corresponding receipt is 149..212 or 152..215 bytes. A larger
body within the preliminary cap is not a valid profile-v1 transaction.
No padding, trailing bytes,
JSON/base64 wrapper, compression, archive, embedded request, user-supplied
`z`, alternate amount, extra public key, timestamp or optional field exists.
Mode/profile must match the independently supplied canonical expected v3
request, and `statement_digest` must equal its independently computed `d`.

Import MUST reconstruct the virtual transactions and `z` from that request,
then check every unsigned transaction field, input count, synthetic prevout,
zero values, output and exact scriptSig/witness shape. Extract exactly one
compressed `Q` and strict DER `r,s` with flag `01`; check canonical on-curve
`Q`, `HASH160(SEC_compressed(Q))=h`, low-S/range and ECDSA validity before
constructing advice.
This host check supplements the circuit; it cannot establish soundness.
Reject an unsigned, partial, altered or extraneously witnessed transaction.
Never trust a stored RPC `complete` flag (none is encoded) or transplant the
signature into a caller-supplied transaction/digest. Do not normalise a receipt
into acceptance. Receipt expiry/request policy is checked at use; there is no
claim that an imported receipt was signed recently.

The receipt holder learns `Q`, the signature and synthetic transaction. With
the expected request, that holder can prove locally/offline or delegate again
for the same request; it does not learn the scalar from this format under the
normal cryptographic assumptions. Receipts MUST NOT be published or sent to
public browser/server verification, uploaded as `.qpf`, embedded in proofs or
shown in logs, telemetry, error messages or public inspection output. Local
inspection may show only bounded non-secret metadata (format/version, digest,
size) by default. A receipt is neither encrypted nor safe to publish because
it omits the scalar. Use explicit private local export/import and owner-only
file permissions; transfer only through a channel intended for that delegated
prover. There is no hosted or browser receipt-import workflow in this plan.

## 15. Rejection and capability policy

Requests for signature creation, signing, receipt import/export, proving and
acceptance require explicit signature-mode selection/allowance and the exact
retained expected request. Format detection only selects a parser; it does
not grant permission to switch the selected mode or enable a capability.
Existing command/API defaults and GUI behaviour MUST remain unchanged.

`QUIETPROOF_BUILD_SIGNATURE_MODE` defaults OFF. Without that capability,
recognised new-mode operations return `unsupported` (existing CLI exit 66),
with bounded reason `signature_mode_disabled`, before wallet/proof work.
Bounded format inspection may report unsupported metadata, but cannot claim
verification. Base-only installed consumers must not acquire ECDSA, oracle or
signing dependencies. Enabled support with missing required components fails
explicitly; it cannot fall back to scalar proving, private-key export, a
different signing kind, old envelope, free digest or bridge authorisation.

Use this error precedence for new formats: validate outer magic/size and safe
length framing; reject unknown version/ID/parameter values as `unsupported`;
reject known incompatible combinations or malformed known fields; check
capability; then require approved circuit identity and cryptographic validity.
Do not allocate a proof or perform RPC to discover an unsupported tuple.
Existing old-format error behaviour remains unchanged.

| Input / operation | Required new-mode result |
| --- | --- |
| Unknown statement/envelope/receipt version, mode/profile/kind, circuit family/version or rate/query tuple | `unsupported`, exit 66; no reinterpretation or retry as another format. |
| Known envelope v1/v2 with statement v3, envelope v3 with statement v1/v2, mode `00` in v3, or duplicated statement/envelope mode/profile mismatch | `malformed_statement`, exit 65. |
| Signature request with bridge purpose/binding, duplicate outpoints, multiple hashes, absent selected kind, noncanonical fields or invalid lengths | `malformed_statement`, exit 65. Wallet lacking the selected kind is an unsupported wallet capability; never infer a descriptor alias. |
| Known new-mode operation while capability disabled | `unsupported`, exit 66, reason `signature_mode_disabled`. |
| Valid tuple with circuit digest not locally approved | `unsupported`, exit 66; zero digest is malformed. No proof verification using a caller-chosen circuit. |
| Invalid proof after valid framing/dispatch/identity, or expected-request mismatch | `invalid_proof`, exit 67; no funds acceptance or nonce consumption. |
| `QPA1` input to a public proof verifier | `malformed_statement`, exit 65, reason `private_receipt_input`; reject locally before upload/provider/RPC and never echo content. File extension does not override magic. |
| Local receipt with malformed known header/length/transaction encoding | `malformed_receipt`, exit 65; unknown IDs in a recognised format instead return `unsupported`, exit 66. |
| Local receipt bound to a different expected request, or invalid signature/key/transaction authorisation | `invalid_authorization`, exit 67; disclose no witness bytes in diagnostics. |

The reason strings are bounded diagnostics, not authorisation decisions.
Feature-disabled requests, unknown/cross-mode combinations and receipt-upload
mistakes must fail without consuming a nonce or invoking signing/export.
Provider-failure/historical/current/final-expiry behaviour remains sections
3 and 4; cryptographic success alone cannot produce a funds result.
Production implementations and cross-build/package consumers must be tested
against these rules before capability is offered. The specification's focused contract models alone are not production-parser
evidence; separate enabled/disabled production codec, CLI, envelope and receipt
tests exercise those boundaries.

Run the focused specification decision-table, transcript and receipt-framing
models with `python3 tests/quietproof/signature_contract_test.py`. Its synthetic
framing bodies/mock circuit metadata are not valid receipts or proof identities.

## 16. Qualification and privacy limits

Current local evidence distinguishes scalar key knowledge from delegatable
request-signature knowledge. A new proof/timestamp does not establish signing
time. Unspent checked value is not immediately spendable, reserved or solvent.
Pruned nodes may qualify current UTXO evidence under section4 readiness; the
bundled provider cannot supply authenticated historical/pruned-away history.
An unvalidated active AssumeUTXO snapshot fails even with a validated background
state. Browser explorer qualification remains trusted/non-atomic and always
`authorizes:false`, with no validated-node or global replay claim.

Owned native CLI byte buffers are cleared where implemented; parsed JSON, SDK
advice, allocator/library copies and OS/swap may retain witness data. This is
partial handling, not comprehensive RAM erasure. Receipts are private plaintext
authorisation capabilities; public history and results retain only public data.

The original L5.3 integrated malicious fresh-proof/advice work remains
WAIVED/UNEXECUTED/UNQUALIFIED. Existing L3 arithmetic/advice rejection evidence
is separate. Honest proofs, witness generation, oracle agreement and supervisor
review do not supply that missing soundness qualification. No external crypto
audit or universal formal theorem is claimed. Historical exploratory docs failure
has a disclosed raw-log gap; configured runtime model assurance is not runtime
attestation. Retained cohort evidence keeps original UTC/source/binary/config
identities; documentation updates do not create a fresh enclosing full run.
L9 acceptance and terminal whole-branch review remain separate gates.
