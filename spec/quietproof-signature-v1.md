# QuietProof signature-possession contract v4

The sole supported PoSC wire contract is [signing profiles v4](signature-profiles-v4.md).
It binds the explicit signing procedure to the request, receipt and proof while
retaining the exact existing ECDSA/HASH160 arithmetic relation, public inputs,
circuit identity and proof parameters. Superseded v3 requests/proofs and their
old private receipts are rejected; fresh v4 artifacts are required.

The closed table recognizes BIP322 ECDSA and compressed-P2PKH Bitcoin Signed
Message procedures. Recognizing a wire tuple is separate from implementing its
signer/import adapter: unsupported operations fail without another procedure,
key export, automatic unlock or proof-mode fallback. PoKC remains explicit.

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
| Trusted wallet adapter | Validate the retained request and execute only its selected signing procedure. Require the selected owned script, compressed key and canonical profile-specific encoding. | Request, wallet identity, resulting signature and public key; no private-key export. |
| Bitcoin Core wallet | Keep the scalar within the wallet and sign the exact selected procedure. | Exact application message or fixed BIP322 virtual transaction, according to the request. |
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


## Funds, freshness and non-spending

Cryptographic validity alone does not establish an unspent output. Independently
check real outpoints, kind-selected scripts, network, amounts and confirmation
policy against validated current chain state. Historical and current evidence
remain distinct; missing/inconsistent evidence is inconclusive.

Real claims are never inputs of the BIP322 synthetic transaction. The BIP322
adapter signs only its request-derived zero-valued virtual prevout with version,
sequence and locktime zero and one zero-valued OP_RETURN output. Legacy message
signing constructs no spending transaction. Ordinary request/import/prove paths
must not fund, broadcast or unlock wallets. Unchanged-wallet public qualification
is recorded separately from mathematical and parser tests.

## Canonical host contract

The normative [v4 profile specification](signature-profiles-v4.md) defines the
closed IDs, exact field order/bounds, 88-byte ASCII application message, signing
digests, current private receipt/public envelope and transcript domain. It
replaces all former PoSC v3 codecs and compatibility branches. The independent
[public fixtures](signature-profile-v1.json) are generated by
[the specification generator](../scripts/generate_signature_profile.py); fixture
format version1 does not imply a PoSC request serialization version.

## Complete signature relation and encoding

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

The BIP322 adapter/receipt parser requires strict DER: `30 L 02 LR R 02 LS S`,
with exact one-byte lengths, positive nonempty minimally encoded big-endian
integers, no redundant leading zero, no negative value and no trailing bytes.
A single leading zero is required precisely when necessary to prevent a sign
bit. `L=4+LR+LS` and the complete DER length is `L+2`; general strict DER is
8..72 bytes, narrowed by the low-S requirement to at most 71. The following
single `01` byte is the sighash flag, outside DER. Zero, `r>=n`, `s>=n` and
high-S are rejected; a parser MUST NOT silently normalise high-S or rewrite a
receipt. Compressed keys and low-S are mandatory for both supported kinds.


## Qualification and privacy limits

Current local evidence distinguishes scalar key knowledge from delegatable
request-signature knowledge. A new proof/timestamp does not establish signing
time. Unspent checked value is not immediately spendable, reserved or solvent.
Pruned nodes may qualify current UTXO evidence under explicit validated-node readiness; the
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
Current milestone acceptance and terminal whole-branch review remain separate gates.
