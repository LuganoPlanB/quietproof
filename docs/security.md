---
title: Security claim matrix
description: The enforcing component, evidence, and residual limitation for each QuietProof v1 claim.
outline: deep
---

# QuietProof v1 security-claim matrix

This matrix is the review map for the current QuietProof implementation.  It
separates a statement that is enforced by the arithmetic circuit from one
enforced by the envelope, verifier policy, or an external Bitcoin/bridge
system.  A successful proof is **not** by itself proof that an output exists,
is unspent, is locked, or is a proof of solvency.

The named tests are in `tests/quietproof/` unless noted otherwise.  A negative
test means an expected rejection, not merely a host-side precondition.

| Claim and attacker strategy | Trusted/enforcing component | Source constraint or check | Positive / negative evidence | Residual limitation |
| --- | --- | --- | --- | --- |
| The prover knows a nonzero scalar in `[1,n-1]`; try `0`, `n`, or non-bit advice. | Arithmetic circuit and its soundness assumptions. | `Secp256k1EcGadget::assert_canonical_scalar` and `assert_nonzero_scalar`; `KeyOwnershipCircuit::derive`. | `key_ownership_test`: valid scalar; zero/order/non-bit mutations. Sage oracle: primality, group order, negation, and `-1,0,n,n+1` rejection; `pokc_sage_vector_test` consumes those boundaries directly. | Soundness depends on the proof system and field/CRT assumptions, not an independent audit. |
| The hidden point is `P=xG`, finite, and on the curve; substitute a point or infinity. | Arithmetic circuit. | `Secp256k1EcGadget::scalar_mult`, `Secp256k1Affine::assert_normalized`, and `KeyOwnershipCircuit::derive`. | `ec_gadget_test`, `key_ownership_test`: altered scalar-multiplication/point witness rejected. | The point is deliberately not a public output. |
| Coordinates and SEC encoding are canonical; use values equal only modulo `p`, a wrong prefix, parity, or byte order. | Arithmetic circuit. | `Secp256k1Encoding::assert_canonical` / `Secp256k1Encoding::compressed`; `KeyOwnershipCircuit::derive`. | `ec_gadget_test`, `key_ownership_test`: `p-1,p,p+1`, parity, prefix and reversed-byte cases. | Canonicality applies to the relation, not to arbitrary external SEC parsers. |
| The program equals `RIPEMD160(SHA256(SEC_compressed(xG)))`; alter a SEC, SHA, RIPEMD, or public-program byte. | Arithmetic circuit. | `CompressedKeySha256Circuit::derive`, `Ripemd160Fixed32::derive`, `Hash160Circuit::assert_hash160`, `PoKCCircuitV1::assert_program`. | `compressed_key_sha256_test`, `ripemd160_test`, `pokc_test`: byte and digest/program mutations. Sage oracle: independent curve/SEC and local hash-compression vectors cross-checked with Python; `pokc_sage_vector_test` checks every Sage result natively and through the circuit. | SHA/RIPEMD design security is assumed; SEC bytes and the intermediate SHA digest remain hidden; the final key hash is public. |
| A proof uses the fixed single-key circuit; add a second key hash or swap the circuit. | Statement validation, circuit construction and proof identity check. | `QuietProofStatementValid`, `PoKCBuildCircuit`, `PoKCCircuitDigest`, `PoKCProofIdentityMatches`, `PoKCVerifyProof`. | `challenge_test`, `protocol_test`: second-key rejection; `pokc_test`: real proof and digest/version mutations. | Different keys require separate proofs. |
| Public statement fields cannot be replayed across verifier, purpose, network, nonce, expiry, circuit, or proof parameters. | Canonical statement/envelope, verifier policy, and durable nonce store. | `QuietProofStatementValid`, `Encode/DecodeQuietProofStatement`, `PoKCTranscriptSeed`, `QuietProofCheckPolicy`, `QuietProofConsumeNonce`, `QuietProofConsumeNonceFile`. | `protocol_test`: canonical round-trip and expiry/replay cases; `integration_test`: durable replay and insecure-permission rejection. | Distributed deployments must provide an equivalently atomic shared nonce store. |
| Parser inputs are bounded and canonical; use truncation, length overflow, bad UTF-8, reserved values, or trailing bytes. | Local parser implementation. | `QuietProofReader::{bytes,text,u8,u16,u32,u64}`, `DecodeQuietProofStatement`, `DecodeQuietProofEnvelope`. | `protocol_test`: statement/envelope truncation, malformed lengths/UTF-8/network/version cases. | Parser testing cannot establish absence of all implementation defects. |
| A claimed outpoint has the exact kind-selected P2WPKH/P2PKH script and amount at the selected snapshot/current tip; race, substitute script/value/network, or report spent. | Independently selected chain provider. | `QuietProofChainProvider::Lookup`, `QuietProofClassifyScript`, `QuietProofMatchesScript`, `VerifyQuietProof`, native and explicit legacy Core providers. | `integration_test`: exact typed scripts, cross-kind mismatch, decimal amounts, networks, tip race, null and confirmations; `regtest_rpc_test`: pinned Core 28.3/30.3 typed real proofs, totals, native/legacy parity and spends. | The bundled provider is current-tip only. A null `gettxout` is inconclusive; authenticated historical state remains an external provider responsibility. |
| Total claimed value is the checked sum of accepted chain evidence; overflow or claim an insufficient total. | Verifier implementation and chain provider. | `VerifyQuietProof` checked `uint64_t` addition and `minimum_total_sats` comparison. | `integration_test`: multi-claim totals, threshold and overflow/inconclusive cases. | This is not a liability proof and therefore not solvency. |
| A bridge claim has a destination/asset/lock binding and cannot mint without bridge authorization. | Bridge operator/destination-chain callback. | `QuietProofStatementValid` bridge validation and `QuietProofVerifierConfig::bridge_authorized`. | `protocol_test` bridge encoding/mutations; `integration_test` accepted/rejected bridge callback. | QuietProof does not prove a Bitcoin lock, custody, destination finality, or one-time mint by itself. |
| The BIP-322 companion has the documented message binding but is not a standard BIP-322 signature. | Companion-format consumers. | `QuietProofBip322MessageHash` and statement `bip322_message_hash` binding. | `protocol_test`: tagged-message and companion binding cases. | An unmodified BIP-322 script verifier must reject/does not understand a PoKC proof. |

## Normative coverage and review boundaries

The MUST/REJECT requirements in
[the v1 specification](../spec/quietproof-v1.md) map to
the rows above: sections 1 and 3 to the first four rows, sections 4 through 6
to the circuit-ID/replay/parser/bridge rows, section 7 to the chain and total
rows, and section 8 to the corresponding negative-test corpus. The
implementation intentionally performs host-side validation in addition to
the circuit.  Those validations are defense in depth only; the scalar, point,
canonical SEC, SHA-256, RIPEMD-160, and public-program relation are circuit
constraints.

Before relying on a deployment, an independent reviewer must assess the proof
system, circuit implementation, parameter generation, nonce-store atomicity,
Bitcoin provider/snapshot/finality policy, and any bridge lock and mint
system.  No row in this document turns those external assumptions into a
cryptographic guarantee.

## Signature-possession mode: specified, not implemented

The [signature-possession claim contract](../spec/quietproof-signature-v1.md)
defines a future, explicitly selected mode. The implemented key-knowledge
matrix above retains its meaning and evidence. The following requirements are
design/review obligations; they are **not claims of tested signing or circuit
support**.

| Claim or boundary | Required enforcing component | Limitation and qualification obligation |
| --- | --- | --- |
| The prover knows a request-bound ECDSA signature under a compressed key hashing to `h`. | New arithmetic circuit with public `h` and independently derived `z`, private `Q,r,s`, and complete point/encoding/signature constraints. | Does not prove private-scalar knowledge, wallet operation, exclusive control or legal ownership. Native prevalidation and transcript binding alone are insufficient. |
| The signature authorises the verifier's exact expected request. | Retained independent request, canonical profile, wallet adapter, digest derivation and proof transcript. | Fresh nonce binds the request; neither a new proof nor a prover timestamp establishes signing time. |
| Core retains the private scalar. | Trusted adapter constructs/checks the fixed zero-valued virtual transaction before wallet RPC. | No arbitrary raw transaction/digest, funding, broadcast, automatic unlock, script-kind substitution or key-export fallback. Stock Core 32.1 signing remains to be qualified. |
| Delegation discloses only the intended witness capability. | Private local/native receipt export/import and handling. | Receipt holder learns `Q` and signature and can re-prove the same request within expiry/replay policy. Receipts must never be published, uploaded for public verification or embedded in proofs/logs. |
| Public proof hides the signature and `Q`. | Proof system and circuit privacy. | Real outpoints, hashes, amounts and request fields remain public/linkable; provider queries expose outpoints, and prior spends/key reuse may already reveal `Q`. No anonymity promise. |
| The reported quantity consists of real qualified unspent outputs. | Verifier/provider checks exact scripts, amounts, network, snapshot/confirmations and checked sum; final expiry and atomic nonce consumption. | Synthetic zero value never contributes. Provider failure is inconclusive; historical/current states differ. Spendability also needs maturity checks; funds are not reserved or an atomic mempool snapshot. No solvency/all-holdings claim. |
| The signature cannot authorise a real spend under normal hash/ECDSA assumptions. | Fixed synthetic transaction shape and independently derived signing digest. | Must be qualified with digest reasoning and transplant negatives with valid-spend positive controls. Version-zero relay rejection alone does not establish this invariant. |

Both modes preserve independent chain and replay policy boundaries. An honest
local prover and a delegated receipt holder can satisfy the same signature
claim. A stale or changed request must fail authorisation; a spent output must
fail the funds claim even when its signature proof is valid; provider failure
must remain inconclusive. These are required review/qualification cases, not
new passing-test assertions.

| Compatibility surface | Required result |
| --- | --- |
| Existing scalar/multisignature APIs, request/proof bytes, circuit identities and golden vectors | Preserve their existing meaning and behaviour. |
| Mode selection and capability | Explicit new-mode selection; specified build flag `QUIETPROOF_BUILD_SIGNATURE_MODE` defaults OFF; disabled support rejects new-mode use explicitly. |
| Private-key export and signing | Separate workflows; no fallback between them. |
| Bridge, browser and native GUI | New mode has no bridge authorisation or native GUI signing workflow; planned browser work is request creation/public verification only. Existing workflows remain unchanged. |

See the claim contract for the wallet/prover/verifier information boundaries,
receipt disclosure rules and complete scope. This addition supplies no
production codec, circuit, wallet adapter or signing qualification evidence.
