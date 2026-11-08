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

## Default signature custody (PoSC)

The [signature profile](../spec/quietproof-signature-v1.md) is enabled by default
with `QUIETPROOF_BUILD_SIGNATURE_MODE=ON`. Native CLI and browser operations
select PoSC by default, with independently retained exact expected-request bytes
required for verification. The native GUI defaults to private receipt import.
Intentional signature-disabled builds report unsupported without key fallback;
explicit legacy PoKC remains available. Low-level PoKC APIs keep their existing
relation and bytes; low-level signature verifier policy still requires explicit
local opt-in. There is no bridge authorization in PoSC.

| Claim or boundary | Enforcing component and evidence | Residual limitation |
| --- | --- | --- |
| Knowledge of a request-bound low-S ECDSA signature and compressed Q hashing to h | `BitcoinEcdsaCircuit` and `SignaturePossessionCircuitV1`: public h/z, raw p/n ranges, e=0, guarded r+n branch, complete projective arithmetic, canonical same-Q SEC/HASH160. L3 corpus62 and advice2096 rejection cases; composed honest proofs and independent supervisor source review. | Signature knowledge permits delegation; no scalar knowledge, signing-time or exclusive-control claim. Original L5.3 integrated malicious fresh-proof/advice attacks were user-waived, remain unexecuted/unqualified. Honest proofs/native prechecks do not fill that gap. |
| Exact expected-request authorisation and mode isolation | Canonical v3 request, independently derived digest, pinned circuit identity, separate transcript/domain, strict codec/envelope/receipt checks. Verifier requires retained expected bytes. | Proof metadata or an accompanying replacement request cannot supply the verifier's authority. Native CLI inspect does not support v3; browser metadata inspection does not verify cryptography. |
| Wallet retains the private scalar and signing does not spend the claims | Production adapter constructs/rechecks fixed zero-valued virtual transactions before/after stock Core32.1 signing. Isolated Core tests include 56 transplant negatives with valid-spend positive controls and 89 malformed deliveries. | Normal hash/ECDSA assumptions still apply. Version-zero relay rejection alone is insufficient. No arbitrary raw transaction/digest, funding, broadcast, automatic unlock, kind switch or key-export fallback. |
| Receipt delegation and privacy | Native CLI `.qpa` imports are regular current-owner owner-only files, bounded to 4096 bytes; new private outputs are owner-only and never overwrite. Browser rejects receipt magic before provider work. | A receipt exposes Q/signature and permits repeated proving for the same request within expiry/replay policy. It is not encrypted; never publish/upload/log it. Public proofs still expose outpoints, amounts, hashes and context. Prior spends/key reuse can disclose Q. |
| Real qualified unspent quantity | `VerifyQuietProofSignature` checks exact real scripts/amounts/network, checked sum, confirmations and selected state policy after cryptography. Synthetic zero values never contribute. | Unspent quantity is not spendability, reservation, an atomic mempool snapshot, all holdings or solvency. Missing coinbase metadata leaves maturity unknown; immature coinbase is separately labelled. |
| Final expiry and replay | Injectable completion-time clock plus required final acceptance store; native file store locks, rechecks owner/type/permissions, checks time and replay under lock, appends/fsyncs before success. Tests include nonce25 and expiry during expensive work. | Device/system time is trusted locally, not a signing timestamp. Distributed services need an equally atomic shared store. Write/fsync failure never accepts and may require a fresh nonce/request. |

### Chain trust and provider policy

Default native signature policy `kValidatedCurrentNode` requires IBD false and
Core32's **last (active)** `getchainstates.chainstates` entry to match the observed
tip and have boolean `validated:true`. AssumeUTXO's validated background state
cannot qualify an unvalidated active snapshot. Readiness brackets exact output
lookups, all at one common tip. Missing/malformed readiness is inconclusive.
`gettxout(...,true)` accounts for known mempool spends; null cannot distinguish
spent from missing. Pruning does not itself disqualify current UTXO evidence if
these checks pass, but the bundled current-tip provider supplies no authenticated
historical snapshot or pruned-away transaction history.

Maximum tip age: mainnet7200s, testnet3/testnet4/signet86400s, regtest3600s;
a tip over7200s in the future also fails. `--max-tip-age` sets independent local
policy. These are freshness observations, not a promise of fully current peers.
`kRecordedHistoricalSnapshot` is an explicit API policy with matching request
snapshot block hash and height and historical provider; a snapshot field cannot silently
select it. `kQualifiedCurrentProvider` remains inconclusive for native acceptance
and does not consume a nonce.

The browser uses trusted non-atomic explorer observations. Its qualified result
always has `authorizes:false`; it neither validates a node nor consumes a global
nonce. Local history is editable origin-local convenience, not durable global
replay prevention. Chain/provider errors cannot become a funds acceptance.

### Review and memory limits

Native proving, wallet RPC and real private receipts stay out of the browser.
Owned CLI byte buffers are cleared where implemented; parsed JSON, SDK advice,
allocator copies, OS/swap and library internals may retain witness data. There
is no comprehensive API/SDK RAM-erasure or memory-remanence guarantee. Public
browser request/check history adds separate linkability and same-origin risks;
no proof payload is persisted in that history.

Local supervisor review and current-provenance tests found no material finding
within their recorded scope. They do not supply an external cryptographic audit,
a universal formal theorem or the waived integrated-attack qualification.
Historical exploratory docs-command failure lacks a retained raw log. Optional
legacy Core28/30 skips, sanitizer prebuilt-SDK exclusion, musl test exclusions,
unobserved GitHub-hosted jobs and physical-device/RSS limits remain disclosed in
the qualification evidence; no new enclosing full-suite run is implied by
reusing exact-source cohorts. L9 acceptance and terminal whole-branch review are
separate gates.
