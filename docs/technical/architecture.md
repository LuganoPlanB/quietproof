---
title: Technical architecture
description: How QuietProof separates proof relations, canonical attestation, verifier policy, and Bitcoin evidence.
---

# Technical architecture

QuietProof is organized in three layers. Keeping them separate is a security property as well as a documentation aid.

```text
APPLICATION
custody · audit · OTC · credit · collaborative protocols
                         │
                         ▼
ATTESTATION AND POLICY
canonical request · transcript · expiry · nonce · chain evidence
                         │
                         ▼
CRYPTOGRAPHIC PRIMITIVE
PoSC (default): request-bound signature custody
PoKC (explicit legacy): private spend-key knowledge
```

## Default PoSC relation

PoSC proves knowledge of a valid request-bound low-S ECDSA signature and a
compressed public key hashing to the disclosed fingerprint. Its v3 statement,
transcript domain and circuit identity remain separate from PoKC. A private
`.qpa` receipt can delegate the signature without a scalar; it never belongs in
public browser uploads. Signature custody does not prove private-key knowledge,
signing time or exclusive control. See the [native workflow](/guide/signature-possession)
and [signature profile](/technical/signature-profile).

## Explicit legacy PoKC relation

For the public 20-byte key hash `h`, the prover privately supplies a scalar `x` and proves:

```text
x ∈ [1, n−1]
P = xG
sec = SEC_compressed(P)
h = RIPEMD160(SHA256(sec))
```

The circuit constrains scalar validity, elliptic-curve multiplication, finite normalized coordinates, canonical compressed SEC encoding, fixed SHA-256, fixed RIPEMD-160, and equality with the public program.

The compressed public key is internal witness data, not a public output.

## Fixed PoKC circuit

PoKC compiles one single-key circuit. All output claims must share its key hash. Mismatched circuit version, digest, Ligero rate, or query count is rejected before proof acceptance.

| Distinct programs | Public inputs | Private inputs | Quadratic terms | Serialized circuit |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 21 | 3,010 | 2,067,522 | 24,876,346 B |

[Read the complete PoKC circuit documentation →](/technical/pokc)

## Canonical statement and envelope

For explicit PoKC, statement v1 means P2WPKH; v2 binds each claim to P2WPKH or compressed-key P2PKH.
Mixed outputs sharing a key hash reuse one witness. New proofs use timestamped
envelope v2; typed statements are invalid in legacy envelope v1. Older verifiers
without statement-v2 support reject typed requests as unsupported. Circuit
identities are unchanged.

The public statement binds network, verifier, purpose, message, timestamps, a 32-byte nonce, one to 16 output claims, and optional application bindings. The proof envelope binds the exact statement bytes, circuit digest, circuit version, Ligero rate, query count, and proof bytes.

The Fiat–Shamir transcript seed uses a tagged hash over the statement digest, circuit identity, and proof parameters. Unknown versions, unsupported parameters, malformed lengths, trailing bytes, and non-canonical fields are rejected.

[Read the normative QuietProof v1 protocol →](/technical/protocol)

## Policy and chain evidence

Default PoSC integrations use the separate `VerifyQuietProofSignature(...)`
policy/chain/replay API with independently retained expected-request bytes and
explicit local acceptance policy. Low-level PoKC APIs keep their relation:
`PoKCVerifyProof(...)` checks only the zero-knowledge relation. Applications should normally use `VerifyQuietProof(...)`, which applies policy, proof verification, chain evidence, confirmation and value thresholds, optional bridge authorization, and atomic nonce consumption.

The chain provider is independently selected by the verifier. The bundled provider checks a stable current Bitcoin Core tip; authenticated historical state remains an external provider responsibility.

## Assurance material

The repository includes:

- deterministic protocol and circuit fixtures;
- positive and negative native tests;
- real single-key proof round trips;
- an independent Sage 10.6 executable mathematical oracle;
- canonical encoding and circuit-digest anchors; and
- a claim-by-claim security review map.

These are evidence for review, not a substitute for an independent cryptographic and protocol audit.
