---
title: What QuietProof proves
description: Default signature custody, explicit legacy key knowledge, and their boundaries.
---

# What QuietProof proves

QuietProof lets one person demonstrate to another:

> I possess a valid wallet signature authorizing your exact request for this Bitcoin key fingerprint.

This is the default **PoSC (Proof of Signature Custody)** relation. The wallet
owner can delegate the signature for the same request without exporting the key.
Explicit **PoKC (Proof of Key Control)** instead proves knowledge of the spend key.

The holder does not need to move the bitcoin. The proof reveals neither the private key nor the compressed public key, and it is not a Bitcoin-valid signature that can be reused elsewhere.

## The idea without the cryptography

A native P2WPKH or P2PKH Bitcoin address contains a short fingerprint derived from a public key. Before that bitcoin is spent, the full public key may never have appeared on-chain.

Default PoSC checks the hidden signature and compressed public key:

```text
request-bound wallet signature + matching public key
        ↓ valid ECDSA signature for the exact request
matching compressed public key
        ↓
public-key fingerprint
        ↓
compressed-key hash and script kind named in the request
```

The public verifier learns that the relationship is correct, but receives neither
the signature nor either key. A private `.qpa` receipt exposes the signature and
public key to its native prover and permits delegated proving for that same request.
Keep it outside browser uploads. Explicit PoKC separately derives the point from
a private scalar before checking the same compressed-key fingerprint.

::: info What “zero knowledge” means here
The proof does not newly disclose keys. Outpoints, key hashes and amounts remain public and linkable. Earlier spends or key reuse may already reveal a public key; proving cannot undo that exposure. This is not anonymous proof of funds.
:::

## Why a fresh challenge matters

The verifier creates a request containing its identity, the purpose, the Bitcoin network, the claimed outputs, a random nonce, and an expiry time. The proof is bound to every byte of that request.

This makes a saved proof much less useful to someone trying to replay it in a different audit, for a different verifier, or after it expires. Production integrations must also keep an atomic record of consumed nonces.

## Proof and Bitcoin evidence are separate checks

QuietProof deliberately separates two questions:

| Question | Checked by |
| --- | --- |
| Does the prover possess a request-authorizing signature for this key fingerprint? | Default PoSC zero-knowledge proof |
| Does the prover know the matching spend key? | Explicit legacy PoKC zero-knowledge proof |
| Does the claimed output exist with this script, value, network, and confirmation state? | An independently selected Bitcoin chain provider |

A mathematically valid proof is not enough by itself. A complete application verifies the proof, the challenge policy, replay state, and current or authenticated historical Bitcoin evidence.

## One key, several outputs

A statement may name up to 16 outputs sharing one compressed-key hash across native P2WPKH/P2PKH kinds. All claims use the same key relation. Uncompressed-key P2PKH is unsupported.

Use separate requests and proofs for different keys. Each proof has its own challenge, transcript and verification decision; applications define any workflow connecting them. QuietProof does not implement a Bitcoin multisignature spending policy.

## What it does not prove

QuietProof does not establish:

- Exclusive control—the key may have been shared or made temporarily available.
- Private-key knowledge under PoSC; the signature can be delegated. Explicit PoKC has a different claim.
- When the wallet signature was made. A proof timestamp does not establish signing time.
- Legal or beneficial ownership of the bitcoin.
- Identity of the person or organization holding the key.
- Assets greater than liabilities, and therefore not solvency.
- That an output is locked, cannot move, or will remain unspent.
- That a custodian has disclosed every wallet or liability.
- A hidden balance or hidden UTXO. The v1 verifier is given the claimed outputs.

State the selected proof relation with every result. It can be one component inside a custody attestation, proof-of-funds check, or future proof-of-reserves system, but it is not the whole system.

## Where to go next

- [Explore practical use cases](/use-cases)
- [Follow the challenge and proof flow](/guide/how-it-works)
- [Read the limits and trust assumptions](/limitations)
- [Inspect the technical architecture](/technical/architecture)
