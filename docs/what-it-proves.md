---
title: What QuietProof proves
description: A plain-language explanation of QuietProof’s proof of key control and its boundaries.
---

# What QuietProof proves

QuietProof lets one person demonstrate to another:

> I know the spend key that matches this specified Bitcoin output, and I am answering your fresh request now.

The holder does not need to move the bitcoin. The proof reveals neither the private key nor the compressed public key, and it is not a Bitcoin-valid signature that can be reused elsewhere.

## The idea without the cryptography

A native P2WPKH Bitcoin address contains a short fingerprint derived from a public key. Before that bitcoin is spent, the full public key may never have appeared on-chain.

QuietProof checks, in zero knowledge, that the holder can follow the hidden chain all the way back:

```text
private spend key
        ↓
matching public key
        ↓
public-key fingerprint
        ↓
P2WPKH witness program named in the request
```

The verifier learns that the relationship is correct, but does not receive either key.

::: info What “zero knowledge” means here
The verifier can check that the holder knows the right secret without learning the secret itself—or even the compressed public key derived from it.
:::

## Why a fresh challenge matters

The verifier creates a request containing its identity, the purpose, the Bitcoin network, the claimed outputs, a random nonce, and an expiry time. The proof is bound to every byte of that request.

This makes a saved proof much less useful to someone trying to replay it in a different audit, for a different verifier, or after it expires. Production integrations must also keep an atomic record of consumed nonces.

## Proof and Bitcoin evidence are separate checks

QuietProof deliberately separates two questions:

| Question | Checked by |
| --- | --- |
| Does the prover know the matching spend key? | The PoKC zero-knowledge proof |
| Does the claimed output exist with this script, value, network, and confirmation state? | An independently selected Bitcoin chain provider |

A mathematically valid proof is not enough by itself. A complete application verifies the proof, the challenge policy, replay state, and current or authenticated historical Bitcoin evidence.

## One key or two keys

QuietProof v1 provides two exact circuit shapes:

- One distinct P2WPKH witness program.
- Two distinct P2WPKH witness programs known by the same prover.

A statement may name up to 16 outputs, but those outputs must share no more than two distinct witness programs. Outputs sharing a program reuse the same key relation.

The two-key form can privately demonstrate continuity between an old wallet and a new one. It proves common key knowledge to the selected verifier; it does not publish an on-chain link or create multisig spending rules.

## What it does not prove

QuietProof does not establish:

- Exclusive control—the key may have been shared or made temporarily available.
- Legal or beneficial ownership of the bitcoin.
- Identity of the person or organization holding the key.
- Assets greater than liabilities, and therefore not solvency.
- That an output is locked, cannot move, or will remain unspent.
- That a custodian has disclosed every wallet or liability.
- A hidden balance or hidden UTXO. The v1 verifier is given the claimed outputs.

That is why “proof of key control” is the precise name for the primitive. It can be one component inside a custody attestation, proof-of-funds check, or future proof-of-reserves system, but it is not the whole system.

## Where to go next

- [Explore practical use cases](/use-cases)
- [Follow the challenge and proof flow](/guide/how-it-works)
- [Read the limits and trust assumptions](/limitations)
- [Inspect the technical architecture](/technical/architecture)
