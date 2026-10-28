---
title: Limits and trust assumptions
description: What QuietProof does not establish and what a safe integration must still verify.
---

# Limits and trust assumptions

This page is the short operational boundary. The [security claim matrix](/security) maps every claim to its enforcing component, tests, and residual limitation.

::: warning
This is free and open source software provided without warranty under
the terms of the GNU GPL v3 license. Professional support,
maintenance, integration services, and contractual warranty options
are available separately. Please contact us for further information.
:::

## Knowledge is not ownership

A valid proof shows that the prover knew the matching secret key while creating a challenge-bound proof. It does not show that the prover:

- is the only person with access;
- owns the bitcoin legally or beneficially;
- did not borrow access temporarily;
- will retain access; or
- represents the organization named in an application.

These questions require organizational, legal, and operational evidence outside the circuit.

## Control is not solvency

QuietProof does not discover undisclosed assets or liabilities. It does not prove that assets exceed liabilities, that the claimed UTXOs form a complete reserve set, or that customer balances were calculated correctly.

A proof-of-reserves or solvency system may use QuietProof for its key-control layer, but must add liability commitments, inclusion and completeness mechanisms, and an independently reviewed accounting policy.

## A proof is not a lock

The holder can spend the output after proving. Applications must not treat a valid proof as collateral lock, escrow, bridge lock, mint authorization, or assurance that funds will remain available.

Where continued availability matters, monitor outpoints and use the appropriate Bitcoin transaction, script, escrow, or custody mechanism.

## The verifier still needs Bitcoin evidence

The zero-knowledge proof checks the key-to-program relation. A chain provider separately checks the outpoint, amount, script, network, confirmations, and unspent state.

The bundled CLI provider checks a stable current Bitcoin Core tip. A null `gettxout` response is inconclusive, not proof that an output was spent. Historical statements require a separately implemented and authenticated historical provider through the library API.

The [browser tool](/guide/browser-tool) instead uses explicitly requested public
explorer observations, after independent policy and cryptography pass. It
trusts the pinned provider, has no atomic observation snapshot, and never
establishes the native verifier's strict current/historical chain validity.
Funding-block metadata is not a current chain snapshot.

## Replay protection is an operational responsibility

The transcript binds the verifier, purpose, network, nonce, expiry, circuit identity, and proof parameters. Deployments must still:

- generate nonces with the operating-system CSPRNG;
- keep request lifetimes short;
- never reuse a nonce, including after interrupted workflows;
- consume nonces atomically in durable storage; and
- provide an equivalently atomic shared store in distributed deployments.

The static browser supplies no such authority or shared store. Its device
clock is untrusted and opt-in local history is editable, bounded and scoped to
one origin/profile/device. Clearing storage or using another device can erase
repeat warnings. A separate accepting application must enforce its own policy.

## Supported scripts and key boundary

QuietProof accepts up to 16 public output claims but only one distinct
compressed-key hash across native P2WPKH and P2PKH outputs. Uncompressed-key
P2PKH, P2SH, P2WSH, P2TR and arbitrary scripts are unsupported. Discovery recognizes
a P2PKH script but cannot determine its hidden key encoding; proving must match
the compressed serialization. It is not an efficient aggregate proof for an HD wallet in which each UTXO has a different key.

Current proofs are also large and computationally expensive. Operators must use memory and CPU quotas around parsing and verification. See [current performance measurements](/performance).

The proof does not newly reveal public keys. Earlier spends or key reuse may
already expose them; proving cannot undo that exposure. Outpoints, key hashes
and amounts remain public and linkable. This is not anonymous proof of funds.

## Platform boundary

The native API requires 64-bit C++20; record the configured compiler and flags.
The browser reactor is separately qualified for desktop Chromium and WebKit
on the [named reference host](/performance#browser-resource-boundary). Firefox,
physical mobile/low-RAM devices and actual screen-reader use are unqualified.
The browser proof-file limit is 134221889 bytes (128 MiB plus envelope); observed
WASM linear allocation reaches about 0.95 GB with a 2 GiB maximum, in addition
to file/JS/browser memory. This is not process RSS or a total-RAM guarantee.
Run one operation at a time and preserve failure/incomplete states.

## Review boundary

Before relying on a deployment, independent reviewers must assess:

- the proof system and its assumptions;
- circuit implementation and parameter generation;
- canonical parser and transcript binding;
- nonce-store atomicity;
- Bitcoin provider, snapshot, and finality policy;
- RPC isolation and resource limits; and
- every external lock, bridge, custody, liability, or issuance system.

No documentation statement turns those external assumptions into a cryptographic guarantee.
