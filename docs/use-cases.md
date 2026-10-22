---
title: Where QuietProof can help
description: Custody, audit, proof-of-funds, credit, wallet continuity, and collaborative Bitcoin workflows.
---

# Where QuietProof can help

QuietProof is most useful when one party needs credible evidence of Bitcoin key control **before** it makes sense to move funds, expose a public key, negotiate a contract, or assemble a collaborative transaction.

## Custody and audit

### Custody attestation without key disclosure

A custodian, exchange, fund, broker, or escrow operator can answer:

> We currently know the keys needed to spend these disclosed native P2WPKH or compressed-key P2PKH outputs.

The proof can be checked without publishing the compressed public keys and without constructing a fake or spend-like transaction.

This is a proof-of-key-control building block. A complete proof of reserves must also address liabilities, asset completeness, valuation, and the possibility of shared or borrowed key access.

### Auditor-to-custodian challenges

An auditor can create a fresh, short-lived request for a known UTXO set. The custodian reviews it and returns a bound proof. The auditor independently checks the output data against Bitcoin and records the challenge as consumed.

This workflow reduces the value of copied historical proofs and cleanly separates key-control evidence from the auditor’s chain, confirmation, value, and policy checks.

## Qualification before a deal

### Proof of disclosed funds

An OTC desk, property seller, large merchant, escrow service, or institutional onboarding team can ask a counterparty to demonstrate control of disclosed funds before investing in a negotiation.

The selected coins and values are disclosed and traceable. The proof does not reveal keys or the full wallet balance.

### Collateral preflight

A prospective borrower can demonstrate control of proposed collateral before the parties negotiate a multisig migration, DLC, escrow, or other locking arrangement.

```text
discovery → off-chain proof of control → terms agreed → actual collateral transaction
```

QuietProof does not lock the collateral. It only makes the pre-contract capability check possible.

### Buyer, seller, or operator bonds

A marketplace may ask a seller to prove control of a disclosed bond UTXO, or ask a buyer to demonstrate funding capability, before starting costly legal, KYC, escrow, or fulfillment work.

## Off-chain continuity and peer credit

### Off-chain wallet linking

The two-key proof can demonstrate to a chosen verifier:

> The same prover knows the key for wallet A and wallet B.

The verifier learns this link and can share it. The proof reveals neither key and creates no blockchain transaction.

### Reputation rollover

A peer-credit network could associate repayment history with a Bitcoin-controlled pseudonym. When the participant rotates wallets, a two-key QuietProof can support an application-level transfer from the old pseudonym to the new one.

The application learns the pseudonym link. It still decides whether to trust the history or identify the presenter as the same person or organization.

### Guarantor and lending-circle preflight

QuietProof can check that a participant can satisfy a key-control prerequisite before a guarantor system, credit cooperative, lending circle, or marketplace constructs its real authorization arrangement.

The current two-key semantics show that one prover knows both keys. Workflows involving two independent people need separate proofs or a higher-level protocol; they must not describe one two-key proof as evidence from two independent parties.

## Collaborative Bitcoin protocols

### CoinJoin admission

A coordinator can ask a participant to prove control of a proposed supported input before spending resources on transaction construction. This can deter fake-input registration while avoiding premature public-key disclosure.

### Liquidity and channel qualification

An on-chain funding source or disclosed bond can be checked before channel opening, liquidity leasing, federated-service participation, or another coordinated funding operation begins.

QuietProof itself is not a Lightning protocol and proves no off-chain balance or channel state.

### Escrow and bridge preflight

An application can use key-control evidence as one input to an escrow or bridge decision. A valid QuietProof never proves that bitcoin is locked, that destination-chain state is final, or that one-time issuance occurred. Those remain separate, mandatory controls.

## “Skin in the game” and future directions

V1 works with disclosed outputs and disclosed values. It could become one part of a later system that proves richer private statements:

1. Key knowledge for a known compressed-key hash.
2. Key knowledge plus membership in a committed UTXO set.
3. A hidden UTXO controlled by the prover.
4. Hidden aggregate value meeting a threshold.
5. Private solvency or credit credentials.

Those are roadmap directions, not current QuietProof claims. Each would require a new construction and security analysis.

## A quick fit check

QuietProof may fit when:

- The relevant outputs are native P2WPKH or compressed-key P2PKH.
- There are at most two distinct key hashes in the proof.
- The verifier already knows which outputs and values it wants to check.
- Avoiding public-key disclosure before spend has practical value.
- The application can issue fresh challenges and verify independent Bitcoin data.

It is not a good fit for a large modern HD wallet in which every UTXO uses a fresh key. The current proof work and size scale with the number of distinct keys, and v1 intentionally caps that number at two.

[Read the current limits in detail →](/limitations)
