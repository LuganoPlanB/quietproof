---
title: Glossary
description: Plain-language definitions of the Bitcoin and cryptographic terms used by QuietProof.
---

# Glossary

## Bitcoin terms

### Bitcoin output / UTXO

A specific amount of bitcoin created by a transaction and not yet spent. QuietProof requests identify outputs by transaction ID and output index.

### Compressed public key

A 33-byte secp256k1 key used by supported P2WPKH and P2PKH relations. QuietProof does not newly disclose it, but cannot hide disclosures elsewhere, including earlier spends with the same key.

### Private key / spend key

The secret scalar that authorizes spending. QuietProof’s prover uses it locally as a private witness. It must never be placed in command arguments, shell history, environment variables, requests, or proof files.

### P2WPKH

“Pay to Witness Public Key Hash,” a common native SegWit output type. Its witness program contains a 20-byte HASH160 fingerprint of the compressed public key.

### Witness program

For P2WPKH, the 20 bytes after `0014` in the output’s `scriptPubKey`. This public fingerprint is an input to the QuietProof relation.

### P2PKH

“Pay to Public Key Hash,” the exact script `76a914{20-byte hash}88ac`.
QuietProof supports hashes of compressed public keys only. The script itself
cannot establish whether the hidden key was compressed or uncompressed.

### Key hash

The public 20-byte HASH160 of the compressed public key. The API retains the
member name `program` for compatibility; typed claims select P2WPKH or P2PKH.

## Proof terms

### Challenge

A short-lived request created by the verifier. It identifies the verifier, purpose, network, outputs, nonce, and expiry.

### Circuit

The arithmetic rules checked by the zero-knowledge proof. QuietProof has exact circuit shapes for one and two distinct compressed-key hashes, shared across supported script kinds.

### Nonce

A fresh random value used once. Together with durable consumption, it prevents the same proof conversation from being replayed as a new one.

### PoKC

Proof of Key Control, the underlying zero-knowledge relation used by QuietProof.

### Prover

The party that supplies the private key locally and creates the proof.

### Statement

The canonical public data bound into the proof: version, network, verifier, purpose, message, times, nonce, claims, and optional bindings.

### Verifier

The party or software that checks the proof, expected policy, replay state, and independent Bitcoin evidence.

### Witness

Private data used to satisfy a zero-knowledge circuit. Here it includes the spend key and derived intermediate values. “Witness” in the proof-system sense is separate from Bitcoin transaction witness data.

### Zero-knowledge proof

Evidence that a private relation is true without revealing the private values that make it true.
