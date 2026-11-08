---
title: How a QuietProof exchange works
description: The challenge, proof, chain check, and decision flow in practical terms.
---

# How a QuietProof exchange works

There are four stages. Keeping them separate prevents a valid cryptographic proof from being mistaken for a complete business authorization.

The [browser guide](./browser-tool) applies these stages to a static public
request and verifier. The commands below describe the native Core-backed
profile; its durable nonce and chain-evidence checks are not supplied by local
browser history or public explorer reports.

## Before the exchange

The verifier identifies the disclosed Bitcoin outputs it expects to check. For every output it needs:

- displayed transaction ID;
- output index;
- value in satoshis;
- script kind, native P2WPKH or compressed-key P2PKH; and
- the 20-byte compressed-public-key HASH160.

Default PoSC uses a signature for the exact request. All outputs share one
compressed-key hash, up to 16 claims. Signature custody may be delegated; it
does not establish private-key knowledge or exclusive funds control.

## 1. The verifier creates a fresh request

The request names the verifier and purpose, selects the Bitcoin network, lists the output claims, sets creation and expiry times, and contains a fresh nonce.

```sh
./quietproof challenge create \
  --network signet \
  --verifier auditor.example \
  --purpose proof-of-funds \
  --message '2026-Q3 custody check' \
  --expires-in 300 \
  --claim TXID:0:100000:p2wpkh:KEY_HASH \
  --output request.qpr
```

Context flags are optional: verifier defaults to `unscoped`, purpose to `proof-of-funds`, message to empty. Verification requires matching verifier/purpose values; specify both for scoped proofs.

The four-part `TXID:VOUT:SATOSHIS:PROGRAM` form means P2WPKH. The five-part
form accepts `p2wpkh` or `p2pkh`. Default PoSC creates a v3 request; homogeneous
claims infer the BIP322 signing kind, while mixed claims need an explicit
`--signing-kind p2wpkh` or `p2pkh`. Uncompressed keys and Taproot are unsupported.
Explicit `--proof-mode key-knowledge` selects legacy PoKC v1/v2 instead.

## 2. The prover reviews and proves

Review the exact issued request, its claims, audience, purpose, nonce and expiry.
Native CLI `inspect` currently supports legacy v1/v2 only; public v3 metadata can
be reviewed in the browser or native GUI. Review is not authorization.

For an external supported signer, export the exact application message and
import its signature into a private receipt:

```sh
./quietproof signing-material --request request.qpr --output message.txt
./quietproof import-signature --request request.qpr \
  --signature-input private-signature.txt --signature-format bip322-simple \
  --receipt-output private.qpa
./quietproof prove --request request.qpr --receipt-input private.qpa --output proof.qpf
```

The signing bytes must not gain a newline. Protect the signature and receipt as
owner-only files; never upload them to the browser. The receipt is a delegated
witness capability. The proof constrains the existing ECDSA/BIP322 relation and
keeps the signature and public key private. No private scalar is required by
this prover. Local stock-wallet signing is also supported through explicit
native RPC parameters; see the [native PoSC guide](signature-possession.md).
Signing failure never retrieves a private key or changes proof mode.

Legacy PoKC proving requires explicit `--proof-mode key-knowledge` and protected
scalar input. Its existing relation constrains the scalar, derives the compressed
secp256k1 key and checks HASH160. Neither mode hides public outpoints, amounts or
key hashes; earlier spends and key reuse may already expose the public key.

## 3. The verifier checks proof and evidence

A complete verification checks several independent layers:

1. Canonical parsing and supported versions.
2. Expected verifier, purpose, lifetime, and replay policy.
3. Exact circuit identity and proof parameters.
4. The zero-knowledge proof.
5. Bitcoin output script, amount, network, confirmations, and state.
6. Checked total value and any application-specific policy.
7. Atomic nonce consumption before authorization succeeds.

```sh
./quietproof verify proof.qpf \
  --expected-request request.qpr \
  --network signet \
  --verifier auditor.example \
  --purpose proof-of-funds \
  --nonce-store ./consumed-nonces \
  --min-confirmations 6 \
  --minimum-total-sats 100000 \
  --max-lifetime 300
```

Native RPC uses the selected trusted Core node and rejects a different chain.
An absolute `--bitcoin-cli` path selects the deprecated compatibility backend
explicitly; it is not required for the ordinary native flow.

## 4. The application decides

Production integrations should fail closed for every outcome except `valid_current` or an explicitly supported `valid_historical` result.

Those are native/integrated-provider outcomes. The static browser tool always
leaves acceptance to a separate application and reports explorer observations
without upgrading them to either strict outcome.

Even then, the application has learned current challenge-bound signature custody plus the selected chain evidence. It has not learned exclusive ownership, solvency, identity, or that funds are locked.

## What is stored

For an auditable exchange, retain the request, proof, verification result, node identity, chain tip, software and circuit digest, and policy version in an append-only audit log. Keep signatures, receipts and keys out of public artifacts and audit logs.

[See the auditor-specific workflow →](/guide/auditor-workflow)
