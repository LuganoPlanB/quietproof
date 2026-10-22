---
title: How a QuietProof exchange works
description: The challenge, proof, chain check, and decision flow in practical terms.
---

# How a QuietProof exchange works

There are four stages. Keeping them separate prevents a valid cryptographic proof from being mistaken for a complete business authorization.

## Before the exchange

The verifier identifies the disclosed Bitcoin outputs it expects to check. For every output it needs:

- displayed transaction ID;
- output index;
- value in satoshis;
- script kind, native P2WPKH or compressed-key P2PKH; and
- the 20-byte compressed-public-key HASH160.

The prover must control no more than two distinct key hashes. Several outputs may share either hash across script kinds, up to 16 claims in total.

## 1. The verifier creates a fresh request

The request names the verifier and purpose, selects the Bitcoin network, lists the output claims, sets creation and expiry times, and contains a fresh nonce.

```sh
./quietproof challenge create \
  --network signet \
  --verifier auditor.example \
  --purpose proof-of-funds \
  --message '2026-Q3 custody check' \
  --expires-in 300 \
  --claim TXID:0:100000:p2pkh:KEY_HASH \
  --output request.qpr
```

Context flags are optional: verifier defaults to `unscoped`, purpose to `proof-of-funds`, message to empty. Verification requires matching verifier/purpose values; specify both for scoped proofs.

The four-part `TXID:VOUT:SATOSHIS:PROGRAM` form remains P2WPKH. The five-part
form accepts `p2wpkh` or `p2pkh`; repeat `--claim` for mixed outputs. Any P2PKH
claim selects statement v2. Statement v1 stays implicitly P2WPKH; new proofs
use envelope v2. Older verifiers without typed-statement support return
`unsupported`. Uncompressed-key P2PKH is unsupported.

## 2. The prover reviews and proves

`inspect` shows `request_created_at` and expiry; new proofs also carry
`proof_created_at` (prover start). Both are bound local-clock Unix timestamps,
not independent evidence of creation time. Legacy proofs have no proof timestamp.

The prover inspects the canonical request before using any key:

```sh
./quietproof inspect request.qpr
./quietproof prove --request request.qpr --output proof.qpf
```

`prove` reads one 32-byte hexadecimal secret from protected standard input for each distinct key hash. Interactive input disables terminal echo, and each secret is matched to its derived compressed-key hash.

::: danger Keep spend keys out of process metadata
Never provide a secret through command arguments, an environment variable, or shell history. Automation should use a protected pipe whose producer does not log its output.
:::

Inside the proof, PoKC constrains the secret scalar, derives the secp256k1 point, encodes the compressed public key canonically, applies SHA-256 and RIPEMD-160, and checks that the result equals the public key hash. The public key remains private witness data.
A P2PKH script cannot establish whether its hidden key was compressed; proving
checks that relation. Public outpoints, hashes and amounts remain linkable.
Earlier spends or key reuse may already expose the key; this proof cannot undo
that exposure or provide anonymity.

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
  --bitcoin-cli /usr/bin/bitcoin-cli \
  --verifier auditor.example \
  --purpose proof-of-funds \
  --nonce-store ./consumed-nonces \
  --min-confirmations 6 \
  --minimum-total-sats 100000 \
  --max-lifetime 300
```

The `bitcoin-cli` path must be absolute. The bundled provider selects the proof’s network explicitly and rejects a node reporting a different chain.

## 4. The application decides

Production integrations should fail closed for every outcome except `valid_current` or an explicitly supported `valid_historical` result.

Even then, the application has learned current challenge-bound key knowledge plus the selected chain evidence. It has not learned exclusive ownership, solvency, identity, or that funds are locked.

## What is stored

For an auditable exchange, retain the request, proof, verification result, node identity, chain tip, software and circuit digest, and policy version in an append-only audit log. Keep secrets out of every stored artifact.

[See the auditor-specific workflow →](/guide/auditor-workflow)
