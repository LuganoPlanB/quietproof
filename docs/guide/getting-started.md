---
title: Build and try QuietProof
description: Build the CLI and run a challenge, proof, and verification flow on Signet.
---

# Build and try QuietProof

QuietProof is native C++17 software intended for Linux/x86-64. Use Signet for public integration testing or regtest for deterministic local testing.

## Prerequisite

Install the [LongfellowZK circuit SDK](https://dyne.org/longfellow-zk). A default installation places the executable under `/usr/local/bin` and its CMake development package under `/usr/local/lib/cmake/LongfellowZK`, subject to platform conventions.

## Build

```sh
cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=/path/to/longfellow-prefix
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure -E '^pokc-test$'
```

The real one- and two-key proof gate is intentionally memory- and CPU-intensive:

```sh
ctest --test-dir build --output-on-failure -R '^pokc-test$'
```

## Create a Signet request

Find the output’s displayed transaction ID, output index, value in satoshis, and 20-byte P2WPKH witness program. `PROGRAM` is the 40 hexadecimal characters following `0014` in the `scriptPubKey`.

```sh
./quietproof challenge create \
  --network signet \
  --verifier verifier.example \
  --purpose proof-of-funds \
  --message 'signet custody check' \
  --expires-in 300 \
  --claim TXID:VOUT:SATOSHIS:PROGRAM \
  --output request.qpr
```

Requests and proofs are created with mode `0600`. Existing output paths are not overwritten.

## Inspect and prove

```sh
./quietproof inspect request.qpr
./quietproof prove --request request.qpr --output proof.qpf
```

Provide one 32-byte hexadecimal secret through protected standard input for each distinct program. Interactive input disables terminal echo.

## Verify with Bitcoin Core

Use a fully validated Signet node and an absolute path to `bitcoin-cli`:

```sh
./quietproof verify proof.qpf \
  --bitcoin-cli /usr/bin/bitcoin-cli \
  --verifier verifier.example \
  --purpose proof-of-funds \
  --nonce-store ./consumed-nonces \
  --min-confirmations 1 \
  --minimum-total-sats SATOSHIS \
  --max-lifetime 300
```

The verifier checks the node-reported chain against the statement and passes the matching explicit network selector. The nonce store is owner-only, locked, atomically updated, and synced before authorization succeeds.

## Supported networks

The CLI accepts `mainnet`, `testnet3` (and alias `testnet`), `testnet4`, `signet`, and `regtest`.

## Next steps

- [Read the full operations runbook](/operations)
- [Understand all non-guarantees](/limitations)
- [Inspect the normative protocol](/technical/protocol)
