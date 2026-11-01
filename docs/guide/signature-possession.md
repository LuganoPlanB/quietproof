---
title: Native signature-possession workflow
description: Explicit stock-wallet authorisation, private receipt delegation and exact-request verification.
---

# Native signature-possession workflow

This optional mode proves knowledge of a signature for the verifier's exact
request. It does not prove private-key knowledge or signing time. A private
receipt can delegate that same request to another native prover. Existing
key-knowledge commands and the native GUI retain their existing defaults.

## Build the capability explicitly

Use the pinned base SDK installed as described in the README. No optional SDK
ECDSA package is required. In separate fresh build directories:

```sh
cmake -S . -B build-signature -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/path/to/longfellow-prefix \
  -DQUIETPROOF_BUILD_SIGNATURE_MODE=ON -DQUIETPROOF_BUILD_RPC=ON
cmake --build build-signature --parallel 2
cmake -S . -B build-signature-offline -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/path/to/longfellow-prefix \
  -DQUIETPROOF_BUILD_SIGNATURE_MODE=ON -DQUIETPROOF_BUILD_RPC=OFF
cmake --build build-signature-offline --parallel 2
```

The flag defaults OFF, including ordinary scalar-only builds. Recognised
signature operations without it return unsupported (exit66). Installed CMake
consumers request `COMPONENTS signature` and link
`LongfellowZKQuietProof::signature`; requesting only the base component does not
discover signing/oracle packages. The test-only libsecp256k1 oracle is not an
installed production dependency.

## Try stock Core32.1 on isolated regtest

Follow [the existing disposable tutorial](./getting-started) using the verified
Core32.1 binaries in `BITCOIN_BIN`. Its old scalar create/inspect/prove/verify
commands remain valid. Keep its owned node running after verification and
retain `core`, `DEMO`, `RPC_URL` and `MINER` in the same Bash session. Never use
a production wallet/datadir for this example. Core32 mining needs sufficiently
responsive local storage; it has no permission to raise application RPC bounds.

Create a separate disposable signing address in the tutorial's funding wallet:

```sh
QP_SIGNATURE="$(pwd)/build-signature/quietproof"
QP_OFFLINE="$(pwd)/build-signature-offline/quietproof"
SIGN_ADDRESS=$(core -rpcwallet=funding getnewaddress '' bech32)
core -rpcwallet=funding sendtoaddress "$SIGN_ADDRESS" 1 >/dev/null
core generatetoaddress 2 "$MINER" >/dev/null
"$QP_SIGNATURE" challenge create --proof-mode signature-possession \
  --signing-kind p2wpkh --network regtest --address "$SIGN_ADDRESS" \
  --verifier example.org --purpose proof-of-funds --message 'Signature demo' \
  --expires-in 3600 --output "$DEMO/expected.qpr" --rpc-wallet funding \
  --rpc-url "$RPC_URL" --rpc-datadir "$DEMO"
```

The verifier retains `expected.qpr` independently before sending the prover a
copy. The selected kind must occur in the claims and be available in the selected
wallet. For P2PKH, create a `legacy` address and explicitly select `p2pkh`; a
`wpkh` descriptor does not imply a `pkh` alias. Review network, audience, purpose,
nonce/expiry, amounts and exact claims through trusted request creation records.
Native CLI `inspect` currently does **not** support v3 requests/proofs; browser
metadata inspection is a separate public capability, not authorisation.

## Local wallet proving or private receipt delegation

Local signing and proving:

```sh
"$QP_SIGNATURE" prove --proof-mode signature-possession \
  --request "$DEMO/expected.qpr" --output "$DEMO/online.qpf" \
  --rpc-wallet funding --rpc-url "$RPC_URL" --rpc-datadir "$DEMO"
```

Alternatively, export an owner-only private capability and prove natively on a
machine with no RPC support. These commands deliberately use different output
names because existing destinations are never overwritten:

```sh
"$QP_SIGNATURE" authorize --proof-mode signature-possession \
  --request "$DEMO/expected.qpr" --receipt-output "$DEMO/private.qpa" \
  --rpc-wallet funding --rpc-url "$RPC_URL" --rpc-datadir "$DEMO"
"$QP_OFFLINE" prove --proof-mode signature-possession \
  --request "$DEMO/expected.qpr" --receipt-input "$DEMO/private.qpa" \
  --output "$DEMO/delegated.qpf"
```

Only the selected stock wallet signs. Unlock it separately if necessary; this
path never unlocks, exports keys, funds or broadcasts. The checked transaction
is fixed and synthetic with zero values, not a spend of the real claims. A
signing failure cannot switch modes, script kinds or export the key.

`private.qpa` is plaintext witness capability, bounded to4096 bytes and accepted
only as a regular current-owner owner-only file. Its holder learns Q/signature
and can re-prove the same request; copying it does not create freshness. Transfer
only to the intended native prover and remove private copies under your own
retention policy. Never upload it to the browser, publish it, put it in logs or
embed it in a proof. Owned CLI buffers are cleared where implemented, but SDK,
JSON/library/allocator copies and OS/swap can retain witness data; no complete
RAM-erasure guarantee is offered.

## Verify with retained authority and durable replay state

For the delegated result (use `online.qpf` instead for the local alternative):

```sh
"$QP_SIGNATURE" verify "$DEMO/delegated.qpf" --proof-mode signature-possession \
  --expected-request "$DEMO/expected.qpr" --network regtest \
  --verifier example.org --purpose proof-of-funds --max-lifetime 3600 \
  --nonce-store "$DEMO/signature-nonces" --rpc-url "$RPC_URL" --rpc-datadir "$DEMO"
```

Expect `valid_current` only after proof, exact real-output checks and final
expiry/replay acceptance. The durable nonce store is a file. Acceptance rechecks
time under its lock and appends/fsyncs before success; preserve it across
restarts. Verifying another proof for the same request with the same store is
a replay rejection. Each later engagement needs a fresh independent request.

Native validated-current policy requires IBD false, a validated **active**
Core32 chainstate and a common fresh tip around every output lookup. A validated
background AssumeUTXO chainstate is insufficient. Pruning may retain adequate
current UTXO evidence but does not provide historical evidence. Read
[exact chain, clock and provider policy](/security#chain-trust-and-provider-policy).
The reported `unspent_quantity` is not immediate spendability, reservation,
solvency or an atomic mempool snapshot. Missing/stale/provider evidence stays
inconclusive; synthetic zero values never enter the sum.

Only public `.qpr` and `.qpf` files belong in the
[browser handoff](./browser-tool). Signature mode requires the exact expected
request; browser provider qualification is trusted/non-atomic and always
`authorizes:false`, without validated-node or global replay acceptance. Native
proving, real receipts and wallet RPC stay native. The native GUI has no signature
workflow.

Stop only the tutorial's owned node and remove its disposable data with its
existing cleanup block. [Measured limits](/performance#signature-possession-measurements)
are host-specific observations. The original L5.3 integrated malicious
fresh-proof/advice attacks remain user-waived, unexecuted/unqualified; local
review is not an external audit or universal soundness theorem.

## Local enable, disable and restart procedure

Prepare separate fresh scalar-only and dual-mode installations. Set `RC_ROOT`
to a new owned local directory and `SDK_PREFIX` to the qualified base SDK prefix;
these are review artifacts, not deployment destinations:

```sh
cmake -S . -B "$RC_ROOT/build-off" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$SDK_PREFIX" -DBUILD_TESTING=OFF \
  -DQUIETPROOF_BUILD_RPC=ON -DQUIETPROOF_BUILD_SIGNATURE_MODE=OFF \
  -DCMAKE_INSTALL_PREFIX="$RC_ROOT/install-off"
cmake --build "$RC_ROOT/build-off" --parallel 2
cmake --install "$RC_ROOT/build-off"
cmake -S . -B "$RC_ROOT/build-on" -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH="$SDK_PREFIX" -DBUILD_TESTING=OFF \
  -DQUIETPROOF_BUILD_RPC=ON -DQUIETPROOF_BUILD_SIGNATURE_MODE=ON \
  -DCMAKE_INSTALL_PREFIX="$RC_ROOT/install-on"
cmake --build "$RC_ROOT/build-on" --parallel 2
cmake --install "$RC_ROOT/build-on"
```

Omitting the new option in a fresh build also selects OFF. Do not install OFF
over an old ON prefix: CMake does not uninstall old ON headers. Keep installed
base, RPC and signature consumer checks separate; an OFF package must reject a
required signature component even if an ON prefix appears later in the search
path. The scalar/multisignature formats and identities remain unchanged.

1. Before enabling, retain the expected request and the external durable nonce
   file independently of either installation. Protect that file with current-owner
   owner-only permissions and keep the same bare lowercase nonce namespace.
2. Select `install-on/bin/quietproof` explicitly for new native invocations and
   pass `--proof-mode signature-possession` for signature operations. Scalar
   commands keep their default. No wallet key-export fallback is enabled.
3. To disable, stop only your owned callers/proving processes and select
   `install-off/bin/quietproof` for subsequent invocations. Recognised signature
   creation/proving/acceptance requests return unsupported before wallet/proof
   work. Existing scalar commands and proofs remain usable. QuietProof supplies
   a CLI/library, not a background configuration service or reload endpoint.
4. In an embedding application, `QuietProofSignatureVerifierConfig::modes` is
   independently selected local verifier policy. Its
   `allow_signature_possession` defaults false even in an enabled build; select
   false for newly constructed verifier calls when disabling acceptance. Untrusted
   request metadata cannot turn it on. Keep the same durable final acceptance
   store, clock and chain-policy checks when enabling it again.
5. Restart your owned caller with the selected OFF installation, then later ON
   if desired. Never clear or replace the nonce file as part of switching. A
   previously accepted signature request remains a replay after re-enabling;
   disabling does not revoke copies of private receipts or erase acceptance
   history. A fresh engagement needs a new independently issued request.

For the static browser, use a separate fresh cross-build directory, omit
`--signature-mode` from both `scripts/build_wasm.py` and
`scripts/build_static.py`, and load that matched OFF artifact in a fresh worker.
Check that signature support is unavailable and creation/verification cannot
select the new mode. Bounded public metadata inspection may remain available;
it is not cryptographic or funds acceptance. Explicit ON builds require the
flag in both scripts. Browser replay history is local convenience and is not
the native durable nonce store.

There is no authoritative browser issuer or global acceptance backend. Cached
old ON clients and offline receipt holders may still construct requests or
proofs. Replacing an artifact or disabling local verifier policy is not global
revocation; an independent service must enforce its own acceptance policy and
replay store. Public artifacts must never include real receipts, keys, RPC
credentials or private witness logs. Review current installed documentation,
source archives, checksums and feature flags before any separately authorised
publication; local qualification does not publish or deploy them.
