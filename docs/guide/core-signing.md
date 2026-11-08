---
title: Stock Bitcoin Core signing
description: Compressed P2PKH descriptor addresses, request-bound signing and offline signature custody proofs.
---

# Stock Bitcoin Core signing

Stock **Bitcoin Core 32.1** was qualified on isolated signet with a private-key
descriptor wallet and compressed P2PKH address. Core's `getnewaddress '' legacy`
selects a P2PKH **address type**; it does not require the removed legacy wallet
storage backend. The wallet must contain an active `pkh` descriptor and own that
address's compressed key. A `wpkh` descriptor alone is insufficient. Create or
load only your own disposable wallet, fund it separately if necessary, and wait
for a confirmed output. These signing commands do not fund or broadcast.

Build the [standard native CLI](./signature-possession#build-the-standard-capability).
In one Bash session from the repository root, select your already running,
validated signet node and already funded owned address:

```sh
umask 077
QP="$(pwd)/build-signature/quietproof"
CORE_DATA=/absolute/path/to/isolated-signet-core-data
RPC_URL=http://127.0.0.1:38332/
WALLET=disposable-signing-wallet
ADDRESS=your-complete-compressed-p2pkh-address
WORK=$(mktemp -d /tmp/quietproof-core.XXXXXX)
chmod 700 "$WORK"
mkdir -m 700 "$WORK/verifier" "$WORK/prover"
"$QP" challenge create --network signet --address "$ADDRESS" \
  --verifier example.org --purpose proof-of-funds --message 'Core signet demo' \
  --expires-in 86400 --min-confirmations 1 \
  --rpc-url "$RPC_URL" --rpc-datadir "$CORE_DATA" \
  --output "$WORK/verifier/issued.qpr"
cp -n "$WORK/verifier/issued.qpr" "$WORK/prover/request.qpr"
"$QP" authorize --request "$WORK/prover/request.qpr" \
  --rpc-wallet "$WALLET" --rpc-url "$RPC_URL" --rpc-datadir "$CORE_DATA" \
  --receipt-output "$WORK/prover/private.qpa"
"$QP" prove --request "$WORK/prover/request.qpr" \
  --receipt-input "$WORK/prover/private.qpa" --output "$WORK/prover/public.qpf"
"$QP" verify "$WORK/prover/public.qpf" \
  --expected-request "$WORK/verifier/issued.qpr" --network signet \
  --verifier example.org --purpose proof-of-funds --max-lifetime 86400 \
  --min-confirmations 1 --nonce-store "$WORK/verifier/nonces" \
  --rpc-url "$RPC_URL" --rpc-datadir "$CORE_DATA"
```

P2PKH selects `bitcoin-message-ecdsa-v1` automatically. `authorize` uses that
wallet's `signmessage`, checks canonical compressed-key compact headers 31–34
and strict low-S, then creates an exclusive mode-0600 receipt. Unlock an encrypted
wallet separately if needed. There is no automatic unlock, key export, profile
retry or PoKC fallback. The selected `--rpc-wallet` names the signing endpoint;
the verifier needs chain access, not wallet access.

Receipt-only proving needs no RPC or wallet and works with an RPC-disabled
build. Transfer that private capability only to the intended native prover.
Retain the verifier's original request and durable nonce-store file independently.
`valid_current` requires proof, expected context, expiry, current real outputs
and replay acceptance; it does not reserve coins or establish future balances,
exclusive custody or private-key knowledge. See [verification policy](./signature-possession#verify-with-retained-authority-and-durable-replay-state).

## External signmessage alternative

Use fresh destinations instead of the integrated authorization above. Set
`BITCOIN_CLI` to the actual verified Core 32.1 `bitcoin-cli` executable:

```sh
BITCOIN_CLI=/absolute/path/to/bitcoin-cli
"$QP" signing-material --request "$WORK/prover/request.qpr" \
  --output "$WORK/prover/message.txt"
python3 -c 'import pathlib,sys; b=pathlib.Path(sys.argv[1]).read_bytes(); assert len(b)==88 and b.isascii() and not b.endswith(b"\n")' "$WORK/prover/message.txt"
SIGNATURE=$("$BITCOIN_CLI" -signet -datadir="$CORE_DATA" \
  -rpcport=38332 -rpcwallet="$WALLET" signmessage "$ADDRESS" \
  "$(cat "$WORK/prover/message.txt")")
(set -C; printf '%s' "$SIGNATURE" > "$WORK/prover/signature.txt")
unset SIGNATURE
"$QP" import-signature --request "$WORK/prover/request.qpr" \
  --network signet --address "$ADDRESS" \
  --signature-input "$WORK/prover/signature.txt" --signature-format bitcoin-message \
  --receipt-output "$WORK/prover/external.qpa"
```

The message is exactly `quietproof:signature:v4:` plus 64 lowercase digest hex
digits, **88 ASCII bytes without a newline**. The assertion runs before shell
substitution; never sign the human `--message` label instead. Core's returned
Base64 is stored without its CLI output newline, privately under `umask 077`.
Use `external.qpa` for receipt-only proving; keep the signature out of logs/Git.
The actual Core external and integrated paths produced identical receipts.

## Explicit BIP322 alternative

P2WPKH defaults to `bip322-ecdsa-v1`. Compressed P2PKH can instead request
`--signing-profile bip322-ecdsa-v1` during `challenge create`; its transport
must be Full. The native Core adapter signs the fixed synthetic zero-value
transaction through `signrawtransactionwithwallet`. This is not `signmessage`
and does not spend the real claims. Actual Core P2PKH Full authorization/import
was qualified, without generating another public-chain proof. Sparrow 2.5.6
cannot produce Full. See [the measured matrix](./sparrow#observed-compatibility).

All procedures use **v4 only**, with one unchanged circuit and one PoSC proof.
Reissue rejected v3 requests and all dependent signatures/receipts/proofs.
The verifier derives the profile/digest from its retained request and local
circuit policy. A signature wrapper cannot override them. PoKC remains a
separate explicit `--proof-mode key-knowledge` workflow.

Primary references: [Core 32 signmessage RPC](https://bitcoincore.org/en/doc/32.0.0/rpc/wallet/signmessage/),
[Core 32.1 message implementation](https://github.com/bitcoin/bitcoin/blob/v32.1/src/common/signmessage.cpp),
[BIP137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki) and
[BIP322](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki).
The RPC reference is 32.0; the executed binary was independently identified as 32.1.
