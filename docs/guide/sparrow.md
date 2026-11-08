---
title: Sparrow to QuietProof on signet
description: Sign an exact request with disposable Sparrow keys, import a private receipt, and verify a public PoSC proof.
---

# Sparrow to QuietProof on signet

This walkthrough uses **Sparrow Server 2.5.6's bundled signer** through the
repository's `scripts/sparrow_signer.py` adapter. It is a tested local integration,
not an official Sparrow RPC or a terminal UI signing command. The adapter calls
Sparrow/Drongo cryptography and downloads nothing. Only this helper path was
exercised; the desktop signing dialog was not qualified. That dialog trims text;
the canonical 88-byte message below has no boundary whitespace to trim.
See [official Sparrow documentation](https://sparrowwallet.com/docs/) for wallet
installation and ordinary wallet use.

PoSC proves custody of a request-bound signature, including delegated custody.
It does not prove private-key knowledge, exclusive control or signing time.
PoSC is the standard CLI/build/browser/native receipt-GUI default; legacy PoKC
requires explicit `--proof-mode key-knowledge`.

## Prepare an isolated wallet

Use Linux x86-64, Python 3.11+, JDK 25 (`java`, `javac`, `jimage`) and the complete
installed Sparrow Server 2.5.6 application image. Build the standard RPC-enabled
QuietProof CLI using the [native build instructions](./signature-possession#build-the-standard-capability).
The executed public-chain path used Bitcoin Core 32.1 on signet. Configure a
trusted, fully synced signet Core node with `server=1`, its default local RPC
port and cookie layout; see [RPC operations](/operations). The helper itself is
offline. Never use a production wallet, mainnet funds or an unmarked wallet.

Run all blocks in one Bash session, from the QuietProof repository root. Replace
these absolute paths with your installations and signet node data directory:

```sh
umask 077
QP="$(pwd)/build-signature/quietproof"
SPARROW=/absolute/path/to/sparrowserver
JDK=/absolute/path/to/jdk25
CORE_DATA=/absolute/path/to/isolated-signet-core-data
RPC_URL=http://127.0.0.1:38332/
WORK=$(mktemp -d /tmp/quietproof-sparrow.XXXXXX)
chmod 700 "$WORK"
mkdir -m 700 "$WORK/verifier" "$WORK/prover"
signer() {
  python3 scripts/sparrow_signer.py "$@" \
    --sparrow "$SPARROW" --jdk "$JDK" --cache "$WORK/cache" \
    --network signet --wallet-dir "$WORK/wallet" --script-kind p2wpkh
}
signer create > "$WORK/address.json"
ADDRESS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["address"])' "$WORK/address.json")
printf '%s\n' "$ADDRESS"
```

The helper creates a disposable, unencrypted Sparrow `.mv.db` wallet in an
owner-only directory and never prints its seed. It selects account 0, external
branch 0, receive index 0. For an existing **helper-created marked disposable**
wallet, set the function's `--wallet-dir` to that directory and run `signer address`
instead of `signer create`; retain the same address and network.

Fund only this owned receive address with a small amount of signet coins, then
wait for at least one confirmation. Reusing an already funded disposable wallet
needs no further funding. Check discovery before asking the verifier to issue:

```sh
"$QP" utxos --network signet --address "$ADDRESS" \
  --rpc-url "$RPC_URL" --rpc-datadir "$CORE_DATA"
```

Require confirmed, challenge-compatible outputs and a synced validated active
chainstate. Signet is the qualified path here; testnet4 was not qualified.
Identical test-network address encodings do not establish the same network.

## Retain the verifier's request and sign its exact bytes

The verifier chooses audience, purpose, claims and lifetime, retains its original
`issued.qpr` independently, and sends the prover a copy. These local directories
model that handoff; across machines transfer only the intended public copy.
Review the request's context, address, amounts, nonce and expiry against trusted
issuance records. CLI `inspect` does not currently inspect v3 requests.

```sh
"$QP" challenge create --network signet --address "$ADDRESS" \
  --verifier example.org --purpose proof-of-funds --message 'Sparrow signet demo' \
  --expires-in 86400 --min-confirmations 1 \
  --rpc-url "$RPC_URL" --rpc-datadir "$CORE_DATA" \
  --output "$WORK/verifier/issued.qpr"
cp -n "$WORK/verifier/issued.qpr" "$WORK/prover/request.qpr"
"$QP" signing-material --request "$WORK/prover/request.qpr" \
  --network signet --address "$ADDRESS" --output "$WORK/prover/message.txt"
python3 -c 'import pathlib,sys; b=pathlib.Path(sys.argv[1]).read_bytes(); assert len(b)==88 and b.isascii() and not b.endswith(b"\n")' "$WORK/prover/message.txt"
signer sign --address "$ADDRESS" --format bip322-simple \
  --message "$WORK/prover/message.txt" --output "$WORK/prover/signature.json"
signer verify --address "$ADDRESS" --format bip322-simple \
  --message "$WORK/prover/message.txt" --signature "$WORK/prover/signature.json"
```

The exported file contains exactly **88 ASCII bytes, without a final newline**.
Sign that file, not the human `--message` text. Do not trim, retype, add a BOM or
append a newline. The helper signs every supplied byte and verifies the result.
Homogeneous address claims infer the signing kind; mixed kinds require an
explicit supported `--signing-kind`.

## Import privately, prove offline, verify against the chain

```sh
"$QP" import-signature --request "$WORK/prover/request.qpr" \
  --network signet --address "$ADDRESS" \
  --signature-input "$WORK/prover/signature.json" --signature-format sparrow-json \
  --receipt-output "$WORK/prover/private.qpa"
"$QP" prove --request "$WORK/prover/request.qpr" \
  --receipt-input "$WORK/prover/private.qpa" --output "$WORK/prover/public.qpf"
"$QP" verify "$WORK/prover/public.qpf" \
  --expected-request "$WORK/verifier/issued.qpr" --network signet \
  --verifier example.org --purpose proof-of-funds --max-lifetime 86400 \
  --min-confirmations 1 --nonce-store "$WORK/verifier/nonces" \
  --rpc-url "$RPC_URL" --rpc-datadir "$CORE_DATA"
```

Receipt proving needs no wallet or RPC access and also works in an RPC-disabled
build. Keep signatures and `.qpa` receipts owner-only, outside Git and the
browser: a receipt holder can delegate/re-prove this request. There is no key
export fallback. Only public requests/proofs belong in a browser handoff.

Alternatively import a private raw text file with `--signature-format bip322-simple`:
it must contain exact canonical Base64, optionally prefixed by Sparrow's `smp`,
without whitespace or a newline. Prefixless input requires this explicit format.
The helper JSON, `smp` text and prefixless Base64 transport the same signature;
they are not different signing schemes. No conversion fixes a legacy digest.

Expect `valid_current` only after cryptography, the retained expected request,
network/audience/purpose, expiry, chain-state checks and durable replay acceptance
all succeed. Preserve the verifier's nonce-store **file** across restarts; the
same request with that store must be rejected as replay. A missing/stale output
can yield `state_inconclusive`; acceptance does not reserve coins or guarantee
future unspent status. See [verifier policy](./signature-possession#verify-with-retained-authority-and-durable-replay-state).

Outputs are exclusive: use fresh paths for retries. An expired request needs a
new verifier-issued request, new signature/receipt and proof. Keep the original
request and durable nonce store under verifier retention policy; remove only
your owned disposable wallet/signature/receipt copies when no longer needed.

## Observed compatibility

Measured 2026-11-08 with Sparrow Server 2.5.6, bundled Drongo
`13059ebc2979640b30bc1534b4584e2191578672`, QuietProof ECDSA v3 and Core 32.1:

| Address / wallet format | Actual Sparrow result | QuietProof result |
| --- | --- | --- |
| P2WPKH / BIP322 Simple | Produced and wallet-verified | Imported; public signet proof `valid_current` |
| P2WPKH or compressed P2PKH / BIP322 Full | Production unsupported | Fixed ECDSA parser tested with independent fixtures only |
| Compressed P2PKH / BIP322 Simple | Unsupported | No Sparrow-derived proof |
| P2WPKH or P2PKH / Standard (Electrum), BIP137 | Produced and wallet-verified | Rejected: legacy signed-message digest |
| P2TR / BIP322 Simple | Schnorr produced and wallet-verified | No P2TR request/proof relation |
| P2TR / Full or legacy compact | Unsupported | No proof claimed |

Only the first row completed actual Sparrow → PoSC → public-chain verification.
The observed public proof was about **49.7 MB**, not a performance guarantee.
Regtest/independent fixtures establish separate parser behavior, not additional
public-network wallet support. The repository's `scripts/sparrow_signer.md`
records the detailed compatibility evidence and public request/proof hashes.
