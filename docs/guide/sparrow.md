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

Both supported signing procedures use the single **v4** PoSC format. Old v3
requests, signatures, receipts and proofs must be replaced with a fresh v4
exchange; importing them never upgrades them. P2WPKH defaults to
`bip322-ecdsa-v1`; compressed P2PKH defaults to
`bitcoin-message-ecdsa-v1`. The request fixes the procedure before signing.
For stock Core signing, see [the Core companion](./core-signing).

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
KIND=p2wpkh
FORMAT=bip322-simple
signer() {
  python3 scripts/sparrow_signer.py "$@" \
    --sparrow "$SPARROW" --jdk "$JDK" --cache "$WORK/cache" \
    --network signet --wallet-dir "$WORK/wallet" --script-kind "$KIND"
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
For a separate compressed-P2PKH wallet, set `KIND=p2pkh` and `FORMAT=standard`
before creation. For an existing marked P2PKH change address, additionally pass
`--key-path m/1/0` to each helper operation; the default is receive `m/0/0`.
The adapter calls stock Drongo `ECKey.signMessage` for Standard/Electrum
signatures; no Sparrow patch or private-key export is needed.

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
issuance records. Native CLI `inspect` does not inspect PoSC requests/proofs.

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
signer sign --address "$ADDRESS" --format "$FORMAT" \
  --message "$WORK/prover/message.txt" --output "$WORK/prover/signature.json"
signer verify --address "$ADDRESS" --format "$FORMAT" \
  --message "$WORK/prover/message.txt" --signature "$WORK/prover/signature.json"
```

The exported file contains exactly **88 ASCII bytes, without a final newline**.
It is `quietproof:signature:v4:` followed by 64 lowercase request-digest hex digits.
Sign that file, not the human `--message` text. Do not trim, retype, add a BOM or
append a newline. The helper signs every supplied byte and verifies the result.
Homogeneous address claims infer the signing kind; mixed kinds require an
explicit supported `--signing-kind`.
For compressed P2PKH only, `--signing-profile bip322-ecdsa-v1` at request
creation explicitly selects the BIP322 Full alternative. Sparrow 2.5.6 cannot
produce that Full transport; use a qualified Core adapter instead. Mixed-kind
claims require explicit signing kind and profile selection.

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
build. Keep signatures and `.qpa` receipts mode **0600**, outside Git and the
browser: a receipt holder can delegate/re-prove this request. There is no key
export fallback. Only public requests/proofs belong in a browser handoff.

Alternatively import a private raw file with `--signature-format bitcoin-message`
for the P2PKH default, or `--signature-format bip322-simple` for P2WPKH. Raw input
is canonical Base64 with no whitespace/newline; BIP322 Simple also accepts the
`smp` prefix. Helper JSON and raw text are transport encodings of the same
signature, not profiles. Legacy compact signatures accept only compressed-P2PKH
headers 31–34 and strict low-S. Changing an encoding cannot change the request's
digest or select another profile.

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
`13059ebc2979640b30bc1534b4584e2191578672`, stock Core 32.1 and PoSC v4:

| Address / profile | Wallet and transport exercised | Import / proof result |
| --- | --- | --- |
| Compressed P2PKH / Bitcoin Signed Message (default) | Core `signmessage`, raw Base64; integrated `authorize` | Matching receipts; RPC-OFF proof, 3,000 sats `valid_current` |
| Compressed P2PKH / Bitcoin Signed Message (default) | Sparrow Standard/Electrum, raw Base64 and helper JSON | Both imports; RPC-OFF proof from raw import, 6,700 sats `valid_current` |
| P2WPKH / BIP322 (default) | Sparrow Simple, `smp`/raw Base64 and helper JSON | Imports; RPC-OFF proof from raw import, 9,343 sats `valid_current` |
| Compressed P2PKH / explicit BIP322 | Core fixed Full transaction adapter | Authorization/import qualified; no fourth public-chain proof |
| P2WPKH / BIP322 Full | Fixed-profile native fixtures | Parser/proof tests; no Sparrow Full production claim |
| P2PKH / BIP322 Simple; P2WPKH / compact message | Incompatible tuples | Rejected; no automatic fallback |
| Uncompressed P2PKH, Taproot, multisig or unknown profiles | Outside the supported relation | No PoSC support; Sparrow Schnorr production is not a PoSC proof |

The three public proofs returned `valid_current` during the retained
19:05–19:11 UTC run, with independent root verification at 19:18–19:20 UTC.
Those are historical observations, not a current balance promise. They all use
**one unchanged ECDSA/HASH160 circuit and one proof per request**; host adapters
derive different signing digests. Detailed measurements and public artifact
identities are in repository `scripts/sparrow_signer.md`.

The [BIP137 header table](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki)
and [BIP322 specification](https://github.com/bitcoin/bips/blob/master/bip-0322.mediawiki)
describe the underlying formats. QuietProof supports the bounded subset above,
not general BIP322 Script or its separate proof-of-funds PSBT format. Inspected
version sources are [Sparrow 2.5.6](https://github.com/sparrowwallet/sparrow/tree/2.5.6)
and [Drongo ECKey](https://github.com/sparrowwallet/drongo/blob/13059ebc2979640b30bc1534b4584e2191578672/src/main/java/com/sparrowwallet/drongo/crypto/ECKey.java).

## Adding a future profile

A new profile needs an explicit address/procedure compatibility entry, canonical
request/transcript binding, an independently derived digest and strict importer,
and positive/negative native, browser and GUI vectors. The verifier must approve
its circuit locally; a request or wrapper cannot choose executable circuits or
supply authoritative `h`/`z`. Recheck circuit identity and public-input layout,
wallet provenance, package delivery, no-fallback behavior and chain/replay policy
before claiming support. See [the normative v4 contract](/technical/signature-profile).
