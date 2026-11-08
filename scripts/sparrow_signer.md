# Disposable Sparrow message signer

`sparrow_signer.py` is a local adapter over **installed Sparrow Server 2.5.6**
and its bundled Drongo classes, not an official RPC API or terminal signing
command. The inspected Sparrow tag pins Drongo commit
`13059ebc2979640b30bc1534b4584e2191578672`. It requires Linux x86-64, Python
3.11+, a JDK 25, and the complete Sparrow application image. It downloads
nothing and never connects to a network. See [official Sparrow documentation](https://sparrowwallet.com/docs/).

Use fresh disposable signet, testnet4 or regtest wallets only. Mainnet is
rejected. Wallet storage is Sparrow's unencrypted `.mv.db` format, protected by
owner-only directories and files; keep the directory private and outside Git.
The helper creates random seeds internally and never prints them. Each wallet
directory has a network-bound disposable marker and one script kind. Existing
unmarked wallets are rejected. The default receive key is account 0, external
branch 0, index 0. Explicit `--key-path m/1/0` selects the same account's owned
change branch, index 0; `m/0/0` preserves the default. Other paths are rejected,
and wallet creation requires the default receive path. `address` reports the
full derivation; signing requires that selected key's exact address. Existing
wallet operations open a private temporary copy, preserving the supplied
wallet and marker byte-for-byte. Both selections remain entirely offline.

```sh
umask 077
# Set these to explicit local paths. Keep work outside the repository.
SPARROW=/path/to/sparrowserver
JDK=/path/to/jdk25
WORK=/path/to/private-disposable-work
mkdir -m 700 "$WORK"

python3 scripts/sparrow_signer.py create \
  --sparrow "$SPARROW" --jdk "$JDK" --cache "$WORK/cache" \
  --network signet --wallet-dir "$WORK/wallet" --script-kind p2wpkh

# Copy the returned owned address. message.txt must contain the exact UTF-8
# signing material; a final newline is significant. No trimming is performed.
python3 scripts/sparrow_signer.py sign \
  --sparrow "$SPARROW" --jdk "$JDK" --cache "$WORK/cache" \
  --network signet --wallet-dir "$WORK/wallet" --script-kind p2wpkh \
  --address "$ADDRESS" --format bip322-simple \
  --message "$WORK/message.txt" --output "$WORK/signature.json"

python3 scripts/sparrow_signer.py verify \
  --sparrow "$SPARROW" --jdk "$JDK" --cache "$WORK/cache" \
  --network signet --wallet-dir "$WORK/wallet" --script-kind p2wpkh \
  --address "$ADDRESS" --format bip322-simple \
  --message "$WORK/message.txt" --signature "$WORK/signature.json"
```

Signatures are written exclusively to a new mode-0600 JSON file. Standard
output contains address, derivation, format and verification status, without the
signature. All input files are bounded to 1 MiB; message input must be valid
UTF-8 and is signed byte-for-byte, including BOMs, NULs and final newlines.
Symlink inputs and existing output paths are rejected. `address` reloads the
same wallet; `provenance` reports the installed module image, native library,
adapter and JDK hashes. The private cache extracts the installed module image
with `jimage`, copies its native secp256k1 library as a resource, and compiles
the adapter. It does not build or replace Drongo cryptography. Use a cache
owned only by you; concurrent preparation of the same cache is unsupported.

| Address kind | `bip322-simple` | `standard` / `electrum` | `bip137` |
| --- | --- | --- | --- |
| P2WPKH | Produced and verified | Compact ECDSA header 31–34 | Compact ECDSA header 39–42 |
| Compressed P2PKH | Rejected by bundled library | Compact ECDSA header 31–34 | Same P2PKH compact header |
| P2TR | Produced and verified, Schnorr | Rejected | Rejected |

Sparrow calls its first compact option “Standard (Electrum)”; both helper
spellings select that same operation. Compact signatures use Bitcoin's legacy
signed-message digest and are **not BIP322**. Sparrow emits `smp` followed by
the Base64 Simple witness. The helper preserves that prefix. BIP322 Full is
unsupported. P2TR signer support does not establish Quietproof proof support.
These are bundled-library observations, not claims of a terminal UI action.
The desktop dialog trims text; this adapter deliberately preserves exact bytes.

Run the integration suite against the actual supplied distribution:

```sh
python3 scripts/test_sparrow_signer.py \
  --sparrow "$SPARROW" --jdk "$JDK" --cache "$WORK/cache" -v
```

Tests create isolated wallets and check reload/ownership, UTF-8/newlines,
repeat signing, independent witness/header decoding, format rejection, wrong
messages/addresses, unsafe files and private output handling. They never use
funded wallets. Live wallet/signature files belong outside Git. This helper
does not itself import a signature into Quietproof or prove public chain custody.

The native CLI can export the exact request-bound signing material and import
the helper's private JSON. Build with `QUIETPROOF_BUILD_SIGNATURE_MODE=ON`;
these operations and receipt proving also work with `QUIETPROOF_BUILD_RPC=OFF`.
Keep the verifier's original `.qpr` independently; signing the user's original
`--message` text does not authorize the request.

```sh
quietproof signing-material --proof-mode signature-possession \
  --request issued.qpr --network signet --address "$ADDRESS" \
  --output "$WORK/message.txt"
# Run the sign command above with this exact message.txt, then:
quietproof import-signature --proof-mode signature-possession \
  --request issued.qpr --network signet --address "$ADDRESS" \
  --signature-input "$WORK/signature.json" --signature-format sparrow-json \
  --receipt-output "$WORK/receipt.qpa"
quietproof prove --proof-mode signature-possession --request issued.qpr \
  --receipt-input "$WORK/receipt.qpa" --output public.qpf
```

Export writes exactly 88 ASCII bytes without a newline and prints the public
address, context and statement digest for inspection. Import validates the
signature, compressed public key, request digest, network, script kind and
fixed SIGHASH_ALL/low-S profile before exclusively creating a mode-0600 receipt.
Raw `bip322-simple` and `bip322-full` inputs are exact Base64 text files, with
`smp`/`ful` prefixes accepted; prefixless pre-final BIP322 encodings require the
explicit format. Whitespace and noncanonical Base64 are rejected. Simple is
P2WPKH only; Full accepts the existing fixed P2WPKH/compressed P2PKH ECDSA
transaction profile. Installed Sparrow cannot produce P2PKH BIP322 or Full:
its compressed-P2PKH Standard/Electrum signatures authorize the separate v4
`bitcoin-message-ecdsa-v1` profile using `--signature-format bitcoin-message`
or `sparrow-json`. P2WPKH compact headers and P2TR Schnorr witnesses cannot
satisfy that profile. Full parser support does not claim
Sparrow Full production. No format conversion changes the signed digest.

Run the opt-in cross-application import tests with actual installed Sparrow:

```sh
python3 tests/quietproof/sparrow_import_test.py --cli /path/to/quietproof \
  --sparrow "$SPARROW" --jdk "$JDK" --cache "$WORK/cache"
```

These disposable offline integration tests make no chain-state claim. Public
verification still requires `--expected-request issued.qpr`, the expected
network/audience/purpose, current chain state, expiry policy and a nonce store.

## Current v4 qualification

The [concise Sparrow guide](../docs/guide/sparrow.md#observed-compatibility) and
[Core companion](../docs/guide/core-signing.md) give the current workflow and
measured matrix. P2PKH defaults to `bitcoin-message-ecdsa-v1`; P2WPKH to
`bip322-ecdsa-v1`. Explicit P2PKH BIP322 uses Full. These are host adapters
around one unchanged ECDSA/HASH160 circuit, 53 public inputs and one proof.
All v3 requests and dependent signatures/receipts/proofs require reissuance.

On **2026-11-08, 19:05–19:11 UTC**, actual stock Core 32.1 P2PKH `signmessage`,
Sparrow 2.5.6 compressed-P2PKH Standard/Electrum (`ECKey.signMessage`) and Sparrow
P2WPKH BIP322 Simple each completed raw import → RPC-disabled proof → signet
`valid_current`. Core integrated `authorize` produced the same receipt as its
external signature. Both Sparrow helper-JSON imports also passed separately;
they did not create additional proofs. Core P2PKH BIP322 Full authorization
and import passed, without a fourth public-chain proof. No upstream patches or
private-key exports were used. Independent root verification at 19:18–19:20 UTC
rechecked the three public proofs and replay rejection.

| Actual wallet/profile | Sats observed | Request SHA256 | Public proof SHA256 / bytes |
| --- | ---: | --- | --- |
| Core P2PKH / Bitcoin Signed Message | 3,000 | `058dcbed282544d78c38dec956fe8ba7d5a6649a3339876ffbc86b5e63e172a1` | `2b0ff9816788960f3c3118414d5b93d5026b20bea29e601759a955d46806630d` / 49,727,432 |
| Sparrow P2PKH change `m/1/0` / Bitcoin Signed Message | 6,700 | `10ff2dac3fbc047544e8fbca61c9c531206ae37924020e676bea46a123d6ff9a` | `bf90c60af3c65b636c49f7fc0bcaeb78c77172d03c05614d3ec853a78e34692d` / 49,727,624 |
| Sparrow P2WPKH / BIP322 Simple | 9,343 | `ffa4a0315d77879e69c2f73704261556a0b2ecf4aa51cbe489b2a11e40d8e58c` | `37be7ddf4259453096ee4196932487f69adfc7a35bf14b4c0a628478c56535d4` / 49,727,560 |

The capped funding transaction was
`4418d5294d06497bc8544b8a8d12f2b0b8e89b3eceb1002f5f77845424cb697e`,
confirmed at signet height 329983: output 0 was 3,000 sats to Core, output 1
6,700 sats to Sparrow's owned change key, and the fee was 300 sats. It spent the
historical 10,000-sat P2PKH output below; that old output is no longer unspent.
The separate P2WPKH 9,343-sat output was retained. Balances and `valid_current`
are original observations, not promises about future unspent status.

## Archived v3 observations — unsupported format

The following older run is historical evidence only. Its v3 artifacts and
legacy-signature rejection describe the superseded BIP322-only contract,
not the supported v4 behavior above. Do not reuse these requests or proofs.

Observed interoperability on **2026-11-08**, installed Sparrow Server **2.5.6**,
bundled Drongo commit above, Quietproof ECDSA v3 profile and Bitcoin Core **32.1**:

| Address | Wallet format | Sparrow produced/verified | Quietproof imported | Sparrow-derived proof / chain verification |
| --- | --- | --- | --- | --- |
| P2WPKH | BIP322 Simple | Yes | Yes, `smp` and explicit prefixless text; helper JSON | Yes / public signet `valid_current` |
| P2WPKH | BIP322 Full | Unsupported | Fixed-profile parser tested with independent fixtures | Not produced |
| Compressed P2PKH | BIP322 Simple | Unsupported | Unsupported | Not produced |
| Compressed P2PKH | BIP322 Full | Unsupported | Fixed-profile parser tested with independent fixtures | Not produced |
| P2WPKH / P2PKH | Standard/Electrum/BIP137 | Yes | Rejected: legacy signed-message digest | Not produced |
| P2TR | BIP322 Simple | Yes, Schnorr | Rejected; no P2TR request/proof relation | Not produced |
| P2TR | Full / Standard/Electrum/BIP137 | Unsupported | Not claimed | Not produced |

The P2WPKH public run used address
`tb1qq7wcnkj5qarr7k650al2z2m2k0f665hflysz5x`, real outpoint
`0c979c5dab2dfa0ebc69438c0269a01d8a675fed464d4c8ea632f26a752092da:0`,
and **9,343 sats**. The original request was retained independently before
proof verification. Its SHA256 is
`2ffda6c051605d8bbb965f1b5258a7fa18b217d4e1e73250e1f9cbec05fc6ddb`;
the public 49,728,669-byte `.qpf` SHA256 is
`0c26d776ca104d62acfd9736b4a77ab7543413aec0e07f236a4316a85fd180c1`.
The proof was generated with RPC disabled. At **01:02:04 UTC**, chain-aware
verification with the retained request, expected signet/audience/purpose,
one-day maximum request lifetime and persistent nonce store returned
`valid_current`, one checked claim and 9,343 sats. Core and an independent
public signet explorer confirmed the output unspent around verification;
this records that observation, not its future status. Replay and altered
request/address/network/audience/purpose/lifetime/proof were rejected.

The funded P2PKH address `mfnsmnVCSGhcC4WrFzaSbupdZYxn9o9Jko` had a confirmed
10,000-sat output. Actual signing attempts established the table's limitation:
available legacy signatures cannot authorize the BIP322 request. The P2TR
probe signed the P2WPKH request's message bytes for a separate P2TR address;
it establishes Schnorr production and rejection, without claiming funding,
a supported P2TR Quietproof request, or a P2TR proof. No keys were exported
and no replacement signature was synthesized.
