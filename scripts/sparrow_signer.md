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
unmarked wallets are rejected. The selected receive key is account 0, external
branch 0, index 0; the `address` command reports the full derivation path.

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
does not import a signature into Quietproof or prove public chain custody.
