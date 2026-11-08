# Disposable signet funding qualification

These separate tools prepare and submit one explicitly authorized disposable
wallet transfer. They are never called by the message signer or Quietproof's
request, import, authorize or proof commands. They export no seeds or keys.

`sparrow_funding.py describe` reports the marked signet P2PKH wallet's receive
`m/0/0` and change `m/1/0` addresses. `prepare` signs with the installed Sparrow
Server 2.5.6 Drongo classes in `SparrowFunding.java`. Both operations open a
private temporary copy of the wallet, preserving the supplied original and
marker. The installed distribution/JDK requirements match `sparrow_signer.py`.
No network or RPC operation occurs in this tool, and no cryptography is
reimplemented in the adapter.

Preparation takes a new, private `--intent` JSON file containing exactly:

```text
network, genesis, sourceTransaction, sourceTxid, sourceVout, sourceAddress,
sourceValueSats, changeAddress, changeScript, destinationAddress,
destinationScript, amountSats, feeSats
```

`sourceTransaction` is canonical lowercase raw transaction hex; scripts are
hex. `network` must be `signet`, with public signet's genesis hash. Integer
`amountSats` must be 3000; `feeSats` must be 1–500, with total external debit
at most 3500 sats and P2PKH change at least 546 sats. The stock wallet must
own the source receive script and change script. The destination must be a
different test-network P2PKH address, independently verified as Core-owned by
the separate live audit. Address prefixes do not distinguish signet/testnet;
the marker, intent genesis and live chain validation bind the network.

```sh
python3 scripts/sparrow_funding.py describe \
  --sparrow "$SPARROW" --jdk "$JDK" --cache "$CACHE" --wallet-dir "$WALLET"
python3 scripts/sparrow_funding.py prepare \
  --sparrow "$SPARROW" --jdk "$JDK" --cache "$CACHE" --wallet-dir "$WALLET" \
  --intent "$PRIVATE/intent.json" --output "$PRIVATE/new-bundle"
```

The new mode-0700 bundle contains exclusive mode-0600 `intent.json`,
`signed.hex` and `audit.json`, including the txid, SHA256 of the binary raw
transaction, intent hash, ownership paths, fee and software identities.
Existing bundles are rejected before signing; preparation never retries or
replaces an earlier transfer. Partial preparation also requires inspection,
not automatic re-signing. Keep this live material outside Git.

`signet_funding.py audit` independently checks exact signed bytes against the
intent, Core's decoder, the current confirmed source, a synchronized validated
public signet chainstate, the named Core descriptor wallet's compressed P2PKH
ownership/private-key capability, and read-only `testmempoolaccept`. Its only
endpoint is explicit IPv4 localhost HTTP with an owner-only Core cookie.
It never unlocks a wallet, imports keys, selects coins or signs a transaction.

```sh
python3 scripts/signet_funding.py audit --bundle "$PRIVATE/new-bundle" \
  --rpc-url http://127.0.0.1:38332 --cookie "$COOKIE" \
  --wallet quietproof-disposable-example --output "$PRIVATE/new-audit.json"
```

After independently checking the complete audit and transaction, explicitly
invoke `broadcast` with `--txid` equal to the prepared txid and a new `--output`
path. This tool records and fsyncs an exclusive attempt before its single
`sendrawtransaction` call. Every reentry with that attempt only reconciles the
same txid through UTXO, mempool and Core-wallet observations. A timeout cannot
cause a second submission or a new signed transfer. `reconcile` is read-only.
An unknown result exits 2 and needs investigation; it is not confirmed funding.
Confirm the output independently on public signet before qualifying a proof.
No tool starts/stops Core or changes its configuration.

The tests never spend. Ordinary tests use synthetic wire fixtures and mocked
RPC. The opt-in installed test creates fresh unfunded wallets and signs a
synthetic parent that is never sent to a node; it checks stock-library signing,
unowned input/change rejection and byte preservation of the original wallet.

```sh
python3 scripts/test_sparrow_funding.py -v
python3 scripts/test_sparrow_funding.py --sparrow "$SPARROW" \
  --jdk "$JDK" --cache "$CACHE" -v
```
