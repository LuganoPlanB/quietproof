---
title: Build and try QuietProof
description: Discover Bitcoin outputs, create a challenge, prove offline, and verify with native Core RPC.
---

# Build and try QuietProof

Discover Bitcoin outputs, create a challenge, prove key control, verify against
Bitcoin Core. Supply a native P2WPKH or compressed-key P2PKH address; Core supplies the public claims.
The prover needs the request and its keys. The verifier chooses the policy and
trusted node, then independently checks the proof and current UTXOs.

## Build

Use a C++20 compiler, CMake 3.20+, the installed
[LongfellowZK circuit SDK](https://dyne.org/longfellow-zk), and the development
package for a supported, patched libcurl (API version 7.62+). Linux and macOS
are supported POSIX environments. The native adapter supports Core 28+;
the live acceptance suite is pinned to Core 28.3 and 30.3.

From the repository root:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  "-DCMAKE_PREFIX_PATH=/path/to/longfellow-prefix"
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure -E '^pokc-test$'
```

The separate `pokc-test` runs real one- and two-key proofs and uses substantial
CPU and memory. The opt-in Core integration test is explicitly skipped by
normal builds; see the [operations runbook](../operations.md#testing-and-release).
The executable is `build/quietproof`.

## Prepare an isolated regtest node

This setup is node administration, separate from the ordinary QuietProof flow.
It needs Bash, Python 3 for port/JSON conveniences, and explicit paths to
`bitcoind` and `bitcoin-cli`. Neither Python nor `bitcoin-cli` is a native
QuietProof runtime dependency. Use verified official Core binaries.

The disposable fixture uses scalar **1**, whose 32-byte hexadecimal encoding is
`0000000000000000000000000000000000000000000000000000000000000001`.
Its compressed public key is published below. This fixture is public: use it
only on this private regtest chain. For real funds, use a key the prover already
holds; never export a production wallet key to follow this tutorial.

Run the remaining blocks in the same Bash session, from the repository root.
Replace the binary directory with your explicit local Core path:

```sh
BITCOIN_BIN=/absolute/path/to/bitcoin-28.3/bin
QP="$(pwd)/build/quietproof"
DEMO=$(mktemp -d "${TMPDIR:-/tmp}/quietproof-demo.XXXXXX")
chmod 700 "$DEMO"
RPC_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
RPC_URL="http://127.0.0.1:$RPC_PORT/"
NODE_PID=
core() { "$BITCOIN_BIN/bitcoin-cli" -regtest -datadir="$DEMO" -rpcport="$RPC_PORT" "$@"; }
stop_demo() {
  if [ -n "$NODE_PID" ]; then
    core stop >/dev/null 2>&1 || kill "$NODE_PID" 2>/dev/null || true
    wait "$NODE_PID" || true
    NODE_PID=
  fi
}
trap stop_demo EXIT
start_demo() {
  "$BITCOIN_BIN/bitcoind" -regtest -server=1 -datadir="$DEMO" \
    -rpcport="$RPC_PORT" -rpcbind=127.0.0.1 -rpcallowip=127.0.0.1 \
    -listen=0 -connect=0 -dnsseed=0 -discover=0 -natpmp=0 \
    -fallbackfee=0.0002 >"$DEMO/node.log" 2>&1 &
  NODE_PID=$!
  for attempt in {1..100}; do
    if core getblockchaininfo >/dev/null 2>&1; then return 0; fi
    sleep 0.1
  done
  printf '%s\n' 'Regtest startup failed; inspect the private node.log' >&2
  return 1
}
start_demo
core createwallet funding >/dev/null
MINER=$(core -rpcwallet=funding getnewaddress '' bech32)
core generatetoaddress 101 "$MINER" >/dev/null
PUBKEY=0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
DESC=$(core getdescriptorinfo "wpkh($PUBKEY)" | python3 -c 'import json,sys; print(json.load(sys.stdin)["descriptor"])')
ADDRESS=$(core deriveaddresses "$DESC" | python3 -c 'import json,sys; print(json.load(sys.stdin)[0])')
core -rpcwallet=funding sendtoaddress "$ADDRESS" 1 >/dev/null
core generatetoaddress 2 "$MINER" >/dev/null
```

The fixture secret remains outside Core. Only its public descriptor is used to
find the address; replace `wpkh($PUBKEY)` with `pkh($PUBKEY)` in `DESC` to try
a compressed-key P2PKH fixture instead. The funding wallet has its own unrelated keys. This creates
one confirmed 1-BTC output on an isolated chain, with no external peers.

## Create, inspect and prove

The verifier supplies its own identity, purpose and message. Discovery is a
node-wide UTXO scan; the challenge clock starts after it finishes.

```sh
"$QP" challenge create --network regtest --address "$ADDRESS" \
  --verifier example.org --purpose proof-of-funds --message 'Proof of control' \
  --output "$DEMO/request.qpr" --rpc-url "$RPC_URL" --rpc-datadir "$DEMO"
"$QP" inspect "$DEMO/request.qpr"
stop_demo
"$QP" prove --request "$DEMO/request.qpr" --output "$DEMO/proof.qpf"
```

At the protected prompt, enter the published disposable scalar-1 encoding
above. For other requests, enter one 32-byte hexadecimal secret per distinct
key hash; input order does not matter. Terminal echo is disabled. For automation,
use a protected pipe whose producer does not log its output. Never put real
secrets in argv, environment variables or shell history.

Core is stopped during proving: this stage reads no RPC cookie/configuration
when invoked without wallet/RPC options. It can run on another offline machine.
Explicit Roots wallet-backed proving supports P2WPKH/P2PKH requests sharing one key hash. Requests and
proofs are mode `0600`, and existing output paths are never overwritten.
The default challenge lifetime is 300 seconds; it must still be valid at
verification. If it expires, create a fresh request and proof.

## Verify against the restarted node

```sh
start_demo
"$QP" verify "$DEMO/proof.qpf" --network regtest \
  --verifier example.org --purpose proof-of-funds --max-lifetime 300 \
  --nonce-store "$DEMO/nonces" --rpc-url "$RPC_URL" --rpc-datadir "$DEMO"
```

Expect JSON `result: "valid_current"` and exit 0. This is fresh chain evidence,
not a cached scan. Core rotates its cookie on restart; the native client reads
it again. A replay with the same nonce store returns `invalid_proof`, exit 67.
The nonce store is a **file**, owner-only and atomically locked/appended/synced
before success. Keep it durable across verifier restarts.

A null UTXO, including a mempool or mined spend, yields `state_inconclusive`,
exit 5. It is not authenticated historical spending evidence. Verification
does not reserve the coins or keep the mempool unchanged.

## Optional diagnostics and wallet discovery

Diagnostics are independent of challenge creation:

```sh
"$QP" utxos --network regtest --address "$ADDRESS" \
  --rpc-url "$RPC_URL" --rpc-datadir "$DEMO"
```

The JSON includes integer `amount_sats`, confirmations, source, observation tip,
`current_rechecked` and `challenge_compatible`. An empty or excessive discovery
can exit 0 with incompatibility; challenge creation rejects it. More than 16
outputs are never silently truncated.

To try the explicit wallet alternative, import only the fixture's public
checksummed descriptor into a test watch wallet:

```sh
core createwallet watch true true >/dev/null
core -rpcwallet=watch importdescriptors "[{\"desc\":\"$DESC\",\"timestamp\":0}]" >/dev/null
"$QP" utxos --network regtest --address "$ADDRESS" --rpc-wallet watch \
  --rpc-url "$RPC_URL" --rpc-datadir "$DEMO"
```

QuietProof does not create, load, import or rescan wallets. This explicit setup
is for the tutorial. Wallet mode covers only what the loaded wallet tracks;
operators are responsible for imports/rescans. It excludes unsafe, locked and
immature outputs. A watch wallet can track the address while the key stays
with the prover; QuietProof does not filter on `spendable`.

When finished, stop only the child created above and remove its temporary data:

```sh
stop_demo
rm -r -- "$DEMO"
trap - EXIT
```

## An already funded signet address

For an existing native P2WPKH or compressed-key P2PKH address whose key the prover already holds, use a trusted,
fully validated local Core node with `server=1` and the default cookie layout:

```sh
build/quietproof challenge create --network signet --address tb1q... \
  --verifier example.org --purpose proof-of-funds --message 'Proof of control' \
  --output request.qpr
build/quietproof prove --request request.qpr --output proof.qpf
build/quietproof verify proof.qpf --network signet --verifier example.org \
  --purpose proof-of-funds --nonce-store ./nonces
```

Replace `tb1q...` with the full address. No `bitcoin-cli`, script extraction or
manual BTC conversion is required. Address prefixes cannot distinguish all
test networks: select the network explicitly and require that chain from Core.
For nondefault datadirs, ports or wallets, see
[RPC configuration and recovery](../operations.md).

The request/proof still discloses outpoints, amounts and public key hashes;
the address is sent to the selected local node. The proof hides the
spend keys and does not newly disclose compressed public keys. Prior spends
or key reuse may already expose a public key; proving cannot undo that exposure.
This is not anonymous proof of funds. Uncompressed-key P2PKH is unsupported,
and discovery cannot identify key encoding from a P2PKH script alone. It proves
neither exclusive ownership, title, solvency nor a collateral lock. Historical
snapshots require a separate authenticated historical provider through the API.
