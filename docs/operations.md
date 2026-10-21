---
title: Operations and production controls
description: Native Core RPC configuration, discovery costs, verifier policy, recovery and release gates.
---

# QuietProof operations

Discover Bitcoin outputs, create a challenge, prove key control, verify against
Bitcoin Core. The [isolated regtest guide](guide/getting-started.md) uses a public,
disposable externally held key and demonstrates offline proving. On an already
funded address, the ordinary commands are:

```sh
build/quietproof challenge create --network signet --address tb1q... \
  --verifier example.org --purpose proof-of-funds --message 'Proof of control' \
  --output request.qpr
build/quietproof prove --request request.qpr --output proof.qpf
build/quietproof verify proof.qpf --network signet --verifier example.org \
  --purpose proof-of-funds --nonce-store ./nonces
```

Replace the placeholder with the full native P2WPKH address. Native RPC is the
default, with no `bitcoin-cli` invocation or automatic backend fallback.
Proving accepts only the request, output and protected stdin secrets; no Core
connection, RPC flags or cookie are needed on the prover's machine.

::: warning
This is free and open source software provided without warranty under
the terms of the GNU GPL v3 license. Professional support,
maintenance, integration services, and contractual warranty options
are available separately. Please contact us for further information.
:::

## Native RPC configuration

Use a trusted, fully validated Core 28+ node with `server=1`, running under the
same user as QuietProof. Live compatibility tests cover pinned Core 28.3 and
30.3. Chain identity and a stable tip alone do not prove synchronization or
server identity. The adapter does not parse `bitcoin.conf`, discover containers
or Snap layouts, or probe alternate endpoints/networks after a failure.

| CLI network | Core `chain` | Default loopback RPC port | Cookie relative to base datadir |
| --- | --- | ---: | --- |
| `mainnet` | `main` | 8332 | `.cookie` |
| `testnet3` (`testnet` alias) | `test` | 18332 | `testnet3/.cookie` |
| `signet` | `signet` | 38332 | `signet/.cookie` |
| `regtest` | `regtest` | 18443 | `regtest/.cookie` |
| `testnet4` | `testnet4` | 48332 | `testnet4/.cookie` |

Default URLs are `http://127.0.0.1:PORT/`. The default base datadir is
`$HOME/.bitcoin` on Linux or `$HOME/Library/Application Support/Bitcoin` on
macOS. Unsupported home/platform resolution requires an explicit path.
Pass the **base** datadir, not its `signet`/`regtest` subdirectory.

| Option | Scope and behavior |
| --- | --- |
| `--rpc-datadir DIR` | Address discovery/native verify; base directory for deterministic cookie lookup. |
| `--rpc-cookie FILE` | Explicit credential file; takes precedence over datadir lookup. |
| `--rpc-url URL` | Explicit numeric IPv4/IPv6 loopback HTTP root URL and port; no credentials, hostname, query or fragment. |
| `--rpc-timeout SECONDS` | Ordinary RPC deadline, default 30 seconds. |
| `--rpc-scan-timeout SECONDS` | Discovery only; scan deadline, default 600 seconds. |
| `--rpc-wallet NAME` | Discovery only; a nonempty, already loaded named wallet instead of a full UTXO scan. |
| `--min-confirmations N` | Discovery defaults to 1 and requires at least 1; verification separately reapplies its local threshold (default 1). |
| `--network NAME` | Required for discovery; optional local assertion on verify, checked before RPC. Otherwise verify uses the statement network and requires that exact Core chain. |

Deadlines must be positive and at most 86,400 seconds. Connect timeout defaults
to 5 seconds in the C++ config. Use a supported patched libcurl; 7.62 is an API
compatibility floor, not a recommendation to deploy an old release.

For a nondefault node:

```sh
build/quietproof utxos --network signet --address tb1q... \
  --rpc-datadir /srv/bitcoin --rpc-url http://127.0.0.1:38333/
build/quietproof challenge create --network signet --address tb1q... \
  --verifier example.org --purpose proof-of-funds --message 'Proof of control' \
  --output request.qpr --rpc-cookie /private/node.cookie \
  --rpc-url 'http://[::1]:38333/'
```

For multiple nodes, configure each endpoint and cookie explicitly. For a remote
node, use an explicitly managed local tunnel and credential file; arbitrary
remote HTTP/TLS endpoints are outside this adapter's scope. Cookie Basic auth
authorizes the client to Core. It does not authenticate a server against a
malicious local process; choosing and protecting the endpoint remains the
operator's responsibility.

Cookies must be regular files owned by the effective user with no group/other
permissions. The final component cannot be a symlink. The client reads at most
4 KiB, rejects malformed credentials and rereads the file on every request for
rotation. Group-shared Core cookies fail explicitly: use same-user operation
or an owner-only explicitly managed credential file. Never put credentials in
URLs, arguments, environment variables, logs or proof files. There is no
`--rpc-password` option. Owned buffers are erased where practical; libcurl does
not guarantee complete credential memory erasure.

The transport disables proxies (including proxy environment variables),
redirects, netrc and compressed responses. Each response body is capped at
1 MiB, headers at 32 KiB and JSON nesting at 64. Requests use strict JSON-RPC
2.0 IDs/envelopes and exact decimal-to-satoshi parsing. A timeout or error does
not trigger a retry, port/network fallback or legacy invocation.

## Discovery costs and coverage

Default discovery uses `validateaddress` and one `scantxoutset` address
descriptor. It supports only native P2WPKH: P2SH, P2WSH, P2TR and arbitrary
scripts/descriptors are unsupported. A `tb1` prefix alone cannot select between
testnet3, testnet4 and signet; select the network and validate the node chain.

A scan visits the whole UTXO set, including unrelated outputs. It may take
minutes and compete for disk/cache resources. It excludes mempool-only outputs.
Confirmations derive from the scan height; eligible compatible outputs are
then independently rechecked at one current tip. A tip advance does not cause
another full scan. A disappeared output or inconsistent tip fails the whole
recheck, rather than silently dropping a candidate.

Only after discovery/rechecks finish does challenge creation generate nonce
and timestamps. The scan observation is not a historical snapshot and does not
become authoritative evidence at verification time.

Wallet mode avoids the full-set scan:

```sh
build/quietproof utxos --network signet --address tb1q... --rpc-wallet watch
build/quietproof challenge create --network signet --address tb1q... \
  --rpc-wallet watch --verifier example.org --purpose proof-of-funds \
  --message 'Proof of control' --output request.qpr
```

The wallet must already be loaded, track the address and have completed any
necessary rescan. QuietProof never creates, loads or imports wallets and never
falls back to a scan. It requests safe outputs for that address using
`listunspent`, excluding unsafe, locked and immature coins. Public-only watch
wallets are supported; the `spendable` flag is not an eligibility filter.
Wallet results describe tracked wallet coverage, not exhaustive address funds.
Use this mode for an already tracking wallet or arrange discovery outside
high-frequency request handling; no persistent index/cache is provided here.

`utxos` JSON reports integer satoshis, public programs/outpoints, confirmations,
source, exclusions, observation identity, recheck and challenge compatibility.
A valid empty set or more than 16 eligible outputs can exit 0 diagnostically.
Challenge creation rejects both. No largest/first-16 selection occurs. Generic
challenges also permit at most two distinct programs, reject duplicates and
check aggregate MAX_MONEY. Advanced callers can explicitly select manual
claims; subsets require their own rechecks. Verification always looks up the
actual proof claims afresh.

A busy scan may belong to another client. A timeout/disconnect can leave Core
scanning. QuietProof never polls, retries or sends an automatic abort. With
your node-administration tool, inspect `scantxoutset status`; wait for the scan
owner, or deliberately use `scantxoutset abort` only when authorized to cancel
that scan. Increase the separate deadline or choose a tracking wallet before
starting a new request. No mainnet/signet scan-latency guarantee is made.

## Trust boundary and local policy

The verifier chooses expected metadata, validity/confirmation/value thresholds,
a durable nonce store and the trusted fully validated node. Discovery supplies
candidate public claims; the prover receives the canonical request and its
protected key material. The verifier checks decoding, local policy and the real
proof before consulting chain evidence, matches exact scripts/amounts/network
at one common stable tip, applies remaining policy and consumes the nonce once.
Neither a successful RPC nor the request itself can authorize a proof.

`BitcoinCoreRpc` performs fresh before/gettxout/after observations, always
including mempool spends. This authenticates evidence through the chosen node
channel; QuietProof does not independently verify headers/PoW or create an
inclusion proof. A null/unknown/spent current UTXO is `state_inconclusive`, never
`spent_at_snapshot`. A stable tip does not freeze the mempool or lock coins.
Historical statements require a separate authenticated historical provider;
the native client and CLI do not reconstruct historical spending.

The node receives the address. Requests/proofs disclose outpoints,
amounts and witness programs, allowing tracing and association with known prover
identities. Recipients can share proofs; verifier binding is not access control.
Keys stay hidden unless disclosed elsewhere. RPC changes no formats
or circuits. Key knowledge proves neither exclusive ownership, legal title,
solvency nor locked collateral.

Supply verifier/purpose expectations locally on every verify operation. Keep
lifetimes short (default challenge 300 seconds, maximum 86,400) and use fresh
requests/nonces. Request/proof outputs are owner-only and never overwrite an
existing path. The nonce store is a **file** whose owner-only, regular-file,
no-follow and locked atomic append/fsync checks must succeed. Persist it across
restarts; concurrent verification of one nonce authorizes at most once. Failed
proof, policy or evidence checks do not consume it.

## Errors and recovery

Successful CLI commands emit JSON on stdout; discovery diagnostics use stable
error categories on stderr. Discovery uses exit 64 for usage, 65 for bad
input/data and 74 for operational failures. Native verification preserves the
existing result JSON and exit codes; RPC failures usually become
`state_inconclusive` with redacted stderr details.

| Situation | Meaning and recovery |
| --- | --- |
| Invalid/wrong-network address | Check the full address/checksum and explicit network; no prefix-based network inference. |
| Unsupported script | Use native P2WPKH; wrapping, multisig, P2WSH and P2TR are unsupported. |
| No eligible outputs | Check funding, confirmed state and minimum confirmations; a diagnostic empty set is not a challenge. |
| Too many outputs | More than 16 cannot become an ordinary address challenge; an advanced explicit subset is a separate caller decision. |
| Missing/insecure cookie or authentication failure | Fix the explicit path, user ownership/mode or rotated credential; never try another node automatically. |
| Wrong Core chain | Correct the configured endpoint/network. `--network` on verify also asserts local policy before RPC. |
| Connection refused/unavailable | Restore the selected node/tunnel; failed evidence does not consume the nonce. |
| Scan busy/timeout/incomplete | Coordinate with the scan owner; check status, wait or deliberately abort only your authorized scan. No automatic retries. |
| Response too large/malformed | Inspect the node/version and response budget; no truncated or partially decoded result authorizes anything. |
| Tip changed/output disappeared | Recheck current state and create a fresh request when appropriate; no automatic rescan or claim dropping. |
| `stale_snapshot` (exit 4) | Evidence fails the locally required confirmation threshold, even for a current-tip proof. |
| `state_inconclusive` (exit 5) | Current evidence is absent, unavailable or inconsistent, or fails an amount/value requirement; never treat it as spending proof. |
| `invalid_proof` (exit 67) | Includes cryptographic failure, local metadata/time-policy mismatch, wrong asserted network or replay; inspect policy and the nonce store. |
| `malformed_statement` (65), `unsupported` (66) | Invalid encoding or unsupported version/circuit; reject and obtain compatible input. |
| `bridge_rejected` (6) | Required independent bridge authorization is absent or rejected; a key proof alone never authorizes issuance. |

Only `valid_current` (0), or a deliberately supported `valid_historical` (1)
from an independent historical integration, is an authorization outcome. Keep
proof parsing/verification under CPU and memory quotas. Persist the request,
proof, result, node identity/tip, software/circuit identity and policy version
in a controlled audit log; never log secrets or RPC credentials. Monitor
outpoints after acceptance when continued availability matters.

## C++ integration

Use `find_package(LongfellowZKQuietProof CONFIG REQUIRED COMPONENTS rpc)` and
link `LongfellowZKQuietProof::rpc`. The
[installed-source example commands](guide/getting-started.md#build-and-run-the-installed-c-example)
compile against the installation, exercise the same client and keep proving
independent of RPC. It has one-key support and fixed local demonstration
policy; applications can use existing `PoKCProveKeys<1|2>`, the shared
`CreateQuietProofChallenge` builder and `VerifyQuietProof` with their own
policy/provider. A bare `PoKCVerifyProof` verifies the relation only.
One RPC instance is sequential/non-thread-safe; use separate instances across
application threads. Core-only consumers use the original no-component package
and `LongfellowZKQuietProof::quietproof`, without curl linkage or lookup.

## Advanced manual and legacy compatibility

Manual claims remain fully offline, using displayed/RPC-order TXIDs and
`TXID:VOUT:SATOSHIS:PROGRAM` (the 20-byte program after `0014`). They cannot be
mixed with `--address` or RPC/discovery-only options:

```sh
build/quietproof challenge create --network signet --verifier example.org \
  --purpose proof-of-funds --message 'Proof of control' \
  --claim TXID:VOUT:SATOSHIS:PROGRAM --output request.qpr
```

To select the retained subprocess verifier explicitly:

```sh
build/quietproof verify proof.qpf --bitcoin-cli /absolute/path/to/bitcoin-cli \
  --verifier example.org --purpose proof-of-funds --nonce-store ./nonces
```

The path must be absolute and executable; this selection rejects simultaneous
native RPC flags and emits a deprecation notice on stderr. Its argv runner
passes the explicit network selector, bounds each output stream to 1 MiB and
kills its process group on timeout/overflow. Use a fixed audited wrapper with
explicit test/node configuration when needed. Native failures never select it.
Older Core installations can use this explicit compatibility path.

`-DQUIETPROOF_BUILD_RPC=OFF` configures without curl and retains manual
challenge creation, offline prove/inspect and the explicit legacy verifier.
RPC-only commands fail clearly. Examples and live native regtest require RPC
ON. Neither the legacy backend nor this optional build changes protocol bytes.

## Testing and release

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  "-DCMAKE_PREFIX_PATH=/path/to/longfellow-prefix"
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure -E '^pokc-test$'
ctest --test-dir build --output-on-failure -R '^pokc-test$'
```

The real one/two-key proof gate is expensive. To execute isolated native CLI
and C++ workflows against both pinned official Core releases:

```sh
cmake -S . -B build -DQUIETPROOF_ENABLE_BITCOIN_REGTEST_TEST=ON \
  -DQUIETPROOF_CORE28_DIR=/absolute/path/to/bitcoin-28.3/bin \
  -DQUIETPROOF_CORE30_DIR=/absolute/path/to/bitcoin-30.3/bin
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure -R '^quietproof-regtest-rpc-test$'
```

The serial test has `bitcoin-regtest`/`proof-heavy` labels and a four-hour outer
timeout. It creates private temporary datadirs, chooses loopback ports, disables
peers, checks official Core version identity, holds the proof key outside Core,
and cleans its own child/data. It tests offline proving, rotated cookies,
watch-only discovery, real proofs, replay single-winner, stable legacy parity,
same-height reorgs and fresh-proof mempool/mined spend rejection. Missing Core
binaries block this opt-in acceptance gate; disabled ordinary builds explicitly
skip it. Verify release checksums/signatures before supplying executable paths.

Release acceptance also requires RPC ON/OFF installed-package consumption,
core-only consumption with curl discovery disabled, shared/static curl link
closure, relevant sanitizer coverage and static analysis. The script needs
`clang-tidy`, `cppcheck` and `shellcheck`:

```sh
LONGFELLOW_ZK_INCLUDE_DIR=/path/to/longfellow-prefix/include/longfellow-zk \
  bash scripts/run_quietproof_static_analysis.sh
```

Keep deterministic protocol/vector, naming and spec gates. The independent
Sage 10.6 reference is optional (`QUIETPROOF_ENABLE_POKC_SAGE_TEST=ON`, requiring
Sage or Docker); the deterministic Sage vectors remain in the normal suite.
The optional CI ASan/UBSan installed-package gate can be enabled through the
CI workflow's manual input, or reproduced with Clang and
`scripts/ci-installed-package.sh`; it includes expensive real proofs. Record
actual runtime/memory, pinned revisions/toolchains and residual assumptions.
