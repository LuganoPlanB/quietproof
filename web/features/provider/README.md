# Public explorer provider

`setupProvider({ network })` creates this feature's adapter. Read its frozen
`provider` descriptor to display the endpoint, network, privacy warning and trust
assumption **before** the user chooses lookup. Construction performs no fetch.
Only an explicit `discover({ addresses, signal })` call discloses addresses.
Abort the operation when the user changes provider/network or leaves the flow;
create a new adapter for the new selection. A running adapter cannot be mutated.
This module has no UI or automatic lookup behavior.

The supported endpoints are pinned:

| Network | Provider endpoint |
| --- | --- |
| mainnet | `https://blockstream.info/api` |
| signet | `https://blockstream.info/signet/api` |

There is no fallback or cross-provider mixing. Genesis identity is checked on
every operation before disclosing addresses. A missing/mismatched genesis
response fails closed. These are checks of the provider's self-reported network,
not authentication of consensus or the signet challenge. Signet shares `tb` and
legacy testnet address prefixes with other test networks, so an address alone
cannot distinguish them; the pinned signet endpoint selects the intended chain.

Supported addresses are checksummed P2WPKH (witness v0, 20-byte program) and
P2PKH (20-byte hash). P2SH, P2WSH and later witness versions are rejected.
P2PKH discovery cannot tell whether the holder uses a compressed key; the native
protocol's compressed-key requirement still applies during external proving.
Validate all addresses before any network access. Never upload proof bytes,
private keys or unrelated wallet addresses to this API.

Discovery checks `/address/:address/utxo` against `/tx/:txid`: exact transaction
ID, output index, script, satoshis and consistent funding confirmation metadata.
Only the resulting claim fields may be selected for `encodeRequestOptions` /
WASM canonical request construction. Amounts use checked original integer JSON
tokens and become decimal strings for the ABI. All responses and results are
bounded: at most two addresses, 256 discovered outputs, 20,000 outputs per
transaction, 2 MiB per response, one 30-second deadline for the entire operation.
Exceeding a bound rejects the whole result; nothing is silently truncated.
Transactions are fetched once per operation. There are no retries in discovery.
Selecting claims remains subject to WASM's 16-claim/two-program limits.

Requests use GET, CORS, no credentials, no referrer, no cache and no redirects.
Browser CORS/network errors are indistinguishable and reported together.
404, 429, other HTTP errors, malformed data, timeout and cancellation reject the
operation; callers must render the error and require a new explicit action.
No partial claims are returned. API error bodies are not exposed as messages.

**Discovery is not verification.** Results explicitly retain chain status
`unavailable` and require fresh verification observations. Funding-block metadata
describes the funding transaction only; it is never an observation snapshot.
Explorer reports are trusted and non-atomic and cannot establish native
`valid_current` or `valid_historical`.

`verify({ proof, wasmBytes, policy, signal, online: true })` owns a fresh dedicated
worker and transfers ownership of the two binary buffers immediately. Supply an
independently selected expected request/policy, with `policy.provider` equal to
the displayed endpoint. The adapter performs `prepare` and real `verify` before
any explorer request; a caller's claimed validation flag has no effect. Only
the worker's verified claim manifest determines which outpoints are fetched.
The same worker and consumed phase token receive the final `evaluate` call.
`online: false` performs offline cryptographic checking without explorer access.
Worker creation is injectable as a trusted test dependency, never a user input.

Fresh assessment fetches genesis identity, tip hash plus that block's height,
funding transaction plus independent status, each exact outspend, funding block
best-chain membership and its current height mapping, then tip hash/height again.
A changed tip discards the entire first attempt and retries once within the
shared 30-second network deadline. Persistent changes remain inconclusive.
Funding transaction/status and block membership requests, including failures,
are deduplicated within each attempt; each distinct outpoint has its own outspend
request. A tip-change retry discards these caches entirely. HTTP failures do not
trigger retries or provider fallback.
Funding block data is kept distinct from before/after observation tips; equal
tips still do not make these requests atomic. Amount/script mismatches, missing
outputs, reorgs, conflicting statuses and insufficient confirmations cannot
produce an explorer-reported unspent result. Only confirmed funding reported
in the best chain can satisfy this initial assessment, even with a zero minimum
confirmation policy.

Observation time is the start of each fetch attempt, from the untrusted browser
clock. The WASM policy independently rejects stale/future observations and checks
all exact claims, totals, network, provider and confirmations. Returned provenance
retains attempt times, tips, issues and the explicit non-atomic trust assumption.
Requests bypass browser cache; visible positive/malformed `Age` headers reject
known cached responses. Hidden headers and a dishonest/stale provider cannot be
detected reliably, so no authenticated freshness claim is made. Whole-provider
outages return the successful cryptographic result with explorer status
`unavailable`; individual missing/conflicting observations produce `inconclusive`.

A new verification on the adapter supersedes the previous verification; a new
discovery supersedes the previous discovery, including an invalid replacement
lookup. Call `dispose()`
on the old adapter when the user switches network/provider or leaves the flow;
this permanently invalidates **both** discovery and verification and terminates
pending work. Future calls on a disposed selection fail before network access.
Late worker/provider responses cannot update a new operation. An external
abort signal also cancels the operation. Each owned worker is terminated on
completion, error or cancellation; an unresponsive worker has a five-minute
hard deadline. Discovery also accepts an explicit abort signal.

Deterministic tests (no network):

```sh
node --test web/features/provider/contract.test.mjs web/features/provider/discovery.test.mjs web/features/provider/verification.test.mjs
```

The worker doubles in the fixture tests check orchestration only. Real proof
verification and the actual WASM evidence evaluator are additionally tested in
Chromium and WebKit (Firefox remains unsupported), using newly generated public
native fixtures whose requests have not expired:

```sh
/path/to/native-build/quietproof-browser-verifier-test /path/to/current/public-fixtures
QUIETPROOF_WASM=/path/to/quietproof.wasm \
QUIETPROOF_WASM_FIXTURES=/path/to/current/public-fixtures \
node --test --test-concurrency=1 web/features/provider/verification.browser.test.mjs
```

`QUIETPROOF_WEBKIT_EXECUTABLE` optionally selects the existing qualified WebKit
launcher. This generator creates one-hour requests; regenerate expired fixtures
instead of weakening expiry checks. The browser test supplies deterministic
explorer responses. Required suites never depend on a live explorer or a node.

## Optional live capability probe

```sh
QUIETPROOF_PROVIDER_PROBE_REPORT=/path/to/provider-probe.json \
node web/features/provider/live-probe.mjs
```

This separate command starts a local HTTP origin and performs at most three
credential-free, non-redirecting CORS GETs per network/engine, with no retries,
eight-second request deadlines and 64 KiB response limits. It fetches only public
genesis identity and tip metadata; it transmits no addresses, proof data, keys or
policy fields. A failure exits nonzero and records the actual observed failure.
It does not bypass TLS checks, CORS or browser security. Use the same optional
WebKit launcher setting as the real-worker test.

Observed 2026-10-27, `07:57:37.740Z`–`07:57:40.821Z`, from
`http://127.0.0.1:41949`:

| Browser | mainnet metadata | signet metadata |
| --- | --- | --- |
| Chromium 149.0.7827.55 | 3/3 HTTP 200, matching genesis, CORS-readable | 3/3 HTTP 200, matching genesis, CORS-readable |
| WebKit 26.5 | 3/3 HTTP 200, matching genesis, CORS-readable | 3/3 HTTP 200, matching genesis, CORS-readable |

Both endpoints exposed `Cache-Control: public, max-age=10` for tip hash and
`max-age=157784630` for genesis/block metadata despite the request's browser
cache bypass. `Age`, `Retry-After` and the CORS allow-origin response header were
not readable through these responses; null does not establish header absence.
Successful browser reads establish CORS for these particular requests only.
They do not establish freshness, a guaranteed quota or availability, or CORS for
all transaction/address endpoints. The linked API contract provides no fixed
public quota/SLA used by this adapter; treat rate limits as unknown. A 429 is an
outage/inconclusive result and requires a new explicit action, with no retry loop.

**The deployed origin does not exist yet and is unqualified.** These local
results do not qualify production-origin CORS. Recheck the deployed-origin
capabilities and actual request/verification flow at the delivery milestone;
this probe neither publishes nor authorizes deployment.

Fixtures use public generator-key addresses and invented transaction/block IDs;
they make no assertions about live UTXOs. Endpoint/API fields were checked
2026-10-27 against the primary [Esplora API documentation](https://github.com/Blockstream/esplora/blob/master/API.md).
Network constants and shared testnet/signet prefixes follow
[Bitcoin Core v29 chain parameters](https://github.com/bitcoin/bitcoin/blob/v29.0/src/kernel/chainparams.cpp).
Witness checksums/program decoding and public witness examples follow
[BIP173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki).
No guaranteed public rate limit or CORS availability is inferred from these
documents. Live capability/CORS probes remain separate from required tests.
