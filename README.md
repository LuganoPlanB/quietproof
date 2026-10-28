# QuietProof

> prove you control bitcoin without revealing your public key.

Discover Bitcoin outputs, create a challenge, prove key control, verify against
Bitcoin Core. Supply a native P2WPKH or compressed-key P2PKH address; the CLI and C++ library discover
its candidate outputs and independently recheck them at verification. Proving
runs offline with the request and protected key input by default; explicit wallet
mode can obtain one address key from Bitcoin Roots. Native verification
uses Core RPC directly, without installing or invoking `bitcoin-cli`.

QuietProof uses **PoKC (Proof of Key Control)** for one compressed-key
hash across P2WPKH, P2PKH, or mixed outputs. Uncompressed-key P2PKH is unsupported;
discovery cannot determine key encoding from a P2PKH script alone.
Up to 16 outputs may share that key hash. Different keys require separate
requests and proofs; existing two-key requests and proofs are rejected.
Proofs do not newly reveal public keys, but disclose outpoints, amounts and key hashes.
Earlier spends or key reuse may already have revealed a public key; proving cannot
undo that exposure. This is not anonymous proof of funds.
Recipients can trace these coins and associate them with a known prover identity.
Discovery sends the address to the selected node. This is not proof of exclusive
ownership, legal title, solvency or locked collateral.

## Browser request and verification

The static website creates public `.qpr` requests and verifies externally
generated `.qpf` files on mainnet/signet. Follow the
[browser handoff guide](docs/guide/browser-tool.md): retain an independent
expected request, prove in the native CLI or a compatible external wallet, then
read cryptography, policy and explorer results separately. Private keys never
enter the browser. Public explorer observations are trusted and non-atomic;
the static tool supplies no authoritative acceptance or global nonce service.

Chromium/WebKit desktop qualification, substantial memory requirements, clock/
history/privacy limits and unsupported Firefox/mobile claims are documented in
the guide. [Build and preview the complete static artifact](docs/wasm-build.md#build-and-preview-the-complete-static-artifact)
with pinned WASI/source inputs, hashed assets, source/license notices and
provenance. Production requires only static hosting; Node is a build/preview
dependency. Theme distribution permission is unresolved and must be settled
before publication. The native Core-backed workflow below has a different
chain-evidence and durable nonce boundary.

## Build

Prebuilt static Linux x86_64 binaries with native RPC support are available from
[GitHub Releases](https://github.com/LuganoPlanB/quietproof/releases).
See [release versioning, checksums and build instructions](docs/releases.md).
Use `quietproof --version` to identify a binary's release.

Use a C++20 compiler, CMake 3.20+, the installed
[LongfellowZK circuit SDK](https://dyne.org/longfellow-zk) and a supported patched
libcurl development package (API 7.62+):

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  "-DCMAKE_PREFIX_PATH=/path/to/longfellow-prefix"
cmake --build build --parallel 2
```

The executable is `build/quietproof`. Native RPC supports Core 28+; live tests
cover pinned Core 28.3 and 30.3. Linux/macOS use deterministic local cookie
lookup; there is no `bitcoin.conf` parsing or automatic endpoint fallback.
`-DQUIETPROOF_BUILD_RPC=OFF` removes curl and retains the manual/offline and
explicit legacy paths.

## Try an isolated regtest workflow

Follow the [getting-started guide](docs/guide/getting-started.md) to start a
private, peerless Core node, fund a reproducible public disposable key fixture,
and obtain `ADDRESS`, `RPC_URL` and `DEMO`. The proof secret stays outside Core.
Node administration is separate from these ordinary commands:

```sh
build/quietproof challenge create --network regtest --address "$ADDRESS" \
  --verifier example.org --purpose proof-of-funds --message 'Proof of control' \
  --output "$DEMO/request.qpr" --rpc-url "$RPC_URL" --rpc-datadir "$DEMO"
build/quietproof inspect "$DEMO/request.qpr"
build/quietproof prove --request "$DEMO/request.qpr" --output "$DEMO/proof.qpf"
build/quietproof verify "$DEMO/proof.qpf" --network regtest \
  --verifier example.org --purpose proof-of-funds --max-lifetime 300 \
  --nonce-store "$DEMO/nonces" --rpc-url "$RPC_URL" --rpc-datadir "$DEMO"
```

Enter the fixture key from the guide at the protected prompt; never export a
production wallet key to try the tutorial. Real secrets belong in protected
stdin, never argv, environment variables or shell history. Interactive input
disables echo. Request/proof files are owner-only and never overwrite an
existing destination. The guide demonstrates proving while Core is stopped.

After validating the keys, `prove` reports phase changes and elapsed time every
10 seconds on standard error. These updates indicate the current phase, not a
completion percentage or a guarantee that computation is advancing. The final
JSON result remains on standard output.

Verification supplies local metadata/policy expectations, verifies the proof,
looks up exact current UTXOs at a common stable tip and atomically consumes the
nonce. Expect `valid_current`, exit 0. Reusing the same nonce store rejects a
replay. The store is a durable **file**, not a directory. A current null/spent
UTXO or unavailable node is `state_inconclusive`; discovery does not reserve
coins or authenticate historical spending.

For an already funded signet address whose key the prover possesses:

```sh
build/quietproof challenge create --network signet --address tb1q... \
  --verifier example.org --purpose proof-of-funds --message 'Proof of control' \
  --output request.qpr
build/quietproof prove --request request.qpr --output proof.qpf
build/quietproof verify proof.qpf --network signet --verifier example.org \
  --purpose proof-of-funds --nonce-store ./nonces
```

Replace the address placeholder and run a trusted, fully validated local Core
node with `server=1` and a same-user owner-only cookie. No script extraction,
manual claim assembly or BTC conversion is required. Supported networks are
`mainnet`, `testnet3` (`testnet` alias), `testnet4`, `signet` and `regtest`.
Select the network explicitly: `tb1` alone cannot distinguish all test networks.

`utxos --network NAME --address ADDRESS` offers optional JSON diagnostics with
integer satoshis and compatibility/recheck status. Default discovery scans the
whole UTXO set and may take minutes. `--rpc-wallet NAME` uses an already loaded,
tracking wallet instead; QuietProof never creates/imports/rescans it. Empty or
more-than-16-output discoveries cannot create an ordinary challenge, and no
outputs are silently selected. See [configuration, costs and recovery](docs/operations.md).

## C++ integration

The existing core target stays header-only and network-free. Request the
optional compiled RPC component explicitly:

```cmake
find_package(LongfellowZKQuietProof CONFIG REQUIRED COMPONENTS rpc)
target_link_libraries(my_application PRIVATE LongfellowZKQuietProof::rpc)
```

`BitcoinCoreRpc` supplies discovery and fresh chain evidence;
`CreateQuietProofChallenge` creates the same canonical requests as the CLI.
Existing `PoKCProve` and `VerifyQuietProof` handle proving and complete
policy/evidence verification. `PoKCVerifyProof` alone verifies only the
zero-knowledge relation. Applications choose verifier policy independently of
the prover and fail closed on non-authorization outcomes.

The key-count templates have been removed. Use `PoKCProve(secret, statement,
&envelope)` with a single `std::array<uint8_t, 32>` secret, or the existing
pointer-and-length overload. `PoKCBuildCircuit` and `PoKCExpectedCircuitDigest`
also take no key-count template argument.

Core-only consumers keep the original no-component package and
`LongfellowZKQuietProof::quietproof` without curl discovery/linkage.

## Testing

The `Tests` GitHub Actions workflow runs on every pull request and pushes to
`main`: the full native CTest suite with RPC enabled (including real proof
tests), package/CLI compatibility tests with RPC disabled, WASM17/provider2,
unit/site/packaging tests and reproducible root/subpath artifacts with focused
Chromium/WebKit hosting/security smoke checks. CI explicitly selects
`qualify_static.py --mode smoke`: it does not run the exhaustive web browser
matrix or resource benchmark. Pages consumes a smoke-checked artifact whose
provenance records that scope. Full local release qualification remains the
default (`--mode full`); see [the build guide](docs/wasm-build.md). Smoke success
does not establish the omitted gates or deployed headers/CORS.
Live Bitcoin-node integration
and the optional Sage reference runtime remain opt-in; deterministic Sage vectors
run in CI.

```sh
ctest --test-dir build --output-on-failure -E '^pokc-test$'
ctest --test-dir build --output-on-failure -R '^pokc-test$'
```

The real single-key proof gate is CPU- and memory-intensive. Ordinary builds
explicitly skip live Core integration. Enable it with
`QUIETPROOF_ENABLE_BITCOIN_REGTEST_TEST=ON` and explicit
`QUIETPROOF_CORE28_DIR`/`QUIETPROOF_CORE30_DIR` executable directories; the
[operations runbook](docs/operations.md#testing-and-release) gives exact commands,
package ON/OFF, sanitizer/static-analysis gates and the optional Sage reference
setup. Deterministic Sage vectors, protocol, naming and spec checks remain in
the normal suite. The [normative protocol](spec/quietproof-v1.md) retains statement
v1's P2WPKH semantics and adds typed statement v2 for P2PKH or mixed claims.
New proofs use timestamped envelope v2 with the unchanged ownership circuits.
Older verifiers that do not support statement v2 reject it as unsupported.

Manual claims and `--bitcoin-cli /absolute/path` remain available in the
[advanced compatibility appendix](docs/operations.md#advanced-manual-and-legacy-compatibility).
Native failures never fall back to the legacy backend.
Four-part `--claim TXID:VOUT:SATOSHIS:PROGRAM` stays P2WPKH. The typed form
`--claim TXID:VOUT:SATOSHIS:p2pkh:KEY_HASH` (or `p2wpkh`) can be repeated for
mixed outputs; duplicate outpoints cannot count twice.

## Use cases

- **Custody attestation:** demonstrate current knowledge of keys controlling specified custody outputs without disclosing their public keys.
- **Auditor challenges:** answer fresh, single-use key-control challenges without constructing a spend-like transaction.
- **Disclosed proof of funds:** qualify parties for trades, purchases, lending, or onboarding.
- **Collateral and escrow preflight:** demonstrate control before negotiating and creating the actual locking or settlement transaction.
- **Wallet continuity:** disclose common key knowledge across old and new supported outputs off-chain.
- **Pseudonymous reputation rollover:** transfer reputation or credentials while revealing wallet links to the application.
- **Collaborative protocols:** verify control of proposed inputs before admitting participants to CoinJoin or other coordinated transactions.
- **Membership and operator bonds:** demonstrate control of a disclosed economic bond without immediately spending or depositing it.
- **Liquidity qualification:** pre-qualify channel, liquidity, or federated-service participants before funding begins.

> QuietProof proves challenge-bound key knowledge. It does not prove exclusive ownership, legal title, solvency, liabilities, or that funds are locked or will remain unspent.

## Current metrics

The following measurements were taken on 2026-08-21 at commit `315aeea812f`
on Linux x86-64, an Intel Core i9-12900HK, Debian clang 19.1.7, C++17, and the
hardened release flags (`-O3 -fstack-protector-all -D_FORTIFY_SOURCE=2
-fno-strict-overflow`). The host exposed 20 logical CPUs, but each measured
API call was single-process. Timings are wall-clock observations, not
performance requirements.

| Distinct keys | End-to-end prove API | End-to-end verify API | Raw proof | Full envelope | Serialized circuit |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 29.892 s | 19.899 s | 46,879,852 B (44.71 MiB) | 46,880,097 B | 24,876,346 B (23.72 MiB) |

These end-to-end measurements include native witness preparation, circuit
construction, proving or verification, and proof serialization/parsing as
performed by the public API. Verification ran in the same process immediately
after proving, so its static expected-circuit-digest cache was warm; a first
verification in a fresh process also constructs that identity circuit. The
measurements are one observation per shape and should be treated as indicative.
Envelope size also varies with the canonical statement, while serialized
circuit size is deterministic.

The proof gate also records six lower-level one-key samples that exclude
circuit construction from the prove/verify intervals. On the same checkout,
proving ranged from 25.882 to 26.149 seconds (mean 25.977 seconds), verification
from 18.067 to 18.207 seconds (mean 18.152 seconds), and raw proofs from
46,878,796 to 46,879,788 bytes. Randomized commitments make small proof-size
variation expected.

Circuit structure is deterministic. Current fixed metrics are:

| Distinct keys | Public inputs | Total inputs | Private inputs | Quadratic terms | CRT block encoding |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 21 | 3,031 | 3,010 | 2,067,522 | 2,070,533 |

Reproduce the real one-key samples with
`ctest --test-dir build -R '^pokc-test$' --output-on-failure`; results are
written to `tests/results/native_pokc_metrics.csv`. Circuit and proof sizes
must be remeasured after any compiler, circuit, field, rate, query-count, or
serialization change. For release comparisons, use an otherwise idle machine,
record peak resident memory separately, and run multiple samples.

## Further documentation

- [PoKC circuit construction](pokc.md)
- [Independent Sage reference model](spec/README.md)
- [Normative v1 format](spec/quietproof-v1.md)
- [Operations and production controls](docs/operations.md)
- [Security claim matrix](docs/security.md)
- [Performance methodology](docs/performance.md)

## Prove with a Bitcoin Roots wallet

Bitcoin Roots v31.1-roots.3 provides `exportaddresskey`. To obtain a key directly
from an already loaded, unlocked descriptor wallet:

```sh
build/quietproof prove --request request.qpr --output proof.qpf \
  --network signet --rpc-url http://127.0.0.1:38332/ \
  --rpc-cookie "$HOME/.config/quietproof/signet.cookie"
```

The address and network come from the request. Optional `--network` must match it.
With exactly one loaded wallet, it is selected automatically; otherwise specify
`--rpc-wallet NAME`. Optional `--address ADDRESS` must match the request.
The node's network and address script must match it before any key export. This mode supports a request with one distinct
compressed-key hash across P2WPKH, P2PKH, or mixed outputs. Automatic address
selection uses P2PKH when present in the request, otherwise P2WPKH. For mixed
requests, `--address` can select either claimed kind with the same key hash.
The returned
compressed key is checked against the request before proof generation.

Supplying any RPC option (or `--address`) selects wallet mode. Plain `prove`
still reads protected stdin without RPC; `--network` alone stays offline.
If the node lacks `exportaddresskey`, use stdin mode instead. Authentication,
locked-wallet, missing-key and malformed-response errors stop the operation;
there is no private-descriptor export or automatic wallet unlocking fallback.
The key is never printed or passed through argv, environment variables or files.
Owned key buffers are cleared, but JSON/HTTP libraries and the OS can retain
copies: this does not guarantee complete memory erasure or protection from swap.
Use only a trusted local node. Exporting a non-hardened child secret together
with its ancestor xpub can compromise the ancestor's private subtree.
