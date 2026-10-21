# QuietProof

> prove you control bitcoin without revealing your public key.

Discover Bitcoin outputs, create a challenge, prove key control, verify against
Bitcoin Core. Supply a native P2WPKH address; the CLI and C++ library discover
its candidate outputs and independently recheck them at verification. Proving
runs offline with the request and protected key input. Native verification
uses Core RPC directly, without installing or invoking `bitcoin-cli`.

QuietProof uses **PoKC (Proof of Key Control)** to prove knowledge of keys for
one or two native P2WPKH witness programs. It hides spend keys and compressed
public keys; requests/proofs still expose outpoints, amounts and witness
programs, and discovery sends the address to the selected node. This is a
verification building block, not proof of exclusive ownership, legal title,
solvency or locked collateral.

## Build

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
Existing `PoKCProveKeys<1|2>` and `VerifyQuietProof` handle proving and complete
policy/evidence verification. `PoKCVerifyProof` alone verifies only the
zero-knowledge relation. Applications choose verifier policy independently of
the prover and fail closed on non-authorization outcomes.

The [shipped example](examples/bitcoin_rpc.cc) separates discovery/challenge,
offline prove and verify stages, uses protected stdin and invokes no CLI.
[Compile its installed source and run the regtest recipe](docs/guide/getting-started.md#build-and-run-the-installed-c-example),
or build in-tree with `-DQUIETPROOF_BUILD_EXAMPLES=ON`.
Core-only consumers keep the original no-component package and
`LongfellowZKQuietProof::quietproof` without curl discovery/linkage.

## Testing

```sh
ctest --test-dir build --output-on-failure -E '^pokc-test$'
ctest --test-dir build --output-on-failure -R '^pokc-test$'
```

The real one/two-key proof gate is CPU- and memory-intensive. Ordinary builds
explicitly skip live Core integration. Enable it with
`QUIETPROOF_ENABLE_BITCOIN_REGTEST_TEST=ON` and explicit
`QUIETPROOF_CORE28_DIR`/`QUIETPROOF_CORE30_DIR` executable directories; the
[operations runbook](docs/operations.md#testing-and-release) gives exact commands,
package ON/OFF, sanitizer/static-analysis gates and the optional Sage reference
setup. Deterministic Sage vectors, protocol, naming and spec checks remain in
the normal suite. The [normative v1 format](spec/quietproof-v1.md) is unchanged.

Manual claims and `--bitcoin-cli /absolute/path` remain available in the
[advanced compatibility appendix](docs/operations.md#advanced-manual-and-legacy-compatibility).
Native failures never fall back to the legacy backend.

## Use cases

- **Custody attestation:** demonstrate current knowledge of keys controlling specified custody outputs without disclosing their public keys.
- **Auditor challenges:** answer fresh, single-use key-control challenges without constructing a spend-like transaction.
- **Private proof of funds:** pre-qualify parties for OTC trades, purchases, lending, or institutional onboarding.
- **Collateral and escrow preflight:** demonstrate control before negotiating and creating the actual locking or settlement transaction.
- **Wallet continuity:** privately prove common control of an old and a new P2WPKH wallet to a selected verifier.
- **Pseudonymous reputation rollover:** support application-level transfer of reputation or credentials between privately linked wallets.
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
| 2 | 60.200 s | 38.967 s | 91,263,372 B (87.04 MiB) | 91,263,681 B | 49,663,186 B (47.36 MiB) |

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
| 2 | 41 | 6,061 | 6,020 | 4,133,092 | 4,139,113 |

Reproduce the real one-key samples with
`ctest --test-dir build -R '^pokc-test$' --output-on-failure`; results are
written to `test/results/native_pokc_metrics.csv`. Circuit and proof sizes
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
