# QuietProof

> prove you control bitcoin without revealing your public key.

QuietProof lets a Bitcoin holder prove to an auditor, lender, buyer, custodian, or business partner that they control the keys for specified native P2WPKH funds without revealing the private keys or their compressed public keys, moving the bitcoin, or creating a Bitcoin-valid signature. Each proof can be bound to a fresh challenge and independently checked against current Bitcoin data, making it useful for private custody reviews, proof-of-funds checks, collateral and escrow preflight, wallet migration, and other situations where one party needs credible evidence of key control before committing time, money, or legal resources. QuietProof is a verification building block rather than a complete proof of reserves, identity, solvency, or collateral lock.

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

## Implementation

QuietProof uses [PoKC (Proof of Key Control)](pokc.md), a generic zero-knowledge
primitive we developed to prove knowledge of the private keys for one or two native
P2WPKH witness programs without revealing any key, not even public keys.

The proof is produced and verified off-chain: verification must also
authenticate the claimed Bitcoin outputs, their amounts, network,
confirmation state, and replay policy.

QuietProof comes with a [Sage implementation of PoKC](spec/README.md)
as an executable mathematical oracle and it tests matching with
vectors produced by it.

## Build

QuietProof depends only on the installed
[dyne/LongfellowZK](https://dyne.org/longfellow-zk) circuit SDK; A
default installation places the executable in `/usr/local/bin`, while
CMake discovers the development package from
`/usr/local/lib/cmake/LongfellowZK` (or the platform-specific
equivalent).

## Testing

Build the CLI and run the production-oriented test gate:

```sh
cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=/path/to/longfellow-prefix
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure
```

The `pokc-test` CTest target includes the real one- and two-key proof
round trips; it is intentionally memory- and CPU-intensive.

The ASan/UBSan package test is optional and disabled in normal push and pull
request CI. To run it in GitHub Actions, open the **CI** workflow, choose
**Run workflow**, select the branch, enable **Run the optional QuietProof
ASan/UBSan package test**, and start the workflow. Leaving the option disabled
skips the sanitizer job.

To run the same sanitizer gate manually from the repository root, use Clang
and allow roughly 90 minutes for the real proof test:

```sh
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
CC=clang CXX=clang++ \
LONGFELLOW_ZK_BUILD_TYPE=Debug \
LONGFELLOW_ZK_LINKAGES=shared \
LONGFELLOW_ZK_SANITIZERS=ON \
bash scripts/ci-installed-package.sh
```
 deterministic Python fixture and specification anchors run in the normal
CTest suite. The independent Sage 10.6 oracle is opt-in because it requires a
local Sage installation or Docker:

```sh
cmake -S . -B build -DQUIETPROOF_ENABLE_POKC_SAGE_TEST=ON
ctest --test-dir build -R pokc-sage-reference-test --output-on-failure
```

Static analysis is also project-local. In an exported checkout, point it at
the installed base headers (the monorepo source tree is detected
automatically):

```sh
LONGFELLOW_ZK_INCLUDE_DIR=/usr/local/include/longfellow-zk \
  bash scripts/run_quietproof_static_analysis.sh
```

The CLI supports `mainnet`, `testnet3` (and the `testnet` alias),
`testnet4`, `signet`, and `regtest`. It always passes the
corresponding explicit network selector to Bitcoin Core and rejects a
node whose reported chain differs from the proof statement. Use signet
for public integration testing and regtest for deterministic local
testing.

## Signet walkthrough

The verifier first obtains the output's displayed transaction ID, output
index, value in satoshis, and 20-byte P2WPKH witness program. `PROGRAM` is the
40 hexadecimal characters after `0014` in the scriptPubKey.

Create a short-lived request:

```sh
./quietproof challenge create \
  --network signet \
  --verifier verifier.example \
  --purpose proof-of-funds \
  --message 'signet reserve check 2026-08-21' \
  --expires-in 300 \
  --claim TXID:VOUT:SATOSHIS:PROGRAM \
  --output request.qpr
```

Multiple `--claim` options are allowed. Claims may reference at most two
distinct witness programs; claims sharing a program require only one key
relation. Inspect the canonical request before proving:

```sh
./quietproof inspect request.qpr
./quietproof prove --request request.qpr --output proof.qpf
```

`prove` reads one 32-byte hexadecimal secret from protected standard input for
each distinct program; input order does not matter because every secret is
matched to its derived program. Interactive input disables terminal echo.
Never put a secret in argv, an environment variable, or shell history. For
automation, feed it through a protected pipe whose producer does not log its
output.

Verify against a fully validated signet Bitcoin Core node:

```sh
./quietproof verify proof.qpf \
  --bitcoin-cli /usr/bin/bitcoin-cli \
  --verifier verifier.example \
  --purpose proof-of-funds \
  --nonce-store ./consumed-nonces \
  --min-confirmations 1 \
  --minimum-total-sats SATOSHIS \
  --max-lifetime 300
```

The expected verifier and purpose are supplied locally, not trusted from the
proof. The nonce store is locked, owner-only, atomically updated, and synced
before authorization succeeds. Request and proof files are created with mode
`0600`; an existing output path is never overwritten.

The bundled Bitcoin Core provider verifies a stable current tip. It treats a
null `gettxout` response as inconclusive rather than as proof that an output
was spent. Historical snapshot statements require a separately implemented
authenticated historical provider through the library API.

## Library entry points

Applications can use the header-only integration layer directly:

- `PoKCProve(...)` proves one distinct witness program.
- `PoKCProveKeys<1|2>(...)` selects an exact circuit-family member.
- `PoKCProofSupported(...)` checks the circuit identity and fixed proof
  parameters before proof parsing.
- `PoKCVerifyProof(...)` verifies only the zero-knowledge relation.
- `VerifyQuietProof(...)` applies policy, proof verification, chain evidence,
  confirmation/value thresholds, optional bridge authorization, and atomic
  nonce consumption.

Production integrations should call `VerifyQuietProof`, provide an appropriate
`QuietProofChainProvider`, and fail closed for every result except
`valid_current` or an explicitly supported `valid_historical`. A valid proof
alone does not establish that an output exists, is unspent, is exclusively
controlled, is locked, or proves solvency.

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
