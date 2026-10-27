# WASI reactor build

The reactor uses the same pinned Longfellow SDK as the native build:
`d2b0fc515f8663e38c79a28e8900ce8438e0106e`. It creates and inspects canonical requests, inspects proof metadata, and
performs real policy-bound proof verification followed by separate explorer
assessment. It does not export a prover. WASI SDK 34.0 is the qualified toolchain.

From the Quietproof repository, with CMake 3.20+, Ninja, Python 3 and Node:

```sh
python3 scripts/build_wasm.py --sdk-source ../longfellow-zk-dyne \
  --work-dir ../.gestalt/quietproof-wasi
```

`--wasi-sdk` or `WASI_SDK_PATH` selects a toolchain installation (default
`/opt/wasi-sdk`). The driver rejects a changed SDK revision or dirty tracked SDK
sources. It builds and installs the SDK into its own WASI prefix, then builds
`quietproof-build/quietproof.wasm`. Use a fresh work directory to reproduce a
clean build; no native dependency prefix is used. Available ccache is used.

Native builds still default to CLI, RPC and tests enabled. A library-only build
can set `QUIETPROOF_BUILD_CLI=OFF`, `QUIETPROOF_BUILD_RPC=OFF`, and
`BUILD_TESTING=OFF`; it does not search for Threads or CURL. WASI defaults these
native options off and rejects attempts to enable them. Set
`QUIETPROOF_BUILD_WASM=ON` with `cmake/toolchains/wasi.cmake` to build the reactor.
This uses WASI SDK 34's supplied preview1 toolchain and `wasm32-wasip1` triple;
the pinned Longfellow toolchain's older `wasm32-wasi` triple cannot find the
version 34 standard library headers. No SDK source modifications are needed.

The reactor has 16 MiB initial linear memory, a 2 GiB maximum and a 1 MiB stack.
The maximum was raised after real two-key verification exceeded the former
1 GiB bootstrap ceiling. See [browser feasibility](./wasm-feasibility) for
measured support, memory definitions and required-engine limitations.
The SDK toolchain enables wasm32 SIMD and disables C++ exceptions and RTTI.
`scripts/inspect_wasm.mjs` compiles the artifact and checks its complete import
and export surface. No filesystem, sockets or native CLI are linked.

ABI version 2 exports allocation/free, the original 72-byte smoke operation,
`quietproof_wasm_create_request`, `quietproof_wasm_inspect`, staged `quietproof_wasm_{prepare,verify,evaluate,reset}`, and borrowed
`quietproof_wasm_{result,error}_{data,size}` getters. Inputs must start at a live
allocation returned by alloc; lengths must fit that allocation and the operation
limit. Unknown/double frees are ignored, and foreign or freed input pointers are
rejected. Free each input after the call. Results and errors belong to the reactor
until the next operation or reset. Copy them before issuing another call;
never free a borrowed result. Status 0 means success, 1 means invalid input,
2 means entropy failure, 3 means clock failure, 4 means rejected policy, and 5 means unsupported mode/circuit. Failure clears prior results.
Allocation is capped at the core maximum envelope size (134221889 bytes), request
inspection at 4096 bytes, creation options at 8192 bytes, and UTF-8 messages at
4096 bytes. These parsing bounds are not browser verification qualification.
Out-of-memory STL allocation and fatal libc++ failures trap the worker through
explicit termination handlers; recreate the worker after a trap. This avoids
further diagnostics on fatal allocation paths. Ordinary SDK verifier diagnostics
use the bounded stderr sink described below.

QWC1 creation options contain network u8 (0 mainnet or 2 signet), lifetime u64,
verifier/purpose/message as u16-length UTF-8 strings, claim count u16, and typed
claim records (txid[32], vout u32, sats u64, script kind u8, program[20]). Integers
are big endian. A lifetime is required (1–86400 seconds); there is no silent
extension. The C++ core sorts and validates claims, selects v1 or typed v2, hashes
the message and obtains a fresh nonce and untrusted time through checked WASI
imports. It returns existing canonical QPS1 `.qpr` bytes. No production message
can select a nonce, clock source, private key or prover operation.

Inspection accepts canonical `.qpr` or `.qpf` bytes and returns QWI1: envelope
version u8 (0 for requests), proof creation time u64, circuit digest[32], circuit
version/rate/queries/proof size as four u32s, followed by canonical QPS1 bytes.
All core format, parameter, UTF-8, size and trailing-byte checks apply. This is
metadata parsing, **not proof verification**; JS reports `verified: false`.
Snapshots and bridge metadata remain inspectable. `web/wasm/codec.mjs` handles
the transport; all u64 output fields are decimal strings, and input accepts
BigInt, canonical decimal strings or safe integer numbers without rounding.

The caller must recreate views after memory growth. Smoke returns 32 entropy
bytes, 8 little-endian realtime nanosecond bytes, and SDK SHA256 of those 40
bytes. Entropy or clock errors clear its output; there is no fallback.

The complete import surface is `wasi_snapshot_preview1.random_get`,
`clock_time_get`, `fd_write`, `fd_seek` and `fd_close`. The SDK's real verifier
logs through stderr and initializes a monotonic clock. The adapter implements
a real stderr-only diagnostic sink (fd 2, at most 64 iovecs and 64 KiB total per
instance); writes report exact bytes or an error. Other descriptors fail with
EBADF, stderr seeking with ESPIPE, and closing with EBADF because there is no
closable descriptor capability. No filesystem/preopens, sockets or missing-import
stubs exist. Clock ID 0 uses checked `Date.now()`; ID 1 uses checked
`performance.now()`. Both are untrusted host time, never consensus evidence.
Entropy uses `crypto.getRandomValues`, chunked at the WebCrypto quota; failure
clears partial bytes. The loader rejects every unexpected import/export,
unsupported ABI version and missing required capability.

`web/wasm/worker.mjs` receives one transferred WASM buffer in an `initialize`
message, then accepts `smoke`, `createRequest` (options object),
`inspectRequest` and `inspectProof` (transferred binary bytes), and staged
`prepare`, `verify`, `evaluate`, `reset` messages. Results are owned copies transferred out
of the worker; linear memory stays private. Reinitializing an initialized worker
is rejected. Terminate the worker to discard synchronous computation and all
instance state, then create a fresh worker. The production message interface
cannot select host callbacks or fixed nonces.

Staged verification uses independent policy, never defaults from the imported
proof. `prepare` receives transferred `.qpf` bytes plus a policy object containing
either separately selected `expectedRequest` bytes, or explicit `network`,
`verifier`, `purpose`, `message`. Both forms require `maxLifetimeSeconds`,
`minConfirmations`, `minimumTotalSats`, `maxObservationAgeSeconds` (1–300), and
`provider` (an exact provider identity, or empty for offline verification).
Only mainnet/signet current requests are supported; snapshot and bridge modes
are inspectable but rejected for verification. Maximum lifetime is 86400 seconds.

`prepare` validates encoding and policy but exposes no fetchable manifest.
`verify` calls the exact native `PoKCProofSupported` and `PoKCVerifyProof`
functions, including circuit digest, parameter, transcript and trailing-proof
checks. They live in `pokc/verifier.h`; native proving includes that same header.
There are no dummy verification callbacks and native `VerifyQuietProof` is
unchanged. Time/policy is checked before and after computation and at evidence
assessment. Proof storage is released after verification. Only a valid result
has the bounded claim manifest needed for provider fetching.

Every stage carries worker-owned `operationId` and `phaseToken` values returned
by its predecessor. A new preparation invalidates older contexts; verification
and evidence phases are consumed once. Evidence includes the pinned provider,
observation time, network, tip-before/after observations and ordered exact
outpoints, amounts, script bytes, confirmation counts and best-chain observations.
Changed tips, stale/future time, provider/network/outpoint/script/amount mismatch,
missing claims or insufficient confirmations/totals remain inconclusive. This
is explicitly non-atomic explorer trust; funding blocks never become strict
chain snapshots.

Results separate `cryptography` (`not_checked`, `valid`, `invalid`), `policy`
(`matched` for successful stages; `PolicyError` on rejection), and `explorer`
(`unavailable`, `reported_unspent`, `reported_spent`, `inconclusive`). They always
have `authorizes: false`; no explorer result can produce native `valid_current`
or `valid_historical`. `UnsupportedError` distinguishes unsupported modes or
circuits. The adapter returns owned binary result copies. On a WASM trap,
`WorkerResetError` permanently poisons the instance and worker; terminate it
and create a new worker. A reset only discards healthy verification state.

The staged wire input is QWP1: mode u8, max lifetime/min confirmations/minimum
sats/max observation age as u64s, provider as u16-length UTF-8, then either a
u32-length canonical expected request (mode 0), or network u8 plus verifier,
purpose and message as u16-length UTF-8 (mode 1). QWE1 observations contain
provider text, observation time u64, network u8, two (block[32], height u64)
observations, count u16, then (txid[32], vout u32, status u8, sats u64,
u16-length script, confirmations u64, in-best-chain u8). Status values are
unspent/spent/missing/unavailable/inconclusive = 0–4. QWR1 results contain
context u32, phase/crypto/policy/explorer as u8s, total sats u64, and QWI1 metadata
only for the verified phase. All integers are big endian. These transports are
bounded internal interfaces, not new proof/request formats.

Run the real Chromium worker gate after building the reactor and generating a
native fixture using the public disposable scalar 1 (never sent to the browser):

```sh
cmake --build build-native-on --target quietproof-browser-verifier-test
ctest --test-dir build-native-on --output-on-failure --parallel 1 \
  -R '^quietproof-browser-verifier-test$'
npm ci
# Provision the browser separately if it is not already cached:
npx playwright install chromium
QUIETPROOF_WASM=../.gestalt/quietproof-wasi/quietproof-build/quietproof.wasm \
  QUIETPROOF_WASM_FIXTURES=build-native-on/tests/wasm-real npm run test:wasm
```

The native test generates a one-hour request/proof, verifies the real proof and
mutations, and checks independent policy, unsupported modes and explorer/phase
cases. Its `provenance.json` records the source, disposable scalar, times and
proof size. Regenerate expired fixtures. The browser suite requires these files;
metadata-only golden fixtures cannot satisfy real verification tests. Heavy
native/browser checks run serially; the real browser crypto case has a ten-minute
correctness timeout separate from the bootstrap per-test timeout. This timeout
is not a supported performance budget.

The pinned Playwright driver uses Chromium 149.0.7827.55. Tests run a loopback
HTTP server, real WebCrypto and module workers; failures are injected only by
test modules. They cover malformed/mismatched imports, absent/failed entropy,
clock failure, SIMD capability diagnostics, transfer ownership, memory growth,
repeated instances, initialization and termination. It also checks exact native golden request bytes for v1, v2 and mixed claims,
inspection lifetime and numeric/malformed input rejection. Native golden sources
and regeneration are documented in `tests/wasm/fixtures/README.md`. This is
one-key correctness qualification in Chromium. The separate feasibility gate
requires real one/two-key checks in Chromium and WebKit. Firefox is explicitly
unsupported and unqualified for the initial release. Cancellation and all supported resource budgets
require the separate real-proof feasibility gate. Compilation
alone does not establish browser proof support.

Build separation and package regression checks:

```sh
python3 tests/cmake/wasm_build_test.py --cross-work ../.gestalt/quietproof-wasi \
  --work ../.gestalt/quietproof-wasi-contract \
  --native-prefix ../.gestalt/longfellow-prefix
ctest --test-dir build-native-on --output-on-failure \
  --no-tests=error --parallel 1 --timeout 600 \
  -R '^quietproof-(package-test|cli-test|cli-rpc-test|prove-feedback-test)$'
```

For the full native gate, use your native SDK and curl installation prefixes:

```sh
cmake -S . -B build-native-on -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DBUILD_TESTING=ON -DQUIETPROOF_BUILD_RPC=ON \
  -DCMAKE_PREFIX_PATH="<native-sdk-prefix>;<curl-prefix>"
cmake --build build-native-on --parallel 2
ctest --test-dir build-native-on --output-on-failure --no-tests=error \
  --parallel 1 --timeout 1800 -E '^quietproof-regtest-rpc-test$'
```

Repeat the compatibility selection above in an RPC OFF build. The documentation gates are
`npm run test:site` and `npm run docs:build`. Native dependency prefixes are
environment-specific; this workspace uses its existing static curl prefix.
