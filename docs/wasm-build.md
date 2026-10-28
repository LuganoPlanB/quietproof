# WASI reactor build

The reactor uses the same pinned Longfellow SDK as the native build:
`d2b0fc515f8663e38c79a28e8900ce8438e0106e`. It creates and inspects canonical requests, inspects proof metadata, and
performs real policy-bound proof verification followed by separate explorer
assessment. It does not export a prover. WASI SDK 34.0 is the qualified toolchain.

For the public workflow, start with the [browser guide](./guide/browser-tool).
This page is for building and operating its static artifact.

## Build the isolated reactor

The qualified build uses Linux x86_64, Python 3.12+, Git, CMake 3.20+, Ninja and
Node 24.22.1/npm. A native C++20 toolchain is additionally needed for the CLI
and public proof fixtures. Keep the shared theme in the sibling `../vite-theme`
location expected by `package.json`.

From the QuietProof repository, prepare **new** dependency checkouts if they
are not already present. Do not overwrite another working checkout:

```sh
git clone https://github.com/dyne/longfellow-zk.git ../longfellow-zk-dyne
git -C ../longfellow-zk-dyne checkout --detach d2b0fc515f8663e38c79a28e8900ce8438e0106e
git clone https://github.com/LuganoPlanB/vite-theme.git ../vite-theme
git -C ../vite-theme checkout --detach a7fde3404a5e2b32bf57b4bcb99337479c5c75b2
```

For existing checkouts, verify those HEADs and clean tracked sources instead.
The builders reject changed dependency revisions or tracked modifications.
The project owner confirmed ownership of the Plan B theme and permission for
its use in this QuietProof deliverable on 2026-10-28; see the
[scoped authorization record](static-release.md#theme-permission). The theme's
package metadata has no license identifier. Existing third-party notices and
licenses remain applicable. Publication requires separate authorization.

Choose a new private build directory, then install the qualified WASI SDK:

```sh
QP_BUILD=$(mktemp -d "${TMPDIR:-/tmp}/quietproof-browser-build.XXXXXX")
python3 scripts/install_wasi.py --destination "$QP_BUILD/wasi-sdk"
python3 scripts/build_wasm.py --sdk-source ../longfellow-zk-dyne \
  --wasi-sdk "$QP_BUILD/wasi-sdk" --work-dir "$QP_BUILD/wasm" --jobs 2
```

`scripts/build-pins.json` pins WASI SDK 34.0's Linux x86_64 archive to SHA256
`b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4`.
The installer checks the full download before extraction, refuses an existing
destination and records the pin. `--archive FILE` can use an already downloaded
copy with the same required digest. No system installation is changed.

The driver builds and installs Longfellow into a separate WASI prefix, builds
`$QP_BUILD/wasm/quietproof-build/quietproof.wasm`, checks its imports/exports and
writes `build-provenance.json`. It normalizes source/build/toolchain paths for
reproducibility. Available ccache is used. `--wasi-sdk` or `WASI_SDK_PATH` can
select an existing installation (default `/opt/wasi-sdk`); version alone does
not establish the archive digest. Release packaging requires the installer pin
record. Use a fresh work directory when switching compiler installations:
CMake can retain its old compiler, so the driver rejects a mismatched cache.
No native dependency prefix is used for the reactor.

## Build and preview the complete static artifact

From the same repository and shell, with a clean reviewed checkout:

```sh
npm ci
npm run test:site
python3 scripts/build_static.py --sdk-source ../longfellow-zk-dyne \
  --cross-work "$QP_BUILD/wasm" --base /
npm run docs:preview -- --host 127.0.0.1 --port 4178 --strictPort
```

Open `http://127.0.0.1:4178/guide/browser-tool`, `/tool` and `/verify`. Stop the
owned preview with Ctrl-C before rebuilding, then restart it. For a subpath,
use `--base /quietproof/`, preview with `DOCS_BASE=/quietproof/` and open
`http://127.0.0.1:4178/quietproof/tool`. Keep the trailing slash. Supported base
paths contain simple alphanumeric, underscore or hyphen segments.

The output is `docs/.vitepress/dist`: HTML/CSS/JS, SHA256-named WASM, fonts,
`asset-manifest.json`, `build-provenance.json`, `SOURCE-NOTICE.txt`, dependency
licenses and corresponding source archives/manifests. Serve this entire
directory from a static HTTP(S) host with clean-URL `.html` routing. Production
needs no Node runtime, RPC, wallet, prover or secret. Node is a build/local
preview dependency. Publishing/deploying is a separate authorized operation;
this command only prepares local files.

The packaging driver verifies the pinned clean SDK/theme and matched reactor
source digest. It rejects dirty tracked application sources by default. For
an explicitly local review build, add `--allow-dirty`; add each new, untracked
deliverable with `--source-addition relative/path` so its actual bytes are also
in the source archive. Such output is labeled `dirtyReviewBuild: true`, not a
clean release. Never add private files or local coordination plans.

For source editing without distribution packaging, the production renderer
also works directly, but **requires** the selected reactor:

```sh
QUIETPROOF_WASM="$QP_BUILD/wasm/quietproof-build/quietproof.wasm" \
  DOCS_BASE=/ npm run docs:build
```

That direct command does not add the packaging driver's source/license and
asset manifests. Use `build_static.py` again before artifact qualification or
distribution. A bare production `npm run docs:build` fails rather than silently
shipping an absent/stale reactor. Source development can use
`QUIETPROOF_WASM=... npm run docs:dev -- --host 127.0.0.1`; production CSP checks
apply to the built preview, not the development server.

The WASM filename contains its full SHA256; the loader checks those bytes before
worker initialization and rejects stale substitutions. It also checks ABI and
capabilities independently. Serve `.wasm` as `application/wasm` and modules as
JavaScript; bounded byte fetching also handles generic WASM MIME. Replace a
deployment's matching HTML/JS/WASM together and retain the prior complete
artifact for rollback. Hashes detect stale bytes, not a malicious deployment
that replaces the loader itself. See [hosting/CSP limits](./browser-security).

CI runs `.github/workflows/test.yml` with two compiler jobs and explicit
`--mode smoke`. It retains native RPC ON/OFF, WASM17/provider2, unit/site/packaging,
byte-reproducibility and focused Chromium/WebKit root/subpath hosting/security
checks (four hosting and four security test executions), plus the build
contracts. It omits the exhaustive `web/*.browser.test.mjs` discovery/matrix and
resource benchmark, including their dedicated long-lived fixtures.

`qualification.json` records the selected mode, actual executed counts and
`not_run_by_selected_mode` entries. Successful artifact provenance records the
same scope; a direct `build_static.py` build records qualification as `not_run`.
Pages consumes the smoke-checked artifact, not a full-browser-qualified release.
Keep separate successful full local evidence for the reviewed source, WASM,
worker and environment identities before a release. Smoke success does not
clear a previous full-suite failure. Neither mode establishes production-origin
CORS/headers.

After configuring native RPC ON/OFF builds, run the full local release gate:

```sh
python3 scripts/qualify_static.py --sdk-source ../longfellow-zk-dyne \
  --cross-work "$QP_BUILD/wasm" --native-on build-native-on \
  --native-off build-native-off --evidence "$QP_BUILD/qualification" --base / --mode full
```

Omitting `--mode` preserves the full local default. To reproduce CI's selected
scope, use the same command with `--mode smoke` and a different new evidence
directory. Full mode additionally executes the exhaustive Chromium/WebKit web
suite (48 named tests in the recorded baseline, including 24 real positive
matrix scenarios and ten negative scenarios) and four resource profiles.
These are not run in smoke mode; actual counts are retained in each report.

The evidence directory must be new. Install both required Playwright engines
first with `npx playwright install chromium webkit` (host libraries must also
be available). Full qualification is expensive: real native/browser proving
and recovery checks are serial. The one-hour direct-reactor/provider fixtures
run before the longer 24-hour UI matrix. Preserve old fixtures before any
regeneration. Retain original failure logs, generation times, source/artifact/
environment digests and named executed-test counts; a filtered smoke is not
full qualification.

## Public fixture roundtrip

This focused handoff uses synthetic explorer responses and **public disposable
scalars 1/2** held only by the external native test process. It never sends a
key to the browser, needs no live node/provider/coins, and makes no real funding
claim. **Never fund these public fixture keys.** Build the native CLI using
[the native guide](./guide/getting-started#build), install Chromium/WebKit and
start the packaged preview above. In another terminal, from the repository:

```sh
QP_NATIVE_CLI=/absolute/path/to/native-build/quietproof
QP_ROUNDTRIP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/quietproof-roundtrip.XXXXXX")
QUIETPROOF_SITE_ORIGIN=http://127.0.0.1:4178 \
QUIETPROOF_NATIVE_CLI="$QP_NATIVE_CLI" \
QUIETPROOF_ROUNDTRIP_ARTIFACTS="$QP_ROUNDTRIP_DIR" \
  node --test --test-concurrency=1 \
    --test-name-pattern='^(chromium|webkit): browser request/native prove/browser verify mainnet-p2wpkh$' \
    web/adversarial/roundtrips.browser.test.mjs
```

Expect exactly **two named positive tests**, one per required engine. They
download a real browser `.qpr`, run `inspect`/`prove` in the external CLI, and
import/verify the real `.qpf` with the independently retained request. The setup
also creates a separate 90-second expiring fixture; selected positive requests
explicitly use 86400 seconds for qualification, without changing UI defaults.
No clock or proof timestamp is rewritten. Files, hashes, commands, generation
times and screenshots are retained under the new directory. This is a smoke
check, not the full 26-test/24-positive matrix described in the source file
`web/adversarial/README.md`. An existing matching WebKit launcher can be selected
with `QUIETPROOF_WEBKIT_EXECUTABLE`; it does not expand browser support.

## Reactor and ABI reference

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
`npm run test:site` and a reactor-selected `QUIETPROOF_WASM=... npm run docs:build`
or the complete packaging command above. Native dependency prefixes are
environment-specific; this workspace uses its existing static curl prefix.
