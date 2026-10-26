# WASI reactor build

The bootstrap reactor uses the same pinned Longfellow SDK as the native build:
`d2b0fc515f8663e38c79a28e8900ce8438e0106e`. It does not contain a prover or
request/verification operations yet. WASI SDK 34.0 is the qualified toolchain.

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

The reactor has 16 MiB initial linear memory, a 1 GiB maximum and a 1 MiB stack.
These are explicit bootstrap bounds, not verified large-proof resource budgets.
The SDK toolchain enables wasm32 SIMD and disables C++ exceptions and RTTI.
`scripts/inspect_wasm.mjs` compiles the artifact and checks its complete import
and export surface. No filesystem, sockets or native CLI are linked.

Bootstrap ABI version 1 exports allocation/free (a maximum 16 MiB per allocation)
and a 72-byte smoke result. The caller owns allocated memory and must free each
allocation exactly once; views must be recreated after memory growth. Smoke
returns 32 entropy bytes, 8 little-endian realtime nanosecond bytes, and SDK
SHA256 of those 40 bytes. Time is untrusted host time. Entropy or clock errors
clear the output and return an error; there is no predictable fallback.

The complete import surface is `wasi_snapshot_preview1.random_get` and
`wasi_snapshot_preview1.clock_time_get`. `web/wasm/runtime.mjs` rejects all other
imports, unexpected exports, unsupported ABI versions and missing SIMD or secure
randomness. It implements only realtime clock ID 0 using checked `Date.now()`
milliseconds converted to nanoseconds. This does not provide trusted time.
Entropy uses `crypto.getRandomValues`, chunked at the WebCrypto quota; failure
clears partial bytes and returns an error. There are no filesystem preopens,
sockets, predictable randomness, diagnostic I/O stubs or missing-import stubs.

`web/wasm/worker.mjs` receives one transferred WASM buffer in an `initialize`
message, then accepts `smoke` messages. Results are owned copies transferred out
of the worker; linear memory stays private. Reinitializing an initialized worker
is rejected. Terminate the worker to discard synchronous computation and all
instance state, then create a fresh worker. The production message interface
cannot select host callbacks or fixed nonces.

Run the real Chromium worker gate after building the reactor:

```sh
npm ci
# Provision the browser separately if it is not already cached:
npx playwright install chromium
QUIETPROOF_WASM=../.gestalt/quietproof-wasi/quietproof-build/quietproof.wasm \
  npm run test:wasm
```

The pinned Playwright driver uses Chromium 149.0.7827.55. Tests run a loopback
HTTP server, real WebCrypto and module workers; failures are injected only by
test modules. They cover malformed/mismatched imports, absent/failed entropy,
clock failure, SIMD capability diagnostics, transfer ownership, memory growth,
repeated instances, initialization and termination. This is bootstrap Chromium
qualification, not large-proof or Firefox/WebKit qualification. Compilation
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
