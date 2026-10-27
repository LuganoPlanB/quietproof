# Browser proof feasibility

The browser executes the native PoKC verifier with unchanged circuits, rate 4,
and 128 queries. Requests support the existing maximum of sixteen claims and
two distinct key programs. The browser exports no proving or private-key API.

## Reproduce the measurements

Build the reactor as described in [WASI build](./wasm-build). Build and run the
native public fixture generator in a native testing build:

```sh
cmake --build build-native-on --target quietproof-browser-fixtures
build-native-on/quietproof-browser-fixtures fixtures/browser
QUIETPROOF_WASM=../.gestalt/quietproof-wasi/quietproof-build/quietproof.wasm \
  QUIETPROOF_WASM_FIXTURES=fixtures/browser \
  QUIETPROOF_FEASIBILITY_REPORT=browser-feasibility.json \
  npm run test:wasm:feasibility
```

The generator uses **public disposable scalars 1 and 2** and verifies both proofs
natively before writing them. The one-key fixture is a mainnet v1 P2WPKH request;
the two-key fixture is a signet typed-v2 request with P2PKH and P2WPKH claims.
Each `.json` provenance file records its generator, public scalars, creation and
expiry times, sizes, and native verification. The explicitly selected fixture
lifetime is 86400 seconds, the core maximum, so a long qualification run does not
expire midway. This does not change production request defaults or bounds. The
runner rejects fixtures expiring within one hour; regenerate them rather than
changing the browser clock or trusting expired proofs.

Provision the pinned Playwright browsers before running. The required command
requires Chromium and WebKit serially and returns failure if either engine
or either one/two-key family is missing, duplicated, unavailable or failed.
Firefox is explicitly unsupported and unqualified for the initial release
(user-approved scope revision, 2026-10-27). `QUIETPROOF_{CHROMIUM,FIREFOX,WEBKIT}_EXECUTABLE` may select an
existing matching browser. Missing libraries and unwritable caches must be
resolved explicitly; an unavailable engine is unverified, never a passing skip.
`QUIETPROOF_ENGINES` and `QUIETPROOF_KEYS` select focused diagnostic subsets;
those subsets do not establish the complete required browser matrix and exit
nonzero when required Chromium/WebKit or key-count coverage is absent. Duplicate
selectors are rejected before artifacts are loaded. `npm run test:wasm:coverage`
checks missing/duplicate/subset/failure accounting without substituting proof
callbacks. Add Firefox explicitly only for optional diagnostics; its result is
tagged `supported: false` / `unsupported-diagnostic` even if checks pass. Optional
Firefox failure does not fail an otherwise complete required matrix, and optional
Firefox success never changes the supported-browser list.

For each key count, the runner checks cold verification, repeated verification,
changed-proof rejection, reset/disposal, hard cancellation during synchronous
computation, and genuine verification in a fresh worker after cancellation. A
test-only wrapper announces entry into the production verification handler;
it does not replace cryptography, clocks, entropy, or proof callbacks. A main
thread heartbeat continues during verification/cancellation, and terminated
workers must deliver no late response. Verification messages include immutable
operation/phase identifiers and observed linear-memory size.

## Memory and copies

The reactor starts with 16 MiB and has an explicit **2 GiB maximum**. The former
1 GiB bootstrap limit admitted the one-key fixture but trapped on the genuine
two-key fixture during circuit work. Increasing the allocation ceiling admits the
same circuits and proof parameters; parsing bounds remain at the core 128 MiB
proof-payload ceiling. This is a large desktop workload, with browser and JS
memory in addition to linear memory. A maximum allocation is not a claim that
any device with that amount of total RAM can run the tool.

The recorded peak is the **observed linear-memory high-water allocation** after
synchronous calls. WebAssembly memory does not shrink, so pages grown during a
call remain observable afterward. It is not a measurement of live C++ objects,
browser-process RSS, engine-internal copies, or JS heap. Identical repeat
verification must not grow this high-water by more than 16 MiB. Reset releases
the verification context; terminate the worker to dispose of its instance and
linear memory. Immediate OS RSS reclamation is not asserted. Keep only one
verification worker active when connecting the UI.

Proof bytes follow this ownership path:

1. File/fetch creates one binary ArrayBuffer in the caller. A transferable
   message detaches it; the runner checks detachment on every proof operation.
   Detachment demonstrates ownership transfer, not a physical zero-copy promise
   about browser internals.
2. The worker holds that binary buffer while `prepare` copies it once into an
   owned WASM input allocation. The C++ wrapper currently copies it into a bounded
   decoder vector; the core decoder copies the proof payload into its immutable
   context. These are explicit linear-memory copies, not JSON/base64 versions.
3. The decoder vector and input allocation are released when preparation returns.
   Real verification allocates the circuit/proof structures required by the
   native algorithm. The retained serialized proof is released after verification.
4. Only a small binary result and bounded claim manifest are copied/transferred
   back. Proof bytes never appear in result JSON or provider observations.

The JSON report retains module SHA256 and raw/gzip/Brotli sizes, fixture hashes
and provenance, engine/runtime/host identities, per-phase wall times, observed
memory, transfer/cancel/repeat outcomes and complete failure details. Measurements
qualify the named runner and engine versions only. Small/mobile devices and other
browser versions require their own qualification; viewport emulation does not
establish a device memory budget.

The current qualification result and any required-engine limitation must be
recorded before UI work proceeds.

## Recorded qualification and release gate

The table below preserves the initial feasibility observations. See
[current browser resource qualification](./performance#browser-resource-boundary)
for the hardened loader/CSP measurements, regression budgets, controlled
allocation-failure recovery and automated accessibility coverage. The current
runner additionally exercises a test-only 512 MiB memory ceiling and recovery
with the unchanged production module. Set `QUIETPROOF_FEASIBILITY_SITE` to a
built static site directory to run beneath its generated CSP and shared asset
loader. Test-only memory ceilings never change production proof parameters.

The measured Linux x86-64 runner reports an AMD Ryzen 7 PRO 8700GE CPU, sixteen
logical CPUs and 66,422,718,464 bytes of host RAM. These results do not qualify
low-memory or mobile hardware. The module is 1,712,288 bytes raw, 460,608 bytes
with gzip level 9, and 358,468 bytes with the tested Brotli encoder. The native
fixture envelopes are 46,879,572 bytes (one key) and 91,263,350 bytes (two keys).

| Engine | One-key valid runs | Two-key valid runs | Peak observed WASM allocation |
| --- | --- | --- | --- |
| Chromium 149.0.7827.55 | 68.9–71.7 s | 134.0–138.6 s | 954,400,768 / 1,815,871,488 bytes |
| WebKit 26.5 | 69.5–76.0 s | 144.0–149.1 s | 954,400,768 / 1,815,871,488 bytes |
| Firefox 151.0, Playwright build 1532 | Unverified | Unverified | Unverified |

Chromium and WebKit pass cold/repeat/fresh-after-cancel verification and changed
proof rejection for both key counts. Repeated allocation high-water growth is
zero in these runs. Maximum observed main-thread heartbeat gaps are 109 ms in
Chromium and 71 ms in WebKit; all four cancellation cases retain responsive
heartbeats and deliver no late response. Cancellation is observed over a 200 ms
quiet window; this is not a measurement of OS memory reclamation latency.

WebKit on this runner uses matching libraries unpacked into a workspace prefix
and a wrapper preserving the bundle resource paths. Package extraction runs no
maintainer scripts and changes no system installation. Chromium uses its existing
pinned cache. Font caches are workspace-local. Exact paths, package hashes and
commands belong with the qualification evidence, because they depend on the
runner.

**Firefox remains unsupported and unqualified for the initial release.** The
user explicitly revised initial supported scope to Chromium and WebKit. The
previous three-engine required run failed because the official Debian and Ubuntu
Firefox 151 builds timed out before readiness. That failed evidence remains
historical; it has not been relabeled as passing. Writable caches, explicit
blank startup, persistent profiles, existing Xvfb, direct headless loading and
service settings did not resolve that managed-runner limitation. No sandbox
disabling or widened permissions were used. These startup failures establish no
conclusion about Firefox proof cryptography or memory support.

The current required gate selects exactly Chromium/WebKit by default and checks
complete unique one/two-key coverage. Missing required coverage cannot be filled
by optional Firefox records. Any later Firefox support claim requires a separate
explicit scope decision and real qualification; optional diagnostics alone cannot
expand support. The earlier external Firefox handoff bundle is historical and is
not an outstanding release requirement under the approved initial scope.
