---
title: Performance and portability
description: Current proof family, measurement method, resource boundary, and supported platform.
---

# QuietProof v1 performance and portability

PoKC v1 has two fixed native circuit shapes: one or two distinct P2WPKH
witness programs.  A statement may contain up to 16 public claims, but claims
sharing a program reuse its relation; more than two distinct programs are
rejected before circuit allocation.  Four relations exceed Longfellow's CRT
block-encoding guard and are deliberately unsupported.

## Reproducing native metrics

Run `make pokc-test` twice on an otherwise idle machine.  Each run writes
`tests/results/native_pokc_metrics.csv` with one row per real
prove/verify round:

```
target,circuit,build_ms,prove_ms,verify_ms,proof_bytes,public_inputs,total_inputs,quad_terms,crt_block_enc
```

The values are descriptive, not timing thresholds.  Record the commit SHA,
compiler/version and flags, CPU/OS, elapsed wall time and peak resident memory
next to a release candidate.  The deterministic columns (`proof_bytes`, input
and term counts, CRT block encoding) must agree across the two runs; the
timing columns are expected to vary.  The circuit digest is independently
checked by `pokc_test`, and changing a circuit shape changes the digest.

## Current support boundary

The native release target is 64-bit C++17 on a Linux/x86_64 host using the
repository's hardened default flags (`-O3 -fstack-protector-all
-D_FORTIFY_SOURCE=2 -fno-strict-overflow`).  The checked envelope ceiling is
128 MiB, selected to bound allocation while admitting the supported proof
family. Native 32-bit builds are unqualified. Browser WASM has the separate
qualification boundary below; a generic WASM build alone does not establish
support. Re-run the compatibility and metric checks before
accepting any parameter, compiler, or circuit-digest change.

## Browser resource boundary

The browser verifier is qualified on the named desktop reference environment
with Chromium and WebKit. Firefox is unsupported and unqualified. Responsive
390×844 layouts do not qualify a phone, tablet, mobile OS or memory-constrained
device. WASM SIMD, secure browser randomness and enough free memory for the
linear heap **plus** file buffers, JavaScript, compiled code and the browser are
required. This is a large desktop workload; reserve ample available memory and
run one proof at a time. There is no reliable browser API that establishes
available process memory before verification.

The module declares 16 MiB initial and 2 GiB maximum linear memory. Reported
linear-memory high-water allocation is **not** process RSS or total browser
memory. WASM memory cannot shrink within an instance; each UI operation owns a
fresh disposable worker. Cancellation terminates that worker, and a failed or
trapped instance is never reused. The whole verification has a five-minute
deadline. Allocation failure, a crash or timeout leaves cryptography incomplete
and chain status unavailable; retry needs a fresh worker/device. None of these
limits changes a circuit, proof parameter or accepted claim count.

The reference host is Linux x86_64, kernel `6.12.113+deb13-amd64`, AMD Ryzen 7 PRO
8700GE, with 66,422,718,464 bytes of host RAM. Host RAM is not a measured free
memory allowance or a minimum requirement. The measured engines are Chromium
149.0.7827.55 and WebKit 26.5 through Playwright 1.61.1. These headless desktop
observations do not establish performance on other hardware, interactive
browser distributions, background tabs, power-saving modes or mobile devices.
“Cold” below means the first verification in a fresh worker; its browser
context may already be warm. OS file caches and engine compilation caches are
not forcibly purged. Repeated
asset loads are loopback transfers, not public-internet timing measurements.

Recorded 2026-10-27 with the hardened shared loader and built CSP:

| Engine | Keys | First verification | Same-worker repeat | Peak observed linear memory |
| --- | --- | --- | --- | --- |
| Chromium 149.0.7827.55 | One | 72.247 s | 69.877 s | 954,400,768 bytes |
| Chromium 149.0.7827.55 | Two | 140.912 s | 141.197 s | 1,815,871,488 bytes |
| WebKit 26.5 | One | 76.051 s | 73.560 s | 954,400,768 bytes |
| WebKit 26.5 | Two | 146.923 s | 143.851 s | 1,815,871,488 bytes |

Same-worker repeats observed zero linear-memory growth. Each later UI attempt
uses a new worker instead. Transfer detachment was checked for every proof and
module input; small request/policy buffers and WASM decoder allocations remain
explicit copies as described below. The earlier failed timing observation is
retained in the regression-budget discussion rather than omitted from the
qualification history.

The first local asset load was 9.9–17.9 ms in Chromium and 11 ms in WebKit;
later fresh-worker loads were 9.7–33.6 ms and 10–13 ms respectively. Worker
initialization ranged 3–8.9 ms and 10–46 ms; preparation ranged 10.4–37.5 ms
and 9–72 ms. A same-worker repeat reuses its initialized module and has no
second module load. These measurements include neither a cold OS cache nor
public-internet latency. Fixture envelopes were 46,879,572 and 91,263,350 bytes.

Across the four qualified cases, maximum main-thread heartbeat gaps were
116.1 ms in Chromium and 48 ms in WebKit. Cancellation was observed over
200–201 ms quiet windows with no late responses; this is not OS thread or
memory reclamation timing. All four test-only 512 MiB ceilings produced real
allocation/trap failures, followed by successful production-module recovery.
The complete evidence retains original capture times and exact matching
source/artifact/environment identities for reused Chromium cases and the
WebKit retry; incomplete diagnostic subsets do not become full coverage merely
because their selected cases pass.

### Copy and ownership inventory

For an imported proof of N bytes, `File.arrayBuffer()` materializes N bytes on
the main thread. The buffer is transferred to the worker and the sender is
detached; it is not cloned as JSON/base64 or returned with metadata. The worker
copies N bytes into WASM linear memory. The C ABI constructs a temporary
`std::vector` of envelope bytes for canonical decoding, which allocates the
proof payload inside the envelope before moving it into verification state.
These C++ allocations are inside the measured linear heap. Preparation frees
the temporary ABI buffer; proof storage is released after verification. Small
policy/request and result buffers are copied separately. There is no claim
that a transferred ArrayBuffer produces zero physical copies inside the engine.

WASM assets use bounded streaming chunks (8 MiB ceiling), followed by one
contiguous assembly buffer, transferred to the worker. Network/engine buffers,
File objects, code compilation and garbage collection add unmeasured overhead.
The qualification harness observes sender detachment and heap high-water
allocation; it cannot measure engine-internal copies, process RSS or peak JS
heap across both engines. Retained memory within one worker is expected; the
repeat gate detects increasing high-water allocation for the same input, not
instant garbage collection or physical page reclamation by the OS.

### Regression budgets

`tests/wasm/resources.mjs` sets reference-environment regression alarms:
10 seconds each for local asset loading, initialization and preparation;
100 seconds for one-key and 200 seconds for two-key verification; 1920 MiB
observed linear memory; at most 16 MiB growth across the same-worker repeat;
2 seconds maximum main-thread heartbeat gap and cancellation settling.
Prior browser reference maxima were 75.454/149.598 seconds for one/two keys;
the timing budgets allow approximately one-third headroom. The current run
also checks these budgets. They are not an internet download SLA, minimum
hardware promise, cryptographic parameter or global browser timeout. An initial
60/120-second draft budget failed at a measured 72.176-second one-key check;
it was corrected against browser measurements before qualification.

Timing is conditional on available CPU capacity. A later WebKit recovery
produced valid cryptography in 104.892 seconds and failed the 100-second alarm
while host load averages were observed rising above 22. The load observation
makes shared-host contention plausible, not proven historical causality. The
failure is retained; it is not relabelled as passing or hidden by a larger
timeout. Retry observations use the same 100/200-second policy. Run heavy jobs
serially with adequate CPU capacity, and investigate timing alarms alongside
the original environment and load evidence. A past pass is not a timing
guarantee under future contention.

The low-memory gate lowers only a **test copy** of the module's memory maximum
to 512 MiB. It exercises a real allocation/trap failure, then verifies recovery
with the unchanged production module. This is not a physical low-RAM device or
OS-pressure test. It does not weaken cryptography or replace any verifier call.

### Reproduce qualification

Build/stage the reactor using [the WASM build guide](./wasm-build), build the
static site, and [generate current native public one/two-key fixtures](./wasm-feasibility#reproduce-the-measurements)
with at least one hour remaining validity. Never extend timestamps in real
proof bytes. The feasibility runner serializes all heavy verification work:

```sh
npm run docs:build
QUIETPROOF_WASM=/path/to/quietproof.wasm \
QUIETPROOF_WASM_FIXTURES=/path/to/current/public-feasibility-fixtures \
QUIETPROOF_FEASIBILITY_SITE=docs/.vitepress/dist \
QUIETPROOF_FEASIBILITY_REPORT=/path/to/new/qualification.json \
  npm run test:wasm:feasibility
node --test tests/wasm/resources.test.mjs
```

Keep the JSON report, source/toolchain/dependency and fixture digests, named
engine/host versions, exact commands, original UTC times and logs. The report
records cold versus same-worker repeat verification, fresh-worker asset and
initialization times, cancellation during real computation, mutation rejection,
controlled allocation failure and fresh-worker recovery. Static HTML is served
with its generated CSP; source-matched test worker wrappers only add timing and
entry notifications. They do not override cryptography, entropy or clocks.

## Accessible resource and result states

Request and verification controls have labels, visible keyboard focus and
non-color status text. Progress uses polite live status. Completion and failure
move keyboard focus to the results heading; cancelling restores the relevant
action button. The cancel action remains available while computation is in its
worker. The browser gate records DOM/ARIA snapshots and viewport/full-page
screenshots at 390×844 and 1440×900 with 100%/200% text size for empty, loading,
error, success, cancelled, allocation-failure and timeout states.

These are automated semantic/reflow/keyboard checks and visual inspections,
not actual screen-reader use, a complete WCAG audit or mobile-device testing.
Full-page screenshot stitching can place a fixed header across the middle of
a tall image; compare the corresponding viewport screenshot before inferring
an actual layout fault. To reproduce the focused UI gate against an owned
static preview:

```sh
QUIETPROOF_SITE_ORIGIN=http://127.0.0.1:4177 \
QUIETPROOF_WASM=/path/to/quietproof.wasm \
QUIETPROOF_VERIFY_FIXTURES=/path/to/current/public-feasibility-fixtures \
QUIETPROOF_ACCESSIBILITY_EVIDENCE=/path/to/new/screenshots \
  node --test --test-concurrency=1 web/accessibility.browser.test.mjs
```

Optional `QUIETPROOF_WEBKIT_EXECUTABLE` selects the qualified existing launcher.
The UI failure/timeout tests use a controlled memory ceiling and a test-only
50 ms substitution for the normal five-minute deadline. Normal recovery runs
the real proof verifier. No successful result is simulated.
