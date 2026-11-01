---
title: Performance and portability
description: Single-key circuit, measurement method, resource boundary, and supported platform.
---

# QuietProof v1 performance and portability

PoKC has one fixed single-key circuit for P2WPKH, P2PKH or mixed claims.
A statement may contain up to 16 public outputs sharing that key hash.
A second distinct key hash is rejected before circuit allocation.

## Reproducing native metrics

Build the native `pokc-test` target, then run the following twice on an otherwise
idle machine. Each run writes
`tests/results/native_pokc_metrics.csv` with one row per real
prove/verify round:

```sh
cmake --build build-native-on --target pokc-test --parallel 2
ctest --test-dir build-native-on --output-on-failure --parallel 1 \
  --timeout 1800 -R '^pokc-test$'
```

```
target,circuit,build_ms,prove_ms,verify_ms,proof_bytes,public_inputs,total_inputs,quad_terms,crt_block_enc
```

The values are descriptive, not timing thresholds.  Record the commit SHA,
compiler/version and flags, CPU/OS, elapsed wall time and peak resident memory
next to a release candidate. Circuit/input/term counts and CRT block encoding
must agree across runs. Randomized proof commitments can vary serialized proof
length slightly; timings are also expected to vary. The circuit digest is independently
checked by `pokc_test`, and changing a circuit shape changes the digest.

## Current support boundary

The native API requires 64-bit C++20. Record the actual configured compiler,
flags and platform; older C++17 timing observations in the README belong to
their recorded historical commit and explicit flags, not current CMake defaults.
The proof-file ceiling is 134221889 bytes (128 MiB payload plus envelope),
selected to bound allocation while admitting the supported proof.
Native 32-bit builds are unqualified. Browser WASM has the separate
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

Historical single-key measurements recorded 2026-10-27 with the hardened shared loader and built CSP; these precede removal of the two-key workflow:

| Engine | Keys | First verification | Same-worker repeat | Peak observed linear memory |
| --- | --- | --- | --- | --- |
| Chromium 149.0.7827.55 | One | 72.247 s | 69.877 s | 954,400,768 bytes |
| WebKit 26.5 | One | 76.051 s | 73.560 s | 954,400,768 bytes |

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
public-internet latency. Fixture envelopes were 46,879,572 bytes.

Across the recorded cases, maximum main-thread heartbeat gaps were
116.1 ms in Chromium and 48 ms in WebKit. Cancellation was observed over
200–201 ms quiet windows with no late responses; this is not OS thread or
memory reclamation timing. The test-only 512 MiB ceilings produced real
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
100 seconds for single-key verification; 1920 MiB
observed linear memory; at most 16 MiB growth across the same-worker repeat;
2 seconds maximum main-thread heartbeat gap and cancellation settling.
Prior browser reference maxima were 75.454 seconds for one key;
the timing budgets allow approximately one-third headroom. The current run
also checks these budgets. They are not an internet download SLA, minimum
hardware promise, cryptographic parameter or global browser timeout. An initial
60-second draft budget failed at a measured 72.176-second one-key check;
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
static site, and [generate current native public single-key fixtures](./wasm-feasibility#reproduce-the-measurements)
with at least one hour remaining validity. Never extend timestamps in real
proof bytes. The feasibility runner serializes all heavy verification work:

```sh
QUIETPROOF_WASM=/path/to/quietproof.wasm npm run docs:build
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

## Signature-possession measurements

The historical scalar tables above retain their original dates, labels and
values. The following are actual composed-signature observations from accepted
L8 cohorts on 2026-11-01, not additive ECDSA/HASH160 estimates. They are reused
with original UTC and exact source/module/fixture/configuration hashes; this
documentation change did not execute or recompile those measurements.
The [machine-readable measurement record](/references/signature-resources-2026-11-01.json)
contains each lifecycle record, source hashes, full build provenance, proof/request
hashes, host and engine identities and exact original times. Retained ON report
SHA256 is `101d6506e2c222b0b253c4085282df0db47382d7ab93d0971061edb933bdebb5`.

The host was Linux x86_64 kernel 6.12.113+deb13-amd64, AMD Ryzen 7 PRO 8700GE,
16 logical CPUs, 66,422,718,464 B host RAM; Node 24.22.2/Playwright 1.61.1.
The signature-enabled WASI 34/clang 23.1.0 reactor was 1,736,785 B, SHA256
`2c35f1fa6a6394931930111cd91f367bf06e047eb1b9e4d457fd1bf33c8357b0`.
It uses Release, RPC OFF and explicit signature ON, the pinned base SDK
`d2b0fc515f8663e38c79a28e8900ce8438e0106e`, unchanged rate 4/queries 128,
CRT/security guards and a 16 MiB initial/2 GiB maximum linear memory. Source hashes
bind the accepted candidate `c3be863b643d32654728dc415ab3b44f6a5fe17e`;
later packaging-only CMake changes have separately checked recipe equivalence.

| Actual fixture | Claims / keys | Full envelope bytes | Chromium 149.0.7827.55 first verify | WebKit 26.5 first verify |
| --- | ---: | ---: | ---: | ---: |
| Signature P2PKH | 1 / 1 | 49,727,346 | 118.388s | 123.931s |
| Signature P2WPKH | 1 / 1 | 49,727,698 | 118.364s | 123.623s |
| Signature mixed | 2 / 1 | 49,728,563 | 117.471s | 123.821s |
| Signature maximum | 16 / 1 | 49,729,089 | 115.068s | 123.440s |

All rows ran real verification. Max16 is an actual 16-output single-key request,
not a modeled/scaled result; more outputs do not add independent keys.
Its same-worker repeats took 113.753 s/122.852 s (Chromium/WebKit), with peak
observed linear allocation 1,301,413,888 B in both engines, versus 1,299,709,952 B
on first verification. Growth was 1,703,936 B, below the unchanged 16 MiB repeat
budget. These bytes are **not RSS, total browser memory or JS heap**. Full-file
buffers, engine/code, OS and other processes add memory outside this measure.

The ON cohort observed 10 engine/key cases: scalar and max16 each completed
load/cold/repeat/mutation/reset/cancel/fresh-recovery/controlled 512 MiB-failure/
production-recovery lifecycles in both engines. P2PKH/P2WPKH/mixed each received
real verification only, not the full lifecycle. Separate OFF cohorts completed
the scalar lifecycle in both engines with signature capability disabled. The
OFF reactor SHA256 is
`54327e9805ff18c851d4542e652cdb7601da01bc59467be3d95ecba5a9665210`.

Regression alarms are 240 s for each signature verification, 100 s scalar, 10 s each
asset/init/preparation, 1920 MiB linear allocation, 16 MiB repeat growth, 2 s heartbeat
and cancellation settling. The operation deadline remains 300 s. These are local
reference alarms, not cryptographic limits, timing guarantees or device minimums.
The 128 MiB payload cap and 2 GiB module ceiling are unchanged. The
native v3 format maximum is 134,221,894 B; the browser import and WASM ceiling
remains 134,221,889 B for both modes. A native-format bound does not grant a
larger browser allocation or accepted import size.

Root/subpath Chromium/WebKit UI and history cohorts separately checked actual
canonical requests, public result reports and max16 proofs. Completed affected
browser-state cases were refreshed with current sources; retained unaffected
cases preserve original UTC rather than becoming a new enclosing full run.
The 390×844/1440×900 captures at 100%/200% repository text size are not actual
browser page zoom, physical-mobile testing or a complete accessibility audit.
Timeout/failure paths never reduce security parameters or supported claim caps.
Original interrupted/failed attempts and their diagnostics remain in the local
qualification record. The original L5.3 integrated malicious fresh-proof/advice
attacks remain waived/unexecuted/unqualified; performance does not qualify them.
