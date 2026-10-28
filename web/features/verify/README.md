# Proof import and verification

`ProofInput.vue` is the `/verify` entry. `setupProofInput` validates file sizes
before reading and transfers binary input to a fresh worker. Canonical decoding
and independent policy preparation use the existing reactor. Inspect proof and
policy does not run cryptography or fetch explorer observations. Its policy match
is explicitly labeled as inspection only. No imported metadata selects policy.

Verify offline runs real cryptography through the provider feature's public
`setupProvider.verify` entry without explorer access. Verify and check explorer
first checks the independent policy and real cryptography, then fetches bounded
fresh observations and evaluates them in WASM against the same immutable worker
operation. The selected verification network is independent of imported proof
metadata. Changing network, provider mode, files or policy disposes pending work
and invalidates results. Each retry rechecks cryptography with a fresh worker.

Crypto, expected policy and explorer states are separate. Provider failures
preserve an established crypto result while leaving chain observations
unavailable. Failed or expired evaluation cannot retain a completed policy
claim. Results show observation limits, provider and device-clock timestamps;
displayed expiry updates while the page stays open. Explorer reports are
trusted, non-atomic observations and never strict current/historical chain
validity. Funding blocks are not observation snapshots. There is no acceptance
authority or global challenge registry.

The optional [local history feature](../history/README.md) saves locally created
canonical requests and completed-check markers only after opt-in. Saved requests
are chosen explicitly; proof metadata never supplies an independent expectation.
Delete/clear fences pending work across connected tabs. Local repeat warnings
are editable, bounded, origin/profile-specific conveniences, not authorization
or global replay prevention. Storage errors do not prevent verification.

The exact expected `.qpr` is preferred. Explicit context requires a selected
network, verifier, purpose, exact message and independent confirmation. Editing
any input invalidates results and terminates pending work. Cancellation, timeout
and unmount dispose the worker; stale responses cannot repopulate the screen.
File reads themselves cannot be interrupted, but their result is discarded after
cancellation and no worker or subsequent fetch starts. No proof byte copy is
returned from the worker. Historical and bridge fields remain inspectable;
the initial acceptance workflow rejects them.

After building/selecting the reactor per the [build guide](../../../docs/wasm-build.md),
build the site before starting an owned preview:

```sh
node --test web/features/verify/input.test.mjs
node --test web/features/verify/results.test.mjs
QUIETPROOF_WASM=/path/to/qualified-build/quietproof-build/quietproof.wasm npm run docs:build
npm run docs:preview -- --host 127.0.0.1 --port 4175
# In another terminal:
node --test --test-concurrency=1 web/features/verify/input.browser.test.mjs
QUIETPROOF_VERIFY_FIXTURES=/path/to/current/native/feasibility-fixtures \
  node --test --test-concurrency=1 web/features/verify/results.browser.test.mjs
```

The browser test uses installed Playwright Chromium/WebKit and the existing
`QUIETPROOF_WEBKIT_EXECUTABLE` launcher override when required. Set
`QUIETPROOF_SITE_ORIGIN` for another preview origin and
`QUIETPROOF_VERIFY_SCREENSHOTS` to retain the 390×844/1440×900, 100%/200% text
matrix. Its native codec fixtures contain synthetic three-byte proof payloads;
test-only timestamp refresh exercises policy preparation, never cryptographic
validity. The separate results browser gate uses the real native-generated
one-key proof and expected request, their recorded provenance and current
validity window. It exercises offline, valid/invalid cryptography, independent
policy rejection, fresh unspent/spent/reorged/unavailable observations, expiry
after real computation, cancel and changing selections. Heavy jobs are serial.
Each authentic state is reflowed to all viewport/text combinations for capture.
Result captures use reduced motion, settle responsive layout, and disable
finite animations so shared navigation transitions do not obscure the screen.
Test-only worker clock and outbound-message gates exercise expiry/loading;
production accepts no clock or crypto override. All held gates have owned
cleanup. Firefox is unqualified.
