# Local request history

`LocalHistory.vue` is an optional shared view used by request creation and proof
verification. `history.mjs` owns a bounded IndexedDB state record. It retains at
most eight canonical binary requests (4096 bytes each) and 24 completed-check
markers, with a 64 KiB accounting bound. It never stores proof payloads, private
keys or an acceptance decision. Data is unencrypted and editable by same-origin
code; it is not an authority or a global nonce/replay registry.

Consent is off by default and survives reload only in the same browser profile
and origin. Opting in saves future locally created requests and successful
cryptography/policy check markers. An existing request preview can also be saved
explicitly. Imported proof metadata never becomes a saved expected request.
On `/verify`, the user explicitly chooses a saved request and independently
chooses the verification network; no proof-derived expectation is populated.
Canonical decoding and exact proof/request binding remain owned by WASM.

Every check reruns real cryptography. Duplicate warnings refer only to retained
local request fingerprints/nonces. Reinspection creates no completed-check
marker, and a warning never grants or denies authorization. Deleting records,
clearing site data, private sessions, other origins/profiles/devices and bounded
eviction reset these local observations. Other tabs can already hold copies.

IndexedDB read/write transactions serialize consent, deletion and updates across
tabs. Async hashing happens outside the transaction; an epoch ticket captured
before work must still match inside the committing transaction. Clear turns
consent off and rotates that epoch. Delete also rotates the epoch, retains other
requests and removes markers linked to a deleted request. Pending work cannot
restore a deleted/cleared record. BroadcastChannel refreshes connected views;
focus refresh is a disclosed fallback when notifications are unavailable.
Ticket refresh also detects missed epoch changes before starting work; manual
preview saves check the request generation again after that refresh.

Storage open, quota and data-format errors remain local to this feature.
Downloads and verification work without persistence. Failed writes never claim
success, and clear can recover an invalid state record. An unavailable or blocked
database may require a reload or closing another tab. No network endpoint is
used for history.

Focused checks, from the repository root:

```sh
node --test web/features/history/history.test.mjs
QUIETPROOF_WASM=/path/to/qualified-build/quietproof-build/quietproof.wasm npm run docs:build
npm run docs:preview -- --host 127.0.0.1 --port 4175
# In another terminal, with a current native CLI and installed Chromium/WebKit:
QUIETPROOF_NATIVE_CLI=/path/to/quietproof \
QUIETPROOF_HISTORY_ARTIFACTS=/path/to/evidence \
  node --test --test-concurrency=1 web/features/history/history.browser.test.mjs
```

The browser gate creates fresh browser requests, proves them in the external
native CLI using only public disposable scalar 1 on native stdin, and verifies
the returned artifacts in real browser workers. Chromium covers mainnet v1
P2WPKH; WebKit covers signet typed v2 P2PKH. Native keys never enter a browser.
Crypto is serialized; request lifetime is explicitly set to 1800 seconds for
the repeated checks. It tests reload, tabs, explicit expectation selection,
repeat/reinspection, deletion, clear during computation, origin isolation,
denied private storage, quota errors and corrupt-state recovery. Request/result
captures cover 390×844/1440×900 and 100%/200% text in both engines. Use the existing
`QUIETPROOF_WEBKIT_EXECUTABLE` and `QUIETPROOF_SITE_ORIGIN` overrides as needed.
