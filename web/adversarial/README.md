# Browser request → external native proof → browser verification matrix

This is a real-cryptography gate. `fixtures.mjs` is Node-only public fixture
composition; no private-key or proving module is imported by the website.
Browser inputs contain public addresses and selected outputs. Native CLI stdin
receives only the well-known disposable scalars 1/2, outside the browser.

Each required engine (Chromium/WebKit) executes ten distinct-fingerprint
positive cases, plus two same-fingerprint mixed cases in the focused supplement:

| Network | Case suffix | Keys | Statement | Claims |
| --- | --- | --- | --- | --- |
| mainnet and signet | `p2wpkh` | 1 | v1 | P2WPKH |
| mainnet and signet | `p2pkh` | 1 | typed v2 | P2PKH |
| mainnet and signet | `p2wpkh-two-key` | 2 | v1 | P2WPKH + P2WPKH |
| mainnet and signet | `p2pkh-two-key` | 2 | typed v2 | P2PKH + P2PKH |
| mainnet and signet | `mixed-two-key` | 2 | typed v2 | P2WPKH + P2PKH |
| mainnet and signet | `mixed-one-key` (supplement) | 1 | typed v2 | P2WPKH + P2PKH with the same fingerprint |

For every case the real request UI discovers deterministic exact outputs,
downloads a canonical `.qpr`, and the native CLI creates a genuine `.qpf` from
that file. The test checks the exact embedded request bytes, then imports the
resulting proof and independent expected request into the current verification
UI. Success requires real WASM cryptography, matched policy, exact fresh
deterministic explorer observations, sender detachment, worker disposal and
unchanged resource budgets. Explorer-reported unspentness remains explicitly
separate from consensus or service authorization. Every verification provider
request must follow the actual cryptographic result and use the selected network
endpoint; request discovery occurs only after its separate lookup action.
Request generation/native inspection alone cannot satisfy this gate.

The qualification explicitly selects a 86400-second request lifetime, within
the core limit, after asserting the production default remains 300 seconds.
That keeps serial proving/verification and focused reruns within the original
validity window; it does not change production defaults or rewrite timestamps.
The per-case JSON records native commands, UTC, artifact SHA256, exact embedding,
browser version, runtime/source identities, phase results and screenshots.
Successful result states are reflowed at 390×844/1440×900 and 100%/200% root/
feature text scale without rerunning or simulating cryptography for screenshots.

Both engines additionally execute these negative/recovery scenarios using real
native-generated proof bytes:

| Scenario | Required result | Explorer access |
| --- | --- | --- |
| Corrupt final proof byte | Cryptography invalid | None, even with online checking selected |
| Different independent expected request | Policy rejected; cryptography incomplete | None |
| Naturally expired browser request/proof | Policy rejected using normal browser time | None |
| Provider outage after valid cryptography | Crypto valid/policy matched; explorer unavailable | One bounded credential-free GET, no proof body |
| Repeated offline recovery | A fresh worker genuinely verifies again | No additional explorer calls |

The expired fixture comes from a separate browser download with an explicitly
selected 90-second lifetime and real native proving. Its original bytes are
retained. The default full matrix naturally outlasts that interval; a focused
negative run may wait for actual expiry. No production or test clock is changed
by this matrix. The separate results browser suite additionally covers spent,
reorged, unavailable and expired-during-computation observations. Cancellation,
low-memory injection and accessible-state qualification have their own gates.

```sh
node --test web/adversarial/fixtures.test.mjs
QUIETPROOF_WASM=/path/to/qualified-build/quietproof-build/quietproof.wasm npm run docs:build
npm run docs:preview -- --host 127.0.0.1 --port 4178 --strictPort
# In another terminal, with the current native CLI and installed browsers:
QUIETPROOF_SITE_ORIGIN=http://127.0.0.1:4178 \
QUIETPROOF_NATIVE_CLI=/path/to/native-build/quietproof \
QUIETPROOF_ROUNDTRIP_ARTIFACTS=/path/to/new/matrix-artifacts \
  node --test --test-concurrency=1 web/adversarial/roundtrips.browser.test.mjs \
    web/adversarial/same-key-mixed.browser.test.mjs
```

The combined run requires 26 named tests: 10 positive cases plus one five-scenario
adversarial test per engine, and four same-key mixed cases across the engines and
networks. The latter demonstrate two script types sharing one proof relation;
claim count does not select the circuit key count. The setup hook creates the expiring real fixture.
Heavy native and browser cryptography is serial. A new timestamped run directory
preserves results; generated material may be reused only after exact product,
native CLI, WASM, built page and fixture identity checks. Original generation
times stay intact. Incomplete material directories are never overwritten.
Do not treat a name-filtered diagnostic subset as a complete matrix. Keep every
required case mapped to its executed JSON/log/fixture identities in release
evidence. Firefox remains unsupported. No live provider or node is required.

Full qualification also requires native RPC ON CTest (excluding opt-in live
regtest), RPC OFF compatibility, WASM/coverage/build contracts, feature units,
site/build, provider/browser and the existing request/import/results/history/
security/accessibility/resource browser suites. Preserve fixture bytes and
provenance before any generator overwrites its output directory. Regenerate
expired fixtures into a new directory; no timestamp or crypto bypass is valid.
