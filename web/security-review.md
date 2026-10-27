# Browser input security review (L6.1)

Scope: browser request, import/verification/history features, Esplora transport,
WASM JavaScript adapter, static HTML policy and npm dependency pins. Starting
revision: `d07f16c1c350ffab96b1fece86c1d44af8b633ff`, branch
`feat/wasm-browser-request-verify`. Review date: 2026-10-27. Findings below describe
the L6.1 working diff; they are not a cryptographic or independent whole-branch
audit. No confirmed P0/P1 application-security finding remains in this scope.

## 001 — P2/medium: missing static CSP (JS-CSP-001)

Evidence: the starting `docs/.vitepress/config.mjs` had no CSP and generated
pages permitted arbitrary inline script execution. An exploitable HTML/script
injection would execute with the tool's origin privileges. No reachable unsafe
HTML sink was found in the feature templates: attacker fields use Vue text
interpolation, and explorer error bodies are replaced by fixed messages.

Correction: `docs/.vitepress/security.mjs:5` inserts early build-specific CSP
with exact inline script hashes, same-origin script/worker sources, bounded
provider connect sources, and no JavaScript `unsafe-eval` or inline script
allowance. Style `unsafe-inline` is deliberately retained for theme/Vue styles.
Validation: both engines create a real WASM request while recording zero normal
CSP violations, display an XSS verifier string literally, and block injected
inline and remote scripts. Test transport receives zero attacker-host requests.

## 002 — P2/low: permissive WASM fetch redirects (JS-URL-002)

Evidence: starting request/verify fetchers accepted `wasmUrl` with default fetch
redirect behavior. Production callers supply fixed same-origin URLs, so this
was a configuration hardening gap, not an established user-controlled URL
exploit. A misconfigured redirect could deliver a substituted artifact.

Correction: `web/wasm/asset.mjs:3` validates origin, scheme, credentials, fragment,
query and ambiguous whitespace/backslashes before fetch; `:18` forbids redirects
and credentials/referrers; `:24` checks final URL and bounded content length.
The streaming 8 MiB cap is shared by both workflows. Validation includes denied
URLs before transport, missing/corrupt artifacts, malformed/oversized streams,
root/subpath MIME and actual worker execution. Compatible malicious WASM is
still a deployment compromise; ABI validation cannot authenticate it.

## 003 — P2 for this static deployment; upstream high: tooling advisories (VUE-SUPPLY-001)

Evidence: original `npm audit --json` reports 14 high dependency entries,
propagated from source-map-js 1.2.1 and Vite 6.4.3. The six original advisories
are GHSA-68fv-2mgg-jv7q, GHSA-698v-4r3x-3vcv, GHSA-r825-w8mm-5pxw,
GHSA-587h-7wmj-h5pm, GHSA-9jrq-w75r-8gcw and GHSA-rq7h-c2jc-7f22.
They concern attacker-controlled source-map processing or dev-server/editor
paths; this static app compiles no imported proofs or request strings as source,
and production has no Vite server/editor endpoint. A reachable development
server would require a separate assessment of its exposure and prerequisites.

Correction: `package.json:21` pins Vite 6.4.5 and source-map-js 1.2.2 through
overrides; only their resolved versions/tarball integrity change in the lockfile.
Post-update registry audit exits zero with zero advisories. Updated builds and
focused unit/site/browser regressions validate compatibility. Audit results are
an observation of the registry at the recorded time, not a future guarantee.

## Reviewed controls and retained limitations

- Provider endpoints are immutable mainnet/signet Blockstream mappings. All
  provider calls are bounded, credential-free, non-redirecting CORS GETs.
  Invalid proof or policy cannot trigger explorer observations; offline import
  and verification transmit no chain requests or proof payloads.
- WASM imports/exports are strict allowlists. Entropy, clocks, stderr iovecs,
  heap boundaries, allocation limits, copies and trapped-instance disposal have
  focused tests. Evidence fields reject malformed script/hash/text/integer and
  claim-count inputs before encoding; WASM independently evaluates exact claims.
- Native strict chain semantics, circuits and cryptographic parameters are
  unchanged. Public explorer observations cannot produce native
  `valid_current`/`valid_historical` or service authorization.
- GitHub Pages response headers, deployed-origin CORS, clickjacking protection,
  device/browser integrity and a malicious same-origin build remain unverified
  or outside this artifact's enforcement. Meta CSP cannot set `frame-ancestors`.
  See [hosting guidance](../docs/browser-security.md) for these explicit limits.
- The shared theme/compiler/browser/SDK are trusted dependencies, not independently
  audited here. Resource/accessibility and full adversarial matrix gates belong
  to L6.2/L6.3. Full L6 suites and root acceptance remain separate gates.

Reproduce input checks with `web/wasm/asset.test.mjs`, `web/security.test.mjs`,
the feature unit suites, `web/security.browser.test.mjs`, and the imports/bounds
selection in `tests/wasm/browser.test.mjs`. Run `npm audit --json` against the
locked dependency tree. Complete commands, original failures/corrections,
environment identities, UTC captures, screenshots and hashes are retained by
the local L6.1 review evidence manifest.
