---
title: Browser security and hosting
description: Browser trust boundaries, input controls, CSP and static hosting limitations.
---

# Browser security and hosting

The browser tool trusts the delivered site, JavaScript, WASM, browser and device.
Use a trusted HTTPS origin. A compromised deployment can replace the verifier
and its displayed results: the loader verifies the SHA256-named WASM bytes and
checks imports/ABI, but **a malicious deployment can replace the loader and
its expected digest too**. Compare
build provenance and artifact digests through an independent trusted channel
when that threat matters. There is no authoritative challenge backend.

Private keys and wallet secrets belong in the native CLI or external wallet.
This app has no private-key input, browser prover, proof upload, analytics or
third-party script endpoint. Local history is opt-in, bounded and origin-local;
it retains requests and check markers, never proof payloads. Other code on the
same origin can access browser storage. Device time is untrusted, and local
history is not global replay prevention.

## Inputs and runtime capabilities

Request fields, proof files, saved history and explorer responses are untrusted.
Vue text interpolation renders their strings as text; they are not compiled as
templates or inserted as HTML. Provider error bodies are discarded in favor of
fixed user-facing explanations. File sizes are checked before reading, protocol
values are checked again in WASM, and evidence is bounded to 16 exact claims.
Unexpected/malformed responses cannot establish proof or chain validity.

The WASM adapter permits exactly five `wasi_snapshot_preview1` function imports:
`clock_time_get`, `fd_close`, `fd_seek`, `fd_write`, `random_get`. No filesystem,
preopen, socket, environment or process capability exists. Descriptor 2 is a
bounded 64 KiB diagnostic sink; close/seek never grant access. Memory ranges and
iovec counts are checked; entropy failures clear the requested region and fail
closed. WebCrypto supplies randomness, and browser clocks are observations.
The explicit ABI v2 export allowlist contains request creation, inspection and
staged verification, allocation/result/error/reset operations and a smoke check;
there is no prover or key-handling export. Workers terminate after operations,
on cancellation or deadline; trapped workers must be recreated.

WASM downloads are same-origin, credential-free and limited to 8 MiB while
streaming. Redirects, URL credentials, query strings and fragments are rejected.
Both request and proof workflows share this loader. The byte-buffer loader
does not require streaming compilation, but static hosting should serve `.wasm`
as `application/wasm` and worker modules as JavaScript. A missing/corrupt artifact
produces a visible failure without a downloadable request or successful check.
The production build must honor its configured `DOCS_BASE` for both routes and
assets. Root and subpath browser tests exercise actual static output.

Only explicit user actions initiate explorer access. The immutable provider
mapping permits `https://blockstream.info/api` for mainnet and
`https://blockstream.info/signet/api` for signet, without redirects, credentials,
referrers or provider fallback. GET requests reveal selected addresses during
discovery and verified claim transaction IDs during fresh observations. They
send neither proof/request bodies nor policy fields, private keys or wallet
secrets. Cryptography and independent expected policy must pass before chain
fetches. See `web/features/provider/README.md` in source and
[limits and trust](./limitations) for non-atomic explorer and clock limits.

## Static CSP and Pages limitations

The production build inserts CSP at the start of each HTML head, before scripts
and resource links. Scripts/workers are same-origin, inline build scripts use
SHA-256 hashes of their exact bytes, and `wasm-unsafe-eval` permits WASM
compilation without enabling JavaScript `eval`. Connections are limited to the
site and the two pinned Blockstream API paths. Objects and native form
submissions are disabled, and a `no-referrer` meta policy suppresses referrers.
Inline **styles** remain permitted for the existing theme/Vue styles; arbitrary
inline scripts and event handlers are not permitted. No runtime CDN is required.

This policy applies to the built artifact, not the VitePress development server.
Rebuild after changing scripts: do not hand-edit generated HTML or add
`unsafe-inline`/`unsafe-eval` to fix a script hash mismatch. Browser tests check
that the real worker/request path has no CSP violations and that injected
inline/external scripts cannot execute or reach transport.

The existing GitHub Pages workflow uploads static files. This repository has no
mechanism that configures Pages response headers; a `_headers` or `.htaccess`
file is not a security-header control in this workflow. Meta CSP cannot enforce
`frame-ancestors`, CSP report-only/reporting, or server response protections.
In particular, the artifact does **not** provide clickjacking protection.
See the [CSP specification](https://www.w3.org/TR/CSP/#directive-frame-ancestors)
for the header-only frame restriction and
[GitHub's static Pages deployment model](https://docs.github.com/en/pages/getting-started-with-github-pages/what-is-github-pages).

If operating behind a header-capable HTTPS host/edge, serve the generated CSP
as an HTTP header (preserving its build hashes), adding `frame-ancestors 'none'`.
Also configure `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
`Referrer-Policy: no-referrer`, and an appropriate Permissions-Policy disabling
unused camera, microphone and geolocation capabilities. HSTS is an operator
domain decision. Verify actual response headers, MIME types and deployed-origin
CORS after deployment; local tests do not establish production protections or
provider availability. Publishing remains a separate authorized operation.

## Reproducible checks and residual risk

Dependencies are exact versions in `package.json` and resolved with integrity
in `package-lock.json`; the local shared theme is a workspace build dependency.
Use `npm ci`, review lockfile changes, and retain SDK/toolchain/source and theme
identities with the build artifact. Version pins do not establish absence of
vulnerabilities. This review does not audit the browser, shared theme, compiler
or cryptographic implementation, or attest production deployment integrity.

```sh
node --test web/wasm/asset.test.mjs web/features/request/form.test.mjs \
  web/features/request/download.test.mjs web/features/verify/input.test.mjs \
  web/features/verify/results.test.mjs web/features/history/history.test.mjs \
  web/features/provider/{contract,discovery,verification}.test.mjs
# First build the complete artifact per /wasm-build, with sources/notices:
python3 scripts/build_static.py --sdk-source ../longfellow-zk-dyne \
  --cross-work /path/to/qualified-wasm-build --base /
npm run docs:preview -- --host 127.0.0.1 --port 4176 --strictPort
# In another terminal; requires installed Chromium and WebKit:
QUIETPROOF_SITE_ORIGIN=http://127.0.0.1:4176 \
  node --test --test-concurrency=1 web/security.browser.test.mjs
```

For a subpath artifact, package with `--base /quietproof/`, start the preview
with `DOCS_BASE=/quietproof/`, and set
`QUIETPROOF_SECURITY_BASE=/quietproof` in the browser command. Optional
`QUIETPROOF_WEBKIT_EXECUTABLE` selects the qualified local WebKit launcher.
Firefox is unsupported and unqualified. Resource/accessibility qualification
and full adversarial round trips are separate gates from these input checks.
See [complete packaging and local-review flags](./wasm-build#build-and-preview-the-complete-static-artifact)
for provenance requirements and the
[owner-confirmed theme permission](static-release.md#theme-permission).
