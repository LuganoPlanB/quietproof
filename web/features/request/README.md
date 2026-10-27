# Request feature

`RequestForm.vue` is the `/tool` feature entry in the existing VitePress site.
`form.mjs` owns selection and context rules; `download.mjs` creates and inspects
canonical request bytes in the existing WASM worker. Public lookup uses the provider feature's public
`setupProvider` entry and disposes it on input/network changes and unmount.
Construction and editing perform no explorer fetch.

Build the reactor using [the build guide](../../../docs/wasm-build.md), then stage
that generated artifact for the existing static site (it is excluded from Git):

```sh
install -D ../.gestalt/quietproof-wasi/quietproof-build/quietproof.wasm docs/public/wasm/quietproof.wasm
```

The tool resolves this path under the configured VitePress base. No reactor is
loaded until explicit request creation. A missing, invalid or unsupported asset
fails without a downloadable artifact. Production packaging is a separate
delivery gate.

For the built artifact, run `npm run docs:build` before `npm run docs:preview`.
Restart the preview after rebuilding so its hashed asset mapping stays current.

From the repository root, start `npm run docs:dev -- --host 127.0.0.1 --port 4174`.
In another terminal run:

```sh
node --test web/features/request/form.test.mjs
node --test --test-concurrency=1 web/features/request/form.browser.test.mjs
node --test web/features/request/download.test.mjs
QUIETPROOF_NATIVE_CLI=/path/to/quietproof node --test --test-concurrency=1 web/features/request/download.browser.test.mjs
QUIETPROOF_NATIVE_CLI=/path/to/quietproof node --test --test-concurrency=1 web/features/request/workflow.browser.test.mjs
```

The browser tests require installed Playwright Chromium and WebKit. Set
`QUIETPROOF_WEBKIT_EXECUTABLE` for an existing supported local launcher when
needed, `QUIETPROOF_SITE_ORIGIN` for a different preview origin, and
`QUIETPROOF_REQUEST_SCREENSHOTS` to retain the viewport/text-scale matrix.
All explorer responses in the suite are deterministic fixtures; no live query
is necessary. Firefox is unsupported and unqualified.

The download suite uses the actual staged reactor, real browser workers and the
native CLI parser. It compares downloaded bytes with worker output, repeats the
same download, checks regeneration and input invalidation, and exercises failure
and cancellation. `QUIETPROOF_REQUEST_SCREENSHOTS` retains its success/error
matrix. The preview owns one Blob URL; changes and unmount revoke it. The worker
is terminated after each creation/inspection or cancellation.

The workflow gate covers mainnet and signet with v1 P2WPKH, typed v2 P2PKH,
and mixed P2WPKH/P2PKH requests with two distinct keys. It downloads and parses
48 fresh requests across the engine/viewport/text-scale matrix, and serially
creates twelve real native proofs from downloaded requests (one per engine,
network and script family). Only well-known disposable scalars 1 and 2 enter
the native CLI's stdin. They never enter the browser or provider requests.
`workflow-fixtures.mjs` imports Node crypto and is test-only. No live coins,
node, RPC credentials or private wallet material are used.

Set `QUIETPROOF_WORKFLOW_ARTIFACTS` to retain a run directory containing
requests, native proofs, per-proof logs, exact command/timing provenance and
complete-workflow screenshots. Without it, artifacts go to a named temporary
directory. Each run uses a fresh subdirectory, preserving earlier failures.
Budget several minutes and roughly 0.8 GiB of artifact storage; heavy native
proving runs serially. This gate demonstrates native proof creation and format
compatibility; end-to-end browser proof verification remains a separate gate.
Expiry and regeneration checks use the ordinary browser clock and fresh
cryptographic nonces; production code has no fixed time/nonce seam. Request
editing and preview state remain in memory; there is no remote persistence.
