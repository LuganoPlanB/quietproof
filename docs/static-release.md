---
title: Static release handoff
description: Qualification, publication prerequisites and rollback for the packaged browser application.
---

# Static release handoff

**Publication has not been authorized.** This document prepares the reviewed
static artifact and its operating handoff; it does not trigger deployment.

## Theme permission

On 2026-10-28 the project owner confirmed ownership of the Plan B theme and
permission to use their theme in this QuietProof deliverable. The scoped
record is `LICENSES/Plan-B-theme-permission.txt`, packaged as
`licenses/Plan-B-theme-permission.txt` and bound by the build provenance.

The theme's package metadata does not declare a license identifier. The owner
confirmation resolves permission for this deliverable; it does not invent an
SPDX license or a blanket grant covering third-party components. Retain their
existing copyright notices and licenses. Theme permission is separate from
authorization to publish from this workspace.

## Candidate and qualification

Use the [pinned build and qualification commands](wasm-build.md), with a clean
committed source tree for a release. `--allow-dirty` and `--source-addition` are
for local review only. Retain the exact source revision, package lock, toolchain
archive/checksum, native/WASM identities, browser versions, complete test logs
and artifact digests. Preserve the previous candidate before regenerating
time-limited public proof fixtures. Run the real crypto suites serially and
keep build concurrency bounded.

The deployable directory is `docs/.vitepress/dist`. It includes
`asset-manifest.json`, `build-provenance.json`, `SOURCE-NOTICE.txt`, corresponding
source archives and license notices. Verify every manifest entry, the
SHA256-named reactor and the recorded source/toolchain provenance. Package for
the actual base path: `/` and `/quietproof/` qualification do not establish
correctness for another production path. Upload the whole matched directory;
keep the HTML, workers, JavaScript and WASM from one build together.

Required local gates include native RPC ON/OFF compatibility, cross-build
separation contracts, real WASM verification, provider policy/cryptography
ordering, unit/site/packaging tests, the full Chromium/WebKit workflow and
adversarial suites, resource measurements and root/subpath static hosting.
Inspect documentation and tools at 390×844 and 1440×900 CSS pixels with 100%
and 200% text. Review the complete intended diff and source/license contents.
Final branch acceptance and the independent terminal branch review remain
separate decisions; a local qualification report is not that acceptance.

## Publication prerequisites

Before an explicitly authorized publication:

1. Retain the scoped theme owner confirmation and existing third-party
   notices, and resolve any outstanding release findings.
2. Complete source review, accepted commits and the terminal whole-branch
   checks. Require a clean release build with `dirtyReviewBuild: false`.
3. Confirm the repository's Pages source, actual base path and deployment
   environment controls. The existing `deploy-pages.yml` runs on a push to
   `main` or a manual dispatch: either is a production trigger, not a preview.
   Do not trigger it while publication prerequisites remain unresolved.
4. Retain an immutable copy and digest of the currently deployed directory,
   its source revision, base path and deployment/run identity. Retain the new
   candidate and qualification evidence separately. Confirm the previous
   candidate is still suitable to restore, including its permissions.
5. Check the real origin's TLS, WASM MIME type, CSP and other response headers,
   cache behavior and provider CORS behavior. Local servers cannot establish
   these. Plan a post-deployment smoke check and an authorized rollback.

The existing Pages workflow calls `test.yml` for qualification with the base
path from `configure-pages`. It downloads the `quietproof-static` artifact,
uploads that exact directory as the Pages artifact and deploys it in the
`github-pages` environment. It does not rebuild the site after qualification.
Its current configuration is not evidence of a successful hosted run or
configured approval protection. Trigger publication only after the separate
deployment authorization and the release prerequisites above are satisfied.

The qualification job allows 240 minutes, with native builds limited to two
jobs and proof/browser suites serialized. The complete local qualification
took approximately 163 minutes with existing native build prerequisites;
cold dependency/compiler/browser setup needs additional time. This observation
is not a hosted CI timing guarantee. The larger job budget does not change the
application's five-minute verification deadline or protocol/resource limits.

After explicit deployment authorization, use that existing
workflow for the reviewed revision. Record its run and deployment identity,
artifact digest and resulting URL. Check the published guide, request and
verification routes, local search, matching worker/reactor fetches and
`application/wasm`. Exercise only public fixture data for the smoke check;
never enter wallet keys, seeds or RPC credentials into the browser. Confirm
reading/importing does not contact an explorer and that an explorer check
requires the explicit action. A live provider check needs its own deliberate
consent and must retain the public explorer trust/non-atomicity warning.

## Rollback

Stop further release triggers if a deployed candidate fails its smoke check.
With explicit rollback authorization, restore the complete retained previous
artifact using the host's approved deployment procedure. Do not mix old HTML
with new assets, change a single WASM file in place, or substitute an
unqualified directory. Retain the failed candidate and its logs for diagnosis.

For the existing source-driven Pages workflow, an alternative is an accepted
revert to the retained previous source revision followed by its normal full
qualification/deployment path. That rebuild is a new candidate: verify its
digests and prerequisites rather than assuming it reproduces the old
deployment. A revert/push or workflow dispatch is itself a production trigger
and requires authorization. Do not bypass qualification with a manual upload
of an unreviewed artifact.

Record the rollback deployment identity and URL, then repeat the route,
asset/MIME, header and public-fixture checks. Investigate caches if a client
still loads the failed version. Local opt-in request/result history is not
reset by a site rollback; it remains unencrypted, device-clock-dependent local
data and is never an authoritative acceptance or global replay record.

## Retained limits

The browser supports mainnet/signet requests and verification only; proving
and all private keys remain in the external CLI/wallet. It supplies no
challenge/acceptance backend and no authenticated or atomic chain snapshot.
See the [operator guide](guide/browser-tool.md) for exact supported scripts,
policy choices, privacy and clocks/history boundaries.

Desktop Chromium and WebKit are qualified. Firefox, physical low-memory/mobile
hardware, actual screen-reader use and native browser zoom behavior remain
unqualified. The extra 195-CSS-pixel stress viewport is outside the required
390-CSS-pixel text-scaling matrix. Peak WASM linear memory is not process RSS.
Hosted CI and production-origin headers/CORS need their own retained evidence.
