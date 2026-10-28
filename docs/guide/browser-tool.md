---
title: Use the browser request and verifier
description: Create a public request, prove outside the browser, then check the returned proof under independent expectations.
---

# Use the browser request and verifier

Create a public `.qpr` request, send it to the prover, and import the returned
`.qpf` proof. Proving happens in the native CLI or a compatible external wallet.
**Never enter a spend key, seed phrase, wallet password or RPC credential into
the browser tool.**

The tool runs locally in your browser. It has no challenge/acceptance server,
proof-upload endpoint or global nonce registry. Cryptographic checking and
explorer-reported output status are separate results. Neither authorizes a
business decision or establishes exclusive control, ownership or solvency.

## Before starting

| Boundary | Browser support |
| --- | --- |
| Networks | Mainnet and signet; choose explicitly. A `tb1` address does not identify signet by itself. |
| Scripts | Native P2WPKH and compressed-key P2PKH, including mixed claims sharing one fingerprint or using two fingerprints. A P2PKH address alone cannot establish key encoding. |
| Request size | One or two addresses; select 1–16 exact outputs with at most two distinct key fingerprints. No automatic output selection. |
| Unsupported | P2SH, P2WSH, P2TR, uncompressed-key P2PKH and other scripts; historical snapshot and bridge verification. Metadata inspection is not acceptance. |
| Browsers | Qualified desktop Chromium and WebKit. Firefox is unsupported and unqualified. |
| Resources | Real proofs are roughly 45/87 MiB for one/two keys and can take minutes. Measured linear allocation is about 0.95/1.82 GB; the module maximum is 2 GiB, **plus** browser, file and JavaScript memory. These are not process RSS or total-RAM requirements. |

Use a desktop with ample available memory and run one proof at a time. A
390-pixel layout does not qualify a phone or a low-RAM device. Physical mobile/
low-memory hardware and actual screen-reader use remain unqualified. See the
[named environments, measurements and limits](/performance#browser-resource-boundary).
Trust the origin delivering the application and its assets; a compromised site
can replace the verifier and results.

## 1. Create and retain the request

1. Open [Create a request](/tool), choose **Bitcoin network**, and enter one or
   two **Bitcoin addresses**, one per line.
2. Select **Look up outputs**. This explicit action sends the addresses to the
   displayed public explorer. Editing the form alone does not query it.
3. Review and select the exact disclosed outputs. Check scripts, amounts,
   confirmations and the total against your own intended claim. The explorer is
   a trusted data source here, not independently validated chain consensus.
4. Set **Intended verifier**, **Purpose**, the exact **Message**, and **Request
   lifetime in seconds**. The default is 300 seconds; the allowed range is
   1–86400. Allow enough time for external proving and verification while
   keeping your own freshness policy short.
5. Select **Create request**, review **Canonical request preview**, and download
   the `.qpr`. Keep your original file as the verifier's independent expectation
   before sending a copy to the prover.

Nonce generation uses browser cryptographic randomness. Creation and expiry use
the device clock, which is untrusted. **Regenerate request** makes a new nonce;
it does not extend an existing proof. Changed inputs invalidate the preview and
download. If a request expires, obtain a new request and a new proof rather than
editing its bytes or changing a clock.

The request discloses outpoints, amounts, script kinds, key fingerprints,
verifier/purpose and a message hash. Send it through an appropriate channel and
restrict retention: it links a counterparty to disclosed coins.

## 2. Prove outside the browser

The prover uses a compatible native QuietProof build; see
[native build and isolated regtest tutorial](./getting-started). Replace the
downloaded filename below with its actual path:

```sh
build/quietproof inspect request.qpr
build/quietproof prove --request request.qpr --output proof.qpf
build/quietproof inspect proof.qpf
```

`inspect` shows a summary: network, statement version/script kinds, verifier,
purpose, claim count and timestamps. It does not print every outpoint, amount,
key fingerprint, message hash or nonce. Review those through the original
request preview and your trusted engagement record, and confirm that the file
is the exact request you intended before using a key. `prove` uses that file exactly;
do not create a replacement CLI challenge or rely on CLI context defaults.
It reads one 32-byte hexadecimal secret per distinct compressed-key hash from
protected stdin. Interactive input disables echo. Secrets belong in protected
input, never command arguments, environment variables, shell history, logs or
the browser. Plain proving needs no node, RPC cookie or network connection.
Existing output paths are never overwritten.

Compatible wallet support is integration-specific. The native CLI's explicit
[Bitcoin Roots wallet-backed mode](/operations#explicit-wallet-backed-proving)
can use an already loaded/unlocked wallet for a request sharing one distinct
key fingerprint. It obtains a key into the native process; it is not a browser
wallet connector and does not guarantee complete memory erasure. Multi-key
requests use protected stdin. Configure and unlock the trusted wallet outside
the browser; unavailable wallet support does not trigger an export fallback.

Return the `.qpf` to the verifier. The verifier should use its retained expected
`.qpr`, not infer expectations from proof metadata or trust a replacement
request supplied with the proof. The proof hides the spend key and does not
newly disclose its public key; outpoints, amounts and wallet links stay public.

## 3. Import and choose independent expectations

Open [Verify a proof](/verify) and select **Proof file (.qpf)**. The file ceiling
is 134221889 bytes (128 MiB plus envelope), checked before reading. Select an
**Expected policy source**:

- **Exact expected .qpr request**: choose your independently retained request
  (at most 4096 bytes). Canonical bytes, including nonce and exact claims, must
  match. An explicitly selected saved local request is also editable local
  data; review its source.
- **Explicit expected context**: independently choose network, verifier,
  purpose and exact message, then confirm that you chose them. This binds that
  context but does not independently retain the nonce or exact claim set.
  Prefer your exact `.qpr` when available.
- **Inspection only — no expected policy**: useful for untrusted metadata, not
  a verification policy.

**Inspect proof and policy** decodes metadata and checks the selected binding.
The heading **Inspection only · cryptography not checked** means exactly that.
A matching inspection does not establish spend-key knowledge or chain state.

## 4. Verify and read each result separately

Choose **Verification network (chosen independently)**. It must match your
expected request or context. Review **Minimum confirmations**, **Minimum unspent
total (sats)** and **Maximum observation age** (1–300 seconds).

| Action/result | What it establishes |
| --- | --- |
| **Verify offline** | Runs real proof cryptography and expected-policy checks without explorer access. Chain status stays **Unavailable**. |
| **Verify and check explorer** | After independent policy and real cryptography pass, fetches fresh exact-claim observations from the displayed provider. Requires the explicit explorer checkbox and verification action. |
| **Proof cryptography: Valid** | The supported proof relation passed. Read expected policy and chain status separately. |
| **Independent expected policy: Matched at check time** | The chosen expectations/time checks matched at that time; device time is untrusted and expiry can change while the page is open. |
| **Reported unspent under selected limits** | The selected explorer reported matching observations. They are trusted and non-atomic, not strict current/historical chain validity or an authenticated snapshot. |
| **Invalid**, **Rejected**, **Not checked to completion**, **Reported spent**, **Unavailable** or **Inconclusive** | Do not reinterpret these as acceptance. Correct policy/input, obtain a fresh request, retry or investigate as appropriate. |

The result shows the provider, observation window, selected limits and separate
totals when available. A funding block is not a current chain snapshot. Coins
can move between observations or after any check. The browser never returns the
native verifier's strict `valid_current`/`valid_historical` authorization result.
A separate application must supply any acceptance policy and durable replay
control it needs.

Phase and elapsed-time feedback is not a completion percentage. **Cancel
verification** terminates the worker. File/network/policy changes invalidate
pending work and old results; retries use a fresh worker. Verification has a
five-minute operation deadline. On timeout or allocation failure, cryptography
is incomplete; use a supported device or investigate before retrying. No smaller
circuit or weaker proof is substituted.

## Privacy, connectivity and local history

The pinned providers are `https://blockstream.info/api` (mainnet) and
`https://blockstream.info/signet/api` (signet). Address lookup reveals the
selected addresses. After valid cryptography, fresh observations reveal claim
transaction IDs/output indices. Requests are credential-free GETs without
proof/request bodies, private keys or wallet credentials. There is no provider
fallback or browser RPC endpoint. Provider availability, rate limits and CORS
can fail; a local pass does not establish production-origin CORS/headers.

Offline means no explorer access. The application, worker and WASM asset must
still be locally available: use a complete artifact served from loopback HTTP
for disconnected work, not an unsupported `file://` page or a promise that the
ordinary browser cache is complete. Building/local preview uses Node; the
deployed artifact needs only a static HTTP(S) host. See
[build and local preview](/wasm-build#build-and-preview-the-complete-static-artifact).

Local history is off by default, unencrypted and limited to the browser profile
and origin. Opt-in can retain up to eight requests and 24 check markers, not
proof bodies or keys. Explicit save/select, repeat warnings, delete and clear
are conveniences. Other profiles/devices/origins, cleared/blocked storage,
private sessions and eviction can lose them; same-origin code can edit them.
Local history is not global nonce consumption, identity authentication or an
acceptance record. Keep your own controlled request/proof/policy/software
evidence and protect its disclosed wallet links.

For operator trust and response-header limitations, read
[browser security and hosting](/browser-security). To exercise the complete
handoff without real coins, live provider access or private wallet material, use the
[public disposable fixture roundtrip](/wasm-build#public-fixture-roundtrip).
