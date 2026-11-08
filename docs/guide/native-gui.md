# Native wallet prover on Linux

The optional QuietProof Prover defaults to signature custody (PoSC). It reviews
a public v3 `.qpr`, consumes an owner-only private `.qpa` receipt after explicit
approval, and saves a locally verified public `.qpf`. Signature custody may be
delegated; it does not prove private-key knowledge or exclusive funds control.
Use the CLI or [browser request tool](browser-tool.md) to create requests.
Only native P2WPKH and compressed-key P2PKH outputs sharing one key hash are
supported, at most 16 per request. Different keys need separate proofs.

## Build and install

Prepare the C++20 compiler, CMake 3.20+, Ninja, pinned Longfellow SDK, a supported
patched curl development package and SDL2 2.0.22+ before configuring. The tested
Linux inputs are GCC 14.2.0, CMake 3.31.6, SDK
`d2b0fc515f8663e38c79a28e8900ce8438e0106e`, curl 8.14.1 and SDL2 2.32.10.
See `src/gui/vendor/PROVENANCE.md`, `src/gui/assets/DEPENDENCIES.md` and
`scripts/build-pins.json` for pinned sources, hashes and notices. There are no
runtime downloads and configure does not fetch dependencies.

```sh
cmake -S . -B build-gui -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DQUIETPROOF_BUILD_GUI=ON -DQUIETPROOF_BUILD_RPC=ON \
  -DCMAKE_INSTALL_PREFIX="$HOME/.local" \
  '-DCMAKE_PREFIX_PATH=/path/to/longfellow-prefix;/path/to/curl-prefix;/path/to/SDL2-prefix'
cmake --build build-gui --parallel 2
cmake --install build-gui
"$HOME/.local/bin/quietproof-prover-gui" --request /absolute/path/request.qpr
```

Installation includes the CLI, C++ packages, Inter/OFL, notices, operating guide,
Linux desktop launcher and the existing QuietProof icon. Put the prefix's `bin`
in PATH for the launcher; desktop discovery depends on your session's XDG data
directories. No privileged installation or desktop database update is needed.
Keep `bin` and `share` together when relocating a conventional prefix. Launch
from any working directory. The tested build still needs system runtime
libraries (`ldd` identifies them); it is not a universal static binary.

GUI defaults OFF. `QUIETPROOF_BUILD_GUI=OFF` preserves the headless CLI/library
build and avoids SDL discovery. `QUIETPROOF_BUILD_RPC=OFF` also requires GUI OFF.
WASI/browser builds remain separate and cannot enable this native GUI.

## Review and prove with a private receipt

Obtain the exact request and its receipt through native
[`signing-material` / `import-signature` or `authorize`](signature-possession.md).
Open the public request, keep **PoSC (default)** selected, and review its network,
verifier, purpose, expiry, amounts and outpoints. Enter the receipt's absolute
path and choose **Prove with receipt**. The file must be regular, owned by the
current user, with no group/other permissions. This worker makes no wallet RPC
calls and never unlocks a wallet or exports a key. Missing or incompatible
receipts fail without switching modes.

Keep private receipts in native tools; only public `.qpr` and `.qpf` belong in
browser uploads. Choose **PoKC (legacy)** explicitly for v1/v2 requests. Request
versions never change modes; a mismatch disables proving. Signature-disabled
builds report unsupported for PoSC. Request replacement clears approval/results.

## Explicit legacy PoKC wallet access

Start your trusted Roots node independently. A compatible local binary is enough
for disposable regtest qualification; never use your funded wallet for tests.
The GUI does not start, stop, import into or rescan a wallet. Open a request with
the chooser, drag/drop or `--request`; check network, verifier, purpose, message,
time window, amounts and exact outpoints before approval. Request replacement
invalidates previous approval and readiness. Display offers light/dark themes
and 100%, 125%, 150%, 200% fonts; minimum window is 400 by 640 logical pixels.

In Node, Test connection authenticates and checks wallet capabilities. Select
the intended loaded wallet. Connection success alone does not establish proof
readiness. Supported wallet state requires the needed private key and Roots'
`exportaddresskey` capability; watch-only wallets, unavailable keys and
unsupported nodes produce an explanation instead of enabling proving.

Linux defaults use HTTP loopback `127.0.0.1`, the request's network port,
`$HOME/.bitcoin` and its network-specific `.cookie`. Ports are mainnet 8332,
testnet3 18332, testnet4 48332, signet 38332, regtest 18443. The mainnet cookie
is directly in the datadir; others use `testnet3`, `testnet4`, `signet`, `regtest`
subdirectories. There is no `bitcoin.conf` parsing or endpoint fallback.
Advanced fields explicitly override host (numeric loopback/localhost), port,
datadir, cookie path, wallet, connect timeout (default 5000 ms) and RPC timeout
(30000 ms); GUI timeout overrides allow 1 through 60000 ms. An explicit cookie
path overrides datadir lookup. Endpoint credentials are never URL/password
fields. Nonsecret connection choices and display preferences persist under
SDL's Linux data directory, normally `$XDG_DATA_HOME/Plan-B/quietproof` or
`$HOME/.local/share/Plan-B/quietproof`, in owner-only files.

## Legacy wallet password and cancellation

RPC cookie authentication and a wallet encryption password are different.
The wallet password belongs only in the private masked unlock dialog after
request approval. Type it there; clipboard paste, drag/drop, argv, environment,
configuration and log input are unsupported. Cancel clears the private buffer.
Wrong password leaves the wallet locked and permits a fresh typed retry.
An unencrypted or already unlocked wallet needs no new unlock password.

For a wallet initially locked, the GUI requests one 15-second unlock, exports
and validates the one required key, then relocks before native proving. It
attempts cleanup on error, cancel and close; it does not intentionally relock
a wallet already unlocked by somebody else. This lease is not exclusive:
another client can change lock state or extend/reset the timer. A timed-out
unlock RPC can finish late on the server, even after a relock acknowledgement.
The short node timer is a fallback counted from server processing of the unlock;
it does not guarantee relock within a fixed wall-clock interval after GUI
dispatch or against another client's timer changes. Test qualification observed
relock before lease expiry, not just expiry after the
proof. A user password/key can still have OS, allocator and native-library
copies; masking and buffer clearing cannot promise complete memory erasure.

Cancel or close waits for the current bounded RPC or whole native proof call,
then discards canceled output and completes cleanup. Native proving is not
interruptible halfway through; the window can remain in Finishing canceled work
while the worker settles. It runs one sequential worker, with no parallel key
or proof jobs. Progress names are phases, not a percentage or time guarantee.

## Save and independently verify

The success screen means native cryptography and exact reviewed-request binding
passed. It does **not** establish current chain state, freshness under a
verifier's policy, reserved coins, exclusivity, ownership or solvency. Public
proofs disclose outpoints, amounts and key hashes. An independent verifier
must supply its expected request/policy and current chain evidence; the CLI
`verify` command can return `valid_current` after exact UTXO checks and durable
nonce consumption. A spent output can leave cryptography valid while current
authorization is `state_inconclusive`. See [operations](../operations.md).

Save As retains only the verified public proof. Choose an explicit destination.
An existing file requires a second explicit approval bound to that exact path
and observed file identity; changing either requires another approval. Saving
uses a 0600 same-directory temporary file. A new destination is published
atomically with a hard link without replacement. An explicitly confirmed existing
regular file uses atomic rename after a path/identity recheck. The public proof
remains available for retry after an unwritable/missing directory or canceled dialog. Choose
a working path and retry without exporting the key or recomputing the proof.
An external process can still race the final POSIX comparison/rename. Publication
is the cancellation boundary: a late cancel leaves the complete published proof
intact. A late
directory-sync failure can mean publication happened but durability is uncertain:
inspect the destination before retrying, and keep a verified copy. Closing loses
the in-memory retained proof. Files never upload automatically.

## Observed qualification and limits

Earlier explicit legacy PoKC qualification used disposable, peerless,
loopback-only regtest with Bitcoin Roots
`v31.1-roots.5`, source ref `93348f8530aadce4562aef40272b1e0af3e3478b`, binary
SHA256 `46e5a080b4eb7b5bef8c986a6ab276924af7d9004e80856d942fd5c6f333ff55`.
Binary identity is pinned; a preexisting test-source delta means rebuild identity
from that worktree is not claimed. Encrypted P2WPKH/v1 and unencrypted compressed
P2PKH/v2 completed GUI proof/save and CLI current-chain verification, including
wrong-password retry, early relock, cancellation, spent-outpoint rejection and
save recovery. The opt-in qualification scripts are
`tests/gui/roots_e2e_test.py` and `tests/gui/roots_masked_matrix_test.py`; they
require explicit existing node binaries and own disposable datadirs/processes.

Bitcoin Core 30.3 capability rejection was exercised live; ordinary Core lacks
the Roots key-export extension. Legacy key-export proving with Core is unsupported. Default PoSC can instead
consume a native receipt acquired through supported signing. The
separate experimental `scripts/prove_core_wallet.py` follows another workflow;
it is not launched by or required by this GUI. CLI RPC qualification also covers
Core 28.3/30.3. Never infer export support merely from a Core version number.

The native UI matrix covered both themes, 400x640/480x720/600x900, all three
font sizes and software HiDPI 2x, with real requests and masked wallet input.
SDL dummy/software and owned Xvfb were used; no physical display was available.
Selected ASAN/UBSAN lifetime checks passed; prebuilt crypto/dependencies and the
OS were not comprehensively instrumented. Linux packaging does not claim macOS,
Windows, physical HiDPI or browser/mobile GUI support.
