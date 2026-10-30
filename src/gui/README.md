# Native GUI shell

The optional Linux application uses Nuklear's SDL renderer and SDL2 >=2.0.22.
Supply the existing LongfellowZK SDK, libcurl development package and an SDL2
CMake package through `CMAKE_PREFIX_PATH`, then configure:

```sh
cmake -S . -B build-gui -DQUIETPROOF_BUILD_GUI=ON -DQUIETPROOF_BUILD_RPC=ON
cmake --build build-gui --target quietproof-prover-gui
./build-gui/quietproof-prover-gui
ctest --test-dir build-gui -R '^quietproof-gui-' --output-on-failure
```

GUI defaults OFF. Its SDL/Nuklear dependencies do not enter exported library
targets, CLI-only or WASI configurations. GUI ON with RPC OFF is rejected.
The application opens existing v1/v2 request files for local review and tests
local RPC connectivity and wallet capabilities. Explicit Prove approval can
validate matching RPC key access; proof generation is not yet available.

Node shows the loaded request's network explicitly. Without a request, Change
test network selects a network for connection testing only. Defaults use numeric
localhost (127.0.0.1), the network's RPC port (8332/18332/38332/18443/48332 for
mainnet/testnet3/signet/regtest/testnet4) and its cookie under the Bitcoin data
directory (Linux `~/.bitcoin`). These match Bitcoin Roots v31.1-roots.3.
Advanced settings accept localhost or numeric loopback hosts, port, data
directory, explicit cookie path, loaded wallet name and connect/RPC timeouts
(milliseconds, at most 60000). Non-loopback hosts, URL syntax and credentials in
hosts are rejected by the same endpoint validation used by the RPC transport.
No redirects are followed. This GUI uses cookie authentication only.

Blank fields inherit defaults. An explicit cookie path takes precedence over
data directory; blank port follows the request network. Explicit overrides
survive request/network changes until cleared or Reset overrides.
Save stores only these nonsecret choices in `Plan-B/quietproof/node.conf`,
atomically with owner-only permissions on Linux. Reset also saves defaults.
Malformed, excessive or unknown config fields restore defaults with a visible
message. Neither cookie contents nor wallet passwords are read or persisted by
configuration; the transport reopens its owner-only cookie on every call, so
rotation after a node restart is supported. Custom node configuration such as
`-rpccookiefile`, `-datadir` or `-rpcport` must be reflected in these overrides;
the GUI does not parse bitcoin.conf. Connection success alone never establishes
proof readiness.

Test connection runs on one worker that owns its sequential RPC instance.
The main thread continues handling SDL/Nuklear events. Authentication, numeric
node version, node chain versus request network, initial-block-download state,
loaded wallets and advertised exportaddresskey support are reported separately.
Help advertisement is a capability observation, not a successful key export.
Core nodes without that method show explicit unsupported-proving guidance;
full Core wallet proving remains deferred. Test connection never unlocks a
wallet, calls exportaddresskey, or exports descriptors/private keys.

For supported single-key requests (including mixed P2PKH/P2WPKH claims with
the same key hash), the probe derives the matching address and checks its
script and network, then checks each wallet's public ownership information.
Watch-only/private-key-disabled, legacy/non-descriptor, external-signer or nonmatching wallets
are ineligible for the current Roots export provider.
Only one eligible loaded wallet is selected automatically. With several,
select a wallet in the report; it is tested again. An explicit advanced wallet
name counts as a selection. The default unnamed wallet is also supported.
Unsupported requests and mismatched networks cannot establish readiness.
These checks do not test current-chain claims, unlock state or actual key
availability; proving still requires later explicit approval and validation.

The worker-only wallet session API rechecks the immutable request's validity,
network, supported script, selected loaded wallet and public key ownership after
explicit Prove intent. A selected empty wallet name is an explicit identity,
even with several loaded wallets. It uses Roots `exportaddresskey`; descriptor
wallets are never assumed to support Core `dumpprivkey`. After Test connection,
return to Request and choose **Prove: approve wallet access**. No manual key
entry/import is exposed. In this milestone a validated key is promptly erased
on the worker; the UI does not retain it or present a completed proof.

Only a locked eligible wallet requests a wallet password; cookie authentication
remains separate. Submission repeats preflight. Already-unlocked and unencrypted
wallets are exported without changing their lock state. A locked wallet gets one
15-second `walletpassphrase` lease, no automatic retry or extension, and prompt
`walletlock` after export, failure, cancellation or invalidation. Cleanup always
targets the captured wallet, regardless of later UI selection. Returned scalar
and compressed-key hash are validated against the exact reviewed request before
the worker retains a key. Failed cleanup discards it. RPC calls are individually
bounded to at most five seconds; the capability probe has a ten-second total
budget. An in-flight call settles before cancellation cleanup.
Cancellation is checked between export preflight RPCs and before key export.
Request/settings/wallet changes invalidate the captured session; stale results
cannot reopen a prompt or retain a key. Cleanup warnings retain the old wallet's
identity even after a selection change. The single worker handles both connection
tests and wallet sessions, so those jobs cannot overlap. Closing while wallet
access is active keeps SDL responsive until the bounded call and relock settle.
If cleanup fails during closing, the window stays open with the warning; closing
again exits. On other exits the worker is canceled and joined, never detached.

Lock ownership is best effort: Core-style RPC has no atomic compare-and-unlock
or per-client unlock token. Another client may change state between checks,
extend the node's timer, or be affected by this app's relock. A lost unlock
response is uncertain even after a relock acknowledgement: late server processing
can unlock after that relock. These cases explicitly warn the user to check the
captured wallet in the node. The node's short timer is a fallback, counted from
its processing of the unlock, not a guarantee after dispatch or against another
client. Prefer avoiding concurrent wallet operations in other clients.

The key result is noncopyable and erased on release; owned unlock serialization
and received export bodies are overwritten with volatile writes. JSON, allocator,
transport, OS and compiler temporaries can retain other copies. This does not
protect against a compromised process/host, swap, crash dumps or the node's own
logging/storage.

Wallet passwords use a dedicated noncopyable 1024-byte buffer. The append-only
field accepts complete UTF-8 text commits, rejects ASCII control characters and input
that would exceed capacity, and displays only a mask (at most 24 asterisks).
Backspace removes and erases one Unicode character; Delete clears the buffer.
Paste is disabled, including Ctrl/Super+V and Shift+Insert. Copy, cut, undo/redo,
and selection are unsupported. Tab/Shift+Tab moves between the input, Unlock
once and Cancel; Enter submits, Escape cancels, and Page Up/Page Down scrolls
the information panel. IME commits are accepted; intermediate composition is
discarded rather than displayed. No Nuklear text editor or undo buffer receives
plaintext. RPC cookie authentication uses its own transport path.

Submission transfers buffer ownership to the worker and clears it immediately
after unlock RPC use, or on earlier failure. Wrong passwords reopen an empty
field and require an explicit fresh retry. Cancel, request replacement, expiry,
error, close and destruction clear owned input. Consumed/queued SDL text and
composition events are overwritten, and extended composition allocations are
freed. SDL/IME/OS internal copies and keyboard interception remain outside this
practical erasure guarantee; this is not protection against a compromised host.
Rendering test scripts must contain synthetic commands only; `private-synthetic`
generates transient fixture input inside the process instead of storing it in a
script, argv, environment or preference file. Never use real credentials in
rendering scripts or evidence screenshots.
RPC state and lease semantics follow the primary
[getwalletinfo](https://bitcoincore.org/en/doc/30.0.0/rpc/wallet/getwalletinfo/),
[walletpassphrase](https://developer.bitcoin.org/reference/rpc/walletpassphrase.html)
and [walletlock](https://developer.bitcoin.org/reference/rpc/walletlock.html)
documentation; live Roots qualification remains a separate gate.

Each test inspects at most 16 loaded wallets and has a ten-second total
budget; configured connect/RPC timeouts can shorten individual calls. No scan
RPC runs. Changed settings, network, wallet selection or request invalidate
results, and late results are discarded. One job runs at a time; a later test
waits for the current bounded test to finish. Closing joins the worker and
may take the remaining time budget (up to ten seconds); no thread is detached.

Use Browse files for the built-in, keyboard-accessible file chooser, enter a
file path and press Enter/Open request, drop a file onto the window, or launch
with `--request path`. The chooser lists up to 256 entries per directory;
the path field supports exact paths when a directory is larger. Cancel or
Escape closes the chooser without replacing the current request. A failed
replacement clears the old request. Reads are limited to 4097 bytes; supported
requests are at most 4096 bytes. Proof files receive a separate error. The
original bytes and decoded request remain immutable in memory; no request
data is stored in preferences and loading makes no RPC or key calls.

Review shows the same request fields as `quietproof inspect`, including the
request-provided verifier, purpose, network, creation/not-before and expiry,
statement version, claim count/script kinds and snapshot request. Timestamps
use UTC; creation and not-before are the same request timestamp. The live time
window includes not-before and excludes expiry, matching the CLI prover.
Time validity alone does not establish wallet readiness or current-chain status.
Show claims expands exact transaction outpoints, integer satoshi/BTC amounts,
public key hashes and canonical output script hex. Summary and claims scroll.
Verifier identity is unverified; URLs remain literal text and are never opened.
Invisible directional/layout characters are shown as explicit Unicode escapes;
the original request bytes and values remain unchanged.

`--help` lists deterministic rendering options. For a headless lifecycle check:

```sh
SDL_VIDEODRIVER=dummy SDL_RENDER_DRIVER=software \
  ./build-gui/quietproof-prover-gui --smoke-test --theme light --screenshot shell.bmp
```

Smoke mode renders three native frames and closes through an SDL_QUIT event.
Rendering tests should set `XDG_DATA_HOME` to a temporary directory to isolate
display preferences. Screenshots require an explicit output path. The normal application
starts at 480x720 logical pixels and supports resizing down to 400x640.

Request, Node and Result share a status area and primary action. Actions stay
disabled until their prerequisites are implemented and available. The Display
view offers light/dark themes and 100%, 125% and 150% text. Only those two
display choices are stored in SDL's per-user `Plan-B/quietproof/display.conf`;
an invalid file falls back to defaults. See `BRANDING.md` for verified tokens.
Tab/Shift+Tab moves visible focus, Enter/Space activates, Page Up/Page Down
scrolls details, and Escape closes Display. Keyboard focus scrolls into view.
The GUI shell test captures both shell and settings at every required size,
font scale and software pixel density, and checks keyboard and pointer paths.

Nuklear/backend and the Inter native font are vendored at recorded revisions;
see `vendor/PROVENANCE.md` and the retained licenses. No runtime downloads occur.
Inter is copied beside the build executable and installed under
`share/quietproof/fonts`; the application also has Nuklear's built-in offline
font fallback (`--builtin-font` exercises it). `cmake --install build-gui
--prefix <destination>` installs the executable, font and notices. SDL itself is
an external dependency; distribution packaging must include its runtime when
using shared SDL and preserve its license when distributing it.
