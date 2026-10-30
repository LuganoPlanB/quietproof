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
The application opens existing v1/v2 request files for local review. It does
not yet connect to wallets or generate proofs.

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
