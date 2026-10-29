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
The current shell does not connect to wallets or generate proofs.

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
