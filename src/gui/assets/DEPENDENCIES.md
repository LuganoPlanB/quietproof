# Native GUI distribution inputs

The GUI uses the existing QuietProof mark (`docs/public/quietproof-mark.svg`)
and compiled light/dark palettes documented in `BRANDING.md`. No theme engine,
web theme code, remote font service or runtime downloader is used. The scoped
Plan B authorization is retained in `Plan-B-theme-permission.txt`.

| Input | Qualified revision | Retained notice |
| --- | --- | --- |
| QuietProof and Longfellow SDK | SDK `d2b0fc515f8663e38c79a28e8900ce8438e0106e` | GPLv3 `COPYING`; source headers specify GPLv3 or later |
| Nuklear / SDL renderer backend | `8407f477c7cb0cc69236c0232a3a4967395e9eb1` | MIT alternative `LICENSE`; embedded font notices remain in source |
| Inter variable TrueType | google/fonts `0b58fb370093f9a9f4ff785d94405710b79de67c` | `fonts/Inter-OFL.txt`, SIL OFL 1.1 |
| SDL2 | 2.32.10; minimum API 2.0.22 | `SDL-LICENSE.txt`, zlib license |
| curl | 8.14.1; minimum API 7.62 with vendor security fixes | `curl-COPYING.txt`, curl license |

`PROVENANCE.md` gives exact vendored font/header and SDL archive hashes.
`scripts/build-pins.json` pins the SDK, website theme and WASI toolchain;
the website theme revision is `a7fde3404a5e2b32bf57b4bcb99337479c5c75b2`.
Build dependencies are prepared before configure; CMake and the application do
not fetch them. This local Linux build links SDL2, curl and the SDK statically;
OpenSSL 3, zlib, zstd, libc, libstdc++ and libgcc remain system runtime libraries.
It is not a self-contained static release. Inspect `ldd` for the actual build.
Distributors must carry the corresponding sources, dependency notices and
system-runtime licenses required for their chosen linkage. The separate musl
CLI archive has its own `LICENSES/release-dependencies.md`; its versions and
linkage must not be attributed to this GUI package.

For the qualified native build, pin curl to upstream tag `curl-8_14_1`
(`https://github.com/curl/curl/tree/curl-8_14_1`) and SDL2 to the 2.32.10
release archive SHA256
`5f5993c530f084535c65a6879e9b26ad441169b3e25d789d83287040a9ca5165`.
Keep the exact SDK/font/Nuklear revisions above. Local security-patched vendor
builds need their own source and binary fingerprints; matching an API minimum
alone does not reproduce this qualification. Updating these inputs requires
fresh build/runtime qualification.

The operating guide is `share/doc/LongfellowZKQuietProof/docs/guide/native-gui.md`;
its related-guide links resolve within that installed documentation tree.
Installed native notices live in `share/doc/quietproof-prover-gui`, the font
and OFL in `share/quietproof/fonts`, and the existing mark in the Linux hicolor
icon tree. The palettes are compiled into the executable. The executable
resolves the font relative to its own location, so a prefix with conventional
relative GNU install directories can be moved together. Missing or unreadable
Inter falls back to Nuklear's embedded licensed default font; it never downloads
a replacement. Keep the package layout intact to retain the qualified font.
