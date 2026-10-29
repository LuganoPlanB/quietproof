Nuklear and the unmodified `demo/sdl_renderer/nuklear_sdl_renderer.h` are vendored
from Immediate-Mode-UI/Nuklear commit
`8407f477c7cb0cc69236c0232a3a4967395e9eb1` (2026-10-29 capture).
Upstream: https://github.com/Immediate-Mode-UI/Nuklear
License: MIT alternative in LICENSE; embedded default font notices are retained
in nuklear.h. Exactly one implementation unit is compiled.

SHA256:
- nuklear.h: 448cf5ae4c37c800da7264e42df73613f05dffde9afda82253a20b979c90a2a4
- nuklear_sdl_renderer.h: af7bd45818ab4d9033b86ad4a9653c3ec57c092966d2c21d254f083fc16124bd

`../assets/Inter.ttf` is the Inter variable native TrueType font from
google/fonts commit `0b58fb370093f9a9f4ff785d94405710b79de67c`,
`ofl/inter/Inter[opsz,wght].ttf`. License: SIL Open Font License 1.1,
retained in `../assets/Inter-OFL.txt`.
SHA256: 29160a80ff49ddcab2c97711247e08b1fab27a484a329ce8b813d820dc559031.

SDL2 >=2.0.22 is a build dependency; no runtime downloads occur. Linux validation
uses locally built SDL2 2.32.10 from https://www.libsdl.org/release/SDL2-2.32.10.tar.gz
(SHA256 5f5993c530f084535c65a6879e9b26ad441169b3e25d789d83287040a9ca5165).
SDL2 is licensed under the zlib license; distributions must retain its license
when distributing the dependency. CLI, library and WASI builds default to GUI OFF.
