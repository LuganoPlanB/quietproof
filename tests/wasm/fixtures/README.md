# Native codec golden bytes

These public, synthetic claims use no private key. `0` is v1 P2WPKH with
one distinct program; `1` is v2 P2PKH; `2` is mixed v2. All use one key hash. The `.options` files use the browser's QWC1 options transport;
`.qpr` files are native canonical requests with nonce bytes `07` and creation
second `1700000000`. The production worker cannot select these sources.

The tiny `.qpf` files exercise **metadata parsing only**. Their three payload
bytes are not cryptographic proofs. Inspection must always return
`verified: false`; real verification fixtures are qualified separately.

`signature-p2pkh` (Bitcoin Signed Message), `signature-p2wpkh` (BIP322) and
`signature-p2pkh-bip322` (explicit BIP322 Full alternative) use the sole v4 PoSC
request and metadata-only proof format. QWC3 options select mode, profile
ID/version and signing kind explicitly. `signature.profiles` is the canonical
library's QSC1 descriptor/default table, not another crypto implementation.
These tiny proofs are never accepted as cryptographic fixtures. Separately
named real native proofs (`signature-p2pkh`, `signature-p2pkh-bip322`,
`signature-p2wpkh`, `signature-mixed`)
are generated into the build's `tests/wasm-real` by
`quietproof-browser-signature-test`; only public requests, proofs and provenance
are retained there. Private native authorisation inputs are temporary and never
served to either browser engine. Existing numbered fixture bytes are preserved.

Regenerate all files from the native core (from the repository):

```sh
cmake --build build-native --target quietproof-browser-codec-test
build-native/quietproof-browser-codec-test tests/wasm/fixtures
```

`tests/wasm/codec_test.cc` defines the exact source options, claims, time and
entropy. Chromium instantiates the real artifact with equivalent test-only host
sources and checks exact byte equality for every request family.
