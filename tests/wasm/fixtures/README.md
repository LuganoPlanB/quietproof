# Native codec golden bytes

These public, synthetic claims use no private key. `0` is v1 P2WPKH with
one distinct program; `1` is v2 P2PKH; `2` is mixed v2. All use one key hash. The `.options` files use the browser's QWC1 options transport;
`.qpr` files are native canonical requests with nonce bytes `07` and creation
second `1700000000`. The production worker cannot select these sources.

The tiny `.qpf` files exercise **metadata parsing only**. Their three payload
bytes are not cryptographic proofs. Inspection must always return
`verified: false`; real verification fixtures are qualified separately.

Regenerate all files from the native core (from the repository):

```sh
cmake --build build-native --target quietproof-browser-codec-test
build-native/quietproof-browser-codec-test tests/wasm/fixtures
```

`tests/wasm/codec_test.cc` defines the exact source options, claims, time and
entropy. Chromium instantiates the real artifact with equivalent test-only host
sources and checks exact byte equality for every request family.
