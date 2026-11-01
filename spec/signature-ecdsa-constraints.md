# Bitcoin ECDSA constraint qualification

This document describes the local ECDSA relation and its retained L3 prototype
evidence. Production HASH160 composition, request codecs, packages and browser
verification are implemented separately; see the signature profile and measured
resource record. Native witness generation is not part of the soundness argument.
The original L5.3 integrated malicious fresh-proof/advice attacks remain
user-waived, unexecuted and unqualified; L3 tests do not fill that coverage gap.

## Reuse decision and domains

Use the base SDK's `Secp256k1EcGadget` complete projective `addE`/`doubleE`
formulas and `Secp256k1Encoding` canonical coordinate constraints. The inspected
SDK is `longfellow-zk-dyne` at
`d2b0fc515f8663e38c79a28e8900ce8438e0106e`, particularly
`src/circuits/secp256k1/{ec_gadget,encoding}.h` and
`src/ec/elliptic_curve.h`. No SDK source or pin changes are needed, and no
`LongfellowZKECDSA` package is used.

The optional SDK `projects/ecdsa/include/circuits/ecdsa/verify_{circuit,evaluate}.h`
uses `rx=r`, documents an `e!=0` precondition, and stores affine precomputation
without an infinity flag. Its P-256 module tests characterize that historical
relation. Those tests and that relation do not qualify Bitcoin's full domain.

The local implementation fixes secp256k1's coordinate prime `p`, group order
`n`, generator and cofactor-one prime-order group. Its complete formulas are the
Renes–Costello–Batina formulas already used by the base SDK: projective
coordinates mean `x=X/Z, y=Y/Z`. Their completeness assumes valid nonzero
projective representatives on this prime-order curve. Input curve assertions,
exact arithmetic bindings and the induction below establish those prerequisites;
testing exceptional points alone would not establish universal completeness.

Only the primary hexadecimal `p` and `n` are constants in the local relation.
`2^256-n`, `floor(n/2)+1` and `p-n` are derived using integer operations at circuit
construction time. In particular:

```
p-n = 0x14551231950b75fc4402da1722fc9baee
```

## Public inputs and private advice

Input zero is Longfellow's mandatory constant one. Inputs 1–32 are the exact
big-endian digest bytes encoded with `BitPluckerEncoder<Field,8>`; the circuit
plucker constrains their eight-bit domain. The prototype has 33 public inputs.
`h[20]` belongs to the separate production composed relation. `verify()` returns the constrained
compressed Q representation for that composition; it exposes no secret scalar.

The 1,805 private inputs use the following single shared allocation layout.
Offsets below are relative to the first private input (absolute input 33).

| Offset(s) | Meaning | Constraint and binding |
| --- | --- | --- |
| 0–255 | Q.x raw bits, MSB first | Each bit Boolean; integer `<p`; reconstruct x in Fp; input to the Q curve equation, table and returned SEC representation |
| 256–511 | Q.y raw bits, MSB first | Each bit Boolean; integer `<p`; reconstruct y; same Q bindings; bit 511 supplies SEC parity |
| 512–767 | r raw bits | Each bit Boolean; `0<r<n`; reconstruct r; bind nonce x and every r scalar-multiplication choice |
| 768–1023 | s raw bits | Each bit Boolean; `0<s<floor(n/2)+1`; bind every s scalar-multiplication choice |
| 1024–1025 | R.x, R.y field elements | Affine curve equation, hence finite R with z=1; x bound to r and branch; negative R enters the table |
| 1026 | x branch | Boolean b; `R.x=r+b*n` in Fp; `b=1 => r<p-n` excludes base-field wrap |
| 1027–1038 | Four projective precomputations | Exact X, Y, Z equality to complete additions: G+Q, G−R, Q−R, G+Q−R; infinity retains its projective representation |
| 1039–1803 | 255 projective trace points | Each triple equals the complete doubling/addition result **coordinate by coordinate**, without cross multiplication or normalization |
| 1804 | Inverse of final Y | Final `X=Z=0` and `Y*inverse=1`; excludes `(0,0,0)` |

There is no unconstrained e, packed scalar selector, inverse-s, normalized table,
point parity or final point advice. R is internal field advice, not a serialized
integer or externally provided SEC key: it needs no separate byte encoding.
Field elements represent residues; raw Q/r/s integers enter through their bits,
before any reduction. This distinction is essential to p/n-alias tests.

## Relation and soundness argument

1. Pluck the digest bytes directly into 256 Boolean bits. Compare z with n.
   Compute `z+(2^256-n) mod 2^256` through the bit adder and select it exactly
   when `z>=n`. Since `z<2^256<2n`, the selected bits encode `e=z mod n`.
   z is never first reconstructed in Fp, so z=p does not become zero.
2. Check all Q/r/s ranges on their raw bits. Reconstruct Q only after enforcing
   unique canonical coordinates. `y²=x³+7`, with affine z=1, makes Q finite and
   on-curve. secp256k1 has cofactor one, so these points are in its order-n group.
3. Constrain finite affine R on the same curve. `0<r<n<p`, the branch bit and
   the `r<p-n` guard make the field x equality an integer equality: either
   `x(R)=r`, or `x(R)=r+n<p`. A wrapped `r+n` cannot pass.
4. Build the complete projective table for G, Q and −R, including actual
   infinity entries. Exactly constrain each supplied table triple to its
   computed triple. There is no affine equality that could become vacuous when
   Z=0. Nonzero validity follows from the base points and complete formulas.
5. Begin with `(0,1,0)`. For each of the 256 scalar-bit positions, select the
   table entry using Boolean e/r/s bits, double the accumulator, and add the
   selected point using complete formulas. Exactly constrain all three trace
   coordinates before using them as the next accumulator. Induction preserves
   a valid nonzero projective point; replacing a table/trace point by the zero
   triple violates its exact arithmetic binding even when its honest value is
   infinity. Q=G/−G, equal addends, cancellation and e=0 need no exception path.
6. Require the final nonzero point to be infinity. Thus `eG+rQ−sR=O`.
   Because `0<s<n` and n is prime, this is equivalent to
   `R=s^-1(eG+rQ)`. R is finite and its x reduction is r, exactly the frozen
   ECDSA relation, with low-S additionally enforced.

`BitcoinEcdsaMakeAdvice` always produces advice for representable test tuples,
including invalid keys, ranges and signatures. A computed infinite R gets an
invalid affine placeholder and still reaches the circuit. It never returns an
ECDSA-validity result. Constraint tests run `ProverLayers::eval_circuit` on the
compiled circuit and its actual input vector; neither the oracle nor a native
precheck decides their outcome.

## Adversarial coverage and classification

The corpus driver accounts for every `signature-vectors.json` entry. Its 57
exactly representable affine tuples execute against compiled constraints.
Q=infinity and the two 257-bit coordinate aliases have no exact finite-affine
256-bit input representation. The 15 malformed digest/SEC/DER objects likewise
belong to the serialization boundary; none counts as a constraint rejection.

Five added constraint cases bring the direct total to 62:

- A valid Q with x=1, z=0, r=s=1, and the invalid raw x=p+1 alias. Both produce
  the same native field point; only the raw canonical-range constraint separates
  them. This tests an alias that actually fits in 256 bits.
- Both rare-branch r=n+k aliases with the branch maliciously changed to zero
  **after** advice generation. The raw x equality and group equation then hold;
  the r<n constraint must reject.
- The constructed wrapped-r+n tuple with the branch maliciously changed to one
  after generation. Its group equation and field x equality hold; the p−n
  range guard must reject. This regression found and corrected a mistyped
  handwritten p−n constant during development; the final relation derives it.

For a valid Q=G, R=G fixture (including G−R and Q−R infinity table entries), the
advice test mutates each of the 1,805 private inputs after honest generation,
mutates each of the 32 public digest elements, and separately zeroes all four
projective table entries and all 255 projective trace points. All 2,096 attacks
must be constraint-rejected, with an unchanged positive control. Bit mutations
include non-Boolean values; Q/r/s/R/table/trace/final-inverse inputs are all
covered. Corpus positives additionally exercise Q=−G, both R parities, equal
verification addends, e=0, exact low-S edges and both x branches.

## Proof prototype and cost model

The native test creates a real proof, serializes and reads it, verifies it with
the public digest alone, and rejects it against a different well-formed digest.
It uses rate 4 and 128 queries, the existing CRT guard, and an actual serialized
proof cap of 128 MiB. The raw `.proof` artifact is test-only and has no production
QuietProof envelope. No SDK security parameters or old circuit identities change.

The ECDSA-only prototype is approximately 87,000 wires and 156,000 quadratic
terms, with 1,838 total inputs and a 2^18 CRT transform. Observed native proof
size is about 3.48 MB and peak RSS about 164 MB; commitment/proving/verification
take about 1.9/0.28/1.7 seconds on this qualification host. Exact current counts,
timings, artifact hashes and hardware are retained with the milestone evidence.

The SDK's `ZkProof::size()` is smaller than the actual serialization for this
prototype. The test labels it `sdk_size_estimate`; it is **not** an upper bound.
The serialized byte count is checked separately against 128 MiB. This observation
does not authorize a sibling SDK fix or a production cap change.

`--hash-metrics` compiles the existing HASH160 relation separately, without
composing it with ECDSA. Its approximate incremental cost is 1,472 private
inputs and 2,044,254 quadratic terms. The additive estimate, after sharing the
257 Q.x/parity inputs, is roughly 2.20 million encoded columns, 1,953 layers and
a 2^22 CRT transform—the largest supported transform order. This is the historical L3 projection; actual composition is now implemented
and separately pinned/measured. The estimate is not a composed proof identity.

At seven Ligero rows, the projected main commitment matrix is about 494 MB.
Each padded `CRT256` vector uses 9 eight-byte residues per element: about
302 MB at 2^22. The current verifier can retain two convolution kernels while
allocating a working transform, so those three vectors alone are about 906 MB,
before Reed–Solomon arrays, the circuit, proof, and runtime overhead. This is a
concrete memory risk near the unchanged 2 GiB WASM ceiling, not measured browser
success. Linear proof-size scaling suggests about 49 MB before the much deeper
sumcheck transcript; actual composed proof bytes must still meet 128 MiB.
These historical estimates are not browser observations. Actual composed
measurements are documented in `docs/performance.md`, including max16 lifecycle
linear allocation; do not infer RSS from either estimate or linear-memory data.

## Reproduction

Build the native test target against the unchanged installed base SDK:

```
cmake --build BUILD --target quietproof-ecdsa-prototype --parallel 2
ctest --test-dir BUILD --output-on-failure --no-tests=error -V \
  -R '^quietproof-ecdsa-(constraint|advice|prototype-proof)-test$'
BUILD/quietproof-ecdsa-prototype --hash-metrics
```

This is focused L3.2 evidence. Complete BASE/NATIVE package and old-proof gates
remain mandatory at parent acceptance; actual HASH160 composition and WASM
verification have their own retained evidence and are not implied by L3 tests.

## Optional installed component

`QUIETPROOF_BUILD_SIGNATURE_MODE` defaults to `OFF`. Enabling it creates the
header-only build and installed target `LongfellowZKQuietProof::signature` and
installs `circuit/bitcoin_ecdsa.h` and `circuit/bitcoin_ecdsa_witness.h`. These two
headers and the signature export are omitted from a fresh OFF installation.
The compiled relation, advice-attack and prototype-proof tests are enabled only
with this option; independent Python vectors and the separately opted-in Core
oracle qualification do not require it.

Consumers explicitly request the component:

```cmake
find_package(LongfellowZKQuietProof CONFIG REQUIRED COMPONENTS signature)
target_link_libraries(my_application PRIVATE LongfellowZKQuietProof::signature)
```

The signature target links only `LongfellowZKQuietProof::quietproof`, which links
the installed base SDK. The reviewed SDK commit remains
`d2b0fc515f8663e38c79a28e8900ce8438e0106e` in `scripts/build-pins.json` and native
release configuration. No `LongfellowZKECDSA` package is required: the complete
formulas used here are already in that base SDK. The test oracle and its
libsecp256k1 dependency are neither installed nor exported.

Ordinary package lookup loads only the base target, even when RPC and signature
components are both installed. Requesting `rpc` additionally resolves CURL;
requesting `signature` alone does not. Unknown required components, disabled
components and removed optional exports produce configuration errors. Optional
unavailable components retain CMake's standard `OPTIONAL_COMPONENTS` behavior.
Configured capability flags prevent stale export files from enabling an OFF
package. Use distinct installation prefixes for ON and OFF packages: CMake does
not uninstall old header files when reusing an installation prefix.

`tests/cmake/package_test.py --signature-enabled ON --rpc-enabled ON` exercises
four distinct build/install configurations, installed core/RPC/signature and
combined consumers, ordinary omitted-flag defaults, removed/stale exports,
missing base-SDK/CURL dependencies and unknown/unavailable components. Package
registries and optional ECDSA/oracle package discovery are disabled throughout.
Installed signature consumers evaluate a valid tuple and reject a non-bit
private input using the installed headers. Every command has a retained log and
UTC/exit/hash record in the test work directory's `results.json`.

Native musl packaging accepts `--signature-mode` and records
`signatureConstraintsBuilt` in `release.json`. This opts into building and testing
the constraints; the packaged CLI additionally exposes the explicitly selected signature
authorize/prove/verify workflow while preserving scalar/multisig commands. The option is explicitly OFF by default, including when a release work
directory is reused. WASI `scripts/build_wasm.py --signature-mode` and static
`scripts/qualify_static.py --signature-mode` propagate the explicit capability.
Both default OFF. See the native workflow and browser guide for actual CLI
capabilities; native CLI v3 inspect remains unsupported.
