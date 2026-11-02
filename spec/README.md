# Independent Sage reference models

QuietProof has two mathematical reference models: PoKC for knowledge of a key
scalar, and **PoSC (Proof of Signature Custody)** for knowledge of a valid
request-bound signature. Custody is transferable: a wallet owner can delegate
the signature without exporting the key. Neither name implies exclusive control.

## PoSC: signature custody

`posc_reference.sage` models the optional
[signature-possession v1 relation](quietproof-signature-v1.md). Its public
inputs are the exact 32-byte digest `z` and 20-byte hash `h`; its private
mathematical witness is `(Q, r, s)`. A signing scalar is not an input to the
relation. The model requires:

- a finite secp256k1 point `Q` with canonical integer coordinates before
  coercion into Sage's `GF(p)`;
- `1 <= r < n` and `1 <= s <= floor(n/2)` (low-S);
- `R = s^-1 ((z mod n)G + rQ)` finite, with `x(R) mod n = r`;
- the equivalent group equation `(z mod n)G + rQ - sR = infinity`; and
- `RIPEMD160(SHA256(SEC_compressed(Q))) = h`, including Q's actual parity.

The reference includes `z=0`, `z=n`, `z=p`, the largest 256-bit digest,
both public-key parities, cancellation/infinity, coordinate/scalar aliases,
high-S rejection and the rare `x(R)=r+n` branch. The rare branch is constructed
algebraically, without a nonce search. Additional cases change every public
digest/hash byte. All fixture signatures, scalars and nonces are **public test
data**, never wallet funds.

Sage supplies the curve arithmetic independently of the C++ gadgets and the
Python ECDSA generator. Prime-order/group anchors and a Hasse-bound check
establish cofactor one. The reference shares only the older Sage model's local
SHA-256/RIPEMD-160 compression implementations; it imports no production
signature code or witness builder. It also independently derives the frozen
P2PKH/P2WPKH canonical request, statement digest, application message, virtual
transactions, sighash preimage and public `z`, then checks that changing request
fields invalidates the original signature. Request derivation is outside the
arithmetic circuit; it is not general Bitcoin Script/BIP-322 verification.

From the project root, check the committed deterministic vectors:

```sh
python3 scripts/run_posc_sage.py
```

The runner uses SageMath 10.6 (`POSC_SAGE_BIN` can select it explicitly), or the
same digest-pinned official `linux/amd64` container as PoKC. The container has no
network, a read-only repository/root filesystem, and a bounded temporary mount.
To inspect fresh vectors without overwriting a fixture:

```sh
python3 scripts/run_posc_sage.py --emit > /tmp/posc-sage-vectors.json
```

The signature-enabled native suite consumes the committed Sage vectors without
requiring Sage at runtime.

The initial corpus has 134 Sage/Python mathematical cases: 131 have exact C++
inputs (43 accepted, 88 constraint-rejected); three infinite/257-bit affine
cases remain explicitly outside that input representation. Two signing
profiles each have five request-binding changes. The always-enabled
`posc-reference-contract-test` also rejects corrupted fixture decisions,
arithmetic metadata, missing cases and incorrect input classifications.

```sh
ctest --test-dir build -R '^quietproof-posc-sage-vector-test$' --output-on-failure
```

This gate independently checks the vectors with Python integer arithmetic and
feeds every representable tuple into the actual composed C++ constraint
evaluator, bypassing native signature preverification. Infinite keys and
257-bit affine aliases are accounted as mathematical cases without exact
circuit input representations; they are not counted as circuit rejections.
The `PoKC and PoSC Sage references` GitHub Actions job runs both models from
fresh Sage calculations, requires byte-for-byte equality with their committed
fixtures, and runs both C++ fixture consumers. PoSC also compares every row
with the independent Python integer oracle. Both fresh JSON corpora and C++
results are retained together as the `quietproof-sage-vectors` artifact.

To add fresh Sage execution to a local CTest run, configure
`-DQUIETPROOF_ENABLE_POSC_SAGE_TEST=ON`; then run
`ctest --test-dir build -R '^posc-sage-reference-test$' --output-on-failure`.

This model provides independent differential evidence. It is not a formal
proof of circuit completeness, Longfellow soundness, witness-wire constraints,
parser correctness, wallet safety, replay/chain-state policy or resource limits.
The original integrated malicious fresh-proof/advice qualification remains
waived and unexecuted; these mathematical/assertion tests do not fill that gap.
PoSC names the mathematical relation and its reference model. The existing wire
mode, profile, circuit identity and CLI spelling remain `signature-possession`.

## PoKC: key control

`pokc_reference.sage` is an executable mathematical oracle for PoKC v1. It is
intentionally independent of the production C++ circuit and is not
linked into any release binary.

## What it checks

The model uses Sage's `GF(p)` and elliptic-curve implementation to check:

- primality of the secp256k1 base-field modulus `p` and subgroup order `n`;
- generator membership, `nG = infinity`, and `(n - 1)G = -G`;
- the canonical scalar interval `1 <= x < n`;
- compressed SEC creation, decompression, parity, curve membership, and
  canonical x-coordinate bounds;
- fixed 33-byte SEC SHA-256 and HASH160 results;
- SHA-256 and RIPEMD-160 padding and byte order using local compression
  implementations rather than OpenSSL or `hashlib`;
- canonical QuietProof statement encoding and tagged hashing; and
- transcript binding to the statement digest, circuit digest, circuit version,
  Ligero rate, and query count.

It generates positive scalar vectors for `1`, `2`, `3`, leading-zero edge
cases `153` and `382`, and `n - 1`. Negative data covers `-1`, `0`, `n`,
`n + 1`, unsupported SEC prefixes, `x = p`, and a non-curve compressed SEC.

## Reproducible execution

From the QuietProof project root:

```sh
cmake -S . -B build -DQUIETPROOF_ENABLE_POKC_SAGE_TEST=ON
ctest --test-dir build -R pokc-sage-reference-test --output-on-failure
```

If Sage 10.6 is installed, the runner uses the local `sage` executable. Set
`POKC_SAGE_BIN` to an explicit Sage 10.6 path when required. Other local
versions are not used; the runner instead selects the official SageMath 10.6
container pinned by OCI digest. The container runs with no network, a
read-only root filesystem and repository mount, and a bounded temporary
filesystem. Its image is pinned for `linux/amd64`; non-amd64 hosts need Docker
architecture emulation or a native Sage 10.6 installation.

The gate requires exact equality with
`tests/quietproof/testdata/pokc_sage_vectors.json` and compares all shared
curve, statement, and HASH160 values with the independently generated
`pokc_vectors.json` fixture.

The normal C++ production gate then loads `pokc_sage_vectors.json`
directly. For every valid vector it compares scalar multiplication, affine
coordinates, parity, compressed SEC, SHA-256, HASH160, scriptPubKey, complete
native witness construction, and full circuit evaluation. It also consumes
the invalid-scalar list and the statement/transcript example. Therefore CI
enforces the complete chain:

```text
fresh Sage computation == Sage fixture == C++ native and circuit results
                              |
                              +== shared independent Python fixture
```

To inspect a freshly generated corpus with an installed Sage:

```sh
sage -python spec/pokc_reference.sage --emit
```

The version-pinned runner also supports the same emission mode as PoSC:

```sh
bash scripts/run_pokc_sage.sh --emit > /tmp/pokc-sage-vectors.json
```

Fixture updates must be reviewed as cryptographic changes. Do not overwrite a
fixture merely to make a changed model pass; inspect the semantic difference,
compare it with an external Bitcoin implementation, and run the C++ circuit
mutation and real-proof gates.

## Assurance boundary

Agreement between Sage, Python, and C++ provides strong differential evidence
for the intended mathematical relation. It does not prove that the arithmetic
circuit contains every intended constraint. In particular, this model cannot
detect an unconstrained C++ witness wire when valid native calculations still
produce the expected output, nor can it prove Longfellow soundness, parser/RPC
safety, replay-store correctness, or Bitcoin chain state.

Keep the Sage oracle alongside:

1. C++ positive and adversarial witness mutation tests;
2. deterministic circuit serialization and identity checks;
3. sanitizer and static-analysis gates;
4. real single-key proofs and second-key rejection; and
5. independent cryptographic, circuit, protocol, and operational review.
