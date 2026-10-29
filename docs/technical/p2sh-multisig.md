---
title: Independent P2SH 2-of-3 circuit
description: Relation, constraints, witness construction, proof API, tests and security limits.
outline: deep
---

# Independent P2SH 2-of-3 circuit

This circuit proves knowledge of one signing scalar at a public position in a
private canonical 2-of-3 redeem script. Two custodians can generate proofs
independently, each using only its own scalar and the common script. An auditor
verifies both proofs against its expected P2SH hash and requires distinct positions.
No private-key sharing, MPC, Co-SNARK or joint witness is required.

The extension is a core-library circuit, witness builder and proof API. Existing
P2WPKH/P2PKH circuits and native formats remain unchanged. The existing CLI,
Bitcoin Core RPC adapter, browser tool and WASM ABI are not extended here.

## Exact relation

Public inputs are a 20-byte hash `h` and position `i`. The private witness is
`(S, x, P0, P1, P2)`, subject to:

```text
1 <= x < n
P0, P1, P2 are valid finite secp256k1 points
P0 != P1, P0 != P2, P1 != P2
S = 52 || 21 || SEC(P0) || 21 || SEC(P1) || 21 || SEC(P2) || 53 || ae
HASH160(S) = RIPEMD160(SHA256(S)) = h
i in {0, 1, 2}
SEC(xG) = SEC(Pi)
```

All displayed script constants are hexadecimal. `G`, `p` and `n` use the
standard secp256k1 parameters from the pinned Longfellow SDK. The circuit
constructs `S` directly from the private points, eliminating a redundant
independently supplied byte array without changing the existential relation.
It has 22 public field inputs: constant one, 20 encoded hash bytes, and `i`.
Coordinates, bit decompositions, selectors and computation traces are private.

## Exact serialization

The 105-byte script is:

```text
OP_2 PUSH33 SEC(P0) PUSH33 SEC(P1) PUSH33 SEC(P2) OP_3 OP_CHECKMULTISIG
```

| Offset | Content |
| --- | --- |
| 0 | `52` (`OP_2`) |
| 1, 35, 69 | `21` (push exactly 33 bytes) |
| 2–34, 36–68, 70–102 | Compressed SEC keys in their original order |
| 103 | `53` (`OP_3`) |
| 104 | `ae` (`OP_CHECKMULTISIG`) |

Each SEC key is prefix `02` for even Y or `03` for odd Y, followed by the
32-byte big-endian X-coordinate. Keys are not sorted. The on-chain P2SH
scriptPubKey is `a9 14 <h:20 bytes> 87`. Other thresholds, nonminimal pushes,
uncompressed keys, duplicate keys, P2WSH and arbitrary scripts are unsupported.

## Circuit enforcement

The complete relation is in `include/circuit/p2sh_multisig.h`:

1. Every script point satisfies `Y^2 = X^3 + 7`. Both coordinate decompositions
   are Boolean, reconstruct their field values, and represent integers strictly
   below `p`. Affine representation excludes infinity; secp256k1's cofactor is one.
2. Three private selectors are individually Boolean and satisfy
   `s0+s1+s2=1` and `i=s1+2*s2`. This enforces both one-hot selection and the
   public position's range. There is no trusted host-side index selection.
3. Reused `KeyOwnershipCircuit` constrains `1 <= x < n`, scalar reconstruction,
   nonzero inversion, complete scalar multiplication, finite normalization and
   canonical SEC encoding. All 33 derived bytes equal the selected script key:
   `SEC(xG)[b] = sum_j sj * SEC(Pj)[b]`.
4. Each key pair must differ in canonical X bits or Y parity. Comparing both
   components enforces compressed-key inequality while permitting distinct
   opposite-parity points with the same X-coordinate.
5. The circuit constructs all script bytes and SHA padding. The fixed padding
   is `80`, 14 zero bytes and the 8-byte length `0000000000000348` (840 bits).
   Two chained `FlatSHA256Circuit` blocks constrain the complete script hash.
   The final constrained SHA state feeds `Ripemd160Fixed32`, and every result
   byte equals the corresponding public hash byte through `BitPlucker`.

`p2sh_multisig_witness.h` supplies native advice, including decompression of
other script keys without knowing their scalars. Native checks give early
errors; every security-critical condition above is independently constrained.
`P2shBuildCircuit` allocates public inputs before `private_input()`, allocates
private advice afterward, and compiles the unified circuit.

## Independent proof API

Include `pokc/p2sh_multisig.h` and link the existing core-only
`LongfellowZKQuietProof::quietproof` target. No RPC or node dependency is needed.

```cpp
proofs::P2shSecret my_secret;  // caller supplies 32 protected big-endian bytes
proofs::P2shScript script;    // caller supplies the common 105-byte script
proofs::P2shMultisigProof mine;
bool proved = proofs::P2shProve(my_secret, script, 0, &mine);
```

Each signer calls `P2shProve` independently with its own scalar and position.
`P2shVerify` checks one proof. For two decoded proofs, the auditor calls:

```cpp
bool sufficient = proofs::P2shVerifyPair(first, second, expected_on_chain_hash);
```

The expected hash is mandatory and must be obtained independently by the
auditor. The pair verifier requires both proofs valid, both hashes equal to
that expected hash, and distinct positions. `EncodeP2shProof` and
`DecodeP2shProof` provide bounded serialization; decoding alone is not verification.

## Proof binding and security limits

Proofs use a separate fixed-parameter `QPM1` format:

```text
"QPM1"[4] || circuit_digest[32] || h[20] || i[1]
          || proof_length[4 big-endian] || proof[proof_length]
```

For example, a payload length of 258 is encoded as `00 00 01 02`.

The format fixes version 1, rate 4 and 128 queries. Circuit identity uses tagged
hash `QuietProof/P2SH-2of3/circuit/v1` over the SDK circuit digest, including its
version/rate/query tuple. The transcript seed uses tagged hash
`QuietProof/P2SH-2of3/proof/v1` over `circuit_digest || h || i`. Verifiers build
the pinned circuit themselves. Parsers reject unknown identity, malformed or
empty lengths, positions outside 0–2, more than 128 MiB of proof, and trailing bytes.

Under proof knowledge soundness and HASH160 binding, two accepted proofs for
the expected hash concern the same script. Distinct positions and the circuit's
key-distinctness constraints then establish knowledge of two different signing
scalars, sufficient for that 2-of-3 script. Relabeling a position changes both a
constrained public input and its transcript binding.

Binding is computational. Alternative scripts for a fixed trusted on-chain
hash require a suitable second preimage; adversarially choosing both scripts
has a generic HASH160 collision bound of at most 80 bits. Security additionally
assumes the SDK proof system, Fiat–Shamir construction, standard secp256k1
assumptions and secure prover randomness. No independent cryptographic audit
has been performed.

Distinct SEC keys do not establish independent generation or people. A holder
of `x` also knows `n-x`, corresponding to `-xG`; such related but distinct keys
are allowed. The one-key attack tests target reusing an unchanged scalar at
other positions of a fixed script. The claim is spending capability, not
custodian identity, exclusive ownership, availability or willingness to sign.

`QPM1` is static and replayable: it has no challenge, expiry, proof timestamp,
nonce consumption, network identifier or current-UTXO policy. These remain
separate application concerns. The public hash and positions are linkable.
Proof privacy cannot hide a script already disclosed elsewhere or on chain.
Witness generation is not guaranteed constant-time, and SDK/allocator/OS copies
may retain secrets; the library does not guarantee complete memory erasure.

## Tests and reproduction

After the repository's normal SDK setup and native CMake build:

```sh
cmake --build build --target p2sh-multisig-test --parallel 2
ctest --test-dir build --output-on-failure -R '^p2sh-multisig-test$'
ctest --test-dir build --output-on-failure -R '^p2sh-multisig-proof-test$'
```

The fast test evaluates the actual compiled circuit with raw mutated witness
vectors, bypassing the native builder. It covers every position, all six
unchanged-scalar/other-position attempts, every duplicate pair, malformed
selectors, invalid public positions, consistently encoded off-curve points,
noncanonical coordinate/scalar aliases, altered scripts, incorrect hashes,
and altered SHA schedules, chaining states, padding and lengths. Valid opposite-
parity points and scalar `n-1` are positive boundary cases.

The proof test generates three independent real proofs, verifies all three
valid pairs, rejects repeated positions and tampered statements/proofs, and
attempts a real low-level second-position proof using only the first scalar.
It also measures the existing one-key PoKC API using a currently valid challenge.
The tests need neither Bitcoin Core nor a JavaScript runtime.

The fixed scalar-1/2/3 serialization vector was independently cross-checked
using bitcoinjs-lib 7.0.1 and Node/OpenSSL. Its expected 105-byte script and
HASH160 `15fc0754e73eb85d1cbce08786fadb7320ecb8dc` are checked directly by the
native test; no extra reference-library dependency is installed.

## Performance

Historical same-machine observations on 2026-10-26, Apple M4 Pro, 48 GiB RAM,
AppleClang 21, C++20 Release `-O3 -DNDEBUG`, SDK
`d2b0fc515f8663e38c79a28e8900ce8438e0106e`, baseline `821ae6d`:

| Relation | Prove API | Verify API | Raw proof | Serialized circuit |
| --- | ---: | ---: | ---: | ---: |
| Original one-key PoKC, one observation | 15.13 s | 9.93 s | 44.71 MiB | 24,876,346 B |
| Independent P2SH signer, mean of three positions | 22.23 s | 18.00 s | 50.60 MiB | 28,312,946 B |

The [recorded CSV](/benchmarks/p2sh-2026-10-26.csv) retains all observations.
Timings include witness preparation, circuit construction, proof machinery and
serialization/parsing; verification's static circuit-identity cache is warm.
The first prover call includes identity construction. Proof sizes vary slightly
with randomness; each envelope adds 61 bytes. These are indicative observations,
not a statistical study or timing requirements.

The circuit has 6,027 private inputs and 2,353,876 quadratic terms. Its CRT block
encoding is 2,359,904, below the 4,194,304 guard. It crosses the convolution's
power-of-two padding threshold, using a 4,194,304-point transform instead of
2,097,152 for the original single-key relation. Two independent proofs require
two verifications and approximately twice the transferred proof bytes.
The proof test writes fresh observations to `build/p2sh-benchmark.csv`.
