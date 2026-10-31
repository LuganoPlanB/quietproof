// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_CIRCUIT_BITCOIN_ECDSA_WITNESS_H_
#define QUIETPROOF_CIRCUIT_BITCOIN_ECDSA_WITNESS_H_

#include "circuit/bitcoin_ecdsa.h"
#include "ec/p256k1.h"

namespace proofs {

// Deliberately total test/prototype advice generation: invalid ranges, keys or
// signatures do not cause an early return. Only circuit assertions decide
// acceptance. Raw integer bits survive the reductions used by native math.
inline BitcoinEcdsaAdvice<Fp256k1Base::Elt> BitcoinEcdsaMakeAdvice(
    const Fp256k1Nat& z, const Fp256k1Nat& qx, const Fp256k1Nat& qy,
    const Fp256k1Nat& r, const Fp256k1Nat& s) {
  using Advice = BitcoinEcdsaAdvice<Fp256k1Base::Elt>;
  using Point = P256k1::ECPoint;
  const auto& f = p256k1_base;
  const auto& sf = p256k1_scalar;
  Advice w;
  w.values.fill(f.zero());
  const Fp256k1Nat integers[] = {qx, qy, r, s};
  for (size_t j = 0; j < 4; ++j)
    for (size_t i = 0; i < 256; ++i) w[256 * j + i] = f.of_scalar(integers[j].bit(255 - i));
  auto reduce = [](Fp256k1Nat x, const Fp256k1Nat& modulus) {
    if (!(x < modulus)) x.sub(modulus);
    return x;
  };
  const Fp256k1Nat prime("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
  const Fp256k1Nat e = reduce(z, n256k1_order);
  const auto ss = sf.to_montgomery(reduce(s, n256k1_order));
  const auto inverse = ss == sf.zero() ? sf.zero() : sf.invertf(ss);
  const auto u = sf.from_montgomery(sf.mulf(sf.to_montgomery(e), inverse));
  const auto v = sf.from_montgomery(sf.mulf(sf.to_montgomery(reduce(r, n256k1_order)), inverse));
  const Point q(f.to_montgomery(reduce(qx, prime)), f.to_montgomery(reduce(qy, prime)), f.one());
  Point nonce = p256k1.addEf(p256k1.scalar_multf(p256k1.generator(), u), p256k1.scalar_multf(q, v));
  p256k1.normalize(nonce);
  // An infinite computed R receives an invalid affine placeholder; this reaches
  // the same circuit as every other tuple and fails there, never in this filler.
  w[Advice::kRx] = nonce.z == f.zero() ? f.zero() : nonce.x;
  w[Advice::kRy] = nonce.z == f.zero() ? f.zero() : nonce.y;
  w[Advice::kBranch] = f.of_scalar(!(f.from_montgomery(w[Advice::kRx]) < n256k1_order));
  const Point negative_r(w[Advice::kRx], f.negf(w[Advice::kRy]), f.one());
  std::array<Point, 8> table;
  table[0] = p256k1.zero();
  table[1] = p256k1.generator();
  table[2] = q;
  table[4] = negative_r;
  table[3] = p256k1.addEf(table[1], table[2]);
  table[5] = p256k1.addEf(table[1], table[4]);
  table[6] = p256k1.addEf(table[2], table[4]);
  table[7] = p256k1.addEf(table[3], table[4]);
  auto store = [&](size_t offset, const Point& point) {
    w[offset] = point.x; w[offset + 1] = point.y; w[offset + 2] = point.z;
  };
  const size_t indices[] = {3, 5, 6, 7};
  for (size_t i = 0; i < 4; ++i) store(Advice::kPre + 3 * i, table[indices[i]]);
  Point accumulator = table[0];
  for (size_t i = 0; i < 256; ++i) {
    const size_t bit = 255 - i;
    const size_t index = e.bit(bit) + 2 * r.bit(bit) + 4 * s.bit(bit);
    p256k1.doubleE(accumulator);
    p256k1.addE(accumulator, table[index]);
    if (i < 255) store(Advice::kTrace + 3 * i, accumulator);
  }
  w[Advice::kFinalYInverse] = accumulator.y == f.zero() ? f.zero() : f.invertf(accumulator.y);
  return w;
}
}  // namespace proofs
#endif
