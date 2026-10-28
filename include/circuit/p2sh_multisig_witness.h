// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_CIRCUIT_P2SH_MULTISIG_WITNESS_H_
#define QUIETPROOF_CIRCUIT_P2SH_MULTISIG_WITNESS_H_

#include "circuit/pokc_witness.h"
#include "ec/p256k1.h"

namespace proofs {
using P2shScript = std::array<uint8_t, 105>;
using P2shKey = std::array<uint8_t, 33>;
using P2shHash = std::array<uint8_t, 20>;
using P2shSecret = std::array<uint8_t, 32>;

inline P2shScript P2shSerialize(const std::array<P2shKey, 3>& keys) {
  P2shScript s{}; s[0] = 0x52;
  for (size_t j = 0; j < 3; ++j) {
    s[1 + 34 * j] = 0x21;
    std::copy(keys[j].begin(), keys[j].end(), s.begin() + 2 + 34 * j);
  }
  s[103] = 0x53; s[104] = 0xae; return s;
}

inline P2shKey P2shPublicKey(const KeyOwnershipWitness<Fp256k1Base, P256k1>& n) {
  P2shKey key{};
  key[0] = 2 + p256k1_base.from_montgomery(n.y).bit(0);
  uint8_t little[32]; p256k1_base.to_bytes_field(little, n.x);
  for (size_t b = 0; b < 32; ++b) key[b + 1] = little[31 - b];
  return key;
}

// Public advice fields deliberately allow adversarial tests to bypass compute.
// Security is provided by P2shMultisigCircuit, not these filling checks.
struct P2shMultisigWitness {
  using Field = Fp256k1Base;
  using Elt = Field::Elt;
  KeyOwnershipWitness<Field, P256k1> ownership;
  struct Point { Elt x, y; std::array<Elt, 256> xb, yb; };
  std::array<Point, 3> points;
  std::array<Elt, 3> selectors;
  FlatSHA256Witness::BlockWitness sha[2];
  P2shHash hash{};

  static bool DecodePoint(const P2shKey& key, Point* out) {
    if (!out || (key[0] != 2 && key[0] != 3)) return false;
    uint8_t little[32];
    for (size_t b = 0; b < 32; ++b) little[b] = key[32 - b];
    auto x = p256k1_base.of_bytes_field(little);
    if (!x) return false;
    const auto& f = p256k1_base;
    const auto rhs = f.addf(f.mulf(f.mulf(*x, *x), *x), f.of_scalar(7));
    // Standard secp256k1 square root exponent (p+1)/4, since p = 3 mod 4.
    const Field::N exponent("0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c");
    auto y = f.one();
    for (size_t bit = 256; bit-- > 0;) {
      y = f.mulf(y, y);
      if (exponent.bit(bit)) y = f.mulf(y, rhs);
    }
    if (f.mulf(y, y) != rhs) return false;
    if (f.from_montgomery(y).bit(0) != (key[0] & 1)) y = f.negf(y);
    out->x = *x; out->y = y;
    const auto xn = f.from_montgomery(*x), yn = f.from_montgomery(y);
    for (size_t b = 0; b < 256; ++b) {
      out->xb[b] = f.of_scalar(xn.bit(255 - b));
      out->yb[b] = f.of_scalar(yn.bit(255 - b));
    }
    return true;
  }

  void HashScript(const P2shScript& script) {
    uint8_t count = 0, padded[128]{};
    FlatSHA256Witness::transform_and_witness_message(105, script.data(), 2,
                                                     count, padded, sha);
    if (count != 2) throw std::logic_error("105-byte script requires two SHA blocks");
    std::array<uint8_t, 32> digest{};
    for (size_t b = 0; b < 32; ++b)
      digest[b] = (sha[1].h1[b / 4] >> (24 - 8 * (b % 4))) & 255;
    hash = Ripemd160::digest(digest);
  }

  bool compute(const P2shSecret& secret, const P2shScript& script, uint8_t position) {
    if (position > 2 || script[0] != 0x52 || script[103] != 0x53 || script[104] != 0xae)
      return false;
    uint8_t little[32];
    for (size_t b = 0; b < 32; ++b) little[b] = secret[31 - b];
    auto scalar = Field::N::of_bytes(little, 256);
    if (scalar == Field::N(0) || !(scalar < n256k1_order)) return false;
    ownership.compute(p256k1, scalar);
    std::array<P2shKey, 3> keys;
    for (size_t j = 0; j < 3; ++j) {
      if (script[1 + 34 * j] != 0x21) return false;
      std::copy_n(script.begin() + 2 + 34 * j, 33, keys[j].begin());
      if (!DecodePoint(keys[j], &points[j])) return false;
      selectors[j] = p256k1_base.of_scalar(j == position);
    }
    if (keys[position] != P2shPublicKey(ownership) || keys[0] == keys[1] ||
        keys[0] == keys[2] || keys[1] == keys[2]) return false;
    HashScript(script); return true;
  }

  template <class Filler> void fill_witness(Filler& f) const {
    f.push_back(ownership.scalar); f.push_back(ownership.scalar_inverse);
    for (size_t b = 0; b < 256; ++b) {
      f.push_back(ownership.scalar_mult.bits[b]);
      if (b < 255) {
        f.push_back(ownership.scalar_mult.int_x[b]);
        f.push_back(ownership.scalar_mult.int_y[b]);
        f.push_back(ownership.scalar_mult.int_z[b]);
      }
    }
    f.push_back(ownership.z_inverse); f.push_back(ownership.x); f.push_back(ownership.y);
    for (const auto& b : ownership.x_bits) f.push_back(b);
    for (const auto& b : ownership.y_bits) f.push_back(b);
    for (const auto& p : points) {
      f.push_back(p.x); f.push_back(p.y);
      for (const auto& b : p.xb) f.push_back(b);
      for (const auto& b : p.yb) f.push_back(b);
    }
    for (const auto& s : selectors) f.push_back(s);
    BitPluckerEncoder<Field, 4> encoder(p256k1_base);
    for (const auto& block : sha) {
      for (auto v : block.outw) for (auto e : encoder.mkpacked_v32(v)) f.push_back(e);
      for (size_t j = 0; j < 64; ++j) {
        for (auto e : encoder.mkpacked_v32(block.oute[j])) f.push_back(e);
        for (auto e : encoder.mkpacked_v32(block.outa[j])) f.push_back(e);
      }
      for (auto v : block.h1) for (auto e : encoder.mkpacked_v32(v)) f.push_back(e);
    }
  }
};
}  // namespace proofs
#endif
