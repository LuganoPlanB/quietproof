// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_CIRCUIT_BITCOIN_ECDSA_H_
#define QUIETPROOF_CIRCUIT_BITCOIN_ECDSA_H_

#include <array>
#include <cstddef>
#include "circuits/logic/bit_plucker.h"
#include "circuits/secp256k1/ec_gadget.h"
#include "circuits/secp256k1/encoding.h"

namespace proofs {

// One allocation order for circuit inputs and native advice. Q/r/s are raw
// 256-bit integers, not field-reduced inputs. Bits are MSB first.
template <class Value>
struct BitcoinEcdsaAdvice {
  static constexpr size_t kSize = 1805;
  static constexpr size_t kQx = 0, kQy = 256, kR = 512, kS = 768;
  static constexpr size_t kRx = 1024, kRy = 1025, kBranch = 1026;
  static constexpr size_t kPre = 1027, kTrace = 1039, kFinalYInverse = 1804;
  std::array<Value, kSize> values;
  Value& operator[](size_t i) { return values[i]; }
  const Value& operator[](size_t i) const { return values[i]; }
  template <class Logic> void input(const Logic& lc) {
    for (auto& value : values) value = lc.eltw_input();
  }
};

// Bitcoin's complete low-S ECDSA relation, using eG+rQ-sR=O. This is independent
// of the SDK's optional ECDSA verifier and does not inherit its affine table or
// rx=r/e!=0 assumptions. Only complete point formulas come from the base SDK.
template <class Logic, class EC>
class BitcoinEcdsaCircuit {
 public:
  using EltW = typename Logic::EltW;
  using BitW = typename Logic::BitW;
  using Bits = typename Logic::v256;
  using Nat = typename EC::N;
  using Gadget = Secp256k1EcGadget<Logic, EC>;
  using Point = typename Gadget::ProjectivePointW;
  using Encoding = Secp256k1Encoding<Logic, EC>;
  using Witness = BitcoinEcdsaAdvice<EltW>;

  BitcoinEcdsaCircuit(const Logic& lc, const EC& ec) : lc_(lc), ec_(ec), gadget_(lc, ec) {}

  typename Encoding::CompressedKey verify(const std::array<EltW, 32>& digest,
                                          const Witness& w) const {
    const auto zero = lc_.konst(lc_.zero()), one = lc_.konst(lc_.one());
    // Public z bytes are range-checked by the plucker. v256 is LSB first.
    Bits z;
    BitPlucker<Logic, 8> plucker(lc_);
    for (size_t byte = 0; byte < 32; ++byte) {
      const auto bits = plucker.pluck(digest[byte]);
      for (size_t bit = 0; bit < 8; ++bit) z[8 * (31 - byte) + bit] = bits[bit];
    }
    const Nat n("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    const Nat p("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
    const Bits order = constant_bits(n);
    // z<2^256<2n. Adding 2^256-n gives z-n modulo 2^256; the comparison
    // chooses it exactly when z>=n. This never reconstructs z in Fp.
    Nat negative_n(0); negative_n.sub(n);  // unsigned 256-bit subtraction
    const Bits minus_order = constant_bits(negative_n);
    const Bits difference = lc_.vadd(z, minus_order);
    Bits e;
    lc_.vmux(lc_.vlt(z, order), e, z, difference);

    const Bits r = raw_bits(w, Witness::kR), s = raw_bits(w, Witness::kS);
    lc_.assert1(lc_.vlt(r, order));
    lc_.assert1(lc_.vlt(constant_bits(Nat(0)), r));
    lc_.assert1(lc_.vlt(constant_bits(Nat(0)), s));
    Nat low_s_bound = n; low_s_bound.shiftr(1); low_s_bound.add(Nat(1));
    lc_.assert1(lc_.vlt(s, constant_bits(low_s_bound)));

    typename Encoding::CoordinateWitness qx_bits, qy_bits;
    for (size_t i = 0; i < 256; ++i) {
      qx_bits.bits[i] = w[Witness::kQx + i];
      qy_bits.bits[i] = w[Witness::kQy + i];
    }
    const EltW qx = reconstruct(w, Witness::kQx), qy = reconstruct(w, Witness::kQy);
    Encoding encoding(lc_);
    encoding.assert_canonical(qx, qx_bits);
    encoding.assert_canonical(qy, qy_bits);
    gadget_.assert_point_on_curve(qx, qy);  // affine z=1 proves Q finite
    const EltW rx = w[Witness::kRx], ry = w[Witness::kRy];
    gadget_.assert_point_on_curve(rx, ry);  // R is also finite affine
    const BitW branch(w[Witness::kBranch], lc_.f_);
    lc_.assert_is_bit(branch);
    // If rx=r+n, require r<p-n before equality in Fp. This prevents p wrap.
    Nat p_minus_n = p; p_minus_n.sub(n);
    lc_.assert_implies(branch, lc_.vlt(r, constant_bits(p_minus_n)));
    lc_.assert_eq(rx, lc_.add(reconstruct(w, Witness::kR),
        lc_.lmul(branch, lc_.konst(lc_.f_.to_montgomery(n)))));

    std::array<Point, 8> table;
    table[0] = {zero, one, zero};
    table[1] = {lc_.konst(ec_.gx_), lc_.konst(ec_.gy_), one};
    table[2] = {qx, qy, one};
    table[4] = {rx, lc_.sub(zero, ry), one};
    const size_t indices[] = {3, 5, 6, 7};
    const size_t left[] = {1, 1, 2, 3};
    const size_t right[] = {2, 4, 4, 4};
    for (size_t i = 0; i < 4; ++i) {
      Point computed;
      gadget_.addE(computed, table[left[i]], table[right[i]]);
      table[indices[i]] = advice_point(w, Witness::kPre + 3 * i);
      assert_exact(computed, table[indices[i]]);
    }
    Point accumulator = table[0];
    for (size_t i = 0; i < 256; ++i) {
      const size_t bit = 255 - i;
      std::array<Point, 4> pairs;
      for (size_t j = 0; j < 4; ++j) pairs[j] = select(e[bit], table[2 * j + 1], table[2 * j]);
      const Point selected = select(s[bit], select(r[bit], pairs[3], pairs[2]),
                                    select(r[bit], pairs[1], pairs[0]));
      gadget_.doubleE(accumulator, accumulator);
      gadget_.addE(accumulator, accumulator, selected);
      if (i < 255) {
        const Point next = advice_point(w, Witness::kTrace + 3 * i);
        assert_exact(accumulator, next);
        accumulator = next;
      }
    }
    lc_.assert0(accumulator.x);
    lc_.assert0(accumulator.z);
    // Exclude the invalid (0,0,0) tuple explicitly at the identity boundary.
    lc_.assert_eq(lc_.mul(accumulator.y, w[Witness::kFinalYInverse]), one);
    return encoding.compressed(qx_bits, qy_bits);
  }

 private:
  Bits constant_bits(const Nat& value) const {
    Bits result;
    for (size_t i = 0; i < 256; ++i) result[i] = lc_.bit(value.bit(i));
    return result;
  }
  Bits raw_bits(const Witness& w, size_t offset) const {
    Bits result;
    for (size_t i = 0; i < 256; ++i) {
      result[255 - i] = BitW(w[offset + i], lc_.f_);
      lc_.assert_is_bit(result[255 - i]);
    }
    return result;
  }
  EltW reconstruct(const Witness& w, size_t offset) const {
    auto result = lc_.konst(lc_.zero());
    for (size_t i = 0; i < 256; ++i) result = lc_.add(lc_.add(result, result), w[offset + i]);
    return result;
  }
  Point advice_point(const Witness& w, size_t offset) const {
    return {w[offset], w[offset + 1], w[offset + 2]};
  }
  void assert_exact(const Point& computed, const Point& advice) const {
    lc_.assert_eq(computed.x, advice.x);
    lc_.assert_eq(computed.y, advice.y);
    lc_.assert_eq(computed.z, advice.z);
  }
  Point select(const BitW& bit, const Point& yes, const Point& no) const {
    return {lc_.mux(bit, yes.x, no.x), lc_.mux(bit, yes.y, no.y), lc_.mux(bit, yes.z, no.z)};
  }
  const Logic& lc_;
  const EC& ec_;
  Gadget gadget_;
};
}  // namespace proofs
#endif
