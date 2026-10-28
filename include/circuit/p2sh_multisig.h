// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_CIRCUIT_P2SH_MULTISIG_H_
#define QUIETPROOF_CIRCUIT_P2SH_MULTISIG_H_

#include "circuit/key_ownership.h"
#include "circuits/logic/bit_plucker.h"
#include "circuits/ripemd160/ripemd160_fixed.h"
#include "circuits/sha/flatsha256_circuit.h"

namespace proofs {

// One custodian, one scalar multiplication, one fixed 2-of-3 script.
// Nothing here depends on native witness validation or a native selector.
template <class Logic, class Field, class EC>
class P2shMultisigCircuit {
 public:
  using EltW = typename Logic::EltW;
  using BitW = typename Logic::BitW;
  using v8 = typename Logic::v8;
  using Encoding = Secp256k1Encoding<Logic, EC>;
  using Ownership = KeyOwnershipCircuit<Logic, Field, EC>;
  using Flat = FlatSHA256Circuit<Logic, BitPlucker<Logic, 4>>;
  struct PointWitness {
    EltW x, y;
    typename Encoding::CoordinateWitness xb, yb;
    void input(const Logic& l) {
      x = l.eltw_input(); y = l.eltw_input(); xb.input(l); yb.input(l);
    }
  };
  struct Witness {
    typename Ownership::Witness ownership;
    std::array<PointWitness, 3> points;
    std::array<EltW, 3> selectors;
    typename Flat::BlockWitness sha[2];
    void input(const Logic& l) {
      ownership.input(l);
      for (auto& p : points) p.input(l);
      for (auto& s : selectors) s = l.eltw_input();
      for (auto& b : sha) b.input(l);
    }
  };

  P2shMultisigCircuit(const Logic& l, const EC& ec) : l_(l), ec_(ec) {}

  void assert_relation(const std::array<EltW, 20>& hash, EltW position,
                       const Witness& w) const {
    Encoding encoding(l_);
    Secp256k1EcGadget<Logic, EC> curve(l_, ec_);
    std::array<typename Encoding::CompressedKey, 3> keys;
    for (size_t j = 0; j < 3; ++j) {
      // Finite affine points on cofactor-one secp256k1, with canonical SEC.
      curve.assert_point_on_curve(w.points[j].x, w.points[j].y);
      encoding.assert_canonical(w.points[j].x, w.points[j].xb);
      encoding.assert_canonical(w.points[j].y, w.points[j].yb);
      keys[j] = encoding.compressed(w.points[j].xb, w.points[j].yb);
    }
    auto sum = l_.konst(0), selected_position = l_.konst(0);
    for (size_t j = 0; j < 3; ++j) {
      l_.assert_is_bit(BitW(w.selectors[j], l_.f_));
      sum = l_.add(sum, w.selectors[j]);
      selected_position = l_.add(selected_position,
                                l_.mul(l_.konst(j), w.selectors[j]));
    }
    l_.assert_eq(sum, l_.konst(1));
    l_.assert_eq(position, selected_position);  // also proves position in 0..2
    const auto derived = Ownership(l_, ec_).derive(w.ownership);
    for (size_t b = 0; b < 33; ++b) {
      auto selected = l_.konst(0);
      for (size_t j = 0; j < 3; ++j)
        selected = l_.add(selected, l_.mul(w.selectors[j], keys[j].bytes[b]));
      l_.assert_eq(derived.bytes[b], selected);
    }
    for (size_t a = 0; a < 3; ++a) for (size_t b = a + 1; b < 3; ++b) {
      typename Logic::v256 ax, bx;
      for (size_t bit = 0; bit < 256; ++bit) {
        ax[bit] = BitW(keys[a].x_bits[bit], l_.f_);
        bx[bit] = BitW(keys[b].x_bits[bit], l_.f_);
      }
      const auto same_parity = l_.lnot(l_.lxor(BitW(keys[a].parity, l_.f_),
                                              BitW(keys[b].parity, l_.f_)));
      l_.assert0(l_.land(l_.veq(ax, bx), same_parity));
    }

    // OP_2 PUSH33 SEC(P0) PUSH33 SEC(P1) PUSH33 SEC(P2) OP_3 OP_CHECKMULTISIG
    // 105 bytes, followed by SHA padding to 128 bytes; bit length = 840.
    std::array<v8, 128> message;
    for (auto& byte : message) byte = l_.template vbit<8>(0);
    message[0] = l_.template vbit<8>(0x52);
    for (size_t j = 0; j < 3; ++j) {
      const size_t offset = 1 + 34 * j;
      message[offset] = l_.template vbit<8>(0x21);
      message[offset + 1][0] = BitW(keys[j].parity, l_.f_);
      message[offset + 1][1] = l_.bit(1);
      for (size_t byte = 0; byte < 32; ++byte)
        for (size_t bit = 0; bit < 8; ++bit)
          message[offset + 2 + byte][bit] =
              BitW(keys[j].x_bits[8 * byte + 7 - bit], l_.f_);
    }
    message[103] = l_.template vbit<8>(0x53);
    message[104] = l_.template vbit<8>(0xae);
    message[105] = l_.template vbit<8>(0x80);
    message[126] = l_.template vbit<8>(3);
    message[127] = l_.template vbit<8>(0x48);
    Flat sha(l_);
    sha.assert_message(2, l_.template vbit<8>(2), message.data(), w.sha);
    typename Logic::v256 digest;
    for (size_t word = 0; word < 8; ++word) {
      const auto bits = sha.bp_.unpack_v32(w.sha[1].h1[word]);
      for (size_t bit = 0; bit < 32; ++bit) digest[(7 - word) * 32 + bit] = bits[bit];
    }
    const auto result = Ripemd160Fixed32<Logic>(l_).derive(digest);
    BitPlucker<Logic, 8> bytes(l_);
    for (size_t j = 0; j < 20; ++j) l_.vassert_eq(result[j], bytes.pluck(hash[j]));
  }
 private:
  const Logic& l_;
  const EC& ec_;
};
}  // namespace proofs
#endif
