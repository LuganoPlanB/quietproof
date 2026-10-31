// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_CIRCUIT_SIGNATURE_POSSESSION_WITNESS_H_
#define QUIETPROOF_CIRCUIT_SIGNATURE_POSSESSION_WITNESS_H_

#include "circuit/bitcoin_ecdsa_witness.h"
#include "circuit/compressed_key_sha256_witness.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/ripemd160/ripemd160.h"

namespace proofs {

// Advice construction has no cryptographic prevalidation: malformed raw tuples
// still reach constraints. Production receipt checks are an additional boundary.
// Mutable advice also permits attacks after honest construction in tests.
struct SignaturePossessionWitnessV1 {
  BitcoinEcdsaAdvice<Fp256k1Base::Elt> ecdsa{};
  CompressedKeySha256Witness sha{};

  void compute(const Fp256k1Nat& digest, const Fp256k1Nat& qx,
               const Fp256k1Nat& qy, const Fp256k1Nat& r, const Fp256k1Nat& s) {
    ecdsa = BitcoinEcdsaMakeAdvice(digest, qx, qy, r, s);
    std::array<uint8_t, 33> sec{};
    sec[0] = 2 + qy.bit(0);
    for (size_t byte = 0; byte < 32; ++byte)
      for (size_t bit = 0; bit < 8; ++bit)
        sec[byte + 1] = static_cast<uint8_t>((sec[byte + 1] << 1) |
                                            qx.bit(255 - 8 * byte - bit));
    sha.compute(sec);
  }

  std::array<uint8_t, 20> hash160() const { return Ripemd160::digest(sha.digest); }

  template <class Filler>
  void fill_witness(Filler& filler) const {
    for (const auto& value : ecdsa.values) filler.push_back(value);
    BitPluckerEncoder<Fp256k1Base, 4> encoder(p256k1_base);
    for (const auto word : sha.block.outw)
      for (const auto& value : encoder.mkpacked_v32(word)) filler.push_back(value);
    for (size_t i = 0; i < 64; ++i) {
      for (const auto& value : encoder.mkpacked_v32(sha.block.oute[i])) filler.push_back(value);
      for (const auto& value : encoder.mkpacked_v32(sha.block.outa[i])) filler.push_back(value);
    }
    for (const auto word : sha.block.h1)
      for (const auto& value : encoder.mkpacked_v32(word)) filler.push_back(value);
  }
};
}  // namespace proofs
#endif
