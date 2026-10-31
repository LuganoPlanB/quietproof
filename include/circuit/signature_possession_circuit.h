// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_CIRCUIT_SIGNATURE_POSSESSION_CIRCUIT_H_
#define QUIETPROOF_CIRCUIT_SIGNATURE_POSSESSION_CIRCUIT_H_

#include <array>
#include "circuit/bitcoin_ecdsa.h"
#include "circuit/hash160.h"

namespace proofs {

// Signature knowledge only: no secret scalar or scalar-knowledge circuit.
template <class Logic, class EC>
class SignaturePossessionCircuitV1 {
 public:
  using EltW = typename Logic::EltW;
  using Ecdsa = BitcoinEcdsaCircuit<Logic, EC>;
  using Hash160 = Hash160Circuit<Logic>;
  struct Witness {
    typename Ecdsa::Witness ecdsa;
    typename Hash160::Witness hash160;
    void input(const Logic& logic) {
      ecdsa.input(logic);
      hash160.input(logic);
    }
  };

  SignaturePossessionCircuitV1(const Logic& logic, const EC& ec)
      : logic_(logic), ecdsa_(logic, ec), hash160_(logic) {}

  void verify(const std::array<EltW, 20>& hash,
              const std::array<EltW, 32>& digest, const Witness& witness) const {
    std::array<typename Logic::v8, 20> hash_bits;
    BitPlucker<Logic, 8> bytes(logic_);
    for (size_t i = 0; i < hash.size(); ++i) hash_bits[i] = bytes.pluck(hash[i]);
    // verify() proves Q finite/on-curve, checks canonical raw coordinate bits,
    // and returns those SAME x bits and the constrained Q.y least-significant
    // bit. HASH160 has no independent key, parity, SEC or digest input.
    const auto key = ecdsa_.verify(digest, witness.ecdsa);
    (void)hash160_.assert_hash160(key, witness.hash160, hash_bits);
  }

 private:
  const Logic& logic_;
  Ecdsa ecdsa_;
  Hash160 hash160_;
};
}  // namespace proofs
#endif
