// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_CIRCUIT_SIGNATURE_POSSESSION_H_
#define QUIETPROOF_CIRCUIT_SIGNATURE_POSSESSION_H_

#include <memory>
#include "circuit/signature_possession_circuit.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256k1.h"

namespace proofs {
using SignaturePossessionField = Fp256k1Base;
using SignaturePossessionBackend = CompilerBackend<SignaturePossessionField>;
using SignaturePossessionLogic = Logic<SignaturePossessionField, SignaturePossessionBackend>;

// QuadCircuit reserves input/wire zero for constant ONE in its constructor.
// Do not allocate it again. Public inputs are [one,h[20],z[32]] (53 total),
// in hash/SHA output byte order, encoded by BitPluckerEncoder<Field,8>.
// All private inputs follow private_input(): ECDSA's 1805 raw/advice elements,
// then FlatSHA's 1472 packed four-bit elements (W[48], E/A[64], H1[8]).
// Absolute input offsets (zero based, endpoints inclusive): Qx 53..308,
// Qy 309..564, r 565..820, s 821..1076, Rx/Ry/branch 1077..1079,
// precomputation 1080..1091, multiplication trace 1092..1856, final inverse
// 1857, SHA W 1858..2241, interleaved E/A 2242..3265, H1 3266..3329.
// No private duplicate h/z, scalar d, SEC message or RIPEMD advice is allocated.
inline std::unique_ptr<Circuit<SignaturePossessionField>> SignaturePossessionBuildCircuit(
    QuadCircuit<SignaturePossessionField>* quad) {
  SignaturePossessionBackend backend(quad);
  SignaturePossessionLogic logic(&backend, p256k1_base);
  std::array<SignaturePossessionLogic::EltW, 20> hash;
  std::array<SignaturePossessionLogic::EltW, 32> digest;
  for (auto& byte : hash) byte = logic.eltw_input();
  for (auto& byte : digest) byte = logic.eltw_input();
  quad->private_input();
  using Relation = SignaturePossessionCircuitV1<SignaturePossessionLogic, P256k1>;
  Relation::Witness witness;
  witness.input(logic);
  auto scope = quad->assertion_scope("signature-possession/ecdsa-hash160");
  Relation(logic, p256k1).verify(hash, digest, witness);
  return quad->mkcircuit(1);
}
}  // namespace proofs
#endif
