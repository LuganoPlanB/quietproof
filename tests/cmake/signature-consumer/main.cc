// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Instantiate and evaluate the installed relation using only exported includes.
#include <array>
#include <memory>
#include "arrays/dense.h"
#include "circuit/bitcoin_ecdsa.h"
#include "circuit/bitcoin_ecdsa_witness.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "sumcheck/prover_layers.h"

int main() {
  using namespace proofs;
  using Field = Fp256k1Base;
  using Backend = CompilerBackend<Field>;
  using CircuitLogic = Logic<Field, Backend>;
  using Relation = BitcoinEcdsaCircuit<CircuitLogic, P256k1>;
  const auto& field = p256k1_base;
  QuadCircuit<Field> quad(field);
  Backend backend(&quad);
  CircuitLogic logic(&backend, field);
  std::array<CircuitLogic::EltW, 32> digest;
  for (auto& byte : digest) byte = logic.eltw_input();
  quad.private_input();
  Relation::Witness witness;
  witness.input(logic);
  Relation(logic, p256k1).verify(digest, witness);
  auto circuit = quad.mkcircuit(1);
  const auto r = field.from_montgomery(p256k1.gx_);
  auto s = r;
  s.add(Fp256k1Nat(1));
  auto advice = BitcoinEcdsaMakeAdvice(Fp256k1Nat(1), r,
      field.from_montgomery(p256k1.gy_), r, s);
  const BitPluckerEncoder<Field, 8> encoder(field);
  auto evaluate = [&](bool corrupt) {
    auto input = std::make_unique<Dense<Field>>(1, circuit->ninputs);
    DenseFiller<Field> fill(*input);
    fill.push_back(field.one());
    for (size_t i = 0; i < 32; ++i) fill.push_back(encoder.encode(i == 31));
    for (auto value : advice.values) fill.push_back(value);
    if (corrupt) input->v_[circuit->npub_in] = field.of_scalar(2);
    ProverLayers<Field> evaluator(field);
    ProverLayers<Field>::inputs layers;
    auto result = evaluator.eval_circuit(&layers, circuit.get(), std::move(input), field);
    if (!result) return false;
    for (size_t i = 0; i < result->n1_; ++i)
      if (result->v_[i] != field.zero()) return false;
    return true;
  };
  return evaluate(false) && !evaluate(true) ? 0 : 1;
}
