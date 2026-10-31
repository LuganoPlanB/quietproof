// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include <array>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include "arrays/dense.h"
#include "circuit/signature_possession.h"
#include "circuit/signature_possession_witness.h"
#include "sumcheck/prover_layers.h"

namespace proofs {
namespace {
using Field = Fp256k1Base;
using Nat = Field::N;
using Advice = BitcoinEcdsaAdvice<Field::Elt>;
void Require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
Nat ReadNat() {
  std::string text;
  Require(static_cast<bool>(std::cin >> text), "truncated test input");
  const auto value = Nat::of_untrusted_string(("0x" + text).c_str());
  Require(value.has_value(), "unrepresentable test integer");
  return *value;
}

std::unique_ptr<Dense<Field>> Inputs(const Circuit<Field>& circuit, const Nat& digest,
                                    const std::string& hash, const SignaturePossessionWitnessV1& witness) {
  Require(hash.size() == 40, "invalid test hash size");
  auto input = std::make_unique<Dense<Field>>(1, circuit.ninputs);
  DenseFiller<Field> filler(*input);
  filler.push_back(p256k1_base.one());
  BitPluckerEncoder<Field, 8> bytes(p256k1_base);
  for (size_t i = 0; i < 20; ++i) filler.push_back(bytes.encode(std::stoul(hash.substr(2 * i, 2), nullptr, 16)));
  for (size_t i = 0; i < 32; ++i) {
    size_t byte = 0;
    for (size_t j = 0; j < 8; ++j) byte = 2 * byte + digest.bit(255 - 8 * i - j);
    filler.push_back(bytes.encode(byte));
  }
  witness.fill_witness(filler);
  Require(filler.size() == circuit.ninputs, "private/public input allocation mismatch");
  return input;
}

bool Evaluate(const Circuit<Field>& circuit, std::unique_ptr<Dense<Field>> input) {
  ProverLayers<Field> evaluator(p256k1_base);
  ProverLayers<Field>::inputs layers;
  auto result = evaluator.eval_circuit(&layers, &circuit, std::move(input), p256k1_base);
  if (!result) return false;
  for (size_t i = 0; i < result->n1_; ++i)
    if (result->v_[i] != p256k1_base.zero()) return false;
  return true;
}

void Run() {
  QuadCircuit<Field> quad(p256k1_base);
  const auto circuit = SignaturePossessionBuildCircuit(&quad);
  Require(circuit->npub_in == 53, "public input layout changed");
  Require(circuit->ninputs == 53 + Advice::kSize + 1472, "private input layout changed");
  std::cout << "layout public=" << circuit->npub_in << " inputs=" << circuit->ninputs
            << " wires=" << quad.nwires_ << " quad_terms=" << quad.nquad_terms_
            << " depth=" << quad.depth_ << " layers=" << circuit->nl << std::endl;
  std::string id;
  while (std::cin >> id) {
    const Nat digest = ReadNat(), qx = ReadNat(), qy = ReadNat(), r = ReadNat(), s = ReadNat();
    std::string hash, mutation;
    Require(static_cast<bool>(std::cin >> hash >> mutation), "truncated test selector");
    SignaturePossessionWitnessV1 witness;
    // Intentionally bypass receipt parsing and native signature/key validation.
    witness.compute(digest, qx, qy, r, s);
    if (mutation == "branch_one") witness.ecdsa[Advice::kBranch] = p256k1_base.one();
    else if (mutation == "branch_zero") witness.ecdsa[Advice::kBranch] = p256k1_base.zero();
    else if (mutation == "sha_splice") {
      const Nat other_x = ReadNat(), other_y = ReadNat();
      SignaturePossessionWitnessV1 other;
      other.compute(digest, other_x, other_y, r, s);
      witness.sha = other.sha;
    }
    auto input = Inputs(*circuit, digest, hash, witness);
    if (mutation == "add" || mutation == "zero_point") {
      size_t offset;
      Require(static_cast<bool>(std::cin >> offset), "missing mutation index");
      Require(offset > 0 && offset < circuit->ninputs, "invalid mutation index");
      if (mutation == "add") input->v_[offset] = p256k1_base.addf(input->v_[offset], p256k1_base.one());
      else {
        Require(offset + 2 < circuit->ninputs, "invalid point index");
        for (size_t j = 0; j < 3; ++j) input->v_[offset + j] = p256k1_base.zero();
      }
    } else Require(mutation == "none" || mutation == "branch_one" ||
                   mutation == "branch_zero" || mutation == "sha_splice", "unknown mutation");
    const bool accepted = Evaluate(*circuit, std::move(input));
    std::cout << "case " << id << ' ' << (accepted ? "accepted" : "constraint_rejected") << std::endl;
  }
}
}  // namespace
}  // namespace proofs

int main() {
  try { proofs::Run(); return 0; }
  catch (const std::exception& error) {
    std::cerr << "signature constraint test: " << error.what() << '\n';
    return 1;
  }
}
