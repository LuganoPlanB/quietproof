// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Standalone test/prototype: no wallet, production proof API or ECDSA package.
#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/resource.h>
#include <vector>
#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuit/bitcoin_ecdsa.h"
#include "circuit/bitcoin_ecdsa_witness.h"
#include "circuit/hash160.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "pokc/crt_guard.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "sumcheck/prover_layers.h"
#include "util/byte_cursor.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace proofs {
namespace {
using Field = Fp256k1Base;
using Nat = Field::N;
using Advice = BitcoinEcdsaAdvice<Field::Elt>;
using Backend = CompilerBackend<Field>;
using LogicCircuit = Logic<Field, Backend>;
using Relation = BitcoinEcdsaCircuit<LogicCircuit, P256k1>;
using Clock = std::chrono::steady_clock;
constexpr size_t kRate = 4, kQueries = 128, kProofCap = 128 * 1024 * 1024;

void Require(bool ok, const char* message) { if (!ok) throw std::runtime_error(message); }
double Seconds(Clock::time_point start) { return std::chrono::duration<double>(Clock::now() - start).count(); }
size_t PeakBytes() { rusage usage{}; getrusage(RUSAGE_SELF, &usage); return static_cast<size_t>(usage.ru_maxrss) * 1024; }

std::unique_ptr<Circuit<Field>> Build(QuadCircuit<Field>& quad) {
  Backend backend(&quad);
  LogicCircuit logic(&backend, p256k1_base);
  std::array<LogicCircuit::EltW, 32> digest;
  for (auto& byte : digest) byte = logic.eltw_input();
  quad.private_input();
  Relation::Witness witness;
  witness.input(logic);
  auto scope = quad.assertion_scope("bitcoin-ecdsa/relation");
  Relation(logic, p256k1).verify(digest, witness);
  return quad.mkcircuit(1);
}

std::unique_ptr<Dense<Field>> Inputs(const Circuit<Field>& circuit, const Nat& z, const Advice& w) {
  auto input = std::make_unique<Dense<Field>>(1, circuit.ninputs);
  DenseFiller<Field> fill(*input);
  fill.push_back(p256k1_base.one());
  BitPluckerEncoder<Field, 8> encoder(p256k1_base);
  for (size_t byte = 0; byte < 32; ++byte) {
    size_t value = 0;
    for (size_t bit = 0; bit < 8; ++bit) value = 2 * value + z.bit(255 - 8 * byte - bit);
    fill.push_back(encoder.encode(value));
  }
  for (auto value : w.values) fill.push_back(value);
  Require(fill.size() == circuit.ninputs, "input allocation mismatch");
  return input;
}

bool Evaluate(const Circuit<Field>& circuit, std::unique_ptr<Dense<Field>> input) {
  ProverLayers<Field> evaluator(p256k1_base);
  ProverLayers<Field>::inputs layers;
  auto result = evaluator.eval_circuit(&layers, &circuit, std::move(input), p256k1_base);
  if (!result) return false;  // compiled assertion failure, not native validation
  for (size_t i = 0; i < result->n1_; ++i) if (result->v_[i] != p256k1_base.zero()) return false;
  return true;
}

Advice Baseline() {
  // Public fixture d=k=z=1; r=x(G), s=r+1, already low-S.
  const auto r = p256k1_base.from_montgomery(p256k1.gx_);
  auto s = r; s.add(Nat(1));
  return BitcoinEcdsaMakeAdvice(Nat(1), r, p256k1_base.from_montgomery(p256k1.gy_), r, s);
}

void Metrics(const Circuit<Field>& circuit, const QuadCircuit<Field>& quad, double seconds) {
  const size_t block = circuit.ninputs - circuit.npub_in + quad.nquad_terms_ + 1;
  Require(PoKCCrtBlockSupported(block), "CRT capacity exceeded before proof allocation");
  ZkProof<Field> proof(circuit, kRate, kQueries, block);
  Require(proof.param.valid(), "invalid unchanged-security proof geometry");
  size_t transform = 1;
  while (transform < block) transform *= 2;
  std::cout << "metrics inputs=" << circuit.ninputs << " public=" << circuit.npub_in
            << " wires=" << quad.nwires_ << " depth=" << quad.depth_
            << " quad_terms=" << quad.nquad_terms_ << " layers=" << circuit.nl
            << " block_enc=" << block << " crt_transform=" << transform
            << " crt_capacity=" << crt::kOmegaOrder << " rate=" << kRate << " queries=" << kQueries
            << " sdk_size_estimate=" << proof.size() << " rows=" << proof.param.nrow
            << " matrix_bytes=" << proof.param.nrow * block * Field::kBytes
            << " build_seconds=" << seconds << " peak_bytes=" << PeakBytes() << std::endl;
  Require(proof.size() <= kProofCap, "proof size estimate exceeds retained 128 MiB cap");
}

void Mutations(const Circuit<Field>& circuit) {
  const Advice honest = Baseline();
  Require(Evaluate(circuit, Inputs(circuit, Nat(1), honest)), "positive baseline failed");
  size_t rejected = 0;
  // Every private input is mutated after honest generation, without rebuilding
  // dependent advice. Raw bit mutations include 1->2 non-bit attacks.
  for (size_t i = 0; i < Advice::kSize; ++i) {
    Advice mutated = honest;
    mutated[i] = p256k1_base.addf(mutated[i], p256k1_base.one());
    if (Evaluate(circuit, Inputs(circuit, Nat(1), mutated))) {
      std::cerr << "accepted private advice mutation " << i << '\n';
      throw std::runtime_error("unbound private advice");
    }
    ++rejected;
  }
  for (size_t i = 0; i < 32; ++i) {
    auto input = Inputs(circuit, Nat(1), honest);
    input->v_[1 + i] = p256k1_base.addf(input->v_[1 + i], p256k1_base.one());
    Require(!Evaluate(circuit, std::move(input)), "mutated public digest accepted");
    ++rejected;
  }
  for (size_t i = 0; i < 4 + 255; ++i) {
    Advice mutated = honest;
    const size_t offset = i < 4 ? Advice::kPre + 3 * i : Advice::kTrace + 3 * (i - 4);
    for (size_t j = 0; j < 3; ++j) mutated[offset + j] = p256k1_base.zero();
    Require(!Evaluate(circuit, Inputs(circuit, Nat(1), mutated)), "zero projective tuple accepted");
    ++rejected;
  }
  std::cout << "mutations passed=1 rejected=" << rejected << " failed=0 skipped=0" << std::endl;
}

void Stream(const Circuit<Field>& circuit) {
  std::string id;
  while (std::cin >> id) {
    std::array<Nat, 5> values;
    for (auto& value : values) {
      std::string text;
      Require(static_cast<bool>(std::cin >> text), "truncated test tuple");
      const auto parsed = Nat::of_untrusted_string(("0x" + text).c_str());
      Require(parsed.has_value(), "tuple is not exactly representable as 256 bits");
      value = *parsed;
    }
    auto witness = BitcoinEcdsaMakeAdvice(values[0], values[1], values[2], values[3], values[4]);
    std::string mutation;
    Require(static_cast<bool>(std::cin >> mutation), "missing test mutation selector");
    if (mutation == "branch_one") witness[Advice::kBranch] = p256k1_base.one();
    else if (mutation == "branch_zero") witness[Advice::kBranch] = p256k1_base.zero();
    else Require(mutation == "none", "unknown test mutation");
    const bool accepted = Evaluate(circuit, Inputs(circuit, values[0], witness));
    std::cout << "case " << id << " " << (accepted ? "accepted" : "constraint_rejected") << '\n';
  }
}

void RunProof(const Circuit<Field>& circuit, const QuadCircuit<Field>& quad, const char* output) {
  const size_t block = circuit.ninputs - circuit.npub_in + quad.nquad_terms_ + 1;
  Require(PoKCCrtBlockSupported(block), "CRT guard failed");
  auto input = Inputs(circuit, Nat(1), Baseline());
  Require(Evaluate(circuit, input->clone()), "proof positive constraint control failed");
  using CF = CrtConvolutionFactory<CRT256<Field>, Field>;
  using RS = ReedSolomonFactory<Field, CF>;
  CF cf(p256k1_base); RS rs(cf, p256k1_base);
  ZkProof<Field> proof(circuit, kRate, kQueries, block);
  Require(proof.param.valid() && proof.size() <= kProofCap, "proof parameter/cap check failed");
  ZkProver<Field, RS> prover(circuit, p256k1_base, rs);
  SecureRandomEngine rng;
  constexpr char domain[] = "QuietProof/ecdsa/prototype/v1";
  Transcript transcript(reinterpret_cast<const uint8_t*>(domain), sizeof(domain) - 1);
  auto start = Clock::now();
  prover.commit(proof, *input, transcript, rng);
  const double commit_seconds = Seconds(start);
  start = Clock::now();
  Require(prover.prove(proof, *input, transcript), "real proof generation failed");
  const double prove_seconds = Seconds(start);
  std::vector<uint8_t> bytes;
  proof.write(bytes, p256k1_base);
  Require(bytes.size() <= kProofCap, "serialized proof exceeds cap");
  if (output) {
    std::ofstream file(output, std::ios::binary);
    file.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    Require(static_cast<bool>(file), "proof artifact write failed");
  }
  ZkProof<Field> decoded(circuit, kRate, kQueries, block);
  ByteCursor cursor(bytes.data(), bytes.size());
  Require(decoded.read(cursor, p256k1_base) && cursor.remaining() == 0, "real proof roundtrip failed");
  Dense<Field> public_input(1, circuit.npub_in);
  for (size_t i = 0; i < circuit.npub_in; ++i) public_input.v_[i] = input->v_[i];
  auto verify = [&]() {
    ZkVerifier<Field, RS> verifier(circuit, rs, kRate, kQueries, block, p256k1_base);
    Transcript challenge(reinterpret_cast<const uint8_t*>(domain), sizeof(domain) - 1);
    verifier.recv_commitment(decoded, challenge);
    return verifier.verify(decoded, public_input, challenge);
  };
  start = Clock::now(); Require(verify(), "real proof verification failed");
  const double verify_seconds = Seconds(start);
  public_input.v_[32] = BitPluckerEncoder<Field, 8>(p256k1_base).encode(2);
  Require(!verify(), "proof verified against changed digest");
  std::cout << "proof verified=1 wrong_digest_rejected=1 bytes=" << bytes.size()
            << " commit_seconds=" << commit_seconds << " prove_seconds=" << prove_seconds
            << " verify_seconds=" << verify_seconds << " peak_bytes=" << PeakBytes() << std::endl;
}

// Separate existing HASH160 circuit cost only; no ECDSA/HASH160 composition or
// production identity. Its 257 key inputs would share the ECDSA key bits in L5.
void HashMetrics(const Circuit<Field>& ecdsa, const QuadCircuit<Field>& eq) {
  QuadCircuit<Field> quad(p256k1_base);
  Backend backend(&quad); LogicCircuit logic(&backend, p256k1_base);
  std::array<LogicCircuit::v8, 20> h;
  BitPlucker<LogicCircuit, 8> plucker(logic);
  for (auto& byte : h) byte = plucker.pluck(logic.eltw_input());
  quad.private_input();
  using Encoding = Secp256k1Encoding<LogicCircuit, P256k1>;
  Encoding::CoordinateWitness x, y;
  for (auto& bit : x.bits) bit = logic.eltw_input();
  for (auto& bit : y.bits) bit = logic.konst(0);
  y.bits[255] = logic.eltw_input();
  Hash160Circuit<LogicCircuit>::Witness witness; witness.input(logic);
  Hash160Circuit<LogicCircuit>(logic).assert_hash160(Encoding(logic).compressed(x, y), witness, h);
  const auto circuit = quad.mkcircuit(1);
  const size_t extra_inputs = circuit->ninputs - circuit->npub_in - 257;
  const size_t projected_block = ecdsa.ninputs - ecdsa.npub_in + extra_inputs + eq.nquad_terms_ + quad.nquad_terms_ + 1;
  const size_t projected_depth = std::max(ecdsa.nl, circuit->nl);
  size_t transform = 1; while (transform < projected_block) transform *= 2;
  std::cout << "hash_cost extra_private_inputs=" << extra_inputs << " quad_terms=" << quad.nquad_terms_
            << " depth=" << quad.depth_ << " projected_combined_block=" << projected_block
            << " projected_combined_layers=" << projected_depth << " projected_crt_transform=" << transform
            << " crt_capacity=" << crt::kOmegaOrder << " peak_bytes=" << PeakBytes() << std::endl;
  Require(PoKCCrtBlockSupported(projected_block), "additive composition estimate exceeds CRT capacity");
}
}  // namespace
}  // namespace proofs

int main(int argc, char** argv) {
  try {
    proofs::Require(argc == 2 || argc == 3, "expected --metrics, --hash-metrics, --stream, --mutations or --proof [artifact]");
    const auto start = proofs::Clock::now();
    proofs::QuadCircuit<proofs::Field> quad(proofs::p256k1_base);
    const auto circuit = proofs::Build(quad);
    proofs::Metrics(*circuit, quad, proofs::Seconds(start));
    const std::string mode = argv[1];
    if (mode == "--stream") proofs::Stream(*circuit);
    else if (mode == "--mutations") proofs::Mutations(*circuit);
    else if (mode == "--proof") proofs::RunProof(*circuit, quad, argc == 3 ? argv[2] : nullptr);
    else if (mode == "--hash-metrics") proofs::HashMetrics(*circuit, quad);
    else proofs::Require(mode == "--metrics", "unknown mode");
    return 0;
  } catch (const std::exception& error) {
    std::cerr << "ecdsa prototype: " << error.what() << '\n';
    return 1;
  }
}
