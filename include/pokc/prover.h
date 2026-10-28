// Copyright (C) 2026 Plan-B Foundation
// designed, written and maintained by Denis Roio
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#ifndef PRIVACY_PROOFS_ZK_LIB_POKC_PROVER_H_
#define PRIVACY_PROOFS_ZK_LIB_POKC_PROVER_H_
#include <array>
#include <chrono>
#include <functional>
#include <memory>
#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "pokc/crt_guard.h"
#include "quietproof/envelope.h"
#include "circuit/pokc_circuit.h"
#include "circuit/pokc_witness.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256k1.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/readbuffer.h"
#include "util/byte_cursor.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "pokc/verifier.h"
namespace proofs {
inline bool PoKCProve(const std::array<uint8_t, 32>& secret,
                      QuietProofStatementV1 statement,
                      QuietProofEnvelopeV1* out,
                      const std::function<void(const char*)>& progress = {}) {
  if (!out || !QuietProofStatementValid(statement)) return false;
  const auto created_at = std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
  if (created_at <= 0 || static_cast<uint64_t>(created_at) < statement.not_before ||
      static_cast<uint64_t>(created_at) >= statement.expires_at) return false;
  PoKCWitnessV1<PoKCField, PoKCEC> witness;
  if (!witness.compute(p256k1, secret.data(), secret.size()) ||
      witness.program() != statement.claims.front().program) return false;

  if (progress) progress("building circuit");
  QuadCircuit<PoKCField> q(p256k1_base);
  auto circuit = PoKCBuildCircuit(&q);
  const size_t block = PoKCBlock(*circuit, q);
  if (!PoKCCrtBlockSupported(block)) return false;
  if (progress) progress("preparing proof inputs");
  auto inputs = std::make_unique<Dense<PoKCField>>(1, circuit->ninputs);
  {
    DenseFiller<PoKCField> filler(*inputs);
    filler.push_back(p256k1_base.one());
    BitPluckerEncoder<PoKCField, 8> encoder(p256k1_base);
    for (auto byte : statement.claims.front().program)
      filler.push_back(encoder.encode(byte));
    witness.fill_witness(filler);
  }
  using CF = CrtConvolutionFactory<CRT256<PoKCField>, PoKCField>;
  using RS = ReedSolomonFactory<PoKCField, CF>;
  CF cf(p256k1_base);
  RS rs(cf, p256k1_base);
  ZkProof<PoKCField> proof(*circuit, 4, 128, block);
  ZkProver<PoKCField, RS> prover(*circuit, p256k1_base, rs);
  SecureRandomEngine rng;
  QuietProofEnvelopeV1 envelope;
  envelope.statement = std::move(statement);
  envelope.envelope_version = 2;
  envelope.proof_created_at = static_cast<uint64_t>(created_at);
  envelope.proof.circuit_digest = PoKCExpectedCircuitDigest();
  const auto seed = PoKCTranscriptSeed(envelope);
  Transcript transcript(seed.data(), seed.size());
  if (progress) progress("computing commitment");
  prover.commit(proof, *inputs, transcript, rng);
  if (progress) progress("generating proof");
  if (!prover.prove(proof, *inputs, transcript)) return false;
  if (progress) progress("serializing proof");
  proof.write(envelope.proof.bytes, p256k1_base);
  *out = std::move(envelope);
  return true;
}

inline bool PoKCProve(const uint8_t* secret, size_t size,
                      QuietProofStatementV1 statement,
                      QuietProofEnvelopeV1* out) {
  if (!secret || size != 32) return false;
  std::array<uint8_t, 32> key{};
  std::memcpy(key.data(), secret, key.size());
  const bool result = PoKCProve(key, std::move(statement), out);
  volatile uint8_t* wipe = key.data();
  for (size_t i = 0; i < key.size(); ++i) wipe[i] = 0;
  return result;
}

}  // namespace proofs
#endif
