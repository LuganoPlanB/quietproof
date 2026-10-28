// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_POKC_VERIFIER_H_
#define QUIETPROOF_POKC_VERIFIER_H_
#include <array>
#include <functional>
#include <memory>
#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "pokc/crt_guard.h"
#include "quietproof/envelope.h"
#include "circuit/pokc_circuit.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256k1.h"
#include "random/transcript.h"
#include "util/readbuffer.h"
#include "util/byte_cursor.h"
#include "zk/zk_proof.h"
#include "zk/zk_verifier.h"
namespace proofs {
using PoKCField = Fp256k1Base; using PoKCEC = P256k1; using PoKCBackend = CompilerBackend<PoKCField>; using PoKCLogic = Logic<PoKCField, PoKCBackend>; using PoKCRelation = PoKCCircuitV1<PoKCLogic, PoKCField, PoKCEC>;
inline std::unique_ptr<Circuit<PoKCField>> PoKCBuildCircuit(QuadCircuit<PoKCField>* q) {
  PoKCBackend backend(q);
  PoKCLogic logic(&backend, p256k1_base);
  PoKCRelation relation(logic, p256k1);
  std::array<PoKCLogic::EltW, 20> program;
  for (auto& byte : program) byte = logic.eltw_input();
  q->private_input();
  PoKCRelation::Witness witness;
  witness.input(logic);
  auto symbol_scope = q->assertion_scope("pokc/programs/relations");
  relation.assert_program(program, witness);
  return q->mkcircuit(1);
}
inline size_t PoKCBlock(const Circuit<PoKCField>& c, const QuadCircuit<PoKCField>& q) { return c.ninputs-c.npub_in+q.nquad_terms_+1; }
inline const std::array<uint8_t, 32>& PoKCExpectedCircuitDigest() {
  static const std::array<uint8_t, 32> digest = [] {
    QuadCircuit<PoKCField> q(p256k1_base);
    auto circuit = PoKCBuildCircuit(&q);
    return PoKCCircuitDigest(*circuit, p256k1_base, SECP_ID);
  }();
  return digest;
}
inline bool PoKCProofSupported(const QuietProofEnvelopeV1& envelope) {
  return QuietProofStatementValid(envelope.statement) &&
      PoKCProofIdentityMatches(envelope.proof, PoKCExpectedCircuitDigest());
}

inline bool PoKCVerifyProof(const QuietProofEnvelopeV1& envelope) {
  if (!QuietProofEnvelopeTimeValid(envelope) || !PoKCProofSupported(envelope))
    return false;
  QuadCircuit<PoKCField> q(p256k1_base);
  auto circuit = PoKCBuildCircuit(&q);
  const size_t block = PoKCBlock(*circuit, q);
  using CF = CrtConvolutionFactory<CRT256<PoKCField>, PoKCField>;
  using RS = ReedSolomonFactory<PoKCField, CF>;
  CF cf(p256k1_base);
  RS rs(cf, p256k1_base);
  ZkProof<PoKCField> proof(*circuit, 4, 128, block);
  ByteCursor cursor(envelope.proof.bytes.data(), envelope.proof.bytes.size());
  if (!proof.read(cursor, p256k1_base) || cursor.remaining() != 0) return false;
  Dense<PoKCField> public_inputs(1, circuit->npub_in);
  {
    DenseFiller<PoKCField> filler(public_inputs);
    filler.push_back(p256k1_base.one());
    BitPluckerEncoder<PoKCField, 8> encoder(p256k1_base);
    for (auto byte : envelope.statement.claims.front().program)
      filler.push_back(encoder.encode(byte));
  }
  const auto seed = PoKCTranscriptSeed(envelope);
  Transcript transcript(seed.data(), seed.size());
  ZkVerifier<PoKCField, RS> verifier(*circuit, rs, 4, 128, block, p256k1_base);
  verifier.recv_commitment(proof, transcript);
  return verifier.verify(proof, public_inputs, transcript);
}

}  // namespace proofs
#endif
