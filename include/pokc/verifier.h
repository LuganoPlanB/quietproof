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
template <size_t Keys>
inline std::unique_ptr<Circuit<PoKCField>> PoKCBuildCircuit(QuadCircuit<PoKCField>* q) { PoKCBackend b(q); PoKCLogic l(&b,p256k1_base); PoKCMultiCircuitV1<PoKCLogic, PoKCField, PoKCEC, Keys> r(l,p256k1); std::array<std::array<PoKCLogic::EltW,20>, Keys> p; for(auto& key:p)for(auto& x:key)x=l.eltw_input(); q->private_input(); std::array<typename PoKCRelation::Witness, Keys> w; for(auto& x:w)x.input(l); auto symbol_scope=q->assertion_scope("pokc/programs/relations"); r.assert_programs(p,w); return q->mkcircuit(1); }
inline std::unique_ptr<Circuit<PoKCField>> PoKCBuildCircuit(QuadCircuit<PoKCField>* q) { return PoKCBuildCircuit<1>(q); }
inline size_t PoKCBlock(const Circuit<PoKCField>& c, const QuadCircuit<PoKCField>& q) { return c.ninputs-c.npub_in+q.nquad_terms_+1; }
template <size_t Keys>
inline const std::array<uint8_t, 32>& PoKCExpectedCircuitDigest() {
  static const std::array<uint8_t, 32> digest = [] {
    QuadCircuit<PoKCField> q(p256k1_base);
    auto circuit = PoKCBuildCircuit<Keys>(&q);
    return PoKCCircuitDigest(*circuit, p256k1_base, SECP_ID);
  }();
  return digest;
}
inline bool PoKCProofSupported(const QuietProofEnvelopeV1& envelope) {
  std::vector<std::array<uint8_t, 20>> programs;
  if (!QuietProofDistinctPrograms(envelope.statement, &programs)) return false;
  switch (programs.size()) {
    case 1: return PoKCProofIdentityMatches(
        envelope.proof, PoKCExpectedCircuitDigest<1>());
    case 2: return PoKCProofIdentityMatches(
        envelope.proof, PoKCExpectedCircuitDigest<2>());
    default: return false;
  }
}
template <size_t Keys>
inline bool PoKCVerifyKeys(const QuietProofEnvelopeV1& e) { std::vector<std::array<uint8_t,20>> programs; if(!QuietProofEnvelopeTimeValid(e) || !QuietProofDistinctPrograms(e.statement,&programs) || programs.size()!=Keys)return false; QuadCircuit<PoKCField> q(p256k1_base); auto c=PoKCBuildCircuit<Keys>(&q); if(!PoKCProofIdentityMatches(e.proof,PoKCExpectedCircuitDigest<Keys>()))return false; const size_t block=PoKCBlock(*c,q); using CF=CrtConvolutionFactory<CRT256<PoKCField>,PoKCField>; using RS=ReedSolomonFactory<PoKCField,CF>; CF cf(p256k1_base); RS rs(cf,p256k1_base); ZkProof<PoKCField> p(*c,4,128,block); ByteCursor rb(e.proof.bytes.data(),e.proof.bytes.size()); if(!p.read(rb,p256k1_base) || rb.remaining()!=0)return false; Dense<PoKCField> pub(1,c->npub_in); { DenseFiller<PoKCField> f(pub); f.push_back(p256k1_base.one()); BitPluckerEncoder<PoKCField,8> enc(p256k1_base); for(const auto& program:programs)for(auto x:program)f.push_back(enc.encode(x)); } const auto seed=PoKCTranscriptSeed(e); Transcript t(seed.data(),seed.size()); ZkVerifier<PoKCField,RS> v(*c,rs,4,128,block,p256k1_base); v.recv_commitment(p,t); return v.verify(p,pub,t); }
inline bool PoKCVerifyProof(const QuietProofEnvelopeV1& e) { std::vector<std::array<uint8_t,20>> p; if(!QuietProofDistinctPrograms(e.statement,&p))return false; switch(p.size()) { case 1:return PoKCVerifyKeys<1>(e); case 2:return PoKCVerifyKeys<2>(e); default:return false; } }
}
#endif
