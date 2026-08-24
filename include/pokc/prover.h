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
inline bool PoKCProveKeys(const std::vector<std::array<uint8_t, 32>>& secrets, QuietProofStatementV1 statement, QuietProofEnvelopeV1* out) { std::vector<std::array<uint8_t,20>> programs; if(!out || secrets.size()!=Keys || !QuietProofDistinctPrograms(statement,&programs) || programs.size()!=Keys)return false; std::array<PoKCWitnessV1<PoKCField,PoKCEC>,Keys> witnesses; for(size_t i=0;i<Keys;++i) { bool found=false; for(size_t j=0;j<Keys;++j) { PoKCWitnessV1<PoKCField,PoKCEC> candidate; if(!candidate.compute(p256k1,secrets[j].data(),secrets[j].size()))return false; if(candidate.program()==programs[i]) { if(found)return false; witnesses[i]=candidate; found=true; } } if(!found)return false; } QuadCircuit<PoKCField> q(p256k1_base); auto c=PoKCBuildCircuit<Keys>(&q); const size_t block=PoKCBlock(*c,q); if(!PoKCCrtBlockSupported(block))return false; auto in=std::make_unique<Dense<PoKCField>>(1,c->ninputs); { DenseFiller<PoKCField> f(*in); f.push_back(p256k1_base.one()); BitPluckerEncoder<PoKCField,8> encoder(p256k1_base); for(const auto& program:programs)for(auto x:program)f.push_back(encoder.encode(x)); for(const auto& witness:witnesses)witness.fill_witness(f); } using CF=CrtConvolutionFactory<CRT256<PoKCField>,PoKCField>; using RS=ReedSolomonFactory<PoKCField,CF>; CF cf(p256k1_base); RS rs(cf,p256k1_base); ZkProof<PoKCField> p(*c,4,128,block); ZkProver<PoKCField,RS> prover(*c,p256k1_base,rs); SecureRandomEngine rng; QuietProofEnvelopeV1 e; e.statement=std::move(statement); e.proof.circuit_digest=PoKCExpectedCircuitDigest<Keys>(); const auto seed=PoKCTranscriptSeed(e.statement,e.proof); Transcript t(seed.data(),seed.size()); prover.commit(p,*in,t,rng); if(!prover.prove(p,*in,t))return false; p.write(e.proof.bytes,p256k1_base); *out=std::move(e); return true; }
inline bool PoKCProve(const uint8_t* secret, size_t n, QuietProofStatementV1 statement, QuietProofEnvelopeV1* out) { if(!secret || n!=32 || !QuietProofStatementValid(statement))return false; std::array<uint8_t,32> key{}; std::memcpy(key.data(),secret,32); const bool result=PoKCProveKeys<1>({key},std::move(statement),out); volatile uint8_t* wipe=key.data(); for(size_t i=0;i<key.size();++i)wipe[i]=0; return result; }
template <size_t Keys>
inline bool PoKCVerifyKeys(const QuietProofEnvelopeV1& e) { std::vector<std::array<uint8_t,20>> programs; if(!QuietProofDistinctPrograms(e.statement,&programs) || programs.size()!=Keys)return false; QuadCircuit<PoKCField> q(p256k1_base); auto c=PoKCBuildCircuit<Keys>(&q); if(!PoKCProofIdentityMatches(e.proof,PoKCExpectedCircuitDigest<Keys>()))return false; const size_t block=PoKCBlock(*c,q); using CF=CrtConvolutionFactory<CRT256<PoKCField>,PoKCField>; using RS=ReedSolomonFactory<PoKCField,CF>; CF cf(p256k1_base); RS rs(cf,p256k1_base); ZkProof<PoKCField> p(*c,4,128,block); ByteCursor rb(e.proof.bytes.data(),e.proof.bytes.size()); if(!p.read(rb,p256k1_base) || rb.remaining()!=0)return false; Dense<PoKCField> pub(1,c->npub_in); { DenseFiller<PoKCField> f(pub); f.push_back(p256k1_base.one()); BitPluckerEncoder<PoKCField,8> enc(p256k1_base); for(const auto& program:programs)for(auto x:program)f.push_back(enc.encode(x)); } const auto seed=PoKCTranscriptSeed(e.statement,e.proof); Transcript t(seed.data(),seed.size()); ZkVerifier<PoKCField,RS> v(*c,rs,4,128,block,p256k1_base); v.recv_commitment(p,t); return v.verify(p,pub,t); }
inline bool PoKCVerifyProof(const QuietProofEnvelopeV1& e) { std::vector<std::array<uint8_t,20>> p; if(!QuietProofDistinctPrograms(e.statement,&p))return false; switch(p.size()) { case 1:return PoKCVerifyKeys<1>(e); case 2:return PoKCVerifyKeys<2>(e); default:return false; } }
}
#endif
