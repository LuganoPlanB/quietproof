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

#include <array>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <stdexcept>
#include <vector>

#include "circuit/pokc_circuit.h"
#include "circuit/pokc_witness.h"
#include "pokc/proof.h"
#include "pokc/prover.h"
#include "pokc/crt_guard.h"
#include "circuits/compiler/compiler.h"
#include "circuits/logic/compiler_backend.h"
#include "circuits/logic/logic.h"
#include "ec/p256k1.h"
#include "proto/circuit_writer.h"
#include "util/crypto.h"
#include "algebra/crt.h"
#include "algebra/crt_convolution.h"
#include "algebra/reed_solomon.h"
#include "arrays/dense.h"
#include "circuits/logic/bit_plucker_encoder.h"
#include "random/secure_random_engine.h"
#include "random/transcript.h"
#include "util/readbuffer.h"
#include "zk/zk_proof.h"
#include "zk/zk_prover.h"
#include "zk/zk_verifier.h"

namespace proofs {
namespace {
using Field = Fp256k1Base;
using EC = P256k1;
using CompileBackend = CompilerBackend<Field>;
using CompileLogic = Logic<Field, CompileBackend>;
using Relation = PoKCCircuitV1<CompileLogic, Field, EC>;
struct NativeMetric {
  uint64_t build_ms;
  uint64_t prove_ms;
  uint64_t verify_ms;
  size_t proof_bytes;
  size_t public_inputs;
  size_t total_inputs;
  size_t quad_terms;
  size_t crt_block_enc;
};
std::vector<NativeMetric> native_metrics;

void Require(bool value, const char* message) {
  if (!value) throw std::runtime_error(message);
}

std::unique_ptr<Circuit<Field>> BuildCircuit(QuadCircuit<Field>& q) {
  const CompileBackend backend(&q);
  const CompileLogic logic(&backend, p256k1_base);
  Relation relation(logic, p256k1);
  std::array<CompileLogic::EltW, Relation::kProgramBytes> program;
  for (auto& byte : program) byte = logic.eltw_input();
  q.private_input();
  Relation::Witness witness;
  witness.input(logic);
  relation.assert_program(program, witness);
  return q.mkcircuit(1);
}

void TestStableLayoutAndDigest() {
  QuadCircuit<Field> q1(p256k1_base);
  auto c1 = BuildCircuit(q1);
  const auto identity = PoKCCircuitDigest(*c1, p256k1_base, SECP_ID);
  PoKCProofV1 envelope; envelope.circuit_digest = identity;
  Require(PoKCProofIdentityMatches(envelope, identity), "circuit identity rejected");
  envelope.rate++;
  Require(!PoKCProofIdentityMatches(envelope, identity), "parameter mismatch accepted");
  Require(c1->npub_in == 21, "PoKC public layout must be one plus 20 bytes");
  Require(c1->ninputs > c1->npub_in, "PoKC private witness missing");

  std::vector<uint8_t> one;
  CircuitWriter<Field>(p256k1_base, SECP_ID).to_bytes(*c1, one);
  uint8_t digest_one[32];
  SHA256 sha_one;
  sha_one.Update(one.data(), one.size());
  sha_one.DigestData(digest_one);

  QuadCircuit<Field> q2(p256k1_base);
  auto c2 = BuildCircuit(q2);
  std::vector<uint8_t> two;
  CircuitWriter<Field>(p256k1_base, SECP_ID).to_bytes(*c2, two);
  uint8_t digest_two[32];
  SHA256 sha_two;
  sha_two.Update(two.data(), two.size());
  sha_two.DigestData(digest_two);
  Require(one == two, "PoKC circuit serialization is not deterministic");
  for (size_t i = 0; i < sizeof(digest_one); ++i)
    Require(digest_one[i] == digest_two[i], "PoKC circuit digest is not deterministic");
}

template <size_t Keys>
std::unique_ptr<Circuit<Field>> BuildMultiCircuit(QuadCircuit<Field>& q) {
  const CompileBackend backend(&q); const CompileLogic logic(&backend, p256k1_base);
  PoKCMultiCircuitV1<CompileLogic, Field, EC, Keys> relation(logic, p256k1);
  std::array<std::array<CompileLogic::EltW, 20>, Keys> programs;
  for (auto& program : programs) for (auto& byte : program) byte = logic.eltw_input();
  q.private_input(); std::array<Relation::Witness, Keys> witnesses; for (auto& witness : witnesses) witness.input(logic);
  relation.assert_programs(programs, witnesses); return q.mkcircuit(1);
}
void TestMultiKeyLayouts() {
  QuadCircuit<Field> q1(p256k1_base), q2(p256k1_base);
  auto one=BuildMultiCircuit<1>(q1); auto two=BuildMultiCircuit<2>(q2);
  Require(one->npub_in==21 && two->npub_in==41,"multi public layout");
  Require(one->ninputs < two->ninputs,"multi ownership relations not composed");
  Require(PoKCCircuitDigest(*one,p256k1_base,SECP_ID)!=PoKCCircuitDigest(*two,p256k1_base,SECP_ID),"key count absent from circuit identity");
  Require(PoKCCrtBlockSupported(two->ninputs-two->npub_in+q2.nquad_terms_+1),"maximum circuit CRT guard");
}
void TestMaximumMultiKeyProofRoundTrip() {
  std::array<uint8_t,32> one{}, n_minus_one = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x40}; one[31]=1;
  PoKCWitnessV1<Field,EC> first, second; Require(first.compute(p256k1,one.data(),one.size()) && second.compute(p256k1,n_minus_one.data(),n_minus_one.size()),"multi witness compute");
  QuietProofStatementV1 s; s.network=QuietProofNetwork::kRegtest; s.verifier="multi-test"; s.purpose="proof-of-funds"; s.expires_at=static_cast<uint64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()))+3600; s.nonce[0]=1; s.bip322_message_hash[0]=1;
  QuietProofClaimV1 a,b; a.txid[0]=1; a.amount_sats=1; a.program=first.program(); b.txid[0]=2; b.amount_sats=2; b.program=second.program(); s.claims={a,b};
  QuietProofEnvelopeV1 envelope; Require(PoKCProveKeys<2>({one,n_minus_one},s,&envelope),"maximum multi-key prove"); std::vector<uint8_t> wire; Require(EncodeQuietProofEnvelope(envelope,&wire),"maximum multi-key encode"); QuietProofEnvelopeV1 parsed; Require(DecodeQuietProofEnvelope(wire,&parsed) && PoKCVerifyProof(parsed),"maximum multi-key verify");
  auto trailing_proof=parsed; trailing_proof.proof.bytes.push_back(0); Require(!PoKCVerifyProof(trailing_proof),"proof trailing byte accepted");
  auto mutated_program=parsed; mutated_program.statement.claims[0].program[0]^=1; Require(!PoKCVerifyProof(mutated_program),"mutated program accepted");
  auto mutated_claims=s; std::swap(mutated_claims.claims[0],mutated_claims.claims[1]); Require(!PoKCProveKeys<2>({one,n_minus_one},mutated_claims,&envelope),"reordered claims accepted"); mutated_claims=s; mutated_claims.claims[1]=mutated_claims.claims[0]; Require(!PoKCProveKeys<2>({one,n_minus_one},mutated_claims,&envelope),"duplicate claim accepted"); Require(!PoKCProveKeys<2>({one},s,&envelope),"omitted relation accepted"); Require(!PoKCProveKeys<2>({one,n_minus_one,one},s,&envelope),"extra relation accepted"); Require(!PoKCProveKeys<2>({one,one},s,&envelope),"mutated key accepted");
  auto too_many=s; QuietProofClaimV1 c=b; c.txid[0]=3; c.program[0]^=1; too_many.claims.push_back(c); std::vector<std::array<uint8_t,20>> too_many_programs; Require(!QuietProofDistinctPrograms(too_many,&too_many_programs),"three program grouping accepted");
  auto shared=s; shared.claims[1].program=shared.claims[0].program; std::vector<std::array<uint8_t,20>> grouped; Require(QuietProofDistinctPrograms(shared,&grouped) && grouped.size()==1,"shared-key mapping rejected");
}

void TestTimestampProofRoundTrip() {
  std::array<uint8_t, 32> secret{};
  secret[31] = 1;
  PoKCWitnessV1<Field, EC> witness;
  Require(witness.compute(p256k1, secret.data(), secret.size()), "timestamp witness");
  QuietProofStatementV1 statement;
  statement.network = QuietProofNetwork::kSignet;
  statement.verifier = "timestamp-test";
  statement.purpose = "proof-of-funds";
  statement.not_before = static_cast<uint64_t>(std::chrono::system_clock::to_time_t(
      std::chrono::system_clock::now()));
  statement.expires_at = statement.not_before + 3600;
  statement.nonce[0] = 1;
  statement.bip322_message_hash[0] = 1;
  QuietProofClaimV1 claim;
  claim.txid[0] = 1;
  claim.amount_sats = 7;
  claim.program = witness.program();
  statement.claims = {claim};
  QuietProofEnvelopeV1 envelope;
  Require(PoKCProve(secret.data(), secret.size(), statement, &envelope), "timestamp prove");
  Require(envelope.envelope_version == 2 &&
              envelope.proof_created_at >= statement.not_before, "prover omitted timestamp");
  std::vector<uint8_t> wire;
  Require(EncodeQuietProofEnvelope(envelope, &wire), "timestamp encode");
  QuietProofEnvelopeV1 decoded;
  Require(DecodeQuietProofEnvelope(wire, &decoded) && PoKCVerifyProof(decoded),
          "timestamp proof round trip");
  ++decoded.proof_created_at;
  Require(!PoKCVerifyProof(decoded), "tampered proof timestamp accepted");
  decoded = envelope;
  decoded.envelope_version = 1;
  decoded.proof_created_at = 0;
  Require(!PoKCVerifyProof(decoded), "timestamp stripping accepted");
  decoded = envelope;
  --decoded.statement.not_before;
  Require(!PoKCVerifyProof(decoded), "tampered request timestamp accepted");
}

void TestWitnessInputValidation() {
  PoKCWitnessV1<Field, EC> witness;
  std::array<uint8_t, 32> one{};
  one[31] = 1;
  std::array<uint8_t, 32> zero{};
  std::array<uint8_t, 32> order = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x41};
  Require(!witness.compute(p256k1, one.data(), 31), "31-byte secret accepted");
  Require(!witness.compute(p256k1, one.data(), 33), "33-byte secret accepted");
  Require(!witness.compute(p256k1, zero.data(), zero.size()), "zero secret accepted");
  Require(!witness.compute(p256k1, order.data(), order.size()), "order secret accepted");
  Require(witness.compute(p256k1, one.data(), one.size()), "valid secret rejected");
  const auto first_program = witness.program();
  std::array<uint8_t, 32> two{}; two[31] = 2;
  Require(witness.compute(p256k1, two.data(), two.size()), "reused witness rejected valid secret");
  Require(witness.program() != first_program, "reused witness retained stale program advice");
  Require(witness.compute(p256k1, one.data(), one.size()), "reused witness could not restore first secret");
  Require(witness.program() == first_program, "reused witness retained stale second-secret advice");
}

void TestProofRoundTrip(const std::array<uint8_t, 32>& secret) {
  const auto build_started = std::chrono::steady_clock::now();
  PoKCWitnessV1<Field, EC> witness;
  Require(witness.compute(p256k1, secret.data(), secret.size()), "witness compute failed");
  QuadCircuit<Field> q(p256k1_base); auto circuit = BuildCircuit(q);
  const auto build_finished = std::chrono::steady_clock::now();
  auto inputs = std::make_unique<Dense<Field>>(1, circuit->ninputs);
  { DenseFiller<Field> fill(*inputs); fill.push_back(p256k1_base.one()); BitPluckerEncoder<Field,8> enc(p256k1_base); for (auto b : witness.program()) fill.push_back(enc.encode(b)); witness.fill_witness(fill); }
  using Crt = CRT256<Field>; using CF = CrtConvolutionFactory<Crt, Field>; using RS = ReedSolomonFactory<Field, CF>;
  const size_t block = circuit->ninputs - circuit->npub_in + q.nquad_terms_ + 1; Require(PoKCCrtBlockSupported(block), "CRT guard rejected circuit"); Require(!PoKCCrtBlockSupported((1ull << 22) + 1), "CRT guard accepted oversized value"); CF cf(p256k1_base); RS rs(cf, p256k1_base);
  ZkProof<Field> proof(*circuit, 4, 128, block); ZkProver<Field, RS> prover(*circuit, p256k1_base, rs); SecureRandomEngine rng; uint8_t tag[] = {'P','K','C','1'}; Transcript tp(tag, sizeof(tag));
  const auto prove_started = std::chrono::steady_clock::now();
  prover.commit(proof, *inputs, tp, rng); Require(prover.prove(proof, *inputs, tp), "prove failed");
  const auto prove_finished = std::chrono::steady_clock::now();
  std::vector<uint8_t> bytes; proof.write(bytes, p256k1_base); ReadBuffer rb(bytes.data(), bytes.size()); ZkProof<Field> parsed(*circuit, 4, 128, block); Require(parsed.read(rb, p256k1_base), "parse failed");
  Dense<Field> pub(1, circuit->npub_in); { DenseFiller<Field> fill(pub); fill.push_back(p256k1_base.one()); BitPluckerEncoder<Field,8> enc(p256k1_base); for (auto b : witness.program()) fill.push_back(enc.encode(b)); }
  Transcript tv(tag, sizeof(tag)); ZkVerifier<Field, RS> verifier(*circuit, rs, 4, 128, block, p256k1_base);
  const auto verify_started = std::chrono::steady_clock::now();
  verifier.recv_commitment(parsed, tv); std::cerr << "positive verify begin\n"; Require(verifier.verify(parsed, pub, tv), "verify failed"); std::cerr << "positive verify done\n";
  const auto verify_finished = std::chrono::steady_clock::now();
  auto changed = pub.clone(); changed->v_[1] = p256k1_base.addf(changed->v_[1], p256k1_base.one()); Transcript changed_tv(tag, sizeof(tag)); ZkVerifier<Field, RS> changed_verifier(*circuit, rs, 4, 128, block, p256k1_base); changed_verifier.recv_commitment(parsed, changed_tv); Require(!changed_verifier.verify(parsed, *changed, changed_tv), "public-byte mutation accepted");
  auto swapped = pub.clone(); std::swap(swapped->v_[1], swapped->v_[2]); Transcript swapped_tv(tag, sizeof(tag)); ZkVerifier<Field, RS> swapped_verifier(*circuit, rs, 4, 128, block, p256k1_base); swapped_verifier.recv_commitment(parsed, swapped_tv); Require(!swapped_verifier.verify(parsed, *swapped, swapped_tv), "swapped public bytes accepted");
  bytes[10] ^= 1; ReadBuffer bad_rb(bytes.data(), bytes.size()); ZkProof<Field> bad(*circuit, 4, 128, block); Require(bad.read(bad_rb, p256k1_base), "tampered proof parse failed"); Transcript bad_tv(tag, sizeof(tag)); ZkVerifier<Field, RS> bad_verifier(*circuit, rs, 4, 128, block, p256k1_base); bad_verifier.recv_commitment(bad, bad_tv); Require(!bad_verifier.verify(bad, pub, bad_tv), "tampered proof accepted");
  native_metrics.push_back({
      static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(build_finished - build_started).count()),
      static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(prove_finished - prove_started).count()),
      static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(verify_finished - verify_started).count()),
      bytes.size(), circuit->npub_in, circuit->ninputs, q.nquad_terms_, block});
}
}  // namespace
}  // namespace proofs

int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "--timestamp-roundtrip") {
      proofs::TestTimestampProofRoundTrip();
      std::cout << "Timestamp proof round trip and tamper checks passed\n";
      return 0;
    }
    proofs::TestStableLayoutAndDigest();
    proofs::TestMultiKeyLayouts();
    proofs::TestMaximumMultiKeyProofRoundTrip();
    proofs::TestWitnessInputValidation();
    std::array<uint8_t, 32> one{}; one[31] = 1;
    proofs::TestProofRoundTrip(one);
    for (uint8_t scalar : {uint8_t{2}, uint8_t{3}, uint8_t{153}}) {
      std::array<uint8_t, 32> value{}; value[31] = scalar;
      proofs::TestProofRoundTrip(value);
    }
    std::array<uint8_t, 32> three_eighty_two{}; three_eighty_two[30] = 1; three_eighty_two[31] = 126;
    proofs::TestProofRoundTrip(three_eighty_two);
    std::array<uint8_t, 32> n_minus_one = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xfe,0xba,0xae,0xdc,0xe6,0xaf,0x48,0xa0,0x3b,0xbf,0xd2,0x5e,0x8c,0xd0,0x36,0x41,0x40};
    proofs::TestProofRoundTrip(n_minus_one);
    std::ofstream metrics("tests/results/native_pokc_metrics.csv");
    proofs::Require(metrics.good(), "metrics output unavailable");
    metrics << "target,circuit,build_ms,prove_ms,verify_ms,proof_bytes,public_inputs,total_inputs,quad_terms,crt_block_enc\n";
    for (const auto& metric : proofs::native_metrics) metrics << "native,pokc," << metric.build_ms << ',' << metric.prove_ms << ',' << metric.verify_ms << ',' << metric.proof_bytes << ',' << metric.public_inputs << ',' << metric.total_inputs << ',' << metric.quad_terms << ',' << metric.crt_block_enc << '\n';
  } catch (const std::exception& error) {
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
  std::cout << "PoKC layout tests passed\n";
}
