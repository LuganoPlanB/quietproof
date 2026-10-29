// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_POKC_P2SH_MULTISIG_H_
#define QUIETPROOF_POKC_P2SH_MULTISIG_H_

#include "circuit/p2sh_multisig.h"
#include "circuit/p2sh_multisig_witness.h"
#include "pokc/prover.h"

namespace proofs {
// A separate format: QPM1, circuit digest[32], HASH160[20], position[1],
// proof length[4 BE], proof bytes. Rate=4, queries=128, circuit version=1
// are fixed by this format and domain-separated from P2WPKH PoKC v1.
struct P2shMultisigProof {
  P2shHash hash{};
  uint8_t position = 0;
  std::array<uint8_t, 32> circuit_digest{};
  std::vector<uint8_t> bytes;
};
constexpr size_t kP2shHeaderBytes = 61;
constexpr size_t kP2shMaxProofBytes = 128 * size_t{1024} * 1024;
using P2shRelation = P2shMultisigCircuit<PoKCLogic, PoKCField, PoKCEC>;

inline std::unique_ptr<Circuit<PoKCField>> P2shBuildCircuit(QuadCircuit<PoKCField>* q) {
  PoKCBackend backend(q); PoKCLogic l(&backend, p256k1_base);
  std::array<PoKCLogic::EltW, 20> hash;
  for (auto& b : hash) b = l.eltw_input();
  auto position = l.eltw_input();
  q->private_input(); P2shRelation::Witness w; w.input(l);
  auto scope = q->assertion_scope("p2sh/2-of-3/independent-key-control");
  P2shRelation(l, p256k1).assert_relation(hash, position, w);
  return q->mkcircuit(1);
}
inline const std::array<uint8_t, 32>& P2shCircuitDigest() {
  static const auto digest = [] {
    QuadCircuit<PoKCField> q(p256k1_base); auto c = P2shBuildCircuit(&q);
    auto inner = PoKCCircuitDigest(*c, p256k1_base, SECP_ID);
    return QuietProofTaggedHash("QuietProof/P2SH-2of3/circuit/v1", inner.data(), inner.size());
  }();
  return digest;
}
inline std::array<uint8_t, 32> P2shTranscriptSeed(const P2shMultisigProof& p) {
  std::vector<uint8_t> binding(p.circuit_digest.begin(), p.circuit_digest.end());
  binding.insert(binding.end(), p.hash.begin(), p.hash.end()); binding.push_back(p.position);
  return QuietProofTaggedHash("QuietProof/P2SH-2of3/proof/v1", binding.data(), binding.size());
}
template <class Filler> inline void P2shFillPublic(Filler& f, const P2shHash& hash, uint8_t position) {
  f.push_back(p256k1_base.one());
  BitPluckerEncoder<PoKCField, 8> enc(p256k1_base);
  for (auto b : hash) f.push_back(enc.encode(b));
  f.push_back(p256k1_base.of_scalar(position));
}

namespace p2sh_detail {
// Low-level entry used by constraint tests, with no native witness validation.
inline bool ProveWitness(const P2shMultisigWitness& witness, P2shMultisigProof* out) {
  if (!out) return false;
  QuadCircuit<PoKCField> q(p256k1_base); auto c = P2shBuildCircuit(&q);
  const auto block = PoKCBlock(*c, q);
  if (!PoKCCrtBlockSupported(block)) return false;
  Dense<PoKCField> in(1, c->ninputs);
  { DenseFiller<PoKCField> f(in); P2shFillPublic(f, out->hash, out->position); witness.fill_witness(f); }
  using CF = CrtConvolutionFactory<CRT256<PoKCField>, PoKCField>;
  using RS = ReedSolomonFactory<PoKCField, CF>;
  CF cf(p256k1_base); RS rs(cf, p256k1_base);
  ZkProof<PoKCField> proof(*c, 4, 128, block);
  ZkProver<PoKCField, RS> prover(*c, p256k1_base, rs);
  out->circuit_digest = P2shCircuitDigest(); out->bytes.clear();
  const auto seed = P2shTranscriptSeed(*out); Transcript t(seed.data(), seed.size());
  SecureRandomEngine rng; prover.commit(proof, in, t, rng);
  if (!prover.prove(proof, in, t)) return false;
  proof.write(out->bytes, p256k1_base);
  return !out->bytes.empty() && out->bytes.size() <= kP2shMaxProofBytes;
}
}  // namespace p2sh_detail

inline bool P2shProve(const P2shSecret& secret, const P2shScript& script,
                      uint8_t position, P2shMultisigProof* out) {
  if (!out) return false;
  P2shMultisigWitness witness;
  if (!witness.compute(secret, script, position)) return false;
  P2shMultisigProof result; result.hash = witness.hash; result.position = position;
  if (!p2sh_detail::ProveWitness(witness, &result)) return false;
  *out = std::move(result); return true;
}
inline bool P2shVerify(const P2shMultisigProof& p) {
  if (p.position > 2 || p.bytes.empty() || p.bytes.size() > kP2shMaxProofBytes ||
      p.circuit_digest != P2shCircuitDigest()) return false;
  QuadCircuit<PoKCField> q(p256k1_base); auto c = P2shBuildCircuit(&q);
  const auto block = PoKCBlock(*c, q);
  if (!PoKCCrtBlockSupported(block)) return false;
  using CF = CrtConvolutionFactory<CRT256<PoKCField>, PoKCField>;
  using RS = ReedSolomonFactory<PoKCField, CF>;
  CF cf(p256k1_base); RS rs(cf, p256k1_base);
  ZkProof<PoKCField> proof(*c, 4, 128, block);
  ByteCursor cursor(p.bytes.data(), p.bytes.size());
  if (!proof.read(cursor, p256k1_base) || cursor.remaining()) return false;
  Dense<PoKCField> pub(1, c->npub_in);
  { DenseFiller<PoKCField> f(pub); P2shFillPublic(f, p.hash, p.position); }
  const auto seed = P2shTranscriptSeed(p); Transcript t(seed.data(), seed.size());
  ZkVerifier<PoKCField, RS> verifier(*c, rs, 4, 128, block, p256k1_base);
  verifier.recv_commitment(proof, t); return verifier.verify(proof, pub, t);
}
// expected_hash must come from the auditor's on-chain P2SH scriptPubKey.
inline bool P2shVerifyPair(const P2shMultisigProof& a, const P2shMultisigProof& b,
                           const P2shHash& expected_hash) {
  return a.hash == expected_hash && b.hash == expected_hash &&
         a.position != b.position && P2shVerify(a) && P2shVerify(b);
}
inline bool EncodeP2shProof(const P2shMultisigProof& p, std::vector<uint8_t>* out) {
  if (!out || p.position > 2 || p.bytes.empty() || p.bytes.size() > kP2shMaxProofBytes ||
      p.circuit_digest != P2shCircuitDigest()) return false;
  out->assign({'Q','P','M','1'});
  out->insert(out->end(), p.circuit_digest.begin(), p.circuit_digest.end());
  out->insert(out->end(), p.hash.begin(), p.hash.end()); out->push_back(p.position);
  QuietProofAppendU32(out, static_cast<uint32_t>(p.bytes.size()));
  out->insert(out->end(), p.bytes.begin(), p.bytes.end()); return true;
}
inline bool DecodeP2shProof(const std::vector<uint8_t>& bytes, P2shMultisigProof* out) {
  if (!out || bytes.size() <= kP2shHeaderBytes || bytes.size() > kP2shHeaderBytes + kP2shMaxProofBytes)
    return false;
  QuietProofReader r(bytes); uint8_t magic[4]; P2shMultisigProof p; uint32_t size;
  if (!r.bytes(magic, 4) || std::memcmp(magic, "QPM1", 4) ||
      !r.bytes(p.circuit_digest.data(), 32) || !r.bytes(p.hash.data(), 20) ||
      !r.u8(&p.position) || p.position > 2 || !r.u32(&size) || size != r.left() ||
      p.circuit_digest != P2shCircuitDigest()) return false;
  p.bytes.resize(size); if (!r.bytes(p.bytes.data(), size)) return false;
  *out = std::move(p); return true;
}
}  // namespace proofs
#endif
