// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include <algorithm>
#include <chrono>
#include <iostream>
#include <fstream>
#include "pokc/p2sh_multisig.h"
#include "sumcheck/prover_layers.h"

namespace proofs {
namespace {
void Require(bool b, const char* message) { if (!b) throw std::runtime_error(message); }
std::string Hex(const auto& bytes) {
  std::string out;
  for (uint8_t b : bytes) { out += "0123456789abcdef"[b >> 4]; out += "0123456789abcdef"[b & 15]; }
  return out;
}
struct Fixture {
  std::array<P2shSecret, 3> secrets{};
  std::array<P2shKey, 3> keys;
  P2shScript script;
  Fixture() {
    for (size_t j = 0; j < 3; ++j) {
      secrets[j][31] = j + 1;
      KeyOwnershipWitness<PoKCField, PoKCEC> n; n.compute(p256k1, PoKCField::N(j + 1));
      keys[j] = P2shPublicKey(n);
    }
    script = P2shSerialize(keys);
  }
};

// Evaluate the actual compiled prover circuit, including its assertions.
// No call to compute(), P2shProve(), or any host validation occurs here.
bool Satisfied(const Circuit<PoKCField>& c, const P2shMultisigWitness& w,
               const P2shHash& hash, unsigned position,
               const std::function<void(Dense<PoKCField>&)>& corrupt = {}) {
  auto input = std::make_unique<Dense<PoKCField>>(1, c.ninputs);
  { DenseFiller<PoKCField> f(*input); P2shFillPublic(f, hash, position); w.fill_witness(f); }
  if (corrupt) corrupt(*input);
  ProverLayers<PoKCField> evaluator(p256k1_base);
  ProverLayers<PoKCField>::inputs layers;
  auto result = evaluator.eval_circuit(&layers, &c, std::move(input), p256k1_base);
  if (!result) return false;
  for (const auto& v : result->v_) if (v != p256k1_base.zero()) return false;
  return true;
}
void CircuitTests() {
  Fixture f;
  QuadCircuit<PoKCField> q(p256k1_base); auto c = P2shBuildCircuit(&q);
  Require(c->npub_in == 22, "only one, hash, position may be public");
  Require(PoKCCrtBlockSupported(PoKCBlock(*c, q)), "CRT limit exceeded");
  P2shMultisigWitness w;
  Require(w.compute(f.secrets[0], f.script, 0), "fixture witness");
  // Independent bitcoinjs-lib 7.0.1 / Node OpenSSL reference, captured once.
  // Running the circuit tests requires neither JavaScript nor Bitcoin Core.
  Require(Hex(f.script) ==
      "52210279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      "2102c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
      "2102f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f953ae",
      "independent canonical script vector mismatch");
  Require(Hex(w.hash) == "15fc0754e73eb85d1cbce08786fadb7320ecb8dc",
          "independent P2SH HASH160 vector mismatch");
  for (size_t j = 0; j < 3; ++j) {
    P2shMultisigWitness good;
    Require(good.compute(f.secrets[j], f.script, j), "valid signer compute");
    Require(Satisfied(*c, good, good.hash, j), "valid signer circuit");
  }
  // Distinctness is compressed SEC equality, not just equality of X.
  auto opposite = f.keys; opposite[1] = opposite[0]; opposite[1][0] ^= 1;
  P2shMultisigWitness opposite_w;
  Require(opposite_w.compute(f.secrets[0], P2shSerialize(opposite), 0) &&
          Satisfied(*c, opposite_w, opposite_w.hash, 0), "distinct opposite-parity keys rejected");
  P2shSecret n_minus_one{};
  const PoKCField::N last("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140");
  uint8_t little[32]; last.to_bytes(little);
  for (size_t b = 0; b < 32; ++b) n_minus_one[b] = little[31-b];
  Require(opposite_w.compute(n_minus_one, P2shSerialize(opposite), 1) &&
          Satisfied(*c, opposite_w, opposite_w.hash, 1), "n-1 scalar rejected");
  // The crucial same-private-key attack at each other public position.
  for (size_t signer = 0; signer < 3; ++signer) {
    P2shMultisigWitness one;
    Require(one.compute(f.secrets[signer], f.script, signer), "signer fixture");
    for (size_t target = 0; target < 3; ++target) if (target != signer) {
      for (size_t j = 0; j < 3; ++j) one.selectors[j] = p256k1_base.of_scalar(j == target);
      Require(!Satisfied(*c, one, one.hash, target), "one key satisfied a second position");
    }
  }
  for (unsigned i : {3u, 255u}) Require(!Satisfied(*c, w, w.hash, i), "invalid position accepted");
  Require(!Satisfied(*c, w, w.hash, 1), "public position unbound");
  auto wrong_hash = w.hash; wrong_hash[0] ^= 1;
  Require(!Satisfied(*c, w, wrong_hash, 0), "wrong hash accepted");
  for (auto selectors : {std::array<unsigned,3>{0,0,0}, {1,1,0}, {2,0,0}, {0,0,1}}) {
    auto bad = w;
    for (size_t j = 0; j < 3; ++j) bad.selectors[j] = p256k1_base.of_scalar(selectors[j]);
    Require(!Satisfied(*c, bad, w.hash, 0), "selector constraints bypassed");
  }
  // p-1 cannot be disguised as a valid selector or public position.
  auto bad = w; bad.selectors[0] = p256k1_base.mone();
  Require(!Satisfied(*c, bad, w.hash, 0), "negative field selector accepted");
  Require(!Satisfied(*c, w, w.hash, 0, [](auto& in) { in.v_[21] = p256k1_base.mone(); }),
          "negative field position accepted");
  for (size_t a = 0; a < 3; ++a) for (size_t b = a + 1; b < 3; ++b) {
    bad = w; bad.points[b] = bad.points[a]; auto keys = f.keys; keys[b] = keys[a];
    bad.HashScript(P2shSerialize(keys));
    // Position 0 still has its real key, even for duplication of keys 1 and 2.
    Require(!Satisfied(*c, bad, bad.hash, 0), "duplicate script keys accepted");
  }
  // False point and coordinate advice, including non-selected keys.
  for (size_t j = 0; j < 3; ++j) {
    bad = w; bad.points[j].y = p256k1_base.zero();
    Require(!Satisfied(*c, bad, w.hash, 0), "off-curve key accepted");
    bad = w; bad.points[j].xb[0] = p256k1_base.of_scalar(2);
    Require(!Satisfied(*c, bad, w.hash, 0), "non-bit coordinate accepted");
  }
  // Consistent canonical encoding/hash of a non-selected off-curve point.
  // Only its curve equation is false, rather than merely stale bit advice.
  bad = w;
  bad.points[1].x = bad.points[1].y = p256k1_base.zero();
  bad.points[1].xb.fill(p256k1_base.zero()); bad.points[1].yb.fill(p256k1_base.zero());
  auto invalid_keys = f.keys; invalid_keys[1].fill(0); invalid_keys[1][0] = 2;
  bad.HashScript(P2shSerialize(invalid_keys));
  Require(!Satisfied(*c, bad, bad.hash, 0), "consistently encoded off-curve key accepted");
  // Canonical point X=1 with consistently rehashed SEC encoding X=p+1.
  // Reconstruction modulo p and the curve equation both hold; X<p must fail.
  bad = w; P2shKey small_key{}; small_key[0] = 2; small_key[32] = 1;
  Require(P2shMultisigWitness::DecodePoint(small_key, &bad.points[1]), "small-X fixture");
  const PoKCField::N alias("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30");
  alias.to_bytes(little); invalid_keys = f.keys; invalid_keys[1] = small_key;
  for (size_t b = 0; b < 32; ++b) invalid_keys[1][b+1] = little[31-b];
  for (size_t b = 0; b < 256; ++b) bad.points[1].xb[b] = p256k1_base.of_scalar(alias.bit(255 - b));
  bad.HashScript(P2shSerialize(invalid_keys));
  Require(!Satisfied(*c, bad, bad.hash, 0), "noncanonical coordinate accepted");
  for (int mutation = 0; mutation < 5; ++mutation) {
    bad = w;
    if (mutation == 0) bad.ownership.scalar = p256k1_base.zero();
    if (mutation == 1) bad.ownership.scalar_inverse = p256k1_base.zero();
    if (mutation == 2) bad.ownership.scalar_mult.bits[0] = p256k1_base.of_scalar(2);
    if (mutation == 3) bad.ownership.scalar_mult.int_x[10] =
        p256k1_base.addf(bad.ownership.scalar_mult.int_x[10], p256k1_base.one());
    if (mutation == 4) bad.ownership.y_bits[255] = p256k1_base.subf(p256k1_base.one(), bad.ownership.y_bits[255]);
    Require(!Satisfied(*c, bad, w.hash, 0), "invalid ownership advice accepted");
  }
  for (auto scalar : {PoKCField::N(0), n256k1_order, PoKCField::N("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")}) {
    bad = w;
    // Raw scalar bits bypass native scalar range checks (and do not need a valid trace).
    for (size_t b = 0; b < 256; ++b) bad.ownership.scalar_mult.bits[b] = p256k1_base.of_scalar(scalar.bit(255 - b));
    Require(!Satisfied(*c, bad, w.hash, 0), "invalid scalar accepted by circuit");
  }
  // n+1 derives the same G as 1, with a valid complete multiplication trace,
  // normalization, scalar inverse and selected script key. Only x<n fails.
  bad = w;
  bad.ownership.compute(p256k1, PoKCField::N("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364142"));
  Require(P2shPublicKey(bad.ownership) == f.keys[0], "n+1 alias fixture must derive G");
  Require(!Satisfied(*c, bad, w.hash, 0), "noncanonical scalar alias accepted");
  // Rehash malformed scripts with fully consistent native SHA advice. The
  // circuit must still require its own canonical opcodes and all 105 bytes.
  for (size_t offset : {0u, 1u, 35u, 69u, 103u, 104u, 34u, 68u, 102u}) {
    auto script = f.script; script[offset] ^= 1; bad = w; bad.HashScript(script);
    Require(!Satisfied(*c, bad, bad.hash, 0), "alternate script accepted");
  }
  for (size_t block = 0; block < 2; ++block) {
    bad = w; bad.sha[block].h1[0] ^= 1;
    Require(!Satisfied(*c, bad, w.hash, 0), "unbound SHA chaining state");
    bad = w; bad.sha[block].outw[0] ^= 1;
    Require(!Satisfied(*c, bad, w.hash, 0), "unbound SHA schedule");
  }
  // Internally consistent SHA advice for alternate padding and lengths.
  // Keep block 0; recompute the entire second-block schedule and state.
  for (size_t offset : {105u, 106u, 119u, 120u, 126u, 127u}) {
    bad = w;
    uint8_t count = 0, padded[128]{};
    FlatSHA256Witness::BlockWitness unused[2];
    FlatSHA256Witness::transform_and_witness_message(105, f.script.data(), 2, count, padded, unused);
    padded[offset] ^= 1;
    uint32_t words[16]{};
    for (size_t j = 0; j < 64; ++j) words[j/4] |= uint32_t(padded[64+j]) << (24 - 8*(j%4));
    auto& block = bad.sha[1];
    FlatSHA256Witness::transform_and_witness_block(words, bad.sha[0].h1,
        block.outw, block.oute, block.outa, block.h1);
    std::array<uint8_t,32> digest;
    for (size_t j = 0; j < 32; ++j) digest[j] = (block.h1[j/4] >> (24 - 8*(j%4))) & 255;
    bad.hash = Ripemd160::digest(digest);
    Require(!Satisfied(*c, bad, bad.hash, 0), "alternate SHA padding/length accepted");
  }
  Require(!Satisfied(*c, w, w.hash, 0, [](auto& in) { in.v_[1] = p256k1_base.zero(); }),
          "nonencoded public hash accepted");
  std::vector<uint8_t> wire;
  P2shMultisigProof proof;
  Require(!DecodeP2shProof(wire, &proof), "empty envelope accepted");
  proof.hash = w.hash; proof.circuit_digest = P2shCircuitDigest(); proof.bytes = {0};
  Require(EncodeP2shProof(proof, &wire), "structural envelope fixture");
  Require(!P2shVerify(proof), "nonproof accepted");
  P2shMultisigProof parsed;
  // Structural wire fixture only: these bytes are not a cryptographic proof.
  // Check a fixed, asymmetric length vector independently of codec helpers.
  auto wire_fixture = proof;
  wire_fixture.bytes.assign(258, 0x5a);
  std::vector<uint8_t> fixture_wire;
  Require(EncodeP2shProof(wire_fixture, &fixture_wire), "encode length vector");
  constexpr size_t length_offset = kP2shHeaderBytes - 4;
  const std::array<uint8_t, 4> expected_length{0x00, 0x00, 0x01, 0x02};
  Require(std::equal(expected_length.begin(), expected_length.end(),
                     fixture_wire.begin() + length_offset), "QPM1 length is not big-endian");
  Require(DecodeP2shProof(fixture_wire, &parsed) && parsed.bytes == wire_fixture.bytes,
          "decode big-endian length vector");
  std::reverse(fixture_wire.begin() + length_offset,
               fixture_wire.begin() + kP2shHeaderBytes);
  Require(!DecodeP2shProof(fixture_wire, &parsed), "little-endian length accepted");
  for (size_t length : {size_t{0}, size_t{4}, size_t{35}, size_t{60}, wire.size()-1}) {
    auto truncated = wire; truncated.resize(length);
    Require(!DecodeP2shProof(truncated, &parsed), "truncated envelope accepted");
  }
  for (size_t offset : {0u, 4u, 36u, 56u, 57u, 60u}) {
    auto changed = wire; changed[offset] ^= 0x80;
    if (offset == 36) {
      // Hash changes are structurally valid; cryptographic verification is
      // tested with real proofs by ProofTests, not claimed by the parser.
      Require(DecodeP2shProof(changed, &parsed), "parser rejected hash-shaped input");
    } else Require(!DecodeP2shProof(changed, &parsed), "malformed envelope accepted");
  }
  std::cout << "compiled circuit adversarial tests passed\n";
}

double Seconds(std::chrono::steady_clock::time_point start) {
  return std::chrono::duration<double>(std::chrono::steady_clock::now() - start).count();
}
void ProofTests() {
  Fixture f;
  std::array<P2shMultisigProof, 3> proofs;
  std::ofstream metrics("p2sh-benchmark.csv");
  metrics << "relation,position,prove_s,verify_s,proof_bytes,circuit_bytes,inputs,quad_terms\n";
  QuadCircuit<PoKCField> q(p256k1_base); auto c = P2shBuildCircuit(&q);
  std::vector<uint8_t> circuit;
  CircuitWriter<PoKCField>(p256k1_base, SECP_ID).to_bytes(*c, circuit);
  for (size_t j = 0; j < 3; ++j) {
    auto start = std::chrono::steady_clock::now();
    Require(P2shProve(f.secrets[j], f.script, j, &proofs[j]), "independent proof generation");
    const auto prove = Seconds(start); start = std::chrono::steady_clock::now();
    Require(P2shVerify(proofs[j]), "independent proof verify");
    const auto verify = Seconds(start);
    metrics << "p2sh," << j << ',' << prove << ',' << verify << ',' << proofs[j].bytes.size()
            << ',' << circuit.size() << ',' << c->ninputs << ',' << q.nquad_terms_ << '\n';
    metrics.flush();
    std::vector<uint8_t> wire;
    Require(EncodeP2shProof(proofs[j], &wire), "encode");
    P2shMultisigProof parsed;
    Require(DecodeP2shProof(wire, &parsed) && parsed.hash == proofs[j].hash &&
            parsed.position == j && parsed.bytes == proofs[j].bytes, "decode round trip");
    wire.push_back(0); Require(!DecodeP2shProof(wire, &parsed), "trailing envelope accepted");
    std::cout << "signer " << j << " proved in " << prove << "s verified in " << verify << "s\n" << std::flush;
  }
  for (size_t a = 0; a < 3; ++a) for (size_t b = a + 1; b < 3; ++b)
    Require(P2shVerifyPair(proofs[a], proofs[b], proofs[0].hash), "valid signer pair rejected");
  Require(!P2shVerifyPair(proofs[0], proofs[0], proofs[0].hash), "repeated position accepted");
  auto wrong_hash = proofs[0].hash; wrong_hash[0] ^= 1;
  Require(!P2shVerifyPair(proofs[0], proofs[1], wrong_hash), "wrong on-chain hash accepted");
  auto changed = proofs[0]; changed.hash[0] ^= 1;
  Require(!P2shVerify(changed), "tampered public hash accepted");
  Require(!P2shVerifyPair(proofs[1], changed, proofs[1].hash), "mismatched proof hashes accepted");
  changed = proofs[0]; changed.position = 1;
  Require(!P2shVerify(changed), "tampered proof position accepted");
  changed = proofs[0]; changed.bytes[changed.bytes.size()/2] ^= 1;
  Require(!P2shVerify(changed), "tampered proof accepted");
  changed = proofs[0]; changed.bytes.push_back(0);
  Require(!P2shVerify(changed), "trailing proof bytes accepted");
  changed = proofs[0]; changed.circuit_digest[0] ^= 1;
  Require(!P2shVerify(changed), "circuit substitution accepted");
  changed = proofs[0]; changed.position = 3;
  Require(!P2shVerify(changed), "invalid proof position accepted");
  P2shMultisigWitness attacker;
  Require(attacker.compute(f.secrets[0], f.script, 0), "attacker fixture");
  attacker.selectors[0] = p256k1_base.zero(); attacker.selectors[1] = p256k1_base.one();
  P2shMultisigProof forged; forged.hash = attacker.hash; forged.position = 1;
  const bool generated = p2sh_detail::ProveWitness(attacker, &forged);
  Require(!(generated && P2shVerifyPair(proofs[0], forged, attacker.hash)),
          "one secret generated two accepted distinct-position proofs");
  // Same-machine original one-key PoKC end-to-end baseline.
  PoKCWitnessV1<PoKCField, PoKCEC> native;
  Require(native.compute(p256k1, f.secrets[0].data(), 32), "v1 fixture");
  QuietProofStatementV1 s; s.network = QuietProofNetwork::kRegtest;
  s.verifier = "multisig-benchmark"; s.purpose = "proof-of-control";
  s.not_before = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count());
  s.expires_at = s.not_before + 3600;
  s.nonce[0] = 1; s.bip322_message_hash[0] = 1;
  QuietProofClaimV1 claim; claim.txid[0] = 1; claim.amount_sats = 1; claim.program = native.program();
  s.claims = {claim}; QuietProofEnvelopeV1 v1;
  auto start = std::chrono::steady_clock::now();
  Require(PoKCProve(f.secrets[0].data(), f.secrets[0].size(), s, &v1),
          "original PoKC baseline prove");
  const auto prove = Seconds(start); start = std::chrono::steady_clock::now();
  Require(PoKCVerifyProof(v1), "original PoKC baseline verify");
  const auto verify = Seconds(start);
  QuadCircuit<PoKCField> vq(p256k1_base); auto vc = PoKCBuildCircuit(&vq); circuit.clear();
  CircuitWriter<PoKCField>(p256k1_base, SECP_ID).to_bytes(*vc, circuit);
  metrics << "pokc-v1,0," << prove << ',' << verify << ',' << v1.proof.bytes.size()
          << ',' << circuit.size() << ',' << vc->ninputs << ',' << vq.nquad_terms_ << '\n';
  std::cout << "all independent proof and auditor tests passed\n";
}
}  // namespace
}  // namespace proofs
int main(int argc, char** argv) {
  try {
    if (argc == 2 && std::string(argv[1]) == "--proofs") proofs::ProofTests();
    else proofs::CircuitTests();
  } catch (const std::exception& e) { std::cerr << e.what() << '\n'; return 1; }
}
