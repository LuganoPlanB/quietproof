// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Explicit real-proof benchmark, using only disposable test authorisations.
#include <chrono>
#include <fstream>
#include <iostream>
#include <stdexcept>
#if defined(__linux__)
#include <sys/resource.h>
#endif
#include "cli/json.hpp"
#include "pokc/prover.h"
#include "poksig/prover.h"

namespace {
using namespace proofs;
using Clock = std::chrono::steady_clock;
void Require(bool ok) {
  if (!ok) throw std::runtime_error("benchmark operation failed");
}
double Seconds(Clock::time_point start) {
  return std::chrono::duration<double>(Clock::now() - start).count();
}
uint64_t Now() {
  return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now().time_since_epoch()).count();
}
std::vector<uint8_t> Unhex(const std::string& text) {
  Require(text.size() % 2 == 0 && text.size() <= 8192);
  std::vector<uint8_t> bytes;
  for (size_t i = 0; i < text.size(); i += 2) {
    const auto part = text.substr(i, 2);
    Require(part.find_first_not_of("0123456789abcdef") == std::string::npos);
    bytes.push_back(static_cast<uint8_t>(std::stoul(part, nullptr, 16)));
  }
  return bytes;
}
template <class Bytes> std::string Hex(const Bytes& bytes) {
  constexpr char hex[] = "0123456789abcdef";
  std::string result;
  for (uint8_t byte : bytes) { result += hex[byte >> 4]; result += hex[byte & 15]; }
  return result;
}
nlohmann::json Run(const nlohmann::json& fixture, bool signature, unsigned rounds) {
  const auto request = Unhex(fixture.at("request"));
  QuietProofSignatureStatementV3 expected;
  Require(DecodeQuietProofSignatureStatement(request, &expected));
  Require(expected.claims.size() == 1 &&
          expected.claims.front().script_kind == QuietProofScriptKind::kP2wpkh);
  QuietProofStatementV1 scalar;
  scalar.network = expected.network; scalar.verifier = expected.verifier;
  scalar.purpose = expected.purpose; scalar.nonce = expected.nonce;
  scalar.bip322_message_hash = expected.bip322_message_hash;
  scalar.not_before = expected.not_before; scalar.expires_at = expected.expires_at;
  scalar.claims = expected.claims;
  // Publicly known, disposable scalar 1. Never use a funded key with this tool.
  std::array<uint8_t, 32> secret{}; secret.back() = 1;
  const auto receipt = signature ? Unhex(fixture.at("receipt")) : std::vector<uint8_t>{};
  nlohmann::json rows = nlohmann::json::array();
  for (unsigned i = 0; i < rounds; ++i) {
    std::cerr << (signature ? "posc" : "pokc") << " round " << i + 1 << " proving\n";
    auto start = Clock::now();
    size_t proof_bytes = 0, envelope_bytes = 0;
    double prove = 0, verify = 0;
    if (signature) {
      PoKSigProofV1 proof; PoKSigError error;
      Require(PoKSigProveReceipt(request, receipt, &proof, {true}, &error));
      prove = Seconds(start);
      start = Clock::now();
      Require(PoKSigVerifyProof(request, proof, Now(), {true}, &error));
      verify = Seconds(start);
      QuietProofSignatureEnvelopeMetadataV3 metadata;
      Require(InspectQuietProofSignatureEnvelope(proof.bytes, &metadata));
      proof_bytes = metadata.proof_size; envelope_bytes = proof.bytes.size();
    } else {
      QuietProofEnvelopeV1 proof; std::vector<uint8_t> wire;
      Require(PoKCProve(secret, scalar, &proof) && EncodeQuietProofEnvelope(proof, &wire));
      prove = Seconds(start);
      start = Clock::now();
      QuietProofEnvelopeV1 parsed;
      Require(DecodeQuietProofEnvelope(wire, &parsed) && PoKCVerifyProof(parsed));
      verify = Seconds(start);
      proof_bytes = proof.proof.bytes.size(); envelope_bytes = wire.size();
    }
    rows.push_back({{"round", i + 1}, {"prove_s", prove}, {"verify_s", verify},
                    {"proof_bytes", proof_bytes}, {"envelope_bytes", envelope_bytes},
                    {"verified", true}});
    std::cerr << "proved=" << prove << "s verified=" << verify << "s\n";
  }
  // Inspect shape AFTER timing, so first prove includes lazy identity work.
  QuadCircuit<Fp256k1Base> quad(p256k1_base);
  const auto circuit = signature ? SignaturePossessionBuildCircuit(&quad) : PoKCBuildCircuit(&quad);
  std::vector<uint8_t> bytes;
  CircuitWriter<Fp256k1Base>(p256k1_base, SECP_ID).to_bytes(*circuit, bytes);
  std::vector<uint8_t> scalar_request;
  Require(EncodeQuietProofStatement(scalar, &scalar_request));
  nlohmann::json report = {{"relation", signature ? "PoSC" : "PoKC"}, {"claims", 1}, {"keys", 1},
    {"script_kind", "p2wpkh"}, {"rate", 4}, {"queries", 128}, {"rows", rows},
    {"request_bytes", signature ? request.size() : scalar_request.size()},
    {"circuit_bytes", bytes.size()}, {"public_inputs", circuit->npub_in},
    {"inputs", circuit->ninputs}, {"quad_terms", quad.nquad_terms_},
    {"crt_block_enc", circuit->ninputs - circuit->npub_in + quad.nquad_terms_ + 1},
    {"circuit_digest", Hex(signature ? PoKSigCircuitDigest(*circuit) :
                                      PoKCCircuitDigest(*circuit, p256k1_base, SECP_ID))}};
#if defined(__linux__)
  rusage usage{}; Require(getrusage(RUSAGE_SELF, &usage) == 0);
  report["process_peak_rss_bytes"] = static_cast<uint64_t>(usage.ru_maxrss) * 1024;
#endif
  return report;
}
}  // namespace
int main(int argc, char** argv) {
  try {
    Require(argc == 4);
    const std::string mode = argv[2];
    Require(mode == "pokc" || mode == "posc");
    const std::string count = argv[3];
    Require(count.size() == 1 && count[0] >= '1' && count[0] <= '9');
    std::ifstream file(argv[1]); nlohmann::json fixture; file >> fixture;
    std::cout << Run(fixture, mode == "posc", count[0] - '0').dump(2) << '\n';
    return 0;
  } catch (...) {
    // Never include parser excerpts of the private fixture in diagnostics.
    std::cerr << "relation benchmark failed\n"; return 1;
  }
}
