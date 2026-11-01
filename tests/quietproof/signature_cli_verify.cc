// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
// Cryptographic-only test oracle for CLI public output; no funds acceptance.
#include <fstream>
#include <iostream>
#include "poksig/verifier.h"
#include "quietproof/envelope.h"
namespace {
bool Read(const char* path, size_t maximum, std::vector<uint8_t>* bytes) {
  std::ifstream input(path, std::ios::binary);
  std::array<char,4096> buffer{};
  while (input) {
    input.read(buffer.data(), buffer.size());
    const auto size = input.gcount();
    if (size < 0 || static_cast<size_t>(size) > maximum - bytes->size()) return false;
    bytes->insert(bytes->end(), buffer.data(), buffer.data()+size);
  }
  return input.eof();
}
}
int main(int argc, char** argv) {
  using namespace proofs;
  try {
    if (argc != 3) return 1;
    std::vector<uint8_t> request;
    PoKSigProofV1 proof;
    if (!Read(argv[1], kQuietProofMaxStatementBytes, &request) ||
        !Read(argv[2], kQuietProofMaxEnvelopeBytes, &proof.bytes)) return 1;
    PoKSigOptionsV1 policy;
    policy.allow_signature_possession = true;
    PoKSigError error;
    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if (now < 0 || !PoKSigVerifyProof(request, proof, static_cast<uint64_t>(now), policy, &error)) return 1;
    std::cout << "signature proof cryptography verified; funds acceptance separate\n";
    return 0;
  } catch (...) { return 1; }
}
