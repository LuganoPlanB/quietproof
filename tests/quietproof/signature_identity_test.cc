// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include "circuit/signature_possession.h"
#include "poksig/proof.h"

namespace {
template <class T> std::string Hex(const T& bytes) {
  constexpr char hex[] = "0123456789abcdef";
  std::string result;
  for (const auto b : bytes) { result += hex[b >> 4]; result += hex[b & 15]; }
  return result;
}
}
int main(int argc, char** argv) {
  try {
    using namespace proofs;
    if (argc != 1 && argc != 2) throw std::runtime_error("optional new circuit artifact path required");
    QuadCircuit<Fp256k1Base> quad(p256k1_base);
    const auto circuit = SignaturePossessionBuildCircuit(&quad);
    std::vector<uint8_t> bytes;
    CircuitWriter<Fp256k1Base>(p256k1_base, SECP_ID).to_bytes(*circuit, bytes);
    std::array<uint8_t, 32> digest;
    SHA256 hash; hash.Update(bytes.data(), bytes.size()); hash.DigestData(digest.data());
    const auto identity = PoKSigCircuitDigest(*circuit);
    if (identity != PoKSigExpectedCircuitDigest() || bytes.size() != 26519998 ||
        Hex(digest) != "07d62ac962dd0f484828c4075bc64fde3575396b28946bdef52931c6f4234d51")
      throw std::runtime_error("qualified circuit serialization changed");
    if (argc == 2) {
      if (std::filesystem::exists(argv[1])) throw std::runtime_error("circuit artifact already exists");
      std::ofstream output(argv[1], std::ios::binary);
      output.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
      if (!output) throw std::runtime_error("circuit artifact write failed");
    }
    std::cout << "{\"serializedBytes\":" << bytes.size() << ",\"serializationSha256\":\"" << Hex(digest)
              << "\",\"identity\":\"" << Hex(identity) << "\",\"publicInputs\":" << circuit->npub_in
              << ",\"inputs\":" << circuit->ninputs << ",\"block\":"
              << circuit->ninputs - circuit->npub_in + quad.nquad_terms_ + 1 << "}" << std::endl;
    return 0;
  } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
