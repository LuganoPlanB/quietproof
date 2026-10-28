// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include "pokc/prover.h"
#include "quietproof/challenge.h"
#define CHECK(x) do { if (!(x)) { std::cerr << "Failed line " << __LINE__ << ": " #x "\n"; std::exit(1); } } while (0)
using namespace proofs;
int main(int argc, char** argv) {
  CHECK(argc == 2);
  const std::filesystem::path directory(argv[1]); std::filesystem::create_directories(directory);
  // Public disposable scalar 1. This is a native test generator, never
  // compiled into the browser reactor or transferred to a worker.
  std::array<uint8_t,32> secret{}; secret[31]=1;
  PoKCWitnessV1<PoKCField,PoKCEC> witness; CHECK(witness.compute(p256k1,secret.data(),32));
  QuietProofClaimV1 claim; claim.txid.fill(0x11); claim.vout=0;
  claim.amount_sats=50000; claim.program=witness.program();
  QuietProofChallengeOptions options; options.network=QuietProofNetwork::kMainnet;
  options.verifier="browser-feasibility.example"; options.purpose="proof-of-funds";
  options.message="public browser feasibility fixture"; options.lifetime_seconds=86400;
  QuietProofStatementV1 statement; CHECK(CreateQuietProofChallenge({claim},options,&statement));
  QuietProofEnvelopeV1 proof;
  CHECK(PoKCProve(secret,statement,&proof));
  CHECK(PoKCVerifyProof(proof));
  std::vector<uint8_t> envelope, request;
  CHECK(EncodeQuietProofEnvelope(proof,&envelope)); CHECK(EncodeQuietProofStatement(statement,&request));
  const std::string prefix="one-key";
  auto write=[&](const char* extension,const std::vector<uint8_t>& bytes) {
    std::ofstream file(directory/(prefix+extension),std::ios::binary);
    file.write(reinterpret_cast<const char*>(bytes.data()),bytes.size()); CHECK(file.good());
  };
  write(".qpf",envelope); write(".qpr",request);
  std::ofstream provenance(directory/(prefix+".json"));
  provenance << "{\"generator\":\"tests/wasm/proof_fixtures.cc\",\"publicDisposableScalars\":[1"
    << "],\"network\":\"" << QuietProofNetworkName(statement.network) << "\",\"statementVersion\":" << unsigned(statement.statement_version)
    << ",\"createdAt\":" << proof.proof_created_at << ",\"expiresAt\":" << statement.expires_at << ",\"envelopeBytes\":" << envelope.size()
    << ",\"requestBytes\":" << request.size() << ",\"nativeVerified\":true}\n";
  CHECK(provenance.good());
  std::cout << prefix << ": generated and natively verified " << envelope.size() << " bytes\n";
}
