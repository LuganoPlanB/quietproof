// SPDX-License-Identifier: GPL-3.0-or-later
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include "cli/json.hpp"
#include "poksig/prover.h"
#include "quietproof/browser_verifier.h"
using namespace proofs;
#define CHECK(x) do { if (!(x)) { std::cerr << "Failed line " << __LINE__ << ": " #x "\n"; std::exit(1); } } while (0)
std::vector<uint8_t> Unhex(const std::string& value) {
  std::vector<uint8_t> out;
  for (size_t i=0; i<value.size(); i+=2) out.push_back(std::stoul(value.substr(i,2),nullptr,16));
  return out;
}
uint64_t Now() { return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); }
int main(int argc, char** argv) {
  CHECK(argc == 3 || argc == 4);
  const bool disabled = argc == 4;
  CHECK(disabled != kQuietProofSignatureModeEnabled);
  std::ifstream input(argv[1]); nlohmann::json cases; input >> cases;
  const std::filesystem::path directory(argv[2]);
  size_t verified = 0;
  for (const auto& row : cases) {
    const auto request = Unhex(row.at("request"));
    QuietProofSignatureStatementV4 s; CHECK(DecodeQuietProofSignatureStatement(request,&s));
    CHECK(!s.has_snapshot);
    QuietProofBrowserPolicy p; p.allow_signature_possession=true;
    p.network=s.network; p.verifier=s.verifier; p.purpose=s.purpose; p.message_hash=s.bip322_message_hash;
    p.expected_request=request; p.max_lifetime=86400; p.max_observation_age=60;
    QuietProofSignatureEnvelopeMetadataV4 m; m.request=request;
    m.proof_created_at=Now(); m.circuit_digest=PoKSigExpectedCircuitDigest();
    std::vector<uint8_t> wire; CHECK(EncodeQuietProofSignatureEnvelope(m,{1},&wire));
    QuietProofBrowserVerification check;
    if (disabled) {
      CHECK(!PrepareQuietProofBrowserSignature(&check,wire,p,Now()) && check.unsupported());
      CHECK(std::string(check.error())=="signature_mode_disabled");
      continue;
    }
    auto wrong=p; wrong.allow_signature_possession=false;
    CHECK(!PrepareQuietProofBrowserSignature(&check,wire,wrong,Now()));
    wrong=p; wrong.expected_request.clear(); CHECK(!PrepareQuietProofBrowserSignature(&check,wire,wrong,Now()));
    wrong=p; wrong.expected_request.back()^=1; CHECK(!PrepareQuietProofBrowserSignature(&check,wire,wrong,Now()));
    auto changed=m; changed.circuit_digest[0]^=1;
    CHECK(EncodeQuietProofSignatureEnvelope(changed,{1},&wire));
    CHECK(!PrepareQuietProofBrowserSignature(&check,wire,p,Now()) && check.unsupported());
    PoKSigProofV1 proof;
    std::cout << row.at("name").get<std::string>() << ": proving" << std::endl;
    CHECK(PoKSigProveReceipt(request,Unhex(row.at("receipt")),&proof,{true}));
    if (!PrepareQuietProofBrowserSignature(&check,proof.bytes,p,Now())) {
      std::cerr << "Browser preparation failed: " << check.error() << std::endl;
      CHECK(false);
    }
    CHECK(check.Verify(Now()));
    CHECK(check.outcome().crypto==QuietProofBrowserCrypto::kValid);
    CHECK(check.outcome().explorer==QuietProofExplorerResult::kUnavailable);
    CHECK(!check.RecheckPolicy(s.expires_at));
    const std::string name=row.at("name");
    auto write=[&](const char* extension,const std::vector<uint8_t>& bytes) {
      std::ofstream out(directory/(name+extension),std::ios::binary);
      out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size()); CHECK(out.good());
    };
    write(".qpr",request); write(".qpf",proof.bytes);
    std::vector<uint8_t> metadata; CHECK(QuietProofBrowserInspect(proof.bytes,true,&metadata));
    CHECK(metadata.size()==request.size()+61);
    std::ofstream provenance(directory/(name+".json"));
    provenance << "{\"generator\":\"tests/wasm/signature_fixtures.py\",\"nativeVerified\":true,\"witnessExported\":false,\"createdAt\":"
      << Now() << ",\"expiresAt\":" << s.expires_at << ",\"envelopeBytes\":" << proof.bytes.size()
      << ",\"claimCount\":" << s.claims.size() << ",\"proofMode\":\"signature-possession\"}\n";
    CHECK(provenance.good()); ++verified;
    std::cout << name << ": native browser verifier valid" << std::endl;
  }
  CHECK(!cases.empty());
  CHECK(verified==(disabled ? 0u : cases.size()));
  std::cout << "signature browser fixtures=" << verified << " failed=0 disabled=" << disabled << std::endl;
}
