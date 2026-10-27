// SPDX-License-Identifier: GPL-3.0-or-later
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include "pokc/prover.h"
#include "quietproof/browser_verifier.h"
using namespace proofs;
#define CHECK(x) do { if (!(x)) { std::cerr << "Failed line " << __LINE__ << ": " #x "\n"; std::exit(1); } } while (0)
uint64_t Now() { return std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()); }
std::vector<uint8_t> Evidence(const QuietProofStatementV1& s, uint64_t now) {
  std::vector<uint8_t> out{'Q','W','E','1'};
  const std::string provider = "fixture-explorer";
  QuietProofAppendU16(&out, provider.size()); out.insert(out.end(), provider.begin(), provider.end());
  QuietProofAppendU64(&out, now); out.push_back(static_cast<uint8_t>(s.network));
  for (int i=0;i<2;++i) { out.insert(out.end(),32,7); QuietProofAppendU64(&out,100); }
  QuietProofAppendU16(&out, s.claims.size());
  for (const auto& claim : s.claims) {
    out.insert(out.end(),claim.txid.begin(),claim.txid.end()); QuietProofAppendU32(&out,claim.vout);
    out.push_back(0); QuietProofAppendU64(&out,claim.amount_sats);
    QuietProofAppendU16(&out,22); out.insert(out.end(),{0,20}); out.insert(out.end(),claim.program.begin(),claim.program.end());
    QuietProofAppendU64(&out,10); out.push_back(1);
  }
  return out;
}
int main(int argc, char** argv) {
  CHECK(argc == 2);
  const std::filesystem::path directory(argv[1]); std::filesystem::create_directories(directory);
  std::array<uint8_t,32> secret{}; secret[31]=1; // Public, disposable fixture scalar; never sent to browser.
  PoKCWitnessV1<PoKCField,PoKCEC> witness; CHECK(witness.compute(p256k1,secret.data(),secret.size()));
  QuietProofClaimV1 claim; claim.txid.fill(0x11); claim.vout=2; claim.amount_sats=50000; claim.program=witness.program();
  QuietProofChallengeOptions options; options.network=QuietProofNetwork::kMainnet;
  options.verifier="browser-fixture.example"; options.purpose="proof-of-funds"; options.message="public browser fixture"; options.lifetime_seconds=3600;
  QuietProofStatementV1 statement; CHECK(CreateQuietProofChallenge({claim},options,&statement));
  QuietProofEnvelopeV1 envelope; CHECK(PoKCProve(secret.data(),secret.size(),statement,&envelope));
  std::vector<uint8_t> proof, request; CHECK(EncodeQuietProofEnvelope(envelope,&proof)); CHECK(EncodeQuietProofStatement(statement,&request));
  auto write = [&](const char* name,const std::vector<uint8_t>& bytes) { std::ofstream out(directory/name,std::ios::binary);out.write(reinterpret_cast<const char*>(bytes.data()),bytes.size());CHECK(out.good()); };
  write("one-key.qpf",proof); write("one-key.qpr",request);
  QuietProofBrowserPolicy policy; policy.network=options.network; policy.verifier=options.verifier;
  policy.purpose=options.purpose; policy.message_hash=statement.bip322_message_hash;
  policy.expected_request=request; policy.max_lifetime=3600; policy.min_confirmations=1;
  policy.minimum_total=50000; policy.max_observation_age=60; policy.provider="fixture-explorer";
  auto prepare = [&](const QuietProofEnvelopeV1& e, const QuietProofBrowserPolicy& p, uint64_t now) {
    QuietProofBrowserVerification v; return v.Prepare(e,p,now);
  };
  const uint64_t now=Now();
  for (int test=0;test<7;++test) {
    auto invalid=policy;
    switch(test) {
      case 0: invalid.network=QuietProofNetwork::kSignet; break;
      case 1: invalid.verifier+="wrong"; break;
      case 2: invalid.purpose="proof-of-control"; break;
      case 3: invalid.message_hash[0]^=1; break;
      case 4: invalid.expected_request.back()^=1; break;
      case 5: invalid.max_lifetime=1; break;
      case 6: invalid.max_lifetime=0; break;
    }
    CHECK(!prepare(envelope,invalid,now));
  }
  CHECK(!prepare(envelope,policy,statement.expires_at));
  CHECK(!prepare(envelope,policy,statement.not_before-1));
  auto unsupported=envelope; unsupported.statement.has_snapshot=true; unsupported.statement.snapshot.fill(1);
  CHECK(!prepare(unsupported,policy,now));
  unsupported=envelope; unsupported.statement.has_bridge_binding=true;
  CHECK(!prepare(unsupported,policy,now));
  auto wrong_circuit=envelope; wrong_circuit.proof.circuit_digest[0]^=1;
  QuietProofBrowserVerification rejected; CHECK(rejected.Prepare(std::move(wrong_circuit),policy,now)); CHECK(!rejected.Verify(now));
  QuietProofBrowserVerification valid; CHECK(valid.Prepare(envelope,policy,now)); CHECK(valid.Verify(Now()));
  CHECK(valid.outcome().crypto==QuietProofBrowserCrypto::kValid);
  CHECK(valid.phase()==QuietProofBrowserVerification::Phase::kVerified);
  auto observations=Evidence(statement,Now()); write("one-key.evidence",observations);
  auto checked=valid; CHECK(checked.Evaluate(observations,Now()));
  CHECK(checked.outcome().explorer==QuietProofExplorerResult::kReportedUnspent);
  CHECK(checked.outcome().total_sats==50000); CHECK(!checked.Evaluate(observations,Now()));
  checked=valid; CHECK(!checked.Verify(Now()));
  checked=valid; CHECK(!checked.Evaluate(observations,statement.expires_at));
  // Each independent invalid observation starts from a genuinely verified copy.
  const size_t provider_size=16, observed=4+2+provider_size, network=observed+8;
  const size_t claims=network+1+80+2, status=claims+32+4, amount=status+1, script=amount+8+2;
  for (size_t offset : {size_t(6),network,network+1,network+33,claims,claims+32,amount,script,script+2}) {
    auto invalid=observations; invalid[offset]^=1; checked=valid;
    CHECK(checked.Evaluate(invalid,Now())); CHECK(checked.outcome().explorer==QuietProofExplorerResult::kInconclusive);
  }
  auto unconfirmed=observations; unconfirmed[script+22+7]=0; checked=valid;
  CHECK(checked.Evaluate(unconfirmed,Now())); CHECK(checked.outcome().explorer==QuietProofExplorerResult::kInconclusive);
  auto spent=observations; spent[status]=1; checked=valid; CHECK(checked.Evaluate(spent,Now()));
  CHECK(checked.outcome().explorer==QuietProofExplorerResult::kReportedSpent);
  checked=valid; CHECK(checked.Evaluate(observations,Now()+61)); CHECK(checked.outcome().explorer==QuietProofExplorerResult::kInconclusive);
  auto malformed=observations; malformed.push_back(1); checked=valid; CHECK(!checked.Evaluate(malformed,Now()));
  CHECK(!checked.Evaluate(observations,Now()));
  auto mutated=envelope; mutated.proof.bytes.back()^=1;
  QuietProofBrowserVerification invalid; CHECK(invalid.Prepare(std::move(mutated),policy,Now())); CHECK(invalid.Verify(Now()));
  CHECK(invalid.outcome().crypto==QuietProofBrowserCrypto::kInvalid);
  CHECK(!invalid.Evaluate(observations,Now()));
  std::ofstream provenance(directory/"provenance.json");
  provenance << "{\"generator\":\"tests/wasm/verifier_test.cc\",\"secret\":\"public disposable secp256k1 scalar 1\",\"message\":\"public browser fixture\",\"createdAt\":" << envelope.proof_created_at << ",\"expiresAt\":" << statement.expires_at << ",\"proofBytes\":" << proof.size() << "}\n";
  CHECK(provenance.good());
  std::cout << "Real one-key proof: native valid/mutated parity, independent policy and explorer/phase cases passed\n";
}
