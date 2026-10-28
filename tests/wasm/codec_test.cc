// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include "quietproof/browser.h"
using namespace proofs;
#define CHECK(x) do { if (!(x)) { std::cerr << "Failed line " << __LINE__ << ": " #x "\n"; std::exit(1); } } while (0)

std::vector<uint8_t> Options(const std::vector<QuietProofClaimV1>& claims) {
  std::vector<uint8_t> out{'Q','W','C','1',2};
  QuietProofAppendU64(&out, 300);
  for (const std::string text : {"golden.example", "proof-of-funds", "public test message"}) {
    QuietProofAppendU16(&out, text.size());
    out.insert(out.end(), text.begin(), text.end());
  }
  QuietProofAppendU16(&out, claims.size());
  for (const auto& claim : claims) {
    out.insert(out.end(), claim.txid.begin(), claim.txid.end());
    QuietProofAppendU32(&out, claim.vout); QuietProofAppendU64(&out, claim.amount_sats);
    out.push_back(static_cast<uint8_t>(claim.script_kind));
    out.insert(out.end(), claim.program.begin(), claim.program.end());
  }
  return out;
}
int main(int argc, char** argv) {
  const auto clock = [](uint64_t* now) { *now = 1700000000; return true; };
  const auto random = [](uint8_t* out, size_t size) { std::memset(out, 7, size); return 0; };
  auto write = [&](const std::string& name, const std::vector<uint8_t>& bytes) {
    if (argc == 2) {
      std::filesystem::create_directories(argv[1]);
      std::ofstream file(std::filesystem::path(argv[1]) / name, std::ios::binary);
      file.write(reinterpret_cast<const char*>(bytes.data()), bytes.size()); CHECK(file.good());
    }
  };
  for (int mode = 0; mode < 3; ++mode) {
    std::vector<QuietProofClaimV1> claims(2);
    for (int i = 0; i < 2; ++i) {
      claims[i].txid.fill(2 - i); claims[i].program.fill(3);
      claims[i].vout = UINT32_MAX; claims[i].amount_sats = 50000 + i;
      if (mode == 1 || (mode == 2 && i)) claims[i].script_kind = QuietProofScriptKind::kP2pkh;
    }
    const auto wire = Options(claims);
    QuietProofChallengeOptions options; std::vector<QuietProofClaimV1> parsed;
    CHECK(DecodeQuietProofBrowserOptions(wire, &options, &parsed));
    QuietProofStatementV1 statement; QuietProofChallengeError error;
    CHECK(quietproof_detail::CreateQuietProofChallengeWithSources(parsed, options, &statement, &error, clock, random));
    CHECK(statement.statement_version == (mode == 0 ? 1 : 2));
    CHECK(statement.claims.front().txid[0] == 1);
    std::vector<uint8_t> request, inspection;
    CHECK(EncodeQuietProofStatement(statement, &request));
    CHECK(QuietProofBrowserInspect(request, false, &inspection));
    CHECK(inspection.size() == request.size() + 61);
    write(std::to_string(mode) + ".options", wire);
    write(std::to_string(mode) + ".qpr", request);
    QuietProofEnvelopeV1 envelope; envelope.statement = statement;
    envelope.envelope_version = 2; envelope.proof_created_at = 1700000001;
    envelope.proof.circuit_digest.fill(1); envelope.proof.bytes = {1, 2, 3};
    std::vector<uint8_t> proof;
    CHECK(EncodeQuietProofEnvelope(envelope, &proof));
    CHECK(QuietProofBrowserInspect(proof, true, &inspection));
    write(std::to_string(mode) + ".qpf", proof); // Metadata-only, NOT a cryptographic fixture.
    proof.push_back(0); CHECK(!QuietProofBrowserInspect(proof, true, &inspection));
    request.push_back(0); CHECK(!QuietProofBrowserInspect(request, false, &inspection));
    auto invalid = wire; invalid.push_back(0);
    CHECK(!DecodeQuietProofBrowserOptions(invalid, &options, &parsed));
    invalid = wire; invalid[15] = 0xff;
    CHECK(!DecodeQuietProofBrowserOptions(invalid, &options, &parsed));
    CHECK(DecodeQuietProofBrowserOptions(wire, &options, &parsed));
    auto create = [&] { return quietproof_detail::CreateQuietProofChallengeWithSources(parsed, options, &statement, &error, clock, random); };
    options.lifetime_seconds = UINT64_MAX; CHECK(!create()); options.lifetime_seconds = 300;
    parsed[1] = parsed[0]; CHECK(!create()); parsed = claims;
    parsed[0].amount_sats = UINT64_MAX; CHECK(!create()); parsed = claims;
    parsed[0].script_kind = static_cast<QuietProofScriptKind>(2); CHECK(!create()); parsed = claims;
    while (parsed.size() < 16) { auto claim = claims[0]; claim.vout = parsed.size(); parsed.push_back(claim); }
    CHECK(create()); auto extra = claims[0]; extra.vout = 17; parsed.push_back(extra); CHECK(!create());
    parsed = claims; parsed[1].program.fill(8); CHECK(!create());
    parsed = claims; auto third = claims[0]; third.vout = 1; third.program.fill(9);
    parsed[1].program.fill(8); parsed.push_back(third); CHECK(!create());
    parsed = claims;
    CHECK(!quietproof_detail::CreateQuietProofChallengeWithSources(parsed, options, &statement, &error, clock,
      [](uint8_t*, size_t) { return 1; })); CHECK(error == QuietProofChallengeError::kRandom);
    CHECK(!quietproof_detail::CreateQuietProofChallengeWithSources(parsed, options, &statement, &error,
      [](uint64_t*) { return false; }, random)); CHECK(error == QuietProofChallengeError::kClock);
  }
  std::cout << "3 native golden families and codec adversarial checks passed\n";
}
