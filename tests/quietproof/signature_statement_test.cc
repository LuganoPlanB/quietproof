// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include <fstream>
#include <iostream>
#include <stdexcept>

#include "cli/json.hpp"
#include "pokc/prover.h"
#include "quietproof/browser.h"
#include "quietproof/signature_challenge.h"
#include "quietproof/verifier.h"

namespace {
using namespace proofs;
size_t checks = 0;
void Require(bool value, const char* message) {
  ++checks;
  if (!value) throw std::runtime_error(message);
}
std::vector<uint8_t> Unhex(const std::string& text) {
  std::vector<uint8_t> out;
  for (size_t i = 0; i < text.size(); i += 2)
    out.push_back(static_cast<uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
  return out;
}
std::vector<uint8_t> Encode(const QuietProofSignatureStatementV3& s) {
  std::vector<uint8_t> bytes;
  Require(EncodeQuietProofSignatureStatement(s, &bytes), "encode valid v3");
  return bytes;
}
void RejectWire(const std::vector<uint8_t>& bytes, QuietProofDecodeError expected,
                const QuietProofSignatureStatementV3& sentinel) {
  auto decoded = sentinel;
  auto error = QuietProofDecodeError::kNone;
  Require(!DecodeQuietProofSignatureStatement(bytes, &decoded, &error), "invalid wire accepted");
  Require(error == expected, "wrong wire failure category");
  Require(Encode(decoded) == Encode(sentinel), "failed decode changed output");
}
void RejectValue(const QuietProofSignatureStatementV3& s) {
  std::vector<uint8_t> output{0xaa};
  const auto before = output;
  std::array<uint8_t, 32> digest;
  digest.fill(0xaa);
  const auto before_digest = digest;
  Require(!QuietProofSignatureStatementValid(s) &&
      !EncodeQuietProofSignatureStatement(s, &output) && output == before &&
      !QuietProofSignatureStatementDigest(s, &digest) && digest == before_digest,
      "invalid value accepted or failure changed output");
}
void TestFixture(const nlohmann::json& vector) {
  const auto bytes = Unhex(vector.at("request_hex"));
  QuietProofSignatureStatementV3 statement;
  auto error = QuietProofDecodeError::kMalformed;
  Require(DecodeQuietProofSignatureStatement(bytes, &statement, &error) &&
      error == QuietProofDecodeError::kNone && Encode(statement) == bytes,
      "independent L1 request bytes differ");
  const auto expected_digest = Unhex(vector.at("d"));
  std::array<uint8_t, 32> digest;
  Require(QuietProofSignatureStatementDigest(statement, &digest) &&
      std::equal(digest.begin(), digest.end(), expected_digest.begin()), "L1 digest differs");
  Require(statement.signing_kind == vector.at("request").at("signing_kind").get<QuietProofScriptKind>(),
      "selected kind changed");
  QuietProofStatementV1 old;
  std::vector<uint8_t> old_output{0xaa};
  Require(!DecodeQuietProofStatement(bytes, &old, &error) &&
      error == QuietProofDecodeError::kUnsupported &&
      !QuietProofStatementValid(statement) && !EncodeQuietProofStatement(statement, &old_output) &&
      old_output == std::vector<uint8_t>{0xaa} &&
      !QuietProofStatementDigest(statement, &digest), "v3 reached old statement API");
  for (size_t n = 0; n < bytes.size(); ++n)
    RejectWire({bytes.begin(), bytes.begin() + n}, QuietProofDecodeError::kMalformed, statement);
  auto changed = bytes;
  changed.push_back(0);
  RejectWire(changed, QuietProofDecodeError::kMalformed, statement);
  RejectWire(std::vector<uint8_t>(4097, 0), QuietProofDecodeError::kMalformed, statement);
  for (size_t offset : {size_t{4}, size_t{5}, size_t{6}, size_t{7}, size_t{8}, size_t{9}}) {
    changed = bytes;
    changed[offset] = 0xff;
    RejectWire(changed, QuietProofDecodeError::kUnsupported, statement);
  }
  changed = bytes; changed[6] = 0;
  RejectWire(changed, QuietProofDecodeError::kMalformed, statement);
  changed[8] = 2;
  RejectWire(changed, QuietProofDecodeError::kUnsupported, statement);
  for (const auto& field : vector.at("fields")) {
    const auto name = field.at("field").get<std::string>();
    const auto offset = field.at("offset").get<size_t>();
    if (name == "bridge_present" || name == "snapshot_present") {
      changed = bytes; changed[offset] = 2;
      RejectWire(changed, QuietProofDecodeError::kMalformed, statement);
    }
    if (name.find("script_kind") != std::string::npos) {
      changed = bytes; changed[offset] = 2;
      RejectWire(changed, QuietProofDecodeError::kUnsupported, statement);
      changed[6] = 0;
      RejectWire(changed, QuietProofDecodeError::kUnsupported, statement);
    }
    if (name == "verifier.length" || name == "purpose.length" || name == "claim_count") {
      changed = bytes; changed[offset] = 0xff;
      RejectWire(changed, QuietProofDecodeError::kMalformed, statement);
    }
  }
  // Every accepted single-byte mutation has one exact encoding and a distinct d.
  for (size_t i = 0; i < bytes.size(); ++i) {
    changed = bytes; changed[i] ^= 1;
    QuietProofSignatureStatementV3 mutated;
    if (!DecodeQuietProofSignatureStatement(changed, &mutated)) continue;
    std::array<uint8_t, 32> mutated_digest;
    Require(Encode(mutated) == changed && QuietProofSignatureStatementDigest(mutated, &mutated_digest) &&
        !std::equal(mutated_digest.begin(), mutated_digest.end(), expected_digest.begin()),
        "accepted mutation is noncanonical or unbound");
  }
  auto bad = statement;
  bad.signing_kind = static_cast<QuietProofScriptKind>(2); RejectValue(bad);
  bad = statement; bad.claims.resize(1); bad.signing_kind = QuietProofScriptKind::kP2pkh; RejectValue(bad);
  bad = statement; bad.claims[1].txid = bad.claims[0].txid; bad.claims[1].vout = bad.claims[0].vout; RejectValue(bad);
  bad = statement; std::swap(bad.claims[0], bad.claims[1]); RejectValue(bad);
  bad = statement; bad.claims[1].program[0] ^= 1; RejectValue(bad);
  bad = statement; bad.claims[0].txid.fill(0); RejectValue(bad);
  bad = statement; bad.claims[0].amount_sats = 0; RejectValue(bad);
  bad = statement; bad.claims[0].amount_sats = kQuietProofMaxMoneySats; RejectValue(bad);
  bad = statement; bad.claims.clear(); RejectValue(bad);
  bad = statement; bad.claims.resize(17, statement.claims[0]); RejectValue(bad);
  bad = statement; bad.has_snapshot = false; bad.snapshot[0] = 1; RejectValue(bad);
  bad = statement; bad.purpose = "bridge-authorization"; RejectValue(bad);
  bad = statement; bad.has_bridge_binding = true; RejectValue(bad);
  bad = statement; bad.bridge.asset_id = "ignored"; RejectValue(bad);
  bad = statement; bad.nonce.fill(0); RejectValue(bad);
  bad = statement; bad.bip322_message_hash.fill(0); RejectValue(bad);
  bad = statement; bad.expires_at = bad.not_before; RejectValue(bad);
  for (const auto& text : {std::string(), std::string(257, 'a'), std::string("\xc0\x80", 2),
                          std::string("bad\x7f", 4), std::string("bad\n")}) {
    bad = statement; bad.verifier = text; RejectValue(bad);
  }
  bad = statement; bad.statement_version = 2; RejectValue(bad);
  // Decode the same invalid common-field cases rather than only testing the
  // in-memory validator. Each record is fixed-width 65 bytes in v3.
  const auto count_field = std::find_if(vector.at("fields").begin(), vector.at("fields").end(),
      [](const auto& field) { return field.at("field") == "claim_count"; });
  const size_t count_offset = count_field->at("offset").template get<size_t>();
  const size_t first = count_offset + 2, second = first + 65;
  changed = bytes;
  std::copy_n(bytes.begin() + first, 36, changed.begin() + second);
  RejectWire(changed, QuietProofDecodeError::kMalformed, statement);
  changed = bytes;
  std::swap_ranges(changed.begin() + first, changed.begin() + second, changed.begin() + second);
  RejectWire(changed, QuietProofDecodeError::kMalformed, statement);
  changed = bytes; changed[second + 45] ^= 1;
  RejectWire(changed, QuietProofDecodeError::kMalformed, statement);
  changed = bytes; std::fill_n(changed.begin() + first + 36, 8, 0);
  RejectWire(changed, QuietProofDecodeError::kMalformed, statement);
  changed = bytes; changed[count_offset + 1] = 1; changed.resize(second); changed[9] = 1;
  RejectWire(changed, QuietProofDecodeError::kMalformed, statement);
  auto max = statement;
  max.claims.assign(16, statement.claims[0]);
  for (size_t i = 0; i < max.claims.size(); ++i) {
    max.claims[i].txid.fill(1); max.claims[i].vout = static_cast<uint32_t>(i);
  }
  max.signing_kind = QuietProofScriptKind::kP2wpkh;
  max.claims.back().amount_sats = kQuietProofMaxMoneySats - 15 * max.claims[0].amount_sats;
  Require(QuietProofSignatureStatementValid(max) && Encode(max).size() <= 4096, "valid maximum rejected");

  // Old proof APIs reject immediately, before circuit/proof work or progress.
  QuietProofEnvelopeV1 envelope;
  envelope.statement = statement;
  envelope.envelope_version = 2;
  envelope.proof_created_at = statement.not_before + 1;
  bool progress = false;
  Require(!QuietProofEnvelopeTimeValid(envelope) && !PoKCProofSupported(envelope) &&
      !PoKCVerifyProof(envelope) &&
      !PoKCProve(std::array<uint8_t, 32>{}, statement, &envelope,
                 [&](const char*) { progress = true; }) && !progress,
      "signature request reached scalar proof API");
  std::vector<uint8_t> metadata;
  // L8 adds public v3 metadata inspection in either build. Inspection carries
  // the exact request and no proof/circuit result; the scalar prove/verify and
  // envelope APIs above and below must continue rejecting signature statements.
  Require(QuietProofBrowserInspect(bytes, false, &metadata) && metadata.size() == bytes.size() + 61 &&
      std::equal(metadata.begin(), metadata.begin() + 4, std::array<uint8_t,4>{'Q','W','I','1'}.begin()) &&
      metadata[4] == 0 && std::equal(bytes.begin(), bytes.end(), metadata.begin() + 61),
      "public v3 inspection did not preserve the unverified request");
  for (uint8_t version : {uint8_t{1}, uint8_t{2}}) {
    std::vector<uint8_t> wire{'Q','P','E','1',version};
    QuietProofAppendU32(&wire, static_cast<uint32_t>(bytes.size()));
    wire.insert(wire.end(), bytes.begin(), bytes.end());
    if (version == 2) QuietProofAppendU64(&wire, statement.not_before + 1);
    wire.insert(wire.end(), 32, 1);
    for (uint32_t n : {1u,4u,128u,1u}) QuietProofAppendU32(&wire,n);
    wire.push_back(1);
    Require(!DecodeQuietProofEnvelope(wire, &envelope, &error) && error == QuietProofDecodeError::kMalformed,
        "old envelope reinterpreted v3");
    bool called = false;
    QuietProofVerifierConfig config;
    config.verify_proof = [&](const auto&) { called = true; return true; };
    Require(VerifyQuietProof(wire, config).result == QuietProofVerifyResult::kMalformedStatement && !called,
        "cross-mode envelope reached verifier callback");
    wire[9 + 9] = 2;
    Require(!DecodeQuietProofEnvelope(wire, &envelope, &error) && error == QuietProofDecodeError::kUnsupported,
        "unknown nested signing kind misclassified");
  }

  QuietProofSignatureChallengeOptions options;
  options.request = {statement.network, statement.verifier, statement.purpose, "test"};
  options.signing_kind = statement.signing_kind;
  auto output = statement;
  auto challenge_error = QuietProofSignatureChallengeError::kNone;
  size_t random_calls = 0, clock_calls = 0;
  const auto build = [&](const auto& claims, const auto& opts) {
    return quietproof_detail::CreateQuietProofSignatureChallengeWithSources(claims, opts, &output,
        &challenge_error, [&](uint64_t* now) { ++clock_calls; *now = 100; return true; },
        [&](void* p, size_t size) { ++random_calls; std::memset(p, 1, size); return 0; });
  };
  auto reversed = statement.claims;
  std::reverse(reversed.begin(), reversed.end());
  if (kQuietProofSignatureModeEnabled) {
    Require(build(reversed, options) && output.statement_version == 3 &&
        output.not_before == 100 && output.expires_at == 400 && output.claims == statement.claims &&
        random_calls == 1 && clock_calls == 1, "explicit signature challenge failed");
    Require(CreateQuietProofSignatureChallenge(statement.claims, options, &output), "production builder failed");
    const auto before = Encode(output);
    const auto fixed_random = [](void* p, size_t n) { std::memset(p, 1, n); return 0; };
    const auto clock_failure = +[](uint64_t*) { return false; };
    const auto clock_overflow = +[](uint64_t* now) { *now = UINT64_MAX; return true; };
    for (const auto clock : {clock_failure, clock_overflow}) {
      Require(!quietproof_detail::CreateQuietProofSignatureChallengeWithSources(
          statement.claims, options, &output, &challenge_error, clock, fixed_random) &&
          challenge_error == QuietProofSignatureChallengeError::kClock && Encode(output) == before,
          "clock failure changed output or validity window overflowed");
    }
    const auto fixed_clock = [](uint64_t* now) { *now = 1; return true; };
    Require(!quietproof_detail::CreateQuietProofSignatureChallengeWithSources(
        statement.claims, options, &output, &challenge_error, fixed_clock,
        [](void*, size_t) { return 1; }) &&
        challenge_error == QuietProofSignatureChallengeError::kRandom && Encode(output) == before,
        "random failure changed output");
    size_t zero_calls = 0;
    Require(!quietproof_detail::CreateQuietProofSignatureChallengeWithSources(
        statement.claims, options, &output, &challenge_error, fixed_clock,
        [&](void* p, size_t n) { ++zero_calls; std::memset(p, 0, n); return 0; }) &&
        challenge_error == QuietProofSignatureChallengeError::kRandom && zero_calls == 4 && Encode(output) == before,
        "zero nonce accepted or unbounded retry");
  } else {
    Require(!build(reversed, options) && challenge_error == QuietProofSignatureChallengeError::kSignatureModeDisabled &&
        std::string(QuietProofSignatureChallengeErrorName(challenge_error)) == "signature_mode_disabled" &&
        Encode(output) == bytes && random_calls == 0 && clock_calls == 0, "disabled builder ran sources or changed output");
  }
  options.signing_kind = static_cast<QuietProofScriptKind>(2);
  Require(!build(statement.claims, options) && challenge_error == QuietProofSignatureChallengeError::kInvalidOptions,
      "unknown selection accepted or disabled outranked invalid options");
  options.signing_kind = QuietProofScriptKind::kP2pkh;
  Require(!build(std::vector<QuietProofClaimV1>{statement.claims[0]}, options) &&
      challenge_error == QuietProofSignatureChallengeError::kInvalidClaims, "descriptor alias inferred");
  options.request.purpose = "bridge-authorization";
  Require(!build(statement.claims, options) && challenge_error == QuietProofSignatureChallengeError::kInvalidOptions,
      "bridge creation accepted");
  options.request.purpose = statement.purpose;
  options.request.lifetime_seconds = 86401;
  Require(!build(statement.claims, options) && challenge_error == QuietProofSignatureChallengeError::kInvalidOptions,
      "unbounded challenge lifetime");
}
}  // namespace
int main(int argc, char** argv) {
  try {
    Require(argc == 2, "expected frozen profile fixture path");
    std::ifstream input(argv[1]);
    nlohmann::json fixture; input >> fixture;
    for (const auto& vector : fixture.at("vectors")) TestFixture(vector);
    std::cout << checks << " signature statement checks passed; capability="
              << kQuietProofSignatureModeEnabled << '\n';
    return 0;
  } catch (const std::exception& e) {
    std::cerr << "not ok: " << e.what() << '\n'; return 1;
  }
}
