// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#include "quietproof/challenge.h"

#include <array>
#include <cstdint>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace proofs {
namespace {

void Require(bool condition, const char* message) {
  if (!condition) throw std::runtime_error(message);
}

QuietProofChallengeOptions Options() {
  return {QuietProofNetwork::kSignet, "auditor.example", "proof-of-funds",
          "reserve-test"};
}

QuietProofClaimV1 Claim(uint8_t id = 1) {
  QuietProofClaimV1 claim;
  claim.txid[0] = id;
  claim.amount_sats = 7;
  claim.program[0] = 4;
  return claim;
}

bool FixedClock(uint64_t* now) {
  *now = 100;
  return true;
}

int FixedRandom(void* output, size_t size) {
  auto* bytes = static_cast<uint8_t*>(output);
  for (size_t i = 0; i < size; ++i) bytes[i] = static_cast<uint8_t>(i + 1);
  return 0;
}

bool Build(const std::vector<QuietProofClaimV1>& claims,
           const QuietProofChallengeOptions& options,
           QuietProofStatementV1* output, QuietProofChallengeError* error) {
  return quietproof_detail::CreateQuietProofChallengeWithSources(
      claims, options, output, error, FixedClock, FixedRandom);
}

std::vector<uint8_t> Bytes(const QuietProofStatementV1& statement) {
  std::vector<uint8_t> bytes;
  Require(EncodeQuietProofStatement(statement, &bytes), "invalid test statement");
  return bytes;
}

QuietProofStatementV1 Sentinel() {
  QuietProofStatementV1 statement;
  Require(Build({Claim(9)}, Options(), &statement, nullptr), "sentinel build");
  return statement;
}

void Reject(const std::vector<QuietProofClaimV1>& claims,
            const QuietProofChallengeOptions& options,
            QuietProofChallengeError expected) {
  auto output = Sentinel();
  const auto before = Bytes(output);
  auto error = QuietProofChallengeError::kNone;
  Require(!Build(claims, options, &output, &error), "invalid challenge accepted");
  Require(error == expected, "wrong failure category");
  Require(Bytes(output) == before, "failure changed output");
}

void TestLegacyEquivalence() {
  const auto options = Options();
  const std::vector<QuietProofClaimV1> claims = {Claim(2), Claim(1)};
  // The pre-extraction CLI algorithm, with fixed nonce/time inputs.
  QuietProofStatementV1 legacy;
  legacy.network = options.network;
  legacy.verifier = options.verifier;
  legacy.purpose = options.purpose;
  FixedRandom(legacy.nonce.data(), legacy.nonce.size());
  legacy.bip322_message_hash = QuietProofBip322MessageHash(
      reinterpret_cast<const uint8_t*>(options.message.data()),
      options.message.size());
  legacy.not_before = 100;
  legacy.expires_at = 400;
  legacy.claims = claims;
  std::sort(legacy.claims.begin(), legacy.claims.end());

  QuietProofStatementV1 output;
  auto error = QuietProofChallengeError::kRandom;
  Require(Build(claims, options, &output, &error), "valid challenge rejected");
  Require(error == QuietProofChallengeError::kNone, "success did not clear error");
  Require(Bytes(output) == Bytes(legacy), "legacy request bytes changed");
  QuietProofStatementV1 permuted;
  Require(Build({Claim(1), Claim(2)}, options, &permuted, nullptr) &&
              Bytes(permuted) == Bytes(output), "claim order changed bytes");
  Require(!output.has_snapshot && !output.has_bridge_binding,
          "builder enabled an authorization extension");

  // Independently generated SHA256 of the fixed legacy request bytes.
  const std::array<uint8_t, 32> expected_digest = {
      0x04, 0x09, 0x23, 0xd6, 0xb8, 0x04, 0x39, 0x4b,
      0xd3, 0x35, 0x1c, 0xcf, 0xf8, 0x8d, 0x12, 0xa6,
      0x8d, 0x42, 0x1e, 0x0f, 0xad, 0xf5, 0xde, 0x08,
      0x3e, 0xc6, 0x0f, 0x3d, 0xfc, 0xc3, 0xb8, 0xf8};
  const auto wire = Bytes(output);
  std::array<uint8_t, 32> digest{};
  SHA256 hash;
  hash.Update(wire.data(), wire.size());
  hash.DigestData(digest.data());
  Require(wire.size() == 251 && digest == expected_digest,
          "fixed legacy wire vector changed");
}

void TestTypedSelection() {
  auto first = Claim(1), second = Claim(2);
  second.script_kind = QuietProofScriptKind::kP2pkh;
  QuietProofStatementV1 statement;
  Require(Build({second, first}, Options(), &statement, nullptr) &&
              statement.statement_version == 2 && statement.claims[0] == first &&
              statement.claims[1].script_kind == QuietProofScriptKind::kP2pkh,
          "builder did not select typed mixed statement");
  second.txid = first.txid;
  Reject({first, second}, Options(), QuietProofChallengeError::kInvalidClaims);
  second = Claim(2);
  second.script_kind = static_cast<QuietProofScriptKind>(2);
  Reject({second}, Options(), QuietProofChallengeError::kInvalidClaims);
}

void TestMissingNetwork() {
  QuietProofChallengeOptions default_constructed;
  QuietProofChallengeOptions value_initialized{};
  for (auto* options : {&default_constructed, &value_initialized}) {
    options->verifier = "auditor.example";
    options->purpose = "proof-of-funds";
    options->message = "reserve-test";
    auto output = Sentinel();
    const auto before = Bytes(output);
    auto error = QuietProofChallengeError::kNone;
    int clock_calls = 0, random_calls = 0;
    const auto clock = [&clock_calls](uint64_t* now) {
      ++clock_calls;
      return FixedClock(now);
    };
    const auto random = [&random_calls](void* bytes, size_t size) {
      ++random_calls;
      return FixedRandom(bytes, size);
    };
    Require(!quietproof_detail::CreateQuietProofChallengeWithSources(
                {Claim()}, *options, &output, &error, clock, random) &&
                error == QuietProofChallengeError::kInvalidOptions &&
                Bytes(output) == before && clock_calls == 0 && random_calls == 0,
            "omitted network accepted, changed output, or invoked sources");
  }
}

void TestOptions() {
  const auto valid = Options();
  for (uint64_t lifetime : {uint64_t{1}, uint64_t{300}, uint64_t{86400}}) {
    auto options = valid;
    options.lifetime_seconds = lifetime;
    auto output = Sentinel();
    Require(Build({Claim()}, options, &output, nullptr) &&
                output.expires_at - output.not_before == lifetime,
            "valid lifetime rejected");
  }
  for (uint64_t lifetime : {uint64_t{0}, uint64_t{86401},
                            std::numeric_limits<uint64_t>::max()}) {
    auto options = valid;
    options.lifetime_seconds = lifetime;
    Reject({Claim()}, options, QuietProofChallengeError::kInvalidOptions);
  }
  for (const auto network : {QuietProofNetwork::kMainnet,
                            QuietProofNetwork::kTestnet3,
                            QuietProofNetwork::kSignet,
                            QuietProofNetwork::kRegtest,
                            QuietProofNetwork::kTestnet4}) {
    auto options = valid;
    options.network = network;
    auto output = Sentinel();
    Require(Build({Claim()}, options, &output, nullptr) &&
                output.network == network, "network changed");
  }
  auto options = valid;
  options.network = static_cast<QuietProofNetwork>(255);
  Reject({Claim()}, options, QuietProofChallengeError::kInvalidOptions);
  for (const auto& verifier : {std::string{}, std::string(257, 'a'),
                               std::string("a\nb"), std::string("a\0b", 3),
                               std::string("\xc0\x80")}) {
    options = valid;
    options.verifier = verifier;
    Reject({Claim()}, options, QuietProofChallengeError::kInvalidOptions);
  }
  for (const auto& verifier : {std::string(256, 'a'), std::string("caf\xc3\xa9")}) {
    options = valid;
    options.verifier = verifier;
    auto output = Sentinel();
    Require(Build({Claim()}, options, &output, nullptr), "valid verifier rejected");
  }
  for (const auto& purpose : {std::string{}, std::string("unknown"),
                              std::string("bridge-authorization"),
                              std::string(65, 'a')}) {
    options = valid;
    options.purpose = purpose;
    Reject({Claim()}, options, QuietProofChallengeError::kInvalidOptions);
  }
  options = valid;
  options.purpose = "proof-of-control";
  options.message = std::string("\0\xff", 2);
  auto output = Sentinel();
  Require(Build({Claim()}, options, &output, nullptr), "binary message rejected");
  options.message.clear();
  Require(Build({Claim()}, options, &output, nullptr), "empty message rejected");
  auto error = QuietProofChallengeError::kNone;
  Require(!Build({Claim()}, valid, nullptr, &error) &&
              error == QuietProofChallengeError::kInvalidOptions,
          "null output accepted");
}

void TestClaimLimits() {
  const auto options = Options();
  const auto invalid = QuietProofChallengeError::kInvalidClaims;
  Reject({}, options, invalid);
  auto claim = Claim();
  claim.txid.fill(0);
  Reject({claim}, options, invalid);
  claim = Claim();
  claim.amount_sats = 0;
  Reject({claim}, options, invalid);
  claim.amount_sats = kQuietProofMaxMoneySats + 1;
  Reject({claim}, options, invalid);
  claim.amount_sats = kQuietProofMaxMoneySats;
  Reject({claim, Claim(2)}, options, invalid);
  auto output = Sentinel();
  claim.vout = std::numeric_limits<uint32_t>::max();
  claim.program.fill(0);
  Require(Build({claim}, options, &output, nullptr), "valid boundary claim rejected");
  claim = Claim();
  claim.amount_sats = kQuietProofMaxMoneySats - 7;
  Require(Build({claim, Claim(2)}, options, &output, nullptr),
          "maximum aggregate rejected");
  claim = Claim();
  claim.vout = 1;
  Require(Build({claim, Claim()}, options, &output, nullptr),
          "different outputs of one transaction rejected");
  Reject({Claim(), Claim()}, options, invalid);
  claim = Claim();
  claim.amount_sats++;
  Reject({Claim(), claim}, options, invalid);
  std::vector<QuietProofClaimV1> claims;
  for (uint8_t i = 1; i <= 16; ++i) claims.push_back(Claim(i));
  Require(Build(claims, options, &output, nullptr), "16 claims rejected");
  claims.push_back(Claim(17));
  Reject(claims, options, invalid);
  claims = {Claim(1), Claim(2), Claim(3)};
  claims[1].program[0] = 5;
  Reject(claims, options, invalid);
  claims[2].program[0] = 6;
  Reject(claims, options, invalid);
}

void TestSources() {
  const auto options = Options();
  auto output = Sentinel();
  const auto before = Bytes(output);
  auto error = QuietProofChallengeError::kNone;
  int calls = 0;
  auto zeros = [&calls](void*, size_t) { ++calls; return 0; };
  Require(!quietproof_detail::CreateQuietProofChallengeWithSources(
              {Claim()}, options, &output, &error, FixedClock, zeros) &&
              calls == 4 && error == QuietProofChallengeError::kRandom &&
              Bytes(output) == before, "zero RNG limit or output changed");
  calls = 0;
  auto retry = [&calls](void* bytes, size_t size) {
    return ++calls == 4 ? FixedRandom(bytes, size) : 0;
  };
  Require(quietproof_detail::CreateQuietProofChallengeWithSources(
              {Claim()}, options, &output, &error, FixedClock, retry) &&
              calls == 4 && error == QuietProofChallengeError::kNone,
          "fourth nonzero RNG attempt rejected");
  output = Sentinel();
  auto failure = [](void* bytes, size_t size) {
    FixedRandom(bytes, size);
    return -1;
  };
  Require(!quietproof_detail::CreateQuietProofChallengeWithSources(
              {Claim()}, options, &output, &error, FixedClock, failure) &&
              error == QuietProofChallengeError::kRandom && Bytes(output) == before,
          "failed RNG accepted or output changed");
  auto bad_clock = [](uint64_t*) { return false; };
  Require(!quietproof_detail::CreateQuietProofChallengeWithSources(
              {Claim()}, options, &output, &error, bad_clock, FixedRandom) &&
              error == QuietProofChallengeError::kClock && Bytes(output) == before,
          "failed clock accepted or output changed");
  auto overflow = [](uint64_t* now) {
    *now = std::numeric_limits<uint64_t>::max() - 299;
    return true;
  };
  Require(!quietproof_detail::CreateQuietProofChallengeWithSources(
              {Claim()}, options, &output, &error, overflow, FixedRandom) &&
              error == QuietProofChallengeError::kClock && Bytes(output) == before,
          "clock overflow accepted or output changed");
  auto boundary = [](uint64_t* now) {
    *now = std::numeric_limits<uint64_t>::max() - 300;
    return true;
  };
  Require(quietproof_detail::CreateQuietProofChallengeWithSources(
              {Claim()}, options, &output, &error, boundary, FixedRandom) &&
              output.expires_at == std::numeric_limits<uint64_t>::max(),
          "clock boundary rejected");
  auto epoch = [](uint64_t* now) { *now = 0; return true; };
  Require(quietproof_detail::CreateQuietProofChallengeWithSources(
              {Claim()}, options, &output, nullptr, epoch, FixedRandom) &&
              output.not_before == 0 && output.expires_at == 300,
          "epoch clock rejected");
  error = QuietProofChallengeError::kClock;
  Require(CreateQuietProofChallenge({Claim()}, options, &output, &error) &&
              error == QuietProofChallengeError::kNone &&
              !QuietProofAllZero(output.nonce), "production sources failed");
}

}  // namespace
}  // namespace proofs

int main() {
  try {
    proofs::TestLegacyEquivalence();
    proofs::TestTypedSelection();
    proofs::TestMissingNetwork();
    proofs::TestOptions();
    proofs::TestClaimLimits();
    proofs::TestSources();
  } catch (const std::exception& error) {
    std::cerr << "not ok - " << error.what() << '\n';
    return 1;
  }
  std::cout << "QuietProof challenge tests passed\n";
  return 0;
}
