// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_CHALLENGE_H_
#define PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_CHALLENGE_H_

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include "quietproof/statement.h"
#include "util/randombytes.h"

namespace proofs {

struct QuietProofChallengeOptions {
  // Callers must select a network explicitly; this is not a v1 network ID.
  QuietProofNetwork network = static_cast<QuietProofNetwork>(0xff);
  std::string verifier;
  std::string purpose;
  std::string message;
  uint64_t lifetime_seconds = 300;
};

enum class QuietProofChallengeError {
  kNone, kInvalidOptions, kInvalidClaims, kClock, kRandom
};

namespace quietproof_detail {

// Internal test seam. Production callers use CreateQuietProofChallenge below;
// fixed nonces and clocks are deliberately absent from its public options.
template <typename Clock, typename Random>
inline bool CreateQuietProofChallengeWithSources(
    const std::vector<QuietProofClaimV1>& claims,
    const QuietProofChallengeOptions& options, QuietProofStatementV1* output,
    QuietProofChallengeError* error, Clock clock, Random random) {
  const auto fail = [error](QuietProofChallengeError code) {
    if (error != nullptr) *error = code;
    return false;
  };
  if (output == nullptr || !QuietProofNetworkValid(options.network) ||
      options.verifier.empty() ||
      options.verifier.size() > kQuietProofMaxVerifierBytes ||
      !QuietProofUtf8(options.verifier) ||
      !QuietProofPurposeValid(options.purpose) ||
      options.purpose.size() > kQuietProofMaxPurposeBytes ||
      options.purpose == "bridge-authorization" ||
      options.lifetime_seconds == 0 || options.lifetime_seconds > 86400) {
    return fail(QuietProofChallengeError::kInvalidOptions);
  }
  if (claims.empty() || claims.size() > kQuietProofMaxClaims) {
    return fail(QuietProofChallengeError::kInvalidClaims);
  }

  QuietProofStatementV1 statement;
  statement.network = options.network;
  statement.verifier = options.verifier;
  statement.purpose = options.purpose;
  for (size_t attempt = 0; QuietProofAllZero(statement.nonce); ++attempt) {
    if (attempt == 4 ||
        random(statement.nonce.data(), statement.nonce.size()) != 0) {
      return fail(QuietProofChallengeError::kRandom);
    }
  }
  statement.bip322_message_hash = QuietProofBip322MessageHash(
      reinterpret_cast<const uint8_t*>(options.message.data()),
      options.message.size());
  uint64_t now = 0;
  if (!clock(&now) || now > std::numeric_limits<uint64_t>::max() -
                               options.lifetime_seconds) {
    return fail(QuietProofChallengeError::kClock);
  }
  statement.not_before = now;
  statement.expires_at = now + options.lifetime_seconds;
  statement.claims = claims;
  std::sort(statement.claims.begin(), statement.claims.end());
  std::vector<uint8_t> request;
  if (!EncodeQuietProofStatement(statement, &request)) {
    return fail(QuietProofChallengeError::kInvalidClaims);
  }
  *output = std::move(statement);
  if (error != nullptr) *error = QuietProofChallengeError::kNone;
  return true;
}

}  // namespace quietproof_detail

// Builds a current-tip request using the existing v1 statement contract.
// On failure output is unchanged; on success error is cleared.
inline bool CreateQuietProofChallenge(
    const std::vector<QuietProofClaimV1>& claims,
    const QuietProofChallengeOptions& options, QuietProofStatementV1* output,
    QuietProofChallengeError* error = nullptr) {
  const auto clock = [](uint64_t* now) {
    const auto current = std::chrono::system_clock::to_time_t(
        std::chrono::system_clock::now());
    if (current < 0) return false;
    *now = static_cast<uint64_t>(current);
    return true;
  };
  return quietproof_detail::CreateQuietProofChallengeWithSources(
      claims, options, output, error, clock, randombytes);
}

}  // namespace proofs

#endif  // PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_CHALLENGE_H_
