// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_SIGNATURE_CHALLENGE_H_
#define QUIETPROOF_SIGNATURE_CHALLENGE_H_

#include "quietproof/challenge.h"

namespace proofs {

// Capability selection and its entry points have translation-unit-local
// linkage. A base-only library and a signature-enabled caller can coexist in
// one executable: the linker must never merge their different capabilities or
// their capability-dependent function/template definitions.
static constexpr bool kQuietProofSignatureModeEnabled =
#if defined(QUIETPROOF_HAS_SIGNATURE_MODE) && QUIETPROOF_HAS_SIGNATURE_MODE
    true;
#else
    false;
#endif

struct QuietProofSignatureChallengeOptions {
  QuietProofChallengeOptions request;
  QuietProofScriptKind signing_kind = static_cast<QuietProofScriptKind>(0xff);
};
enum class QuietProofSignatureChallengeError {
  kNone, kInvalidOptions, kInvalidClaims, kClock, kRandom, kSignatureModeDisabled
};
inline const char* QuietProofSignatureChallengeErrorName(
    QuietProofSignatureChallengeError error) {
  switch (error) {
    case QuietProofSignatureChallengeError::kNone: return "none";
    case QuietProofSignatureChallengeError::kInvalidOptions: return "invalid_options";
    case QuietProofSignatureChallengeError::kInvalidClaims: return "invalid_claims";
    case QuietProofSignatureChallengeError::kClock: return "clock_unavailable";
    case QuietProofSignatureChallengeError::kRandom: return "random_unavailable";
    case QuietProofSignatureChallengeError::kSignatureModeDisabled: return "signature_mode_disabled";
  }
  return "invalid_options";
}

namespace quietproof_detail {
template <typename Clock, typename Random>
static inline bool CreateQuietProofSignatureChallengeWithSources(
    const std::vector<QuietProofClaimV1>& claims,
    const QuietProofSignatureChallengeOptions& options,
    QuietProofSignatureStatementV3* output,
    QuietProofSignatureChallengeError* error, Clock clock, Random random) {
  const auto fail = [error](QuietProofSignatureChallengeError code) {
    if (error) *error = code;
    return false;
  };
  const auto& request = options.request;
  if (!output || !QuietProofNetworkValid(request.network) ||
      request.verifier.empty() || request.verifier.size() > kQuietProofMaxVerifierBytes ||
      !QuietProofUtf8(request.verifier) ||
      (request.purpose != "proof-of-control" && request.purpose != "proof-of-funds") ||
      !QuietProofScriptKindValid(options.signing_kind) ||
      !request.lifetime_seconds || request.lifetime_seconds > 86400) {
    return fail(QuietProofSignatureChallengeError::kInvalidOptions);
  }
  QuietProofSignatureStatementV3 statement;
  statement.network = request.network;
  statement.verifier = request.verifier;
  statement.purpose = request.purpose;
  statement.signing_kind = options.signing_kind;
  statement.nonce.fill(1);
  statement.bip322_message_hash = QuietProofBip322MessageHash(
      reinterpret_cast<const uint8_t*>(request.message.data()), request.message.size());
  statement.expires_at = request.lifetime_seconds;
  if (claims.empty() || claims.size() > kQuietProofMaxClaims)
    return fail(QuietProofSignatureChallengeError::kInvalidClaims);
  statement.claims = claims;
  std::sort(statement.claims.begin(), statement.claims.end());
  if (!QuietProofSignatureStatementValid(statement))
    return fail(QuietProofSignatureChallengeError::kInvalidClaims);
  if (!kQuietProofSignatureModeEnabled)
    return fail(QuietProofSignatureChallengeError::kSignatureModeDisabled);
  statement.nonce.fill(0);
  for (size_t attempt = 0; QuietProofAllZero(statement.nonce); ++attempt) {
    if (attempt == 4 || random(statement.nonce.data(), statement.nonce.size()) != 0)
      return fail(QuietProofSignatureChallengeError::kRandom);
  }
  uint64_t now = 0;
  if (!clock(&now) || now > std::numeric_limits<uint64_t>::max() - request.lifetime_seconds)
    return fail(QuietProofSignatureChallengeError::kClock);
  statement.not_before = now;
  statement.expires_at = now + request.lifetime_seconds;
  *output = std::move(statement);
  if (error) *error = QuietProofSignatureChallengeError::kNone;
  return true;
}
}  // namespace quietproof_detail

// Calling this separate operation explicitly selects signature mode. A parsed
// request cannot enable it. Defaults of CreateQuietProofChallenge stay intact.
static inline bool CreateQuietProofSignatureChallenge(
    const std::vector<QuietProofClaimV1>& claims,
    const QuietProofSignatureChallengeOptions& options,
    QuietProofSignatureStatementV3* output,
    QuietProofSignatureChallengeError* error = nullptr) {
  const auto clock = [](uint64_t* now) {
    const auto current = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if (current < 0) return false;
    *now = static_cast<uint64_t>(current);
    return true;
  };
  return quietproof_detail::CreateQuietProofSignatureChallengeWithSources(
      claims, options, output, error, clock, randombytes);
}
}  // namespace proofs
#endif
