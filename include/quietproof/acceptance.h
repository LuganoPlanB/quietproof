// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_ACCEPTANCE_H_
#define QUIETPROOF_ACCEPTANCE_H_

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>

namespace proofs {
using QuietProofClock = std::function<bool(uint64_t*)>;
inline bool QuietProofSystemClock(uint64_t* output) {
  const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  if (!output || now < 0) return false;
  *output = static_cast<uint64_t>(now);
  return true;
}
inline bool QuietProofReadClock(const QuietProofClock& clock, uint64_t* output) {
  try { return clock && output && clock(output); }
  catch (...) { return false; }
}
enum class QuietProofFinalAcceptanceStatus : uint8_t {
  kAccepted, kReplay, kNotYetValid, kExpired, kClockUnavailable, kStoreFailure, kInvalidRequest
};
struct QuietProofFinalAcceptance {
  QuietProofFinalAcceptanceStatus status = QuietProofFinalAcceptanceStatus::kStoreFailure;
  uint64_t accepted_at = 0;
};
struct QuietProofFinalAcceptanceRequest {
  std::array<uint8_t, 32> nonce{};
  uint64_t not_before = 0;
  uint64_t expires_at = 0;
};

// Explicit atomic capability, separate from advisory nonce_seen/consume_nonce.
// Implementations MUST acquire their serialization lock/transaction, inspect
// the store and then invoke clock under that lock immediately before deciding
// validity/replay and recording the nonce. No acceptance without durable storage.
class QuietProofFinalAcceptanceStore {
 public:
  virtual ~QuietProofFinalAcceptanceStore() = default;
  virtual QuietProofFinalAcceptance Accept(const QuietProofFinalAcceptanceRequest&,
                                           const QuietProofClock&) = 0;
};
}  // namespace proofs
#endif
