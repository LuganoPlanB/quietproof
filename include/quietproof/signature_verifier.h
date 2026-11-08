// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_SIGNATURE_VERIFIER_H_
#define QUIETPROOF_SIGNATURE_VERIFIER_H_

#include "poksig/verifier.h"
#include <optional>
#include "quietproof/acceptance.h"
#include "quietproof/verifier.h"

namespace proofs {

enum class QuietProofSignatureStatePolicy : uint8_t {
  kValidatedCurrentNode, kQualifiedCurrentProvider, kRecordedHistoricalSnapshot
};

inline uint64_t QuietProofSignatureMaxTipAge(QuietProofNetwork network) {
  switch (network) {
    case QuietProofNetwork::kMainnet: return 7200;
    case QuietProofNetwork::kTestnet3:
    case QuietProofNetwork::kTestnet4:
    case QuietProofNetwork::kSignet: return 86400;
    case QuietProofNetwork::kRegtest: return 3600;
  }
  return 0;
}

struct QuietProofSignatureVerifierConfig {
  // Local policy only: neither the request nor envelope can enable this mode.
  PoKSigOptionsV1 modes;
  QuietProofReplayPolicy policy;
  QuietProofChainProvider* provider = nullptr;
  uint64_t min_confirmations = 1;
  uint64_t minimum_total_sats = 0;
  QuietProofSignatureStatePolicy state_policy = QuietProofSignatureStatePolicy::kValidatedCurrentNode;
  // Zero selects the explicit network default above. This is local policy,
  // never taken from proof-provided metadata or a historical snapshot's age.
  uint64_t max_tip_age_seconds = 0;
  // Signature time comes from this clock; scalar policy.now remains unchanged.
  QuietProofClock clock = QuietProofSystemClock;
  QuietProofFinalAcceptanceStore* final_acceptance_store = nullptr;
};

struct QuietProofSignatureVerificationTimes {
  std::optional<uint64_t> verification_started_at;
  std::optional<uint64_t> proof_checked_at;
  std::optional<uint64_t> chain_observed_at;
  std::optional<uint64_t> accepted_at;
};

namespace quietproof_detail {
struct SignatureFundsCheck {
  QuietProofVerification verification{QuietProofVerifyResult::kStateInconclusive, {}};
  bool ready_for_acceptance = false;
  std::optional<uint64_t> observed_at;
};

inline bool SignatureNodeReady(const QuietProofNodeState& state,
    const QuietProofSignatureStatementV4& expected,
    const QuietProofSignatureVerifierConfig& config, uint64_t observed_at, const char** reason) {
  const auto fail = [reason](const char* detail) {
    if (reason) *reason = detail;
    return false;
  };
  if (state.status != QuietProofNodeStateStatus::kObserved ||
      state.network != expected.network || QuietProofAllZero(state.block))
    return fail("signature_node_state_unknown");
  if (state.initial_block_download) return fail("signature_node_initial_block_download");
  if (!state.active_chainstate_validated) return fail("signature_active_chainstate_unvalidated");
  const uint64_t maximum_age = config.max_tip_age_seconds ? config.max_tip_age_seconds :
      QuietProofSignatureMaxTipAge(expected.network);
  if (!maximum_age || !state.tip_time ||
      (state.tip_time > observed_at && state.tip_time - observed_at > 7200) ||
      (observed_at > state.tip_time && observed_at - state.tip_time > maximum_age))
    return fail("signature_node_tip_stale");
  return true;
}

// Real-state observation only, never cryptographic or replay acceptance. The
// production entry point invokes it AFTER signature verification. Keeping this
// operation separate also makes every state denial independently testable.
inline SignatureFundsCheck CheckSignatureFunds(
    const QuietProofSignatureStatementV4& expected,
    const QuietProofSignatureVerifierConfig& config, const char** reason) {
  SignatureFundsCheck out;
  const auto fail = [&](QuietProofVerifyResult result, const char* detail) {
    out.verification.result = result;
    if (reason) *reason = detail;
    return out;
  };
  const auto observe_time = [&] {
    uint64_t now = 0;
    if (!QuietProofReadClock(config.clock, &now)) {
      fail(QuietProofVerifyResult::kStateInconclusive, "signature_clock_unavailable");
      return false;
    }
    out.observed_at = now;
    if (now < expected.not_before || now >= expected.expires_at) {
      fail(QuietProofVerifyResult::kInvalidProof,
           now < expected.not_before ? "signature_request_not_yet_valid" : "signature_request_expired");
      return false;
    }
    return true;
  };
  if (!QuietProofSignatureStatementValid(expected))
    return fail(QuietProofVerifyResult::kMalformedStatement, "invalid_expected_request");
  if (!config.provider || config.minimum_total_sats > kQuietProofMaxMoneySats)
    return fail(QuietProofVerifyResult::kStateInconclusive, "signature_funds_checks_pending");
  const bool historical = expected.has_snapshot;
  const bool qualified = config.state_policy == QuietProofSignatureStatePolicy::kQualifiedCurrentProvider;
  if (historical ?
      config.state_policy != QuietProofSignatureStatePolicy::kRecordedHistoricalSnapshot ||
          config.provider->kind() != QuietProofProviderKind::kHistoricalSnapshot :
      (config.state_policy != QuietProofSignatureStatePolicy::kValidatedCurrentNode && !qualified) ||
          config.provider->kind() != QuietProofProviderKind::kCurrentTip)
    return fail(QuietProofVerifyResult::kStateInconclusive, "signature_state_policy_mismatch");
  QuietProofNodeState before;
  if (!historical && !qualified) {
    before = config.provider->ObserveNodeState();
    if (!observe_time() || !SignatureNodeReady(before, expected, config, *out.observed_at, reason)) return out;
  }
  std::array<uint8_t, 32> observed_block{};
  uint64_t observed_height = 0;
  bool have_tip = false;
  for (const auto& claim : expected.claims) {
    const auto evidence = config.provider->Lookup({expected.network, claim.txid, claim.vout,
        historical, expected.snapshot, expected.snapshot_height});
    out.verification.claims.push_back(evidence);
    if (!observe_time()) return out;
    if (historical) {
      if (evidence.block != expected.snapshot || evidence.height != expected.snapshot_height)
        return fail(QuietProofVerifyResult::kStateInconclusive, "signature_snapshot_mismatch");
    } else {
      if (QuietProofAllZero(evidence.block))
        return fail(QuietProofVerifyResult::kStateInconclusive, "signature_chain_tip_unknown");
      if (!have_tip) { observed_block = evidence.block; observed_height = evidence.height; have_tip = true; }
      if (evidence.block != observed_block || evidence.height != observed_height ||
          (!qualified && (evidence.block != before.block || evidence.height != before.height)))
        return fail(QuietProofVerifyResult::kStateInconclusive, "signature_chain_tip_changed");
    }
    const auto state = QuietProofMatchClaim(claim, expected.network, evidence);
    if (state == QuietProofChainStatus::kSpent)
      return fail(QuietProofVerifyResult::kSpentAtSnapshot, "signature_output_spent");
    if (state != QuietProofChainStatus::kUnspent)
      return fail(QuietProofVerifyResult::kStateInconclusive, "signature_output_inconclusive");
    if (evidence.confirmations < config.min_confirmations)
      return fail(QuietProofVerifyResult::kStaleSnapshot, "signature_output_confirmations");
    if (!evidence.amount_sats || evidence.amount_sats > kQuietProofMaxMoneySats ||
        evidence.amount_sats > kQuietProofMaxMoneySats - out.verification.total_sats)
      return fail(QuietProofVerifyResult::kStateInconclusive, "signature_amount_range");
    // Synthetic value never enters this sum. Use only the checked real value.
    out.verification.total_sats += evidence.amount_sats;
  }
  if (out.verification.total_sats < config.minimum_total_sats)
    return fail(QuietProofVerifyResult::kStateInconclusive, "signature_minimum_total");
  if (!historical && !qualified) {
    const auto after = config.provider->ObserveNodeState();
    if (!observe_time() || !SignatureNodeReady(after, expected, config, *out.observed_at, reason)) return out;
    if (after.block != observed_block || after.height != observed_height || after.tip_time != before.tip_time)
      return fail(QuietProofVerifyResult::kStateInconclusive, "signature_chain_tip_changed");
  }
  if (qualified)
    return fail(QuietProofVerifyResult::kStateInconclusive, "signature_provider_qualified_quantity");
  out.ready_for_acceptance = true;
  return fail(QuietProofVerifyResult::kStateInconclusive, "signature_final_acceptance_pending");
}
}  // namespace quietproof_detail

// A separate entry point preserves all scalar API and policy contracts. The
// verifier must retain the independently issued canonical request. Inspecting
// public metadata never promotes its embedded request to expected authority.
static inline QuietProofVerification VerifyQuietProofSignatureDetailed(
    const std::vector<uint8_t>& expected_request, const std::vector<uint8_t>& bytes,
    const QuietProofSignatureVerifierConfig& config,
    QuietProofSignatureVerificationTimes* times, const char** reason) {
  if (reason) *reason = nullptr;
  if (times) *times = {};
  const auto fail = [reason](QuietProofVerifyResult result, const char* detail) {
    if (reason) *reason = detail;
    return QuietProofVerification{result, {}};
  };
  if (expected_request.empty())
    return fail(QuietProofVerifyResult::kInvalidProof, "missing_expected_request");
  QuietProofSignatureStatementV4 expected;
  QuietProofDecodeError decode_error;
  if (!DecodeQuietProofSignatureStatement(expected_request, &expected, &decode_error))
    return fail(decode_error == QuietProofDecodeError::kUnsupported ?
        QuietProofVerifyResult::kUnsupported : QuietProofVerifyResult::kMalformedStatement,
        "invalid_expected_request");
  if (!config.modes.allow_signature_possession)
    return fail(QuietProofVerifyResult::kUnsupported, "signature_mode_not_allowed");
  if (config.policy.purpose == "bridge-authorization")
    return fail(QuietProofVerifyResult::kBridgeRejected, "signature_bridge_rejected");
  QuietProofSignatureEnvelopeMetadataV4 metadata;
  QuietProofSignatureEnvelopeError envelope_error;
  if (!InspectQuietProofSignatureEnvelope(bytes, &metadata, &envelope_error))
    return fail(envelope_error == QuietProofSignatureEnvelopeError::kUnsupported ?
        QuietProofVerifyResult::kUnsupported : QuietProofVerifyResult::kMalformedStatement,
        QuietProofSignatureEnvelopeErrorName(envelope_error));
  // Exact bytes precede circuit allocation, proof parsing, hashing and all
  // chain/nonce work. h/z are subsequently derived only from expected_request.
  if (metadata.request != expected_request)
    return fail(QuietProofVerifyResult::kInvalidProof, "expected_request_mismatch");
  if (!QuietProofSignatureEnvelopeSupported(bytes, &envelope_error))
    return fail(QuietProofVerifyResult::kUnsupported,
                QuietProofSignatureEnvelopeErrorName(envelope_error));
  uint64_t started_at = 0;
  if (!QuietProofReadClock(config.clock, &started_at))
    return fail(QuietProofVerifyResult::kStateInconclusive, "signature_clock_unavailable");
  if (times) times->verification_started_at = started_at;
  if (expected.verifier != config.policy.verifier || expected.purpose != config.policy.purpose ||
      started_at < expected.not_before || started_at >= expected.expires_at ||
      metadata.proof_created_at > started_at ||
      (config.policy.max_lifetime &&
       expected.expires_at - expected.not_before > config.policy.max_lifetime))
    return fail(QuietProofVerifyResult::kInvalidProof, "signature_request_policy_rejected");
  if (config.policy.nonce_seen && config.policy.nonce_seen(expected.nonce))
    return fail(QuietProofVerifyResult::kInvalidProof, "signature_request_replayed");
  PoKSigError proof_error;
  if (!PoKSigVerifyProof(expected_request, PoKSigProofV1{bytes}, started_at,
                        config.modes, &proof_error))
    return fail(QuietProofVerifyResult::kInvalidProof, PoKSigErrorName(proof_error));
  uint64_t proof_checked_at = 0;
  if (!QuietProofReadClock(config.clock, &proof_checked_at))
    return fail(QuietProofVerifyResult::kStateInconclusive, "signature_clock_unavailable");
  if (times) times->proof_checked_at = proof_checked_at;
  if (proof_checked_at < expected.not_before || proof_checked_at >= expected.expires_at)
    return fail(QuietProofVerifyResult::kInvalidProof, proof_checked_at < expected.not_before ?
                "signature_request_not_yet_valid" : "signature_request_expired");
  auto funds = quietproof_detail::CheckSignatureFunds(expected, config, reason);
  if (times) times->chain_observed_at = funds.observed_at;
  if (!funds.ready_for_acceptance) return funds.verification;
  if (!config.final_acceptance_store) {
    if (reason) *reason = "signature_final_acceptance_unavailable";
    return funds.verification;
  }
  QuietProofFinalAcceptance acceptance;
  try {
    acceptance = config.final_acceptance_store->Accept(
        {expected.nonce, expected.not_before, expected.expires_at}, config.clock);
  } catch (...) { acceptance.status = QuietProofFinalAcceptanceStatus::kStoreFailure; }
  using Status = QuietProofFinalAcceptanceStatus;
  if (acceptance.status != Status::kAccepted) {
    const bool authorization_failure = acceptance.status == Status::kReplay ||
        acceptance.status == Status::kNotYetValid || acceptance.status == Status::kExpired;
    funds.verification.result = authorization_failure ? QuietProofVerifyResult::kInvalidProof : QuietProofVerifyResult::kStateInconclusive;
    if (reason) *reason = acceptance.status == Status::kReplay ? "signature_request_replayed" :
        acceptance.status == Status::kExpired ? "signature_request_expired" :
        acceptance.status == Status::kNotYetValid ? "signature_request_not_yet_valid" :
        acceptance.status == Status::kClockUnavailable ? "signature_clock_unavailable" : "signature_nonce_store_failed";
    return funds.verification;
  }
  if (times) times->accepted_at = acceptance.accepted_at;
  if (reason) *reason = nullptr;
  funds.verification.result = expected.has_snapshot ? QuietProofVerifyResult::kValidHistorical : QuietProofVerifyResult::kValidCurrent;
  return funds.verification;
}

static inline QuietProofVerification VerifyQuietProofSignatureWithReason(
    const std::vector<uint8_t>& expected_request, const std::vector<uint8_t>& bytes,
    const QuietProofSignatureVerifierConfig& config, const char** reason) {
  return VerifyQuietProofSignatureDetailed(expected_request, bytes, config, nullptr, reason);
}

static inline QuietProofVerification VerifyQuietProofSignature(
    const std::vector<uint8_t>& expected_request, const std::vector<uint8_t>& bytes,
    const QuietProofSignatureVerifierConfig& config) {
  return VerifyQuietProofSignatureWithReason(expected_request, bytes, config, nullptr);
}
}  // namespace proofs
#endif
