// Copyright (C) 2026 Plan-B Foundation
// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef QUIETPROOF_BROWSER_VERIFIER_H_
#define QUIETPROOF_BROWSER_VERIFIER_H_

#include "pokc/verifier.h"
#include "quietproof/browser.h"
#include "quietproof/chain_state.h"

namespace proofs {
// Browser policy is independent input. Proof metadata never fills these fields.
struct QuietProofBrowserPolicy {
  QuietProofNetwork network = static_cast<QuietProofNetwork>(255);
  std::string verifier, purpose, provider;
  std::array<uint8_t, 32> message_hash{};
  std::vector<uint8_t> expected_request;
  uint64_t max_lifetime = 0, min_confirmations = 0, minimum_total = 0;
  uint64_t max_observation_age = 0;
};
inline bool DecodeQuietProofBrowserPolicy(const std::vector<uint8_t>& bytes,
                                         QuietProofBrowserPolicy* output) {
  if (!output || bytes.size() > 8192) return false;
  QuietProofReader r(bytes); uint8_t magic[4], mode, network;
  QuietProofBrowserPolicy p;
  if (!r.bytes(magic, 4) || std::memcmp(magic, "QWP1", 4) || !r.u8(&mode) || mode > 1 ||
      !r.u64(&p.max_lifetime) || !p.max_lifetime || p.max_lifetime > 86400 ||
      !r.u64(&p.min_confirmations) || !r.u64(&p.minimum_total) ||
      p.minimum_total > kQuietProofMaxMoneySats || !r.u64(&p.max_observation_age) ||
      !p.max_observation_age || p.max_observation_age > 300 ||
      !r.text(&p.provider, 256)) return false;
  if (mode == 0) {
    uint32_t count;
    if (!r.u32(&count) || !count || count > kQuietProofMaxStatementBytes || count > r.left()) return false;
    p.expected_request.resize(count);
    if (!r.bytes(p.expected_request.data(), count)) return false;
    QuietProofStatementV1 s;
    if (!DecodeQuietProofStatement(p.expected_request, &s)) return false;
    p.network = s.network; p.verifier = s.verifier; p.purpose = s.purpose;
    p.message_hash = s.bip322_message_hash;
  } else {
    std::string message;
    if (!r.u8(&network) || !r.text(&p.verifier, kQuietProofMaxVerifierBytes) ||
        p.verifier.empty() || !r.text(&p.purpose, kQuietProofMaxPurposeBytes) ||
        !QuietProofPurposeValid(p.purpose) ||
        !r.text(&message, kQuietProofBrowserMaxMessageBytes)) return false;
    p.message_hash = QuietProofBip322MessageHash(
        reinterpret_cast<const uint8_t*>(message.data()), message.size());
    p.network = static_cast<QuietProofNetwork>(network);
  }
  if (r.left() || (p.network != QuietProofNetwork::kMainnet && p.network != QuietProofNetwork::kSignet)) return false;
  *output = std::move(p); return true;
}

// These outcomes deliberately have no strict valid_current/valid_historical.
enum class QuietProofBrowserCrypto : uint8_t { kNotChecked, kValid, kInvalid };
enum class QuietProofBrowserPolicyResult : uint8_t { kMatched = 1, kRejected, kExpired };
enum class QuietProofExplorerResult : uint8_t { kUnavailable, kReportedUnspent, kReportedSpent, kInconclusive };
struct QuietProofBrowserOutcome {
  QuietProofBrowserCrypto crypto = QuietProofBrowserCrypto::kNotChecked;
  QuietProofBrowserPolicyResult policy = QuietProofBrowserPolicyResult::kMatched;
  QuietProofExplorerResult explorer = QuietProofExplorerResult::kUnavailable;
  uint64_t total_sats = 0;
};

// One immutable proof/policy context. No callback can substitute cryptography or
// treat explorer observations as an authenticated chain snapshot.
class QuietProofBrowserVerification {
 public:
  enum class Phase { kEmpty, kPrepared, kVerified, kFinished };
  bool Prepare(QuietProofEnvelopeV1 envelope, QuietProofBrowserPolicy policy,
               uint64_t now) {
    phase_ = Phase::kEmpty; outcome_ = {}; error_ = ""; unsupported_ = false;
    envelope_ = std::move(envelope); policy_ = std::move(policy);
    if (envelope_.statement.has_snapshot || envelope_.statement.has_bridge_binding ||
        envelope_.statement.purpose == "bridge-authorization") {
      unsupported_ = true; return Fail("Unsupported snapshot or bridge mode");
    }
    if (!PolicyMatches(now)) return false;
    QuietProofBrowserMetadata(envelope_, true, &metadata_);
    phase_ = Phase::kPrepared; return true;
  }
  bool Verify(uint64_t now) {
    if (phase_ != Phase::kPrepared) return Fail("Invalid verification phase");
    phase_ = Phase::kFinished;
    if (!PolicyMatches(now)) return false;
    if (!PoKCProofSupported(envelope_)) {
      unsupported_ = true; return Fail("Unsupported circuit identity or parameters");
    }
    outcome_.crypto = PoKCVerifyProof(envelope_) ? QuietProofBrowserCrypto::kValid : QuietProofBrowserCrypto::kInvalid;
    // Verify can be long. The caller checks time again before returning/fetching.
    std::vector<uint8_t>().swap(envelope_.proof.bytes);
    if (outcome_.crypto == QuietProofBrowserCrypto::kValid) phase_ = Phase::kVerified;
    return true;
  }
  bool RecheckPolicy(uint64_t now) {
    if (!PolicyMatches(now)) { phase_ = Phase::kFinished; return false; }
    return true;
  }
  bool Evaluate(const std::vector<uint8_t>& bytes, uint64_t now) {
    if (phase_ != Phase::kVerified) return Fail("Invalid evidence phase");
    phase_ = Phase::kFinished; // Every attempt consumes this phase, including malformed evidence.
    if (!PolicyMatches(now)) return false;
    outcome_.explorer = QuietProofExplorerResult::kInconclusive;
    if (bytes.size() > 4096 || policy_.provider.empty()) return Fail("Unavailable or oversized explorer evidence");
    QuietProofReader r(bytes); uint8_t magic[4], network; uint16_t count;
    std::string provider; uint64_t observed, before_height, after_height;
    std::array<uint8_t,32> before{}, after{};
    if (!r.bytes(magic, 4) || std::memcmp(magic, "QWE1", 4) ||
        !r.text(&provider, 256) || !r.u64(&observed) || !r.u8(&network) ||
        !r.bytes(before.data(), 32) || !r.u64(&before_height) ||
        !r.bytes(after.data(), 32) || !r.u64(&after_height) || !r.u16(&count) ||
        count != envelope_.statement.claims.size()) return Fail("Malformed explorer evidence");
    bool inconclusive = provider != policy_.provider || network != static_cast<uint8_t>(policy_.network) ||
        observed > now || now - observed > policy_.max_observation_age ||
        QuietProofAllZero(before) || before != after || before_height != after_height;
    bool spent = false; uint64_t total = 0;
    for (const auto& claim : envelope_.statement.claims) {
      std::array<uint8_t,32> txid{}; uint32_t vout; uint8_t status, best_chain;
      uint64_t amount, confirmations; uint16_t script_size;
      if (!r.bytes(txid.data(), 32) || !r.u32(&vout) || !r.u8(&status) || status > 4 ||
          !r.u64(&amount) || !r.u16(&script_size) || script_size > 25 || script_size > r.left())
        return Fail("Malformed claim observation");
      std::vector<uint8_t> script(script_size);
      if (!r.bytes(script.data(), script.size()) || !r.u64(&confirmations) ||
          !r.u8(&best_chain) || best_chain > 1) return Fail("Malformed claim observation");
      const bool matches = txid == claim.txid && vout == claim.vout && amount == claim.amount_sats &&
                           QuietProofMatchesScript(claim, script);
      if (!matches || status > 1 || !best_chain) inconclusive = true;
      if (matches && status == 1) spent = true;
      if (matches && status == 0) {
        if (confirmations < policy_.min_confirmations ||
            (before_height != UINT64_MAX && confirmations > before_height + 1)) inconclusive = true;
        total += claim.amount_sats; // Core validation already bounds the aggregate by MAX_MONEY.
      }
    }
    if (r.left()) return Fail("Trailing explorer evidence");
    if (!spent && total < policy_.minimum_total) inconclusive = true;
    outcome_.total_sats = total;
    // Mismatched/stale/network/provider data cannot assert even a spent result.
    outcome_.explorer = inconclusive ? QuietProofExplorerResult::kInconclusive :
        spent ? QuietProofExplorerResult::kReportedSpent : QuietProofExplorerResult::kReportedUnspent;
    return true;
  }
  Phase phase() const { return phase_; }
  const QuietProofBrowserOutcome& outcome() const { return outcome_; }
  const QuietProofEnvelopeV1& envelope() const { return envelope_; }
  const std::vector<uint8_t>& metadata() const { return metadata_; }
  const char* error() const { return error_; }
  bool unsupported() const { return unsupported_; }
 private:
  bool Fail(const char* error) { error_ = error; return false; }
  bool PolicyMatches(uint64_t now) {
    const auto& s = envelope_.statement;
    std::vector<uint8_t> request;
    if (!EncodeQuietProofStatement(s, &request) ||
        (policy_.network != QuietProofNetwork::kMainnet && policy_.network != QuietProofNetwork::kSignet) ||
        s.network != policy_.network || s.verifier != policy_.verifier || s.purpose != policy_.purpose ||
        s.bip322_message_hash != policy_.message_hash ||
        (!policy_.expected_request.empty() && request != policy_.expected_request) ||
        !policy_.max_lifetime || policy_.max_lifetime > 86400 ||
        s.expires_at - s.not_before > policy_.max_lifetime || envelope_.proof_created_at > now) {
      outcome_.policy = QuietProofBrowserPolicyResult::kRejected;
      return Fail("Expected request or independent policy mismatch");
    }
    if (now < s.not_before || now >= s.expires_at) {
      outcome_.policy = QuietProofBrowserPolicyResult::kExpired;
      return Fail("Request is not active or has expired");
    }
    return true;
  }
  Phase phase_ = Phase::kEmpty;
  QuietProofEnvelopeV1 envelope_;
  QuietProofBrowserPolicy policy_;
  QuietProofBrowserOutcome outcome_;
  std::vector<uint8_t> metadata_;
  const char* error_ = "";
  bool unsupported_ = false;
};
}  // namespace proofs
#endif
