// Copyright (C) 2026 Plan-B Foundation
// designed, written and maintained by Denis Roio
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published
// by the Free Software Foundation, either version 3 of the License,
// or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.
#ifndef PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_VERIFIER_H_
#define PRIVACY_PROOFS_ZK_LIB_QUIETPROOF_VERIFIER_H_
#include <limits>
#include "quietproof/chain_state.h"
#include "quietproof/envelope.h"
namespace proofs {
enum class QuietProofVerifyResult : uint8_t { kInvalidProof, kMalformedStatement, kUnsupported, kStateInconclusive, kSpentAtSnapshot, kStaleSnapshot, kBridgeRejected, kValidHistorical, kValidCurrent };
inline const char* QuietProofVerifyResultName(QuietProofVerifyResult r) { switch(r) { case QuietProofVerifyResult::kInvalidProof:return "invalid_proof"; case QuietProofVerifyResult::kMalformedStatement:return "malformed_statement"; case QuietProofVerifyResult::kUnsupported:return "unsupported"; case QuietProofVerifyResult::kStateInconclusive:return "state_inconclusive"; case QuietProofVerifyResult::kSpentAtSnapshot:return "spent_at_snapshot"; case QuietProofVerifyResult::kStaleSnapshot:return "stale_snapshot"; case QuietProofVerifyResult::kBridgeRejected:return "bridge_rejected"; case QuietProofVerifyResult::kValidHistorical:return "valid_historical"; case QuietProofVerifyResult::kValidCurrent:return "valid_current"; } return "invalid_proof"; }
inline int QuietProofVerifyExitCode(QuietProofVerifyResult r) { switch(r) { case QuietProofVerifyResult::kValidCurrent: return 0; case QuietProofVerifyResult::kValidHistorical: return 1; case QuietProofVerifyResult::kSpentAtSnapshot: return 3; case QuietProofVerifyResult::kStaleSnapshot: return 4; case QuietProofVerifyResult::kStateInconclusive: return 5; case QuietProofVerifyResult::kBridgeRejected: return 6; case QuietProofVerifyResult::kMalformedStatement: return 65; case QuietProofVerifyResult::kUnsupported: return 66; case QuietProofVerifyResult::kInvalidProof: return 67; } return 67; }
struct QuietProofVerification { QuietProofVerifyResult result = QuietProofVerifyResult::kMalformedStatement; std::vector<QuietProofChainEvidence> claims; uint64_t total_sats = 0; };
struct QuietProofVerifierConfig { QuietProofReplayPolicy policy; std::function<bool(const QuietProofEnvelopeV1&)> verify_proof; std::function<bool(const QuietProofEnvelopeV1&)> supports; std::function<bool(const QuietProofStatementV1&)> bridge_authorized; QuietProofChainProvider* provider = nullptr; uint64_t min_confirmations = 0; uint64_t minimum_total_sats = 0; };
inline QuietProofVerification VerifyQuietProof(const std::vector<uint8_t>& bytes, const QuietProofVerifierConfig& config) {
  QuietProofEnvelopeV1 envelope;
  QuietProofDecodeError decode_error = QuietProofDecodeError::kMalformed;
  if (!DecodeQuietProofEnvelope(bytes, &envelope, &decode_error)) {
    return {decode_error == QuietProofDecodeError::kUnsupported
                ? QuietProofVerifyResult::kUnsupported
                : QuietProofVerifyResult::kMalformedStatement,
            {}};
  }
  if (QuietProofCheckPolicy(envelope.statement, config.policy, true) != QuietProofAuthorization::kPendingReplayCheck) return {QuietProofVerifyResult::kInvalidProof, {}};
  if (config.supports && !config.supports(envelope)) return {QuietProofVerifyResult::kUnsupported, {}};
  if (!config.verify_proof || !config.verify_proof(envelope)) return {QuietProofVerifyResult::kInvalidProof, {}};
  if (!config.provider || (envelope.statement.has_snapshot && config.provider->kind() != QuietProofProviderKind::kHistoricalSnapshot)) return {QuietProofVerifyResult::kStateInconclusive, {}};
  QuietProofVerification out; bool historical = envelope.statement.has_snapshot;
  std::array<uint8_t, 32> current_block{};
  uint64_t current_height = 0;
  bool have_current_tip = false;
  for (const auto& claim : envelope.statement.claims) {
    QuietProofChainRequest request{envelope.statement.network, claim.txid,
                                 claim.vout, historical,
                                 envelope.statement.snapshot,
                                 envelope.statement.snapshot_height};
    QuietProofChainEvidence evidence = config.provider->Lookup(request); out.claims.push_back(evidence);
    if (historical && (evidence.block != envelope.statement.snapshot ||
                       evidence.height != envelope.statement.snapshot_height)) {
      out.result = QuietProofVerifyResult::kStateInconclusive;
      return out;
    }
    if (!historical) {
      if (QuietProofAllZero(evidence.block)) {
        out.result = QuietProofVerifyResult::kStateInconclusive;
        return out;
      }
      if (!have_current_tip) {
        current_block = evidence.block;
        current_height = evidence.height;
        have_current_tip = true;
      } else if (evidence.block != current_block ||
                 evidence.height != current_height) {
        out.result = QuietProofVerifyResult::kStateInconclusive;
        return out;
      }
    }
    const auto state = QuietProofMatchClaim(claim, envelope.statement.network, evidence);
    if (state == QuietProofChainStatus::kSpent) { out.result = QuietProofVerifyResult::kSpentAtSnapshot; return out; }
    if (state != QuietProofChainStatus::kUnspent) { out.result = QuietProofVerifyResult::kStateInconclusive; return out; }
    if (evidence.confirmations < config.min_confirmations) { out.result = QuietProofVerifyResult::kStaleSnapshot; return out; }
    if (claim.amount_sats > std::numeric_limits<uint64_t>::max() - out.total_sats) { out.result = QuietProofVerifyResult::kStateInconclusive; return out; }
    out.total_sats += claim.amount_sats;
  }
  if (out.total_sats < config.minimum_total_sats) { out.result = QuietProofVerifyResult::kStateInconclusive; return out; }
  if (envelope.statement.has_bridge_binding && (!config.bridge_authorized || !config.bridge_authorized(envelope.statement))) { out.result = QuietProofVerifyResult::kBridgeRejected; return out; }
  if (QuietProofConsumeNonce(envelope.statement, config.policy) != QuietProofAuthorization::kAuthorized) return {QuietProofVerifyResult::kInvalidProof, out.claims};
  out.result = historical ? QuietProofVerifyResult::kValidHistorical : QuietProofVerifyResult::kValidCurrent; return out;
}
}  // namespace proofs
#endif
